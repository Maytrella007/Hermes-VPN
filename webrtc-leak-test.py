#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
webrtc-leak-test.py -- Deterministic WebRTC / IP leak detector for a proxied browser.

WHAT IT DOES
  Drives the real Chrome binary over the Chrome DevTools Protocol (CDP), makes it
  gather ICE candidates against a STUN server we run ourselves on this host, and
  reports every IP address the browser is willing to hand to a remote peer.

WHY CDP AND NOT --dump-dom
  ICE gathering is asynchronous and finishes hundreds of ms after first paint.
  --dump-dom / --virtual-time-budget snapshot the DOM before candidates exist, so
  that approach always reports "waiting". Here we Runtime.evaluate a promise with
  awaitPromise=true, so we block until icegatheringstatechange == "complete"
  (or a hard timeout) and read the candidate list straight out of the JS heap.

THREE LEAK FAMILIES DETECTED
  1. PUBLIC_V4    a routable IPv4 in a candidate (host or srflx)
  2. PUBLIC_V6    a routable IPv6 in a candidate
  3. LOCAL/MDNS   RFC1918 / ULA / link-local / loopback addresses, and the
                  *.local mDNS hostnames Chrome uses to obfuscate them

INDEPENDENT CORROBORATION (does not trust the browser's own reporting)
  - the built-in STUN server logs the source address of every binding request it
    receives, i.e. the address the browser's UDP socket actually used;
  - tcpdump matches STUN by its magic cookie on ANY port, not just 19302.

No third-party service is contacted unless --external-stun is passed.

Exit status: 0 = clean, 1 = leak detected, 2 = test could not run (inconclusive).
"""

import argparse
import base64
import errno
import hashlib
import ipaddress
import json
import os
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STUN_MAGIC = 0x2112A442
STUN_MAGIC_BYTES = struct.pack("!I", STUN_MAGIC)
STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_RESPONSE = 0x0101
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_MAPPED_ADDRESS = 0x0001
ATTR_SOFTWARE = 0x8022

# The canonical tcpdump filter: match STUN by its magic cookie on ANY port
# instead of guessing port 19302.
#
# Two traps live in this one line:
#   * the cookie is at STUN-payload offset 4, and udp[] is indexed from the
#     start of the 8-byte UDP header -> udp[12:4], NOT udp[8:4]. udp[8:4] is
#     the message type + length and never equals the cookie, so the obvious
#     filter silently matches nothing.
#   * udp[] is IPv4-only in libpcap; "ip6 and udp[...]" compiles to
#     "expression rejects all packets". IPv6 must use an absolute offset:
#     40 (IPv6 header) + 8 (UDP header) + 4 (cookie) = 52.
STUN_BPF = (
    "(ip and udp and udp[12:4] = 0x2112a442) or "
    "(ip6 and ip6[6] = 17 and ip6[52:4] = 0x2112a442)"
)
# Broad net: every outbound UDP datagram that is not routine infrastructure
# noise. Use it to catch non-STUN egress (QUIC, DTLS/SRTP, plain TURN) that the
# magic-cookie filter would miss.
#
# 51820 is gluetun's own WireGuard tunnel. Leave it in and ~98% of the capture
# is legitimate tunnel traffic, which buries the few datagrams we care about.
# Drop it from this list if you ever want to look at the tunnel itself.
NOISE_PORTS = ("53 or port 123 or port 5353 or port 67 or port 68 or port 1900 "
               "or port 5355 or port 51820")


def _find_chrome():
    """The first Chrome-like binary on this host, or "" to make the user say.

    Searches the places Hermes and Playwright install one. Returning "" rather
    than a guess keeps `hermes vpn doctor` from printing a command that fails
    with "chrome binary not found" on every host but one.
    """
    import glob as _glob

    roots = [
        os.path.expanduser("~/.hermes/tools"),
        "/opt/playwright",
        os.path.expanduser("~/.cache/ms-playwright"),
    ]
    for root in roots:
        for pattern in ("chromium-*/chrome-linux64/chrome", "chromium-*/chrome-linux/chrome"):
            found = sorted(_glob.glob(os.path.join(root, pattern)))
            # headless_shell cannot open a window, so it is not the browser
            # under test even when it is the only one installed.
            found = [path for path in found if "headless" not in path]
            if found:
                return found[-1]
    return ""


def log(msg):
    sys.stderr.write("[*] %s\n" % msg)
    sys.stderr.flush()


# --------------------------------------------------------------------------
# Host address discovery
# --------------------------------------------------------------------------
def host_addresses():
    """Return (public_v4, public_v6, all_local) as seen on this machine."""
    pub4, pub6, every = [], [], []
    try:
        out = subprocess.run(
            ["ip", "-j", "-o", "addr", "show"],
            capture_output=True, text=True, timeout=10,
        ).stdout
        data = json.loads(out) if out.strip() else []
    except Exception:
        data = []
    for iface in data:
        for ai in iface.get("addr_info", []):
            addr = ai.get("local")
            if not addr:
                continue
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                continue
            every.append(addr)
            if ip.is_global and not ip.is_private:
                (pub4 if ip.version == 4 else pub6).append(addr)
    return pub4, pub6, every


# --------------------------------------------------------------------------
# Minimal STUN server (RFC 5389 Binding only), dual-stack, no dependencies
# --------------------------------------------------------------------------
class StunServer(threading.Thread):
    # Don't reuse threading.Thread's private names. Thread.__init__ sets
    # self._handle (a _thread._ThreadHandle on 3.13), so naming a method
    # _handle gets it shadowed by that attribute and calling it raises
    # "'_thread._ThreadHandle' object is not callable". That only happens on
    # the first packet, in a daemon thread nobody checks, so the server looks
    # fine and reports "nothing seen", which reads like a clean result.
    #
    # `_stop` is the same idea, different fact: on 3.12 and earlier Thread had
    # a `_stop()` method and an Event assigned over it breaks threading's own
    # bookkeeping. On 3.13 there is nothing there to collide with, but a
    # private name on a base class still isn't ours. Hence _quit and
    # _serve_packet.
    def __init__(self, port, bind4="0.0.0.0", bind6="::"):
        super().__init__(daemon=True)
        self.port = port
        self.observations = []          # list of dicts: who talked to us
        self._quit = threading.Event()
        self.socks = []
        self.errors = []
        for family, addr in ((socket.AF_INET, bind4), (socket.AF_INET6, bind6)):
            if addr is None:
                continue
            try:
                s = socket.socket(family, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6:
                    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                s.bind((addr, port))
                s.setblocking(False)
                self.socks.append(s)
            except OSError as e:
                self.errors.append("bind %s:%d failed: %s" % (addr, port, e))

    def stop(self):
        self._quit.set()

    def run(self):
        while not self._quit.is_set():
            if not self.socks:
                return
            try:
                ready, _, _ = select.select(self.socks, [], [], 0.25)
            except (OSError, ValueError):
                return
            for s in ready:
                try:
                    data, src = s.recvfrom(2048)
                except OSError as e:
                    if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                        continue
                    continue
                self._serve_packet(s, data, src)

    def _serve_packet(self, sock, data, src):
        if len(data) < 20:
            return
        mtype, mlen, magic = struct.unpack("!HH4s", data[:8])
        if magic != STUN_MAGIC_BYTES:
            return
        txid = data[8:20]
        src_ip, src_port = src[0], src[1]
        # A dual-stack kernel can hand us v4-mapped addresses; normalise.
        if src_ip.startswith("::ffff:"):
            src_ip = src_ip[7:]
        self.observations.append({
            "ts": time.time(),
            "src_ip": src_ip,
            "src_port": src_port,
            "msg_type": "0x%04x" % mtype,
        })
        if mtype != STUN_BINDING_REQUEST:
            return
        try:
            resp = self._binding_response(txid, src_ip, src_port)
            sock.sendto(resp, src)
        except Exception:
            pass

    @staticmethod
    def _attr(atype, value):
        pad = (-len(value)) % 4
        return struct.pack("!HH", atype, len(value)) + value + (b"\x00" * pad)

    def _binding_response(self, txid, src_ip, src_port):
        ip = ipaddress.ip_address(src_ip)
        raw = ip.packed
        fam = 0x01 if ip.version == 4 else 0x02
        xport = src_port ^ (STUN_MAGIC >> 16)
        key = STUN_MAGIC_BYTES if ip.version == 4 else STUN_MAGIC_BYTES + txid
        xaddr = bytes(a ^ b for a, b in zip(raw, key))
        attrs = self._attr(
            ATTR_XOR_MAPPED_ADDRESS, struct.pack("!BBH", 0, fam, xport) + xaddr
        )
        attrs += self._attr(ATTR_MAPPED_ADDRESS, struct.pack("!BBH", 0, fam, src_port) + raw)
        attrs += self._attr(ATTR_SOFTWARE, b"leaktest")
        header = struct.pack("!HH4s12s", STUN_BINDING_RESPONSE, len(attrs), STUN_MAGIC_BYTES, txid)
        return header + attrs


# --------------------------------------------------------------------------
# Local HTTP server: gives the test page a real (non-file://, non-opaque) origin
# --------------------------------------------------------------------------
PAGE_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>webrtc-leak-test</title></head>
<body><h1>webrtc-leak-test</h1><p id="s">idle</p></body></html>
"""


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = PAGE_HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def start_page_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, srv.server_address[1]


# --------------------------------------------------------------------------
# Minimal WebSocket client, enough for CDP (stdlib only)
# --------------------------------------------------------------------------
class WS:
    def __init__(self, url, timeout=30):
        m = re.match(r"ws://([^/:]+):(\d+)(/.*)$", url)
        if not m:
            raise ValueError("unsupported ws url: %s" % url)
        host, port, path = m.group(1), int(m.group(2)), m.group(3)
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            "GET %s HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n" % (path, host, port, key)
        )
        self.sock.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise IOError("ws handshake closed")
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        if b"101" not in head.split(b"\r\n")[0]:
            raise IOError("ws handshake failed: %r" % head[:200])
        expect = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode().lower()
        if expect.encode() not in head.lower():
            raise IOError("ws handshake accept mismatch")
        self._buf = bytearray(rest)
        self._next_id = 0

    def _recv_into_buf(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            raise IOError("ws closed")
        self._buf.extend(chunk)

    def _read_frame(self):
        """Return (opcode, fin, payload) consuming one frame from the buffer."""
        while True:
            b = self._buf
            if len(b) < 2:
                self._recv_into_buf()
                continue
            b0, b1 = b[0], b[1]
            fin = bool(b0 & 0x80)
            opcode = b0 & 0x0F
            masked = bool(b1 & 0x80)
            ln = b1 & 0x7F
            off = 2
            if ln == 126:
                if len(b) < off + 2:
                    self._recv_into_buf()
                    continue
                ln = struct.unpack("!H", bytes(b[off:off + 2]))[0]
                off += 2
            elif ln == 127:
                if len(b) < off + 8:
                    self._recv_into_buf()
                    continue
                ln = struct.unpack("!Q", bytes(b[off:off + 8]))[0]
                off += 8
            if masked:
                if len(b) < off + 4:
                    self._recv_into_buf()
                    continue
                mask = bytes(b[off:off + 4])
                off += 4
            else:
                mask = None
            if len(b) < off + ln:
                self._recv_into_buf()
                continue
            payload = bytes(b[off:off + ln])
            if mask:
                payload = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
            del self._buf[:off + ln]
            return opcode, fin, payload

    def recv_text(self):
        parts = []
        while True:
            opcode, fin, payload = self._read_frame()
            if opcode == 0x8:
                raise IOError("ws close frame")
            if opcode == 0x9:                      # ping -> pong
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            parts.append(payload)
            if fin:
                return b"".join(parts).decode("utf-8", "replace")

    def _send_frame(self, opcode, payload):
        mask = os.urandom(4)
        masked = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
        n = len(payload)
        if n < 126:
            hdr = struct.pack("!BB", 0x80 | opcode, 0x80 | n)
        elif n < 65536:
            hdr = struct.pack("!BBH", 0x80 | opcode, 0x80 | 126, n)
        else:
            hdr = struct.pack("!BBQ", 0x80 | opcode, 0x80 | 127, n)
        self.sock.sendall(hdr + mask + masked)

    def send_text(self, s):
        self._send_frame(0x1, s.encode())

    def call(self, method, params=None, session_id=None, timeout=120):
        self._next_id += 1
        mid = self._next_id
        msg = {"id": mid, "method": method, "params": params or {}}
        if session_id:
            msg["sessionId"] = session_id
        self.send_text(json.dumps(msg))
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.sock.settimeout(max(1.0, deadline - time.time()))
            try:
                data = json.loads(self.recv_text())
            except socket.timeout:
                continue
            if data.get("id") == mid:
                if "error" in data:
                    raise RuntimeError("CDP %s: %s" % (method, data["error"]))
                return data.get("result", {})
        raise TimeoutError("CDP %s timed out" % method)

    def close(self):
        try:
            self._send_frame(0x8, b"")
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


# --------------------------------------------------------------------------
# The in-page probe. Returns every candidate plus the final SDP.
# --------------------------------------------------------------------------
JS_PROBE = r"""
(async () => {
  const servers = __ICE_SERVERS__;
  const budgetMs = __BUDGET_MS__;
  const out = {iceServers: servers, candidates: [], errors: [], sdp: null,
               gatheringState: null, elapsedMs: 0, supported: true};
  if (typeof RTCPeerConnection === 'undefined') {
    out.supported = false; return out;
  }
  const t0 = performance.now();
  let pc;
  try {
    pc = new RTCPeerConnection({iceServers: servers, iceCandidatePoolSize: 0});
  } catch (e) { out.errors.push('ctor: ' + e); out.supported = false; return out; }
  pc.onicecandidateerror = (e) => {
    out.errors.push('icecandidateerror url=' + (e.url||'') +
                    ' code=' + (e.errorCode||'') + ' text=' + (e.errorText||''));
  };
  const done = new Promise((resolve) => {
    const finish = () => resolve();
    const timer = setTimeout(finish, budgetMs);
    pc.onicecandidate = (e) => {
      if (!e.candidate) { clearTimeout(timer); finish(); return; }
      const c = e.candidate;
      out.candidates.push({
        candidate: c.candidate, type: c.type, protocol: c.protocol,
        address: c.address, port: c.port, relatedAddress: c.relatedAddress,
        foundation: c.foundation, sdpMid: c.sdpMid
      });
    };
    pc.onicegatheringstatechange = () => {
      if (pc.iceGatheringState === 'complete') { clearTimeout(timer); finish(); }
    };
  });
  try {
    pc.createDataChannel('leaktest');
    const offer = await pc.createOffer({offerToReceiveAudio: true,
                                        offerToReceiveVideo: true});
    await pc.setLocalDescription(offer);
  } catch (e) { out.errors.push('offer: ' + e); }
  await done;
  out.gatheringState = pc.iceGatheringState;
  out.sdp = pc.localDescription ? pc.localDescription.sdp : null;
  out.elapsedMs = Math.round(performance.now() - t0);
  try { pc.close(); } catch (e) {}
  return out;
})()
"""


# --------------------------------------------------------------------------
# Candidate classification
# --------------------------------------------------------------------------
CAND_RE = re.compile(
    r"candidate:(?P<foundation>\S+)\s+(?P<component>\d+)\s+(?P<proto>\S+)\s+"
    r"(?P<prio>\d+)\s+(?P<addr>\S+)\s+(?P<port>\d+)\s+typ\s+(?P<typ>\S+)"
)


def norm_addr(addr):
    if addr is None:
        return None
    a = str(addr).strip()
    if a.startswith("[") and a.endswith("]"):
        a = a[1:-1]
    try:                       # collapse IPv6 spellings so string compares work
        return str(ipaddress.ip_address(a))
    except ValueError:
        return a


def classify_address(addr):
    """-> (family_tag, parsed_ip_or_None)"""
    if addr is None:
        return "UNKNOWN", None
    a = addr.strip()
    # Chrome reports IPv6 candidate addresses bracketed in some code paths;
    # unbracketed in others. Normalise or the bracketed copy parses as UNKNOWN
    # and a real leak slips through as "ok".
    if a.startswith("[") and a.endswith("]"):
        a = a[1:-1]
    if a.endswith(".local"):
        return "MDNS", None
    try:
        ip = ipaddress.ip_address(a)
    except ValueError:
        return "UNKNOWN", None
    if ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved:
        return "LOCAL_V%d" % ip.version, ip
    if ip.is_global:
        return "PUBLIC_V%d" % ip.version, ip
    return "OTHER_V%d" % ip.version, ip


def addresses_from_sdp(sdp):
    """Pull every address out of a= lines and c= lines of the SDP."""
    found = []
    if not sdp:
        return found
    for line in sdp.splitlines():
        line = line.strip()
        if line.startswith("a=candidate:"):
            m = CAND_RE.search(line)
            if m:
                found.append((m.group("addr"), m.group("typ"), line))
            # raddr (the local address behind an srflx/relay) leaks too
            r = re.search(r"raddr\s+(\S+)", line)
            if r and r.group(1) not in ("0.0.0.0", "::"):
                found.append((r.group(1), "raddr", line))
        elif line.startswith("c=IN IP"):
            parts = line.split()
            if len(parts) >= 3 and parts[2] not in ("0.0.0.0", "::"):
                found.append((parts[2], "c-line", line))
    return found


# --------------------------------------------------------------------------
# tcpdump capture
# --------------------------------------------------------------------------
class Capture:
    def __init__(self, iface, outdir, bpf, label):
        self.iface = iface
        self.bpf = bpf
        self.label = label
        self.pcap = os.path.join(outdir, "capture-%s.pcap" % label)
        self.txt = os.path.join(outdir, "capture-%s.txt" % label)
        self.proc = None
        self.available = shutil.which("tcpdump") is not None and os.geteuid() == 0

    def start(self):
        if not self.available:
            return False
        self._fh = open(self.txt, "wb")
        self.proc = subprocess.Popen(
            ["tcpdump", "-i", self.iface, "-nn", "-l", "-s", "256",
             "-w", self.pcap, "-U", self.bpf],
            stdout=self._fh, stderr=self._fh, start_new_session=True,
        )
        time.sleep(1.2)   # let the BPF program attach before traffic starts
        return self.proc.poll() is None

    def stop(self):
        if not self.proc:
            return {"available": False}
        time.sleep(0.8)
        try:
            self.proc.send_signal(signal.SIGINT)
            self.proc.wait(timeout=10)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
        try:
            self._fh.close()
        except Exception:
            pass
        info = {"available": True, "iface": self.iface, "bpf": self.bpf,
                "pcap": self.pcap, "log": self.txt, "packets": 0, "peers": []}
        try:
            with open(self.txt, "r", errors="replace") as f:
                blob = f.read()
            m = re.search(r"(\d+)\s+packets captured", blob)
            if m:
                info["packets"] = int(m.group(1))
        except Exception:
            pass
        if info["packets"] and shutil.which("tcpdump"):
            try:
                out = subprocess.run(
                    ["tcpdump", "-nn", "-r", self.pcap],
                    capture_output=True, text=True, timeout=30,
                ).stdout
                info["sample"] = out.splitlines()[:40]
            except Exception:
                pass
        return info


# --------------------------------------------------------------------------
# Chrome driver
# --------------------------------------------------------------------------
def wait_for_cdp(port, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(
                "http://127.0.0.1:%d/json/version" % port, timeout=2
            ) as r:
                return json.loads(r.read().decode())
        except Exception:
            time.sleep(0.5)
    return None


def cdp_targets(port):
    with urllib.request.urlopen("http://127.0.0.1:%d/json/list" % port, timeout=5) as r:
        return json.loads(r.read().decode())


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def run_browser_probe(args, page_url, ice_servers, workdir):
    cdp_port = free_port()
    profile = os.path.join(workdir, "profile")
    os.makedirs(profile, exist_ok=True)
    chrome_log = os.path.join(workdir, "chrome.log")

    flags = [
        args.chrome,
        "--headless=new",
        "--no-sandbox",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-timer-throttling",
        "--remote-debugging-address=127.0.0.1",
        "--remote-debugging-port=%d" % cdp_port,
        "--user-data-dir=%s" % profile,
    ]
    if args.proxy:
        flags.append("--proxy-server=%s" % args.proxy)
    if args.extra_flag:
        flags.extend(args.extra_flag)
    flags.append(page_url)

    # Run as the browser's normal user so we exercise the same sandbox/profile
    # situation as the agent, but never its user-data-dir (Chrome's singleton
    # would forward our launch into the agent's existing browser).
    if args.user and args.user != _current_user():
        cmd = ["su", "-s", "/bin/bash", args.user, "-c",
               " ".join(_shq(f) for f in flags)]
    else:
        cmd = flags

    lf = open(chrome_log, "wb")
    proc = subprocess.Popen(cmd, stdout=lf, stderr=lf, start_new_session=True)
    result = {"cdp_port": cdp_port, "chrome_log": chrome_log, "flags": flags}
    try:
        ver = wait_for_cdp(cdp_port, timeout=args.launch_timeout)
        if not ver:
            lf.flush()
            with open(chrome_log, "r", errors="replace") as f:
                tail = f.read()[-2000:]
            result["error"] = "CDP never came up. chrome.log tail:\n" + tail
            return result
        result["browser"] = ver.get("Browser")
        result["user_agent"] = ver.get("User-Agent")

        page_ws = None
        deadline = time.time() + 20
        while time.time() < deadline and not page_ws:
            for t in cdp_targets(cdp_port):
                if t.get("type") == "page" and t.get("webSocketDebuggerUrl"):
                    page_ws = t["webSocketDebuggerUrl"]
                    break
            if not page_ws:
                time.sleep(0.5)
        if not page_ws:
            result["error"] = "no page target exposed over CDP"
            return result

        ws = WS(page_ws, timeout=args.budget / 1000.0 + 60)
        try:
            ws.call("Page.enable")
            ws.call("Runtime.enable")
            ws.call("Page.navigate", {"url": page_url})
            time.sleep(1.0)
            js = JS_PROBE.replace("__ICE_SERVERS__", json.dumps(ice_servers))
            js = js.replace("__BUDGET_MS__", str(args.budget))
            ev = ws.call(
                "Runtime.evaluate",
                {"expression": js, "awaitPromise": True, "returnByValue": True},
                timeout=args.budget / 1000.0 + 45,
            )
            if ev.get("exceptionDetails"):
                result["error"] = "JS exception: %s" % json.dumps(ev["exceptionDetails"])[:600]
                return result
            result["probe"] = ev.get("result", {}).get("value")
        finally:
            ws.close()
    finally:
        _graceful_close(cdp_port)
        _terminate(proc)
        _sweep_orphans(args.chrome, profile)
        try:
            lf.close()
        except Exception:
            pass
    return result


def _graceful_close(cdp_port):
    """Ask Chrome to shut itself down; this reaps renderers/zygotes that `su`
    moved into their own session, where killpg cannot reach them."""
    try:
        with urllib.request.urlopen(
            "http://127.0.0.1:%d/json/version" % cdp_port, timeout=3
        ) as r:
            ws_url = json.loads(r.read().decode()).get("webSocketDebuggerUrl")
        if not ws_url:
            return
        bws = WS(ws_url, timeout=6)
        try:
            bws.call("Browser.close", timeout=6)
        finally:
            bws.close()
        time.sleep(1.0)
    except Exception:
        pass


def _sweep_orphans(chrome_path, profile_dir):
    """Last resort: kill by PID only processes whose argv[0] IS the chrome
    binary AND whose command line names OUR private profile directory.

    Deliberately not `pkill -f <pattern>`: a pattern broad enough to match the
    browser also matches the ssh/bash command line that started this script,
    which would kill the operator's own session.
    """
    victims = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open("/proc/%s/cmdline" % entry, "rb") as f:
                argv = f.read().split(b"\x00")
        except OSError:
            continue
        if not argv or not argv[0]:
            continue
        if argv[0].decode("utf-8", "replace") != chrome_path:
            continue          # excludes our own shell/ssh, which never exec'd chrome
        if profile_dir.encode() not in b" ".join(argv):
            continue          # excludes the agent's browser (different profile)
        victims.append(int(entry))
    for pid in victims:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    return victims


def _current_user():
    try:
        import pwd
        return pwd.getpwuid(os.geteuid()).pw_name
    except Exception:
        return None


def _shq(s):
    return "'" + str(s).replace("'", "'\"'\"'") + "'"


def _terminate(proc):
    """Kill the browser by PID/process group only -- never pkill -f, which would
    also match the ssh command line that launched this script."""
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass
    try:
        proc.wait(timeout=8)
        return
    except Exception:
        pass
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    try:
        proc.wait(timeout=5)
    except Exception:
        pass


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
def build_report(args, probe, stun_obs, cap_info, expected_real, exit_ip):
    findings = {"PUBLIC_V4": [], "PUBLIC_V6": [], "LOCAL": [], "MDNS": []}
    rows = []

    seen = set()
    sources = []
    for c in (probe or {}).get("candidates", []) or []:
        sources.append((c.get("address"), c.get("type") or "?", c.get("candidate") or ""))
    sources.extend(addresses_from_sdp((probe or {}).get("sdp")))

    for addr, typ, raw in sources:
        addr = norm_addr(addr)
        key = (addr, typ)
        if key in seen:
            continue
        seen.add(key)
        fam, ip = classify_address(addr)
        verdict = "ok"
        if fam.startswith("PUBLIC"):
            bucket = "PUBLIC_V4" if fam.endswith("V4") else "PUBLIC_V6"
            if addr in expected_real:
                verdict = "LEAK-REAL-HOST-IP"
            elif exit_ip and addr == exit_ip:
                verdict = "proxy-exit-ip"
            else:
                verdict = "LEAK-PUBLIC-IP"
            if verdict != "proxy-exit-ip":
                findings[bucket].append(addr)
        elif fam.startswith("LOCAL") or fam.startswith("OTHER"):
            verdict = "LEAK-LOCAL-ADDR"
            findings["LOCAL"].append(addr)
        elif fam == "MDNS":
            verdict = "LEAK-MDNS-NAME"
            findings["MDNS"].append(addr)
        else:
            verdict = "unparsed-INSPECT-MANUALLY"
        rows.append({"address": addr, "cand_type": typ, "family": fam,
                     "verdict": verdict, "raw": raw[:200]})

    stun_seen = sorted({norm_addr(o["src_ip"]) for o in stun_obs})
    stun_leaks = sorted(a for a in stun_seen if a in expected_real)

    for k in findings:
        findings[k] = sorted(set(findings[k]))

    leaked = bool(findings["PUBLIC_V4"] or findings["PUBLIC_V6"]
                  or findings["LOCAL"] or findings["MDNS"] or stun_leaks)
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "proxy": args.proxy,
        "expected_real_ips": sorted(expected_real),
        "proxy_exit_ip": exit_ip,
        "browser": None,
        "ice_gathering_state": (probe or {}).get("gatheringState"),
        "ice_elapsed_ms": (probe or {}).get("elapsedMs"),
        "candidate_count": len((probe or {}).get("candidates") or []),
        "ice_errors": (probe or {}).get("errors") or [],
        "rows": rows,
        "findings": findings,
        "stun_server_observations": stun_obs,
        "stun_source_ips": stun_seen,
        "stun_real_ip_sources": stun_leaks,
        "capture": cap_info,
        "sdp": (probe or {}).get("sdp"),
        "leak": leaked,
    }


def print_report(rep):
    W = sys.stdout.write
    W("\n" + "=" * 74 + "\n")
    W("  WebRTC / IP LEAK TEST\n")
    W("=" * 74 + "\n")
    W("  run at             : %s\n" % rep["generated_at"])
    W("  browser proxy      : %s\n" % (rep["proxy"] or "(none)"))
    W("  proxy exit IP      : %s\n" % (rep["proxy_exit_ip"] or "(unknown)"))
    W("  real host IPs      : %s\n" % ", ".join(rep["expected_real_ips"]))
    W("  ICE gathering      : %s after %sms, %d candidate(s)\n" % (
        rep["ice_gathering_state"], rep["ice_elapsed_ms"], rep["candidate_count"]))
    W("-" * 74 + "\n")
    if rep["rows"]:
        W("  %-40s %-9s %-s\n" % ("ADDRESS", "CAND", "VERDICT"))
        for r in rep["rows"]:
            W("  %-40s %-9s %s\n" % (str(r["address"])[:40], r["cand_type"][:9], r["verdict"]))
    else:
        W("  no addresses appeared in any candidate or in the SDP\n")
    W("-" * 74 + "\n")
    f = rep["findings"]
    W("  LEAK FAMILY 1  public IPv4   : %s\n" % (", ".join(f["PUBLIC_V4"]) or "clean"))
    W("  LEAK FAMILY 2  public IPv6   : %s\n" % (", ".join(f["PUBLIC_V6"]) or "clean"))
    W("  LEAK FAMILY 3  local / mDNS  : %s\n" % (
        ", ".join(f["LOCAL"] + f["MDNS"]) or "clean"))
    W("-" * 74 + "\n")
    W("  STUN server saw source IPs   : %s\n" % (", ".join(rep["stun_source_ips"]) or "nothing"))
    W("  ... of which are real host IP: %s\n" % (
        ", ".join(rep["stun_real_ip_sources"]) or "none"))
    cap = rep.get("capture") or {}
    if cap.get("available"):
        W("  tcpdump %-21s: %d packet(s) -> %s\n" % (
            "(" + str(cap.get("iface")) + ")", cap.get("packets", 0), cap.get("pcap")))
    else:
        W("  tcpdump                      : not run (need root)\n")
    if rep["ice_errors"]:
        W("-" * 74 + "\n")
        for e in rep["ice_errors"][:6]:
            W("  ice note: %s\n" % e[:140])
    W("=" * 74 + "\n")
    if rep["leak"]:
        W("  VERDICT: *** LEAK DETECTED ***\n")
    elif rep.get("inconclusive"):
        # A clean result is only worth the channel that could have shown a
        # dirty one. With no STUN server bound and no external one offered,
        # zero candidates is what a working block AND a broken test both look
        # like, and this script's own header reserves exit 2 for exactly that.
        W("  VERDICT: inconclusive — %s\n" % rep["inconclusive"])
        W("           a clean result here proves nothing; fix that and re-run.\n")
    else:
        W("  VERDICT: no leak detected\n")
    W("=" * 74 + "\n\n")


# --------------------------------------------------------------------------
def detect_exit_ip(proxy, timeout=8):
    if not proxy or not shutil.which("curl"):
        return None
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            out = subprocess.run(
                ["curl", "-s", "-m", str(timeout), "-x", proxy, url],
                capture_output=True, text=True, timeout=timeout + 4,
            ).stdout.strip()
            ipaddress.ip_address(out)
            return out
        except Exception:
            continue
    return None


def main():
    p = argparse.ArgumentParser(
        description="Detect WebRTC/IP leaks in a proxied Chrome, via CDP + a self-hosted STUN server.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--chrome", default=_find_chrome(),
                   help="path to the Chrome binary under test (default: the first one found "
                        "under ~/.hermes/tools, /opt/playwright or ~/.cache/ms-playwright)")
    p.add_argument("--user", default="",
                   help="OS user to run the browser as, via su; default is whoever runs "
                        "this. Pass the agent's user when running as root.")
    p.add_argument("--proxy", default="http://127.0.0.1:8891",
                   help="value for --proxy-server; '' to run unproxied")
    p.add_argument("--stun-port", type=int, default=3478,
                   help="UDP port for the built-in STUN server")
    p.add_argument("--external-stun", action="store_true",
                   help="ALSO use stun.l.google.com:19302 (third party; forces real egress on eth0)")
    p.add_argument("--no-self-stun", action="store_true",
                   help="do not run the built-in STUN server / do not offer it to the browser")
    p.add_argument("--extra-ice", action="append", default=[],
                   help="extra ICE server URL, e.g. stun:host:3478 (repeatable)")
    p.add_argument("--budget", type=int, default=12000,
                   help="max ms to wait for ICE gathering to complete")
    p.add_argument("--launch-timeout", type=int, default=40,
                   help="seconds to wait for the CDP endpoint")
    p.add_argument("--capture-iface", default="any",
                   help="interface for tcpdump ('any' catches lo + eth0; '' disables)")
    p.add_argument("--broad-capture", action="store_true",
                   help="capture all non-noise outbound UDP instead of only STUN")
    p.add_argument("--extra-flag", action="append", default=[],
                   help="extra Chrome flag (repeatable)")
    p.add_argument("--expect-ip", action="append", default=[],
                   help="additional real-host IP that must never appear (repeatable)")
    p.add_argument("--json", dest="json_out", default=None,
                   help="write the full machine-readable report here")
    p.add_argument("--workdir", default=None,
                   help="keep artifacts here instead of a temp dir")
    p.add_argument("--quiet-exit-check", action="store_true",
                   help="skip the outbound curl that discovers the proxy exit IP")
    args = p.parse_args()

    if not os.path.exists(args.chrome):
        log("chrome binary not found: %s" % args.chrome)
        return 2

    pub4, pub6, _ = host_addresses()
    expected_real = {norm_addr(a) for a in (list(pub4) + list(pub6) + list(args.expect_ip))}
    if not expected_real:
        log("could not determine this host's public IPs; pass --expect-ip")

    workdir = args.workdir or tempfile.mkdtemp(prefix="webrtc-leak-")
    os.makedirs(workdir, exist_ok=True)
    os.chmod(workdir, 0o755)
    log("workdir: %s" % workdir)

    stun = StunServer(args.stun_port) if not args.no_self_stun else None
    if stun:
        for e in stun.errors:
            log("stun: %s" % e)
        if not stun.socks:
            log("STUN server could not bind any socket; srflx evidence unavailable")
        stun.start()

    ice = []
    if not args.no_self_stun:
        for a in pub4:
            ice.append({"urls": "stun:%s:%d" % (a, args.stun_port)})
        for a in pub6:
            ice.append({"urls": "stun:[%s]:%d" % (a, args.stun_port)})
    if args.external_stun:
        ice.append({"urls": "stun:stun.l.google.com:19302"})
    for u in args.extra_ice:
        ice.append({"urls": u})
    if not ice:
        log("no ICE servers configured -- only host candidates will be gathered")

    srv, page_port = start_page_server()
    page_url = "http://127.0.0.1:%d/leaktest" % page_port
    log("test page: %s" % page_url)

    cap_info = {"available": False}
    cap = None
    if args.capture_iface:
        bpf = ("udp and not (port %s)" % NOISE_PORTS) if args.broad_capture else STUN_BPF
        cap = Capture(args.capture_iface, workdir, bpf, "stun")
        if cap.start():
            log("tcpdump running on %s with filter: %s" % (args.capture_iface, bpf))
        else:
            log("tcpdump could not start (need root / bad iface); continuing")
            cap = None

    exit_ip = None if args.quiet_exit_check else detect_exit_ip(args.proxy)

    log("launching browser and gathering ICE (budget %dms) ..." % args.budget)
    res = run_browser_probe(args, page_url, ice, workdir)

    if cap:
        cap_info = cap.stop()

    if stun:
        stun.stop()
    try:
        srv.shutdown()
    except Exception:
        pass

    if "error" in res:
        log("PROBE FAILED: %s" % res["error"])
        return 2

    rep = build_report(args, res.get("probe"),
                       stun.observations if stun else [], cap_info,
                       expected_real, exit_ip)
    rep["browser"] = res.get("browser")
    rep["chrome_flags"] = res.get("flags")
    rep["workdir"] = workdir

    # Was there a channel that could have shown a leak? With the policy in
    # force zero candidates is the expected pass, so a STUN server that never
    # bound, or a thread that died on its first packet, makes that pass
    # unprovable. Don't report "clean" from a dead sensor.
    channel = []
    if stun is None:
        channel.append("the built-in STUN server was not run (--no-self-stun)")
    else:
        if not stun.socks:
            channel.append("the built-in STUN server could not bind a socket")
        # Deliberately NOT `if stun.errors`. We bind IPv4 and IPv6, and with
        # IPv6 off (most containers) the v6 bind fails while the v4 socket is
        # up and perfectly able to see a leak. Treat any error as a dead sensor
        # and every clean result on those hosts comes back "inconclusive". The
        # errors are logged above, which is where a half-bound server belongs.
        if not ice:
            channel.append("no ICE server was offered to the browser, so only host "
                           "candidates could ever appear")
    if args.external_stun or args.extra_ice:
        channel = []  # a third party was asked, so there was a real channel
    if channel and not rep["leak"] and not rep["candidate_count"]:
        rep["inconclusive"] = "; ".join(channel)
    print_report(rep)

    out = args.json_out or os.path.join(workdir, "report.json")
    try:
        with open(out, "w") as f:
            json.dump(rep, f, indent=2)
        log("full report: %s" % out)
    except Exception as e:
        log("could not write report: %s" % e)

    if rep["leak"]:
        return 1
    return 2 if rep.get("inconclusive") else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
