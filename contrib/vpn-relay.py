#!/usr/bin/env python3
"""Stable-address TCP relay with hot-swappable upstream.

Clients always dial ONE address (e.g. vpn-exit:8888). Each new connection is
relayed to the upstream named in UPSTREAM_FILE ("host:port", one line).

Writing a different upstream to that file:
  1. changes where subsequent connections go, and
  2. tears down every live relayed connection, so a browser that is pooling
     a CONNECT tunnel to the old exit is forced to redial and lands on the
     new one. Without (2) a persistent browser keeps the old country.
"""
import os
import socket
import sys
import threading
import time

LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8888"))
UPSTREAM_FILE = os.environ.get("UPSTREAM_FILE", "/upstream/upstream")
POLL_SECONDS = float(os.environ.get("POLL_SECONDS", "0.1"))

_live = set()
_lock = threading.Lock()


def read_upstream():
    with open(UPSTREAM_FILE) as f:
        raw = f.read().strip()
    host, _, port = raw.partition(":")
    # An empty file means no country has been chosen yet. Saying so is what
    # keeps `create_connection(("", 8888))` from resolving to this container
    # and relaying the relay to itself.
    if not host:
        raise RuntimeError("no country chosen yet: %s is empty" % UPSTREAM_FILE)
    return raw, (host, int(port or 8888))


def pipe(a, b):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def handle(client):
    try:
        _, addr = read_upstream()
        up = socket.create_connection(addr, timeout=10)
    except Exception as exc:  # noqa: BLE001
        print("upstream fail: %s" % exc, file=sys.stderr, flush=True)
        client.close()
        return
    pair = (client, up)
    with _lock:
        _live.add(pair)

    def run():
        # Both directions have to finish before the sockets are released, or
        # the descriptors pile up: shutdown() alone leaves them open, and a
        # browser opens a lot of tunnels over a long session.
        back = threading.Thread(target=pipe, args=(up, client), daemon=True)
        back.start()
        pipe(client, up)
        back.join()
        with _lock:
            _live.discard(pair)
        for s in pair:
            try:
                s.close()
            except OSError:
                pass

    threading.Thread(target=run, daemon=True).start()


def drain():
    """Force-close every live relayed connection."""
    with _lock:
        pairs = list(_live)
        _live.clear()
    for pair in pairs:
        for s in pair:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass
    return len(pairs)


def watcher():
    # Inside the try as well: with no country chosen the first read raises, and
    # a watcher that died at startup stops draining live connections, so the
    # first country ever chosen would not reach a browser already pooling.
    try:
        current, _ = read_upstream()
    except Exception:  # noqa: BLE001
        current = ""
    while True:
        time.sleep(POLL_SECONDS)
        try:
            new, _ = read_upstream()
        except Exception:  # noqa: BLE001
            continue
        if new != current:
            n = drain()
            print("upstream %s -> %s (dropped %d live conns)" % (current, new, n), flush=True)
            current = new


srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", LISTEN_PORT))
srv.listen(128)
threading.Thread(target=watcher, daemon=True).start()
print("relay on :%d, upstream file %s" % (LISTEN_PORT, UPSTREAM_FILE), flush=True)
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
