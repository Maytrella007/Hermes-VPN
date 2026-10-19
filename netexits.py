"""Named network exits for a Hermes agent, and the truth about which one is live.

The agent's browser leaves by whichever exit is selected; an exit is just a
local proxy, so what produces it -- a gluetun container, an SSH tunnel, a
commercial proxy -- is none of this plugin's business. gluetun containers are
discovered automatically because they announce themselves; anything else is
listed in a small file.

Two rules shape the code:

* **Verify, never assume.** An exit is only reported as working after a request
  through it comes back, and the country reported is the one the other end
  actually saw. A tunnel that silently dropped is worse than no tunnel, because
  decisions get made on the belief that it is up.
* **Fail closed.** If an exit cannot be verified, the switch does not happen and
  the browser keeps whatever it had.

No third-party dependencies: everything here is standard library.
"""

from __future__ import annotations

import contextlib
import difflib
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

#: Chromium reads its proxy from the command line, and Hermes passes extra
#: arguments through this variable, comma separated.
BROWSER_ARGS_ENV = "AGENT_BROWSER_ARGS"
#: Setting the variable replaces Hermes's own defaults, so they are re-added.
BASE_BROWSER_ARGS = ("--no-sandbox", "--disable-dev-shm-usage")

#: Where a manual list of exits can live (gluetun needs no file).
EXITS_FILE_ENV = "NET_EXITS_FILE"
#: Where the current choice is remembered, so it survives a restart.
STATE_FILE_ENV = "NET_EXITS_STATE_FILE"

#: Services that report the address they saw. The friendly ones go first: a
#: VPN exit is a shared address, and the strict ones rate-limit those, so a
#: healthy tunnel looks dead. Keep the timeout short, a switch waits on this.
LOOKUP_URLS = (
    "https://ipwho.is/",
    "https://ifconfig.co/json",
    "https://ipinfo.io/json",
)

#: Tried first: no rate limit, tiny body, and it gives us the country too.
#: It answers `key=value` lines, not JSON, so `_read_trace` parses it.
TRACE_URL = "https://1.1.1.1/cdn-cgi/trace"
LOOKUP_TIMEOUT = 6

DIRECT = "direct"


def here(script: str) -> str:
    """A command that can be pasted, wherever this plugin happens to live.

    The printed strings were relative -- `contrib/vpn-migrate`,
    `contrib/install` -- and no document says the plugin is installed in
    ``~/.hermes/plugins/hermes-vpn``, so the reader was told to run something
    from a directory they had not been told to be in.
    """
    return str(Path(__file__).resolve().parent / script)


def hermes_home() -> Path:
    """Where this agent's Hermes home is, with the path actually resolved.

    Resolved, because everything about *which profile this is* is derived from
    the shape of this path: inside a profile, ``HERMES_HOME`` is
    ``…/profiles/<name>``. A symlink to it, or a ``…/profiles/lab/..``, left
    the plugin believing it was on the host -- so it moved the host's browser
    and reported the sandbox's country.
    """
    raw = Path(os.environ.get("HERMES_HOME") or Path.home() / ".hermes")
    try:
        return raw.resolve()
    except OSError:
        return raw


def exits_file() -> Path:
    return Path(os.environ.get(EXITS_FILE_ENV) or hermes_home() / "net-exits.json")


def state_file() -> Path:
    return Path(os.environ.get(STATE_FILE_ENV) or hermes_home() / "net-exits-state.json")


class ExitError(Exception):
    """Something the caller should be told in words."""


#: A proxy is a scheme and an authority, nothing else. Hermes splits
#: AGENT_BROWSER_ARGS on commas, so a comma in here ends the switch and starts
#: another one. We reject a trailing slash too: urllib would happily ignore the
#: path, but Chromium throws out the whole proxy with ERR_NO_SUPPORTED_PROXIES.
#: `\Z`, not `$`: `$` matches before a trailing newline, so a proxy with one
#: passed and went into the browser's arguments carrying it.
PROXY_PATTERN = re.compile(r"^(?:https?|socks4|socks5|socks5h)://[A-Za-z0-9._\-\[\]:]+\Z")


def _is_socks(proxy: str) -> bool:
    """Is this a proxy only curl can ask through?"""
    return bool(proxy) and urllib.parse.urlsplit(proxy).scheme not in {"http", "https"}


def check_proxy(proxy: str) -> str:
    """Return *proxy* unchanged, or refuse to let it near the browser."""
    if not PROXY_PATTERN.match(proxy or ""):
        # Without the authority: someone who wrote `http://user:pass@host`
        # learns the format does not take credentials by having them printed
        # back into the agent's context and the chat it answers on.
        shown = (proxy or "").split("@")[-1][:60]
        raise ExitError(
            f"{shown!r} is not a proxy address (any credentials in it are not shown, and "
            "are not supported). Expected something like "
            "http://127.0.0.1:8891 — a scheme and a host, with no spaces, "
            "commas or path, because these become the browser's arguments."
        )
    return proxy


@dataclass(frozen=True)
class Exit:
    """One way out: a name, a proxy, and where it is supposed to come out."""

    name: str
    proxy: str
    country: str = ""
    source: str = "file"
    container: str = ""
    #: Which VPN subscription this exit leaves by, when it can be told. Only a
    #: gluetun container knows; an exit listed in the file is whatever the user
    #: pointed it at and says so by staying empty.
    provider: str = ""

    def __post_init__(self) -> None:
        check_proxy(self.proxy)

    @property
    def label(self) -> str:
        return f"{self.name} ({self.country})" if self.country else self.name


@dataclass
class Sighting:
    """What the far end reported when asked through an exit."""

    ok: bool
    ip: str = ""
    country: str = ""
    city: str = ""
    detail: str = ""
    elapsed: float = 0.0
    #: We never got to ask, as opposed to asked and got nothing.
    unverifiable: bool = False

    @property
    def summary(self) -> str:
        """The shape of the failure, for a sentence someone reads aloud.

        `detail` keeps every endpoint that was tried and what each said,
        which is the right thing for `doctor` and the wrong thing in a
        message a bot paraphrases: four URLs and four urllib strings read
        like four separate faults, and the useful half of the sentence ends
        up last.
        """
        if not self.detail:
            return "no answer"
        first = self.detail.split(";")[0]
        shape = first.split(": ", 1)[-1].strip() or first.strip()
        tried = self.detail.count(";") + 1
        return f"{shape[:70]}" + (f"; {tried} lookups tried" if tried > 1 else "")

    @property
    def place(self) -> str:
        parts = [p for p in (self.city, self.country) if p]
        return ", ".join(parts) or "unknown"


# -- discovery -------------------------------------------------------------


def _docker_try(*args: str, timeout: int = 15) -> tuple[bool, str]:
    """(did the call run, what it printed).

    Separate from :func:`_docker` because some questions have three answers.
    Collapsing "docker could not be asked" into "the answer is no" is how a
    check ends up reporting a clean result it never obtained.
    """
    try:
        done = subprocess.run(
            ["docker", *args], capture_output=True, text=True, timeout=timeout
        )
    # Catch OSError, not just FileNotFoundError. A docker on PATH without +x
    # gives us PermissionError, and a broken binary gives OSError("Exec format
    # error").
    except (OSError, subprocess.SubprocessError):
        return False, ""
    return done.returncode == 0, done.stdout


def _docker(*args: str, timeout: int = 15) -> str:
    ok, out = _docker_try(*args, timeout=timeout)
    return out if ok else ""


#: The port gluetun's HTTP proxy listens on inside the container. Exits are
#: recognised by this, not by whichever published port comes first.
PROXY_PORT = "8888"


def _published_proxy_port(ports: str) -> str:
    """The host port a container publishes for its proxy, from docker's ports text.

    Docker prints things like ``127.0.0.1:8889->8888/tcp``. The loopback-bound
    ones are what we want; a proxy published to the world is not an exit, it is
    an open relay.
    """
    # Match on the container port. docker sorts by it, so grabbing the first
    # loopback line can hand us gluetun's control API on 8000 instead.
    for match in re.finditer(r"(127\.0\.0\.1|localhost):(\d+)->(\d+)/tcp", ports):
        if match.group(3) == PROXY_PORT:
            return match.group(2)
    return ""


#: Running containers that look like an exit and cannot be used, and why.
#: `doctor` names them: telling someone to start a tunnel they already have
#: running is useless.
_unusable_exits: list[str] = []

#: Set when docker itself couldn't be asked, which is not the same as finding
#: nothing. Usually the agent's user is not in the docker group.
_docker_silent = ""

#: The same distinction for the sandbox listing, kept apart because the two
#: are asked at different moments and only this one decides which browser
#: this plugin is talking about.
_sandbox_listing_silent = ""


#: The label `vpn-exit` puts on what it creates, and the one anything else can
#: wear to be treated as an exit. It is already how the helper decides whether
#: a container may be pointed at a sandbox, so this is the same answer to the
#: same question rather than a second rule.
EXIT_LABEL = "managed-by"
EXIT_LABEL_VALUE = "vpn-exit"

#: Optional labels for an exit that is not gluetun and therefore carries no
#: `SERVER_COUNTRIES` to read. They set what a reader sees, and nothing else:
#: the country failover matches on is read from the container's environment,
#: so a labelled exit is never a stand-in and never gets one. A label is what
#: someone wrote, not what the tunnel does.
PROVIDER_LABEL = "exit-provider"
COUNTRY_LABEL = "exit-country"


def _labels_of(column: str) -> dict[str, str]:
    """`docker ps` prints labels as `k=v,k2=v2`, which is all we need here."""
    found: dict[str, str] = {}
    for item in (column or "").split(","):
        key, sep, value = item.partition("=")
        if sep:
            found[key.strip()] = value.strip()
    return found


def discover_containers() -> list[Exit]:
    """Exits from running containers: gluetun, and anything wearing the label.

    gluetun is recognised by its image because it carries its own country and
    provider in its environment, which is what makes an exit describe itself.
    Anything else has to say so with a label, so that a container someone
    happens to be running never becomes a way out by accident.
    """
    global _unusable_exits, _docker_silent
    _unusable_exits = []
    _docker_silent = ""
    ok, listing = _docker_try(
        "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Labels}}", timeout=15
    )
    if not ok:
        _docker_silent = (
            "docker could not be asked, so no exit could be discovered — is this user in "
            "the docker group?"
        )
        return []
    found: list[Exit] = []
    for line in listing.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        name, image, ports = parts[0], parts[1], parts[2]
        # Docker's own charset. A label value may carry a newline or a comma,
        # and the listing is split on both, so a crafted label can forge an
        # extra row with a name of its choosing -- which would then travel to
        # the root helper and into messages.
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name):
            continue
        labels = _labels_of(parts[3] if len(parts) > 3 else "")
        gluetun = "gluetun" in image.lower()
        if not gluetun and labels.get(EXIT_LABEL) != EXIT_LABEL_VALUE:
            continue
        port = _published_proxy_port(ports)
        if not port:
            # No reachable proxy, so not an exit. Remember it anyway.
            _unusable_exits.append(
                f"{name} is running but publishes no HTTP proxy on 127.0.0.1:<port>->8888"
                + (f" (it publishes {ports})" if ports.strip() else " (it publishes no ports)")
                + ("" if gluetun else " [labelled]")
            )
            continue
        # One inspect, both facts. Asking twice doubles a docker call that runs
        # for every container on every listing.
        env = _container_env(name) if gluetun else []
        found.append(
            Exit(
                name=name,
                proxy=f"http://127.0.0.1:{port}",
                country=_container_country(env) or labels.get(COUNTRY_LABEL, ""),
                source="gluetun" if gluetun else "labelled",
                container=name,
                provider=(
                    _env_value(env, "VPN_SERVICE_PROVIDER").lower()
                    or labels.get(PROVIDER_LABEL, "").lower()
                ),
            )
        )
    return found


def _container_env(container: str) -> list[str]:
    """A container's environment as gluetun was started with it."""
    raw = _docker("inspect", "--format", "{{json .Config.Env}}", container)
    try:
        parsed = json.loads(raw or "[]")
    except ValueError:
        return []
    return [entry for entry in parsed if isinstance(entry, str)]


def _env_value(env: list[str], *keys: str) -> str:
    for key in keys:
        for entry in env:
            if entry.startswith(f"{key}="):
                value = entry.split("=", 1)[1].strip()
                if value:
                    return value
    return ""


def _container_country(env: list[str]) -> str:
    """What to call this exit's place, for a person reading a list.

    A city exit declares SERVER_CITIES and no SERVER_COUNTRIES, so read both.
    This is the label and nothing decides on it; `_declared_countries` is what
    failover compares.
    """
    return _env_value(env, "SERVER_CITIES", "SERVER_COUNTRIES")


#: Entries the last read of the exits file threw out, and why. An exit the
#: user wrote down and cannot use needs an explanation, not an absence.
_rejected_exits: list[str] = []


def load_file_exits() -> list[Exit]:
    """Exits written by hand: SSH tunnels, commercial proxies, anything."""
    global _rejected_exits
    # Cleared on every read, including the early returns: a rejection that
    # outlives the file it came from is a complaint about nothing.
    _rejected_exits = []
    path = exits_file()
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise ExitError(f"{path} could not be read: {exc}") from exc

    entries = data.get("exits", data) if isinstance(data, dict) else data
    exits: list[Exit] = []
    rejected: list[str] = []
    for entry in entries or []:
        if not isinstance(entry, dict) or not entry.get("name") or not entry.get("proxy"):
            continue
        try:
            exits.append(
                Exit(
                    name=str(entry["name"]),
                    proxy=str(entry["proxy"]),
                    country=str(entry.get("country", "")),
                    source="file",
                )
            )
        except ExitError as exc:
            # Skip this one, keep the rest. Remember why, though: dropping it
            # in silence is how the user never learns about the typo.
            rejected.append(f"{entry['name']}: {exc}")
    _rejected_exits = rejected
    return exits


def all_exits() -> list[Exit]:
    """Every known exit, file entries winning a name clash with a container."""
    by_name: dict[str, Exit] = {}
    for found in (*discover_containers(), *load_file_exits()):
        by_name[found.name] = found
    return sorted(by_name.values(), key=lambda e: e.name)


def resolve(selector: str) -> Exit:
    """Find the exit a request means: exact name, then a distinctive fragment."""
    selector = (selector or "").strip()
    if not selector:
        raise ExitError("which exit? name one, or 'direct' for no proxy")

    exits = all_exits()
    if not exits:
        raise ExitError(why_no_exits().rstrip("."))

    lowered = selector.lower()
    for candidate in exits:
        if candidate.name.lower() == lowered:
            return candidate

    # A country name or a fragment is fine when it picks out exactly one.
    partial = [
        c
        for c in exits
        if lowered in c.name.lower() or (c.country and lowered in c.country.lower())
    ]
    if len(partial) == 1:
        return partial[0]
    if partial:
        names = ", ".join(c.label for c in partial)
        raise ExitError(f"{selector!r} matches several exits ({names}); be exact")

    names = ", ".join(c.label for c in exits)
    raise ExitError(
        f"no exit matches {selector!r}; available: {names}. To create one for a place that "
        "has none, use net_open (`hermes vpn open <place>`)"
    )


# -- verification ----------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects instead of following them without the proxy.

    ``HTTPRedirectHandler`` builds a fresh Request for the target and nothing
    re-applies ``set_proxy``, so a lookup service that starts redirecting --
    or a proxy that chooses to -- turns the measurement into this host's own
    egress, reported as the exit's. A service whose entire job is to answer
    one question has no business redirecting, so this is a refusal rather
    than a re-application.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def _opener() -> urllib.request.OpenerDirector:
    """An opener that uses the proxy we name, and no other.

    ``ProxyHandler({})`` registers no scheme handlers, so urllib neither picks
    proxies out of the environment nor consults ``no_proxy``; the proxy goes on
    each request instead, through ``Request.set_proxy``.

    urllib's own ``ProxyHandler`` asks ``proxy_bypass()`` first, and that reads
    ``no_proxy``/``NO_PROXY`` from the environment. With ``no_proxy=*`` set --
    ordinary in corporate networks and in containers -- it connects *direct*
    and says nothing about it. That does not weaken this measurement, it
    inverts it: the host's own address comes back under the exit's name, and
    the armed kill switch admits an exit that is not running.
    """
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


#: What curl should be told, so that the *proxy* resolves the name instead of
#: this host. With plain `socks5` curl looks the name up locally: the DNS
#: query leaks past the tunnel, and `.onion` never resolves at all because no
#: ordinary resolver knows what it is. Only the curl argument is rewritten;
#: the browser keeps the address the user wrote.
_REMOTE_DNS_SCHEMES = {"socks5": "socks5h", "socks4": "socks4a"}


def _curl_proxy(proxy: str) -> str:
    scheme, _, rest = proxy.partition("://")
    return f"{_REMOTE_DNS_SCHEMES.get(scheme, scheme)}://{rest}" if rest else proxy


def _fetch(
    url: str, proxy: str, timeout: int = LOOKUP_TIMEOUT, single: bool = False
) -> tuple[str, str]:
    """(body, error) for *url*, through *proxy*, trying urllib and then curl.

    Two ways to ask, because the lookup services fingerprint the TLS
    handshake and Python's is not a browser's: through a working exit they
    answer urllib 403 or 404 and curl 200. Asking one way only fails closed on
    a healthy exit, which refuses every browser call for no reason.

    A SOCKS proxy gets one way, not two: urllib would send an HTTP CONNECT at
    it and nothing would answer, so the attempt is skipped rather than spent.
    *single* skips it as well, for a caller that is waiting on something slow:
    an onion rendezvous is a minute of waiting and two attempts are two
    minutes, for a question whose whole answer is "did anything come back".
    """
    first = ""
    if not single and not _is_socks(proxy):
        request = urllib.request.Request(url)
        if proxy:
            parsed = urllib.parse.urlsplit(proxy)
            request.set_proxy(parsed.netloc, parsed.scheme)
        try:
            with _opener().open(request, timeout=timeout) as response:
                return response.read().decode("utf-8", "replace"), ""
        except Exception as exc:  # noqa: BLE001, see look()
            first = f"{type(exc).__name__}: {exc}"

    if not shutil.which("curl"):
        return "", first or "no curl on this host to speak SOCKS with"
    # --noproxy "" because curl honours no_proxy even with --proxy set. Without
    # it we go direct and report this host's address as the exit's.
    # `-q` first, and it has to be first: without it curl reads ~/.curlrc,
    # where one `insecure` line turns off the TLS verification that is the
    # only reason a hostile exit cannot choose the address this plugin
    # reports, and one `url =` line appends a second transfer whose `ip=`
    # wins the parse. `vpn-migrate` already writes to that file, so it is an
    # input here, not a user preference.
    command = ["curl", "-q", "-sS", "--noproxy", "", "--max-time", str(timeout)]
    if proxy:
        command += ["--proxy", _curl_proxy(proxy)]
    try:
        done = subprocess.run(command + [url], capture_output=True, text=True,
                              timeout=timeout + 4)
    except (OSError, subprocess.SubprocessError) as exc:
        return "", f"{first}; curl: {type(exc).__name__}"
    if done.returncode == 0 and done.stdout.strip():
        return done.stdout, ""
    said = (done.stderr or "").strip()[:120] or "no output"
    # curl prefixes its own errors with "curl: (7) ...", and prefixing that
    # again reads like a stutter in the one line a reader gets.
    said = said.removeprefix("curl: ")
    # Without a urllib attempt there is no first error, and "; curl: ..." with
    # nothing in front of it reads like something went missing.
    return "", f"{first}; curl: {said}" if first else f"curl: {said}"


#: Carrier-grade NAT. `ipaddress` does not call it private, and a far end
#: cannot be there, so the two places that ask "could this be the outside"
#: have to name it themselves.
CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _is_an_address(value: str) -> bool:
    """Is this a routable address a far end could have reported?

    The liveness criterion was "a non-empty `ip` key", so a service's error
    page, a proxy serving its own JSON, or a verifier printing the word
    "unknown" all satisfied the kill switch. Loopback and private addresses
    are refused too: the far end cannot be 127.0.0.1, and a relay's own
    10.x address is the inside of the tunnel, not the outside.
    """
    try:
        parsed = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    # 100.64.0.0/10 is carrier-grade NAT: not `is_private` in this Python,
    # and not somewhere a far end can be either.
    return not (parsed.is_private or parsed.is_loopback or parsed.is_unspecified
                or parsed.is_link_local or parsed.is_multicast
                or parsed in CGNAT)


def _read_trace(body: str) -> tuple[str, str]:
    """(ip, country) out of Cloudflare's key=value trace body."""
    fields = dict(
        line.split("=", 1) for line in body.splitlines() if "=" in line
    )
    return fields.get("ip", ""), fields.get("loc", "")


def look(proxy: str = "") -> Sighting:
    """Ask the internet what address it sees, optionally through *proxy*."""
    started = time.time()
    if proxy:
        scheme = urllib.parse.urlsplit(proxy).scheme
        if scheme not in {"http", "https"} and not shutil.which("curl"):
            # urllib would send an HTTP CONNECT at it and no SOCKS server
            # answers that, so without curl there is no way to ask. Say it is
            # us rather than blaming their tunnel.
            return Sighting(
                ok=False,
                unverifiable=True,
                detail=(
                    f"a {scheme} proxy cannot be verified without curl: urllib speaks HTTP "
                    "to the proxy and SOCKS does not answer that. The browser could use it, "
                    "but nothing here could confirm where it comes out — install curl, or "
                    "put an HTTP proxy in front of it (privoxy, tinyproxy) and point the "
                    "exit at that"
                ),
                elapsed=time.time() - started,
            )

    # Keep every failure. "ipinfo is down" and "nothing can confirm this exit"
    # are different answers and only the full list tells them apart.
    failures: list[str] = []

    body, error = _fetch(TRACE_URL, proxy) if TRACE_URL else ("", "")
    if body:
        address, code = _read_trace(body)
        if address and not _is_an_address(address):
            failures.append(f"{TRACE_URL}: {address!r} is not a routable address")
        elif address:
            return Sighting(
                ok=True, ip=address, country=code, elapsed=time.time() - started,
            )
        failures.append(f"{TRACE_URL}: no ip in the trace")
    elif error:
        failures.append(f"{TRACE_URL}: {error}")

    for url in LOOKUP_URLS:
        body, error = _fetch(url, proxy)
        if not body:
            failures.append(f"{url}: {error}")
            continue
        try:
            payload = json.loads(body)
        except ValueError as exc:
            failures.append(f"{url}: not JSON ({exc})")
            continue
        if not isinstance(payload, dict):
            # A JSON list or string has no address in it, and `.get` would raise.
            failures.append(f"{url}: the reply was not a JSON object")
            continue

        address = str(payload.get("ip") or payload.get("query") or "")
        if address and not _is_an_address(address):
            failures.append(f"{url}: {address!r} is not a routable address")
            continue
        if not address:
            # Some services answer 200 with an error body (a rate-limit
            # notice, say). An answer without an address is not an answer.
            failures.append(
                f"{url}: "
                + str(payload.get("message") or payload.get("error") or "no address in the reply")
            )
            continue

        return Sighting(
            ok=True,
            ip=address,
            country=str(
                payload.get("country") or payload.get("country_iso") or payload.get("cc") or ""
            ),
            city=str(payload.get("city") or ""),
            elapsed=time.time() - started,
        )

    return Sighting(ok=False, detail="; ".join(failures) or "no service answered",
                    elapsed=time.time() - started)


# -- applying --------------------------------------------------------------


#: Armed, the browser may only leave by an exit, never by this host's own
#: address. Elsewhere this is called a kill switch.
LOCK_ENV = "NET_EXITS_LOCKED"

#: Nothing listens here, deliberately. Pointing the browser at it is how "no
#: exit" becomes "no browsing" instead of "browsing from the server".
DEAD_END_PROXY = "http://127.0.0.1:1"

#: Re-checking the exit before every click would be its own kind of broken.
_CHECK_CACHE_SECONDS = 20
_last_check: tuple[str, float, bool] = ("", 0.0, False)

#: Whether that verdict was "could not be asked" rather than "did not answer".
#: Cached with it, because it is a fact about the exit and not about the call.
_last_unverifiable: bool = False


def locked() -> bool:
    """Is the kill switch armed?

    Total on purpose: the middleware asks this to decide whether to refuse, so
    it must answer rather than raise. An unreadable state file answers True --
    not knowing whether the protection is on is not a reason to act as though
    it is off.
    """
    try:
        state = _read_state()
    except Exception:  # noqa: BLE001 - see the docstring
        return True
    if state is None:
        return True
    if "locked" in state:
        standing = state["locked"]
        if isinstance(standing, bool):
            return standing
        # Only a bool counts. `null`, `0`, `[]` and `""` mean we cannot read
        # the switch, and that ends armed.
        return True
    return (os.environ.get(LOCK_ENV) or "").strip().lower() in {"1", "true", "yes", "on"}


def set_locked(value: bool) -> str:
    _write_state(locked=bool(value))

    if not value:
        sandbox = in_sandbox()
        # Name it. "may now leave directly, if no exit is selected" left the
        # person to work out whether one was, in the moment they reach for
        # this: something is already wrong and they are being told about a
        # permission rather than about their own state.
        on = str((saved_choice() or {}).get("name") or "")
        still = (
            f" The browser is still on {on} and keeps using it — disarming permits leaving "
            "directly, it does not move anything, and `hermes vpn use direct` is the step "
            f"that takes {on} out. Browser calls are no longer held when it stops "
            "answering: they go out through it and fail like a broken page."
            if on else
            " No exit is selected, so the browser leaves by this host's own address from "
            "now on."
        )
        if sandbox:
            # Disarming used to change nothing in here: the sandbox is on an
            # internal network, so there was no "directly" to leave by, and
            # the sentence promised one. Now the seal follows the switch, and
            # a sandbox behaves like the host does.
            return "Kill switch disarmed." + still + open_sandbox(sandbox, direct=True)
        return "Kill switch disarmed." + still

    sandbox = in_sandbox()
    if sandbox:
        return (
            "Kill switch armed. This profile browses from a sandbox, so what is checked is "
            "the sandbox's own way out, confirmed from inside it: if that cannot be "
            "confirmed, browser tools are refused rather than allowed to try."
            + open_sandbox(sandbox, direct=False)
        )

    # Arming it must not leave a gap: with no exit in hand, browsing stops.
    if not current_proxy():
        chosen = saved_choice()
        if chosen and chosen.get("proxy"):
            # Validated here as well. `apply()` goes through `Exit`, which
            # checks; this path read the state file straight into the browser's
            # arguments, and the state file is the input `PROXY_PATTERN`'s own
            # comment names as "not theoretical".
            try:
                saved_proxy = check_proxy(str(chosen["proxy"]))
            except ExitError as exc:
                os.environ[BROWSER_ARGS_ENV] = browser_args(DEAD_END_PROXY)
                return (
                    f"Kill switch armed, and the saved exit was refused ({exc}), so the "
                    "browser points at a dead end until an exit is chosen."
                )
            os.environ[BROWSER_ARGS_ENV] = browser_args(saved_proxy)
            # Nothing asked this exit for an address on this path, so say so.
            # Adopting it quietly and promising it works is a promise about
            # something nobody looked at.
            return (
                f"Kill switch armed, and the browser was put back on the saved exit "
                f"{chosen.get('name', 'unknown')!r} — not checked yet; `hermes vpn where` "
                "confirms it. If that exit stops answering, browser tools are refused "
                "rather than allowed out by this host's own address."
            )
        else:
            os.environ[BROWSER_ARGS_ENV] = browser_args(DEAD_END_PROXY)
            return (
                "Kill switch armed, and no exit is selected — so the browser now points at a "
                "dead end and cannot reach anything until an exit is chosen. That is the "
                "intended behaviour: no exit means no browsing, not browsing from here."
            )
    return (
        "Kill switch armed. The browser will only leave by an exit; if that exit stops "
        "answering, browser tools are refused rather than allowed through this host's own "
        "address. Say so explicitly to disarm it."
    )


#: Armed, a browser call that finds its exit dead moves to another exit in the
#: same country instead of being refused. Off by default: a switch nobody asked
#: for is a surprise, and this one spends a second subscription.
FAILOVER_ENV = "NET_EXITS_FAILOVER"

#: How long after a move before another one may happen. A tunnel that flaps
#: would otherwise walk the browser through every exit it has, once per call.
FAILOVER_COOLDOWN_SECONDS = 60

#: What the last move was, for the sentence the agent reads. Set by the guard
#: and taken by the middleware, because a failover nobody is told about is the
#: silent country change this plugin exists to prevent.
_failover_note: str = ""


def failover_armed() -> bool:
    """Is automatic failover armed?

    Reads like `locked()` and ends the opposite way. An unreadable state file
    answers False: not knowing what was configured is a reason to refuse and
    say so, never a reason to start moving a browser between countries on its
    own.
    """
    try:
        state = _read_state()
    except Exception:  # noqa: BLE001 - total, for the same reason `locked()` is
        return False
    if state is None:
        return False
    if "failover" in state:
        standing = state["failover"]
        return standing if isinstance(standing, bool) else False
    return (os.environ.get(FAILOVER_ENV) or "").strip().lower() in {"1", "true", "yes", "on"}


def standby() -> dict[str, Any]:
    """The exit chosen to take over, or {} when none has been."""
    chosen = (_read_state() or {}).get("standby")
    return chosen if isinstance(chosen, dict) and chosen.get("exit") else {}


def _other_providers() -> list[str]:
    """Providers with credentials here, other than the one in use."""
    here = (_exit_in_use().provider if _exit_in_use() else "")
    try:
        configured = [name for name, _file in configured_providers()]
    except ExitError:
        configured = []
    return [name for name in configured if name and name != here]


def set_standby(name: str) -> str:
    """Name the exit that takes over, after checking it can.

    Checked rather than taken on trust, because a standby that was never
    going to answer is worse than none: it is the one thing everything else
    is counting on, and nobody looks at it until the day it is needed.
    """
    target = resolve(name)
    if target.provider == TOR_PROVIDER:
        raise ExitError(
            "Tor is not a standby. Failover does not enter Tor mode, so it would put the "
            "browser on Tor carrying the cookies of the ordinary session, which is the "
            "linkage Tor mode exists to break. `net_tor_connect` is how to use it, "
            "deliberately."
        )
    in_use = _exit_in_use()
    if in_use and in_use.name == target.name:
        raise ExitError(
            f"{target.name} is the exit in use, so it cannot also be what takes over from "
            "it. Pick one on another provider."
        )
    sighting = look(target.proxy)
    if not sighting.ok:
        raise ExitError(
            f"{target.label} did not answer ({sighting.detail}), so it was not made the "
            "standby. A standby has to be running: bringing a tunnel up takes tens of "
            "seconds and a browser call cannot wait for that."
        )
    _write_state(standby={"exit": target.name, "at": int(time.time())})
    same_provider = in_use and in_use.provider and in_use.provider == target.provider
    note = ""
    if same_provider:
        note = (
            f" Both are {target.provider}, so a subscription that fails takes the standby "
            "with it. Another provider is what covers that."
        )
    elif in_use and in_use.country and target.country and in_use.country != target.country:
        note = (
            f" It is in {target.country} and you are in {in_use.country}: anything that "
            "depends on where you appear changes when it takes over."
        )
    return (
        f"{target.label} is the standby, answering at {sighting.ip} in {sighting.place}."
        + note
    )


def set_failover(value: bool) -> str:
    if not value:
        _write_state(failover=False)
        return (
            "Failover disarmed. A browser call whose exit has stopped answering is refused "
            "again, and the exit stays where it was put. The standby is remembered."
        )

    chosen = standby()
    if not chosen:
        # Nothing to arm around. Rather than arming and promising a move that
        # cannot happen, say what is missing and what the person has to pick.
        here = _exit_in_use()
        others = _other_providers()
        where = f"You are on {here.label}. " if here else ""
        if others:
            return (
                f"{where}Nothing is armed yet: a standby has to be chosen first. You have "
                + ", ".join(others)
                + " configured besides it. Ask which city or country the standby should "
                "come out of — `net_places` lists what a provider offers — then open it "
                "with net_open and name it with net_failover again."
            )
        return (
            f"{where}Nothing is armed yet, and the only provider configured here is the one "
            "in use. A standby on the same subscription does not cover the subscription "
            "failing. Adding another is the person's to do, not this agent's: "
            "`hermes vpn provider <name>` prints exactly what that VPN needs and the file "
            "it goes in, and the credentials are never handled here. If cover for a dead "
            "server is what is wanted rather than cover for a dead subscription, name a "
            "second exit on this provider and it is taken, with that limit stated."
        )

    _write_state(failover=True)
    name = str(chosen.get("exit"))
    if not locked():
        return (
            f"Failover armed with {name} as the standby, but the kill switch is disarmed, "
            "so nothing checks the exit before a browser call and failover will never "
            "fire. Arm the kill switch too (`hermes vpn lock`)."
        )
    return (
        f"Failover armed. If the exit in use stops answering, a browser call moves to "
        f"{name} and says so. If {name} is down as well, the call is refused and the kill "
        "switch holds the browser rather than letting it out by this host's address."
    )


def take_failover_note() -> str:
    """The note about the last automatic move, once."""
    global _failover_note
    note, _failover_note = _failover_note, ""
    return note


def _failover_blocked_by_cooldown() -> str:
    """Why no move may happen yet, or "" when one may."""
    last = (_read_state() or {}).get("failover_at")
    if not isinstance(last, (int, float)):
        return ""
    waited = time.time() - last
    if waited >= FAILOVER_COOLDOWN_SECONDS:
        return ""
    return (
        f"another exit was tried {int(waited)}s ago and failover waits "
        f"{FAILOVER_COOLDOWN_SECONDS}s between moves"
    )


def _last_check_clear() -> None:
    """Forget the cached liveness answer.

    Called whenever the exit changes. Without this the cache outlived the
    switch in both directions: a negative from an outage survived a verified
    switch, so `use` said connected and the next browser call said the exit
    was dead; and a positive survived an exit going down, for up to the cache
    age. The cache is keyed on the proxy, which does not change when the
    *upstream* of a relay does.
    """
    global _last_check
    _last_check = ("", 0.0, False)


def _sandbox_is_answering(container: str, *, max_age: int = _CHECK_CACHE_SECONDS) -> bool:
    """Does the sandbox's own way out answer, asked from inside it?

    Cached in the same slot as the host's check and keyed on the container, so
    a browser call does not pay for `vpn-verify` every time.
    """
    global _last_check
    key = f"sandbox:{container}"
    seen, at, ok = _last_check
    if seen == key and time.time() - at < max_age:
        return ok
    ok = verify_sandbox(container)[0]
    _last_check = (key, time.time(), ok)
    return ok


def exit_is_answering(proxy: str, *, max_age: int = _CHECK_CACHE_SECONDS) -> bool:
    """Is this exit alive? Cached briefly, because this runs before every browser call.

    An empty proxy is never alive. Without that line, `look("")` performs a
    *direct, unproxied* lookup, which succeeds -- so anything that reached this
    function with no exit selected would be told the exit answers and browsing
    would leave by this host's own address. `guard_browser` checks for that
    case before calling here, and mutation testing showed that deleting its
    check leaves every test green: the guarantee rested on one `if` in one
    caller. Now it rests here too.
    """
    if not proxy or proxy == DEAD_END_PROXY:
        return False
    global _last_check
    seen_proxy, seen_at, seen_ok = _last_check
    if seen_proxy == proxy and time.time() - seen_at < max_age:
        return seen_ok
    global _last_unverifiable
    sighting = look(proxy)
    _last_unverifiable = sighting.unverifiable
    _last_check = (proxy, time.time(), sighting.ok)
    return sighting.ok


def _record_failover(dead: str, taken: Exit, where: str) -> None:
    """Remember the move: the cooldown reads it, and `doctor` reports it."""
    _write_state(
        failover_at=int(time.time()),
        last_failover={
            "from": dead,
            "to": taken.name,
            "country": taken.country,
            "provider": taken.provider,
            "where": where,
            "at": int(time.time()),
        },
    )


def _note_the_cooldown() -> None:
    """Start the cooldown after a sweep that moved nothing.

    Without this the cooldown only ever followed a success, so a country whose
    exits have all gone dark paid for the whole sweep again on every browser
    call, with a lookup timeout per candidate. Failing is exactly when not
    trying again for a minute is worth the most.
    """
    try:
        _write_state(failover_at=int(time.time()))
    except ExitError:
        # An unwritable state file is already reported by everything that
        # matters. It must not turn a refusal into an exception.
        pass


def _attempt_failover(dead_name: str, dead_country: str, *, sandbox: str = "") -> tuple[bool, str]:
    """Move to the standby the user chose. Returns (moved, why not).

    No guessing. Earlier this looked for an exit in the same country and
    ordered the candidates by city and provider, which was a lot of
    machinery for a decision the person can make once and mean: a tunnel
    dropping is not the moment to infer where someone wanted to be. The
    standby is named in advance, it is kept running, and if it is down too
    the call is refused and the kill switch does its job.

    The second value is appended to a refusal, so the agent is told why no
    move happened.
    """
    global _failover_note

    chosen = standby()
    if not chosen:
        return False, (
            " Failover is armed but no standby exit has been chosen, so there is nowhere "
            "to go — `net_failover` with a place picks one on another provider."
        )
    blocked = _failover_blocked_by_cooldown()
    if blocked:
        return False, f" Failover is armed but did not move: {blocked}."

    name = str(chosen.get("exit") or "")
    if name.lower() == (dead_name or "").strip().lower():
        return False, (
            f" The standby is {name}, which is the exit that just failed, so there is "
            "nowhere else to go."
        )
    try:
        target = resolve(name)
    except ExitError as exc:
        _note_the_cooldown()
        return False, f" The standby {name} is no longer available ({exc})."

    if sandbox:
        try:
            switch_sandbox(target.name, sandbox)
        except ExitError as exc:
            _note_the_cooldown()
            return False, (
                f" The standby {target.label} did not answer either ({exc}), so this sandbox "
                "stays where it is and the call is refused."
            )
        _failover_note = _moved_note(dead_name, target, "this sandbox was moved")
        _record(dead_name, target, sandbox)
        return True, ""

    # Verify first, de-isolate second. Leaving Tor mode before the standby
    # answered deleted the profile and rewrote the browser arguments, then the
    # refusal below said nothing had changed while the browser sat de-isolated
    # on the dead Tor exit.
    sighting = look(target.proxy)
    if not sighting.ok:
        _note_the_cooldown()
        return False, (
            f" The standby {target.label} did not answer either ({sighting.detail}), so "
            "nothing was changed and the call is refused."
        )
    left_tor = (
        leave_tor_mode() if tor_mode() and target.provider != TOR_PROVIDER else []
    )
    apply(target)
    closed = restart_browser()
    _last_check_clear()
    _failover_note = _moved_note(
        dead_name, target, "the browser was moved",
        extra=f" The far end reports {sighting.ip} in {sighting.place}."
              + (f" Closed {closed} browser process(es)." if closed else "")
        + (f" Tor mode ended first: {'; '.join(left_tor)}." if left_tor else ""),
    )
    _record(dead_name, target, "host")
    return True, ""


def _moved_note(dead: str, target: Exit, what: str, extra: str = "") -> str:
    """The sentence the agent reads about a move it did not ask for."""
    return (
        f"[failover] {dead or 'the exit in use'} stopped answering, so {what} to the standby "
        f"{target.name}"
        + (f" ({target.country})" if target.country else "")
        + (f" on {target.provider}" if target.provider else "")
        + "."
        + extra
    )


def _record(dead: str, taken: Exit, where: str) -> None:
    try:
        _record_failover(dead, taken, where)
    except ExitError:
        global _failover_note
        _failover_note += " The move could not be written to the state file."


def guard_browser(tool_name: str, call_args: Any = None) -> str:
    """Why this browser call must not happen, or "" when it may.

    Two concerns meet here. The first is the kill switch, below. The first
    check is not about security at all: a browser sent to an onion whose
    rendezvous does not exist yet waits, and then reports a timeout that reads
    like a broken site. Holding that call and saying what to do instead costs
    a second and saves the minute the browser would have spent failing.

    The kill switch doing its job: Chromium pointed at a dead proxy
    would fail anyway, but it would fail *after* the agent decided to go
    somewhere, with an error that reads like a broken site. Refusing here says
    what actually happened.
    """
    if not str(tool_name).startswith("browser_"):
        return ""

    # Not `tor_mode()` alone. The question is whether Hermes' own refusal of
    # internal addresses is off, and the mode turns it off by writing a line
    # into the profile config under a marker. A path that leaves that line
    # behind while the state says the mode is off -- a sandbox `net_use`, a
    # `close_exit`, a state write that drops the key -- would otherwise take
    # both guards down at once. The marker is there as long as the line is,
    # so gate on it too.
    if tor_mode() or PRIVATE_URLS_MARK in _read_profile_config():
        # Hermes' own check is off and this one is what is left. It says no
        # to the destinations that check existed for.
        local = _private_destination(call_args)
        if local:
            return (
                f"Refused: {local}, and Tor mode has turned off the browser's own refusal "
                "of internal addresses so that onion names can resolve. Nothing on this "
                "machine is reachable through Tor anyway."
            )

    onion = _onion_in(call_args)
    if onion and _onion_is_warm(onion):
        # The browser is about to use it, which is better evidence than the
        # last check: without this the clock ran from the warm-up and the
        # hold fired at someone who had been reading that page for ten
        # minutes.
        _warm_onions[onion] = time.time()
    elif onion:
        # Whether or not the kill switch is armed: this is about a request
        # that is going to fail, not about where the browser leaves from.
        here = tor_exit()
        if here is None or (current_proxy() != here.proxy and not in_sandbox()):
            return (
                f"Held: {onion} is an onion address and this browser is not going through "
                "Tor, so the name cannot resolve at all. `net_tor_connect` with that "
                "address switches to the Tor exit, waits for the circuit and says when it "
                "is up."
            )
        seen_before = onion in _warm_onions
        if seen_before:
            return (
                f"Held: the circuit to {onion} was last confirmed more than "
                f"{ONION_WARM_SECONDS // 60} minutes ago, and this plugin does not know "
                "whether it is still up. `net_tor_connect` with that address checks in a "
                "second or two if it is, and waits if it is not — cheaper than the minute "
                "the browser would spend timing out."
            )
        return (
            f"Held: nothing has reached {onion} through Tor yet, and a first connection to "
            "an onion service can take a minute — long enough that the browser would give "
            "up and report it as a broken site. Call `net_tor_connect` with that address "
            "first; it waits for the circuit and says when the page can be opened."
        )

    if not locked():
        return ""

    # In a sandbox the way out is the managed policy inside the container, not
    # AGENT_BROWSER_ARGS. Judge by the host's proxy here and we get it wrong
    # both ways: refuse every call for an exit nothing in a sandbox can choose,
    # or wave one through on a proxy that browser never reads.
    sandbox = in_sandbox()
    if (
        not sandbox
        and _sandbox_listing_silent
        and current_profile() in _configured_sandbox_profiles()
    ):
        # Only when something says this profile is sandboxed. Docker being
        # unreachable is ordinary on a host that has none, and refusing there
        # would hold every browser call for a setup that never had a sandbox.
        # The config is a weak reading, which is why it is allowed to make
        # this more careful and not less.
        return (
            f"Refused: the kill switch is armed, {_sandbox_listing_silent}, and this "
            "profile's config says its browser runs in one. Judging it by the host's proxy "
            "would be judging a browser it does not have. `hermes vpn doctor` checks the rest."
        )
    if sandbox:
        if _sandbox_is_answering(sandbox):
            return ""
        why = ""
        # No verifier means switch_sandbox can confirm nothing, so every
        # candidate would be tried, rolled back and reported as dead. That is
        # a long way to say what `doctor` says in one line.
        if failover_armed() and os.path.exists(VERIFY_HELPER):
            chosen = saved_choice() or {}
            moved, why = _attempt_failover(
                str(chosen.get("name") or ""), "", sandbox=sandbox
            )
            if moved:
                return ""
        return (
            f"Refused: the kill switch is armed and the sandbox {sandbox} could not confirm "
            "its way out just now. It is held rather than allowed to try — `hermes vpn "
            "where` says what the sandbox can see, and `hermes vpn use <place>` re-selects."
            + why
        )

    proxy = current_proxy()
    if not proxy or proxy == DEAD_END_PROXY:
        return (
            "Refused: the kill switch is armed and no exit is selected, so browsing would "
            "go out by this host's own address. Choose an exit first, or disarm the kill "
            "switch deliberately."
        )
    if not exit_is_answering(proxy):
        why = ""
        # Armed, and only for an exit that answered "no" rather than "could
        # not be asked". A SOCKS exit is unverifiable by design, and a shared
        # address being rate-limited by the lookup endpoint reads the same
        # way: swapping a working exit out from under the agent on that
        # evidence is the silent change this feature exists to prevent.
        #
        # Both conditions are also what keeps the default path cheap. Nothing
        # above this line asks docker anything, and with failover off that
        # stays true.
        if failover_armed() and not _last_unverifiable:
            chosen = saved_choice() or {}
            moved, why = _attempt_failover(str(chosen.get("name") or ""), "")
            if moved:
                return ""
        if _last_unverifiable:
            # Cached with the answer: it describes the exit, not this call.
            return (
                f"Refused: the exit at {proxy} cannot be checked from here. The kill switch "
                "is armed, so the browser is held rather than allowed out by this host's "
                "own address. An exit this plugin cannot confirm is not one it will trust."
                + why
            )
        return (
            f"Refused: the exit at {proxy} has stopped answering. The kill switch is armed, "
            "so the browser is held rather than allowed out by this host's own address. "
            "Check the tunnel, or pick another exit."
            + why
        )
    return ""


#: Keeps WebRTC off the network. A proxy only carries TCP, so WebRTC's UDP
#: walks straight out of the host: the page sees your real IPv4 and IPv6 while
#: its HTTP request looks like it came from the exit.
#:
#: Note the name has no `force-` prefix. `--force-webrtc-ip-handling-policy` is
#: the spelling everyone quotes and Chrome 145 doesn't have it. Unknown
#: switches are dropped in silence, so that one protects nothing.
#:
#: Named once here because the same value also goes in the managed-policy
#: file, and the two must not drift.
WEBRTC_SETTING = "disable_non_proxied_udp"
WEBRTC_ARG = f"--webrtc-ip-handling-policy={WEBRTC_SETTING}"


def browser_args(proxy: str = "") -> str:
    args = list(BASE_BROWSER_ARGS)
    if proxy:
        args.append(f"--proxy-server={proxy}")
        args.append(WEBRTC_ARG)
    mode = tor_mode()
    if mode and proxy:
        # A profile of its own, so nothing crosses between what Tor sees and
        # the ordinary session, and no script, which is what Tor Browser's
        # safest level does and for the same reasons.
        args.append(f"--user-data-dir={TOR_PROFILE_DIR}")
        if not mode.get("javascript"):
            args.append(NO_JS_ARG)
    return ",".join(args)


def current_proxy() -> str:
    """The proxy the next browser launch would use, read back from the args."""
    for arg in (os.environ.get(BROWSER_ARGS_ENV) or "").split(","):
        if arg.startswith("--proxy-server="):
            return arg.split("=", 1)[1]
    return ""


def apply(exit_: Exit | None) -> None:
    """Point the next browser launch at *exit_* (or nowhere), and remember it.

    This writes ``AGENT_BROWSER_ARGS`` into the running process's environment,
    which is how Hermes passes arguments to the browser it launches. Mutating
    the environment is not something a plugin should do lightly -- it is done
    here because that variable *is* the documented knob for the browser, it is
    read fresh at every launch, and there is no other way to change the exit
    without restarting the gateway.
    """
    # Save first, then move the browser. `_save_state` raises on an unwritable
    # home, and this way the browser stays put instead of sitting on an exit we
    # have no record of.
    _save_state(exit_)
    os.environ[BROWSER_ARGS_ENV] = browser_args(exit_.proxy if exit_ else "")
    _last_check_clear()


def _read_state() -> dict[str, Any] | None:
    """The saved state, or None when it exists and could not be read.

    None and ``{}`` are opposite answers and the difference is the whole
    protection. ``{}`` means nothing was ever chosen; None means the file is
    there and unreadable -- a truncated write, a full disk, a permission
    change, a half-restored backup, one stray shell redirect. This used to
    return ``{}`` for both, so a single corrupt byte disarmed the kill switch
    and ``doctor`` reported it as a deliberate choice ("· kill switch
    disarmed"), which is the one thing that stops anyone from looking.
    """
    path = state_file()
    try:
        if not path.exists():
            return {}
        parsed = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _write_state(**changes: Any) -> None:
    """Update the state file in place, keeping what we are not changing.

    State and cache are kept apart on purpose: the places cache is disposable
    and someone will delete it to force a refresh. A security setting that
    vanished with it would be a trap.
    """
    path = state_file()
    # Don't merge onto a file we couldn't read: that carries the garbage over,
    # or drops `locked`. Starting fresh loses the saved exit, which is the safe
    # way to lose it (no exit while armed is a dead end, not a leak) and lets
    # `lock` repair the file.
    current = _read_state()
    if current is None:
        # Unreadable is armed, in the file as well as in `locked()`. Starting
        # from {} rebuilt a valid file with no `locked` key, so the next
        # ordinary `use` -- a successful one, with a cheerful answer --
        # silently disarmed the kill switch and `doctor` then reported it as
        # somebody's choice.
        current = {"locked": True}
    payload = {**current, "version": 1, **changes, "at": int(time.time())}
    tmp = path.with_suffix(".tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(payload, indent=2))
        os.replace(tmp, path)
    except OSError as exc:
        # Raise. Callers arming the switch need to know the write landed.
        raise ExitError(f"the state at {path} could not be written: {exc}") from exc


def _save_state(exit_: Exit | None) -> None:
    _write_state(
        chosen=None
        if exit_ is None
        else {
            "name": exit_.name,
            "proxy": exit_.proxy,
            "country": exit_.country,
            # Kept for failover: when the container is gone, `docker ps` can no
            # longer say what this exit was, and preferring another provider is
            # exactly what it has to know.
            "provider": exit_.provider,
        }
    )


def saved_choice() -> dict[str, Any] | None:
    # `or {}`: an unreadable state has no saved choice to offer. Returning
    # None here is what keeps `lock` from re-applying a proxy it cannot read.
    chosen = (_read_state() or {}).get("chosen")
    return chosen if isinstance(chosen, dict) else None


def reapply_saved_choice() -> str:
    """Re-apply the remembered exit at load time, without touching the network.

    A restart rebuilds the environment, so without this the agent would quietly
    go back to leaving by the host's own address.

    It deliberately does **not** verify the exit first, for two reasons. Hermes
    gives a plugin ten seconds to import and register, and a lookup through a
    sulky exit can take longer than that -- a plugin that misses the deadline is
    dropped, taking its tools and commands with it. And the unverified choice is
    the safer one anyway: pointing at a dead proxy makes navigation fail loudly,
    while skipping it sends the browser out by the host's own address with
    nobody the wiser. Verification happens when a tool is actually used.
    """
    chosen = saved_choice()
    if not chosen or not chosen.get("proxy"):
        if locked():
            # Armed with nothing to apply, so point at the dead end instead of
            # letting the browser come back up on this host.
            os.environ[BROWSER_ARGS_ENV] = browser_args(DEAD_END_PROXY)
            return "kill switch armed with no exit saved: browsing is blocked until one is chosen"
        return ""
    apply(
        Exit(
            name=str(chosen.get("name", "")),
            proxy=str(chosen["proxy"]),
            country=str(chosen.get("country", "")),
        )
    )
    return f"re-applied exit {chosen.get('name')!r} (not checked yet)"


# -- the browser -----------------------------------------------------------


def _browser_binaries() -> list[str]:
    explicit = os.environ.get("AGENT_BROWSER_EXECUTABLE_PATH")
    if explicit:
        return [explicit]
    return [str(p) for p in sorted(hermes_home().glob("tools/chromium-*/chrome-linux64/chrome"))]


def browser_processes() -> list[int]:
    """The agent's own browser, by its bundled binary, parents only.

    Matching the bundled path keeps a person's own Chromium out of it, and
    skipping ``--type=`` leaves the renderer and zygote children alone: killing
    the parent takes them with it.
    """
    binaries = _browser_binaries()
    if not binaries:
        return []
    try:
        done = subprocess.run(
            ["ps", "-eo", "pid=,args="], capture_output=True, text=True, timeout=10
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return []

    pids: list[int] = []
    for line in done.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        pid_text, _, args = line.partition(" ")
        if "--type=" in args:
            continue
        if not any(binary in args for binary in binaries):
            continue
        try:
            pids.append(int(pid_text))
        except ValueError:
            continue
    return pids


def restart_browser(grace: float = 3.0) -> int:
    """Close the running browser so the next launch takes the new exit.

    Hermes launches the browser on demand and lets it idle out, and there is no
    tool to close it, so this asks the process to quit and waits briefly before
    insisting. Returns how many actually went away.
    """
    pids = browser_processes()
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass

    deadline = time.time() + grace
    while time.time() < deadline and browser_processes():
        time.sleep(0.2)

    for pid in browser_processes():
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    # Look again instead of trusting the list we signalled. Both kills swallow
    # PermissionError, so a process we can't touch is still holding the old
    # exit and must not count as closed.
    left = browser_processes()
    # Clamp: a browser that started during the grace window makes `left` bigger.
    return max(0, len(pids) - len(left))


# -- the operation the agent asks for --------------------------------------


def _tor_without_the_mode(target: Exit) -> str:
    """Said when the Tor exit is selected by hand, on either path.

    The exit without the mode is what the README calls theatre: the session
    that was there is still there, and a site that recognises it knows who
    it is talking to whatever address the request arrived from. Both paths
    say it, because a sentence only the host profile gets is a sentence the
    bots never see.
    """
    if target.provider != TOR_PROVIDER or tor_mode():
        return ""
    return (
        " This is the Tor exit, but Tor mode is off: the browser keeps the cookies and the "
        "session it already had, JavaScript is on, and an onion name still will not "
        "resolve. `net_tor_connect` is the way to use Tor properly — it clears the session "
        "first and waits for the circuit."
    )


def switch(selector: str, *, restart: bool = True) -> str:
    """Verify an exit, point the browser at it, and say what the world sees.

    Nothing is changed until the exit answers: a switch that silently leaves
    the browser on the host's address is the failure this guards against.

    Which browser depends on where this agent lives. In a profile whose
    terminal is a container, the browser is in there with it, behind a sealed
    network, and the exit is moved by repointing the relay rather than by
    changing an argument on the host.
    """
    sandbox = in_sandbox()
    if sandbox:
        return switch_sandbox(selector, sandbox)

    if (selector or "").strip().lower() == DIRECT:
        if locked():
            raise ExitError(
                "the kill switch is armed, so the browser may not leave directly. Disarm it "
                "first if that is really what you want: `hermes vpn lock --off`, or "
                "net_lock with armed=false."
            )
        leave_tor_mode()
        apply(None)
        closed = restart_browser() if restart else 0
        here = look()
        word = "process" if closed == 1 else "processes"
        # Say a failed check out loud, or this sentence reads the same whether
        # we confirmed the address or never got one.
        where = (
            f", seen as {here.ip} ({here.place})" if here.ok
            else f", though the check did not confirm where ({here.detail})"
        )
        return (
            "Proxy off: the browser now leaves directly"
            + where
            + (f". Closed {closed} browser {word}." if closed else ".")
        )

    target = resolve(selector)
    # Verify before leaving Tor mode, not after. Leaving it deletes the Tor
    # profile, takes the config line out and rewrites the browser arguments;
    # doing that first and then refusing on a dead standby left the browser
    # de-isolated on the old exit while the message said nothing had changed.
    sighting = look(target.proxy)
    if not sighting.ok:
        raise ExitError(
            (
                f"exit {target.label} cannot be checked from here ({sighting.detail}), so "
                "nothing was changed"
                if sighting.unverifiable else
                f"exit {target.label} did not answer ({sighting.summary}), so nothing was "
                "changed and the browser keeps its current exit. If that exit should be up, "
                "`hermes vpn list` shows what is running and `hermes vpn doctor` prints what "
                "each lookup said"
            )
        )

    left = (
        leave_tor_mode()
        if tor_mode() and target.provider != TOR_PROVIDER
        else []
    )
    apply(target)
    closed = restart_browser() if restart else 0
    note = ""
    if closed:
        word = "process" if closed == 1 else "processes"
        note = f" Closed {closed} browser {word}, so the next page loads through it."
    labelled = f", which the provider labels {target.country}" if target.country else ""
    bare_tor = _tor_without_the_mode(target)
    ended = f" Tor mode ended: {'; '.join(left)}." if left else ""
    # The standby was chosen in front of another exit. Saying it on every
    # switch is how a choice made once stays a choice made knowingly.
    kept = standby().get("exit") or ""
    standing = (
        f" The standby is still {kept}, which is where failover would take you from here."
        if kept and failover_armed() and kept != target.name
        else ""
    )
    return (
        f"Now leaving by {target.name}: the far end reports {sighting.ip} in "
        f"{sighting.place}{labelled}. Checked in {sighting.elapsed:.1f}s."
        f"{bare_tor}{note}{ended}{standing}"
    )


#: A root-owned helper that creates and removes exits. It exists so the agent
#: can ask for a country without being handed the VPN credentials; see
#: contrib/vpn-exit.
HELPER_ENV = "NET_EXITS_HELPER"
DEFAULT_HELPER = "/usr/local/sbin/vpn-exit"
#: Longer than the helper's worst case: `vpn-exit up --auto` waits
#: READY_TIMEOUT on a country and then again on a city. Give up early and we
#: only kill the direct child, so the root-owned attempt keeps going and the
#: exit shows up later with nobody expecting it.
OPEN_TIMEOUT = 200


def helper() -> str:
    return os.environ.get(HELPER_ENV) or DEFAULT_HELPER


#: What may be handed to a root-owned helper as a positional argument. No
#: leading dash, because the helper parses options anywhere on its line, and
#: nothing exotic: these come from tool arguments and from docker output,
#: and the helper's own validation should be the second check, not the only
#: one.
#: The only options the helper takes. Allow-listed by exact value: an earlier
#: version waved through anything starting with `--`, which is how a profile
#: named `--city` (from a crafted HERMES_HOME) reached the helper as a flag
#: and moved the shared relay. A flag the helper does not know is refused.
HELPER_FLAGS = frozenset({"--city", "--provider"})

#: A positional helper argument: a verb, an exit name, a place or a profile.
#: Unicode letters are allowed because gluetun's own place names include
#: Zürich and São Paulo, which the helper accepts under a UTF-8 locale and
#: `net_places` prints verbatim; the ASCII-only version refused them before
#: the helper ever saw them. It must not begin with a dash (the helper would
#: read it as an option) or a space, holds no control character, and is long
#: enough for the longest name the helper mints: `exit-` + a 31-char provider
#: + `-` + a 41-char place is 78, where the old cap of 64 orphaned a tunnel
#: that could be opened and then neither closed nor selected.
HELPER_ARG = re.compile(r"[^\W_][\w .'-]{0,127}\Z", re.UNICODE)


def _run_helper(*args: str) -> str:
    """Call the helper through sudo, and turn its failures into plain sentences."""
    for argument in args:
        if argument in HELPER_FLAGS or HELPER_ARG.match(argument):
            continue
        raise ExitError(
            f"{argument[:40]!r} is not something to hand a root-owned helper: a known "
            "option, or a name, place or profile that does not begin with a dash."
        )
    try:
        done = subprocess.run(
            ["sudo", "-n", helper(), *args],
            capture_output=True,
            text=True,
            timeout=OPEN_TIMEOUT,
        )
    except FileNotFoundError as exc:
        raise ExitError(f"this host cannot run the helper without sudo ({exc})") from exc
    except subprocess.TimeoutExpired as exc:
        raise ExitError(
            f"the tunnel did not come up within {OPEN_TIMEOUT}s; it may still be starting"
        ) from exc

    if done.returncode != 0:
        detail = (done.stderr or done.stdout or "").strip().splitlines()
        reason = detail[-1] if detail else f"exit code {done.returncode}"
        if "a password is required" in reason or "is not allowed to execute" in reason:
            reason = (
                f"this account may not run {helper()} through sudo — see the plugin's "
                "contrib/vpn-exit for the rule it needs"
            )
        raise ExitError(reason)
    return (done.stdout or "").strip()


#: gluetun ships every provider's server list inside the container, so one
#: running exit can answer "where could I go with Mullvad?" as readily as about
#: the provider it is using. The answer is the provider's to give, not ours to
#: guess.
CATALOGUE_DIR = "/gluetun/servers"


def places_cache() -> Path:
    return hermes_home() / "net-exits-places.json"


def _any_running_exit() -> Exit | None:
    return next(iter(discover_containers()), None)


def providers() -> list[str]:
    """Every provider gluetun carries a server list for."""
    cached = _load_cache().get("providers_list") or []
    exit_ = _any_running_exit()
    if exit_ is None:
        if cached:
            return cached
        raise ExitError(
            "the provider lists live inside a gluetun container and none is running; "
            "start one exit and ask again"
        )
    listing = _docker("exec", exit_.container, "ls", CATALOGUE_DIR, timeout=20)
    names = sorted(
        line[:-5] for line in listing.split() if line.endswith(".json") and line != "manifest.json"
    )
    if names:
        cache = _load_cache()
        cache["providers_list"] = names
        _save_cache(cache)
    return names or cached


def _load_cache() -> dict[str, Any]:
    path = places_cache()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def _save_cache(data: dict[str, Any]) -> None:
    path = places_cache()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def catalogue(provider: str = "", refresh: bool = False) -> dict[str, Any]:
    """The places one provider offers, read from a running exit or the last copy."""
    cache = _load_cache()
    stored = cache.get("providers", {})

    provider = (provider or "").strip().lower()
    if not provider:
        exit_ = _any_running_exit()
        provider = (exit_.provider if exit_ else "") or cache.get("default", "")
    if not provider:
        raise ExitError(
            "which provider? no exit is running to infer one from — name one, or start any "
            "exit once and every provider's list becomes available (it is cached after "
            "that, so it keeps answering when nothing is running)"
        )

    if not refresh and provider in stored:
        return {"provider": provider, **stored[provider]}

    exit_ = _any_running_exit()
    if exit_ is None:
        if provider in stored:
            return {"provider": provider, **stored[provider]}
        raise ExitError(
            f"the list for {provider} lives inside a gluetun container and none is "
            "running; start one exit and ask again"
        )

    if not re.fullmatch(r"[a-z0-9-]{1,32}", provider):
        # It is a path segment one line below. `guide()` has always done
        # this; this one did not.
        raise ExitError(f"{provider[:40]!r} is not a provider name")
    raw = _docker("exec", exit_.container, "cat", f"{CATALOGUE_DIR}/{provider}.json", timeout=20)
    if not raw:
        known = ", ".join(providers())
        raise ExitError(f"gluetun carries no server list for {provider!r}; it has: {known}")
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise ExitError(f"the server list for {provider} could not be read ({exc})") from exc
    # gluetun always hands back an object with a "servers" array, but guard the
    # shape so a format change is a sentence, not an AttributeError traceback.
    servers = data.get("servers", []) if isinstance(data, dict) else []

    found = {
        "countries": sorted({s.get("country", "") for s in servers if isinstance(s, dict) and s.get("country")}),
        "cities": sorted(
            [list(pair) for pair in {(s.get("country", ""), s.get("city", "")) for s in servers if isinstance(s, dict) and s.get("city")}]
        ),
        "at": int(time.time()),
    }
    stored[provider] = found
    cache["providers"] = stored
    cache.setdefault("default", provider)
    _save_cache(cache)
    return {"provider": provider, **found}


#: Setup guides shipped with the plugin, so "what do I need for AirVPN?" is
#: answerable without reaching the network. See providers/NOTICE.md.
GUIDES_DIR = Path(__file__).resolve().parent / "providers"

#: Spellings people use that are not the file names.
_GUIDE_ALIASES = {
    "pia": "private-internet-access",
    "privateinternetaccess": "private-internet-access",
    "proton": "protonvpn",
    "protonmail": "protonvpn",
    "nord": "nordvpn",
    "express": "expressvpn",
    "pure": "purevpn",
    "vpnsecure": "vpn-secure",
    "vpnunlimited": "vpn-unlimited",
    "perfectprivacy": "perfect-privacy",
    "hma": "hidemyass",
    "air": "airvpn",
}


def guides() -> list[str]:
    """Providers with a setup guide shipped here."""
    if not GUIDES_DIR.is_dir():
        return []
    return sorted(p.stem for p in GUIDES_DIR.glob("*.md") if p.stem != "NOTICE")


#: Sections of the shipped gluetun wiki page a plugin user does not need, dropped
#: from what `guide()` prints. The TLDR is docker/compose commands that OMIT the
#: HTTPPROXY/loopback settings this plugin requires, so copying it misleads; the
#: server list is long and `net_places` answers it.
_GUIDE_DROP_SECTIONS = {"tldr", "servers"}


def _trim_guide(text: str) -> str:
    """Keep the parts that say where in the provider's dashboard to get the values,
    and drop the docker/compose TLDR and the server list."""
    out: list[str] = []
    dropping = False
    for line in text.splitlines():
        if line.startswith("## "):
            dropping = line[3:].strip().lower() in _GUIDE_DROP_SECTIONS
        if not dropping:
            out.append(line)
    return "\n".join(out).strip()


def guide(provider: str) -> str:
    """The setup page for one provider: what to configure and where to get it."""
    wanted = re.sub(r"[^a-z0-9-]+", "", (provider or "").strip().lower())
    if not wanted:
        raise ExitError("which provider? " + ", ".join(guides()))

    wanted = _GUIDE_ALIASES.get(wanted.replace("-", ""), wanted)
    available = guides()
    if not available:
        raise ExitError(f"no setup guides are installed at {GUIDES_DIR}")

    if wanted not in available:
        # Close matches, then substrings: "mulvad" needs one, "nordvpnn" the other.
        near = difflib.get_close_matches(wanted, available, n=3, cutoff=0.6)
        near += [name for name in available if wanted and wanted in name and name not in near]
        hint = f" Did you mean: {', '.join(near[:3])}?" if near else ""
        raise ExitError(
            # Our guide files, not gluetun's providers. `custom` is a mode.
            f"no guide for {provider!r}. Guides shipped here: {', '.join(available)}.{hint}"
        )

    body = _trim_guide((GUIDES_DIR / f"{wanted}.md").read_text())
    return (
        f"To set up {wanted}:\n"
        f"1. In {wanted}'s own dashboard, generate a WireGuard config: a private key "
        "and an address. The exact steps for this provider are under \"Required "
        "environment variables\" below.\n"
        "2. Store it on the host, without the key ever passing through this chat. Either:\n"
        f"   - at a terminal (the dashboard's Terminal tab works from a phone too): run "
        f"`hermes vpn provider {wanted} --set`, then paste the config and press Ctrl-D; or\n"
        "   - if you already keep secrets in `pass`/gopass or a file, give a reference "
        f"and the agent can do it for you: `hermes vpn provider {wanted} --from-ref "
        f"pass:vpn/{wanted}` (or `--from-ref file:/path/to/{wanted}.conf`).\n"
        f"   Either way it writes the root-only /root/vpn-exits/{wanted}.env; the agent "
        "never sees the key. Never paste the key into the chat.\n"
        "3. Then `hermes vpn open <country>` brings up the exit and verifies it.\n"
        "You do not need the docker or compose commands; `hermes vpn open` builds the "
        "container for you.\n\n"
        f"--- {wanted} reference (from the gluetun wiki, MIT; shipped with this plugin, "
        "see providers/NOTICE.md) ---\n"
        f"{body}\n\n---\n"
        "Note: this plugin needs two settings these pages do not mention: HTTPPROXY on, "
        "and the proxy port published on 127.0.0.1. `hermes vpn open` writes both, and "
        "`hermes vpn doctor` names them if a container you composed yourself lacks them."
    )


def find_places(search: str = "", provider: str = "", limit: int = 40) -> str:
    """Answer 'where could I go' -- matching places, or a summary when asked nothing."""
    data = catalogue(provider)
    name = data.get("provider", "the provider")
    countries: list[str] = data.get("countries", [])
    cities: list[list[str]] = data.get("cities", [])

    search = (search or "").strip().lower()
    if not search:
        # `limit` bounds the summary as well as the hits. The model pays for every
    # name we print, and an empty query matches a hundred countries.
        shown = ", ".join(countries[:limit])
        more = f", and {len(countries) - limit} more" if len(countries) > limit else ""
        return (
            f"{name} offers {len(countries)} countries and {len(cities)} cities.\n"
            f"Countries: {shown}{more}\n"
            "Ask with a search term for the cities of one of them, or for the rest of the list."
        )

    hit_countries = [c for c in countries if search in c.lower()]
    hit_cities = [
        f"{city} ({country})"
        for country, city in cities
        if search in city.lower() or search in country.lower()
    ]
    if not hit_countries and not hit_cities:
        return (
            f"{name} has nothing matching {search!r}. It covers {len(countries)} countries; "
            "ask without a search term to see them, or name another provider."
        )

    lines = []
    if hit_countries:
        lines.append(f"Countries on {name}: " + ", ".join(hit_countries[:limit]))
    if hit_cities:
        lines.append("Cities: " + ", ".join(hit_cities[:limit]))
    return "\n".join(lines)


def suggest_places(place: str) -> str:
    """Names close to one the provider rejected, for the failure message."""
    try:
        data = catalogue()
    except ExitError:
        return ""
    needle = (place or "").strip().lower()[:4]
    if not needle:
        return ""
    near = [c for c in data.get("countries", []) if needle in c.lower()]
    near += [city for _country, city in data.get("cities", []) if needle in city.lower()]
    return ", ".join(sorted(set(near))[:8])


#: Where Chrome for Testing reads managed policy. Get it exactly right:
#: /etc/opt/chrome, /etc/opt/chrome-for-testing and /etc/chromium are all
#: ignored in silence, and so is the old policy name WebRtcIPHandlingPolicy.
CHROME_POLICY_FILE = Path(
    os.environ.get("NET_EXITS_CHROME_POLICY")
    or "/etc/opt/chrome_for_testing/policies/managed/hermes-vpn-webrtc.json"
)


#: The proxy the sandbox's browsers use. They read it from the managed policy
#: and nowhere else, no env var involved. The alias is the relay's and never
#: moves (a country switch changes the relay's upstream, not this), so a repair
#: can write it without knowing which country is selected.
SANDBOX_PROXY = os.environ.get("NET_EXITS_SANDBOX_PROXY") or "http://vpn-exit:8888"

#: Same filename `contrib/vpn-migrate` uses, on purpose. Chrome merges every
#: file in that directory, so a second name would leave two mandatory
#: ProxySettings in there and let the merge order pick our exit.
SANDBOX_POLICY_NAME = "vpn.json"


def sandbox_policy_body(proxy: str = "") -> str:
    """The policy a sealed sandbox needs in order to have an exit at all."""
    return json.dumps(
        {
            "ProxyMode": "fixed_servers",
            "ProxyServer": proxy or SANDBOX_PROXY,
            "ProxyBypassList": "",
            "WebRtcIPHandling": WEBRTC_SETTING,
            "DnsOverHttpsMode": "off",
        },
        # Byte-for-byte what contrib/vpn-migrate writes, so a repaired sandbox
        # and a migrated one are the same file and a diff of the two is empty.
        separators=(",", ":"),
    )


def sandbox_direct_policy_body() -> str:
    """The policy for a sandbox that is allowed out on its own.

    Written when the kill switch is disarmed, so that a browser whose exit is
    gone behaves the way it does on the host: it browses, by this machine's
    address, because that is what disarming means. WebRTC stays pinned either
    way -- it is about what a page can read, not about where the traffic
    goes.
    """
    return json.dumps(
        {
            "ProxyMode": "direct",
            "WebRtcIPHandling": WEBRTC_SETTING,
            "DnsOverHttpsMode": "off",
        },
        separators=(",", ":"),
    )


#: The network a sandbox is put on to have a way out of its own. Docker's
#: default bridge, because it is the one that exists everywhere and nothing
#: else uses it here.
OPEN_NETWORK = "bridge"


def _sandbox_network(container: str, give_it_one: bool) -> tuple[bool, str]:
    """Attach the sandbox to a network of its own, or take that away.

    Sealing is docker's job and it is absolute: on an internal network there
    is no route off this host whatever the browser is configured with. That
    is the strongest guarantee here, and it is also why disarming the kill
    switch used to change nothing inside a sandbox -- there was nothing to
    disarm into.

    So the seal follows the switch. Armed: internal only. Disarmed: a bridge
    as well, which is what makes going direct possible at all. The cost is
    written down rather than hidden -- while disarmed, what keeps that
    browser inside the tunnel is this plugin's state and not docker's
    refusal, and a gateway that dies while disarmed leaves it attached.
    `doctor` reports it.
    """
    if not container:
        return True, ""
    # Asked, not inferred from docker's wording. Matching "is not connected"
    # in the error text meant that a disconnect of something already
    # disconnected reported "could not be sealed again ()", with an empty
    # reason, while the sandbox was in exactly the state wanted.
    on = set(
        _docker(
            "inspect", container, "-f",
            "{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}",
        ).split()
    )
    if give_it_one == (OPEN_NETWORK in on):
        return True, ""
    verb = "connect" if give_it_one else "disconnect"
    ok, said = _docker_try("network", verb, OPEN_NETWORK, container, timeout=20)
    return ok, said.strip()[:80]


def write_sandbox_policy(container: str, direct: bool) -> str:
    """Point the browser in *container* at the exit, or at nothing."""
    body = sandbox_direct_policy_body() if direct else sandbox_policy_body()
    path = CHROME_POLICY_FILE.parent / SANDBOX_POLICY_NAME
    script = (
        f"mkdir -p {shlex.quote(str(CHROME_POLICY_FILE.parent))} && "
        f"printf '%s\\n' {shlex.quote(body)} > {shlex.quote(str(path))} && "
        f"chmod 644 {shlex.quote(str(path))}"
    )
    ok, said = _docker_try("exec", "-u", "root", container, "sh", "-c", script, timeout=30)
    _close_sandbox_browser(container)
    return "" if ok else said.strip()[:80]


def open_sandbox(container: str, direct: bool) -> str:
    """What the kill switch does to a sandbox, and only that.

    Disarming **permits** going direct: it attaches the bridge, and nothing
    else. It deliberately does not move the browser off the exit it is on --
    disarming while a healthy tunnel is selected should not take anyone out
    of it, and an earlier draft of this did exactly that. Going direct is
    `net_use direct`, the same two steps the host has always had.

    Arming puts the exit's proxy back in the policy and seals the sandbox.
    """
    if not container:
        return ""
    ok, detail = _sandbox_network(container, give_it_one=direct)
    if direct:
        if not ok:
            return f" The sandbox {container} could not be given a network of its own ({detail})."
        return (
            f" The sandbox {container} now has a second network with a path off this host, "
            "which is what makes going direct possible at all."
        )
    problem = write_sandbox_policy(container, direct=False)
    if not ok or problem:
        return (
            f" The sandbox {container} could not be sealed again ({problem or detail}); "
            "`hermes vpn doctor` says what it is on."
        )
    return (
        f" The sandbox {container} is back on its tunnel-only network, with the exit in "
        "its policy, where docker gives it no route off this host whatever the browser is "
        "configured with."
    )


def _policy_bodies(text: str, nonce: str = "__") -> list[tuple[str, dict[str, Any]]]:
    """Parse the ``<nonce>FILE <path>`` stream a policy read produces.

    The delimiters carry a per-call nonce because the framed content is a file
    anyone with root in that container can write. With fixed delimiters, a
    policy file quoting one of them truncates the stream: the files after it
    disappear from the parse, and whether that reads as healthy or as missing
    depends only on sort order.
    """
    found: list[tuple[str, dict[str, Any]]] = []
    text = text.split(f"{nonce}READ")[0]
    for chunk in text.split(f"{nonce}FILE ")[1:]:
        name, _, body = chunk.partition("\n")
        try:
            parsed = json.loads(body)
        except ValueError:
            continue
        if isinstance(parsed, dict):
            found.append((name.strip(), parsed))
    return found


def _bodies_get(bodies: list[tuple[str, dict[str, Any]]], name: str) -> Any:
    """What *name* set WebRtcIPHandling to, for a message that says which value."""
    return next((body.get("WebRtcIPHandling") for key, body in bodies if key == name), None)


def _policy_verdict(bodies: list[tuple[str, dict[str, Any]]], *, proxy: str = "") -> tuple[str, str]:
    """Judge a set of managed-policy files: ("ok" | "wrong" | "missing", detail).

    Parsed and compared field by field, never grepped. A substring search for
    the setting's name said yes to all of these, every one of which leaves the
    browser unprotected or unproxied:

    * ``{"WebRtcIPHandlingPolicy": …}`` -- the legacy spelling Chrome ignores in
      silence, which is exactly what someone who hardened by hand before
      reading this plugin has on disk;
    * ``{"WebRtcIPHandling": "default", "_note": "…disable_non_proxied_udp"}``;
    * ``{"ProxyMode": "direct", "WebRtcIPHandling": …}`` -- the file that is
      supposed to carry the exit says *direct*.

    When *proxy* is given the proxy fields are judged too, because in a
    sandbox this one file is the only thing pointing that browser at the exit.
    """
    if not bodies:
        return "missing", "no managed policy file sets anything"

    faults: list[str] = []
    webrtc = [(name, body) for name, body in bodies if "WebRtcIPHandling" in body]
    if not webrtc:
        legacy = [name for name, body in bodies if "WebRtcIPHandlingPolicy" in body]
        faults.append(
            f"{legacy[0]} uses WebRtcIPHandlingPolicy, the spelling Chrome ignores"
            if legacy else "no file sets WebRtcIPHandling"
        )
    else:
        bad = [name for name, body in webrtc if body.get("WebRtcIPHandling") != WEBRTC_SETTING]
        if bad:
            # Any file, not every file. Chrome merges the directory and one
            # that sets this to something else can win on resolution order.
            # (Which is why we reuse a single filename.)
            faults.append(
                f"{bad[0]} sets WebRtcIPHandling to {_bodies_get(bodies, bad[0])!r}"
                + (f" while {webrtc[0][0]} sets it correctly" if len(webrtc) > len(bad) else "")
            )

    if proxy:
        proxied = [(name, body) for name, body in bodies if "ProxyMode" in body or "ProxyServer" in body]
        if not proxied:
            faults.append("no file points the browser at the exit")
        elif len(proxied) > 1:
            faults.append(
                "more than one file sets the proxy (" + ", ".join(n for n, _ in proxied) + ")"
            )
        else:
            name, body = proxied[0]
            if body.get("ProxyMode") != "fixed_servers":
                faults.append(f"{name} sets ProxyMode to {body.get('ProxyMode')!r}, not fixed_servers")
            elif body.get("ProxyServer") != proxy:
                faults.append(f"{name} points at {body.get('ProxyServer')!r}, not {proxy}")
        # Judge ProxyBypassList too. Set it to `*` and the browser uses the
        # exit for nothing, same as having no proxy at all. Check every file: one
        # that sets only this key shows up in neither list above.
        for name, body in bodies:
            listed = body.get("ProxyBypassList")
            if listed:
                faults.append(f"{name} sets ProxyBypassList to {listed!r}, so the exit is bypassed")

    return ("wrong", "; ".join(faults)) if faults else ("ok", "")


def browser_policy_file() -> str:
    """The managed policy on this filesystem that disables non-proxied UDP."""
    directory = CHROME_POLICY_FILE.parent
    try:
        files = sorted(directory.glob("*.json"))
    except OSError:
        return ""
    for path in files:
        try:
            body = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if isinstance(body, dict) and body.get("WebRtcIPHandling") == WEBRTC_SETTING:
            return str(path)
    return ""


def browser_policy_installed() -> bool:
    return bool(browser_policy_file())


def sandbox_policy_state(container: str) -> tuple[str, str]:
    """Judge the managed policy inside *container*: the browser reads it there.

    Returns ("ok" | "wrong" | "missing" | "unknown", detail). Four answers,
    not two: the host's ``/etc`` says nothing about a browser in a container,
    a policy that exists but carries the wrong exit is not the same as none,
    and "I could not ask docker" is not a finding about the browser at all.
    """
    if not container:
        return "unknown", "no container"
    directory = shlex.quote(str(CHROME_POLICY_FILE.parent))
    # The marker proves the command ran: `cat` of a missing glob exits
    # non-zero, which would otherwise look like a dead docker.
    script = (
        f'for f in {directory}/*.json; do [ -e "$f" ] || continue; '
        f'echo "__FILE__ $f"; cat "$f"; echo; done; echo __READ__'
    )
    nonce = f"__{os.urandom(8).hex()}__"
    script = script.replace("__FILE__", f"{nonce}FILE").replace("__READ__", f"{nonce}READ")
    ok, out = _docker_try("exec", container, "sh", "-c", script)
    if not ok or f"{nonce}READ" not in out:
        return "unknown", "the policy could not be read"
    # The proxy is judged only while the kill switch is armed. Disarmed, the
    # policy this sandbox is supposed to have is the one without a proxy, and
    # calling that "wrong" would have `doctor` reporting a fault every time
    # someone deliberately let the browser out.
    judged = SANDBOX_PROXY if (locked() or saved_choice()) else ""
    return _policy_verdict(_policy_bodies(out, nonce), proxy=judged)


#: Host ports worth naming when a sandbox can reach them. The docker API ones
#: are in the list because they would be root on the host; the ssh ones because
#: they are the usual answer to "what else is listening".
HOST_PORTS_WORTH_NAMING = (22, 2222, 2375, 2376)


def sandbox_reaches_host(container: str) -> list[int]:
    """Which of this host's own ports answer from inside *container*.

    A fact to report, never a fault to fail on. A sealed sandbox has no path to
    the internet, which is the guarantee; it is still on a network whose
    gateway is this machine, because ``--internal`` only drops forwarded
    traffic and leaves traffic *to the host* alone. Whether this host answers
    on port 22 is the operator's policy and none of the plugin's business --
    a check that failed over it would be imposing an opinion about someone
    else's firewall. Saying nothing about it would be the other error, since
    "no way out except the tunnel" is easy to read as "isolated from here".
    """
    if not container:
        return []
    ports = ",".join(str(port) for port in HOST_PORTS_WORTH_NAMING)
    probe = (
        "import socket\n"
        "gateway = None\n"
        "for line in open('/proc/net/route').readlines()[1:]:\n"
        "    bits = line.split()\n"
        "    if bits[1] == '00000000':\n"
        "        continue\n"
        "    packed = int(bits[1], 16).to_bytes(4, 'little')\n"
        "    gateway = '%d.%d.%d.1' % (packed[0], packed[1], packed[2])\n"
        "    break\n"
        "open_ports = []\n"
        "if gateway:\n"
        f"    for port in ({ports},):\n"
        "        sock = socket.socket()\n"
        "        sock.settimeout(1)\n"
        "        try:\n"
        "            sock.connect((gateway, port))\n"
        "            open_ports.append(port)\n"
        "        except OSError:\n"
        "            pass\n"
        "        finally:\n"
        "            sock.close()\n"
        "print('PORTS ' + ','.join(str(p) for p in open_ports))\n"
    )
    ok, out = _docker_try("exec", "-i", container, "python3", "-I", "-c", probe, timeout=20)
    if not ok or "PORTS" not in out:
        return []
    listed = out.split("PORTS", 1)[1].strip()
    return [int(part) for part in listed.split(",") if part.strip().isdigit()]


def heal_sandbox_policy(container: str, expect_direct: bool | None = None) -> str:
    """Put the policy back inside *container* when it is missing or wrong.

    Returns a sentence about what happened, or "" when nothing needed doing.
    Four rules, and the last three are the ones that took work:

    * it never raises -- a country switch that worked must not be reported as
      failed because a repair could not be made, and the exit is verified
      separately and fails closed on its own;
    * it never stays quiet about a repair, because a silent repair teaches the
      reader that nothing was ever wrong, and then a real fault has no way to
      be noticed;
    * it never writes when it could not read: not knowing is not a licence to
      overwrite a file something else may be managing;
    * it never claims a repair it did not confirm, and it distinguishes "reads
      back wrong" from "could not be read back" -- the second is not a finding
      about the file.
    """
    if not container:
        return ""
    verdict, detail = sandbox_policy_state(container)
    if verdict == "ok":
        return ""
    if verdict == "unknown":
        return (
            f" The policy inside {container} could not be read ({detail}), so it was left "
            "alone; `hermes vpn doctor` says more."
        )

    directory = CHROME_POLICY_FILE.parent
    path = directory / SANDBOX_POLICY_NAME
    quoted = shlex.quote(str(directory))
    # Disarmed, the file this profile is supposed to have is the one without
    # a proxy: repairing it back to the exit would put the browser behind a
    # tunnel the person just said they did not want.
    # Direct only when that is what this profile is actually on: disarmed
    # *and* no exit chosen. Keying it on the switch alone would repair a
    # browser back to no proxy right after someone picked an exit.
    # The caller says what this profile is supposed to be on, because it
    # knows: `switch_sandbox` is putting it on an exit whatever the switch
    # says, and inferring here would repair a browser back to no proxy right
    # after someone picked one.
    going_direct = (
        (not locked() and not saved_choice()) if expect_direct is None else expect_direct
    )
    body = sandbox_direct_policy_body() if going_direct else sandbox_policy_body()
    # Set the parents' modes too, the same ones vpn-migrate uses. Chrome
    # ignores the whole directory if it can't traverse into it.
    script = (
        f"mkdir -p {quoted} && "
        f"printf '%s\\n' {shlex.quote(body)} > {shlex.quote(str(path))} && "
        f"chmod 755 /etc/opt /etc/opt/chrome_for_testing /etc/opt/chrome_for_testing/policies "
        f"{quoted} && chmod 644 {shlex.quote(str(path))}"
    )
    # Guess at a cause only for the missing case. An edited file was not
    # recreated and we have no idea what touched it.
    was = (
        "had no browser policy — a container Hermes recreated, most likely —"
        if verdict == "missing" else f"had the wrong policy ({detail}) —"
    )
    ok, _out = _docker_try("exec", "-u", "root", container, "sh", "-c", script)
    if not ok:
        return (
            f" Warning: {container} {was} and a new one could not be written, so the browser "
            f"in there has no exit. `contrib/vpn-migrate` writes the same path the same way, "
            f"so it will fail too: look at {CHROME_POLICY_FILE.parent} inside that container "
            "— something is in the way."
        )
    after, after_detail = sandbox_policy_state(container)
    if after == "unknown":
        return (
            f" The sandbox {was}, so the policy was written to {path}; the readback could "
            f"not be made ({after_detail}), so that write is unconfirmed."
        )
    if after != "ok":
        return (
            f" Warning: the policy was written to {path} inside {container} and still reads "
            f"wrong ({after_detail}); something else is managing that file."
        )
    return (
        f" The sandbox {was} so it was written "
        f"back to {path}. Chrome re-reads managed policy on its own, so a page already open "
        "may take ~20s to go through the exit. Only the browser was repaired: curl, pip, apt "
        "and git in there are `contrib/vpn-migrate`'s step 2."
    )


def profiles_dir() -> Path:
    """Where all the profiles live, seen from wherever this agent is running.

    Inside a profile, ``HERMES_HOME`` *is* ``…/profiles/<name>`` -- so the set of
    profiles is its parent, not a ``profiles`` directory beneath it. Getting
    this wrong is not a missing feature, it is a lie: the plugin then believes
    it is running on the host, moves the host's browser, verifies the host's
    proxy, and reports a country the sandbox never had.
    """
    home = hermes_home()
    if home.parent.name == "profiles":
        return home.parent
    return home / "profiles"


def _sandbox_state(container: str) -> tuple[str, str]:
    """(state, detail) for a running sandbox, from the networks it is on.

    Sealed means docker gives it no route off this host, so a browser inside
    cannot leak past the tunnel even if it is configured wrong.
    """
    networks = _docker(
        "inspect", container, "-f",
        "{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}",
    ).split()
    if len(networks) != 1:
        return "open", f"on {len(networks)} networks: {' '.join(networks)}"
    internal = _docker("network", "inspect", networks[0], "-f", "{{.Internal}}").strip()
    if internal == "true":
        return "sealed", f"on {networks[0]} (internal)"
    return "open", f"on {networks[0]}, which is not internal"


def _configured_sandbox_profiles() -> list[str]:
    """Profiles whose config says their terminal is a container.

    Only used to report the ones that are configured and not running. The
    reading is a regex over YAML, which is as weak as it sounds, so nothing
    is decided on it: a profile it misses is one `doctor` does not mention,
    not a profile judged as running on the host.
    """
    root = profiles_dir()
    if not root.is_dir():
        return []
    found = []
    for config in sorted(root.glob("*/config.yaml")):
        try:
            text = config.read_text()
        except OSError:
            continue
        # Comments stripped first, so a commented-out line does not count.
        uncommented = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
        if BACKEND_DOCKER.search(uncommented):
            found.append(config.parent.name)
    return found


def sandbox_profiles() -> list[tuple[str, str, str]]:
    """Profiles whose browser runs in a container, and whether it has a way out.

    Reports (profile, state, detail) with state "sealed", "open" or "idle".

    What is running comes from docker, by the label Hermes puts on a sandbox,
    and not from the configuration. The two can disagree in both directions:
    a sandbox can be migrated onto a sealed network while it runs, and a
    config that promises one can be ignored by a container that already
    existed. What matters is where the thing is right now.

    That also keeps a weak reading out of a strong decision. Finding these by
    pattern-matching the config meant a profile written in a form the pattern
    did not expect was taken for one running on the host, and then the
    browser this plugin measures is not the browser it moves. The label is
    evidence; the config is a description.
    """
    global _sandbox_listing_silent
    _sandbox_listing_silent = ""
    found: list[tuple[str, str, str]] = []
    ok, listing = _docker_try(
        "ps", "--filter", "label=hermes-profile", "--format",
        # `.Label "key"`, not `index .Labels "key"`. In `docker ps` the
        # template's .Labels is the whole comma-joined string, so indexing it
        # fails the template, docker prints nothing, and every sandbox looks
        # idle: the host path on a profile whose browser is in a container.
        # `docker inspect` is the one where .Labels is a map.
        '{{.Names}}\t{{.Label "hermes-profile"}}',
    )
    if not ok:
        # Not the same as "nothing is running". A sandboxed profile that looks
        # like it has no sandbox is judged on the host's proxy, which is not
        # the browser it has: the permissive direction. Remembered so the
        # guard and `doctor` can say it instead of acting on it.
        _sandbox_listing_silent = (
            "docker could not be asked which profiles have a sandbox running"
            + (f" ({listing.strip()[:120]})" if listing.strip() else "")
        )
        return found
    running: dict[str, str] = {}
    for line in listing.splitlines():
        name, _, profile = line.partition("\t")
        if name.strip() and profile.strip():
            running.setdefault(profile.strip(), name.strip())

    for profile, container in sorted(running.items()):
        state, detail = _sandbox_state(container)
        found.append((profile, state, detail))

    # The ones that say they are sandboxes and have nothing running. Only a
    # line in `doctor`, which is why the weak reading is allowed here.
    for profile in _configured_sandbox_profiles():
        if profile not in running:
            found.append((profile, "idle", "no sandbox running"))
    return found


def configured_providers() -> list[tuple[str, str]]:
    """VPNs this host has credentials for, as the helper reports them.

    The agent gets the names without being able to read a single secret.
    """
    try:
        said = _run_helper("providers")
    except ExitError as exc:
        # The caller gets the reason, because "no credentials are configured"
        # and "the helper is missing, or the sudo rule is" look identical to a
        # reader and have completely different fixes.
        raise ExitError(f"the exit helper could not be asked: {exc}") from exc
    # (provider name, file it came from). `--provider` takes the second one,
    # so report both or we name something `net_open` will reject.
    found = []
    for line in said.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        name = parts[0].strip()
        stem = parts[1].strip().removesuffix(".env") if len(parts) > 1 else name
        found.append((name, stem))
    return found


#: A provider name as the helper accepts it: lowercase, digits and dashes.
#: The helper validates this too; this is the first of the two checks the
#: argument should pass, not the only one.
_PROVIDER_NAME = re.compile(r"^[a-z][a-z0-9-]{1,30}$")


def resolve_secret_ref(ref: str) -> str:
    """Turn a vault reference into the config text it points at, host-side.

    The reference is not the secret: it names where the secret lives, so it is
    safe for the model and the chat to carry. We resolve it here, inside the
    plugin process, and the text we get back never becomes a tool return or a
    message. ``pass:`` reads an entry from the local ``pass`` store (gopass
    reads the same GPG store); ``file:`` reads a file the agent user can already
    read. Both stay on this host, with no network of their own.
    """
    ref = (ref or "").strip()
    if not ref or "\n" in ref:
        raise ExitError("a vault reference is a single line, like pass:vpn/airvpn")
    if ref.startswith("pass:"):
        return _resolve_pass(ref)
    if ref.startswith("file:"):
        return _resolve_file(ref)
    if ref.startswith("env:"):
        raise ExitError(
            "env: is not a vault; store the config in pass or a file and give its "
            "pass: or file: reference instead"
        )
    raise ExitError(
        "unsupported reference; use pass:folder/item (pass or gopass) or file:/absolute/path"
    )


def _resolve_pass(ref: str) -> str:
    """Read an entry from the ``pass`` store (or gopass), host-side.

    ``pass show <name>`` prints the whole decrypted entry, so a WireGuard config
    kept as one entry comes back verbatim. gopass reads the same GPG store and
    answers the same command, so whichever is installed is used.
    """
    name = ref[len("pass:"):].strip()
    # No leading dash: pass/gopass would read it as an option, not an entry.
    if not name or name[0] in "/-" or ".." in name.split("/"):
        raise ExitError("a pass: reference is a store path like pass:vpn/airvpn, with no leading / or - or ..")
    tool = shutil.which("pass") or shutil.which("gopass")
    if not tool:
        raise ExitError("neither 'pass' nor 'gopass' is on this host, so pass: cannot be read")
    try:
        done = subprocess.run([tool, "show", name], capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired as exc:
        raise ExitError("the password store did not answer within 30s") from exc
    if done.returncode != 0:
        # stderr only: the decrypted entry goes to stdout, and must never be
        # folded into an error that travels back to the caller.
        detail = (done.stderr or "").strip().splitlines()
        raise ExitError("the password store could not read that entry: "
                        + (detail[-1] if detail else "unknown error"))
    if not (done.stdout or "").strip():
        raise ExitError("that pass entry resolved to nothing")
    return done.stdout


def _resolve_file(ref: str) -> str:
    path = ref[len("file:"):]
    if not path.startswith("/") or ".." in path.split("/"):
        raise ExitError("a file: reference needs an absolute path with no .., like file:/home/you/airvpn.conf")
    try:
        text = Path(path).read_text()
    except OSError as exc:
        raise ExitError(f"could not read {path}: {exc}") from exc
    if not text.strip():
        raise ExitError(f"{path} is empty")
    return text


def _looks_like_wireguard(config: str) -> bool:
    """A WireGuard config, by the field the helper needs to find a private key in."""
    return bool(re.search(r"(?m)^\s*(WIREGUARD_PRIVATE_KEY|PrivateKey)\s*=", config))


def _write_credentials_via_helper(provider: str, config: str) -> str:
    """Feed a resolved config to the helper's set-credentials over a pty.

    ``set-credentials`` guards on an interactive terminal, so a chat-pasted
    secret can never be written by the agent. This path never carries a
    chat-pasted secret: the config came from a vault the user set up and was
    read back host-side. We give the helper the terminal it insists on with a
    pty, and turn that pty's echo off first, so the config is never reflected
    into anything we read. We read back only what the helper prints, which is
    variable names, never values.
    """
    import pty
    import termios

    master, slave = pty.openpty()
    # The line discipline would otherwise copy every byte we write to the
    # master straight back onto it; turn echo off before the secret goes near.
    attrs = termios.tcgetattr(slave)
    attrs[3] &= ~termios.ECHO  # lflags
    termios.tcsetattr(slave, termios.TCSANOW, attrs)
    try:
        proc = subprocess.Popen(
            ["sudo", "-n", helper(), "set-credentials", provider],
            stdin=slave,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    except FileNotFoundError as exc:
        os.close(master)
        os.close(slave)
        raise ExitError(f"this host cannot run the helper without sudo ({exc})") from exc
    os.close(slave)
    payload = config if config.endswith("\n") else config + "\n"
    # Keep the master open until the helper has finished. Closing it earlier
    # revokes the pty, and the helper then sees no terminal and refuses.
    try:
        try:
            os.write(master, payload.encode())
            os.write(master, b"\x04")  # EOF for the helper's `cat`
        except OSError:
            pass
        out, err = proc.communicate(timeout=OPEN_TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        raise ExitError("storing the credentials did not finish in time")
    finally:
        os.close(master)
    if proc.returncode != 0:
        detail = (err or out or "").strip().splitlines()
        reason = detail[-1] if detail else f"the helper exited {proc.returncode}"
        if "a password is required" in reason or "is not allowed to execute" in reason:
            reason = (
                f"this account may not run {helper()} through sudo; see contrib/vpn-exit "
                "for the rule it needs"
            )
        raise ExitError(reason)
    return (out or "").strip()


def add_provider_from_ref(provider: str, ref: str) -> str:
    """Add a provider from a vault reference, keeping the secret off the model.

    The user put the WireGuard config in a vault and told us a reference to it.
    We resolve the reference host-side, check it looks like a WireGuard config,
    and hand it to the helper. The model and the chat only ever saw the
    reference; the config is never a return value or a message.
    """
    provider = (provider or "").strip()
    if not _PROVIDER_NAME.match(provider):
        raise ExitError("a provider name is lowercase letters, digits and dashes, 2 to 31 long")
    for name, _stem in configured_providers():
        if name == provider:
            raise ExitError(
                f"{provider} already has credentials; remove /root/vpn-exits/{provider}.env "
                "first if you mean to replace them"
            )
    config = resolve_secret_ref(ref)
    if not _looks_like_wireguard(config):
        raise ExitError(
            "that reference did not resolve to a WireGuard config (no private key in it); "
            "check it points at the config, not at a password"
        )
    wrote = _write_credentials_via_helper(provider, config)
    # Never the config, only the helper's names-only line.
    return wrote or f"stored credentials for {provider} (root only)"


#: Where the agent is running. A profile whose terminal is a container has its
#: browser in there too, and that browser is reached in a completely different
#: way from the one on the host.
PROFILE_ENV = "NET_EXITS_PROFILE"

#: A profile whose terminal is a container. Matched as a key with a value, not
#: as a literal line, because YAML spells the same thing several ways.
#: The whole value, not a prefix: ``\b`` matched before the hyphen, so
#: ``backend: docker-compose`` was read as a sandbox. The flow form
#: (``terminal: {backend: docker, …}``) is accepted too, since it is valid
#: YAML for the same setting and reading it as "on the host" is the failure
#: `profiles_dir`'s docstring calls a lie.
BACKEND_DOCKER = re.compile(
    r"backend\s*:\s*['\"]?docker['\"]?\s*(?:[,}\n]|$)", re.M
)
VERIFY_HELPER = os.environ.get("NET_EXITS_VERIFY") or "/usr/local/bin/vpn-verify"

def read_sighting(said: str) -> tuple[str, str, str]:
    """(address, label, why this is not a measurement) out of `vpn-verify`.

    It prints ``OK <ip> <cc>`` on success and only on success. This reads it
    by tokens rather than by matching the line's shape, and the difference is
    not style. The shape version required the code to be two letters, so
    ``OK 109.70.100.14 T1`` -- Cloudflare's code for a Tor exit -- was thrown
    out as "not a measurement", a sandbox that was demonstrably out through
    Tor was put back on its old exit, and a working tunnel was reported as
    broken.

    Strict where it decides, lenient where it labels. The decision is that a
    token parses as a routable address, which `_is_an_address` answers and no
    pattern here can loosen. Everything else on the line is a label: it is
    shown and never gates anything, so a verifier that one day prints a
    latency or a profile name alongside it keeps working.
    """
    for line in (said or "").splitlines():
        tokens = line.split()
        if not tokens or tokens[0] != "OK":
            continue
        rest = tokens[1:]
        if not rest:
            # "OK" by itself carries no measurement at all, which is the
            # other complaint below rather than this one.
            continue
        for index, token in enumerate(rest):
            if _is_an_address(token):
                return token, " ".join(rest[:index] + rest[index + 1:]), ""
        return "", " ".join(rest), (
            f"the verifier reported {' '.join(rest)!r}, which is not a routable address, "
            "so nothing was confirmed"
        )
    return "", "", (
        f"the verifier exited 0 but its answer is not a measurement: {said.strip()!r}"
    )



#: A profile name as the helper will accept it. `NET_EXITS_PROFILE` is an
#: override the agent can set, and `--city` as a profile made the helper
#: consume it as an option, leaving the profile empty: the *shared* relay
#: moved while the caller was told its own had.
PROFILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,39}\Z")


def current_profile() -> str:
    """Which profile this agent is running as."""
    override = (os.environ.get(PROFILE_ENV) or "").strip()
    if override and not PROFILE_NAME.match(override):
        raise ExitError(
            f"{PROFILE_ENV}={override[:40]!r} is not a profile name, and this plugin acts "
            "on whatever it says. Unset it or correct it."
        )
    if override:
        return override
    try:
        from hermes_cli.profiles import current_profile_name  # type: ignore

        named = current_profile_name()
        # A string, or nothing. This value becomes a docker label filter
        # (`label=hermes-profile=<this>`), so an object's repr matches no
        # container, `in_sandbox()` answers "" for a sandboxed profile, and
        # the kill switch falls back to judging the host's proxy for a browser
        # that does not use it. `str()` on whatever Hermes returns was one
        # refactor away from that.
        if isinstance(named, str) and named.strip():
            return named.strip()
    except Exception:
        pass
    # Same signal Hermes itself derives it from, in case the import moves.
    # Validated like the override above: HERMES_HOME is as settable, and an
    # unchecked `.../profiles/--city` became the profile name, which the
    # helper then read as a flag and moved the shared relay. A name that is
    # not a profile name is not trusted to act as one -- fall back to default.
    home = hermes_home()
    name = home.name if home.parent.name == "profiles" else "default"
    return name if PROFILE_NAME.match(name) else "default"


def sandbox_container(profile: str = "") -> str:
    """The running sandbox of a profile, matched by label.

    By label and never by name: a recreated sandbox gets a fresh random one.
    """
    profile = profile or current_profile()
    names = _docker(
        "ps", "--filter", f"label=hermes-profile={profile}", "--format", "{{.Names}}"
    ).split()
    return names[0] if names else ""


def in_sandbox() -> str:
    """The sandbox this agent browses from, or "" when it browses on the host."""
    profile = current_profile()
    for name, state, _detail in sandbox_profiles():
        if name == profile and state != "idle":
            return sandbox_container(profile)
    return ""


def verify_sandbox(container: str) -> tuple[bool, str]:
    """Ask, from inside the sandbox, where it really comes out. Fail-closed."""
    if not os.path.exists(VERIFY_HELPER):
        return False, f"no verifier at {VERIFY_HELPER}"
    try:
        done = subprocess.run(
            [VERIFY_HELPER, container], capture_output=True, text=True, timeout=30
        )
    # OSError, so this stays fail-closed: a verifier without +x raises
    # PermissionError and one without a shebang raises OSError("Exec format
    # error").
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"{type(exc).__name__}: {exc}"
    said = (done.stdout or "").strip()
    if done.returncode != 0:
        return False, (done.stderr or said or f"exit {done.returncode}").strip()
    # A zero exit code is not enough: without this a silent verifier becomes
    # "the far end reports  in ".
    _ip, _label, problem = read_sighting(said)
    if problem:
        return False, problem
    return True, said


def switch_sandbox(selector: str, container: str) -> str:
    """Move the sandbox's exit, then confirm it from inside before saying so."""
    if (selector or "").strip().lower() == DIRECT:
        if locked():
            raise ExitError(
                "the kill switch is armed, so this sandbox stays on its tunnel-only "
                "network and has no direct path to the internet — that is the point of "
                "it. Disarm it deliberately, or pick another exit."
            )
        _sandbox_network(container, give_it_one=True)
        problem = write_sandbox_policy(container, direct=True)
        if problem:
            raise ExitError(
                f"the policy inside {container} could not be changed ({problem}), so that "
                "browser is still pointed at the exit and nothing was changed."
            )
        _save_state(None)
        _last_check_clear()
        return (
            f"Proxy off for the sandbox {container}: its browser now leaves by this host's "
            "address, like a browser on the host would. Arming the kill switch puts the "
            "exit back and seals it again."
        )

    target = resolve(selector)
    # Choosing an exit is asking for the tunnel, so the sandbox goes back on
    # its own network first. The verifier refuses a container on two
    # networks -- it cannot tell which one carried the answer -- so without
    # this, coming back from direct meant arming the kill switch first and
    # the error said nothing about that.
    sealed_again = ""
    if any(state == "open" for name, state, _d in sandbox_profiles()
           if name == current_profile()):
        ok, detail = _sandbox_network(container, give_it_one=False)
        sealed_again = (
            " It was taken off its own network first, so the tunnel is the only way out again."
            if ok else f" It could not be taken off its own network ({detail})."
        )
    # Repair before switching, not after. That same file carries the proxy, so
    # if it's missing the browser in there has no exit at all and the sentence
    # we return would describe a sandbox that can't load a page.
    repaired = heal_sandbox_policy(container, expect_direct=False)
    # What it was on, before anything moves. The relay's upstream is the only
    # way out that sandbox has, so a switch that cannot be confirmed must not
    # leave it pointing at the new one: that is not a failed switch, it is a
    # sandbox with no egress, and the value that worked is already gone.
    previous = (saved_choice() or {}).get("name") or ""
    # And the stale verdict goes, for the same reason the host path clears it:
    # the sandbox guard caches on the container for 20s, so without this a
    # refusal survived a successful switch ("`use` says connected, the next
    # browser call says the exit is dead") and a positive survived a *refused*
    # one, which is the kill switch acting on a measurement it was just told
    # not to trust.
    _last_check_clear()

    # Pass the profile: each one has its own relay, so its own upstream file,
    # so its own country. Share a relay between bots and moving one bot moves
    # them all, while each keeps reporting the exit it picked.
    _run_helper("country", target.container or target.name, current_profile())

    ok, said = verify_sandbox(container)
    if not ok:
        back = ""
        if previous and previous != target.name:
            try:
                _run_helper("country", previous, current_profile())
                if verify_sandbox(container)[0]:
                    back = f" The sandbox was put back on {previous}, which still answers."
                else:
                    back = (
                        f" Putting it back on {previous} did not confirm either, so that "
                        "sandbox has no working way out right now."
                    )
            except ExitError as exc:
                back = f" It could not be put back on {previous} either ({exc})."
        raise ExitError(
            f"the sandbox could not confirm the new exit ({said}). Nothing is trusted "
            f"until it does.{back} `hermes vpn doctor` checks the rest."
        )

    # Record the choice, but not through apply(): that writes a proxy into the
    # host's browser arguments and the sandbox's browser doesn't read them.
    # `doctor` and the rollback above need this to be true.
    _save_state(target)
    _last_check_clear()

    # Moving to a clearnet exit while Tor mode is on ends the mode, the same
    # as on the host. Only now, after the exit is confirmed: leaving it clears
    # the browser's identity and takes the config line out, which must not
    # happen for a switch that did not land. The host path's own regression
    # was doing this before the check.
    ended = ""
    if tor_mode() and target.provider != TOR_PROVIDER:
        left = leave_tor_mode()
        ended = f" Tor mode ended: {'; '.join(left)}." if left else ""

    ip, code, _problem = read_sighting(said)
    labelled = f", which the provider labels {target.country}" if target.country else ""
    return (
        f"The sandbox for profile {current_profile()!r} now leaves by {target.name}: "
        f"from inside, the far end reports {ip} in {code}{labelled}. Checked just now."
        f"{ended}{_tor_without_the_mode(target)}{sealed_again}{repaired}"
    )


#: A Tor exit says so with this, and nothing else here assumes it. An exit
#: that is not Tor has no circuit to change, and saying that plainly is better
#: than running a command that will fail inside a container.
TOR_PROVIDER = "tor"

#: What Tor's control port is told, from inside the container. The cookie
#: never leaves it: `docker exec` is a capability this plugin already uses to
#: read gluetun's server lists, so asking here adds no privilege, while
#: putting it in the root-owned helper would.
#:
#: `-w 5` because a control port that accepts the connection and then says
#: nothing would otherwise hold this call for as long as docker allows.
def _control_script(*commands: str) -> str:
    """The shell that authenticates to Tor and sends *commands*, one per line."""
    lines = "".join(command + "\\r\\n" for command in commands)
    return (
        'cookie=$(od -An -tx1 /var/lib/tor/control_auth_cookie | tr -d " \\n") || exit 1; '
        'printf "AUTHENTICATE %s\\r\\n' + lines + 'QUIT\\r\\n" "$cookie" '
        "| nc -w 5 127.0.0.1 9051"
    )


_NEWNYM_SCRIPT = _control_script("SIGNAL NEWNYM")


def _read_control_reply(said: str) -> str:
    """"" when Tor accepted the signal, or why it did not.

    The control protocol answers one line per command, `250 OK` for each of
    ours. It also uses `250-` for a line that continues and `250 ` for the
    last one, which is why nothing here waits for the stream to end: a reply
    that is already complete would hold the call until the timeout.
    """
    lines = [line.strip() for line in (said or "").splitlines() if line.strip()]
    if not lines:
        return "the control port said nothing at all"
    for line in lines:
        if line.startswith(("515", "514")):
            return f"the control port refused the cookie ({line})"
        if line[:3].isdigit() and not line.startswith("250"):
            return f"the control port answered {line}"
    if sum(1 for line in lines if line.startswith("250")) < 2:
        # One 250 is the authentication; the signal needs its own.
        return f"the control port did not accept the signal ({lines[-1]})"
    return ""


#: A v2 address was 16 characters and a v3 one is 56. Both are matched because
#: an old address in a browser call is still an onion request, and telling
#: someone their circuit is cold is a better answer than a DNS error.
ONION_HOST = re.compile(r"\b([a-z2-7]{16}|[a-z2-7]{56})\.onion\b", re.IGNORECASE)

#: How long a rendezvous stays worth counting as established. Tor keeps a
#: circuit about ten minutes, so this follows it rather than inventing a
#: number.
ONION_WARM_SECONDS = 600

#: A cold onion took 56s through this exit, and the same page 5s once the
#: rendezvous existed. A browser left on its own 30s timeout gives up in the
#: middle of that and reports what reads like a broken site.
ONION_CONNECT_TIMEOUT = 120

#: Onion hosts this plugin has reached, and when. In memory on purpose: after
#: a restart the circuit is probably gone too, and warming it again costs one
#: request.
_warm_onions: dict[str, float] = {}


#: The first http(s) URL anywhere in a tool's arguments. The shape of those
#: arguments is the host's, not ours, so this reads them as text rather than
#: guessing at a key name.
#: A URL inside a tool argument. It stops only at whitespace, quotes, angle
#: brackets and a backtick -- the things that end a URL in a string or in the
#: text a dict stringifies to. It deliberately keeps `,`, `@`, `\` and square
#: brackets, which an earlier version stopped at: `http://a,@127.0.0.1/` was
#: then read as `http://a`, hiding the host the browser actually dials, and
#: `http://[::1]/` lost its closing bracket and would not parse. Chrome reads
#: the whole thing; so must this.
URL_IN_ARGS = re.compile(r"https?://[^\s\"'<>`]+", re.IGNORECASE)


def _onion_in(text: Any) -> str:
    """The onion host named anywhere in *text*, lowercased, or ""."""
    found = ONION_HOST.search(str(text or ""))
    return f"{found.group(1).lower()}.onion" if found else ""


#: Names that mean this machine without being an address. Not a resolver:
#: see `_private_destination`.
LOCAL_NAMES = ("localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata.google.internal")


#: An IP written in a shape `ipaddress` does not take but Chrome does:
#: `127.1`, `2130706433`, `0x7f000001`, `0177.0.0.1`. Matching this and then
#: failing to parse as a clean address is itself the refusal -- a numeric
#: host the standard parser rejects is a disguise, not a typo.
NUMERIC_HOST = re.compile(r"[0-9.]+|0[xX][0-9a-fA-F.]+|\d+")

#: A plain DNS host: ASCII letters, digits, hyphens, dots. A name that still
#: holds anything else once it has been read the way Chrome reads it (a left
#: over percent-escape, a stray unicode glyph) is not a host this will pass.
DNS_HOST = re.compile(r"[a-z0-9]([a-z0-9-]{0,62})(\.[a-z0-9]([a-z0-9-]{0,62}))*")


def _host_as_chrome_reads_it(url: str) -> str | None:
    """The host Chrome will dial for *url*, canonicalised, or None for no host.

    The guard used to judge the text of the URL. Chrome judges something
    else: it turns `\\` into `/` in the authority, takes what follows the
    last `@`, percent-decodes the host, and folds it under IDNA/NFKC. So
    `http://a,@127.0.0.1/`, `http://127.0.0.1\\@evil/`, `http://%6c..%74/`
    and `http://１２７.0.0.1/` all dial a machine the plain text
    did not name. This reads the host the same way, so the guard judges the
    destination and not its spelling. "" is returned for a host that cannot
    be parsed at all, which the caller treats as a refusal.
    """
    url = url.replace("\\", "/")
    try:
        host = urllib.parse.urlsplit(url).hostname
    except ValueError:
        return ""
    if not host:
        return None
    host = unicodedata.normalize("NFKC", urllib.parse.unquote(host))
    return host.strip().rstrip(".").lower()


def _private_destination(text: Any) -> str:
    """The reason a browser call must not happen while Hermes' SSRF check is off.

    Tor mode turns that check off, because it resolves the hostname and an
    onion address resolves nowhere here. This stands in for it, but only over
    the http(s) URLs it finds in the browser arguments: each such URL is
    passed only when it reads, the way Chrome reads it, as a public IP or a
    plain DNS name that is not this machine; an IP in disguise, a host that
    will not parse, or one that still carries odd characters is refused.

    What it does NOT examine is an argument with no http(s) URL in it -- a
    scheme-less host (`localhost:9051`), a `file:` path, a non-http scheme:
    those are not refused here. On a sandbox profile the browser sits on an
    internal network, so `localhost` is the container and the host is out of
    reach; on a host profile this is a gap (Chrome bypasses the proxy for
    loopback), tracked for a follow-up that refuses any non-public-http(s)
    destination while Tor is on. It also does not resolve hostnames, so a name
    that *resolves* to a private address (`localtest.me`) is a gap the README
    names.
    """
    for found in URL_IN_ARGS.finditer(str(text or "")):
        url = found.group(0)
        host = _host_as_chrome_reads_it(url)
        if host is None:
            continue
        if not host:
            return f"{url[:60]} cannot be read as an address"
        if host.endswith(".onion"):
            continue
        if host in LOCAL_NAMES or host.endswith((".localhost", ".internal")):
            return f"{host} is this machine"
        # IPv6 arrives here with its colons and its brackets gone.
        if ":" in host:
            try:
                parsed = ipaddress.ip_address(host)
            except ValueError:
                return f"{host} cannot be read as an address"
            if not _is_an_address(str(parsed)):
                return f"{host} is not an address on the internet"
            continue
        # Numeric-looking: it is an address or it is a disguise, never a name.
        if NUMERIC_HOST.fullmatch(host):
            try:
                parsed = ipaddress.ip_address(host)
            except ValueError:
                return f"{host} is an address written in a shape only the browser reads"
            if not _is_an_address(str(parsed)):
                return f"{host} is not an address on the internet"
            continue
        # A plain name. Accepted without resolving it, refused if reading it
        # the way Chrome does left anything that is not a hostname character.
        if not DNS_HOST.fullmatch(host):
            return f"{host} cannot be read as a plain host"
    return ""


def _onion_is_warm(host: str) -> bool:
    return time.time() - _warm_onions.get(host, 0.0) < ONION_WARM_SECONDS


#: A second managed-policy file, written only while Tor mode is on. Chrome
#: merges every file in that directory, so this one carries what the mode
#: adds and the existing file keeps carrying the proxy. Two files rather than
#: one because `vpn-migrate` writes the other byte for byte, and a key added
#: there would read as a policy someone tampered with.
TOR_POLICY_NAME = "tor.json"

#: Blink reads this at launch, which is how the host browser loses JavaScript
#: without a policy file only root can write.
NO_JS_ARG = "--blink-settings=scriptEnabled=false"

#: Where the host browser keeps a Tor-mode profile. A directory of its own
#: rather than the usual one: the point is that nothing crosses between what
#: Tor sees and what the ordinary browsing session has, and a profile that is
#: never shared cannot leak either way. In a sandbox the browser's profile is
#: Hermes' to place, so there the identity is cleared instead.
TOR_PROFILE_DIR = "/tmp/hermes-vpn-tor-profile"


def tor_policy_body(javascript: bool = False) -> str:
    """What Tor mode adds to the browser's managed policy.

    JavaScript off is what Tor Browser's safest level does, and for the same
    reason: it is the surface that fingerprints, that reaches into the local
    network, and that runs whatever a page feels like running. The rest are
    the device permissions a page has no business having here.
    """
    policy: dict[str, Any] = {
        "DefaultGeolocationSetting": 2,
        "DefaultNotificationsSetting": 2,
        "DefaultSensorsSetting": 2,
        "DefaultWebBluetoothGuardSetting": 2,
        "DefaultWebUsbGuardSetting": 2,
        "DefaultSerialGuardSetting": 2,
        "DefaultFileSystemReadGuardSetting": 2,
        "DefaultFileSystemWriteGuardSetting": 2,
        "PasswordManagerEnabled": False,
        "AutofillAddressEnabled": False,
        "AutofillCreditCardEnabled": False,
    }
    if not javascript:
        policy["DefaultJavaScriptSetting"] = 2
    return json.dumps(policy, separators=(",", ":"))


def tor_mode() -> dict[str, Any]:
    """What Tor mode is doing right now, or {} when it is off."""
    mode = (_read_state() or {}).get("tor_mode")
    return mode if isinstance(mode, dict) and mode.get("on") else {}


#: The line the plugin writes into a profile's config, and the comment that
#: marks it as ours. Removing it again is a text edit on someone else's file,
#: so it has to be findable without guessing.
PRIVATE_URLS_MARK = "# hermes-vpn: Tor mode, removed when it ends"
PRIVATE_URLS_LINE = "allow_private_urls: true"


def _read_profile_config() -> str:
    try:
        path = profile_config()
        return path.read_text() if path.exists() else ""
    except OSError:
        return ""


def profile_config() -> Path:
    """The config.yaml of the profile this agent runs as."""
    return hermes_home() / "config.yaml"


#: A `browser:` line that opens a block, with an optional trailing comment.
#: Anything else beginning with `browser:` is a flow mapping or an anchor,
#: which this cannot edit without rewriting someone's file by guesswork.
BROWSER_KEY = re.compile(r"^(?P<indent>[ \t]*)browser:[ \t]*(?:#.*)?$")

#: The setting itself, however it ended up written. PRIVATE_URLS_MARK says a
#: line is ours; this says the setting is on, which is what the browser acts
#: on and therefore what the removal, `leave_tor_mode` and `doctor` have to
#: look for. Keying any of them on the comment alone meant that a config run
#: through a YAML library once -- which drops comments -- left the setting on
#: with nothing able to see it.
PRIVATE_URLS_SET = re.compile(
    r"^[ \t]*allow_private_urls[ \t]*:[ \t]*(?:true|yes|on|y|1)[ \t]*(?:#.*)?$",
    re.IGNORECASE,
)


def private_urls_allowed() -> bool:
    """Whether this profile's config leaves internal addresses reachable."""
    return any(PRIVATE_URLS_SET.match(line) for line in _read_profile_config().split("\n"))


def _without_an_empty_browser_block(lines: list[str]) -> list[str]:
    """Drop a top-level `browser:` that has nothing under it any more.

    This appends that key to a config that has none, so an empty one left
    behind on the way out is its own leftover. YAML reads it as None, and a
    config that then looks up `browser.something` fails on it.
    """
    for index, line in enumerate(lines):
        found = BROWSER_KEY.match(line)
        if not found or found.group("indent"):
            continue
        for below in lines[index + 1:]:
            if not below.strip():
                continue
            if below[:1].isspace():
                return lines
            break
        return lines[:index] + lines[index + 1:]
    return lines


def _block_indent(lines: list[str], start: int) -> str:
    """The indent the children of the block opened at *start* already use.

    Taken from the file rather than assumed: inserting two spaces into a
    block whose children sit at four produces a line less indented than the
    ones under it, and the file stops parsing. The indent is returned as the
    literal string so a tab-indented tree stays tab-indented.
    """
    opener = lines[start]
    base = len(opener) - len(opener.lstrip())
    for line in lines[start + 1:]:
        if not line.strip():
            continue
        indent = line[:len(line) - len(line.lstrip())]
        return indent if len(indent) > base else " " * (base + 2)
    return " " * (base + 2)


def _set_private_urls(on: bool) -> str:
    """Let the browser reach a name that does not resolve here, or stop it.

    An onion address resolves at the far end of the tunnel and nowhere else,
    so Hermes' own check -- which resolves the hostname before navigating,
    as SSRF protection -- refuses every one of them. This turns that check
    off for as long as Tor mode lasts, and the guard in this plugin takes
    over what it can of the job in the meantime.

    The line is written with a marker so that taking it out again is an
    exact edit rather than a guess at someone else's file, and the removal
    only ever touches the pair this wrote. A setting that outlives its
    marker is reported rather than removed, and rather than passed over:
    whoever reads the answer has to know the browser is still open.
    """
    path = profile_config()
    try:
        # newline="" so the endings arrive as they are on disk. `read_text`
        # translates CRLF to LF before this function can see it, and the
        # file was then written back with the endings it never had.
        text = ""
        if path.exists():
            with path.open(encoding="utf-8", newline="") as handle:
                text = handle.read()
    except OSError as exc:
        return f"the profile config at {path} could not be read ({exc})"

    # Not `splitlines()`. It also breaks on U+2028, U+0085, \x0b and \x0c,
    # so a quoted scalar holding one of them came back as two lines and was
    # rejoined as a different value, and it flattens CRLF for the whole file.
    crlf = "\r\n" in text
    lines = (text.replace("\r\n", "\n") if crlf else text).split("\n")
    if lines and lines[-1] == "":
        lines.pop()

    # Only the pair this wrote: a value someone set deliberately elsewhere
    # in the tree is theirs.
    kept: list[str] = []
    drop_next = False
    for line in lines:
        if PRIVATE_URLS_MARK in line:
            drop_next = True
            continue
        if drop_next and PRIVATE_URLS_SET.match(line):
            drop_next = False
            continue
        drop_next = False
        kept.append(line)

    warning = ""
    if on:
        if "allow_private_urls" in "\n".join(kept):
            return "the profile config already sets allow_private_urls, so it was left alone"
        openers = [
            index for index, line in enumerate(kept)
            if (found := BROWSER_KEY.match(line)) and not found.group("indent")
        ]
        if len(openers) > 1:
            return (
                f"{path} opens `browser:` {len(openers)} times and only the last one counts, "
                "so this edited neither. Merge them, or add `allow_private_urls: true` under "
                "the last one by hand to let the browser open an onion address."
            )
        if openers:
            at = openers[0]
            pad = _block_indent(kept, at)
            kept[at + 1:at + 1] = [f"{pad}{PRIVATE_URLS_MARK}", f"{pad}{PRIVATE_URLS_LINE}"]
        elif any(line.strip().startswith("browser:") and not line[:1].isspace() for line in kept):
            return (
                f"the browser settings in {path} are not a plain block, so this did not "
                "touch them. Add `allow_private_urls: true` under `browser:` by hand to "
                "let the browser open an onion address."
            )
        else:
            kept += ["browser:", f"  {PRIVATE_URLS_MARK}", f"  {PRIVATE_URLS_LINE}"]
    else:
        if kept != lines:
            kept = _without_an_empty_browser_block(kept)
        stray = next((line.strip() for line in kept if PRIVATE_URLS_SET.match(line)), "")
        if stray:
            warning = (
                f"{path} still says `{stray}`, which this left alone: with no marker above it "
                "there is nothing to tell it from a setting you made. Internal addresses stay "
                "reachable from the browser until that line goes"
            )
        if kept == lines:
            return warning

    try:
        if text:
            backup = path.with_suffix(f".yaml.bak-{int(time.time())}")
            # Created with the original's mode instead of chmod'ed after it
            # is written: a config carrying the bot's own settings may well
            # be 0600, and the copy was readable by every account on the
            # host for as long as the two calls took.
            with contextlib.suppress(OSError):
                fd = os.open(
                    backup,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                    path.stat().st_mode & 0o777,
                )
                with os.fdopen(fd, "w") as handle:
                    handle.write(text)
        end = "\r\n" if crlf else "\n"
        # newline="" so Python translates nothing on the way out and the
        # file keeps the endings it came with.
        path.write_text(end.join(kept) + end, newline="")
    except OSError as exc:
        return f"the profile config at {path} could not be written ({exc})"
    return warning


#: `-x`, by process name, and never `-f`: with `-f` the pattern is matched
#: against every command line, this script's own included -- it carries the
#: word -- so the shell killed itself before doing anything and the step
#: reported a failure it had caused.
CLOSE_BROWSER = "pkill -x chrome chromium chrome-headless-shell >/dev/null 2>&1; sleep 1"


def _close_sandbox_browser(sandbox: str) -> bool:
    """Close the browser inside *sandbox*. True when the call ran."""
    ok, _said = _docker_try("exec", "-u", "root", sandbox, "sh", "-c", CLOSE_BROWSER, timeout=30)
    return ok


def _clear_browsing_identity(sandbox: str) -> str:
    """Close the browser and leave it nothing it saw before.

    Cookies and sessions are what make a Tor exit beside the point: a site
    that recognises the session knows who it is talking to whatever address
    the request came from. Done on the way in *and* on the way out, so
    neither direction carries anything across.

    The old profile is **set aside, not deleted**. Two reasons, and the
    second is the one that decided it. A recursive delete run as root is
    worth a human reading it, and this plugin's scanner says so by refusing
    the package outright; a rename is the same guarantee for what comes next
    without that. And a profile moved aside can be recovered by whoever
    wanted it, which a deleted one cannot. It stays inside the sandbox and
    goes when the container does.

    It does not make the browser anonymous. The fingerprint is the same one
    it always had, and this plugin cannot change that.
    """
    if not sandbox:
        return f"the host browser gets a profile of its own at {TOR_PROFILE_DIR}"
    script = (
        CLOSE_BROWSER + "; "
        'for d in /home/*/.config/google-chrome* /home/*/.config/chromium* '
        '/root/.config/google-chrome* /root/.config/chromium*; do '
        # The glob matches what an earlier pass set aside, and renaming that
        # again builds `...set-aside-1.set-aside-2` without end.
        'case "$d" in *.set-aside-*) continue;; esac; '
        '[ -d "$d" ] || continue; mv "$d" "$d.set-aside-$(date +%s)" || exit 1; done'
    )
    ok, said = _docker_try("exec", "-u", "root", sandbox, "sh", "-c", script, timeout=30)
    if not ok:
        return f"the browser's cookies in {sandbox} could not be set aside ({said.strip()[:80]})"
    return (
        f"the browser in {sandbox} was closed and its cookies and sessions set aside, so it "
        "starts with nothing"
    )


def _write_tor_policy(sandbox: str, javascript: bool) -> str:
    """Add the Tor-mode policy file inside the sandbox, or take it away."""
    directory = CHROME_POLICY_FILE.parent
    path = directory / TOR_POLICY_NAME
    quoted = shlex.quote(str(path))
    if javascript is None:
        script = f"rm -f {quoted}"
    else:
        script = (
            f"mkdir -p {shlex.quote(str(directory))} && "
            f"printf '%s\\n' {shlex.quote(tor_policy_body(javascript))} > {quoted} && "
            f"chmod 644 {quoted}"
        )
    ok, said = _docker_try("exec", "-u", "root", sandbox, "sh", "-c", script, timeout=30)
    if not ok:
        return f"the Tor policy in {sandbox} could not be written ({said.strip()[:80]})"
    return ""


def tor_bootstrap(container: str) -> tuple[int, str]:
    """(percent, what Tor calls the phase). (-1, reason) when it cannot be asked."""
    ok, said = _docker_try(
        "exec", container, "sh", "-c",
        _control_script("GETINFO status/bootstrap-phase"), timeout=25,
    )
    if not ok:
        return -1, said.strip()[:120] or "the control port could not be reached"
    refusal = _read_control_reply(said)
    if refusal:
        return -1, refusal
    percent = re.search(r"PROGRESS=(\d+)", said)
    summary = re.search(r'SUMMARY="([^"]*)"', said)
    return (int(percent.group(1)) if percent else -1), (summary.group(1) if summary else "")


def tor_exit() -> Exit | None:
    return next((e for e in all_exits() if e.provider == TOR_PROVIDER), None)


def _reapply_browser_args() -> None:
    """Rebuild the browser's arguments for the state the plugin is now in.

    `browser_args` reads the mode, so entering or leaving Tor changes what
    it returns -- and nothing was calling it. The host browser restarted on
    the ordinary profile with JavaScript on, through Tor, while the answer
    said the session had been set aside and scripting was off. The suite
    missed it because the test asserts on `browser_args(...)`, the pure
    function, and not on the variable the browser is launched with.

    Not `apply()`: that rewrites the saved choice, and the exit has not
    changed.
    """
    proxy = current_proxy()
    if proxy:
        os.environ[BROWSER_ARGS_ENV] = browser_args(proxy)


def enter_tor_mode(javascript: bool = False) -> list[str]:
    """Put the browser in the state Tor browsing deserves. Returns what changed."""
    sandbox = in_sandbox()
    done = [_clear_browsing_identity(sandbox)]
    if sandbox:
        problem = _write_tor_policy(sandbox, javascript)
        done.append(
            problem or (
                "JavaScript is off and the device permissions are denied"
                if not javascript else
                "JavaScript was left on at your request, and the device permissions are denied"
            )
        )
    elif not javascript:
        done.append("JavaScript is off for the host browser")
    # The state first, and only then the setting it accounts for. The other
    # order left a window -- a failed state write, a crash, an OOM kill --
    # where the config said `allow_private_urls` while the mode said off: so
    # Hermes' own refusal of internal addresses was gone and the substitute
    # in this plugin never ran. Both guards down, and the agent told that
    # nothing had happened.
    # Remember the exit this was on, so `tor --off` can go back to it rather
    # than leave the browser on the Tor exit with the mode gone.
    prior = (saved_choice() or {}).get("name") or ""
    _write_state(
        tor_mode={"on": True, "javascript": bool(javascript), "at": int(time.time())},
        before_tor=prior,
    )
    problem = _set_private_urls(True)
    done.append(
        problem or "the browser may now be sent to an address that resolves only through Tor"
    )
    if not sandbox:
        shutil.rmtree(TOR_PROFILE_DIR, ignore_errors=True)
        _reapply_browser_args()
        restart_browser()
    return [step for step in done if step]


def leave_tor_mode() -> list[str]:
    """Undo all of it, and clear the identity on the way out as well.

    It also runs when the mode looks off but the config still carries the
    line the mode writes, which is what a crash between the two leaves
    behind. `doctor` prescribes this as the cure; returning early on the
    state alone made the prescription a no-op.
    """
    # The marker, not the setting: it is what says a line is ours. Keying
    # this on the setting meant that someone who had turned private URLs on
    # themselves got their cookies cleared and their browser restarted by a
    # plain `net_use direct`, which also calls this.
    if not tor_mode() and PRIVATE_URLS_MARK not in _read_profile_config():
        return []
    sandbox = in_sandbox()
    done = [_clear_browsing_identity(sandbox)]
    if sandbox:
        problem = _write_tor_policy(sandbox, None)
        done.append(problem or "JavaScript and the device permissions are back to normal")
    else:
        shutil.rmtree(TOR_PROFILE_DIR, ignore_errors=True)
        done.append("the Tor profile was deleted")
    problem = _set_private_urls(False)
    done.append(problem or "the browser is back to refusing an address that does not resolve")
    _write_state(tor_mode={"on": False, "at": int(time.time())}, before_tor="")
    if not sandbox:
        shutil.rmtree(TOR_PROFILE_DIR, ignore_errors=True)
        _reapply_browser_args()
        restart_browser()
    return [step for step in done if step]


def end_tor_mode() -> str:
    """Leave Tor mode and return to the exit that was in use before it.

    `leave_tor_mode` undoes the isolation but does not touch the exit, so on
    its own it leaves the browser on the Tor exit with the mode gone. This is
    what `tor --off` calls: the two move paths (`switch`, `close_exit`) end
    the mode as a side effect of going somewhere and do not come through here.
    """
    prior = (_read_state() or {}).get("before_tor") or ""
    left = leave_tor_mode()
    if not left:
        return "Tor mode was not on."
    note = "Tor mode ended: " + "; ".join(left) + "."
    if prior and prior != (saved_choice() or {}).get("name"):
        try:
            note += " " + switch(prior)
        except ExitError as exc:
            note += (
                f" The exit from before Tor ({prior}) could not be restored ({exc}); "
                "choose one with net_use."
            )
    else:
        note += " Choose an exit with net_use."
    return note


def set_tor_javascript(enabled: bool) -> str:
    """Turn JavaScript on or off inside Tor mode, keeping the current session.

    Entering the mode sets the cookies aside; this does not. The point is to
    get past a site that answers an empty-handed 406 (DuckDuckGo's onion does)
    without throwing away the circuit and the session you are already on.
    JavaScript is off by default, and this is how someone turns it back on, and
    off again, in place. The browser is closed so the next page reads the new
    setting; what it saw is kept.
    """
    mode = tor_mode()
    if not mode:
        raise ExitError(
            "Tor mode is not on, so there is no Tor JavaScript setting to change. "
            "net_tor_connect enters it, with JavaScript off unless you ask for it."
        )
    if bool(mode.get("javascript")) == bool(enabled):
        return f"JavaScript is already {'on' if enabled else 'off'} in Tor mode; nothing changed."

    sandbox = in_sandbox()
    if sandbox:
        problem = _write_tor_policy(sandbox, enabled)
        if problem:
            raise ExitError(problem)
    updated = dict(mode)
    updated["javascript"] = bool(enabled)
    _write_state(tor_mode=updated)
    if sandbox:
        _close_sandbox_browser(sandbox)
    else:
        _reapply_browser_args()
        restart_browser()

    if enabled:
        return (
            "JavaScript is on in Tor mode now, at your request. The browser was closed so the "
            "next page loads with it, and your Tor session was kept. This hands back the surface "
            "the mode turns off -- fingerprinting, the local network, whatever a page runs -- so "
            "turn it off again (net_tor_connect javascript=false, or `hermes vpn tor "
            "--no-javascript`) once the site that needed it is done."
        )
    return (
        "JavaScript is off in Tor mode again. The browser was closed so the next page loads "
        "without it, and your Tor session was kept."
    )


def tor_connect(url: str = "", javascript: bool | None = None) -> str:
    """Get Tor ready, and only say so once something has come back through it.

    This exists because of what a cold onion looks like. The rendezvous for a
    service nobody has talked to yet can take a minute, and a browser pointed
    at it in the meantime fails with a timeout that reads like a broken site.
    So the circuit is established here, from the plugin, and the browser is
    told to go only after something has actually answered.
    """
    # Already in Tor mode and all this asks is to change JavaScript: do exactly
    # that, keep the session, and leave the circuit alone. It works even if the
    # Tor exit is momentarily unreachable, because the setting is local.
    if tor_mode() and not url.strip() and javascript is not None \
            and bool(javascript) != bool(tor_mode().get("javascript")):
        return set_tor_javascript(bool(javascript))

    target = tor_exit()
    if target is None:
        raise ExitError(
            "no Tor exit is running. As root: "
            f"`docker compose -f {here('contrib/tor-exit/compose.yml')} up -d`. It needs no "
            "credentials, and the hermes-exits network has to exist first — opening any "
            "ordinary exit creates it."
        )

    steps: list[str] = []
    if not tor_mode():
        # Before the switch, not after: the browser is closed and emptied
        # while it is still on the old exit, so the first page Tor carries is
        # the first page this profile has ever asked for.
        steps += enter_tor_mode(bool(javascript))
    elif javascript is not None and bool(javascript) != bool(tor_mode().get("javascript")):
        # Already in Tor mode and opening something that needs the other
        # setting: flip JavaScript in place, keeping the session, then go.
        steps.append(set_tor_javascript(bool(javascript)))
    if current_proxy() != target.proxy or in_sandbox():
        # In a sandbox the host proxy says nothing about where that browser
        # goes, so the switch is what moves the relay and confirms it.
        steps.append(switch(target.name))

    if target.container:
        percent, phase = tor_bootstrap(target.container)
        if percent == -1:
            steps.append(f"Tor's own state could not be read ({phase}).")
        elif percent < 100:
            raise ExitError(
                f"Tor is still starting: {percent}% ({phase}). It is not ready to carry "
                "anything yet, so nothing was opened. Try again in a few seconds."
            )
        else:
            steps.append("Tor reports it is bootstrapped.")

    host = _onion_in(url)
    if not url.strip():
        return " ".join(steps) + (
            " The browser can be opened now. An onion address is a separate matter: ask for "
            "it here first, because the first connection to one can take a minute."
        )

    # It becomes curl's last argument, and curl reads options anywhere on
    # the line: `-K/path` would make it read a file somebody else wrote.
    if urllib.parse.urlsplit(url).scheme not in {"http", "https"}:
        raise ExitError(
            f"{url[:60]!r} is not an http or https address, so nothing was fetched. "
            "This takes the page you want the circuit to, not a command."
        )
    started = time.time()
    body, error = _fetch(url, target.proxy, timeout=ONION_CONNECT_TIMEOUT, single=True)
    took = time.time() - started
    if not body:
        if host:
            _warm_onions.pop(host, None)
        raise ExitError(
            f"{url} did not answer through Tor after {took:.0f}s ({error}). Nothing was "
            "opened. A service that is gone fails in about a second, so a slow failure is "
            "usually worth one more attempt."
        )
    if host:
        _warm_onions[host] = time.time()
    steps.append(
        f"{host or url} answered through Tor in {took:.0f}s, so the circuit is up and the "
        "browser can be pointed at it now."
    )
    return " ".join(steps)


def _measure_exit(target: Exit, sandbox: str) -> tuple[bool, str, str]:
    """(confirmed, address, what to say) for where this agent comes out.

    In a sandbox that question is answered from inside it. Asking the proxy
    from here measures *this* process's way out, which ends at the same Tor
    daemon and is still not the browser's path: the browser goes through its
    profile's relay. Reporting one as the other is the failure the rest of
    this plugin is built to avoid.
    """
    if sandbox:
        ok, said = verify_sandbox(sandbox)
        if not ok:
            return False, "", said
        ip, label, problem = read_sighting(said)
        return (not problem), ip, (problem or label or "the far end")
    seen = look(target.proxy)
    return seen.ok, seen.ip, (seen.place if seen.ok else seen.detail)


def new_circuit(selector: str = "") -> str:
    """Ask Tor for another exit node, and report where it comes out now.

    Measured before and after, because a signal that was accepted is not the
    same as a circuit that changed: Tor coalesces these within about ten
    seconds, so two asks in a row can honestly produce one new circuit and the
    old address.

    The reverse is true as well, and is why the sentence reports a
    measurement rather than a cause. Tor builds a separate circuit per
    destination and rotates them on its own, so two readings minutes apart can
    differ with nobody asking for anything. What this guarantees is that the
    signal was accepted and that the address named was seen after it.
    """
    target = resolve(selector) if selector.strip() else _exit_in_use()
    if target is None:
        raise ExitError(
            "no exit is in use, so there is no circuit to change. `net_tor_connect` first, "
            "or name an exit."
        )
    if target.provider != TOR_PROVIDER:
        raise ExitError(
            f"{target.label} is not a Tor exit"
            + (f" (it is {target.provider})" if target.provider else "")
            + ". A new circuit is a Tor idea; to change where a VPN exit comes out, use "
            "`hermes vpn use <place>` or `hermes vpn open <place>`."
        )
    if not target.container:
        raise ExitError(
            f"{target.label} is listed in {exits_file()} rather than being a container "
            "here, so its control port is not this plugin's to reach. Ask Tor for a new "
            "circuit wherever it runs."
        )

    sandbox = in_sandbox()
    before_ok, before_ip, _before_said = _measure_exit(target, sandbox)
    ok, said = _docker_try("exec", target.container, "sh", "-c", _NEWNYM_SCRIPT, timeout=25)
    if not ok:
        raise ExitError(
            f"the control port of {target.container} could not be reached ({said.strip()[:120]}"
            ") — is this the Tor exit from contrib/tor-exit, with its control port and "
            "cookie?"
        )
    refusal = _read_control_reply(said)
    if refusal:
        raise ExitError(f"Tor did not take the signal: {refusal}")

    # The signal reaches the streams opened after it and none of the ones
    # already open, so the browser holding the old circuit is closed and made
    # to dial again. Tor Browser's own "new identity" closes your tabs for
    # the same reason: a new circuit that leaves the old session running is
    # not a new circuit.
    _last_check_clear()
    closed = _close_sandbox_browser(sandbox) if sandbox else restart_browser()
    after_ok, after_ip, after_said = _measure_exit(target, sandbox)

    if not after_ok:
        return (
            f"Tor took the new circuit, but {target.label} could not be measured afterwards "
            f"({after_said}). Nothing is claimed about where it comes out now."
        )
    moved = (
        f"was {before_ip}, now {after_ip} in {after_said}"
        if before_ok and before_ip != after_ip
        else f"still {after_ip} in {after_said}"
    )
    note = ""
    if before_ok and before_ip == after_ip:
        note = (
            " Tor coalesces these signals within about ten seconds, so asking again right "
            "away gives the same circuit; wait a moment if you need a different node."
        )
    if sandbox:
        note += (
            f" The browser in {sandbox} was closed{'' if closed else ' — or could not be'}, so "
            "the next page it opens dials the new circuit, and the address above was "
            "measured from inside that sandbox."
        )
    elif closed:
        note += f" Closed {closed} browser process(es), so the next page loads through it."
    return f"New Tor circuit on {target.name}: {moved}.{note}"


def _exit_in_use() -> Exit | None:
    """The exit the browser is on, as an Exit rather than a remembered name.

    The name first, and in a sandbox the name only. The host's proxy is a
    value that means nothing to a browser reading a managed policy, and
    matching on it picked whichever exit happened to hold a stale address:
    `net_new_circuit` with nothing named went to the Mexican exit while the
    sandbox was out through Tor. Third time this value has answered for a
    browser that never reads it, after `list` and `doctor`.
    """
    exits = all_exits()
    chosen = (saved_choice() or {}).get("name") or ""
    if chosen:
        named = next((e for e in exits if e.name == chosen), None)
        if named:
            return named
    if in_sandbox():
        return None
    proxy = current_proxy()
    return next((e for e in exits if proxy and e.proxy == proxy), None)


def doctor() -> tuple[bool, str]:
    """Check what protects this agent's browsing and what does not.

    Returns (everything_ok, report). Written to be run by a person right after
    installing: each problem comes with the one command that fixes it, because
    a check that only says "wrong" makes the reader go looking.
    """
    good: list[str] = []
    bad: list[str] = []

    exits = []
    listed = True
    try:
        exits = all_exits()
    except ExitError as exc:
        listed = False
        bad.append(f"✗ exits cannot be listed: {exc} — fix that file, or move it aside")
    if exits:
        good.append(f"✓ {len(exits)} exit(s) available: " + ", ".join(e.label for e in exits))
    elif listed:
        # Only when we actually got the list. Otherwise someone with a typo in
        # their exits file gets told to start a container, right under the
        # complaint about the typo.
        bad.append(
            "✗ no exits yet — start a gluetun container, or run "
            "`hermes vpn provider <name>` to see what your VPN needs"
        )

    if _docker_silent:
        bad.append(f"✗ {_docker_silent}")
    if _sandbox_listing_silent:
        bad.append(
            f"✗ {_sandbox_listing_silent} — until that answers, a sandboxed profile cannot "
            "be told from one browsing on the host, and browser calls are refused while "
            "the kill switch is armed"
        )
    for unusable in _unusable_exits:
        if unusable.endswith(" [labelled]"):
            # Not gluetun, so the advice about gluetun's own settings would
            # send the reader to look for a knob their container does not have.
            bad.append(
                f"✗ {unusable[: -len(' [labelled]')]}. It carries the "
                f"`{EXIT_LABEL}={EXIT_LABEL_VALUE}` label, so it is meant to be an exit: "
                "publish its proxy on loopback — `ports: [\"127.0.0.1:8899:8888\"]` — or "
                "drop the label"
            )
            continue
        bad.append(
            f"✗ {unusable}. Add `HTTPPROXY: on` and publish it — "
            "`ports: [\"127.0.0.1:8891:8888\"]` — and it becomes an exit with no further "
            "configuration. gluetun leaves the proxy off by default, and its own wiki pages "
            "(which `hermes vpn provider <name>` prints) do not mention either setting"
        )
    for rejected in _rejected_exits:
        bad.append(
            f"✗ an entry in {exits_file()} was ignored — {rejected}. Fix that line, or the "
            "exit it names stays unavailable"
        )

    proxy = current_proxy()
    pick = f"`hermes vpn use {exits[0].name}`" if exits else "`hermes vpn open <country>`"
    sandboxed_here = bool(in_sandbox())
    if sandboxed_here:
        # Say nothing about this value here. It is the *host* browser's proxy,
        # and in this profile the browser lives in a container that reads a
        # managed policy instead. Reporting it is false either way: a migrated
        # sandbox looks exitless, and after a switch we would name a loopback
        # port nothing inside that container can reach.
        pass
    elif proxy and proxy != DEAD_END_PROXY:
        good.append(f"✓ the browser is pointed at {proxy}")
    elif proxy == DEAD_END_PROXY:
        # Offer the command here too. The fix is obvious to us and this is
        # still the line a reader is most likely to be stuck on.
        bad.append(
            f"✗ the browser is pointed at a dead end (kill switch armed, no exit chosen) — {pick}"
        )
    elif exits:
        # Only when there is something to choose. Under "no exits yet" this
        # points at a command that answers "no exits are available".
        bad.append(f"✗ the browser is not using any exit — {pick}")

    # Ask the question that fits where the browser actually runs. On the host
    # that's the argument, backed by the policy. In a sandbox the argument
    # isn't ours (Hermes rewrites AGENT_BROWSER_ARGS for the browser it starts
    # in there, and the Bot Screen's dock builds its own argv), so the policy
    # inside the container is the whole protection. Read this host's /etc to
    # answer for a browser in a container and we go green on a filesystem that
    # browser never opens.
    if in_sandbox():
        good.append(
            "· this profile browses from a sandbox, where Hermes overwrites the WebRTC "
            "argument — the policy inside the container is what protects it, checked below"
        )
    else:
        if WEBRTC_ARG in (os.environ.get(BROWSER_ARGS_ENV) or ""):
            good.append("✓ WebRTC is told not to use non-proxied UDP")
        elif proxy:
            bad.append("✗ the WebRTC argument is missing from the browser's arguments")

        if browser_policy_installed():
            good.append(
                f"✓ the browser-wide WebRTC policy is installed ({browser_policy_file()}), "
                "so the argument cannot be lost"
            )
        elif not os.path.exists(helper()):
            # The command and nothing else inside the backticks: they used to
            # wrap the prose too, so the one line here meant to be copied
            # could not be.
            bad.append(
                f"✗ no exit helper at {helper()} — run `{here('contrib/install')} --apply` "
                "as root. Without it exits can be selected but not created, and `harden` "
                "cannot run"
            )
        else:
            bad.append(
                "✗ the browser-wide WebRTC policy is not installed — `hermes vpn harden` "
                "(one file, written by the exit helper)"
            )

    if locked():
        good.append("✓ kill switch armed: no exit means no browsing")
    else:
        good.append("· kill switch disarmed — `hermes vpn lock` to require an exit")

    chosen_standby = str(standby().get("exit") or "")
    if failover_armed():
        if not chosen_standby:
            bad.append(
                "✗ failover is armed with no standby chosen, so it has nowhere to go — "
                "`hermes vpn failover --standby <exit>` names one"
            )
        elif locked():
            good.append(
                f"✓ failover armed: if the exit in use stops answering, the browser moves "
                f"to {chosen_standby}"
            )
        else:
            # Armed and inert. Only the kill switch's check can notice a dead
            # exit, so without it this setting never runs.
            bad.append(
                "✗ failover is armed but the kill switch is not, so nothing checks the exit "
                "before a browser call and failover can never fire — `hermes vpn lock`"
            )
    else:
        good.append(
            "· failover disarmed — `hermes vpn failover` to allow automatic swaps"
            + (f" (standby remembered: {chosen_standby})" if chosen_standby else "")
        )
    if chosen_standby:
        # A standby nobody has looked at is the whole point of checking here:
        # it is what everything else is counting on, on a day nobody expects.
        try:
            waiting = resolve(chosen_standby)
        except ExitError as exc:
            bad.append(f"✗ the standby {chosen_standby} is not available: {exc}")
        else:
            seen = look(waiting.proxy)
            if seen.ok:
                good.append(f"✓ the standby {waiting.label} answers, at {seen.ip} in {seen.place}")
            else:
                bad.append(
                    f"✗ the standby {waiting.label} does not answer ({seen.detail}) — it has "
                    "to be running, because a browser call cannot wait for a tunnel to come up"
                )

    mode = tor_mode()
    if mode:
        good.append(
            "✓ Tor mode: the browser has a cleared profile"
            + (", JavaScript is off" if not mode.get("javascript") else ", JavaScript is on")
            + ", and internal addresses are refused by this plugin instead of by Hermes"
        )
    elif private_urls_allowed():
        # The setting, not the marker: the risk is that Hermes is not
        # refusing internal addresses, and that is true whoever wrote the
        # line. Whether it is ours decides the advice, not the finding.
        ours = PRIVATE_URLS_MARK in _read_profile_config()
        bad.append(
            f"✗ Tor mode is off and {profile_config()} still allows private URLs, so Hermes "
            "is not refusing internal addresses"
            + (
                " from when the mode was on — `hermes vpn tor --off` takes the line out"
                if ours else
                ". This plugin did not write that line, so it will not remove it: take it "
                "out by hand unless you meant it"
            )
        )

    last_move = (_read_state() or {}).get("last_failover")
    if isinstance(last_move, dict) and last_move.get("to"):
        when = last_move.get("at")
        ago = f"{int((time.time() - when) / 60)} min ago" if isinstance(when, (int, float)) else "earlier"
        good.append(
            f"· last automatic swap: {last_move.get('from') or 'an exit'} → "
            f"{last_move['to']} ({ago})"
        )

    for name, state, topology in sandbox_profiles():
        if state == "idle":
            good.append(f"· profile {name!r}: no sandbox running to check")
            continue
        container = sandbox_container(name)
        where = container or "its sandbox"
        if state == "open" and not locked():
            # Expected, not a fault: this is what disarming buys. The policy
            # below is still checked, because WebRTC is about what a page can
            # read and that question does not go away.
            good.append(
                f"· profile {name!r}: its sandbox has a network of its own ({topology}) "
                "because the kill switch is disarmed, so its browser can leave by this "
                "host's address. Arming the switch seals it again"
            )
        elif state == "sealed":
            good.append(
                f"✓ profile {name!r}: its sandbox has no way to the internet except the "
                f"tunnel ({topology})"
            )
            reachable = sandbox_reaches_host(container)
            if reachable:
                listed = ", ".join(str(port) for port in reachable)
                risky = [port for port in reachable if port in (2375, 2376)]
                good.append(
                    f"· profile {name!r}: this host itself answers on port(s) {listed} from "
                    "inside that sandbox — sealed means no internet except the tunnel, not "
                    "isolated from this machine. That is this host's firewall policy, not "
                    "the plugin's to change"
                    + (
                        f". Port {risky[0]} is the docker API, which is root here — that one "
                        "is worth closing"
                        if risky else ""
                    )
                )
        else:
            bad.append(
                f"✗ profile {name!r}: its sandbox can reach the internet directly ({topology}), "
                "so a browser or a command in there goes out by this machine's own address. "
                "It can be sealed while it runs, without recreating it: "
                f"`{here('contrib/vpn-migrate')} {container} {name}`"
            )

        verdict, detail = sandbox_policy_state(container)
        if verdict == "ok":
            good.append(
                f"✓ profile {name!r}: the policy inside {where} points that browser at the "
                "exit and disables non-proxied UDP"
            )
        elif verdict == "unknown":
            bad.append(
                f"✗ profile {name!r}: the policy inside {where} could not be read ({detail}), "
                "so nothing here is a statement about that browser"
            )
        elif verdict == "wrong":
            # Both remedies only ever write `vpn.json`, so neither can fix a
            # fault that lives in another file in that directory. Chrome merges
            # them all, which is how such a file wins. Say which case it is.
            ours = SANDBOX_POLICY_NAME in detail
            remedy = (
                f"The next `hermes vpn use <place>` rewrites it, or "
                f"`{here('contrib/vpn-migrate')} {container} {name}`"
                if ours else
                f"That is not the file this plugin writes ({SANDBOX_POLICY_NAME}), so a "
                f"switch cannot repair it: remove it inside the container, or decide it is "
                f"meant to be there"
            )
            bad.append(
                f"✗ profile {name!r}: the policy inside {where} is there but does not protect "
                f"that browser — {detail}. {remedy}"
            )
        elif state == "sealed":
            # Sealed and no policy fails shut, not open: the file carries the
            # proxy and the network is internal, so pages just don't load.
            # Worth fixing, not worth dressing up as a leak.
            bad.append(
                f"✗ profile {name!r}: no policy inside {where} — that browser reads /etc in "
                f"the container, not on this host. Since the same file carries the proxy and "
                f"the network is sealed, pages there will not load at all. The next "
                f"`hermes vpn use <place>` writes it back, or `{here('contrib/vpn-migrate')} {container} {name}`"
            )
        else:
            bad.append(
                f"✗ profile {name!r}: no policy inside {where} and that sandbox is not sealed, "
                f"so WebRTC in there can hand out this machine's own address. "
                f"`{here('contrib/vpn-migrate')} {container} {name}`"
            )

        # Everything above is about the shape of the way out. This asks the
        # only question that shape cannot answer: does anything come back?
        # A profile whose relay has no country chosen is sealed, carries a
        # correct policy, and loads nothing.
        if name == current_profile() and sandbox_is_direct():
            seen = look_inside(container)
            good.append(
                f"· profile {name!r}: off the tunnel on purpose (kill switch disarmed, no "
                "exit chosen)"
                + (f" — from inside it comes out at {seen.ip} in {seen.place}" if seen.ok
                   else f" — asking from inside did not come back ({seen.detail})")
            )
            continue
        answers, said = verify_sandbox(container)
        if answers:
            good.append(f"✓ profile {name!r}: checked from inside — {said}")
        elif "no verifier" in said:
            good.append(
                f"· profile {name!r}: cannot be checked from inside ({said}); "
                f"`{here('contrib/install')} --apply` installs the verifier"
            )
        else:
            bad.append(
                f"✗ profile {name!r}: nothing comes back from inside {where} ({said}). If no "
                f"country has been chosen for this profile yet, its relay refuses every "
                f"connection until one is: `hermes -p {name} vpn use <place>`"
            )

    # A one-line verdict and a legend first: the three marks carry the meaning, and
    # the reader should know the answer before reading the list. Problems lead.
    legend = "Marks: \u2713 good \u00b7 note (no action) \u2717 needs action"
    verdict = (
        f"{len(bad)} thing(s) need action." if bad else "All clear \u2014 nothing needs action."
    )
    report = "\n".join([verdict, legend, "", *bad, *good])
    if bad:
        report += "\n\nRun `hermes vpn doctor` again after fixing, and "
        report += f"`python3 {leak_test_command()}` for a measurement rather than a checklist."
    return (not bad, report)


def leak_test_command() -> str:
    """How to run the leak test *here*, with this host's paths filled in.

    The script's own defaults are one machine's paths, so the command is built
    with the chrome binary and driver found on this host instead.
    """
    parts = [here("webrtc-leak-test.py")]
    binaries = _browser_binaries()
    if binaries:
        parts.append(f"--chrome {binaries[0]}")
    proxy = current_proxy()
    if proxy and proxy != DEAD_END_PROXY:
        parts.append(f"--proxy {proxy}")
    return " ".join(parts)


def harden() -> str:
    """Install the browser-wide WebRTC policy through the root helper."""
    found = browser_policy_file()
    if found:
        # Report the path we found, not the one we would have written: the setting
        # may live in vpn.json, and naming a file that isn't there sends the
        # reader hunting for it.
        return f"Already installed: {found}"
    said = _run_helper("harden-browser")
    return said or "done"


def unharden() -> str:
    """Remove the browser-wide WebRTC policy, through the root helper.

    The CLI had no way to undo `harden`, although the helper has implemented
    the verb all along -- so the only documented way out was to delete a file
    in /etc by hand.
    """
    if not browser_policy_file():
        return "There is no managed WebRTC policy to remove."
    said = _run_helper("unharden-browser")
    return said or "done"


def describe_providers() -> str:
    """What is set up here, and what could be -- the two are different questions."""
    available = guides()
    lines = []
    try:
        configured = configured_providers()
    except ExitError as exc:
        lines.append(f"Which providers are set up could not be determined: {exc}")
        configured = []
    else:
        if configured:
            # Show the name to pass only when it differs from the provider's
            # own, since `--provider` resolves to <name>.env in the helper's
            # directory: surfshark credentials in work.env are "surfshark" to
            # the provider and "work" to the flag. The default file `.env` has
            # an empty stem and needs no flag, so print it bare.
            named = [
                name if name == stem or not stem else f"{name} (pass provider: {stem})"
                for name, stem in sorted(set(configured))
            ]
            lines.append("Credentials are configured for: " + ", ".join(named))
        else:
            lines.append(
                "No VPN credentials are configured on this host yet, so exits cannot be "
                "opened. Add one with `hermes vpn provider <name> --set`, which prompts at "
                "the terminal and writes the root-only file for you. The helper's "
                f"environment directory and a starter template come from "
                f"`{here('contrib/install')} --apply`, run as root."
            )
    if available:
        lines.append("Setup guides are available for: " + ", ".join(available))
        lines.append(
            "Ask for one by name to see exactly which values that provider needs and where "
            "in its dashboard to find them."
        )
    return "\n".join(lines)


def open_exit(place: str, *, city: bool = False, provider: str = "") -> tuple[str, str]:
    """Bring up a new exit for a place. Returns (exit name, what the helper said)."""
    place = (place or "").strip()
    if not place:
        raise ExitError("which country or city should the new exit be in?")
    if not os.path.exists(helper()):
        raise ExitError(
            f"no exit helper at {helper()}: exits can be selected but not created. That "
            f"half is installed by a person as root — `{here('contrib/install')} --apply` — "
            "and this plugin cannot do it, which is the point of it. A gluetun container "
            "started by hand is discovered without any of this."
        )

    extra: list[str] = ["--city"] if city else []
    if provider.strip():
        extra += ["--provider", provider.strip().lower()]
    said = _run_helper("up", place, *extra)
    name = said.split()[0] if said else ""
    if not name.startswith("exit-"):
        raise ExitError(f"the helper answered something unexpected: {said[:200]}")
    return name, said


def profiles_using(name: str) -> list[str]:
    """Which other profiles' relays point at this exit right now.

    Read from the relay, not from this process's state: each profile has its
    own relay and its own upstream file, which is the whole point of them.
    Asking only "is this the exit *I* am on" was the hole in that promise --
    closing a container another bot's sealed sandbox depends on leaves it
    with no way out, and nothing connects the two events for whoever is
    reading its `doctor` afterwards.
    """
    found: list[str] = []
    for profile, state, _detail in sandbox_profiles():
        if state == "idle":
            continue
        upstream = _docker("exec", f"vpn-relay-{profile}", "cat", f"/upstream/{profile}")
        if upstream.strip().partition(":")[0] == name:
            found.append(profile)
    return found


def close_exit(name: str, force: bool = False) -> str:
    if not os.path.exists(helper()):
        raise ExitError(f"no exit helper at {helper()}")
    name = name.strip()
    depending = [p for p in profiles_using(name) if p != current_profile()]
    if depending and not force:
        raise ExitError(
            f"{name} is what "
            + (f"profile {depending[0]!r} is" if len(depending) == 1
               else f"profiles {', '.join(repr(p) for p in depending)} are")
            + " browsing through, and their sandboxes have no other way out. Closing it "
            "leaves them with none, and nothing in their own `doctor` would connect that "
            "to this. Ask first; then close it again with force."
        )
    # Clear the browser if this exit is the one in use. The port goes back in
    # the pool and `open` allocates from the bottom again, so a later exit in
    # another country can bind it and inherit the browser with no `use` at all.
    try:
        standing = next((item for item in all_exits() if item.name == name), None)
    except ExitError:
        # We don't need the exits file to shut a tunnel down, so don't let an
        # unparseable one leave a paid exit running. Without `standing` the
        # browser is left alone below.
        standing = None
    said = _run_helper("down", name)
    if standing and current_proxy() == standing.proxy:
        # Tor mode runs over this exit. With the exit gone it cannot work, so
        # end it here rather than leave the state saying it is on, the config
        # loosened and doctor asserting a cleared profile over a dead exit.
        # Before the browser args are set below, which then win.
        tor_ended = ""
        if tor_mode():
            left = leave_tor_mode()
            tor_ended = f" Tor mode ended first: {'; '.join(left)}." if left else ""
        if locked():
            # Dead end, not `apply(None)`: that drops the WebRTC switch too.
            os.environ[BROWSER_ARGS_ENV] = browser_args(DEAD_END_PROXY)
            _save_state(None)
            tail = (
                "\nIt was the exit in use, so the browser now points at a dead end: the "
                "kill switch is armed, so pick another with `hermes vpn use <exit>`."
            )
        else:
            apply(None)
            tail = (
                "\nIt was the exit in use, so the browser has none now: pick another with "
                "`hermes vpn use <exit>`, or arm the kill switch to make that a refusal."
            )
        said = (said or "").rstrip() + tail + tor_ended
    return said


def why_no_exits() -> str:
    """What is actually in the way, when the list comes back empty.

    Discovery already knows: a gluetun container running with its proxy
    unpublished, or docker refusing to answer at all. Both were computed and
    then thrown away, so the first sentence anybody hears told them to start
    a container they already had running -- and `after-install.md` promises
    in as many words that this plugin says which of the two it is.
    """
    if _docker_silent:
        return (
            f"No exits could be discovered: {_docker_silent} Nothing here is a statement "
            "about what is running."
        )
    if _unusable_exits:
        found = "; ".join(_unusable_exits)
        return (
            f"No exits available, but something is close: {found}. Add `HTTPPROXY: on` and "
            'publish the port -- `ports: ["127.0.0.1:8891:8888"]` -- and it becomes an exit '
            "with no further configuration."
        )
    return (
        "No exits available yet. `hermes vpn open <country>` brings one up when the helper "
        "and credentials are installed, `net_providers` says whether they are, and "
        f"`hermes vpn doctor` checks the rest. An exit of your own goes in {exits_file()}."
    )


def describe_exits() -> str:
    """List the exits and say which one is in use, without probing them all."""
    exits = all_exits()
    if not exits:
        return why_no_exits()
    # In a sandbox the host's proxy says nothing: that browser reads a managed
    # policy and its exit is the relay's upstream, which `switch_sandbox`
    # records by name. Marking the host's value here is how `list` came to say
    # Tor while `where` and `doctor` said Mexico, with the sandbox out through
    # Mexico and the sentence naming the exit it used an hour ago.
    sandbox = in_sandbox()
    chosen = str((saved_choice() or {}).get("name") or "") if sandbox else ""
    active = "" if sandbox else current_proxy()
    lines = []
    for item in exits:
        in_use = item.name == chosen if sandbox else bool(active) and item.proxy == active
        mark = " <- in use" if in_use else ""
        # The provider matters when two subscriptions both have a Japan: it is
        # how a reader tells which exit is which, and what failover would pick.
        via = f" | {item.provider}" if item.provider else ""
        lines.append(
            f"- {item.name} | {item.country or 'country not declared'} | {item.proxy} | "
            f"{item.source}{via}{mark}"
        )
    if sandbox and not chosen:
        lines.append(
            f"- no exit chosen for the sandbox {sandbox}: with the kill switch disarmed its "
            "browser leaves by this host's own address, and `net_where` measures it"
            if not locked() else
            f"- none chosen yet for the sandbox {sandbox}, and the kill switch is armed, so "
            "it is not browsing at all"
        )
    elif active == DEAD_END_PROXY:
        lines.append(
            "- none in use: the browser is pointed at a dead end because the kill switch is "
            "armed and no exit is chosen"
        )
    elif not active and not sandbox:
        lines.append("- direct (no proxy) <- in use")
    return "Exits:\n" + "\n".join(lines)


def sandbox_is_direct() -> bool:
    """Is this sandbox deliberately off the tunnel?

    The same rule the policy writer uses, so the two cannot disagree: the
    kill switch is down and no exit is chosen. Anything else means the
    browser in there is pointed at the relay.
    """
    return bool(in_sandbox()) and not locked() and not saved_choice()


def look_inside(container: str) -> Sighting:
    """Where the sandbox comes out when it is not going through the exit.

    The verifier cannot answer this one: it measures through the relay, and
    in this state there is nothing behind the relay. So the question is put
    from inside the container, directly, which is how that browser is
    leaving. Still a measurement, not an assumption -- this plugin has no
    business reporting the host's address as the sandbox's without asking.
    """
    if not TRACE_URL:
        return Sighting(ok=False, unverifiable=True, detail="no trace endpoint configured")
    # `--noproxy '*'` is the whole point of this call. `vpn-migrate` writes
    # `proxy = http://vpn-exit:8888` into the sandbox's ~/.curlrc so that
    # curl and pip in there go through the tunnel too, and without this the
    # measurement went through the relay and reported the exit's address as
    # the one a direct browser would show -- right-looking and wrong.
    ok, said = _docker_try(
        "exec", container, "curl", "-q", "-sS", "--noproxy", "*",
        "--max-time", str(LOOKUP_TIMEOUT), TRACE_URL,
        timeout=LOOKUP_TIMEOUT + 6,
    )
    if not ok:
        return Sighting(ok=False, detail=f"asking from inside failed ({said.strip()[:80]})")
    address, code = _read_trace(said)
    if not _is_an_address(address):
        return Sighting(ok=False, detail=f"the answer carried no address ({said.strip()[:60]})")
    return Sighting(ok=True, ip=address, country=code)


def _switch_and_tor_notes(exit_name: str = "") -> tuple[str, str]:
    """The two clauses every answer about "where am I" has to carry.

    Both ways on the switch, because silence cannot be told from "this tool
    does not report that". And the Tor caveat wherever a Tor exit is the
    answer. Computed once and used by both paths: three times today a
    sentence was added to the host branch and the profiles that browse from
    containers -- the ones this plugin is for -- never saw it.
    """
    guard = " The kill switch is armed." if locked() else " The kill switch is disarmed."
    on_tor = any(
        e.provider == TOR_PROVIDER and (e.name == exit_name or e.proxy == current_proxy())
        for e in all_exits()
    )
    tor_note = (
        " This is a Tor exit, and T1 is Cloudflare's code for one. Tor rotates circuits on "
        "its own, so another check can report a different address in a different country "
        "with nothing being wrong."
        if on_tor else ""
    )
    return guard, tor_note


def describe_here() -> str:
    """What the browser's traffic looks like from outside, right now."""
    sandbox = in_sandbox()
    if sandbox and sandbox_is_direct():
        # Not "could not confirm": there is nothing to confirm through. The
        # verifier measures the tunnel, and this sandbox is deliberately off
        # it, so the honest answer is where it comes out now.
        seen = look_inside(sandbox)
        where = (
            f" From inside, the far end reports {seen.ip} in {seen.place}."
            if seen.ok else f" Asking from inside did not come back ({seen.detail})."
        )
        return (
            f"This agent browses from the sandbox {sandbox}, and it is off the tunnel: the "
            "kill switch is disarmed and no exit is chosen, so it leaves by this host's "
            "own address." + where + " `hermes vpn use <place>` puts it back on an exit."
        )
    if sandbox:
        ok, said = verify_sandbox(sandbox)
        if not ok:
            return (
                f"This agent browses from the sandbox {sandbox}, and it could not confirm "
                f"where it comes out ({said}). Treat the location as unknown."
            )
        ip, code, _problem = read_sighting(said)
        # Take the shape from the topology we inspected. `in_sandbox()` is
        # true for an open sandbox too, so it can't tell us the tunnel is the
        # only way out.
        here = current_profile()
        shape = next((state for name, state, _t in sandbox_profiles() if name == here), "")
        sealed = (
            "which has no way to the internet except the tunnel"
            if shape == "sealed"
            else "which can also reach the internet directly, so the exit is not the only way out"
        )
        guard, tor_note = _switch_and_tor_notes(str((saved_choice() or {}).get("name") or ""))
        return (
            f"This agent browses from the sandbox {sandbox}, {sealed}, and is seen as "
            f"{ip} ({code}). Checked from inside just now.{guard}{tor_note}"
        )

    proxy = current_proxy()
    if locked() and (not proxy or proxy == DEAD_END_PROXY):
        # Armed with no exit, so every browser call is refused and there is no
        # browser egress to describe. Report this host's address as this host's.
        here = look()
        seen = f" This host itself is seen as {here.ip} ({here.place})." if here.ok else ""
        return (
            "Browser tools are currently refused: the kill switch is armed and no exit is "
            f"selected, so nothing is allowed out by this host's own address.{seen} "
            "`hermes vpn use <exit>` to choose one."
        )
    sighting = look(proxy)
    through = f"through {proxy}" if proxy else "directly, with no proxy"
    guard, tor_note = _switch_and_tor_notes()
    if not sighting.ok:
        return (
            f"The browser is set to leave {through}, but the check failed "
            f"({sighting.summary}). Treat the location as unknown — and if an exit was "
            f"selected, it may have dropped.{guard}"
        )
    return (
        f"The browser leaves {through} and is seen as {sighting.ip} ({sighting.place}). "
        f"Checked just now in {sighting.elapsed:.1f}s.{guard}{tor_note}"
    )
