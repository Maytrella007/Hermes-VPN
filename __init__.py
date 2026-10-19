"""hermes-vpn: let the agent choose which way its browser leaves.

Registers fifteen tools (``net_exits``, ``net_use``, ``net_where``, ``net_places``,
``net_providers``, ``net_provider_setup``, ``net_add_provider``, ``net_open``, ``net_close``, ``net_lock``,
``net_failover``, ``net_tor_connect``, ``net_new_circuit``, ``net_doctor``,
``net_harden``) and the ``hermes vpn`` command. An exit is a local proxy; gluetun containers are
discovered automatically, anything else is listed in a file.

Nothing here implements a tunnel. The point of the plugin is the part that was
missing: an agent that can pick an exit *and knows which one it actually got*.
"""

from __future__ import annotations

import logging
import os
import sys

# Importable whether Hermes loaded the plugin or someone ran the CLI.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from typing import Any

import netexits

logger = logging.getLogger(__name__)

__version__ = "0.2.0"

TOOLSET = "net_exits"


def _schema(name: str, description: str, properties: dict[str, Any], required=None) -> dict[str, Any]:
    params: dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        params["required"] = required
    params["additionalProperties"] = False
    return {"name": name, "description": description, "parameters": params}


NET_EXITS_SCHEMA = _schema(
    "net_exits",
    "List the network exits the agent's browser can leave by, and which one is in use. "
    "Each exit is a local proxy with a name and usually a country. Call this before "
    "net_use when you do not know the exact names.",
    {},
)

NET_USE_SCHEMA = _schema(
    "net_use",
    "Send the agent's browser out through one of the exits — use this when someone asks "
    "to browse from another country. The exit is checked first and the switch is "
    "abandoned if it does not answer, so a dropped tunnel never leaves the browser "
    "quietly on the server's own address. The running browser is closed so the next page "
    "loads through the new exit; pass 'direct' to stop using a proxy at all. The answer "
    "reports the address and place the far end actually saw, which is what you should "
    "repeat back — not the exit's label. To browse by Tor, call net_tor_connect instead: "
    "selecting the Tor exit here gives the exit without the mode, so the session, the "
    "cookies and JavaScript stay as they were.",
    {
        "exit": {
            "type": "string",
            "description": (
                "Exit name, a country, a distinctive fragment of either, or 'direct' "
                "for no proxy."
            ),
        },
        "restart_browser": {
            "type": "boolean",
            "description": (
                "Close the running browser so the change takes effect immediately "
                "(default true). False leaves an open browser on the old exit until it "
                "idles out. Ignored in a profile whose terminal is a container: there the "
                "exit moves at the relay and no browser needs restarting."
            ),
        },
    },
    required=["exit"],
)

NET_WHERE_SCHEMA = _schema(
    "net_where",
    "Check where the agent's browser appears to be right now, by making a request and "
    "reading back the address the far end saw. Use it to answer 'where am I browsing "
    "from', and whenever a site behaves as if it dislikes the connection — a datacenter "
    "address explains a lot of blocks and verification prompts. It reports what is true "
    "now rather than what was selected earlier, so it also catches a tunnel that dropped.",
    {},
)


def handle_list(args: dict[str, Any], **_kw: Any) -> str:
    try:
        return netexits.describe_exits()
    except netexits.ExitError as exc:
        return f"Could not list the exits: {exc}"


def handle_use(args: dict[str, Any], **_kw: Any) -> str:
    selector = str(args.get("exit") or "")
    restart = args.get("restart_browser")
    try:
        return netexits.switch(selector, restart=True if restart is None else bool(restart))
    except netexits.ExitError as exc:
        return f"Could not change the exit: {exc}"


NET_OPEN_SCHEMA = _schema(
    "net_open",
    "Bring up a new exit in a country or city that is not running yet, and switch to it. "
    "Use this when someone names a place the existing exits do not cover — "
    "'connect to a server in Miami'. Say that bringing a tunnel up takes tens of seconds "
    "and that you will report back when it answers, then call this; prefer net_use when "
    "an exit for that place already exists. On a timeout the helper keeps going as root, "
    "so the exit can still turn up afterwards: net_exits settles that, not a second "
    "net_open. The new exit stays up until it is closed with net_close.",
    {
        "place": {
            "type": "string",
            "description": (
                "One place name on its own: 'Mexico', 'Miami', 'New York'. No commas, no "
                "country code, nothing like 'Miami, USA' — the helper refuses those, and "
                "net_places says how this provider spells it."
            ),
        },
        "provider": {
            "type": "string",
            "description": (
                "Which configured VPN to use. net_providers lists them, and when it "
                "lists more than one, ask which subscription rather than letting it "
                "default: the answer names the exit, not the provider behind it."
            ),
        },
        "city": {
            "type": "boolean",
            "description": (
                "Rarely needed: a place is tried as a country and then as a city "
                "automatically. Set it only to force a city when a country of the same "
                "name also exists."
            ),
        },
        "switch": {
            "type": "boolean",
            "description": "Switch the browser to it once it is up (default true).",
        },
    },
    required=["place"],
)

NET_CLOSE_SCHEMA = _schema(
    "net_close",
    "Shut down an exit that was opened with net_open and free its resources. Only exits "
    "created by the helper can be closed; ones defined in the host's own configuration are "
    "left alone. On a host with more than one profile this refuses when another profile's "
    "browser is going through that exit, and names it: ask that person before passing "
    "force, because their sandbox has no other way out and nothing in their own "
    "diagnostics would connect losing it to this.",
    {
        "name": {
            "type": "string",
            "description": (
                "The exit's name, as net_exits lists it. Only exits this plugin created "
                "(named 'exit-...') can be closed; one started by hand is left alone."
            ),
        },
        "force": {
            "type": "boolean",
            "description": (
                "Close it even though another profile is browsing through it. Only after "
                "asking, and say which profile is losing its way out."
            ),
        },
    },
    required=["name"],
)


NET_PLACES_SCHEMA = _schema(
    "net_places",
    "Ask which countries and cities a VPN provider offers, before trying to open an exit "
    "there. With no search term it summarises and lists the countries; with one it returns "
    "the matching countries and cities. The provider defaults to the one the running exits "
    "use, and any of the ones gluetun knows can be named instead — so 'what could I reach "
    "with Mullvad?' is answerable without having a Mullvad subscription.",
    {
        "search": {
            "type": "string",
            "description": "Part of a country or city name. Omit to list the countries.",
        },
        "provider": {
            "type": "string",
            "description": "A VPN provider gluetun knows, such as mullvad or nordvpn. "
            "Defaults to the one in use.",
        },
    },
)


def handle_places(args: dict[str, Any], **_kw: Any) -> str:
    try:
        return netexits.find_places(
            str(args.get("search") or ""), str(args.get("provider") or "")
        )
    except netexits.ExitError as exc:
        return f"Could not read the list of places: {exc}"


NET_PROVIDERS_SCHEMA = _schema(
    "net_providers",
    "Which VPN providers this host has credentials for, and which ones there are setup "
    "guides for. Ask this when someone mentions a VPN by name and you do not know whether "
    "it is set up here, and again right after they have added one, to confirm it is now "
    "configured before you open an exit for it.",
    {},
)

NET_PROVIDER_SETUP_SCHEMA = _schema(
    "net_provider_setup",
    "Explain how to set up a particular VPN provider: which values it needs, where in that "
    "provider's dashboard to find them, and the configuration that uses them. Answers from "
    "guides shipped with the plugin, so it works without searching the web. Use it whenever "
    "someone says 'connect to my AirVPN' or asks what you need from them — read the guide "
    "and tell them the steps rather than guessing. Then drive the rest: have them run the "
    "`hermes vpn provider <name> --set` command the guide gives in their terminal (the "
    "Terminal tab in Hermes Desktop or the dashboard, or their shell over SSH) and paste the "
    "config there. If they offer to paste the credentials to you in chat, decline and point "
    "them back to that terminal — the key must not pass through this conversation. When they "
    "say it is done, call net_providers to confirm it is configured, then offer to open an "
    "exit for it.",
    {
        "provider": {
            "type": "string",
            "description": "The provider's name, such as airvpn, mullvad or nordvpn.",
        }
    },
    required=["provider"],
)


NET_LOCK_SCHEMA = _schema(
    "net_lock",
    "Arm or disarm the kill switch — what people also call security mode, safe mode or "
    "'modo seguridad'. Armed, the agent's browser may only leave by a selected exit: if "
    "that exit stops answering, browser tools are refused rather than quietly allowed out "
    "by this machine's own address, and switching to 'direct' is refused too. Arm it when "
    "someone wants their browsing not to fall back to the server's real address. It guards "
    "the browser tools, which is where browsing happens; a shell or a fetch tool is not the "
    "browser and is not covered. In a profile whose terminal is a container, what gets "
    "checked is that sandbox's own way out, confirmed from inside it. Disarm it only when "
    "they ask plainly.",
    {
        "armed": {
            "type": "boolean",
            "description": "True to arm the kill switch, false to disarm it.",
        }
    },
    required=["armed"],
)


NET_FAILOVER_SCHEMA = _schema(
    "net_failover",
    "Arm or disarm failover, which is off by default, and name the standby exit it moves "
    "to. The standby is chosen by the person, not guessed: ask which city or country they "
    "want it to come out of, preferably on a different VPN provider so that a subscription "
    "failing does not take both. Call this with armed=true and no standby to find out what "
    "is missing — it answers with the providers configured here and does not arm until one "
    "is chosen. Open the exit first with net_open, then name it here. It has to stay "
    "running: bringing a tunnel up takes tens of seconds and a browser call cannot wait. "
    "If the standby is down too when it is needed, the call is refused and the kill switch "
    "holds the browser. Tor is never a standby.",
    {
        "armed": {
            "type": "boolean",
            "description": "True to arm failover, false to disarm it.",
        },
        "standby": {
            "type": "string",
            "description": (
                "The exit that takes over, by name, as net_exits lists it. It is checked "
                "when named: one that does not answer is refused rather than remembered."
            ),
        },
    },
    required=["armed"],
)


NET_TOR_CONNECT_SCHEMA = _schema(
    "net_tor_connect",
    "Connect through Tor and wait until the circuit actually carries something, before "
    "any browser is pointed at it. This also puts the browser in Tor mode: its cookies "
    "and sessions are cleared on the way in and again on the way out, JavaScript is off "
    "unless asked for, device permissions are denied, and the browser is allowed to open "
    "an address that only Tor can resolve while this plugin refuses the internal ones. "
    "Ask before calling it: entering Tor mode closes the browser and sets its cookies and "
    "sessions aside, so every logged-in site is logged out. In a profile whose browser "
    "runs in a container that session cannot be restored from here; on the host the "
    "ordinary profile is kept and comes back when Tor mode ends. "
    "Use this whenever someone asks to browse by Tor, and "
    "always before opening a .onion address: pass the address and this establishes the "
    "circuit to that service, which on a first connection can take a minute. Tell the "
    "person it may take a moment and that you will say when it is up, then call this; "
    "the answer reports what actually came back and how long it took, and only then "
    "should a browser tool be used. A browser call to an onion that has not been reached "
    "this way is held, because it would wait and then fail as if the site were broken.",
    {
        "url": {
            "type": "string",
            "description": (
                "The address to establish the circuit to, usually a .onion. Leave it out "
                "to switch to Tor and confirm it is bootstrapped without fetching "
                "anything."
            ),
        },
        "javascript": {
            "type": "boolean",
            "description": (
                "Leave JavaScript on (default false). Tor mode turns it off, which is "
                "what Tor Browser's safest level does; some sites need it and will look "
                "broken without it (DuckDuckGo's onion answers an empty 406 without it). "
                "Say that you are turning it on when you do. While already in Tor mode "
                "this toggles the setting in place and keeps the session, so pass true to "
                "get past such a site and false to turn it back off; leave it out to keep "
                "the current setting."
            ),
        },
        "off": {
            "type": "boolean",
            "description": (
                "End Tor mode instead of starting it: clears the browser again, puts "
                "JavaScript and the internal-address refusal back, and leaves the exit "
                "for you to choose with net_use."
            ),
        }
    },
)


NET_NEW_CIRCUIT_SCHEMA = _schema(
    "net_new_circuit",
    "Ask Tor for another exit node, when a site refuses the one in use. This is a Tor "
    "idea and only works on a Tor exit: a VPN exit is moved with net_use or net_open "
    "instead. The exit is measured before and after, and the answer says whether the "
    "address actually changed, because Tor coalesces these requests within about ten "
    "seconds and two asks in a row can honestly produce one new circuit.",
    {
        "exit": {
            "type": "string",
            "description": (
                "Which exit to ask. Defaults to the one the browser is using."
            ),
        }
    },
)


NET_DOCTOR_SCHEMA = _schema(
    "net_doctor",
    "Check what is protecting this agent's browsing and what is not: exits, whether the "
    "browser is using one, the WebRTC protections, the kill switch, and whether a "
    "sandboxed profile's browser (where a Bot Screen runs) is tunnelled or leaking. Each "
    "problem comes with the command that fixes it. Run it when someone asks whether their "
    "setup is safe, or when something behaves as if the location is not what you think.",
    {},
)


def handle_doctor(args: dict[str, Any], **_kw: Any) -> str:
    try:
        ok, report = netexits.doctor()
    except netexits.ExitError as exc:
        return f"Could not check: {exc}"
    return report


def handle_lock(args: dict[str, Any], **_kw: Any) -> str:
    try:
        return netexits.set_locked(bool(args.get("armed")))
    except netexits.ExitError as exc:
        return f"Could not change the kill switch: {exc}"


def handle_tor_connect(args: dict[str, Any], **_kw: Any) -> str:
    try:
        if args.get("off"):
            return netexits.end_tor_mode()
        js = args.get("javascript")
        return netexits.tor_connect(
            str(args.get("url") or ""), javascript=None if js is None else bool(js)
        )
    except netexits.ExitError as exc:
        return f"Not connected: {exc}"


def handle_new_circuit(args: dict[str, Any], **_kw: Any) -> str:
    try:
        return netexits.new_circuit(str(args.get("exit") or ""))
    except netexits.ExitError as exc:
        return f"No new circuit: {exc}"


def handle_failover(args: dict[str, Any], **_kw: Any) -> str:
    try:
        named = str(args.get("standby") or "").strip()
        said = netexits.set_standby(named) + " " if named else ""
        return said + netexits.set_failover(bool(args.get("armed")))
    except netexits.ExitError as exc:
        return f"Could not change failover: {exc}"


#: Keyword names a host might pass the tool's name under. The shape of the
#: middleware call is not written down anywhere, so all of them are accepted
#: and a positional string is taken as a fallback.
_NAME_KEYS = ("tool_name", "name", "tool", "tool_id")


def _tool_name_from(args, kwargs) -> str | None:
    """The tool's name out of whatever shape the host called us with.

    None when it cannot be determined, which is a refusal while armed rather
    than a pass: a guard that does not know what it is guarding is not a
    guard. `str(b"browser_navigate")` is `"b'browser_navigate'"`, which fails
    the prefix test, so bytes are decoded rather than stringified.
    """
    for key in _NAME_KEYS:
        if key in kwargs and kwargs[key] is not None:
            found = kwargs[key]
            break
    else:
        found = next((a for a in args if isinstance(a, (str, bytes))), None)
    if isinstance(found, bytes):
        return found.decode("utf-8", "replace")
    return found if isinstance(found, str) else None


def _guard_browser_tools(*args, **kwargs):
    """Hold a browser call when the kill switch says the way out is not safe.

    Registered as tool-execution middleware so the refusal happens before the
    browser is asked to do anything. Chromium pointed at a dead proxy would
    fail by itself, but it would fail looking like a broken website; this says
    what really happened.

    The signature accepts anything. The shape of this call is a contract with
    the host and is not documented, and a signature mismatch would mean the
    kill switch never runs.
    """
    tool_name = _tool_name_from(args, kwargs)
    next_call = kwargs.get("next_call") or next(
        (a for a in args if callable(a)), None
    )
    call_args = kwargs.get("args")
    if call_args is None:
        call_args = next((a for a in args if isinstance(a, dict)), None)

    if tool_name is None:
        if netexits.locked():
            return (
                "Refused: the kill switch is armed and this plugin could not tell which "
                "tool was being called, so it cannot tell whether it is a browser. "
                "Nothing is trusted until it can."
            )
        if next_call is None:
            raise TypeError("tool_execution middleware called without next_call")
        return next_call(call_args)

    try:
        refusal = netexits.guard_browser(tool_name, call_args)
    except Exception as exc:  # noqa: BLE001
        # A guard that could not run has not said yes. While armed, an
        # exception here refuses the call: the kill switch is for the case
        # where something is broken, so the check failing is itself a reason to
        # hold the browser. Disarmed, it allows the call.
        if not netexits.locked():
            refusal = ""
        else:
            refusal = (
                "Refused: the kill switch is armed and this plugin could not check the "
                f"exit ({type(exc).__name__}: {exc}). Nothing is trusted until it can — "
                "`hermes vpn doctor`, or disarm the kill switch deliberately."
            )
    if refusal:
        return refusal
    if next_call is None:
        raise TypeError("tool_execution middleware called without next_call")
    # Taken whatever happens next, so a note never arrives on a later call
    # describing a move that is no longer the reason for anything.
    note = netexits.take_failover_note()
    try:
        result = next_call(call_args)
    except BaseException:
        # The move already happened, and the browser it was holding has just
        # been killed, so this call failing is a likely way out of here. The
        # note is gone from the module by now, and a swap nobody is told about
        # is the silent change this feature exists to prevent.
        if note:
            logger.info("hermes-exits: %s", note)
        raise
    if note and isinstance(result, str):
        return f"{note}\n\n{result}"
    if note:
        # A tool that answers with something other than text still has to say
        # it moved; the log is the only place left.
        logger.info("hermes-exits: %s", note)
    return result


def handle_providers(args: dict[str, Any], **_kw: Any) -> str:
    try:
        return netexits.describe_providers()
    except netexits.ExitError as exc:
        return f"Could not tell which providers are set up: {exc}"


def handle_provider_setup(args: dict[str, Any], **_kw: Any) -> str:
    try:
        return netexits.guide(str(args.get("provider") or ""))
    except netexits.ExitError as exc:
        return str(exc)


def handle_open(args: dict[str, Any], **_kw: Any) -> str:
    place = str(args.get("place") or "")
    try:
        name, said = netexits.open_exit(
            place, city=bool(args.get("city")), provider=str(args.get("provider") or "")
        )
    except netexits.ExitError as exc:
        near = netexits.suggest_places(place)
        hint = f" Close names the provider does have: {near}." if near else ""
        reason = str(exc).rstrip(".")
        return f"Could not open an exit in {place or 'that place'}: {reason}.{hint}"

    if args.get("switch") is False:
        return f"{said}\nIt is up but not in use; switch with net_use."
    try:
        return f"{said}\n" + netexits.switch(name)
    except netexits.ExitError as exc:
        return f"{said}\nBut switching to it failed: {exc}"


def handle_close(args: dict[str, Any], **_kw: Any) -> str:
    try:
        return netexits.close_exit(
            str(args.get("name") or ""), force=bool(args.get("force"))
        )
    except netexits.ExitError as exc:
        return f"Could not close it: {exc}"


def handle_where(args: dict[str, Any], **_kw: Any) -> str:
    try:
        return netexits.describe_here()
    except netexits.ExitError as exc:
        return f"Could not check: {exc}"


NET_HARDEN_SCHEMA = _schema(
    "net_harden",
    "Install the browser-wide WebRTC policy, so the protection cannot be lost if something "
    "changes how the browser is launched. net_doctor asks for this when it is missing. It "
    "needs the root helper, and it only covers the browser on this host: a profile whose "
    "terminal is a container has its own browser, covered by the policy inside it.",
    {},
)


def handle_harden(args: dict[str, Any], **_kw: Any) -> str:
    try:
        return netexits.harden()
    except netexits.ExitError as exc:
        return f"Could not install the policy: {exc}"


NET_ADD_PROVIDER_SCHEMA = _schema(
    "net_add_provider",
    "Add a VPN provider from a reference to where its WireGuard config is stored, so the "
    "key never passes through this chat. The reference is not the secret: it names a `pass` "
    "store entry (pass:vpn/airvpn) or a file on the host (file:/home/you/airvpn.conf). The "
    "plugin resolves it on the host, reads the config there, and writes the root-only "
    "credentials file; only a confirmation comes back, never the key. Use this when someone "
    "keeps their config in `pass`/gopass or a host file and gives you that reference. If "
    "instead they offer to paste the WireGuard config or the private key into the chat, do "
    "not take it here: decline and point them to `hermes vpn provider <name> --set` in their "
    "terminal. After it succeeds, call net_providers to confirm, then offer to open an exit.",
    {
        "provider": {
            "type": "string",
            "description": "The name to file it under: lowercase letters, digits and dashes, "
            "such as airvpn or mullvad.",
        },
        "secret_ref": {
            "type": "string",
            "description": "Where the config is stored, not the config itself: "
            "pass:folder/item (pass or gopass) or file:/absolute/path.",
        },
    },
    required=["provider", "secret_ref"],
)


def handle_add_provider(args: dict[str, Any], **_kw: Any) -> str:
    try:
        return netexits.add_provider_from_ref(
            str(args.get("provider") or ""), str(args.get("secret_ref") or "")
        )
    except netexits.ExitError as exc:
        return f"Could not add that provider: {exc}"


TOOLS = (
    ("net_exits", NET_EXITS_SCHEMA, handle_list, "🚪"),
    ("net_places", NET_PLACES_SCHEMA, handle_places, "🗺️"),
    ("net_doctor", NET_DOCTOR_SCHEMA, handle_doctor, "🩺"),
    ("net_lock", NET_LOCK_SCHEMA, handle_lock, "🔒"),
    ("net_failover", NET_FAILOVER_SCHEMA, handle_failover, "🪂"),
    ("net_tor_connect", NET_TOR_CONNECT_SCHEMA, handle_tor_connect, "🧅"),
    ("net_new_circuit", NET_NEW_CIRCUIT_SCHEMA, handle_new_circuit, "🎲"),
    ("net_providers", NET_PROVIDERS_SCHEMA, handle_providers, "🔌"),
    ("net_provider_setup", NET_PROVIDER_SETUP_SCHEMA, handle_provider_setup, "📘"),
    ("net_add_provider", NET_ADD_PROVIDER_SCHEMA, handle_add_provider, "🔑"),
    ("net_open", NET_OPEN_SCHEMA, handle_open, "🛫"),
    ("net_close", NET_CLOSE_SCHEMA, handle_close, "🛬"),
    ("net_use", NET_USE_SCHEMA, handle_use, "🧭"),
    ("net_where", NET_WHERE_SCHEMA, handle_where, "📍"),
    ("net_harden", NET_HARDEN_SCHEMA, handle_harden, "🧱"),
)


def _setup_cli(parser) -> None:
    sub = parser.add_subparsers(dest="vpn_command", required=True)
    # Aliases accepted alongside the canonical names: `exits` for `list`,
    # `status` for `doctor`, `unlock` for `lock --off`, `unharden` for
    # `harden --off`.
    sub.add_parser("list", aliases=["exits"], help="list the known exits")
    sub.add_parser("where", help="check where the browser appears to be")

    places = sub.add_parser("places", help="which countries and cities a provider offers")
    places.add_argument("search", nargs="?", default="",
                        help="narrow the list to names containing this")
    places.add_argument("--provider", default="", help="defaults to the one in use")

    sub.add_parser("doctor", aliases=["status"],
                   help="check what protects this browsing and what does not")
    sub.add_parser("harden", help="install the browser-wide WebRTC policy (needs the helper)")
    sub.add_parser("unharden", help="remove that policy again")

    lock = sub.add_parser(
        "lock", help="arm the kill switch: browse by an exit or not at all"
    )
    lock.add_argument("--off", action="store_true", help="disarm it instead")
    sub.add_parser("unlock", help="disarm the kill switch (same as `lock --off`)")

    failover = sub.add_parser(
        "failover",
        help="arm automatic failover: a dead exit is swapped for another in the same country",
    )
    failover.add_argument("--off", action="store_true", help="disarm it instead")
    failover.add_argument("--standby", default="",
                          help="the exit that takes over, by name; it is checked when named")

    tor = sub.add_parser(
        "tor", help="switch to Tor and wait until the circuit carries something"
    )
    tor.add_argument("url", nargs="?", default="",
                     help="an address, usually a .onion, to establish the circuit to")
    tor.add_argument("--javascript", dest="javascript", action="store_true", default=None,
                     help="turn JavaScript on: at connect, or in place while already in Tor mode")
    tor.add_argument("--no-javascript", dest="javascript", action="store_false",
                     help="turn JavaScript off again, in Tor mode, without leaving it")
    tor.add_argument("--off", action="store_true",
                     help="end Tor mode: clear the browser again and put the rest back")

    circuit = sub.add_parser(
        "circuit", help="ask Tor for another exit node (Tor exits only)"
    )
    circuit.add_argument("exit", nargs="?", default="",
                         help="which exit to ask; defaults to the one in use")

    sub.add_parser("providers", help="which VPNs are configured, and which have guides")

    guide = sub.add_parser("provider", help="setup steps for one VPN provider")
    guide.add_argument("name", help="a provider name; `providers` lists the guides")
    guide.add_argument(
        "--set", dest="set_creds", action="store_true",
        help="store this provider's credentials on the host: prompts at the terminal "
             "for its WireGuard config and writes the root-only file. You run this; "
             "the agent cannot.",
    )
    guide.add_argument(
        "--from-ref", dest="from_ref", metavar="REF", default="",
        help="store the config from a reference to where it lives "
             "(pass:folder/item or file:/absolute/path), without pasting the key. "
             "The agent can do this too, with net_add_provider.",
    )

    opened = sub.add_parser("open", help="bring up a new exit in a country or city")
    opened.add_argument("place", help="a country, or a city with --city")
    opened.add_argument("--city", action="store_true", help="the place is a city")
    opened.add_argument("--provider", default="", help="which configured VPN to use")
    opened.add_argument("--no-switch", action="store_true",
                        help="bring it up without switching to it")

    closed = sub.add_parser("close", help="shut down an exit opened with `open`")
    closed.add_argument("name", help="the exit's name, as `list` shows it")
    closed.add_argument("--force", action="store_true",
                        help="close it even if another profile is browsing through it")

    sub.add_parser(
        "setup",
        help="guided first-time setup: install check, doctor, a provider, a first exit",
    )

    use = sub.add_parser("use", help="switch the browser to an exit ('direct' for none)")
    use.add_argument("exit", help="an exit name or a country fragment, or 'direct'")
    use.add_argument(
        "--no-restart",
        action="store_true",
        help="do not close the running browser (the change applies on its next launch)",
    )


def _enter_credentials(provider: str) -> int:
    """Hand off to the helper's interactive credential entry, host-side.

    Kept off the tool surface on purpose: the model never calls this. It inherits
    the terminal so the helper can prompt and read the secret, and that same
    terminal is what keeps the agent out. The agent reaches the helper through
    ``_run_helper``, which captures its output and so gives it no terminal, and
    the helper refuses credential entry when there is none.
    """
    import subprocess

    try:
        done = subprocess.run(["sudo", netexits.helper(), "set-credentials", provider])
    except FileNotFoundError:
        print("error: sudo is needed to run the exit helper, and was not found")
        return 1
    return done.returncode


def _run_setup() -> int:
    """Walk a first-time setup one guided step at a time. Human-run, never a tool.

    Each step reuses the same netexits functions the individual commands do, so
    the wizard cannot drift from what `doctor`, `provider --set`, `open` and the
    rest actually do. Credentials are entered only through `_enter_credentials`,
    the terminal path the agent is blocked from, so nothing here moves a secret
    anywhere the model can see it.
    """
    import sys

    steps = (
        "1. host side (root, once): sudo " + netexits.here("contrib/install") + " --apply",
        "2. hermes vpn doctor        — what protects this browsing, and what does not",
        "3. hermes vpn provider <name> --set   — store a VPN's credentials",
        "4. hermes vpn open <country>          — bring up an exit and switch to it",
        "5. hermes vpn harden  and  hermes vpn lock   — the WebRTC policy and kill switch",
    )
    if not sys.stdin.isatty():
        # No one is here to answer prompts, so lay out the path instead of
        # stalling on input. This is also the shape the test drives.
        print("hermes vpn setup walks these, in order:")
        for step in steps:
            print("  " + step)
        return 0

    def ask(question: str, default: str = "") -> str:
        try:
            return input(question).strip() or default
        except EOFError:
            return default

    def yes(question: str) -> bool:
        return ask(question + " [Y/n] ").lower() not in {"n", "no"}

    print("Let's get this agent's browser leaving by a country you choose.\n")

    # Step 1: is the host side installed? configured_providers asks the helper,
    # which fails plainly when the helper or its sudo rule is missing.
    try:
        configured = netexits.configured_providers()
    except netexits.ExitError:
        print(
            "The host side is not installed yet. As root, run:\n"
            f"  sudo {netexits.here('contrib/install')} --apply\n"
            "It prints everything it will do before it touches anything, and it does not "
            "write your VPN credentials. Re-run `hermes vpn setup` afterward."
        )
        return 1

    # Step 2: show the checklist.
    print("— what is protecting this browsing right now —")
    _ok, report = netexits.doctor()
    print(report + "\n")

    # Step 3: a provider, if there is none.
    if configured:
        print("Already configured: " + ", ".join(sorted({name for name, _ in configured})) + "\n")
    else:
        print("No VPN is set up here yet.")
        available = netexits.guides()
        if available:
            print("Guides ship for: " + ", ".join(available))
        if yes("Add one now?"):
            name = ask("Which provider? (for example airvpn, mullvad, nordvpn) ").lower()
            if name:
                # The terminal path: it prompts for the config here, writes the
                # root-only file, and never hands the secret back to anything.
                _enter_credentials(name)
                try:
                    configured = netexits.configured_providers()
                except netexits.ExitError:
                    configured = []
        print()

    # Step 4: a first exit, verified by measurement rather than by its label.
    if configured and yes("Open an exit now?"):
        place = ask("Which country? (for example Mexico) ")
        if place:
            try:
                exit_name, said = netexits.open_exit(place)
                print(said)
                print(netexits.switch(exit_name))
                print(netexits.describe_here())
            except netexits.ExitError as exc:
                print(f"could not open it: {exc}")
        print()

    # Step 5: the two protections are the safe default, not an opt-in. Turn the
    # WebRTC policy on and make sure the kill switch is armed, saying how to relax
    # each, rather than asking two yes/no questions whose safe answer is always yes.
    try:
        print(netexits.harden())
    except netexits.ExitError as exc:
        print(f"WebRTC policy not set yet: {exc}")
    if netexits.locked():
        print("Kill switch: armed — no exit means no browsing (relax with `hermes vpn lock --off`).")
    else:
        print(netexits.set_locked(True))
    print("Remove the WebRTC policy later with `hermes vpn unharden` if you need to.")

    print("\nDone. `hermes vpn doctor` is the one command to come back to.")
    return 0


def _handle_cli(args) -> int:
    """The CLI calls netexits directly, so a failure is a non-zero exit code.

    The ``handle_*`` wrappers turn every error into a sentence, which is what
    the model needs and the wrong thing for a shell: routed through them, a
    failed command prints the problem and still exits 0.
    """
    command = getattr(args, "vpn_command", None)
    try:
        if command == "setup":
            return _run_setup()
        if command in {"list", "exits"}:
            print(netexits.describe_exits())
            return 0
        if command == "where":
            print(netexits.describe_here())
            return 0
        if command == "places":
            print(netexits.find_places(args.search, args.provider))
            return 0

        if command in {"doctor", "status"}:
            ok, report = netexits.doctor()
            print(report)
            return 0 if ok else 1

        if command == "harden":
            print(netexits.harden())
            return 0
        if command == "unharden":
            print(netexits.unharden())
            return 0

        if command == "lock":
            print(netexits.set_locked(not args.off))
            return 0
        if command == "unlock":
            print(netexits.set_locked(False))
            return 0

        if command == "failover":
            if args.standby:
                print(netexits.set_standby(args.standby))
            print(netexits.set_failover(not args.off))
            return 0

        if command == "tor":
            if args.off:
                print(netexits.end_tor_mode())
                return 0
            print(netexits.tor_connect(args.url, javascript=args.javascript))
            return 0

        if command == "circuit":
            print(netexits.new_circuit(args.exit))
            return 0

        if command == "providers":
            print(netexits.describe_providers())
            return 0

        if command == "provider":
            if getattr(args, "from_ref", ""):
                print(netexits.add_provider_from_ref(args.name, args.from_ref))
                return 0
            if getattr(args, "set_creds", False):
                return _enter_credentials(args.name)
            print(netexits.guide(args.name))
            return 0

        if command == "open":
            try:
                name, said = netexits.open_exit(
                    args.place, city=args.city, provider=args.provider
                )
            except netexits.ExitError as exc:
                # Near-names included, as the tool path gives them: a place
                # the provider spells differently answers "no server found".
                near = netexits.suggest_places(args.place)
                print(f"error: {exc}" + (f"\nClose names it does have: {near}." if near else ""))
                return 1
            print(said)
            if args.no_switch:
                print(f"It is up but not in use; switch with `hermes vpn use {name}`.")
                return 0
            try:
                print(netexits.switch(name))
            except netexits.ExitError as exc:
                # The name is printed even when the switch fails: the tunnel
                # is up and has to be closable.
                print(f"error: it is up, but switching to it failed: {exc}")
                print(f"Close it with `hermes vpn close {name}`, or retry `hermes vpn use {name}`.")
                return 1
            return 0

        if command == "close":
            print(netexits.close_exit(args.name, force=args.force))
            return 0

        if command == "use":
            print(netexits.switch(args.exit, restart=not args.no_restart))
            return 0
    except netexits.ExitError as exc:
        print(f"error: {exc}")
        return 1
    except Exception as exc:  # noqa: BLE001 - a CLI prints one line, not a traceback
        print(f"error: unexpected failure ({exc.__class__.__name__}: {exc}). Try `hermes vpn doctor`.")
        return 1

    print("unknown subcommand")
    return 2


def _never_raises(name: str, fn):
    """A tool must answer with a sentence, never a traceback. The ``handle_*``
    functions already turn ``ExitError`` into one; this backstops everything else
    (a docker hiccup, a malformed server list) so an unexpected failure still reads
    as a sentence in the chat rather than a stack trace the agent relays verbatim.
    """

    def wrapped(args, **kw):
        try:
            return fn(args, **kw)
        except netexits.ExitError as exc:
            return str(exc)
        except Exception as exc:  # noqa: BLE001 - a tool call must not crash the turn
            logger.exception("hermes-vpn: tool %s failed", name)
            return (
                f"{name} hit an unexpected problem ({exc.__class__.__name__}). "
                "Run `hermes vpn doctor` to see what is wrong."
            )

    return wrapped


def register(ctx) -> None:
    """Called once by the plugin loader."""
    for name, schema, handler, emoji in TOOLS:
        ctx.register_tool(
            name=name,
            toolset=TOOLSET,
            schema=schema,
            handler=_never_raises(name, handler),
            emoji=emoji,
        )
    # The kill switch is enforced here, before a browser tool runs, not left to
    # Chromium failing to reach a dead proxy.
    ctx.register_middleware("tool_execution", _guard_browser_tools)

    ctx.register_cli_command(
        name="vpn",
        help="Give the agent's browser a VPN exit, and check which one it really got",
        setup_fn=_setup_cli,
        handler_fn=_handle_cli,
        description=(
            "Choose which exit the agent's browser leaves by, and check which one it "
            "actually got. Exits are local proxies; gluetun containers are found "
            "automatically."
        ),
    )

    # The saved exit is re-applied because a restart rebuilds the environment
    # from scratch, which would put the browser back on this host's own
    # address. Nothing here touches the network: Hermes drops a plugin that
    # takes more than ten seconds to register.
    try:
        note = netexits.reapply_saved_choice()
        if note:
            logger.info("hermes-exits: %s", note)
    except Exception as exc:  # noqa: BLE001, never block plugin load
        logger.warning("hermes-exits: could not restore the saved exit: %s", exc)
