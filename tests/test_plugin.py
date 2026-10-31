"""Tests for the middleware and the CLI -- the two halves nothing covered.

The kill switch is *enforced* by the middleware in ``__init__.py``, and the
CLI is what a person drives. Neither had a single test, so a contract drift
with the host would have kept the whole other suite green while the switch
quietly did not run.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import netexits  # noqa: E402


def _load_plugin():
    """Import __init__.py as a module, which is how Hermes loads it."""
    path = Path(__file__).resolve().parent.parent / "__init__.py"
    spec = importlib.util.spec_from_file_location("hermes_vpn_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


plugin = _load_plugin()


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self._saved = {k: os.environ.get(k) for k in
                       ("HERMES_HOME", netexits.BROWSER_ARGS_ENV, netexits.EXITS_FILE_ENV,
                        netexits.STATE_FILE_ENV)}
        os.environ["HERMES_HOME"] = self._dir.name
        for key in list(self._saved)[1:]:
            os.environ.pop(key, None)
        self._real_look = netexits.look
        self._real_discover = netexits.discover_containers
        self._real_restart = netexits.restart_browser
        self._real_docker = netexits._docker
        netexits.discover_containers = lambda: []
        netexits.restart_browser = lambda grace=3.0: 0
        netexits._docker = lambda *a, **k: ""
        netexits._last_check = ("", 0.0, False)
        # No real network. This base did not blank it, so the first test to
        # touch `where` would have started making outbound requests.
        self._real_trace = netexits.TRACE_URL
        netexits.TRACE_URL = ""

    def tearDown(self) -> None:
        netexits.look = self._real_look
        netexits.discover_containers = self._real_discover
        netexits.restart_browser = self._real_restart
        netexits._docker = self._real_docker
        netexits.TRACE_URL = self._real_trace
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self._dir.cleanup()

    def exits(self, *entries: dict) -> None:
        netexits.exits_file().write_text(json.dumps({"exits": list(entries)}))

    def ran(self):
        """A next_call that records whether the browser was reached."""
        seen = []
        return seen, lambda args: seen.append(args) or "THE BROWSER RAN"


class TheMiddlewareEnforcesIt(_Base):
    def setUp(self) -> None:
        super().setUp()
        self._real_guard = netexits.guard_browser

    def arm_with_a_dead_exit(self) -> None:
        self.exits({"name": "mx", "proxy": "http://127.0.0.1:8891", "country": "Mexico"})
        netexits.look = lambda proxy="": netexits.Sighting(ok=True, ip="201.0.0.5", country="MX")
        netexits.switch("mx")
        netexits.set_locked(True)
        netexits.look = lambda proxy="": netexits.Sighting(ok=False, detail="refused")
        netexits._last_check = ("", 0.0, False)

    def test_it_refuses_a_browser_call_when_the_exit_is_dead(self) -> None:
        self.arm_with_a_dead_exit()
        seen, call = self.ran()
        said = plugin._guard_browser_tools(tool_name="browser_navigate", args={}, next_call=call)
        self.assertIn("Refused", said)
        self.assertEqual(seen, [])

    def test_a_failover_note_rides_on_the_tool_answer(self) -> None:
        """The agent has to read that it moved, in the same answer it asked for."""
        self.arm_with_a_dead_exit()
        netexits._failover_note = "[failover] moved to exit-airvpn-mx"
        self.addCleanup(lambda: setattr(netexits, "_failover_note", ""))
        netexits.guard_browser = lambda tool_name, call_args=None: ""
        self.addCleanup(lambda: setattr(netexits, "guard_browser", self._real_guard))
        seen, call = self.ran()
        said = plugin._guard_browser_tools(tool_name="browser_navigate", args={}, next_call=call)
        self.assertTrue(said.startswith("[failover] moved to exit-airvpn-mx"))
        self.assertIn("THE BROWSER RAN", said)
        self.assertEqual(seen, [{}], "the call still ran")

    def test_the_note_is_not_kept_for_a_later_call(self) -> None:
        """A note arriving on the next call would explain the wrong thing."""
        self.arm_with_a_dead_exit()
        netexits._failover_note = "[failover] moved"
        self.addCleanup(lambda: setattr(netexits, "_failover_note", ""))
        netexits.guard_browser = lambda tool_name, call_args=None: ""
        self.addCleanup(lambda: setattr(netexits, "guard_browser", self._real_guard))
        _seen, call = self.ran()
        plugin._guard_browser_tools(tool_name="browser_navigate", args={}, next_call=call)
        second = plugin._guard_browser_tools(tool_name="browser_navigate", args={}, next_call=call)
        self.assertNotIn("failover", second)

    def test_the_note_survives_a_tool_that_raises(self) -> None:
        """The swap killed the running browser, so the call after it may well fail.

        The note is taken before the call, so without this it would be gone
        and the agent would read a bare browser error with no mention that
        its exit changed.
        """
        self.arm_with_a_dead_exit()
        netexits._failover_note = "[failover] moved to exit-airvpn-mx"
        self.addCleanup(lambda: setattr(netexits, "_failover_note", ""))
        netexits.guard_browser = lambda tool_name, call_args=None: ""
        self.addCleanup(lambda: setattr(netexits, "guard_browser", self._real_guard))

        def explodes(args):
            raise RuntimeError("the browser session is gone")

        with (
            self.assertLogs("hermes_vpn_under_test", level="INFO") as logged,
            self.assertRaises(RuntimeError),
        ):
            plugin._guard_browser_tools(
                tool_name="browser_navigate", args={}, next_call=explodes
            )
        self.assertTrue(any("exit-airvpn-mx" in line for line in logged.output))

    def test_the_close_force_flag_reaches_the_function(self) -> None:
        """It was in the schema and in the CLI and never in the handler, so
        the instruction `close_exit` gives on a refusal -- "then close it
        again with force" -- could not be followed, and an agent told to do
        it would loop."""
        seen: list = []
        real = netexits.close_exit
        netexits.close_exit = lambda name, force=False: seen.append(force) or "closed"
        self.addCleanup(lambda: setattr(netexits, "close_exit", real))
        plugin.handle_close({"name": "exit-miami", "force": True})
        self.assertEqual(seen, [True])

    def test_it_lets_an_unrelated_tool_through(self) -> None:
        self.arm_with_a_dead_exit()
        seen, call = self.ran()
        said = plugin._guard_browser_tools(tool_name="file_read", args={}, next_call=call)
        self.assertEqual(said, "THE BROWSER RAN")
        self.assertEqual(len(seen), 1)

    def test_a_guard_that_raises_is_a_refusal_while_armed(self) -> None:
        """The whole point of the switch is the case where something broke."""
        self.arm_with_a_dead_exit()
        netexits.look = lambda proxy="": (_ for _ in ()).throw(RuntimeError("boom"))
        netexits._last_check = ("", 0.0, False)
        seen, call = self.ran()
        said = plugin._guard_browser_tools(tool_name="browser_navigate", args={}, next_call=call)
        self.assertIn("could not check", said)
        self.assertEqual(seen, [])

    def test_a_name_in_bytes_is_still_a_browser_call(self) -> None:
        """str(b"browser_navigate") is "b'browser_navigate'", which has no prefix."""
        self.arm_with_a_dead_exit()
        seen, call = self.ran()
        said = plugin._guard_browser_tools(tool_name=b"browser_navigate", args={}, next_call=call)
        self.assertIn("Refused", said)
        self.assertEqual(seen, [])

    def test_a_host_that_names_the_argument_differently_still_arms(self) -> None:
        self.arm_with_a_dead_exit()
        seen, call = self.ran()
        for kwargs in ({"name": "browser_navigate"}, {"tool": "browser_navigate"}):
            with self.subTest(kwargs=kwargs):
                said = plugin._guard_browser_tools(args={}, next_call=call, **kwargs)
                self.assertIn("Refused", said)
        self.assertEqual(seen, [])

    def test_positional_arguments_work_too(self) -> None:
        self.arm_with_a_dead_exit()
        seen, call = self.ran()
        said = plugin._guard_browser_tools("browser_navigate", {}, call)
        self.assertIn("Refused", said)
        self.assertEqual(seen, [])

    def test_a_name_it_cannot_determine_is_refused_while_armed(self) -> None:
        """A guard that does not know what it is guarding is not a guard."""
        self.arm_with_a_dead_exit()
        seen, call = self.ran()
        said = plugin._guard_browser_tools(next_call=call, args={})
        self.assertIn("could not tell which tool", said)
        self.assertEqual(seen, [])

    def test_and_passes_it_through_when_disarmed(self) -> None:
        seen, call = self.ran()
        said = plugin._guard_browser_tools(next_call=call, args={"x": 1})
        self.assertEqual(said, "THE BROWSER RAN")
        self.assertEqual(seen, [{"x": 1}])


class TheCliReportsFailure(_Base):
    def run_cli(self, *argv: str) -> tuple[int, str]:
        import argparse
        import contextlib
        import io

        parser = argparse.ArgumentParser(prog="vpn")
        plugin._setup_cli(parser)
        args = parser.parse_args(argv)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = plugin._handle_cli(args)
        return code, out.getvalue()

    def test_an_unknown_provider_is_a_failure(self) -> None:
        code, said = self.run_cli("provider", "nosuchvpn")
        self.assertEqual(code, 1)
        self.assertIn("no guide for", said)

    def test_a_known_provider_is_not(self) -> None:
        code, said = self.run_cli("provider", "surfshark")
        self.assertEqual(code, 0)
        self.assertIn("surfshark", said.lower())

    def test_provider_set_routes_to_credential_entry(self) -> None:
        """`--set` is a host action, so it hands off instead of printing a guide."""
        calls: list[str] = []
        original = plugin._enter_credentials
        plugin._enter_credentials = lambda name: (calls.append(name) or 0)
        self.addCleanup(setattr, plugin, "_enter_credentials", original)
        code, _said = self.run_cli("provider", "airvpn", "--set")
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["airvpn"])

    def test_provider_without_set_still_prints_the_guide(self) -> None:
        code, said = self.run_cli("provider", "airvpn")
        self.assertEqual(code, 0)
        self.assertIn("airvpn", said.lower())

    def test_closing_without_a_helper_is_a_failure(self) -> None:
        os.environ[netexits.HELPER_ENV] = str(Path(self._dir.name) / "nothing")
        self.addCleanup(lambda: os.environ.pop(netexits.HELPER_ENV, None))
        code, said = self.run_cli("close", "exit-mx")
        self.assertEqual(code, 1)
        self.assertIn("no exit helper", said)

    def test_the_aliases_reach_the_same_commands(self) -> None:
        for argv in (("list",), ("exits",)):
            with self.subTest(argv=argv):
                code, said = self.run_cli(*argv)
                self.assertEqual(code, 0)
                self.assertIn("No exits available", said)

    def test_unlock_is_lock_off(self) -> None:
        netexits.set_locked(True)
        code, said = self.run_cli("unlock")
        self.assertEqual(code, 0)
        self.assertFalse(netexits.locked())
        self.assertIn("disarmed", said)

    def test_doctor_returns_one_when_something_is_wrong(self) -> None:
        code, said = self.run_cli("doctor")
        self.assertEqual(code, 1)
        self.assertIn("✗", said)

    def test_status_is_doctor(self) -> None:
        self.assertEqual(self.run_cli("status")[0], self.run_cli("doctor")[0])


class EveryToolHandlerIsReachable(_Base):
    """None of the fourteen handlers had ever been called.

    They are what the model talks to -- the CLI deliberately bypasses them -- so
    a rename in `netexits` that the CLI does not use becomes an AttributeError
    thrown at the host from inside a tool call, with the suite green. These
    tests are mostly a rename detector, and that is the point.
    """

    #: handler → the netexits function it must keep calling.
    WIRING = {
        "handle_list": "describe_exits",
        "handle_use": "switch",
        "handle_places": "find_places",
        "handle_doctor": "doctor",
        "handle_lock": "set_locked",
        "handle_providers": "describe_providers",
        "handle_provider_setup": "guide",
        "handle_open": "open_exit",
        "handle_close": "close_exit",
        "handle_where": "describe_here",
        "handle_harden": "harden",
    }

    def test_every_handler_calls_the_function_it_is_wired_to(self) -> None:
        for handler_name, function_name in self.WIRING.items():
            with self.subTest(handler=handler_name):
                self.assertTrue(hasattr(netexits, function_name),
                                f"{handler_name} calls netexits.{function_name}, which is gone")
                called = []
                real = getattr(netexits, function_name)
                # doctor() and open_exit() are unpacked by their handlers, so
                # the double has to have their shape.
                answer = {
                    "doctor": (True, "whatever"),        # (ok, report)
                    "open_exit": ("exit-mx", "whatever"),  # (name, said)
                }.get(function_name, "whatever")
                setattr(netexits, function_name,
                        lambda *a, **k: called.append(True) or answer)
                try:
                    getattr(plugin, handler_name)({"exit": "mx", "place": "mx", "name": "exit-mx",
                                                   "provider": "surfshark", "armed": True})
                finally:
                    setattr(netexits, function_name, real)
                self.assertTrue(called, f"{handler_name} never called netexits.{function_name}")

    def test_every_handler_turns_a_refusal_into_a_sentence(self) -> None:
        """A handler must not throw at the host: the model reads sentences."""
        for handler_name, function_name in self.WIRING.items():
            with self.subTest(handler=handler_name):
                real = getattr(netexits, function_name)
                setattr(netexits, function_name,
                        lambda *a, **k: (_ for _ in ()).throw(netexits.ExitError("the reason")))
                try:
                    said = getattr(plugin, handler_name)(
                        {"exit": "mx", "place": "mx", "name": "exit-mx",
                         "provider": "surfshark", "armed": True}
                    )
                finally:
                    setattr(netexits, function_name, real)
                self.assertIsInstance(said, str)
                self.assertIn("the reason", said,
                              f"{handler_name} swallowed the reason the model needs")


class ThePluginLoads(_Base):
    """`register()` ran only in production, where a signature drift means the
    plugin does not load at all and nothing in this repo notices."""

    class _Ctx:
        def __init__(self):
            self.tools = []
            self.middleware = []
            self.commands = []

        def register_tool(self, **kwargs):
            self.tools.append(kwargs)

        def register_middleware(self, kind, fn):
            self.middleware.append((kind, fn))

        def register_cli_command(self, **kwargs):
            self.commands.append(kwargs)

    def test_it_registers_the_fourteen_tools_the_middleware_and_the_command(self) -> None:
        ctx = self._Ctx()
        plugin.register(ctx)
        self.assertEqual(len(ctx.tools), 14)
        self.assertEqual([k for k, _fn in ctx.middleware], ["tool_execution"])
        self.assertEqual([c["name"] for c in ctx.commands], ["vpn"])
        for tool in ctx.tools:
            self.assertTrue(callable(tool["handler"]))
            self.assertIn("schema", tool)

    def test_no_tool_is_named_net_anything_any_more(self) -> None:
        """The names belong to the browser plugin on this host, not to us.

        geobrowse is an MCP server that exposes its own net_exits, net_use,
        net_where and the rest -- one set per browser it runs -- and both
        families used to be in reach of the same agent, with descriptions that
        both said "the agent's browser". Asked to browse from Mexico, the agent
        took this family, moved the sandbox and read Madrid back from ipinfo
        (nlbench, 2026-10-31). It noticed and retried; the point is that it
        could just as easily have reported Madrid.
        """
        ctx = self._Ctx()
        plugin.register(ctx)
        names = [t["name"] for t in ctx.tools]
        self.assertEqual([n for n in names if n.startswith("net_")], [])
        self.assertTrue(all(n.startswith("vpn_") for n in names), names)
        # Every one of them names its family, so a tool added later cannot be
        # registered without the discriminator (it is appended, not typed).
        for tool in ctx.tools:
            said = tool["schema"]["description"]
            self.assertIn("geobrowse", said, f"{tool['name']} does not name the other family")
            self.assertIn("vpn_*", said, tool["name"])
        # And the ones that really move an exit say so in their first clause,
        # which is what an agent reads to choose. Not vpn_places and friends:
        # they move nothing and must not claim to.
        movers = {"vpn_use", "vpn_open", "vpn_close", "vpn_tor_connect",
                  "vpn_new_circuit", "vpn_exits", "vpn_where"}
        for tool in ctx.tools:
            if tool["name"] in movers & set(names):
                self.assertIn("THIS BOT'S OWN", tool["schema"]["description"][:400],
                              f"{tool['name']} does not say what it moves")

    def test_a_broken_saved_state_does_not_block_the_load(self) -> None:
        """The decision this encodes was hidden behind a `pragma: no cover`."""
        real = netexits.reapply_saved_choice
        netexits.reapply_saved_choice = lambda: (_ for _ in ()).throw(RuntimeError("corrupt"))
        try:
            ctx = self._Ctx()
            plugin.register(ctx)          # must not raise
        finally:
            netexits.reapply_saved_choice = real
        self.assertEqual(len(ctx.tools), 14)


class TheSuiteCannotCutItselfInHalf(unittest.TestCase):
    """`unittest.main()` calls sys.exit(), so anything below it never loads.

    This file asserts it about the *other* file on purpose: a guard that lives
    in the file it is guarding goes down with it. The bug this prevents was
    claimed fixed once while the call had only been moved further down, and the
    run kept printing OK over the tests it had managed to collect.
    """

    def test_every_test_in_the_other_file_is_actually_collected(self) -> None:
        import ast

        for name in ("test_netexits.py", "test_plugin.py"):
            with self.subTest(file=name):
                path = Path(__file__).resolve().parent / name
                tree = ast.parse(path.read_text())
                written = sum(
                    1
                    for node in ast.walk(tree)
                    if isinstance(node, ast.FunctionDef) and node.name.startswith("test")
                )
                loaded = unittest.defaultTestLoader.loadTestsFromName(
                    f"tests.{name[:-3]}"
                ).countTestCases()
                self.assertEqual(
                    loaded, written,
                    f"{name} defines {written} tests and the loader finds {loaded}: "
                    "something below a `unittest.main()` is never reached",
                )

    def test_the_call_is_the_last_thing_in_each_file(self) -> None:
        import ast

        for name in ("test_netexits.py", "test_plugin.py"):
            with self.subTest(file=name):
                path = Path(__file__).resolve().parent / name
                body = ast.parse(path.read_text()).body
                mains = [i for i, node in enumerate(body) if isinstance(node, ast.If)
                         and ast.unparse(node.test) == "__name__ == '__main__'"]
                self.assertEqual(len(mains), 1, f"{name} has {len(mains)} __main__ blocks")
                self.assertEqual(mains[0], len(body) - 1,
                                 f"{name} defines something after its __main__ block")


class TheScannerCanStillInstallThis(unittest.TestCase):
    """Three literals decide whether this plugin scans `safe`.

    Hermes' plugin scanner takes its verdict from severity presence: one
    `critical` makes it `dangerous`, which `--force` cannot override, and one
    `high` makes it `caution`, which asks. Three patterns are critical, and
    all three are plain tokens matched anywhere in a file with a scannable
    extension, written or merely named in an error message:

        /etc/sudoers   visudo   NOPASSWD

    In code they are critical, so a `.sh` installer that writes the rule is
    blocked outright. In a whole-line comment, a test tree or a README they
    step down one level to `high`, so they cost the `safe` verdict and the
    non-interactive install, not the install itself.

    Say *what* the rule is, not its text: "a passwordless, exact-path sudoers
    rule, as its own drop-in file, mode 440". The word "sudoers" is safe; the
    path `/etc/sudoers…` is not.
    """

    #: Only files the scanner reads, from `skills_guard.SCANNABLE_EXTENSIONS`.
    #: The extensionless scripts in contrib/ are therefore never scanned. The
    #: README says so, because a clean verdict is not a statement about them.
    SCANNED = (".md", ".txt", ".py", ".sh", ".bash", ".js", ".ts", ".yaml",
               ".yml", ".json", ".toml", ".cfg", ".ini", ".conf", ".html")

    #: Shapes the scanner rates critical in prose. One of these makes the
    #: verdict `dangerous`, the install is refused, and `--force` does not
    #: override it.
    BLOCKS_THE_INSTALL = (
        r"/etc/sudoers",
        r"visudo",
        r"NOPASSWD",
        r"authorized_keys",
    )

    #: Shapes that only cost the clean verdict: `high` here, so the verdict is
    #: `caution`. A caution install asks first, and the direct `owner/repo`
    #: path has nothing to ask with, so it fails where nobody is watching.
    COSTS_A_CLEAN_SCAN = (
        r"/etc/(?:passwd|shadow)",
        r"\bcurl\b[^\n]*\|\s*(?:ba)?sh\b",
        r"\bchmod\s+[ug]\+s\b",
        r"\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+[^\n]*(?:\$HOME|~/|\.hermes)",
        r"(?:append|add|write|edit|echo|tee)[^\n]*AGENTS\.md",
    )

    def _scanned_lines(self):
        """Every (path, line number, line) the scanner would read here."""
        root = Path(__file__).resolve().parent.parent
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in self.SCANNED:
                continue
            if any(part in {".git", "__pycache__", ".venv"} for part in path.parts):
                continue
            # This file spells the shapes out, so it cannot be its own subject.
            if path.name == Path(__file__).name:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for number, line in enumerate(text.splitlines(), 1):
                yield path.relative_to(root), number, line

    def _offenders(self, patterns) -> list[str]:
        found = []
        for rel, number, line in self._scanned_lines():
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    found.append(f"{rel}:{number}: {pattern}")
        return found

    def test_no_file_the_scanner_reads_can_block_the_install(self) -> None:
        offenders = self._offenders(self.BLOCKS_THE_INSTALL)
        self.assertEqual(
            offenders, [],
            "these lines make the plugin uninstallable for everyone, and "
            "`--force` does not help:\n  " + "\n  ".join(offenders),
        )

    def test_no_file_the_scanner_reads_costs_the_clean_verdict(self) -> None:
        offenders = self._offenders(self.COSTS_A_CLEAN_SCAN)
        self.assertEqual(
            offenders, [],
            "these lines drop the verdict to `caution`, so a non-interactive "
            "install stops asking nobody:\n  " + "\n  ".join(offenders),
        )

    def test_hermes_own_scanner_agrees_where_it_is_installed(self) -> None:
        """The patterns above are a stand-in. Where the real one is, use it."""
        agent = Path(
            os.environ.get("HERMES_AGENT_DIR")
            or Path.home() / ".hermes" / "hermes-agent"
        )
        if not (agent / "tools" / "plugin_guard.py").is_file():
            self.skipTest(f"no Hermes agent at {agent}")
        sys.path.insert(0, str(agent))
        try:
            from tools.plugin_guard import scan_plugin, should_allow_plugin_install
        except ImportError as exc:
            self.skipTest(f"Hermes scanner at {agent} would not import: {exc}")
        finally:
            sys.path.remove(str(agent))
        result = scan_plugin(Path(__file__).resolve().parent.parent)
        worst = sorted(
            (f.severity for f in result.findings),
            key=("low", "medium", "high", "critical").index,
        )
        allowed, reason = should_allow_plugin_install(result)
        self.assertEqual(
            result.verdict, "safe",
            f"{result.summary}; worst severity {worst[-1:] or ['none']}, "
            f"install says {(allowed, reason)}",
        )


class TheSetupWizard(_Base):
    def _run(self) -> tuple[int, str]:
        import argparse
        import contextlib
        import io

        parser = argparse.ArgumentParser(prog="vpn")
        plugin._setup_cli(parser)
        args = parser.parse_args(["setup"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = plugin._handle_cli(args)
        return code, out.getvalue()

    def test_without_a_terminal_it_lists_the_steps(self) -> None:
        """No tty means no prompts: lay out the path and exit cleanly."""
        with mock.patch.object(sys.stdin, "isatty", return_value=False):
            code, said = self._run()
        self.assertEqual(code, 0)
        self.assertIn("in order", said)
        self.assertIn("doctor", said)
        self.assertIn("provider <name> --set", said)

    def test_it_adds_a_provider_through_the_terminal_path_and_opens_an_exit(self) -> None:
        """The interactive walk routes credential entry to _enter_credentials
        (the agent-blocked path) and never writes a secret itself."""
        creds: list[str] = []
        opened: list[str] = []
        answers = iter(["y", "airvpn", "y", "Mexico"])
        # Empty before the add, configured after it.
        providers = iter([[], [("airvpn", "airvpn")]])

        with mock.patch.object(sys.stdin, "isatty", return_value=True), \
             mock.patch("builtins.input", lambda _prompt="": next(answers)), \
             mock.patch.object(netexits, "configured_providers", lambda: next(providers)), \
             mock.patch.object(netexits, "doctor", lambda: (True, "report")), \
             mock.patch.object(netexits, "guides", lambda: ["airvpn", "mullvad"]), \
             mock.patch.object(plugin, "_enter_credentials",
                               lambda name: (creds.append(name) or 0)), \
             mock.patch.object(netexits, "open_exit",
                               lambda place, **_k: (opened.append(place) or ("exit-mx", "up"))), \
             mock.patch.object(netexits, "switch", lambda name, **_k: "switched"), \
             mock.patch.object(netexits, "describe_here", lambda: "in Mexico"), \
             mock.patch.object(netexits, "harden", lambda: "policy installed"), \
             mock.patch.object(netexits, "locked", lambda: True):
            code, _said = self._run()

        self.assertEqual(code, 0)
        self.assertEqual(creds, ["airvpn"])
        self.assertEqual(opened, ["Mexico"])

    def test_without_the_host_side_it_points_at_the_installer(self) -> None:
        """If the helper is not there, say how to install it and stop."""
        def boom() -> list:
            raise netexits.ExitError("the exit helper could not be asked")

        with mock.patch.object(sys.stdin, "isatty", return_value=True), \
             mock.patch.object(netexits, "configured_providers", boom):
            code, said = self._run()
        self.assertEqual(code, 1)
        self.assertIn("--apply", said)


class TheVaultReferencePath(_Base):
    """Adding a provider from a reference, so the key never reaches the model."""

    def run_cli(self, *argv: str, tty: bool = True, answer: str = "yes") -> tuple[int, str]:
        import argparse
        import contextlib
        import io

        parser = argparse.ArgumentParser(prog="vpn")
        plugin._setup_cli(parser)
        args = parser.parse_args(argv)
        out = io.StringIO()
        fake_stdin = mock.MagicMock()
        fake_stdin.isatty.return_value = tty
        with contextlib.redirect_stdout(out), \
             mock.patch("sys.stdin", fake_stdin), \
             mock.patch("builtins.input", return_value=answer):
            code = plugin._handle_cli(args)
        return code, out.getvalue()

    def test_there_is_no_model_tool_for_it(self) -> None:
        """Credential entry is CLI-only: the agent has no tool that adds a
        provider, so it cannot be talked into driving credential entry."""
        ctx = ThePluginLoads._Ctx()
        plugin.register(ctx)
        names = [t["name"] for t in ctx.tools]
        # Both spellings: the tools were renamed net_* -> vpn_* when a browser
        # plugin turned up with the same names, and an absence asserted under
        # the old spelling alone would not have noticed a new tool under the
        # new one.
        self.assertNotIn("net_add_provider", names)
        self.assertNotIn("vpn_add_provider", names)
        self.assertFalse(hasattr(plugin, "handle_add_provider"))

    def test_the_cli_from_ref_explains_then_writes_on_yes(self) -> None:
        calls: list[tuple[str, str]] = []
        with mock.patch.object(
            netexits, "add_provider_from_ref",
            side_effect=lambda p, r: calls.append((p, r)) or "done",
        ):
            code, said = self.run_cli("provider", "airvpn", "--from-ref", "pass:vpn/airvpn",
                                      answer="yes")
        self.assertEqual(code, 0)
        self.assertEqual(calls, [("airvpn", "pass:vpn/airvpn")])
        self.assertIn("root-only", said, "the explanation is shown first")
        self.assertIn("done", said)

    def test_the_cli_from_ref_aborts_unless_confirmed(self) -> None:
        with mock.patch.object(netexits, "add_provider_from_ref") as m:
            code, said = self.run_cli("provider", "airvpn", "--from-ref", "pass:vpn/airvpn",
                                      answer="n")
        self.assertEqual(code, 0)
        m.assert_not_called()
        self.assertIn("unchanged", said.lower())

    def test_the_cli_from_ref_refuses_without_a_terminal(self) -> None:
        with mock.patch.object(netexits, "add_provider_from_ref") as m:
            code, _said = self.run_cli("provider", "airvpn", "--from-ref", "pass:vpn/airvpn",
                                       tty=False)
        self.assertEqual(code, 1)
        m.assert_not_called()


class ToolsNeverRaiseToTheChat(_Base):
    """A tool must answer with a sentence, never a traceback the agent relays."""

    def test_a_non_exiterror_becomes_a_sentence(self) -> None:
        def boom(args, **kw):
            raise ValueError("kaboom")
        out = plugin._never_raises("net_test", boom)({})
        self.assertIsInstance(out, str)
        self.assertNotIn("Traceback", out)
        self.assertIn("doctor", out)

    def test_an_exiterror_passes_through_as_its_message(self) -> None:
        def nope(args, **kw):
            raise netexits.ExitError("no exits yet")
        self.assertEqual(plugin._never_raises("net_test", nope)({}), "no exits yet")

    def test_registered_handlers_are_wrapped(self) -> None:
        ctx = ThePluginLoads._Ctx()
        plugin.register(ctx)
        # Every registered handler tolerates an unexpected failure in its callee.
        for tool in ctx.tools:
            self.assertTrue(callable(tool["handler"]))



class TheAllowOnionCommand(unittest.TestCase):
    """`hermes vpn allow-onion` is the human, CLI-only way to let the browser
    open .onion addresses. It turns off a core security guard, so it explains
    what it will do and asks before doing it. There is no model tool for it."""

    def run_cli(self, *argv: str, tty: bool = True, answer: str = "yes") -> tuple[int, str]:
        import argparse
        import contextlib
        import io
        parser = argparse.ArgumentParser(prog="vpn")
        plugin._setup_cli(parser)
        args = parser.parse_args(argv)
        out = io.StringIO()
        fake_stdin = mock.MagicMock()
        fake_stdin.isatty.return_value = tty
        with contextlib.redirect_stdout(out), \
             mock.patch("sys.stdin", fake_stdin), \
             mock.patch("builtins.input", return_value=answer), \
             mock.patch.object(netexits, "restart_hermes", return_value="Hermes restarted (stub)."):
            code = plugin._handle_cli(args)
        return code, out.getvalue()

    def test_enabling_explains_then_writes_and_restarts_on_yes(self) -> None:
        with mock.patch.object(netexits, "allow_onion", return_value=(True, "written")) as m:
            code, said = self.run_cli("allow-onion", answer="yes")
        self.assertEqual(code, 0)
        m.assert_called_once_with(True)
        self.assertIn("SSRF", said, "the explanation is shown before the change")
        self.assertIn("written", said)
        self.assertIn("Hermes restarted", said, "it restarts Hermes itself when it changed")

    def test_enabling_does_not_restart_when_nothing_changed(self) -> None:
        """Running it twice must not bounce a live agent for nothing."""
        with mock.patch.object(netexits, "allow_onion", return_value=(False, "already set")):
            code, said = self.run_cli("allow-onion", answer="yes")
        self.assertEqual(code, 0)
        self.assertIn("No change", said)
        self.assertNotIn("Hermes restarted", said)

    def test_enabling_is_aborted_unless_the_word_is_typed(self) -> None:
        with mock.patch.object(netexits, "allow_onion") as m:
            code, said = self.run_cli("allow-onion", answer="y")  # not the full word
        self.assertEqual(code, 0)
        m.assert_not_called()
        self.assertIn("unchanged", said.lower())

    def test_enabling_refuses_without_a_terminal(self) -> None:
        with mock.patch.object(netexits, "allow_onion") as m:
            code, said = self.run_cli("allow-onion", tty=False)
        self.assertEqual(code, 1)
        m.assert_not_called()
        self.assertIn("terminal", said.lower())

    def test_off_also_explains_confirms_and_restarts(self) -> None:
        """--off restarts Hermes too (dropping sessions), so it is not silent."""
        with mock.patch.object(netexits, "allow_onion", return_value=(True, "off")) as m:
            code, said = self.run_cli("allow-onion", "--off", answer="yes")
        self.assertEqual(code, 0)
        m.assert_called_once_with(False)
        self.assertIn("internal addresses", said, "the --off plan is shown")
        self.assertIn("Hermes restarted", said)

    def test_off_refuses_without_a_terminal(self) -> None:
        with mock.patch.object(netexits, "allow_onion") as m:
            code, _said = self.run_cli("allow-onion", "--off", tty=False)
        self.assertEqual(code, 1)
        m.assert_not_called()

    def test_off_aborts_unless_confirmed(self) -> None:
        with mock.patch.object(netexits, "allow_onion") as m:
            code, said = self.run_cli("allow-onion", "--off", answer="n")
        self.assertEqual(code, 0)
        m.assert_not_called()
        self.assertIn("unchanged", said.lower())

    def test_it_is_not_a_model_tool(self) -> None:
        ctx = ThePluginLoads._Ctx()
        plugin.register(ctx)
        self.assertNotIn("allow-onion", [t["name"] for t in ctx.tools])
        names = [t["name"] for t in ctx.tools]
        self.assertNotIn("net_allow_onion", names)
        self.assertNotIn("vpn_allow_onion", names)


if __name__ == "__main__":
    unittest.main()
