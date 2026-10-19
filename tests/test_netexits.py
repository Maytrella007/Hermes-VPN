"""Tests for exit selection, verification and the browser restart.

Nothing here touches the network or Docker: the lookup and the process list are
replaced with stubs, because what matters is the decisions, not the plumbing.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import time
import types
import unittest
from unittest import mock
from pathlib import Path

# So that `python3 tests/test_netexits.py` works as well as discovery from the
# repo root.
#
# There is exactly one `unittest.main()` and it is the last thing in this file.
# It has to be: `unittest.main()` calls `sys.exit()`, so anything defined below
# it never gets collected and the run reports OK over whatever it did reach.
# If you add a class, add it above the block at the bottom.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import netexits  # noqa: E402

#: Captured at import, before any test can replace them. Capturing these in
#: setUp records whatever the previous class left behind, and then restoring
#: keeps the leak alive: that is how a test asking the real `_docker_try` what
#: it does with an OSError ended up asking a stub.
REAL_DOCKER = netexits._docker
REAL_DOCKER_TRY = netexits._docker_try

#: The two exits most of these tests use. Named once instead of repeated forty
#: times: easier to read, and Hermes' plugin scanner files one finding on this
#: line instead of forty.
MX_PROXY = "http://127.0.0.1:8891"
JP_PROXY = "http://127.0.0.1:8892"


def policy_reply(args, *bodies: str) -> str:
    """What a container prints for the policy read in *args*.

    The delimiters carry a per-call nonce, because the thing being framed is a
    file anyone with root in that container can write. So this double does
    what a shell would: it reads the nonce out of the script it was handed and
    frames the bodies with it, rather than hardcoding delimiters the code no
    longer uses.
    """
    joined = " ".join(str(a) for a in args)
    found = re.search(r"__[0-9a-f]{16}__", joined)
    nonce = found.group(0) if found else "__"
    base = "/etc/opt/chrome_for_testing/policies/managed"
    out = ""
    for index, body in enumerate(bodies):
        name = "vpn.json" if index == 0 else f"other{index}.json"
        out += f"{nonce}FILE {base}/{name}\n{body}\n"
    return out + f"{nonce}READ\n"


class _Sandbox(unittest.TestCase):
    """Each test gets its own HERMES_HOME and a clean environment."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self._saved = {
            key: os.environ.get(key)
            for key in ("HERMES_HOME", netexits.BROWSER_ARGS_ENV, netexits.EXITS_FILE_ENV, netexits.STATE_FILE_ENV)
        }
        os.environ["HERMES_HOME"] = self._dir.name
        os.environ.pop(netexits.BROWSER_ARGS_ENV, None)
        os.environ.pop(netexits.EXITS_FILE_ENV, None)
        os.environ.pop(netexits.STATE_FILE_ENV, None)
        self._real_look = netexits.look
        self._real_discover = netexits.discover_containers
        self._real_restart = netexits.restart_browser
        # Capture it here, before any fixture patches it. Don't restore it
        # with `import subprocess; netexits.subprocess.run = subprocess.run`:
        # `netexits.subprocess` *is* that module, so that restores the fake
        # onto itself and leaks it into every test that runs afterwards.
        self._real_run = netexits.subprocess.run
        # Captured here for the same reason: several fixtures replace these and
        # only some of them put them back, so a fake docker outlived its class
        # and a later test with a profile config would inherit a sealed sandbox
        # that does not exist.
        self._real_docker = REAL_DOCKER
        self._real_docker_try = REAL_DOCKER_TRY
        netexits.discover_containers = lambda: []
        # Docker answers, and answers nothing, unless a test says otherwise.
        # "Could not be asked" is a third answer now: it holds browser calls
        # for a profile whose config calls it a sandbox, so a suite that
        # never stubbed the listing would be testing that refusal instead of
        # what it meant to. `_docker_try` reads `_docker` at call time, so a
        # class that overrides one gets the other to agree.
        netexits._docker = lambda *a, **k: ""
        netexits._docker_try = lambda *a, **k: (True, netexits._docker(*a, **k))
        netexits.restart_browser = lambda grace=3.0: 0
        # Module state the real `discover_containers` clears on every call. The
        # stub above doesn't, so without this a report from one test turns up
        # in the next. Same for the cached liveness verdict, where a stale
        # "alive" is the permissive direction.
        netexits._last_check = ("", 0.0, False)
        netexits._last_unverifiable = False
        netexits._unusable_exits = []
        netexits._docker_silent = ""
        netexits._rejected_exits = []
        # No real network, which this file's docstring promises. look() asks a
        # trace endpoint first and falls back to `curl`, and either one would
        # leave the suite depending on the machine it runs on.
        self._real_trace = netexits.TRACE_URL
        netexits.TRACE_URL = ""
        # A configured host has /usr/local/bin/vpn-verify, and anything that
        # reached it would run a real `docker exec` and answer differently
        # there than here. Pointed at a path that does not exist, so the
        # fail-closed branch is what tests see unless they say otherwise.
        self._real_verify_helper = netexits.VERIFY_HELPER
        netexits.VERIFY_HELPER = str(Path(self._dir.name) / "no-verifier")
        # `shutil.which` is deliberately NOT stubbed. Hiding curl made the
        # test that encodes the no_proxy guarantee blind to the second way of
        # asking, and that is where the guarantee was then inverted. The real
        # curl runs; what it is pointed at is a dead local port, so it fails
        # fast, and `subprocess.run` is restored by this class anyway.

    def tearDown(self) -> None:
        netexits.look = self._real_look
        netexits.discover_containers = self._real_discover
        netexits.restart_browser = self._real_restart
        netexits.subprocess.run = self._real_run
        netexits._docker = self._real_docker
        netexits._docker_try = self._real_docker_try
        netexits.TRACE_URL = self._real_trace
        netexits.VERIFY_HELPER = self._real_verify_helper
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self._dir.cleanup()

    def write_exits(self, *entries: dict) -> None:
        Path(netexits.exits_file()).write_text(json.dumps({"exits": list(entries)}))

    def seeing(self, **kwargs) -> None:
        """Make every lookup report this."""
        netexits.look = lambda proxy="": netexits.Sighting(**kwargs)


class PortParsing(unittest.TestCase):
    def test_takes_a_loopback_published_port(self) -> None:
        self.assertEqual(
            netexits._published_proxy_port("127.0.0.1:8889->8888/tcp"), "8889"
        )

    def test_ignores_a_port_open_to_the_world(self) -> None:
        """A proxy published on every interface is an open relay, not an exit."""
        self.assertEqual(netexits._published_proxy_port("0.0.0.0:8888->8888/tcp"), "")

    def test_no_ports_at_all(self) -> None:
        self.assertEqual(netexits._published_proxy_port(""), "")


class BrowserArguments(unittest.TestCase):
    def test_base_arguments_are_kept(self) -> None:
        """Setting the variable replaces Hermes's defaults, so they must be re-added."""
        args = netexits.browser_args("http://127.0.0.1:8888")
        for base in netexits.BASE_BROWSER_ARGS:
            self.assertIn(base, args)
        self.assertIn("--proxy-server=http://127.0.0.1:8888", args)

    def test_comma_separated(self) -> None:
        """Hermes splits this variable on commas, so a space would break a flag."""
        self.assertNotIn(" ", netexits.browser_args("http://127.0.0.1:1"))
        self.assertEqual(
            len(netexits.browser_args("http://x:1").split(",")),
            len(netexits.BASE_BROWSER_ARGS) + 2,  # proxy and the WebRTC policy
        )

    def test_direct_has_no_proxy_argument(self) -> None:
        self.assertNotIn("--proxy-server", netexits.browser_args(""))


class Resolution(_Sandbox):
    def setUp(self) -> None:
        super().setUp()
        self.write_exits(
            {"name": "mx", "proxy": MX_PROXY, "country": "Mexico"},
            {"name": "jp", "proxy": JP_PROXY, "country": "Japan"},
        )

    def test_exact_name(self) -> None:
        self.assertEqual(netexits.resolve("jp").country, "Japan")

    def test_by_country(self) -> None:
        self.assertEqual(netexits.resolve("Mexico").name, "mx")

    def test_case_insensitive(self) -> None:
        self.assertEqual(netexits.resolve("mexico").name, "mx")

    def test_empty_selector_is_refused(self) -> None:
        with self.assertRaises(netexits.ExitError):
            netexits.resolve("")

    def test_unknown_lists_what_exists(self) -> None:
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.resolve("brazil")
        self.assertIn("Mexico", str(caught.exception))

    def test_ambiguous_is_not_guessed(self) -> None:
        self.write_exits(
            {"name": "mx-1", "proxy": "http://127.0.0.1:1", "country": "Mexico"},
            {"name": "mx-2", "proxy": "http://127.0.0.1:2", "country": "Mexico"},
        )
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.resolve("mexico")
        self.assertIn("be exact", str(caught.exception))

    def test_no_exits_at_all_explains_how_to_add_one(self) -> None:
        Path(netexits.exits_file()).unlink()
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.resolve("mx")
        self.assertIn("hermes vpn open", str(caught.exception))


class Switching(_Sandbox):
    def setUp(self) -> None:
        super().setUp()
        self.write_exits({"name": "mx", "proxy": MX_PROXY, "country": "Mexico"})

    def test_a_working_exit_is_applied_and_reported(self) -> None:
        self.seeing(ok=True, ip="201.0.0.5", country="MX", city="Mexico City")
        answer = netexits.switch("mx")
        self.assertIn("201.0.0.5", answer)
        self.assertIn("Mexico City", answer)
        self.assertEqual(netexits.current_proxy(), MX_PROXY)

    def test_a_dead_exit_changes_nothing(self) -> None:
        """Fail closed: a switch that silently leaves the host address is the bug."""
        os.environ[netexits.BROWSER_ARGS_ENV] = netexits.browser_args("http://127.0.0.1:9999")
        self.seeing(ok=False, detail="connection refused")
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.switch("mx")
        self.assertIn("nothing was changed", str(caught.exception))
        self.assertEqual(netexits.current_proxy(), "http://127.0.0.1:9999")

    def test_direct_removes_the_proxy(self) -> None:
        self.seeing(ok=True, ip="167.0.0.1", country="DE", city="Falkenstein")
        netexits.switch("mx")
        netexits.switch("direct")
        self.assertEqual(netexits.current_proxy(), "")

    def test_the_label_and_the_sighting_both_appear(self) -> None:
        """The label is a claim and the sighting is evidence; show both, judge neither."""
        self.seeing(ok=True, ip="5.5.5.5", country="DE", city="Frankfurt")
        answer = netexits.switch("mx")
        self.assertIn("Frankfurt", answer)
        self.assertIn("Mexico", answer)

    def test_the_choice_survives_a_restart(self) -> None:
        self.seeing(ok=True, ip="201.0.0.5", country="MX", city="Mexico City")
        netexits.switch("mx")
        os.environ.pop(netexits.BROWSER_ARGS_ENV)  # as a gateway restart would
        self.assertEqual(netexits.current_proxy(), "")
        note = netexits.reapply_saved_choice()
        self.assertIn("mx", note)
        self.assertEqual(netexits.current_proxy(), MX_PROXY)

    def test_reapplying_never_touches_the_network(self) -> None:
        """Hermes drops a plugin that needs more than ten seconds to register."""
        self.seeing(ok=True, ip="201.0.0.5", country="MX", city="Mexico City")
        netexits.switch("mx")
        os.environ.pop(netexits.BROWSER_ARGS_ENV)

        def _explode(proxy: str = ""):
            raise AssertionError("register() must not make network calls")

        netexits.look = _explode
        netexits.reapply_saved_choice()
        self.assertEqual(netexits.current_proxy(), MX_PROXY)

    def test_a_dead_exit_is_still_re_applied(self) -> None:
        """A dead proxy fails loudly; skipping it leaks the host address quietly."""
        self.seeing(ok=True, ip="201.0.0.5", country="MX", city="Mexico City")
        netexits.switch("mx")
        os.environ.pop(netexits.BROWSER_ARGS_ENV)
        self.seeing(ok=False, detail="timed out")
        netexits.reapply_saved_choice()
        self.assertEqual(netexits.current_proxy(), MX_PROXY)

    def test_restart_is_requested_by_default(self) -> None:
        calls: list[float] = []
        netexits.restart_browser = lambda grace=3.0: calls.append(grace) or 2
        self.seeing(ok=True, ip="201.0.0.5", country="MX", city="Mexico City")
        answer = netexits.switch("mx")
        self.assertEqual(len(calls), 1)
        self.assertIn("Closed 2 browser process", answer)

    def test_restart_can_be_skipped(self) -> None:
        netexits.restart_browser = lambda grace=3.0: (_ for _ in ()).throw(AssertionError("should not run"))
        self.seeing(ok=True, ip="201.0.0.5", country="MX", city="Mexico City")
        netexits.switch("mx", restart=False)


class BrowserProcesses(_Sandbox):
    def setUp(self) -> None:
        super().setUp()
        self.binary = str(Path(self._dir.name) / "tools/chromium-1208/chrome-linux64/chrome")
        Path(self.binary).parent.mkdir(parents=True, exist_ok=True)
        Path(self.binary).touch()

    def _ps(self, *lines: str) -> None:
        class _Done:
            stdout = "\n".join(lines)

        netexits.subprocess.run = lambda *a, **k: _Done()

    def tearDown(self) -> None:
        super().tearDown()

    def test_finds_the_agent_browser(self) -> None:
        self._ps(f"4242 {self.binary} --headless --remote-debugging-port=0")
        self.assertEqual(netexits.browser_processes(), [4242])

    def test_skips_renderer_children(self) -> None:
        """Killing the parent takes them along; killing them one by one is noise."""
        self._ps(
            f"4242 {self.binary} --headless",
            f"4243 {self.binary} --type=renderer",
            f"4244 {self.binary} --type=zygote",
        )
        self.assertEqual(netexits.browser_processes(), [4242])

    def test_leaves_someone_elses_chromium_alone(self) -> None:
        self._ps("999 /usr/bin/chromium --user-data-dir=/home/someone/.config/chromium")
        self.assertEqual(netexits.browser_processes(), [])


class Reporting(_Sandbox):
    def test_lists_exits_and_marks_the_active_one(self) -> None:
        self.write_exits({"name": "mx", "proxy": MX_PROXY, "country": "Mexico"})
        os.environ[netexits.BROWSER_ARGS_ENV] = netexits.browser_args(MX_PROXY)
        listing = netexits.describe_exits()
        self.assertIn("mx", listing)
        self.assertIn("in use", listing)

    def test_says_direct_when_no_proxy_is_set(self) -> None:
        self.write_exits({"name": "mx", "proxy": MX_PROXY})
        self.assertIn("direct (no proxy) <- in use", netexits.describe_exits())

    def test_no_exits_explains_how_to_add_one(self) -> None:
        self.assertIn("hermes vpn open", netexits.describe_exits())

    def test_a_gluetun_with_its_proxy_unpublished_is_named_instead(self) -> None:
        """The commonest first run: someone followed their VPN's own gluetun
        page, which does not mention HTTPPROXY. Telling them to start a
        container they are already running is the dead end `after-install.md`
        promises this does not have."""
        netexits._unusable_exits = [
            "exit-mx is running but publishes no HTTP proxy on 127.0.0.1:<port>->8888"
        ]
        said = netexits.describe_exits()
        self.assertIn("exit-mx is running", said)
        self.assertIn("HTTPPROXY", said)

    def test_and_a_docker_that_did_not_answer_is_not_an_empty_host(self) -> None:
        netexits._docker_silent = "docker could not be asked — is this user in the docker group?"
        said = netexits.describe_exits()
        self.assertIn("docker group", said)
        self.assertIn("Nothing here is a statement about what is running", said)

    def test_where_reports_a_failed_check_as_unknown(self) -> None:
        self.seeing(ok=False, detail="timed out")
        answer = netexits.describe_here()
        self.assertIn("unknown", answer)

    def test_where_names_the_place_it_saw(self) -> None:
        self.seeing(ok=True, ip="201.0.0.5", country="MX", city="Mexico City")
        self.assertIn("Mexico City", netexits.describe_here())




class LookupRobustness(unittest.TestCase):
    """What the lookup does when a service is unfriendly to a shared VPN address."""

    def setUp(self) -> None:
        self._real_urls = netexits.LOOKUP_URLS
        self._real_trace = netexits.TRACE_URL
        # Captured before `_answers` patches it. Restoring it with
        # `netexits.urllib.request.build_opener = urllib.request.build_opener`
        # was a no-op, because those are the same module object: the fake was
        # restored onto itself and leaked into every class after this one.
        self._real_opener = netexits.urllib.request.build_opener
        netexits.TRACE_URL = ""          # the trace endpoint is a real host
        self._opened: list[str] = []

    def tearDown(self) -> None:
        netexits.LOOKUP_URLS = self._real_urls
        netexits.TRACE_URL = self._real_trace
        netexits.urllib.request.build_opener = self._real_opener

    def _answers(self, mapping: dict) -> None:
        """Make each URL answer with a payload, an exception, or nothing."""
        import contextlib
        import io
        import json as _json
        import urllib.error

        opened = self._opened

        class _Opener:
            def open(self, url, timeout=0):
                # look() hands us a Request, not a string: that is how it sets
                # the proxy without urllib consulting no_proxy. Unwrap it so
                # this double sees exactly what the real opener sees.
                url = getattr(url, "full_url", url)
                opened.append(url)
                answer = mapping.get(url)
                if isinstance(answer, Exception):
                    raise answer
                return contextlib.closing(io.BytesIO(_json.dumps(answer).encode()))

        netexits.urllib.request.build_opener = lambda *a, **k: _Opener()

    def test_falls_through_a_rate_limited_service(self) -> None:
        import urllib.error

        netexits.LOOKUP_URLS = ("https://first", "https://second")
        self._answers(
            {
                "https://first": urllib.error.HTTPError("https://first", 429, "Too Many", {}, None),
                "https://second": {"ip": "201.0.0.7", "country": "Mexico"},
            }
        )
        sighting = netexits.look("http://127.0.0.1:1")
        self.assertTrue(sighting.ok)
        self.assertEqual(sighting.ip, "201.0.0.7")
        self.assertEqual(self._opened, ["https://first", "https://second"])

    def test_a_200_with_an_error_body_is_not_an_answer(self) -> None:
        """A rate-limit notice served with a 200 would otherwise read as success."""
        netexits.LOOKUP_URLS = ("https://first", "https://second")
        self._answers(
            {
                "https://first": {"status": 429, "error": {"message": "Rate limit hit"}},
                "https://second": {"ip": "201.0.0.7", "country": "Mexico"},
            }
        )
        sighting = netexits.look()
        self.assertTrue(sighting.ok)
        self.assertEqual(sighting.ip, "201.0.0.7")

    def test_every_service_failing_is_reported_as_unknown(self) -> None:
        netexits.LOOKUP_URLS = ("https://only",)
        self._answers({"https://only": {"status": 429}})
        sighting = netexits.look()
        self.assertFalse(sighting.ok)
        self.assertIn("no address", sighting.detail)

    def test_the_services_own_complaint_is_passed_along(self) -> None:
        netexits.LOOKUP_URLS = ("https://only",)
        self._answers({"https://only": {"error": {"message": "Rate limit hit"}, "message": "Rate limit hit"}})
        self.assertIn("Rate limit", netexits.look().detail)

    def test_reads_the_country_code_field_some_services_use(self) -> None:
        netexits.LOOKUP_URLS = ("https://only",)
        self._answers({"https://only": {"ip": "201.0.0.7", "cc": "MX"}})
        self.assertEqual(netexits.look().country, "MX")


class OpeningExits(_Sandbox):
    """Creating an exit goes through a root-owned helper, never raw docker."""

    def setUp(self) -> None:
        super().setUp()
        self.helper = str(Path(self._dir.name) / "vpn-exit")
        Path(self.helper).touch()
        os.environ[netexits.HELPER_ENV] = self.helper
        self.calls: list[list[str]] = []

    def tearDown(self) -> None:
        os.environ.pop(netexits.HELPER_ENV, None)
        super().tearDown()

    def _helper_says(self, stdout: str = "", code: int = 0, stderr: str = "") -> None:
        calls = self.calls

        class _Done:
            returncode = code

        done = _Done()
        done.stdout = stdout
        done.stderr = stderr
        netexits.subprocess.run = lambda cmd, **k: (calls.append(cmd), done)[1]

    def test_calls_the_helper_through_sudo(self) -> None:
        self._helper_says("exit-miami ready: 146.70.183.206 (United States, Florida, Miami)")
        name, said = netexits.open_exit("Miami", city=True)
        self.assertEqual(name, "exit-miami")
        self.assertIn("Miami", said)
        self.assertEqual(self.calls[0][:3], ["sudo", "-n", self.helper])
        self.assertIn("--city", self.calls[0])

    def test_a_country_is_not_passed_as_a_city(self) -> None:
        self._helper_says("exit-mexico ready: 1.2.3.4 (Mexico)")
        netexits.open_exit("Mexico")
        self.assertNotIn("--city", self.calls[0])

    def test_an_empty_place_is_refused_before_sudo(self) -> None:
        self._helper_says("")
        with self.assertRaises(netexits.ExitError):
            netexits.open_exit("   ")
        self.assertEqual(self.calls, [])

    def test_a_missing_helper_explains_itself(self) -> None:
        os.environ[netexits.HELPER_ENV] = str(Path(self._dir.name) / "nope")
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.open_exit("Miami")
        self.assertIn("contrib/install", str(caught.exception))
        self.assertIn("this plugin cannot do it", str(caught.exception))

    def test_a_refused_sudo_rule_is_explained(self) -> None:
        self._helper_says(code=1, stderr="sudo: a password is required")
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.open_exit("Miami")
        self.assertIn("sudo", str(caught.exception))
        self.assertIn("contrib/vpn-exit", str(caught.exception))

    def test_the_helpers_own_failure_is_passed_along(self) -> None:
        self._helper_says(code=1, stderr="vpn-exit: exit-x did not come up within 75s")
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.open_exit("Nowhere")
        self.assertIn("did not come up", str(caught.exception))

    def test_an_unexpected_answer_is_not_taken_as_a_name(self) -> None:
        self._helper_says("something else entirely")
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.open_exit("Miami")
        self.assertIn("unexpected", str(caught.exception))

    def test_closing_passes_the_name_through(self) -> None:
        self._helper_says("exit-miami removed")
        self.assertIn("removed", netexits.close_exit("exit-miami"))
        self.assertEqual(self.calls[0][3:], ["down", "exit-miami"])


class Catalogue(_Sandbox):
    """Where could I go -- answered from the provider's own list, not from guesses."""

    def setUp(self) -> None:
        super().setUp()
        netexits._save_cache(
            {
                "default": "surfshark",
                "providers_list": ["mullvad", "nordvpn", "surfshark"],
                "providers": {
                    "surfshark": {
                        "countries": ["Mexico", "Japan", "Spain", "United States"],
                        "cities": [["United States", "Miami"], ["Mexico", "Mexico City"]],
                    },
                    "mullvad": {"countries": ["Sweden", "Japan"], "cities": [["Sweden", "Malmo"]]},
                },
            }
        )

    def test_no_search_summarises_and_lists_countries(self) -> None:
        answer = netexits.find_places()
        self.assertIn("4 countries", answer)
        self.assertIn("Mexico", answer)

    def test_search_finds_a_city(self) -> None:
        answer = netexits.find_places("miami")
        self.assertIn("Miami (United States)", answer)

    def test_search_is_case_insensitive(self) -> None:
        self.assertIn("Japan", netexits.find_places("JAPAN"))

    def test_a_city_search_also_matches_its_country(self) -> None:
        self.assertIn("Mexico City", netexits.find_places("mexico"))

    def test_another_provider_can_be_asked_about(self) -> None:
        """Answerable without having a subscription to it."""
        answer = netexits.find_places("", "mullvad")
        self.assertIn("Sweden", answer)
        self.assertNotIn("Mexico", answer)

    def test_an_unknown_place_says_so_without_inventing(self) -> None:
        answer = netexits.find_places("atlantis")
        self.assertIn("nothing matching", answer)

    def test_suggestions_for_a_rejected_place(self) -> None:
        self.assertIn("Mexico", netexits.suggest_places("Mexi"))

    def test_suggestions_stay_quiet_when_there_is_no_catalogue(self) -> None:
        netexits.places_cache().unlink()
        netexits.discover_containers = lambda: []
        self.assertEqual(netexits.suggest_places("Mexico"), "")


class ContainerPlaceLabel(unittest.TestCase):
    """A city exit declares SERVER_CITIES and no country, and still has a place.

    These read the container's environment, which is what `discover_containers`
    passes in after one inspect. The label and the countries come from the
    same read and mean different things: the label is for a person, and only
    the countries are compared.
    """

    def test_reads_a_city(self) -> None:
        env = ["VPN_TYPE=wireguard", "SERVER_CITIES=Miami"]
        self.assertEqual(netexits._container_country(env), "Miami")

    def test_reads_a_country(self) -> None:
        self.assertEqual(netexits._container_country(["SERVER_COUNTRIES=Mexico"]), "Mexico")

    def test_prefers_the_city_when_both_are_set(self) -> None:
        env = ["SERVER_COUNTRIES=United States", "SERVER_CITIES=Miami"]
        self.assertEqual(netexits._container_country(env), "Miami")

    def test_nothing_declared(self) -> None:
        self.assertEqual(netexits._container_country(["VPN_TYPE=wireguard"]), "")

class ProviderGuides(unittest.TestCase):
    """Answering 'what do I need for AirVPN?' from the shipped pages."""

    def test_every_provider_gluetun_supports_has_a_guide(self) -> None:
        names = netexits.guides()
        self.assertGreater(len(names), 20)
        for expected in ("airvpn", "mullvad", "nordvpn", "surfshark", "protonvpn", "custom"):
            self.assertIn(expected, names)

    def test_a_guide_names_the_variables_and_where_they_come_from(self) -> None:
        text = netexits.guide("airvpn")
        self.assertIn("VPN_SERVICE_PROVIDER=airvpn", text)
        self.assertIn("WIREGUARD_PRIVATE_KEY", text)

    def test_the_guide_names_the_exact_per_provider_file(self) -> None:
        """A reader should not have to ask 'which file?' after reading it."""
        self.assertIn("/root/vpn-exits/airvpn.env", netexits.guide("airvpn"))
        self.assertIn("/root/vpn-exits/mullvad.env", netexits.guide("mullvad"))

    def test_the_guide_offers_the_set_command(self) -> None:
        """The easy path to storing credentials is named, per provider."""
        text = netexits.guide("airvpn")
        self.assertIn("hermes vpn provider airvpn --set", text)
        # The handoff names where to run it, and that it is not the chat.
        self.assertIn("Terminal tab", text)

    def test_with_no_providers_the_answer_points_at_set(self) -> None:
        """The empty case names the one next command, not just the installer."""
        with mock.patch.object(netexits, "configured_providers", return_value=[]):
            said = netexits.describe_providers()
        self.assertIn("hermes vpn provider <name> --set", said)

    def test_the_answer_says_where_it_came_from(self) -> None:
        """Shipped upstream text, credited, not a summary that drifts."""
        self.assertIn("gluetun wiki", netexits.guide("mullvad"))

    def test_common_spellings_resolve(self) -> None:
        for spelling in ("PIA", "pia", "private-internet-access"):
            self.assertIn("private internet access", netexits.guide(spelling).lower())
        self.assertIn("protonvpn", netexits.guide("Proton").lower())

    def test_an_unknown_provider_lists_the_real_ones(self) -> None:
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.guide("notavpn")
        self.assertIn("mullvad", str(caught.exception))

    def test_an_empty_name_asks_which(self) -> None:
        with self.assertRaises(netexits.ExitError):
            netexits.guide("   ")

    def test_a_near_miss_is_suggested(self) -> None:
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.guide("surfsharkk")
        self.assertIn("surfshark", str(caught.exception))


class KillSwitch(_Sandbox):
    """Armed, the browser leaves by an exit or it does not leave at all."""

    def setUp(self) -> None:
        super().setUp()
        self.write_exits({"name": "mx", "proxy": MX_PROXY, "country": "Mexico"})
        netexits._last_check = ("", 0.0, False)

    def _alive(self, ok: bool) -> None:
        self.seeing(ok=ok, ip="201.0.0.5", country="MX", city="Mexico City", detail="down")
        netexits._last_check = ("", 0.0, False)

    def test_off_by_default(self) -> None:
        self.assertFalse(netexits.locked())

    def test_arming_with_no_exit_blocks_browsing_rather_than_allowing_it(self) -> None:
        answer = netexits.set_locked(True)
        self.assertIn("dead end", answer)
        self.assertEqual(netexits.current_proxy(), netexits.DEAD_END_PROXY)

    def test_arming_keeps_the_chosen_exit(self) -> None:
        self._alive(True)
        netexits.switch("mx")
        netexits.set_locked(True)
        self.assertEqual(netexits.current_proxy(), MX_PROXY)

    def test_direct_is_refused_while_armed(self) -> None:
        self._alive(True)
        netexits.switch("mx")
        netexits.set_locked(True)
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.switch("direct")
        self.assertIn("kill switch", str(caught.exception))
        self.assertEqual(netexits.current_proxy(), MX_PROXY)

    def test_browser_calls_pass_while_the_exit_answers(self) -> None:
        self._alive(True)
        netexits.switch("mx")
        netexits.set_locked(True)
        self.assertEqual(netexits.guard_browser("browser_navigate"), "")

    def test_browser_calls_are_held_when_the_exit_dies(self) -> None:
        self._alive(True)
        netexits.switch("mx")
        netexits.set_locked(True)
        self._alive(False)
        refusal = netexits.guard_browser("browser_navigate")
        self.assertIn("stopped answering", refusal)

    def test_a_dead_exit_is_allowed_through_when_disarmed(self) -> None:
        """Without the switch, a dead tunnel is Chromium's problem, not ours."""
        self._alive(True)
        netexits.switch("mx")
        self._alive(False)
        self.assertEqual(netexits.guard_browser("browser_navigate"), "")

    def test_other_tools_are_never_held(self) -> None:
        netexits.set_locked(True)
        self._alive(False)
        for tool in ("net_where", "write_file", "terminal"):
            self.assertEqual(netexits.guard_browser(tool), "")

    def test_the_check_is_cached_between_calls(self) -> None:
        """Re-checking before every click would be its own kind of broken."""
        self._alive(True)
        netexits.switch("mx")
        netexits.set_locked(True)
        calls = []

        def _count(proxy: str = ""):
            calls.append(proxy)
            return netexits.Sighting(ok=True, ip="1.2.3.4")

        netexits.look = _count
        netexits._last_check = ("", 0.0, False)
        for _ in range(5):
            netexits.guard_browser("browser_navigate")
        self.assertEqual(len(calls), 1)

    def test_it_survives_a_restart(self) -> None:
        self._alive(True)
        netexits.switch("mx")
        netexits.set_locked(True)
        os.environ.pop(netexits.BROWSER_ARGS_ENV)
        netexits.reapply_saved_choice()
        self.assertTrue(netexits.locked())
        self.assertEqual(netexits.current_proxy(), MX_PROXY)

    def test_a_restart_with_nothing_saved_still_blocks(self) -> None:
        netexits.set_locked(True)
        os.environ.pop(netexits.BROWSER_ARGS_ENV, None)
        note = netexits.reapply_saved_choice()
        self.assertIn("blocked", note)
        self.assertEqual(netexits.current_proxy(), netexits.DEAD_END_PROXY)


class AnUnreadableStateFileStaysArmed(_Sandbox):
    """Every reader treats "could not be read" as armed. The writer did not.

    Found by a security audit, twice over: `_write_state` merged onto `{}`,
    so the next ordinary write rebuilt a valid file with no `locked` key and
    the kill switch was off -- after a successful `use` with a cheerful
    answer, and `doctor` reporting it as somebody's choice.
    """

    def test_an_ordinary_write_does_not_rebuild_the_file_disarmed(self) -> None:
        self.write_exits({"name": "mx", "proxy": MX_PROXY, "country": "Mexico"})
        self.seeing(ok=True, ip="201.0.0.5", country="MX", city="Mexico City")
        netexits.set_locked(True)
        Path(netexits.state_file()).write_text("{ not json")
        self.assertTrue(netexits.locked(), "unreadable reads as armed")
        netexits.switch("mx")
        self.assertTrue(netexits.locked(), "and a switch must not quietly disarm it")

    def test_the_rebuilt_file_says_so_rather_than_leaving_it_to_the_env(self) -> None:
        Path(netexits.state_file()).write_text("{ not json")
        netexits._write_state(chosen=None)
        self.assertIs(json.loads(Path(netexits.state_file()).read_text())["locked"], True)


class StateIsNotCache(_Sandbox):
    """A security setting must not live where someone will delete it."""

    def test_the_lock_survives_clearing_the_places_cache(self) -> None:
        netexits.set_locked(True)
        netexits.places_cache().unlink(missing_ok=True)
        self.assertTrue(netexits.locked())

    def test_the_chosen_exit_and_the_lock_coexist(self) -> None:
        self.write_exits({"name": "mx", "proxy": MX_PROXY, "country": "Mexico"})
        self.seeing(ok=True, ip="201.0.0.5", country="MX", city="Mexico City")
        netexits.set_locked(True)
        netexits.switch("mx")
        self.assertTrue(netexits.locked())
        self.assertEqual((netexits.saved_choice() or {}).get("name"), "mx")


class WebRTCLeak(unittest.TestCase):
    """A proxy carries TCP only; WebRTC's UDP would walk straight past it."""

    def test_the_webrtc_policy_rides_along_with_a_proxy(self) -> None:
        args = netexits.browser_args(MX_PROXY)
        self.assertIn(netexits.WEBRTC_ARG, args)

    def test_nothing_to_protect_without_a_proxy(self) -> None:
        self.assertNotIn(netexits.WEBRTC_ARG, netexits.browser_args(""))

    def test_the_base_arguments_still_survive(self) -> None:
        args = netexits.browser_args(MX_PROXY).split(",")
        for base in netexits.BASE_BROWSER_ARGS:
            self.assertIn(base, args)
        self.assertEqual(len(args), len(netexits.BASE_BROWSER_ARGS) + 2)


class Doctor(_Sandbox):
    """The check a person runs right after installing."""

    def setUp(self) -> None:
        super().setUp()
        self._saved_policy = netexits.CHROME_POLICY_FILE
        netexits.CHROME_POLICY_FILE = Path(self._dir.name) / "policy.json"

    def tearDown(self) -> None:
        netexits.CHROME_POLICY_FILE = self._saved_policy
        super().tearDown()

    def _profile(self, name: str, backend: str, extra: str = "") -> None:
        path = Path(self._dir.name) / "profiles" / name / "config.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        body = f'terminal:\n  backend: "{backend}"\n'
        if extra:
            body += f"  docker_extra_args:\n    - \"{extra}\"\n"
        path.write_text(body)

    def test_a_fresh_install_lists_what_is_missing(self) -> None:
        ok, report = netexits.doctor()
        self.assertFalse(ok)
        self.assertIn("no exits yet", report)
        self.assertIn("hermes vpn provider", report)  # the fix, not just the fault

    def test_every_problem_carries_its_command(self) -> None:
        ok, report = netexits.doctor()
        for line in report.splitlines():
            if line.startswith("✗"):
                self.assertTrue(
                    "`" in line or "Fix:" in line, f"problem without a fix: {line}"
                )

    def test_a_healthy_setup_passes(self) -> None:
        self.write_exits({"name": "mx", "proxy": MX_PROXY, "country": "Mexico"})
        self.seeing(ok=True, ip="201.0.0.5", country="MX", city="Mexico City")
        netexits.switch("mx")
        netexits.CHROME_POLICY_FILE.write_text('{"WebRtcIPHandling": "disable_non_proxied_udp"}')
        ok, report = netexits.doctor()
        self.assertTrue(ok, report)

    def _docker_says(self, answers: dict) -> None:
        """Stub docker: {(args tuple prefix): output}.

        Stubs both callers. ``_docker_try`` reports whether the call ran, so an
        unmatched prefix comes back as "could not ask" rather than as an empty
        answer -- the same distinction the real one makes.
        """
        def fake(*args, timeout=15):
            for prefix, out in answers.items():
                if args[: len(prefix)] == prefix:
                    return out
            return ""

        def fake_try(*args, timeout=15):
            for prefix, out in answers.items():
                if args[: len(prefix)] == prefix:
                    # A policy read is framed with the nonce it asked for.
                    return True, (policy_reply(args, *out) if isinstance(out, tuple) else out)
            return False, ""

        self._real_docker = netexits._docker
        real_try = netexits._docker_try
        netexits._docker = fake
        netexits._docker_try = fake_try

        def restore() -> None:
            netexits._docker = self._real_docker
            netexits._docker_try = real_try

        self.addCleanup(restore)

    #: The bodies a container holds; `policy_reply` frames them. Built from
    #: production so this double cannot drift from the real file.
    POLICY_IN_PLACE = (netexits.sandbox_policy_body(),)

    def test_a_sandbox_that_can_reach_the_internet_is_called_out(self) -> None:
        """Checked on the container, not the config: the two can disagree.

        While the kill switch is armed, that is: disarmed, a sandbox with a
        network of its own is what disarming does, and reporting it as a
        fault would cry wolf at every deliberate use.
        """
        netexits.set_locked(True)
        self._profile("lab", "docker")
        self._docker_says(
            {
                ("ps",): "hermes-abc123\tlab",
                ("inspect",): "bridge ",
                ("network", "inspect"): "false",
            }
        )
        try:
            _ok, report = netexits.doctor()
        finally:
            netexits._docker = self._real_docker
        self.assertIn("'lab'", report)
        self.assertIn("can reach the internet directly", report)

    def test_a_sealed_sandbox_passes(self) -> None:
        self._profile("web", "docker")
        self._docker_says(
            {
                ("ps",): "hermes-def456\tweb",
                ("inspect",): "hermes-vpn ",
                ("network", "inspect"): "true",
                ("exec",): self.POLICY_IN_PLACE,
            }
        )
        _ok, report = netexits.doctor()
        self.assertIn("no way to the internet except the tunnel", report)
        self.assertIn("the policy inside hermes-def456 points that browser at the exit", report)

    def _sealed_web(self) -> None:
        """A sealed profile with its policy in place, so only egress is in doubt."""
        self._profile("web", "docker")
        self._docker_says(
            {
                ("ps",): "hermes-def456\tweb",
                ("inspect",): "hermes-vpn ",
                ("network", "inspect"): "true",
                ("exec",): self.POLICY_IN_PLACE,
            }
        )
        real = netexits.verify_sandbox
        self.addCleanup(lambda: setattr(netexits, "verify_sandbox", real))

    def test_a_sealed_sandbox_is_asked_whether_anything_comes_back(self) -> None:
        self._sealed_web()
        netexits.verify_sandbox = lambda c: (True, "OK 1.2.3.4 MX")
        _ok, report = netexits.doctor()
        self.assertIn("checked from inside — OK 1.2.3.4 MX", report)

    def test_a_relay_with_no_country_is_a_problem_not_a_pass(self) -> None:
        """Sealed, policy correct, and nothing loads: the state a fresh install
        is in before anyone picks a country."""
        self._sealed_web()
        netexits.verify_sandbox = lambda c: (
            False, "upstream fail: no country chosen yet: /upstream/web is empty")
        ok, report = netexits.doctor()
        self.assertFalse(ok, "a profile that cannot reach anything passed the check")
        self.assertIn("nothing comes back from inside hermes-def456", report)
        self.assertIn("hermes -p web vpn use <place>", report)
        # The shape is still right, and saying so is not the same as passing.
        self.assertIn("no way to the internet except the tunnel", report)

    def test_a_missing_verifier_is_not_reported_as_no_egress(self) -> None:
        """Nothing was asked, so nothing may be concluded about the exit."""
        self._sealed_web()  # the base fixture points VERIFY_HELPER at nothing
        _ok, report = netexits.doctor()
        self.assertIn("cannot be checked from inside", report)
        self.assertNotIn("nothing comes back", report)

    def test_the_policy_is_read_inside_the_container(self) -> None:
        """The host's /etc says nothing about a browser living in a container."""
        self._profile("web", "docker")
        netexits.CHROME_POLICY_FILE.write_text(
            '{"WebRtcIPHandling": "disable_non_proxied_udp"}'
        )  # the host is hardened; the sandbox is not
        self._docker_says(
            {
                ("ps",): "hermes-def456\tweb",
                ("inspect",): "hermes-vpn ",
                ("network", "inspect"): "true",
                ("exec",): (),   # no policy file at all
            }
        )
        ok, report = netexits.doctor()
        self.assertFalse(ok, report)
        self.assertIn("no policy inside hermes-def456", report)
        self.assertIn("will not load", report)  # sealed: it fails shut, not open
        self.assertIn("vpn-migrate hermes-def456", report)  # the script takes a container

    def test_in_a_sandbox_profile_the_host_argument_is_not_the_claim(self) -> None:
        """Hermes overwrites the flag in there, so reporting it green is a lie."""
        os.environ[netexits.PROFILE_ENV] = "lab"
        self.addCleanup(lambda: os.environ.pop(netexits.PROFILE_ENV, None))
        self._profile("lab", "docker")
        self._docker_says(
            {
                ("ps",): "hermes-abc123\tlab",
                ("inspect",): "hermes-vpn ",
                ("network", "inspect"): "true",
                ("exec",): self.POLICY_IN_PLACE,
            }
        )
        _ok, report = netexits.doctor()
        self.assertIn("Hermes overwrites the WebRTC", report)
        self.assertNotIn("WebRTC is told not to use non-proxied UDP", report)
        self.assertNotIn("browser-wide WebRTC policy is not installed", report)

    def test_and_is_not_called_out_when_the_kill_switch_is_down(self) -> None:
        """The same topology, the other switch position, the other verdict."""
        self._profile("lab", "docker")
        self._docker_says(
            {
                ("ps",): "hermes-abc123\tlab",
                ("inspect",): "bridge ",
                ("network", "inspect"): "false",
            }
        )
        try:
            _ok, report = netexits.doctor()
        finally:
            netexits._docker = self._real_docker
        self.assertIn("because the kill switch is disarmed", report)
        self.assertNotIn("can reach the internet directly", report)

    def test_an_unsealed_sandbox_without_policy_is_a_leak_not_a_breakage(self) -> None:
        self._profile("lab", "docker")
        self._docker_says(
            {
                ("ps",): "hermes-abc123\tlab",
                ("inspect",): "bridge ",
                ("network", "inspect"): "false",
                ("exec",): (),   # no policy file at all
            }
        )
        _ok, report = netexits.doctor()
        self.assertIn("can hand out this machine's own address", report)

    def test_a_policy_that_cannot_be_read_is_not_reported_as_absent(self) -> None:
        """Three answers, not two: "I could not look" is its own line."""
        self._profile("web", "docker")
        self._docker_says(
            {
                ("ps",): "hermes-def456\tweb",
                ("inspect",): "hermes-vpn ",
                ("network", "inspect"): "true",
            }  # no ("exec",) entry: the read itself fails
        )
        ok, report = netexits.doctor()
        self.assertFalse(ok, report)
        self.assertIn("could not be read", report)
        self.assertNotIn("no policy inside", report)

    def test_two_networks_means_a_way_out(self) -> None:
        """A sandbox reconnected to bridge is open even if one network is internal."""
        self._profile("lab", "docker")
        self._docker_says(
            {
                ("ps",): "hermes-abc123\tlab",
                ("inspect",): "bridge hermes-vpn ",
                ("network", "inspect"): "true",
            }
        )
        try:
            _ok, report = netexits.doctor()
        finally:
            netexits._docker = self._real_docker
        self.assertIn("on 2 networks", report)

    def test_no_sandbox_running_is_not_a_failure(self) -> None:
        self._profile("lab", "docker")
        self._docker_says({("ps",): ""})
        try:
            ok, report = netexits.doctor()
        finally:
            netexits._docker = self._real_docker
        self.assertIn("no sandbox running", report)

    def test_a_local_profile_is_not_a_sandbox_problem(self) -> None:
        self._profile("default", "local")
        _ok, report = netexits.doctor()
        self.assertNotIn("'default'", report)

    def test_the_policy_check_reads_the_real_setting(self) -> None:
        netexits.CHROME_POLICY_FILE.write_text('{"WebRtcIPHandling": "default"}')
        self.assertFalse(netexits.browser_policy_installed())
        netexits.CHROME_POLICY_FILE.write_text('{"WebRtcIPHandling": "disable_non_proxied_udp"}')
        self.assertTrue(netexits.browser_policy_installed())


class SandboxSwitching(_Sandbox):
    """An agent inside a sandbox moves the relay, not an argument on the host."""

    def setUp(self) -> None:
        super().setUp()
        os.environ[netexits.PROFILE_ENV] = "lab"
        self.write_exits({"name": "exit-jp", "proxy": JP_PROXY, "country": "Japan"})
        self._real_docker = netexits._docker
        self._real_verify = netexits.verify_sandbox
        self._real_helper = netexits._run_helper
        self.helper_calls: list[tuple] = []
        path = Path(self._dir.name) / "profiles" / "lab" / "config.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('terminal:\n  backend: "docker"\n')
        netexits._docker = lambda *a, **k: (
            "hermes-abc123\tlab" if a[0] == "ps" else ("hermes-vpn " if a[0] == "inspect" else "true")
        )
        netexits._run_helper = lambda *a: self.helper_calls.append(a) or "relay upstream: exit-jp:8888"

        # The policy reads go through _docker_try. Left unstubbed they would
        # reach the real docker, which is how a unit test starts depending on
        # the machine it runs on. Default: the policy is already in place.
        self._real_try = netexits._docker_try
        self.exec_calls: list[tuple] = []
        self.policy_reads: list[tuple] = [self.POLICY_IN_PLACE]
        netexits._docker_try = self._fake_try

    #: The bodies a container holds; `policy_reply` frames them. Built from
    #: production so this double cannot drift from the real file.
    POLICY_IN_PLACE = (netexits.sandbox_policy_body(),)
    #: ... and a container with no policy file at all.
    POLICY_ABSENT: tuple = ()
    #: ... and one whose policy exists but sends that browser out directly.
    #: A substring search for the WebRTC setting called this healthy.
    POLICY_WRONG = ('{"ProxyMode":"direct","WebRtcIPHandling":"disable_non_proxied_udp"}',)

    def _fake_try(self, *args, timeout=15):
        """Answer policy reads from self.policy_reads; record writes."""
        if args[:1] == ("ps",):
            # The sandbox listing, which this class answers through _docker.
            return True, netexits._docker(*args)
        if "cat" in " ".join(args):
            bodies = self.policy_reads[0] if len(self.policy_reads) == 1 else self.policy_reads.pop(0)
            return True, policy_reply(args, *bodies)
        self.exec_calls.append(args)
        return self.write_succeeds, ""

    #: Whether the repair's docker exec is allowed to succeed.
    write_succeeds = True

    def tearDown(self) -> None:
        os.environ.pop(netexits.PROFILE_ENV, None)
        netexits._docker = self._real_docker
        netexits._docker_try = self._real_try
        netexits.verify_sandbox = self._real_verify
        netexits._run_helper = self._real_helper
        super().tearDown()

    def test_it_knows_it_is_in_a_sandbox(self) -> None:
        self.assertEqual(netexits.in_sandbox(), "hermes-abc123")

    def test_switching_moves_the_relay_and_confirms_from_inside(self) -> None:
        netexits.verify_sandbox = lambda c: (True, "OK 89.187.161.3 JP")
        answer = netexits.switch("exit-jp")
        self.assertEqual(self.helper_calls, [("country", "exit-jp", "lab")])
        self.assertIn("89.187.161.3", answer)
        self.assertIn("from inside", answer)

    def test_an_unconfirmed_switch_is_an_error(self) -> None:
        """Fail-closed: the relay may have moved, but nothing is claimed."""
        netexits.verify_sandbox = lambda c: (False, "VPN-VERIFY FAIL(3): direct egress open")
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.switch("exit-jp")
        self.assertIn("could not confirm", str(caught.exception))

    def test_direct_is_refused_while_the_kill_switch_is_armed(self) -> None:
        netexits.set_locked(True)
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.switch("direct")
        self.assertIn("no direct path", str(caught.exception))

    def test_and_allowed_once_it_is_disarmed(self) -> None:
        """Which is the same rule the host follows, in the place that used to
        answer "that is the point of it" whatever the switch said."""
        said = netexits.switch("direct")
        self.assertIn("Proxy off", said)

    def test_the_label_and_the_sighting_both_appear(self) -> None:
        netexits.verify_sandbox = lambda c: (True, "OK 1.2.3.4 DE")
        answer = netexits.switch("exit-jp")
        self.assertIn("DE", answer)
        self.assertIn("Japan", answer)

    def test_a_missing_policy_is_written_back_before_the_switch(self) -> None:
        """A container Hermes recreated comes up without it; the switch repairs it."""
        netexits.verify_sandbox = lambda c: (True, "OK 89.187.161.3 JP")
        self.policy_reads = [self.POLICY_ABSENT, self.POLICY_IN_PLACE]
        answer = netexits.switch("exit-jp")
        self.assertEqual(len(self.exec_calls), 1, self.exec_calls)
        written = " ".join(self.exec_calls[0])
        self.assertIn("-u root", written)
        self.assertIn("vpn.json", written)
        self.assertIn("disable_non_proxied_udp", written)
        self.assertIn("http://vpn-exit:8888", written)
        self.assertIn("had no browser policy", answer)
        self.assertIn("89.187.161.3", answer)  # still reports the switch itself

    def test_a_policy_in_place_is_left_alone_and_unmentioned(self) -> None:
        netexits.verify_sandbox = lambda c: (True, "OK 89.187.161.3 JP")
        answer = netexits.switch("exit-jp")
        self.assertEqual(self.exec_calls, [])
        self.assertNotIn("policy", answer)

    def test_a_repair_that_fails_does_not_fail_the_switch(self) -> None:
        """The exit is verified separately; a failed repair is news, not an error."""
        netexits.verify_sandbox = lambda c: (True, "OK 89.187.161.3 JP")
        self.policy_reads = [self.POLICY_ABSENT]
        self.write_succeeds = False
        answer = netexits.switch("exit-jp")
        self.assertIn("could not be written", answer)
        self.assertIn("89.187.161.3", answer)

    def test_a_policy_that_reads_back_missing_is_not_claimed_as_repaired(self) -> None:
        netexits.verify_sandbox = lambda c: (True, "OK 89.187.161.3 JP")
        self.policy_reads = [self.POLICY_ABSENT, self.POLICY_ABSENT]
        answer = netexits.switch("exit-jp")
        self.assertIn("still reads wrong", answer)
        self.assertIn("something else is managing that file", answer)

    def test_an_unreadable_policy_is_not_overwritten(self) -> None:
        """Three answers again: not knowing is not a licence to write."""
        netexits.verify_sandbox = lambda c: (True, "OK 89.187.161.3 JP")
        # Unreadable policy, not an unreachable docker: the sandbox listing
        # still answers, or this stops being a test about the policy.
        netexits._docker_try = lambda *a, **k: (
            (True, netexits._docker(*a)) if a[:1] == ("ps",) else (False, "")
        )
        answer = netexits.switch("exit-jp")
        self.assertIn("could not be read", answer)

    def test_choosing_an_exit_takes_the_sandbox_off_its_own_network(self) -> None:
        """Choosing an exit is asking for the tunnel. A bot coming back from
        direct got "sandbox is on 2 networks; it must be on exactly one" from
        the verifier, with nothing saying that arming the kill switch first
        was the way out of it."""
        netexits._docker = lambda *a, **k: (
            "hermes-abc123\tlab" if a[0] == "ps"
            else ("bridge hermes-vpn-lab " if a[0] == "inspect" else "false")
        )
        netexits.verify_sandbox = lambda c: (True, "OK 89.187.161.3 JP")
        said = netexits.switch("exit-jp")
        self.assertIn("taken off its own network first", said)

    def test_where_reports_from_inside(self) -> None:
        netexits._write_state(chosen={"name": "exit-jp", "proxy": JP_PROXY})
        netexits.verify_sandbox = lambda c: (True, "OK 89.187.161.3 JP")
        answer = netexits.describe_here()
        self.assertIn("no way to the internet except the tunnel", answer)
        self.assertIn("89.187.161.3", answer)

    def test_where_says_unknown_when_it_cannot_confirm(self) -> None:
        netexits._write_state(chosen={"name": "exit-jp", "proxy": JP_PROXY})
        netexits.verify_sandbox = lambda c: (False, "timed out")
        self.assertIn("unknown", netexits.describe_here())


class ProfileLocation(_Sandbox):
    """Knowing where the agent is running. Getting it wrong produces a lie."""

    def test_inside_a_profile_the_siblings_are_found(self) -> None:
        """HERMES_HOME is .../profiles/<name> there, not a root with profiles/ under it."""
        root = Path(self._dir.name) / "profiles"
        (root / "lab").mkdir(parents=True)
        (root / "web").mkdir(parents=True)
        os.environ["HERMES_HOME"] = str(root / "lab")
        try:
            self.assertEqual(netexits.profiles_dir(), root)
            self.assertEqual(netexits.current_profile(), "lab")
        finally:
            os.environ["HERMES_HOME"] = self._dir.name

    def test_on_the_host_the_profiles_live_below(self) -> None:
        self.assertEqual(netexits.profiles_dir(), Path(self._dir.name) / "profiles")
        self.assertEqual(netexits.current_profile(), "default")

    def test_a_profile_sees_its_own_sandbox_as_its_own(self) -> None:
        root = Path(self._dir.name) / "profiles"
        (root / "lab").mkdir(parents=True)
        (root / "lab" / "config.yaml").write_text('terminal:\n  backend: "docker"\n')
        os.environ["HERMES_HOME"] = str(root / "lab")
        real = netexits._docker
        netexits._docker = lambda *a, **k: (
            "hermes-xyz\tlab" if a[0] == "ps" else ("hermes-vpn " if a[0] == "inspect" else "true")
        )
        try:
            self.assertEqual(netexits.in_sandbox(), "hermes-xyz")
        finally:
            netexits._docker = real
            os.environ["HERMES_HOME"] = self._dir.name


class ReportsFactsNotVerdicts(_Sandbox):
    """The tool measures; whoever reads it decides what that means.

    So it prints both the country it asked for and the one it got, instead of
    comparing them against a table of names. Two values in a sentence work in
    any language and spelling, and the reader is better at judging them.
    """

    def setUp(self) -> None:
        super().setUp()
        self.write_exits({"name": "exit-jp", "proxy": JP_PROXY, "country": "Japan"})

    def test_both_the_label_and_the_sighting_are_reported(self) -> None:
        self.seeing(ok=True, ip="89.187.161.3", country="JP", city="Tokyo")
        answer = netexits.switch("exit-jp")
        self.assertIn("89.187.161.3", answer)
        self.assertIn("Tokyo", answer)
        self.assertIn("Japan", answer)

    def test_a_real_mismatch_is_visible_without_being_judged(self) -> None:
        """A reader seeing Germany next to a Japan label needs no help."""
        self.seeing(ok=True, ip="1.2.3.4", country="DE", city="Frankfurt")
        answer = netexits.switch("exit-jp")
        self.assertIn("Frankfurt", answer)
        self.assertIn("Japan", answer)
        self.assertNotIn("stale", answer.lower())

    def test_an_exit_with_no_label_says_nothing_about_one(self) -> None:
        self.write_exits({"name": "exit-x", "proxy": "http://127.0.0.1:8899"})
        self.seeing(ok=True, ip="1.2.3.4", country="DE", city="Frankfurt")
        answer = netexits.switch("exit-x")
        self.assertNotIn("labels", answer)




class FailsClosed(_Sandbox):
    """The guarantee the plugin advertises, attacked from every angle.

    They are grouped because they are one bug with many faces: a measurement
    that could not be made, read as a measurement that came back fine.
    """

    def _serving(self, body: object) -> str:
        """A local HTTP server that answers *body*; returns its URL."""
        import contextlib
        import io
        import json as _json
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        payload = _json.dumps(body).encode()

        class _H(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *a):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), _H)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        with contextlib.suppress(Exception):
            pass
        return f"http://127.0.0.1:{server.server_port}/"

    def _listening_without_http(self) -> str:
        """A socket that accepts and answers bytes that are not HTTP."""
        import socket
        import threading

        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(5)
        self.addCleanup(server.close)

        def serve():
            while True:
                try:
                    conn, _ = server.accept()
                    conn.recv(4096)
                    conn.sendall(b" not-http\r\n\r\n")
                    conn.close()
                except OSError:
                    return

        threading.Thread(target=serve, daemon=True).start()
        return f"http://127.0.0.1:{server.getsockname()[1]}"

    # -- the measurement itself ---------------------------------------------

    def test_no_proxy_in_the_environment_cannot_silence_the_proxy(self) -> None:
        """urllib would connect direct and say nothing; the answer must not lie."""
        netexits.LOOKUP_URLS = (self._serving({"ip": "45.33.32.156", "country": "Germany"}),)
        self.addCleanup(lambda: setattr(netexits, "LOOKUP_URLS", _ORIGINAL_URLS))
        for name in ("no_proxy", "NO_PROXY"):
            os.environ[name] = "*"
            self.addCleanup(lambda n=name: os.environ.pop(n, None))
        seen = netexits.look("http://127.0.0.1:2")  # nothing listens there
        self.assertFalse(seen.ok, f"a dead exit was reported as {seen.ip}")

    def test_a_listener_that_does_not_speak_http_is_a_failed_sighting(self) -> None:
        """Not an exception: the kill switch asks this question."""
        netexits.LOOKUP_URLS = ("https://example.invalid/",)
        self.addCleanup(lambda: setattr(netexits, "LOOKUP_URLS", _ORIGINAL_URLS))
        seen = netexits.look(self._listening_without_http())
        self.assertFalse(seen.ok)

    def test_a_lookup_naming_a_private_address_is_not_an_answer(self) -> None:
        """A proxy that answers with its own 10.x address would otherwise be a
        confirmed exit."""
        netexits.LOOKUP_URLS = (self._serving({"ip": "10.8.0.2", "country": "Mexico"}),)
        self.addCleanup(lambda: setattr(netexits, "LOOKUP_URLS", _ORIGINAL_URLS))
        seen = netexits.look()
        self.assertFalse(seen.ok)
        self.assertIn("not a routable address", seen.detail)

    def test_a_reply_that_is_not_an_object_is_not_an_answer(self) -> None:
        netexits.LOOKUP_URLS = (self._serving(["rate limited"]),)
        self.addCleanup(lambda: setattr(netexits, "LOOKUP_URLS", _ORIGINAL_URLS))
        self.assertFalse(netexits.look().ok)

    def test_a_redirect_does_not_become_a_direct_connection(self) -> None:
        """A redirect must not be followed.

        `HTTPRedirectHandler` builds a new request and nothing re-applies the
        proxy, so following one measures this host's own egress and reports it
        as the exit's.
        """
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        target = self._serving({"ip": "45.33.32.156", "country": "Germany"})

        class _Redirect(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                self.send_response(302)
                self.send_header("Location", target)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), _Redirect)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        netexits.LOOKUP_URLS = (f"http://127.0.0.1:{server.server_port}/",)
        self.addCleanup(lambda: setattr(netexits, "LOOKUP_URLS", _ORIGINAL_URLS))
        seen = netexits.look()
        self.assertFalse(seen.ok, f"a redirect was followed and reported as {seen.ip}")

    def test_the_guard_refuses_when_the_exit_speaks_nonsense(self) -> None:
        dead = self._listening_without_http()
        netexits.LOOKUP_URLS = ("https://example.invalid/",)
        self.addCleanup(lambda: setattr(netexits, "LOOKUP_URLS", _ORIGINAL_URLS))
        self.write_exits({"name": "mx", "proxy": dead, "country": "Mexico"})
        netexits.apply(netexits.resolve("mx"))
        netexits.set_locked(True)
        self.assertIn("stopped answering", netexits.guard_browser("browser_navigate"))

    # -- the state file -----------------------------------------------------

    def test_a_truncated_state_file_leaves_the_kill_switch_armed(self) -> None:
        """Unreadable is not disarmed: a corrupt byte must not turn it off."""
        netexits.set_locked(True)
        netexits.state_file().write_text('{"version": 1, "locked": true, "cho')
        self.assertTrue(netexits.locked())

    def test_a_state_file_that_is_not_an_object_leaves_it_armed(self) -> None:
        netexits.state_file().write_text("[1, 2, 3]")
        self.assertTrue(netexits.locked())
        self.assertIsNone(netexits.saved_choice())

    def test_an_unwritable_home_is_an_error_not_a_traceback(self) -> None:
        import stat

        home = Path(self._dir.name)
        mode = home.stat().st_mode
        home.chmod(stat.S_IREAD | stat.S_IEXEC)
        try:
            if os.access(home, os.W_OK):  # root: the mode means nothing
                self.skipTest("this user can write regardless of the mode")
            with self.assertRaises(netexits.ExitError):
                netexits.set_locked(True)
        finally:
            # Restored here, not in a cleanup: tearDown removes the directory
            # before cleanups run, so the cleanup would chmod a missing path.
            home.chmod(mode)

    # -- what may reach the browser's arguments -----------------------------

    def test_a_proxy_with_a_comma_never_becomes_a_browser_argument(self) -> None:
        """A comma ends the switch and starts another one."""
        with self.assertRaises(netexits.ExitError):
            netexits.Exit(name="mx", proxy="http://127.0.0.1:8891,--proxy-bypass-list=*")

    def test_a_proxy_with_a_space_or_a_path_is_refused(self) -> None:
        for hostile in ("http://127.0.0.1:8891 --disable-web-security",
                        "http://127.0.0.1:8891/x?y", "not-a-url", "",
                        # Chromium refuses a proxy with a path outright
                        # (ERR_NO_SUPPORTED_PROXIES) while urllib ignores it,
                        # so this verified and then loaded nothing.
                        "http://127.0.0.1:8891/"):
            with self.subTest(hostile=hostile), self.assertRaises(netexits.ExitError):
                netexits.check_proxy(hostile)

    def test_the_shapes_a_real_exit_uses_are_accepted(self) -> None:
        for good in (MX_PROXY, "http://vpn-exit:8888", "socks5://127.0.0.1:1080",
                     "http://[::1]:8891", "https://proxy.example:3128"):
            with self.subTest(good=good):
                self.assertEqual(netexits.check_proxy(good), good)

    # -- the policy ---------------------------------------------------------

    def test_the_legacy_spelling_chrome_ignores_is_not_protection(self) -> None:
        directory = Path(self._dir.name) / "policies"
        directory.mkdir()
        saved = netexits.CHROME_POLICY_FILE
        netexits.CHROME_POLICY_FILE = directory / "hermes-vpn-webrtc.json"
        self.addCleanup(lambda: setattr(netexits, "CHROME_POLICY_FILE", saved))
        (directory / "old.json").write_text('{"WebRtcIPHandlingPolicy": "disable_non_proxied_udp"}')
        self.assertFalse(netexits.browser_policy_installed())
        (directory / "note.json").write_text('{"WebRtcIPHandling": "default"}')
        self.assertFalse(netexits.browser_policy_installed())
        (directory / "vpn.json").write_text('{"WebRtcIPHandling": "disable_non_proxied_udp"}')
        self.assertTrue(netexits.browser_policy_installed())
        self.assertTrue(netexits.browser_policy_file().endswith("vpn.json"))

    def test_a_policy_that_sends_the_browser_out_directly_is_wrong_not_ok(self) -> None:
        bodies = netexits._policy_bodies(
            policy_reply((), '{"ProxyMode":"direct","WebRtcIPHandling":"disable_non_proxied_udp"}')
        )
        verdict, detail = netexits._policy_verdict(bodies, proxy=netexits.SANDBOX_PROXY)
        self.assertEqual(verdict, "wrong")
        self.assertIn("fixed_servers", detail)

    def test_two_files_fighting_over_the_proxy_are_reported(self) -> None:
        bodies = netexits._policy_bodies(policy_reply(
            (),
            netexits.sandbox_policy_body(),
            '{"ProxyMode":"fixed_servers","ProxyServer":"http://other:8888"}',
        ))
        verdict, detail = netexits._policy_verdict(bodies, proxy=netexits.SANDBOX_PROXY)
        self.assertEqual(verdict, "wrong")
        self.assertIn("more than one file", detail)

    # -- docker and the verifier -------------------------------------------

    def test_a_docker_that_cannot_be_executed_is_not_an_absence(self) -> None:
        def boom(*a, **k):
            raise PermissionError(13, "Permission denied")

        netexits.subprocess.run = boom  # the base class restores it
        # The real one: this is about what it does with an OSError, and the
        # base class stubs it so a listing does not reach the machine.
        netexits._docker_try = self._real_docker_try
        self.assertEqual(netexits._docker_try("ps"), (False, ""))
        self.assertEqual(netexits.heal_sandbox_policy("c1"),
                         " The policy inside c1 could not be read (the policy could not be "
                         "read), so it was left alone; `hermes vpn doctor` says more.")

    def test_a_verifier_that_exits_zero_without_a_measurement_is_not_a_confirmation(self) -> None:
        helper = Path(self._dir.name) / "verify"
        saved = netexits.VERIFY_HELPER
        netexits.VERIFY_HELPER = str(helper)
        self.addCleanup(lambda: setattr(netexits, "VERIFY_HELPER", saved))
        for printed in ("", "VPN-VERIFY FAIL(3): direct egress open", "could not determine it",
                        # "OK" and an address three lines apart: `\s` spanned
                        # newlines, so this matched the shape.
                        "OK\n\n\n1.2.3.4 JP"):
            with self.subTest(printed=printed):
                helper.write_text(f"#!/bin/sh\nprintf '%s\\n' {printed!r}\nexit 0\n")
                helper.chmod(0o755)
                ok, said = netexits.verify_sandbox("c1")
                self.assertFalse(ok, said)
                self.assertIn("not a measurement", said)
        # A shape is not a measurement: these fit `^OK <word> <CC>$` exactly
        # and name nothing a far end could be.
        for printed, why in (("OK unknown MX", "a word"),
                             ("OK 10.0.0.5 JP", "the inside of the tunnel"),
                             ("OK 127.0.0.1 MX", "this machine"),
                             ("OK 0.0.0.0 MX", "nowhere")):
            with self.subTest(printed=printed, why=why):
                helper.write_text(f"#!/bin/sh\nprintf '%s\\n' {printed!r}\n")
                helper.chmod(0o755)
                ok, said = netexits.verify_sandbox("c1")
                self.assertFalse(ok, said)
                self.assertIn("not a routable address", said)

        helper.write_text("#!/bin/sh\necho 'OK 1.2.3.4 JP'\n")
        helper.chmod(0o755)
        self.assertEqual(netexits.verify_sandbox("c1"), (True, "OK 1.2.3.4 JP"))

    def test_a_verifier_without_the_execute_bit_fails_closed(self) -> None:
        helper = Path(self._dir.name) / "verify"
        helper.write_text("#!/bin/sh\necho 'OK 1.2.3.4 JP'\n")
        helper.chmod(0o644)
        saved = netexits.VERIFY_HELPER
        netexits.VERIFY_HELPER = str(helper)
        self.addCleanup(lambda: setattr(netexits, "VERIFY_HELPER", saved))
        ok, said = netexits.verify_sandbox("c1")
        self.assertFalse(ok)
        self.assertIn("Error", said)

    # -- which profile am I in ----------------------------------------------

    def test_a_backend_with_a_trailing_comment_is_still_a_sandbox(self) -> None:
        for spelling in ('backend: "docker"', "backend: docker",
                         "backend: docker   # sealed by contrib/vpn-migrate",
                         "backend: 'docker'", "backend:  docker"):
            with self.subTest(spelling=spelling):
                path = Path(self._dir.name) / "profiles" / "lab" / "config.yaml"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"terminal:\n  {spelling}\n")
                netexits._docker = lambda *a, **k: ""
                self.assertEqual([n for n, _s, _d in netexits.sandbox_profiles()], ["lab"])

    def test_a_commented_out_backend_is_still_not_a_sandbox(self) -> None:
        path = Path(self._dir.name) / "profiles" / "lab" / "config.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('terminal:\n  backend: "local"\n  # backend: "docker"\n')
        netexits._docker = lambda *a, **k: ""
        self.assertEqual(netexits.sandbox_profiles(), [])

    def test_the_profile_is_the_same_through_an_indirect_path(self) -> None:
        """`…/profiles/lab/..` is the root, not a profile called '..'."""
        os.environ["HERMES_HOME"] = f"{self._dir.name}/profiles/lab/.."
        (Path(self._dir.name) / "profiles" / "lab").mkdir(parents=True, exist_ok=True)
        self.assertEqual(netexits.current_profile(), "default")
        os.environ["HERMES_HOME"] = f"{self._dir.name}/profiles/./lab"
        self.assertEqual(netexits.current_profile(), "lab")

    # -- the cache ----------------------------------------------------------

    def test_changing_the_exit_forgets_the_old_answer(self) -> None:
        self.write_exits({"name": "mx", "proxy": MX_PROXY, "country": "Mexico"})
        netexits._last_check = (MX_PROXY, 1e18, False)  # a stale "dead"
        self.seeing(ok=True, ip="201.0.0.5", country="MX", city="Mexico City")
        netexits.switch("mx")
        self.assertEqual(netexits._last_check[0], "")


#: Captured once: several tests point LOOKUP_URLS at a local server.
_ORIGINAL_URLS = netexits.LOOKUP_URLS


class RejectedEntries(_Sandbox):
    """A hand-written exit the plugin will not use has to say why."""

    def test_one_bad_entry_does_not_take_the_others_with_it(self) -> None:
        self.write_exits(
            {"name": "good", "proxy": MX_PROXY, "country": "Mexico"},
            {"name": "hostile", "proxy": "http://127.0.0.1:8891,--proxy-bypass-list=*"},
        )
        exits = netexits.load_file_exits()
        self.assertEqual([e.name for e in exits], ["good"])

    def test_and_doctor_explains_the_one_it_dropped(self) -> None:
        self.write_exits({"name": "hostile", "proxy": "http://x:1,--disable-web-security"})
        netexits._docker = lambda *a, **k: ""
        _ok, report = netexits.doctor()
        self.assertIn("was ignored — hostile:", report)
        self.assertIn("not a proxy address", report)


class OneRelayPerProfile(_Sandbox):
    """A bot's country is its own: changing it must not move another bot."""

    def setUp(self) -> None:
        super().setUp()
        os.environ[netexits.PROFILE_ENV] = "lab"
        self.addCleanup(lambda: os.environ.pop(netexits.PROFILE_ENV, None))
        self.write_exits({"name": "exit-jp", "proxy": JP_PROXY, "country": "Japan"})
        path = Path(self._dir.name) / "profiles" / "lab" / "config.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('terminal:\n  backend: "docker"\n')
        self.helper_calls: list[tuple] = []
        # `ps` answers in the shape sandbox_profiles asks for: the container
        # and the profile label Hermes puts on it.
        netexits._docker = lambda *a, **k: (
            "hermes-abc123\tlab" if a[0] == "ps"
            else ("hermes-vpn-lab " if a[0] == "inspect" else "true")
        )
        # No policy: it gets written. `ps` goes to _docker, which answers the
        # sandbox listing this profile needs to be seen as sandboxed.
        netexits._docker_try = lambda *a, **k: (
            (True, netexits._docker(*a)) if a[:1] == ("ps",) else (True, policy_reply(a))
        )
        netexits._run_helper = lambda *a: self.helper_calls.append(a) or "relay upstream for lab: exit-jp:8888"
        netexits.verify_sandbox = lambda c: (True, "OK 89.187.161.3 JP")
        self.addCleanup(lambda: setattr(netexits, "verify_sandbox", self._real_verify_sandbox))
        self.addCleanup(lambda: setattr(netexits, "_run_helper", self._real_helper))
        self.addCleanup(lambda: setattr(netexits, "_docker_try", self._real_try))

    _real_verify_sandbox = staticmethod(netexits.verify_sandbox)
    _real_helper = staticmethod(netexits._run_helper)
    _real_try = staticmethod(netexits._docker_try)

    def test_the_switch_names_the_profile_whose_relay_moves(self) -> None:
        netexits.switch("exit-jp")
        self.assertEqual(self.helper_calls, [("country", "exit-jp", "lab")])


class WhereDoesNotOverclaim(_Sandbox):
    """`net_where` may only describe the topology it actually inspected."""

    def setUp(self) -> None:
        super().setUp()
        os.environ[netexits.PROFILE_ENV] = "lab"
        self.addCleanup(lambda: os.environ.pop(netexits.PROFILE_ENV, None))
        path = Path(self._dir.name) / "profiles" / "lab" / "config.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('terminal:\n  backend: "docker"\n')
        self._real_verify = netexits.verify_sandbox
        netexits.verify_sandbox = lambda c: (True, "OK 1.2.3.4 JP")
        self.addCleanup(lambda: setattr(netexits, "verify_sandbox", self._real_verify))
        # On an exit, which is what these describe. With none chosen and the
        # kill switch down, the sandbox is off the tunnel and `where` says
        # that instead of describing a tunnel it is not using.
        netexits._write_state(chosen={"name": "exit-jp", "proxy": JP_PROXY, "country": "Japan"})

    def _networks(self, *names: str, internal: str = "true") -> None:
        netexits._docker = lambda *a, **k: (
            "hermes-abc123\tlab" if a[0] == "ps"
            else (" ".join(names) + " " if a[0] == "inspect" else internal)
        )

    def test_a_sealed_sandbox_is_described_as_sealed(self) -> None:
        self._networks("hermes-vpn-lab")
        self.assertIn("no way to the internet except the tunnel", netexits.describe_here())

    def test_a_sandbox_on_the_bridge_is_not_called_sealed(self) -> None:
        """An open sandbox must not be described as having only the tunnel."""
        self._networks("bridge", internal="false")
        answer = netexits.describe_here()
        self.assertNotIn("except the tunnel", answer)
        self.assertIn("can also reach the internet directly", answer)


class SocksIsAskedThroughCurl(_Sandbox):
    """A SOCKS proxy: the README offers it, and curl is how it gets checked.

    urllib cannot: it would send an HTTP CONNECT and no SOCKS server answers
    that. curl speaks SOCKS, so the exit is measured like any other instead of
    being refused for what this plugin could not do.
    """

    SOCKS = "socks5://127.0.0.1:1080"

    def curl_says(self, body: str = '{"ip": "201.0.113.9"}', code: int = 0) -> list:
        """Stand in for curl, and keep the argv it was called with."""
        seen: list = []

        def fake(command, **kwargs):
            seen.append(command)
            return types.SimpleNamespace(returncode=code, stdout=body, stderr="")

        netexits.subprocess.run = fake
        return seen

    def no_curl(self) -> None:
        real = netexits.shutil.which
        netexits.shutil.which = lambda name: None if name == "curl" else real(name)
        self.addCleanup(lambda: setattr(netexits.shutil, "which", real))

    def test_it_is_verified_through_curl(self) -> None:
        self.curl_says()
        seen = netexits.look(self.SOCKS)
        self.assertTrue(seen.ok)
        self.assertEqual(seen.ip, "201.0.113.9")

    def test_curl_is_told_to_resolve_at_the_far_end(self) -> None:
        """`socks5` would look the name up here: the DNS leaks past the tunnel
        and `.onion` never resolves, because no ordinary resolver knows it."""
        seen = self.curl_says()
        netexits.look(self.SOCKS)
        self.assertIn("socks5h://127.0.0.1:1080", seen[0])
        self.assertNotIn(self.SOCKS, seen[0])

    def test_curl_is_told_not_to_read_anybody_rc_file(self) -> None:
        """`-q`, and first. Without it curl reads ~/.curlrc, where one
        `insecure` line removes the TLS verification that is the only reason
        a hostile exit cannot choose the address this plugin reports, and one
        `url =` line appends a second transfer whose `ip=` wins the parse.
        `vpn-migrate` writes to that file, so it is an input, not a
        preference."""
        seen = self.curl_says()
        netexits.look(self.SOCKS)
        self.assertEqual(seen[0][:2], ["curl", "-q"])

    def test_the_address_the_user_wrote_is_not_rewritten(self) -> None:
        """Only curl's argument changes. The browser keeps what it was given."""
        self.curl_says()
        self.assertEqual(netexits.check_proxy(self.SOCKS), self.SOCKS)

    def test_urllib_is_not_spent_on_a_proxy_that_cannot_answer_it(self) -> None:
        self.curl_says()
        tried: list = []
        real_opener = netexits._opener
        # Recorded, not raised: `_fetch` catches everything around the urllib
        # attempt, so an exception here would be swallowed and the test would
        # pass over the very thing it is checking.
        netexits._opener = lambda: tried.append(1) or real_opener()
        self.addCleanup(lambda: setattr(netexits, "_opener", real_opener))
        self.assertTrue(netexits.look(self.SOCKS).ok)
        self.assertEqual(tried, [], "urllib was spent on a proxy that cannot answer it")

    def test_a_dead_socks_exit_reads_as_no_answer_not_as_unaskable(self) -> None:
        """Which is what lets the kill switch judge it like any other exit."""
        self.curl_says(body="", code=7)
        seen = netexits.look(self.SOCKS)
        self.assertFalse(seen.ok)
        self.assertFalse(seen.unverifiable)
        self.assertIn("curl:", seen.detail)

    def test_the_switch_uses_it_once_it_can_be_confirmed(self) -> None:
        self.curl_says()
        self.write_exits({"name": "home", "proxy": self.SOCKS, "country": "Uruguay"})
        said = netexits.switch("home")
        self.assertIn("201.0.113.9", said)
        self.assertEqual(netexits.current_proxy(), self.SOCKS)

    def test_without_curl_it_says_which_side_cannot_do_it(self) -> None:
        self.no_curl()
        seen = netexits.look(self.SOCKS)
        self.assertFalse(seen.ok)
        self.assertTrue(seen.unverifiable)
        self.assertIn("cannot be verified without curl", seen.detail)
        self.assertNotIn("did not answer", seen.detail)

    def test_and_then_the_switch_refuses_rather_than_guessing(self) -> None:
        self.no_curl()
        self.write_exits({"name": "home", "proxy": self.SOCKS, "country": "Uruguay"})
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.switch("home")
        self.assertIn("cannot be checked", str(caught.exception))


class AWorkingTunnelThePluginCannotSee(_Sandbox):
    """The state a reader who followed a provider guide exactly ends up in."""

    def _ps(self, *lines: str, ok: bool = True) -> None:
        netexits._docker_try = lambda *a, **k: (ok, "\n".join(lines))
        netexits._docker = lambda *a, **k: ("\n".join(lines) if ok else "")
        self.addCleanup(lambda: setattr(netexits, "_docker_try", self._real_try))

    _real_try = staticmethod(netexits._docker_try)

    def test_a_gluetun_with_no_published_proxy_is_named_not_ignored(self) -> None:
        self._ps("mx\tqmcgaw/gluetun:latest\t")
        netexits.discover_containers = self._real_discover  # the real one, against the stub
        self.assertEqual(netexits.discover_containers(), [])
        _ok, report = netexits.doctor()
        self.assertIn("mx is running but publishes no HTTP proxy", report)
        self.assertIn("HTTPPROXY: on", report)
        self.assertIn("publishes no ports", report)

    def test_a_proxy_published_to_the_world_is_named_too(self) -> None:
        self._ps("mx\tqmcgaw/gluetun:latest\t0.0.0.0:8891->8888/tcp")
        netexits.discover_containers = self._real_discover
        self.assertEqual(netexits.discover_containers(), [])
        _ok, report = netexits.doctor()
        self.assertIn("it publishes 0.0.0.0:8891->8888/tcp", report)

    def test_a_docker_that_could_not_be_asked_is_not_an_empty_host(self) -> None:
        """"No exits yet" sent the reader to start what was already running."""
        self._ps("", ok=False)
        netexits.discover_containers = self._real_discover
        self.assertEqual(netexits.discover_containers(), [])
        _ok, report = netexits.doctor()
        self.assertIn("docker could not be asked", report)
        self.assertIn("docker group", report)




class WhatTheVerifierIsAllowedToSay(unittest.TestCase):
    """How a confirmed sandbox sighting is read, and what must not reject one.

    Strict where it decides, lenient where it labels. The decision is that
    some token is a routable address; the rest of the line is a label.
    """

    def test_an_ordinary_country(self) -> None:
        self.assertEqual(netexits.read_sighting("OK 201.0.0.5 MX"), ("201.0.0.5", "MX", ""))

    def test_a_tor_exit(self) -> None:
        """`T1` is Cloudflare's code for one, and it has a digit in it.

        Requiring two letters turned every confirmed sighting through Tor
        into "not a measurement", so a sandbox demonstrably out through Tor
        was reported as unverified and put back on its old exit.
        """
        ip, label, problem = netexits.read_sighting("OK 109.70.100.14 T1")
        self.assertEqual((ip, label), ("109.70.100.14", "T1"))
        self.assertEqual(problem, "")

    def test_a_label_it_has_never_seen_before(self) -> None:
        """A verifier that one day prints more alongside keeps working."""
        ip, label, problem = netexits.read_sighting("OK 109.70.100.14 T1 42ms lab")
        self.assertEqual(ip, "109.70.100.14")
        self.assertEqual(problem, "")
        self.assertIn("42ms", label)

    def test_an_ipv6_address(self) -> None:
        ip, _label, problem = netexits.read_sighting("OK 2606:4700:4700::1111 US")
        self.assertEqual(ip, "2606:4700:4700::1111")
        self.assertEqual(problem, "")

    def test_ok_without_a_routable_address_is_not_a_measurement(self) -> None:
        for said in ("OK unknown MX", "OK 127.0.0.1 MX", "OK 10.0.0.4 MX"):
            _ip, _label, problem = netexits.read_sighting(said)
            self.assertIn("not a routable address", problem, said)

    def test_anything_that_is_not_an_ok_line(self) -> None:
        for said in ("FAIL 201.0.0.5 MX", "", "   ", "the exit is fine, trust me",
                     "OK", "OK\n\n\n1.2.3.4 JP"):
            _ip, _label, problem = netexits.read_sighting(said)
            self.assertIn("not a measurement", problem, said)

    def test_a_measurement_among_the_noise(self) -> None:
        """stderr is captured separately, but a stray line must not hide it."""
        ip, _label, problem = netexits.read_sighting("NOTE: something\nOK 201.0.0.5 MX\n")
        self.assertEqual(ip, "201.0.0.5")
        self.assertEqual(problem, "")


class TheCircuitIsConfirmedBeforeTheBrowserMoves(_Sandbox):
    """A cold onion takes a minute, and a browser sent there first just fails.

    So the circuit is established from here and the browser is held until
    something has actually come back through it. That is the difference
    between "Tor is selected" and "Tor is carrying this".
    """

    ONION = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
    TOR_PROXY = "http://127.0.0.1:8899"

    def setUp(self) -> None:
        super().setUp()
        netexits._warm_onions.clear()
        self.addCleanup(netexits._warm_onions.clear)
        self.tor = netexits.Exit(
            name="exit-tor", proxy=self.TOR_PROXY, country="Tor", source="labelled",
            container="exit-tor", provider="tor",
        )
        self.mx = netexits.Exit(
            name="exit-mx", proxy="http://127.0.0.1:8891", country="Mexico",
            source="gluetun", container="exit-mx", provider="surfshark",
        )
        netexits.discover_containers = lambda: [self.tor, self.mx]
        self.seeing(ok=True, ip="201.0.0.5", country="T1", city="")
        netexits._last_check = ("", 0.0, False)

    def bootstrapped(self, percent: int = 100) -> None:
        reply = (
            f"250 OK\n250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS={percent} "
            'TAG=done SUMMARY="Done"\n250 OK\n250 closing connection\n'
        )
        netexits._docker_try = lambda *a, **k: (True, reply)

    def answers(self, body: str = "<html>onion</html>", error: str = "") -> list:
        asked: list = []

        def fake(url, proxy, timeout=netexits.LOOKUP_TIMEOUT, single=False):
            asked.append((url, proxy, timeout, single))
            return (body, error)

        netexits._fetch = fake
        self.addCleanup(lambda: setattr(netexits, "_fetch", self._real_fetch))
        return asked

    _real_fetch = staticmethod(netexits._fetch)

    def test_it_waits_for_the_onion_with_a_timeout_a_rendezvous_can_use(self) -> None:
        self.bootstrapped()
        asked = self.answers()
        said = netexits.tor_connect(f"https://{self.ONION}/")
        self.assertEqual(asked[0][1], self.TOR_PROXY, "through Tor, not direct")
        self.assertGreaterEqual(asked[0][2], 60, "a cold onion took 56s on the real thing")
        self.assertTrue(asked[0][3], "one attempt, not two: each one is a minute of waiting")
        self.assertIn("the circuit is up", said)

    def test_a_browser_call_is_held_until_something_came_back(self) -> None:
        netexits.apply(self.tor)
        held = netexits.guard_browser("browser_navigate", {"url": f"https://{self.ONION}/"})
        self.assertIn("Held", held)
        self.assertIn("net_tor_connect", held)

    def test_and_let_through_once_it_has(self) -> None:
        netexits.apply(self.tor)
        self.bootstrapped()
        self.answers()
        netexits.tor_connect(f"https://{self.ONION}/")
        self.assertEqual(
            netexits.guard_browser("browser_navigate", {"url": f"https://{self.ONION}/page"}),
            "",
        )

    def test_an_onion_through_a_vpn_exit_is_held_with_the_real_reason(self) -> None:
        """It would not resolve at all, and the browser would blame the site."""
        netexits.apply(self.mx)
        held = netexits.guard_browser("browser_navigate", {"url": f"http://{self.ONION}/"})
        self.assertIn("not going through Tor", held)

    def test_the_hold_does_not_depend_on_the_kill_switch(self) -> None:
        """A cold rendezvous is not a security question, it is a doomed request."""
        netexits.apply(self.tor)
        self.assertFalse(netexits.locked())
        self.assertIn("Held", netexits.guard_browser("browser_navigate", {"url": self.ONION}))

    def test_nothing_is_claimed_when_the_onion_does_not_answer(self) -> None:
        self.bootstrapped()
        self.answers(body="", error="curl: (28) timed out")
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.tor_connect(f"https://{self.ONION}/")
        self.assertIn("did not answer", str(caught.exception))
        self.assertIn("Nothing was opened", str(caught.exception))
        self.assertIn(
            "Held",
            netexits.guard_browser("browser_navigate", {"url": self.ONION}),
            "a failed attempt does not count as warm",
        )

    def test_a_tor_that_is_still_starting_is_not_ready(self) -> None:
        self.bootstrapped(percent=45)
        self.answers()
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.tor_connect(f"https://{self.ONION}/")
        self.assertIn("45%", str(caught.exception))
        self.assertIn("nothing was opened", str(caught.exception))

    def test_without_a_url_it_only_promises_what_it_checked(self) -> None:
        self.bootstrapped()
        said = netexits.tor_connect()
        self.assertIn("bootstrapped", said)
        self.assertIn("can take a minute", said)

    def test_with_no_tor_exit_running_it_says_how_to_get_one(self) -> None:
        netexits.discover_containers = lambda: [self.mx]
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.tor_connect()
        self.assertIn("contrib/tor-exit", str(caught.exception))

    def test_an_ordinary_page_is_never_held(self) -> None:
        netexits.apply(self.tor)
        self.assertEqual(
            netexits.guard_browser("browser_navigate", {"url": "https://example.com/"}), ""
        )


class WhatTheAuditFoundInTheSmallerPlaces(_Sandbox):
    """Each of these is one tool argument, one docker row or one config
    file arriving somewhere it should not have been trusted."""

    def test_a_profile_name_that_is_an_option_is_refused(self) -> None:
        """`NET_EXITS_PROFILE=--city` made the helper consume it as an
        option, so the profile arrived empty and the *shared* relay moved
        while the caller was told its own had."""
        os.environ[netexits.PROFILE_ENV] = "--city"
        self.addCleanup(lambda: os.environ.pop(netexits.PROFILE_ENV, None))
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.current_profile()
        self.assertIn("is not a profile name", str(caught.exception))

    def test_a_derived_profile_that_is_an_option_is_not_trusted(self) -> None:
        """NET_EXITS_PROFILE is validated; so is the name derived from
        HERMES_HOME, which is just as settable. `.../profiles/--city` became
        the profile and the helper read it as a flag -- the same hole through
        a second door. An impostor name falls back to default rather than
        acting as a profile."""
        os.environ.pop(netexits.PROFILE_ENV, None)
        os.environ["HERMES_HOME"] = f"{self._dir.name}/profiles/--city"
        self.assertEqual(netexits.current_profile(), "default")
        os.environ["HERMES_HOME"] = f"{self._dir.name}/profiles/lab"
        self.assertEqual(netexits.current_profile(), "lab", "a real one is kept")

    def test_nothing_with_a_leading_dash_reaches_the_root_helper(self) -> None:
        with self.assertRaises(netexits.ExitError) as caught:
            netexits._run_helper("up", "-oProxyCommand=x")
        self.assertIn("root-owned helper", str(caught.exception))

    def test_an_unknown_option_is_refused_even_though_it_starts_with_dashes(self) -> None:
        """The guard waved through anything beginning with `--`, which is how
        a `--city` profile reached the helper. Only the options it actually
        takes pass now."""
        with self.assertRaises(netexits.ExitError) as caught:
            netexits._run_helper("up", "--not-a-real-flag")
        # The guard's own refusal, not a downstream sudo failure: with the old
        # `startswith("--")` the flag passed the guard and only sudo stopped it.
        self.assertIn("root-owned helper", str(caught.exception))
        self.assertEqual(netexits.HELPER_FLAGS, frozenset({"--city", "--provider"}))

    def test_an_accented_place_is_handed_to_the_helper_not_refused(self) -> None:
        """gluetun lists Zürich and São Paulo; the helper takes them under a
        UTF-8 locale. The ASCII-only guard refused them before it ever ran."""
        for place in ("Zürich", "São Paulo", "Kraków", "Montréal"):
            self.assertTrue(netexits.HELPER_ARG.match(place), place)

    def test_a_name_as_long_as_the_helper_mints_is_accepted(self) -> None:
        """`exit-` + a 31-char provider + `-` + a 41-char place is 78, and the
        64-char cap left such a tunnel openable but not closeable."""
        name = "exit-private-internet-access-saint-petersburg-and-leningrad-oblast"
        self.assertGreater(len(name), 64)
        self.assertTrue(netexits.HELPER_ARG.match(name))

    def test_a_forged_container_row_is_ignored(self) -> None:
        """A label value may carry a newline, and the listing is split on
        one: a crafted label forges a row whose name is its own choosing,
        and that name travels to the helper and into messages."""
        netexits.discover_containers = self._real_discover
        netexits._docker_try = lambda *a, **k: (
            True,
            ("real-one\tqmcgaw/gluetun:latest\t127.0.0.1:8891->8888/tcp\t\n"
             "--oops;rm\tqmcgaw/gluetun:latest\t127.0.0.1:8892->8888/tcp\t"),
        )
        netexits._docker = lambda *a, **k: "[]"
        found = [e.name for e in netexits.discover_containers()]
        self.assertEqual(found, ["real-one"])

    def test_a_provider_is_a_name_and_not_a_path(self) -> None:
        netexits.discover_containers = lambda: [
            netexits.Exit(name="exit-mx", proxy=MX_PROXY, country="Mexico",
                          source="gluetun", container="exit-mx", provider="surfshark")
        ]
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.catalogue("../../etc/foo")
        self.assertIn("is not a provider name", str(caught.exception))

    def test_a_rejected_proxy_does_not_print_its_credentials(self) -> None:
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.check_proxy("http://someone:hunter2@gw.example:8080")
        self.assertNotIn("hunter2", str(caught.exception))
        self.assertNotIn("someone", str(caught.exception))

    def test_a_proxy_with_a_trailing_newline_is_not_a_proxy(self) -> None:
        """`$` matches before one, and the value becomes a browser argument."""
        with self.assertRaises(netexits.ExitError):
            netexits.check_proxy("http://127.0.0.1:8891\n")

    def test_a_nested_browser_block_is_left_alone(self) -> None:
        """A `browser:` under `agent:` is not the key the setting goes in."""
        config = Path(self._dir.name) / "config.yaml"
        config.write_text("agent:\n  browser:\n    inactivity_timeout: 120\n")
        said = netexits._set_private_urls(True)
        after = config.read_text()
        self.assertIn("allow_private_urls: true", after, "a top-level block is appended")
        self.assertIn("agent:\n  browser:\n", after, "and the nested one is untouched")
        self.assertEqual(said, "")

    def test_a_flow_mapping_is_reported_instead_of_rewritten(self) -> None:
        config = Path(self._dir.name) / "config.yaml"
        config.write_text("browser: {headless: true}\n")
        said = netexits._set_private_urls(True)
        self.assertIn("not a plain block", said)
        self.assertEqual(config.read_text(), "browser: {headless: true}\n")


class TheGuardReadsTheHostTheWayChromeDoes(_Sandbox):
    """The substitute for Hermes' SSRF check, while Tor mode has it off.

    Every refusal here was measured to reach 127.0.0.1 in a real Chromium:
    the browser turns `\\` into `/`, reads what follows the last `@`,
    percent-decodes the host and folds it under NFKC, so a URL whose text
    names one host dials another. The guard now reads the host the same way,
    which is why these are an allow-list of destinations and not of spellings.
    """

    REACHES_LOOPBACK = [
        ("comma truncates the old regex", "http://example.com,@127.0.0.1/"),
        ("backslash in the authority", "http://127.0.0.1\\@example.com/"),
        ("trailing dot on a local name", "http://localhost./"),
        ("trailing dot on metadata", "http://metadata.google.internal./"),
        ("percent-encoded host", "http://%6c%6f%63%61%6c%68%6f%73%74/"),
        ("percent-encoded last octet", "http://127.0.0.%31/"),
        ("fullwidth digits", "http://１２７.0.0.1/"),
        ("ideographic full stops", "http://127。0。0。1/"),
    ]

    DISGUISED_IPS = ["http://127.1/", "http://2130706433/",
                     "http://0x7f000001/", "http://0177.0.0.1/"]

    PRIVATE_RANGES = ["http://10.0.0.5/", "http://192.168.1.1/", "http://[fe80::1]/",
                      "http://100.64.0.1/", "http://169.254.169.254/", "http://[::1]/"]

    PUBLIC = ["https://example.com/", "https://sub.domain.co.uk/a?b=c",
              "http://8.8.8.8/", "http://[2606:4700::1111]/",
              "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/"]

    def test_the_measured_bypasses_are_all_refused(self) -> None:
        for name, url in self.REACHES_LOOPBACK:
            self.assertTrue(netexits._private_destination(url), name)

    def test_an_address_in_a_shape_only_the_browser_reads_is_refused(self) -> None:
        for url in self.DISGUISED_IPS:
            self.assertTrue(netexits._private_destination(url), url)

    def test_private_and_internal_ranges_are_refused(self) -> None:
        for url in self.PRIVATE_RANGES:
            self.assertTrue(netexits._private_destination(url), url)

    def test_a_public_destination_is_allowed(self) -> None:
        for url in self.PUBLIC:
            self.assertEqual(netexits._private_destination(url), "", url)

    def test_a_public_ipv6_literal_is_allowed(self) -> None:
        """It was refused before: the regex dropped the closing bracket and
        the URL would not parse, so every IPv6 site read as unparseable."""
        self.assertEqual(netexits._private_destination("http://[2606:4700::1111]/"), "")

    def test_a_percent_encoded_public_host_is_decoded_and_allowed(self) -> None:
        """Not refused for carrying a `%`: the host is read as Chrome reads
        it, so a decoded public name passes and a decoded local one does not.
        This is what tells canonicalisation apart from a blanket refusal of
        anything unusual."""
        self.assertEqual(
            netexits._private_destination("http://%65%78%61%6d%70%6c%65.com/"), "")
        self.assertTrue(
            netexits._private_destination("http://%6c%6f%63%61%6c%68%6f%73%74/"))

    def test_a_benign_url_in_front_does_not_hide_the_real_one(self) -> None:
        both = 'first https://example.com/ then http://127.0.0.1/admin'
        self.assertIn("127.0.0.1", netexits._private_destination(both))

    def test_the_host_is_judged_inside_a_stringified_dict(self) -> None:
        """What the middleware actually hands it is a dict, not a bare URL."""
        self.assertTrue(netexits._private_destination({"url": "http://example.com,@127.0.0.1/"}))
        self.assertEqual(netexits._private_destination({"url": "https://example.com/"}), "")

    def test_nothing_that_is_not_a_url_is_a_destination(self) -> None:
        self.assertEqual(netexits._private_destination("open the file please"), "")
        self.assertEqual(netexits._private_destination(None), "")


class TheGuardRunsWheneverHermesCheckIsOff(_Sandbox):
    """It is not enough to run while the state says Tor mode is on.

    The mode turns Hermes' refusal off by writing a marked line into the
    config. Three paths leave that line while the state reads off: a sandbox
    `net_use`, a `close_exit`, a state write that drops the key. In each,
    Hermes is not refusing and nor would this if it keyed on the state alone.
    """

    def with_the_marker_but_the_mode_off(self) -> None:
        Path(self._dir.name, "config.yaml").write_text(
            f"browser:\n  {netexits.PRIVATE_URLS_MARK}\n  allow_private_urls: true\n"
        )
        netexits._write_state(tor_mode={"on": False}, locked=True,
                              chosen={"name": "x", "proxy": "http://127.0.0.1:8891"})
        os.environ[netexits.BROWSER_ARGS_ENV] = "--proxy-server=http://127.0.0.1:8891"
        netexits.look = lambda proxy="": netexits.Sighting(
            ok=True, ip="1.2.3.4", country="US", city="", detail="")
        netexits._last_check = ("", 0.0, False)

    def test_an_internal_address_is_held_in_that_window(self) -> None:
        self.with_the_marker_but_the_mode_off()
        self.assertFalse(netexits.tor_mode(), "the state says off")
        self.assertTrue(netexits.guard_browser("browser_navigate", {"url": "http://127.0.0.1/"}))

    def test_a_public_one_is_not(self) -> None:
        self.with_the_marker_but_the_mode_off()
        self.assertEqual(netexits.guard_browser("browser_navigate",
                                                {"url": "https://example.com/"}), "")

    def test_a_setting_with_no_marker_does_not_turn_the_guard_on(self) -> None:
        """Without the marker the line is the profile owner's, not ours, and
        Hermes' own check is the one in force -- this does not second-guess it."""
        Path(self._dir.name, "config.yaml").write_text(
            "browser:\n  allow_private_urls: true\n")
        netexits._write_state(tor_mode={"on": False}, locked=False)
        self.assertEqual(netexits.guard_browser("browser_navigate",
                                                {"url": "http://127.0.0.1/"}), "")


class TheConfigSurgeryIsOnSomeoneElsesFile(_Sandbox):
    """Entering Tor mode edits a file this plugin did not write.

    So every shape here is one a real config.yaml can have, and the test is
    whether the file still means what it meant. Nothing imports a YAML
    parser: the suite has no dependencies, and the thing that decides
    whether it parses is the indent, which is checked directly.
    """

    def config(self, body: str) -> Path:
        path = Path(self._dir.name) / "config.yaml"
        with path.open("w", newline="") as handle:
            handle.write(body)
        return path

    def indent_of(self, line: str) -> str:
        return line[:len(line) - len(line.lstrip())]

    def test_a_four_space_block_is_written_at_four_spaces(self) -> None:
        """Two spaces into a four-space block is a line less indented than
        its siblings, and the file stops parsing from there on."""
        path = self.config("browser:\n    headless: true\n")
        self.assertEqual(netexits._set_private_urls(True), "")
        lines = path.read_text().split("\n")
        ours = next(line for line in lines if "allow_private_urls" in line)
        sibling = next(line for line in lines if "headless" in line)
        self.assertEqual(self.indent_of(ours), self.indent_of(sibling))
        self.assertEqual(self.indent_of(ours), "    ")

    def test_a_tab_indented_block_keeps_its_tabs(self) -> None:
        path = self.config("browser:\n\theadless: true\n")
        netexits._set_private_urls(True)
        ours = next(l for l in path.read_text().split("\n") if "allow_private_urls" in l)
        self.assertEqual(self.indent_of(ours), "\t")

    def test_a_comment_after_the_key_is_still_a_block(self) -> None:
        """It was read as a shape this could not edit, so the mode came up
        with the setting never written and said nothing was wrong."""
        path = self.config("browser:  # the bot's own browser\n  headless: true\n")
        self.assertEqual(netexits._set_private_urls(True), "")
        self.assertIn("allow_private_urls: true", path.read_text())

    def test_crlf_line_endings_survive(self) -> None:
        path = self.config("browser:\r\n  headless: true\r\n")
        netexits._set_private_urls(True)
        with path.open(newline="") as handle:
            after = handle.read()
        self.assertIn("allow_private_urls: true\r\n", after)
        self.assertEqual(after.count("\r\n"), after.count("\n"), "no ending was left bare")

    def test_a_line_separator_inside_a_scalar_is_not_a_line(self) -> None:
        """`splitlines()` breaks on U+2028 and the value came back changed."""
        path = self.config('browser:\n  note: "a b"\n')
        netexits._set_private_urls(True)
        self.assertIn('"a b"', path.read_text())

    def test_two_browser_keys_are_refused_rather_than_half_edited(self) -> None:
        """YAML keeps the last, so writing into the first sets nothing."""
        body = "browser:\n  headless: true\nmodel: x\nbrowser:\n  other: 1\n"
        path = self.config(body)
        said = netexits._set_private_urls(True)
        self.assertIn("opens `browser:` 2 times", said)
        self.assertEqual(path.read_text(), body, "and it did not touch the file")

    def test_the_backup_is_never_wider_than_the_original(self) -> None:
        path = self.config("browser:\n  headless: true\n")
        path.chmod(0o600)
        netexits._set_private_urls(True)
        backups = list(Path(self._dir.name).glob("config.yaml.bak-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)

    def test_our_pair_goes_out_again_without_a_word(self) -> None:
        path = self.config("browser:\n  headless: true\n")
        netexits._set_private_urls(True)
        self.assertEqual(netexits._set_private_urls(False), "")
        self.assertFalse(netexits.private_urls_allowed())
        self.assertIn("headless: true", path.read_text())

    def test_a_config_with_no_browser_key_gets_it_back_unchanged(self) -> None:
        """The key is appended when there is none, and an empty one left
        behind reads as None, which breaks a lookup of `browser.anything`."""
        path = self.config("model: opus\n")
        netexits._set_private_urls(True)
        self.assertIn("browser:", path.read_text())
        netexits._set_private_urls(False)
        self.assertEqual(path.read_text(), "model: opus\n")

    def test_a_browser_block_that_was_already_there_stays(self) -> None:
        path = self.config("browser:\n  headless: true\n")
        netexits._set_private_urls(True)
        netexits._set_private_urls(False)
        self.assertEqual(path.read_text(), "browser:\n  headless: true\n")

    def test_a_reformatted_value_under_our_marker_is_still_ours(self) -> None:
        self.config(f"browser:\n  {netexits.PRIVATE_URLS_MARK}\n  allow_private_urls: True\n")
        self.assertEqual(netexits._set_private_urls(False), "")
        self.assertFalse(netexits.private_urls_allowed())

    def test_a_setting_that_outlived_its_marker_is_reported_not_passed_over(self) -> None:
        """Any program that round-trips this YAML drops the comment. Keying
        the removal on it meant the setting stayed on, `tor --off` reported
        success, and `doctor` could no longer see it either."""
        path = self.config("browser:\n  allow_private_urls: true\n")
        said = netexits._set_private_urls(False)
        self.assertIn("still says", said)
        self.assertIn("allow_private_urls", said)
        self.assertTrue(netexits.private_urls_allowed(), "and it is still on, truthfully")
        self.assertEqual(path.read_text(), "browser:\n  allow_private_urls: true\n")

    def test_a_setting_someone_made_themselves_is_left_where_it_is(self) -> None:
        path = self.config("browser:\n  allow_private_urls: yes\n")
        said = netexits._set_private_urls(False)
        self.assertIn("left alone", said)
        self.assertEqual(path.read_text(), "browser:\n  allow_private_urls: yes\n")

    def test_the_setting_turned_off_on_purpose_is_not_a_finding(self) -> None:
        self.config("browser:\n  allow_private_urls: false\n")
        self.assertEqual(netexits._set_private_urls(False), "")
        self.assertFalse(netexits.private_urls_allowed())

    def test_doctor_names_the_setting_whoever_wrote_it(self) -> None:
        """The risk is that Hermes is not refusing internal addresses, and
        that is true either way. Who wrote the line decides the advice."""
        self.config("browser:\n  allow_private_urls: true\n")
        _ok, report = netexits.doctor()
        self.assertIn("take it out by hand", report)
        self.config(f"browser:\n  {netexits.PRIVATE_URLS_MARK}\n  allow_private_urls: true\n")
        _ok, report = netexits.doctor()
        self.assertIn("hermes vpn tor --off", report)

    def test_leaving_the_mode_does_not_touch_a_config_with_nothing_of_ours(self) -> None:
        """`net_use direct` calls it unconditionally, and clearing someone's
        cookies over a setting they made themselves is not its business."""
        self.config("browser:\n  allow_private_urls: true\n")
        self.assertEqual(netexits.leave_tor_mode(), [])


class WhatWhereSaysAboutProtection(_Sandbox):
    """`where` is the cheapest and most asked question, so it has to carry
    the two facts a person is really asking about."""

    def test_it_reports_the_kill_switch_both_ways(self) -> None:
        """Silence when disarmed cannot be told from "this tool does not say",
        and a model reading it either keeps quiet or guesses."""
        self.write_exits({"name": "mx", "proxy": MX_PROXY, "country": "Mexico"})
        self.seeing(ok=True, ip="201.0.0.5", country="MX", city="Mexico City")
        netexits.switch("mx")
        self.assertIn("kill switch is disarmed", netexits.describe_here())
        netexits.set_locked(True)
        self.assertIn("kill switch is armed", netexits.describe_here())

    def test_the_sandbox_answer_carries_the_same_two_clauses(self) -> None:
        """Three times in one day a sentence went into the host branch and
        the profiles that browse from containers never saw it. Both paths
        read the same function now, and this is what holds them together."""
        netexits.in_sandbox = lambda: "hermes-box"
        self.addCleanup(lambda: setattr(netexits, "in_sandbox", self._real_in_sandbox))
        netexits.verify_sandbox = lambda c: (True, "OK 185.220.101.4 T1")
        self.addCleanup(lambda: setattr(netexits, "verify_sandbox", self._real_verify))
        netexits.discover_containers = lambda: [
            netexits.Exit(name="exit-tor", proxy="http://127.0.0.1:8899", country="Tor",
                          source="labelled", container="exit-tor", provider="tor")
        ]
        netexits._write_state(chosen={"name": "exit-tor", "proxy": "http://127.0.0.1:8899"})
        netexits.set_locked(True)
        said = netexits.describe_here()
        self.assertIn("kill switch is armed", said)
        self.assertIn("rotates circuits on its own", said)

    _real_in_sandbox = staticmethod(netexits.in_sandbox)
    _real_verify = staticmethod(netexits.verify_sandbox)

    def test_on_tor_it_says_the_address_moves_on_its_own(self) -> None:
        """Otherwise a bot reports Tor rotating a circuit as a change."""
        netexits.discover_containers = lambda: [
            netexits.Exit(name="exit-tor", proxy="http://127.0.0.1:8899", country="Tor",
                          source="labelled", container="exit-tor", provider="tor")
        ]
        self.seeing(ok=True, ip="185.220.101.4", country="T1", city="")
        netexits.switch("exit-tor")
        said = netexits.describe_here()
        self.assertIn("rotates circuits on its own", said)
        self.assertIn("T1", said)

    def test_and_an_ordinary_exit_is_not_given_that_speech(self) -> None:
        self.write_exits({"name": "mx", "proxy": MX_PROXY, "country": "Mexico"})
        self.seeing(ok=True, ip="201.0.0.5", country="MX", city="Mexico City")
        netexits.switch("mx")
        self.assertNotIn("rotates circuits", netexits.describe_here())


class TheOnionHoldKnowsWhatItIsHolding(_Sandbox):
    """"Nothing has reached it yet" was said to people who had been reading
    that page for ten minutes: the warm entry had expired, not never existed."""

    ONION = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"

    def setUp(self) -> None:
        super().setUp()
        netexits._warm_onions.clear()
        self.addCleanup(netexits._warm_onions.clear)
        netexits.discover_containers = lambda: [
            netexits.Exit(name="exit-tor", proxy="http://127.0.0.1:8899", country="Tor",
                          source="labelled", container="exit-tor", provider="tor")
        ]
        self.seeing(ok=True, ip="185.220.101.4", country="T1", city="")
        netexits.switch("exit-tor")

    def test_an_expired_circuit_is_not_described_as_one_that_never_existed(self) -> None:
        netexits._warm_onions[self.ONION] = time.time() - netexits.ONION_WARM_SECONDS - 60
        held = netexits.guard_browser("browser_navigate", {"url": f"https://{self.ONION}/"})
        self.assertIn("last confirmed more than", held)
        self.assertNotIn("nothing has reached", held)

    def test_and_a_page_in_use_keeps_its_circuit_warm(self) -> None:
        """The browser using it is better evidence than the last check."""
        netexits._warm_onions[self.ONION] = time.time() - 300
        netexits.guard_browser("browser_navigate", {"url": f"https://{self.ONION}/"})
        self.assertGreater(netexits._warm_onions[self.ONION], time.time() - 5)


class ClosingAnExitAnotherBotIsOn(_Sandbox):
    """Per-profile relays stop one bot's country change from moving another.
    Closing was the hole in that: it checked only this process's browser."""

    def setUp(self) -> None:
        super().setUp()
        os.environ[netexits.PROFILE_ENV] = "lab"
        self.addCleanup(lambda: os.environ.pop(netexits.PROFILE_ENV, None))
        netexits._run_helper = lambda *a: "closed"
        self.addCleanup(lambda: setattr(netexits, "_run_helper", self._real_run_helper))
        helper = Path(self._dir.name) / "vpn-exit"
        helper.write_text("#!/bin/sh\nexit 0\n")
        helper.chmod(0o755)
        os.environ[netexits.HELPER_ENV] = str(helper)
        # `web` is out through exit-miami; this profile is not.
        netexits._docker = lambda *a, **k: (
            "hermes-def456\tweb" if a[0] == "ps"
            else ("exit-miami:8888" if a[:2] == ("exec", "vpn-relay-web")
                  else ("hermes-vpn-web " if a[0] == "inspect" else "true"))
        )

    _real_run_helper = staticmethod(netexits._run_helper)

    def test_it_refuses_and_names_the_profile_losing_its_way_out(self) -> None:
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.close_exit("exit-miami")
        self.assertIn("'web'", str(caught.exception))
        self.assertIn("no other way out", str(caught.exception))

    def test_force_is_the_way_through_once_it_has_been_asked(self) -> None:
        said = netexits.close_exit("exit-miami", force=True)
        self.assertTrue(said)

    def test_an_exit_nobody_else_is_on_closes_without_ceremony(self) -> None:
        netexits.close_exit("exit-brazil")


class WhatListSaysIsInUse(_Sandbox):
    """In a sandbox, the host's proxy is not that browser's exit.

    A bot reported it: `list` said Tor while `where` and `doctor` said
    Mexico, with the sandbox demonstrably out through Mexico. The host value
    was left over from a switch an hour earlier and means nothing to a
    browser that reads a managed policy.
    """

    def setUp(self) -> None:
        super().setUp()
        self.tor = netexits.Exit(name="exit-tor", proxy="http://127.0.0.1:8899",
                                 country="Tor", source="labelled", container="exit-tor",
                                 provider="tor")
        self.mx = netexits.Exit(name="exit-mx", proxy=MX_PROXY, country="Mexico",
                                source="gluetun", container="exit-mx", provider="surfshark")
        netexits.discover_containers = lambda: [self.tor, self.mx]
        netexits.in_sandbox = lambda: "hermes-box"
        self.addCleanup(lambda: setattr(netexits, "in_sandbox", self._real_in_sandbox))

    _real_in_sandbox = staticmethod(netexits.in_sandbox)

    def test_it_names_the_exit_the_sandbox_was_put_on(self) -> None:
        netexits._write_state(chosen={"name": "exit-mx", "proxy": MX_PROXY})
        # As a host switch would have left it, pointing somewhere else.
        os.environ[netexits.BROWSER_ARGS_ENV] = netexits.browser_args("http://127.0.0.1:8899")
        listing = netexits.describe_exits()
        self.assertIn("exit-mx | Mexico | http://127.0.0.1:8891 | gluetun | surfshark <- in use",
                      listing)
        self.assertNotIn("exit-tor | Tor | http://127.0.0.1:8899 | labelled | tor <- in use",
                         listing)

    def test_and_says_so_when_nothing_has_been_chosen(self) -> None:
        netexits.set_locked(True)
        listing = netexits.describe_exits()
        self.assertIn("none chosen yet for the sandbox hermes-box", listing)
        self.assertIn("not browsing at all", listing)
        self.assertNotIn("<- in use", listing)
        self.assertNotIn("direct (no proxy)", listing)

    def test_and_that_an_empty_choice_is_a_choice_when_the_switch_is_down(self) -> None:
        """"Yet" said unconfigured. The sandbox is deliberately direct, and
        `where` three functions away already worded it correctly."""
        listing = netexits.describe_exits()
        self.assertIn("no exit chosen for the sandbox hermes-box", listing)
        self.assertIn("leaves by this host's own address", listing)
        self.assertNotIn("yet", listing)


class TheTorExitWithoutTheMode(_Sandbox):
    """Choosing the Tor exit by hand is not the same as using Tor.

    The README calls it theatre: the session that was there is still there,
    and a site that recognises it knows who it is talking to whatever
    address the request arrived from. A model reading `net_use`'s
    description will reach for it, and the plugin's own `new_circuit` error
    used to point at it.
    """

    def setUp(self) -> None:
        super().setUp()
        # Only the discovered one: a file entry of the same name has no
        # provider, and `resolve` would hand back the one that cannot be
        # told apart from any other proxy.
        netexits.discover_containers = lambda: [
            netexits.Exit(name="exit-tor", proxy="http://127.0.0.1:8899", country="Tor",
                          source="labelled", container="exit-tor", provider="tor"),
            netexits.Exit(name="exit-mx", proxy=MX_PROXY, country="Mexico",
                          source="gluetun", container="exit-mx", provider="surfshark"),
        ]
        self.seeing(ok=True, ip="185.220.101.4", country="T1", city="")

    def test_switching_to_it_says_what_is_missing(self) -> None:
        said = netexits.switch("exit-tor")
        self.assertIn("Tor mode is off", said)
        self.assertIn("net_tor_connect", said)

    def test_the_sandbox_path_says_it_too(self) -> None:
        """It was added to the host path and the bots never saw it — the
        asymmetry this plugin keeps re-learning."""
        netexits.in_sandbox = lambda: "hermes-box"
        netexits._run_helper = lambda *a: "relay upstream: exit-tor:8888"
        netexits.verify_sandbox = lambda c: (True, "OK 185.220.101.4 T1")
        self.addCleanup(lambda: setattr(netexits, "in_sandbox", self._real_in_sandbox))
        self.addCleanup(lambda: setattr(netexits, "_run_helper", self._real_run_helper))
        self.addCleanup(lambda: setattr(netexits, "verify_sandbox", self._real_verify_sandbox))
        said = netexits.switch("exit-tor")
        self.assertIn("Tor mode is off", said)

    _real_in_sandbox = staticmethod(netexits.in_sandbox)
    _real_run_helper = staticmethod(netexits._run_helper)
    _real_verify_sandbox = staticmethod(netexits.verify_sandbox)

    def test_and_says_nothing_of_the_sort_for_an_ordinary_exit(self) -> None:
        said = netexits.switch("exit-mx")
        self.assertNotIn("Tor mode", said)

    def test_the_circuit_tool_points_at_the_right_door(self) -> None:
        """It used to send people to `hermes vpn use tor`, which is the one
        that gives the exit without the mode."""
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.new_circuit()
        self.assertIn("net_tor_connect", str(caught.exception))
        self.assertNotIn("vpn use tor", str(caught.exception))


class TorModeIsADifferentBrowser(_Sandbox):
    """Entering Tor is a change of browser state, not only of exit.

    A Tor exit with the cookie jar of the ordinary session is theatre: the
    site that recognises the session knows who it is talking to whatever
    address the request came from. So the identity is cleared on the way in
    and on the way out, JavaScript goes off, and the one thing Tor mode
    loosens -- Hermes' refusal of names that do not resolve -- is taken over
    here while it lasts.
    """

    def setUp(self) -> None:
        super().setUp()
        self.tor = netexits.Exit(
            name="exit-tor", proxy="http://127.0.0.1:8899", country="Tor",
            source="labelled", container="exit-tor", provider="tor",
        )
        self.mx = netexits.Exit(
            name="exit-mx", proxy=MX_PROXY, country="Mexico", source="gluetun",
            container="exit-mx", provider="surfshark",
        )
        netexits.discover_containers = lambda: [self.tor, self.mx]
        self.seeing(ok=True, ip="201.0.0.5", country="T1", city="")
        self.execs: list[tuple] = []
        netexits._docker_try = lambda *a, **k: self.execs.append(a) or (True, "")
        self._real_fetch = netexits._fetch
        netexits._fetch = lambda url, proxy, timeout=6, single=False: ("<html></html>", "")
        self.addCleanup(lambda: setattr(netexits, "_fetch", self._real_fetch))
        self.config = Path(self._dir.name) / "config.yaml"
        self.config.write_text("browser:\n  inactivity_timeout: 120\n")

    def _in_sandbox(self, container: str = "hermes-box") -> None:
        netexits.in_sandbox = lambda: container
        netexits._run_helper = lambda *a: "relay upstream: exit-tor:8888"
        netexits.verify_sandbox = lambda c: (True, "OK 185.220.101.4 T1")
        self.addCleanup(lambda: setattr(netexits, "in_sandbox", self._real_in_sandbox))
        self.addCleanup(lambda: setattr(netexits, "_run_helper", self._real_run_helper))
        self.addCleanup(lambda: setattr(netexits, "verify_sandbox", self._real_verify_sandbox))

    _real_in_sandbox = staticmethod(netexits.in_sandbox)
    _real_run_helper = staticmethod(netexits._run_helper)
    _real_verify_sandbox = staticmethod(netexits.verify_sandbox)

    def test_the_cookies_go_before_the_exit_changes(self) -> None:
        """Cleared while still on the old exit: the first page Tor carries is
        the first page this profile has ever asked for."""
        self._in_sandbox()
        netexits.tor_connect()
        wiped = [a for a in self.execs if "set-aside" in " ".join(str(x) for x in a)]
        self.assertTrue(wiped, "the browser profile was not cleared")
        self.assertIn("pkill", " ".join(str(x) for x in wiped[0]), "and the browser not closed")
        self.assertNotIn("rm -rf", " ".join(str(x) for x in wiped[0]),
                         "set aside, not deleted: a root delete belongs in a file a human installs")

    def test_the_browser_is_closed_by_name_and_not_by_command_line(self) -> None:
        """`pkill -f chrome` matches the command line of the script running it.

        The script carries the word, so the shell killed itself (SIGTERM,
        exit 143) before moving anything, and the step reported a failure it
        had caused. A stub cannot see that: the argv is checked here.
        """
        self._in_sandbox()
        netexits.tor_connect()
        script = next(
            " ".join(str(x) for x in a) for a in self.execs if "set-aside" in str(a)
        )
        self.assertIn("pkill -x", script)
        self.assertNotIn("pkill -f", script)

    def test_it_does_not_set_aside_what_it_already_set_aside(self) -> None:
        """The glob matches the renamed one too, and the names nested."""
        self._in_sandbox()
        netexits.tor_connect()
        script = next(
            " ".join(str(x) for x in a) for a in self.execs if "set-aside" in str(a)
        )
        self.assertIn("*.set-aside-*) continue", script)

    def test_javascript_is_off_unless_it_was_asked_for(self) -> None:
        self.assertIn('"DefaultJavaScriptSetting":2', netexits.tor_policy_body())
        self.assertNotIn("DefaultJavaScriptSetting", netexits.tor_policy_body(javascript=True))

    def test_a_failed_switch_out_of_tor_leaves_the_mode_on(self) -> None:
        """Verify before leaving. The old order deleted the Tor profile and
        rewrote the arguments, then refused on a dead exit while the message
        said nothing had changed -- the browser de-isolated on the old exit."""
        netexits.apply(self.tor)
        netexits.tor_connect()
        self.assertTrue(netexits.tor_mode())
        self.seeing(ok=False, detail="down")  # exit-mx does not answer
        with self.assertRaises(netexits.ExitError):
            netexits.switch("exit-mx")
        self.assertTrue(netexits.tor_mode(), "a move that did not happen did not end the mode")
        live = os.environ[netexits.BROWSER_ARGS_ENV]
        self.assertIn(netexits.NO_JS_ARG, live, "and the isolation is still in place")

    def _patch(self, name: str, value) -> None:
        """Replace a module function and put the original back at tearDown.

        Without the restore a stub here leaks into the next class -- an
        all_exits returning one exit made a later failover test resolve the
        wrong name."""
        original = getattr(netexits, name)
        setattr(netexits, name, value)
        self.addCleanup(lambda: setattr(netexits, name, original))

    def test_moving_a_sandbox_to_clearnet_ends_the_mode(self) -> None:
        """switch_sandbox never ended Tor mode: the sandbox left by a clearnet
        VPN while the state said the mode was on and the config stayed loose."""
        self._in_sandbox()
        self._patch("sandbox_profiles", lambda: [])
        self._patch("heal_sandbox_policy", lambda c, expect_direct=False: "")
        self._patch("verify_sandbox", lambda c: (True, "OK 201.0.0.9 MX"))
        netexits.tor_connect()
        self.assertTrue(netexits.tor_mode())
        said = netexits.switch_sandbox("exit-mx", "hermes-box")
        self.assertFalse(netexits.tor_mode(), "the mode followed the sandbox to clearnet")
        self.assertNotIn(netexits.PRIVATE_URLS_MARK, self.config.read_text())
        self.assertIn("Tor mode ended", said)

    def test_tor_off_returns_to_the_exit_from_before_tor(self) -> None:
        """`tor --off` left the browser on the Tor exit with the mode gone.
        It now goes back to what was in use before -- `leave_tor_mode` only
        undoes the isolation, so the exit has to be restored on top of it."""
        netexits.switch("exit-mx")
        self.assertEqual((netexits.saved_choice() or {}).get("name"), "exit-mx")
        netexits.tor_connect()
        self.assertEqual((netexits.saved_choice() or {}).get("name"), "exit-tor")
        said = netexits.end_tor_mode()
        self.assertFalse(netexits.tor_mode())
        self.assertEqual((netexits.saved_choice() or {}).get("name"), "exit-mx",
                         "back on the exit from before Tor, not left on exit-tor")
        self.assertIn("exit-mx", said)

    def test_tor_off_when_it_was_not_on_says_so(self) -> None:
        self.assertEqual(netexits.end_tor_mode(), "Tor mode was not on.")

    def test_closing_the_tor_exit_ends_the_mode(self) -> None:
        """Otherwise the state says the mode is on over an exit that is gone,
        and doctor keeps asserting a cleared profile."""
        self._patch("helper", lambda: "/bin/true")
        self._patch("all_exits", lambda: [self.tor])
        self._patch("profiles_using", lambda name: [])
        self._patch("_run_helper", lambda *a: "removed exit-tor")
        netexits.apply(self.tor)
        netexits.tor_connect()
        netexits.set_locked(False)
        self.assertTrue(netexits.tor_mode())
        said = netexits.close_exit("exit-tor")
        self.assertFalse(netexits.tor_mode(), "the mode ended with the exit it ran on")
        self.assertNotIn(netexits.PRIVATE_URLS_MARK, self.config.read_text())
        self.assertIn("Tor mode ended first", said)

    def test_javascript_turns_on_in_place_and_keeps_the_session(self) -> None:
        """The reason the toggle exists: get past a 406 that needs scripting
        without re-entering the mode, which would set the session aside."""
        self._in_sandbox()
        netexits.tor_connect()
        self.assertFalse(bool(netexits.tor_mode().get("javascript")))
        self.execs.clear()
        said = netexits.tor_connect(javascript=True)
        self.assertTrue(netexits.tor_mode().get("javascript"), "the state did not change")
        joined = [" ".join(str(x) for x in a) for a in self.execs]
        self.assertTrue(any("pkill" in j for j in joined),
                        "the browser was not closed, so it would not read the new setting")
        self.assertFalse(any("set-aside" in j for j in joined),
                         "the session was set aside; the whole point is to keep it")
        self.assertIn("JavaScript is on", said)

    def test_javascript_turns_back_off_in_place(self) -> None:
        self._in_sandbox()
        netexits.tor_connect(javascript=True)
        self.assertTrue(netexits.tor_mode().get("javascript"))
        said = netexits.tor_connect(javascript=False)
        self.assertFalse(bool(netexits.tor_mode().get("javascript")), "it did not turn back off")
        self.assertIn("off", said)

    def test_a_bare_reconnect_does_not_disturb_the_setting(self) -> None:
        """A call that does not mention JavaScript leaves it as it was, rather
        than defaulting it off under someone who turned it on."""
        self._in_sandbox()
        netexits.tor_connect(javascript=True)
        netexits.tor_connect()
        self.assertTrue(netexits.tor_mode().get("javascript"), "a bare reconnect reset it")

    def test_changing_javascript_outside_tor_mode_is_refused(self) -> None:
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.set_tor_javascript(True)
        self.assertIn("Tor mode is not on", str(caught.exception))

    def test_asking_for_the_setting_it_already_has_changes_nothing(self) -> None:
        self._in_sandbox()
        netexits.tor_connect()
        self.execs.clear()
        said = netexits.set_tor_javascript(False)
        self.assertIn("already off", said)
        self.assertFalse(self.execs, "a no-op still closed the browser or rewrote the policy")

    def test_on_the_host_the_flag_reaches_the_browser_arguments(self) -> None:
        """Not only the state: the host browser reads JavaScript off the args."""
        netexits.tor_connect()
        self.assertIn(netexits.NO_JS_ARG, os.environ[netexits.BROWSER_ARGS_ENV])
        netexits.tor_connect(javascript=True)
        self.assertNotIn(netexits.NO_JS_ARG, os.environ[netexits.BROWSER_ARGS_ENV],
                         "JavaScript on, but the argument that turns it off is still there")

    def test_the_arguments_reach_the_browser_and_not_only_the_function(self) -> None:
        """A security audit found this: the host browser restarted on the
        ordinary profile with JavaScript on, through Tor, while the answer
        said the session had been set aside and scripting was off. The old
        test asserted on `browser_args(...)` -- the pure function, which was
        right -- and nothing delivered its output."""
        netexits.apply(self.tor)
        netexits.tor_connect()
        live = os.environ[netexits.BROWSER_ARGS_ENV]
        self.assertIn(f"--user-data-dir={netexits.TOR_PROFILE_DIR}", live)
        self.assertIn(netexits.NO_JS_ARG, live)

    def test_and_are_taken_back_out_when_the_mode_ends(self) -> None:
        netexits.apply(self.tor)
        netexits.tor_connect()
        netexits.leave_tor_mode()
        live = os.environ[netexits.BROWSER_ARGS_ENV]
        self.assertNotIn(netexits.TOR_PROFILE_DIR, live)
        self.assertNotIn(netexits.NO_JS_ARG, live)

    def test_the_mode_is_recorded_before_the_setting_it_accounts_for(self) -> None:
        """A crash between the two left Hermes' own refusal of internal
        addresses off with the mode reading off, so the substitute never ran
        either: both guards down, and the agent told nothing had happened."""
        order: list = []
        real_write, real_private = netexits._write_state, netexits._set_private_urls
        netexits._write_state = lambda **kw: order.append("state" if "tor_mode" in kw else "other") or real_write(**kw)
        netexits._set_private_urls = lambda on: order.append("config") or real_private(on)
        self.addCleanup(lambda: setattr(netexits, "_write_state", real_write))
        self.addCleanup(lambda: setattr(netexits, "_set_private_urls", real_private))
        netexits.enter_tor_mode()
        self.assertLess(order.index("state"), order.index("config"))

    def test_the_cure_doctor_prescribes_can_actually_clean_up(self) -> None:
        """`doctor` says to run `tor --off`; it returned immediately on the
        state alone, so the loosened setting was permanent."""
        netexits.tor_connect()
        netexits._write_state(tor_mode={"on": False})  # as a crash would leave it
        self.assertIn(netexits.PRIVATE_URLS_MARK, self.config.read_text())
        netexits.leave_tor_mode()
        self.assertNotIn(netexits.PRIVATE_URLS_MARK, self.config.read_text())

    def test_the_host_browser_gets_a_profile_of_its_own_and_no_script(self) -> None:
        netexits.tor_connect()
        args = netexits.browser_args("http://127.0.0.1:8899")
        self.assertIn(f"--user-data-dir={netexits.TOR_PROFILE_DIR}", args)
        self.assertIn(netexits.NO_JS_ARG, args)

    def test_the_profile_is_allowed_to_reach_a_name_that_does_not_resolve(self) -> None:
        netexits.tor_connect()
        written = self.config.read_text()
        self.assertIn("allow_private_urls: true", written)
        self.assertIn(netexits.PRIVATE_URLS_MARK, written)

    def test_and_this_plugin_refuses_the_internal_ones_meanwhile(self) -> None:
        """What Hermes stopped checking, this checks, for as long as it lasts."""
        netexits.tor_connect()
        for url in ("http://127.0.0.1:9222/json", "http://169.254.169.254/latest/meta-data/",
                    "http://10.0.0.5:8080/", "http://localhost:7681/",
                    "http://metadata.google.internal/"):
            held = netexits.guard_browser("browser_navigate", {"url": url})
            self.assertIn("Refused", held, url)

    def test_the_four_ways_around_the_first_version(self) -> None:
        """All four came from one tool argument, and all four were allowed:
        a benign URL in front of the real one, two addresses `ipaddress`
        will not read and Chrome will, and an IPv6 literal that raised out
        of the guard into the middleware's blanket except."""
        netexits.tor_connect()
        for argument, why in (
            ({"note": "https://example.com/x", "url": "http://127.0.0.1:9051/"},
             "a benign URL in front"),
            ({"url": "http://127.1/"}, "IPv4 shorthand"),
            ({"url": "http://2130706433/"}, "an integer address"),
            ({"url": "http://[::1]:80/"}, "an IPv6 literal"),
            ({"url": "http://100.64.0.1/"}, "carrier-grade NAT"),
        ):
            with self.subTest(why=why):
                self.assertIn(
                    "Refused", netexits.guard_browser("browser_navigate", argument), why
                )

    def test_an_ordinary_name_is_still_allowed(self) -> None:
        netexits.tor_connect()
        self.assertEqual(
            netexits.guard_browser("browser_navigate", {"url": "https://example.com/"}), ""
        )

    def test_the_url_it_is_given_has_to_be_one(self) -> None:
        """It becomes curl's last argument, and curl reads options anywhere."""
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.tor_connect("-K/tmp/evil")
        self.assertIn("not an http or https address", str(caught.exception))

    def test_but_not_the_onion_it_is_there_for(self) -> None:
        netexits.tor_connect("https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/")
        self.assertEqual(
            netexits.guard_browser(
                "browser_navigate",
                {"url": "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/"},
            ),
            "",
        )

    def test_leaving_clears_the_identity_again_and_puts_the_rest_back(self) -> None:
        self._in_sandbox()
        netexits.tor_connect()
        self.execs.clear()
        said = netexits.leave_tor_mode()
        self.assertTrue(any("set-aside" in " ".join(str(x) for x in a) for a in self.execs),
                        "what Tor saw stayed in the browser")
        self.assertNotIn("allow_private_urls: true", self.config.read_text())
        self.assertFalse(netexits.tor_mode())
        self.assertTrue(said)

    def test_switching_to_an_ordinary_exit_ends_the_mode(self) -> None:
        """Nobody has to remember to turn it off: the loosened setting cannot
        follow the browser onto a clearnet exit."""
        netexits.tor_connect()
        said = netexits.switch("exit-mx")
        self.assertIn("Tor mode ended", said)
        self.assertFalse(netexits.tor_mode())
        self.assertNotIn("allow_private_urls: true", self.config.read_text())

    def test_doctor_catches_a_setting_left_behind(self) -> None:
        netexits.tor_connect()
        netexits._write_state(tor_mode={"on": False})  # as a crash would leave it
        _ok, report = netexits.doctor()
        self.assertIn("still allows private URLs", report)


class AskingTorForAnotherNode(_Sandbox):
    """A new circuit is the one thing Tor has and no VPN exit does.

    What is measured matters more than what was signalled: Tor coalesces these
    within about ten seconds, so "the control port said 250 OK" and "you are
    coming out somewhere else now" are different claims.
    """

    TOR_PROXY = "http://127.0.0.1:8899"

    def setUp(self) -> None:
        super().setUp()
        self.tor = netexits.Exit(
            name="exit-tor", proxy=self.TOR_PROXY, country="Tor", source="labelled",
            container="exit-tor", provider="tor",
        )
        self.mx = netexits.Exit(
            name="exit-mx", proxy="http://127.0.0.1:8891", country="Mexico",
            source="gluetun", container="exit-mx", provider="surfshark",
        )
        netexits.discover_containers = lambda: [self.tor, self.mx]
        self.closed = []
        netexits.restart_browser = lambda grace=3.0: self.closed.append(1) or 1

    def seeing_in_turn(self, *ips: str) -> None:
        """A different answer each time, so before and after can differ."""
        answers = list(ips)

        def look(proxy=""):
            ip = answers.pop(0) if answers else ips[-1]
            return netexits.Sighting(ok=True, ip=ip, country="T1", city="")

        netexits.look = look

    def control_says(self, reply: str = "250 OK\n250 OK\n250 closing connection\n",
                     ran: bool = True) -> list:
        asked: list = []

        def fake(*args, **kwargs):
            asked.append(args)
            return ran, reply

        netexits._docker_try = fake
        return asked

    def test_it_signals_the_control_port_inside_the_container(self) -> None:
        asked = self.control_says()
        self.seeing_in_turn("198.51.100.4", "203.0.113.7")
        netexits.apply(self.tor)
        said = netexits.new_circuit()
        signal = next(a for a in asked if "SIGNAL NEWNYM" in " ".join(str(x) for x in a))
        self.assertIn("exec", signal)
        self.assertIn("exit-tor", signal)
        self.assertIn("was 198.51.100.4, now 203.0.113.7", said)

    def test_the_browser_is_closed_so_the_next_page_redials(self) -> None:
        """The signal only reaches streams opened after it."""
        self.control_says()
        self.seeing_in_turn("198.51.100.4", "203.0.113.7")
        netexits.apply(self.tor)
        netexits.new_circuit()
        self.assertEqual(self.closed, [1])

    def test_an_unchanged_address_is_reported_as_unchanged(self) -> None:
        """Tor coalesces these, so two asks in a row give one circuit."""
        self.control_says()
        self.seeing_in_turn("198.51.100.4", "198.51.100.4")
        netexits.apply(self.tor)
        said = netexits.new_circuit()
        self.assertIn("still 198.51.100.4", said)
        self.assertIn("coalesces", said)

    def test_with_nothing_named_it_asks_the_exit_this_profile_is_on(self) -> None:
        """A bot hit this: `net_new_circuit` went to the Mexican exit while
        the sandbox was out through Tor, because the host's stale proxy
        matched it first. In a sandbox that value is not the browser's."""
        netexits.in_sandbox = lambda: "hermes-box"
        self.addCleanup(lambda: setattr(netexits, "in_sandbox", self._real_in_sandbox))
        netexits.verify_sandbox = lambda c: (True, "OK 185.220.101.4 T1")
        self.addCleanup(lambda: setattr(netexits, "verify_sandbox", self._real_verify_sandbox))
        os.environ[netexits.BROWSER_ARGS_ENV] = netexits.browser_args(self.mx.proxy)
        netexits._write_state(chosen={"name": "exit-tor", "proxy": self.TOR_PROXY})
        self.control_says()
        said = netexits.new_circuit()
        self.assertIn("exit-tor", said)
        self.assertNotIn("not a Tor exit", said)

    def test_a_vpn_exit_has_no_circuit_to_change(self) -> None:
        self.control_says()
        netexits.apply(self.mx)
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.new_circuit("exit-mx")
        self.assertIn("not a Tor exit", str(caught.exception))
        self.assertIn("hermes vpn use", str(caught.exception))

    def test_a_refused_cookie_is_not_reported_as_a_new_circuit(self) -> None:
        self.control_says(reply="515 Authentication failed: Wrong length on authentication cookie.\n")
        self.seeing_in_turn("198.51.100.4")
        netexits.apply(self.tor)
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.new_circuit()
        self.assertIn("refused the cookie", str(caught.exception))

    def test_a_container_that_cannot_be_reached_says_so(self) -> None:
        self.control_says(reply="Error: No such container: exit-tor", ran=False)
        self.seeing_in_turn("198.51.100.4")
        netexits.apply(self.tor)
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.new_circuit()
        self.assertIn("control port", str(caught.exception))
        self.assertIn("contrib/tor-exit", str(caught.exception))

    def test_an_exit_from_the_file_is_not_ours_to_signal(self) -> None:
        listed = netexits.Exit(name="tor-elsewhere", proxy="http://127.0.0.1:9999",
                               provider="tor", source="file")
        netexits.discover_containers = lambda: [listed]
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.new_circuit("tor-elsewhere")
        self.assertIn("not this plugin's to reach", str(caught.exception))

    def test_a_signal_that_was_not_acknowledged_is_not_a_circuit(self) -> None:
        """One 250 is the authentication. The signal needs its own."""
        self.assertEqual(netexits._read_control_reply("250 OK\n250 OK\n"), "")
        self.assertIn("did not accept", netexits._read_control_reply("250 OK\n"))
        self.assertIn("said nothing", netexits._read_control_reply(""))
        self.assertIn("answered", netexits._read_control_reply("250 OK\n550 Unrecognized\n"))

    def test_in_a_sandbox_the_browser_is_closed_and_measured_from_inside(self) -> None:
        """Two halves of one promise. The signal reaches no stream already
        open, so the browser has to dial again; and the address reported has
        to be the sandbox's, not this process's. Both end at the same Tor
        daemon and only one of them is the browser's path."""
        netexits.in_sandbox = lambda: "hermes-box"
        self.addCleanup(lambda: setattr(netexits, "in_sandbox", self._real_in_sandbox))
        # Routable on purpose: a documentation range is not an address a far
        # end could have reported, and `_is_an_address` refuses it.
        seen = iter(["OK 185.220.101.4 T1", "OK 201.0.113.7 T1"])
        netexits.verify_sandbox = lambda c: (True, next(seen))
        self.addCleanup(lambda: setattr(netexits, "verify_sandbox", self._real_verify_sandbox))
        netexits.look = lambda proxy="": self.fail("the host's own way out was measured")
        asked = self.control_says()
        netexits._write_state(chosen={"name": "exit-tor", "proxy": self.TOR_PROXY})

        said = netexits.new_circuit()

        self.assertIn("was 185.220.101.4, now 201.0.113.7", said)
        self.assertIn("measured from inside that sandbox", said)
        self.assertIn("was closed", said)
        self.assertTrue(
            any("pkill" in " ".join(str(x) for x in a) for a in asked),
            "the browser inside the sandbox kept its old circuit",
        )
        self.assertEqual(self.closed, [], "and the host's browser is not the one to close")

    _real_in_sandbox = staticmethod(netexits.in_sandbox)
    _real_verify_sandbox = staticmethod(netexits.verify_sandbox)


class WhichProfilesAreSandboxes(_Sandbox):
    """Found by the label docker put on the container, not by reading YAML.

    The config says what someone meant; the container says what is running,
    and the two disagree often enough that the docstring of
    `sandbox_profiles` is about it. A profile missed here used to be taken
    for one running on the host, and then the browser this plugin measures is
    not the browser it moves.
    """

    def _docker_answers(self, listing: str, networks: str = "hermes-vpn-lab ",
                        internal: str = "true") -> None:
        netexits._docker = lambda *a, **k: (
            listing if a[0] == "ps"
            else (networks if a[0] == "inspect" else internal)
        )

    def _config(self, profile: str, body: str) -> None:
        path = Path(self._dir.name) / "profiles" / profile / "config.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)

    def test_the_listing_asks_docker_in_a_way_docker_accepts(self) -> None:
        """A stub cannot catch a template docker refuses, so check the argv.

        In `docker ps` the template's `.Labels` is the whole comma-joined
        string, so `index .Labels "k"` fails with "cannot index slice/array
        with type string": docker prints nothing, every sandbox looks idle,
        and the host path runs for a browser that lives in a container. The
        suite was green through all of it.
        """
        asked: list = []
        netexits._docker_try = lambda *a, **k: asked.append(a) or (True, "")
        netexits.sandbox_profiles()
        argv = " ".join(asked[0])
        self.assertIn('{{.Label "hermes-profile"}}', argv)
        self.assertNotIn("index .Labels", argv)

    def test_a_running_sandbox_is_found_by_its_label(self) -> None:
        self._docker_answers("hermes-abc123\tlab")
        self.assertEqual(netexits.sandbox_profiles(), [("lab", "sealed", "on hermes-vpn-lab (internal)")])

    def test_even_when_the_config_is_written_in_a_way_no_pattern_expected(self) -> None:
        """This is the whole point: the decision no longer reads the file."""
        self._config("lab", "terminal:\n  backend:\n    !!str docker\n")
        self._docker_answers("hermes-abc123\tlab")
        self.assertEqual(
            [name for name, _s, _d in netexits.sandbox_profiles()], ["lab"]
        )

    def test_a_container_without_the_label_is_not_a_sandbox(self) -> None:
        self._docker_answers("some-container\t")
        self.assertEqual(netexits.sandbox_profiles(), [])

    def test_a_configured_profile_with_nothing_running_is_still_reported(self) -> None:
        """`doctor` says "no sandbox running to check", which is worth keeping."""
        self._config("web", 'terminal:\n  backend: "docker"\n')
        self._docker_answers("")
        self.assertEqual(netexits.sandbox_profiles(), [("web", "idle", "no sandbox running")])

    def test_the_running_one_wins_over_the_idle_reading(self) -> None:
        self._config("lab", 'terminal:\n  backend: "docker"\n')
        self._docker_answers("hermes-abc123\tlab")
        states = {name: state for name, state, _d in netexits.sandbox_profiles()}
        self.assertEqual(states, {"lab": "sealed"})


class ExitsThatAreNotGluetun(_Sandbox):
    """A container becomes an exit by saying so, never by being there.

    gluetun is recognised by its image because it describes itself: country
    and provider live in its environment. Anything else -- the Tor exit in
    contrib, someone's own privoxy over WireGuard -- has to wear the label the
    helper already uses, so that a random container with a published port
    never turns into a way out.
    """

    TOR = "exit-tor\thermes-vpn/tor-exit:latest\t127.0.0.1:8899->8888/tcp\tmanaged-by=vpn-exit,exit-provider=tor,exit-country=Tor"
    RELAY = "vpn-relay-lab\tpython:3.12-alpine\t\t"

    def _ps(self, *lines: str) -> None:
        # Only the discovery listing, which asks for the image. The sandbox
        # listing asks for a label and must not be handed exits.
        netexits._docker_try = lambda *a, **k: (
            (True, "\n".join(lines)) if any("{{.Image}}" in arg for arg in a) else (True, "")
        )
        # `ps` is also how sandboxes are found, so it answers; an `inspect`
        # would mean a labelled exit was read for an environment it does not
        # have, which is the call this class is here to keep out.
        netexits._docker = lambda *a, **k: (
            "" if a[0] == "ps" else self.fail("a labelled exit was inspected")
        )
        netexits.discover_containers = self._real_discover

    def test_a_labelled_container_is_an_exit(self) -> None:
        self._ps(self.TOR)
        found = netexits.discover_containers()
        self.assertEqual([e.name for e in found], ["exit-tor"])
        self.assertEqual(found[0].proxy, "http://127.0.0.1:8899")
        self.assertEqual(found[0].source, "labelled")

    def test_an_unlabelled_container_is_not(self) -> None:
        """The relay publishes nothing and is nobody's exit, but say it out loud."""
        self._ps(self.RELAY, "web\tnginx:latest\t127.0.0.1:8080->80/tcp\t")
        self.assertEqual(netexits.discover_containers(), [])
        self.assertEqual(netexits._unusable_exits, [], "and it is not reported as broken")

    def test_the_labels_describe_it_for_a_reader(self) -> None:
        self._ps(self.TOR)
        found = netexits.discover_containers()[0]
        self.assertEqual(found.provider, "tor")
        self.assertEqual(found.country, "Tor")

    def test_a_labelled_exit_with_no_published_proxy_gets_advice_it_can_use(self) -> None:
        """The gluetun advice names settings a Tor container does not have."""
        self._ps("exit-tor\thermes-vpn/tor-exit:latest\t\tmanaged-by=vpn-exit")
        self.assertEqual(netexits.discover_containers(), [])
        _ok, report = netexits.doctor()
        self.assertIn("publish its proxy on loopback", report)
        self.assertNotIn("HTTPPROXY", report)


class FixesThatBrokeOtherThings(_Sandbox):
    """Each of these covers a guard that a later change could undo quietly."""

    def _sandbox(self) -> None:
        os.environ[netexits.PROFILE_ENV] = "lab"
        self.addCleanup(lambda: os.environ.pop(netexits.PROFILE_ENV, None))
        path = Path(self._dir.name) / "profiles" / "lab" / "config.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('terminal:\n  backend: "docker"\n')
        netexits._docker = lambda *a, **k: (
            "hermes-abc123\tlab" if a[0] == "ps" else ("hermes-vpn-lab " if a[0] == "inspect" else "true")
        )
        netexits._docker_try = lambda *a, **k: (
            (True, netexits._docker(*a)) if a[:1] == ("ps",) else (True, policy_reply(a))
        )
        netexits._run_helper = lambda *a: "relay upstream for lab: ok"
        self.addCleanup(lambda: setattr(netexits, "_run_helper", self._real_helper))

    _real_helper = staticmethod(netexits._run_helper)

    def test_a_sandbox_switch_records_which_exit_it_chose(self) -> None:
        """Without this the rollback had nothing to roll back to, and the
        profile's state kept naming whatever the host chose last."""
        self._sandbox()
        self.write_exits({"name": "exit-jp", "proxy": JP_PROXY, "country": "Japan"})
        netexits.verify_sandbox = lambda c: (True, "OK 1.2.3.4 JP")
        self.addCleanup(lambda: setattr(netexits, "verify_sandbox", self._real_verify))
        netexits.switch("exit-jp")
        self.assertEqual((netexits.saved_choice() or {}).get("name"), "exit-jp")

    _real_verify = staticmethod(netexits.verify_sandbox)

    def test_a_sandbox_switch_forgets_the_previous_verdict(self) -> None:
        self._sandbox()
        self.write_exits({"name": "exit-jp", "proxy": JP_PROXY, "country": "Japan"})
        netexits.verify_sandbox = lambda c: (True, "OK 1.2.3.4 JP")
        self.addCleanup(lambda: setattr(netexits, "verify_sandbox", self._real_verify))
        netexits._last_check = ("sandbox:hermes-abc123", 1e18, False)  # a stale refusal
        netexits.switch("exit-jp")
        self.assertEqual(netexits._last_check[0], "")

    def test_closing_the_exit_in_use_keeps_the_dead_end_when_armed(self) -> None:
        """apply(None) drops the WebRTC argument too, which is the one state
        the plugin calls browsing from here."""
        self.write_exits({"name": "mx", "proxy": MX_PROXY, "country": "Mexico"})
        self.seeing(ok=True, ip="201.0.0.5", country="MX", city="Mexico City")
        netexits.switch("mx")
        netexits.set_locked(True)
        netexits._run_helper = lambda *a: "exit-mx removed"
        self.addCleanup(lambda: setattr(netexits, "_run_helper", self._real_helper))
        os.environ[netexits.HELPER_ENV] = str(Path(self._dir.name) / "helper")
        Path(os.environ[netexits.HELPER_ENV]).write_text("#!/bin/sh\n")
        self.addCleanup(lambda: os.environ.pop(netexits.HELPER_ENV, None))
        said = netexits.close_exit("mx")
        args = os.environ.get(netexits.BROWSER_ARGS_ENV, "")
        self.assertIn(netexits.DEAD_END_PROXY, args)
        self.assertIn(netexits.WEBRTC_ARG, args)
        self.assertIn("dead end", said)

    def test_a_saved_proxy_with_a_comma_cannot_be_armed_into_the_browser(self) -> None:
        netexits.state_file().write_text(json.dumps(
            {"version": 1, "chosen": {"name": "mx",
                                      "proxy": "http://127.0.0.1:8891,--proxy-bypass-list=*"}}
        ))
        said = netexits.set_locked(True)
        args = os.environ.get(netexits.BROWSER_ARGS_ENV, "")
        self.assertNotIn("--proxy-bypass-list", args)
        self.assertIn(netexits.DEAD_END_PROXY, args)
        self.assertIn("refused", said)

    def test_one_policy_file_turning_the_setting_off_is_not_ok(self) -> None:
        bodies = netexits._policy_bodies(policy_reply(
            (), netexits.sandbox_policy_body(), '{"WebRtcIPHandling":"default"}'
        ))
        verdict, detail = netexits._policy_verdict(bodies, proxy=netexits.SANDBOX_PROXY)
        self.assertEqual(verdict, "wrong")
        self.assertIn("other1.json", detail)  # the second file, named by policy_reply

    def test_an_unreadable_exits_file_is_not_also_reported_as_empty(self) -> None:
        netexits.exits_file().write_text("{not json")
        netexits._docker = lambda *a, **k: ""
        _ok, report = netexits.doctor()
        self.assertIn("exits cannot be listed", report)
        self.assertNotIn("no exits yet", report)
        for line in report.splitlines():
            if line.startswith("✗"):
                self.assertTrue("`" in line or "move it aside" in line, line)

    def test_an_unaskable_exit_is_not_said_to_have_stopped_answering(self) -> None:
        # Unaskable now means a SOCKS proxy on a host with no curl: with curl
        # it is measured like any other exit, and a refusal that blames the
        # tunnel for what we could not ask is the fault being guarded here.
        real = netexits.shutil.which
        netexits.shutil.which = lambda name: None if name == "curl" else real(name)
        self.addCleanup(lambda: setattr(netexits.shutil, "which", real))
        self.write_exits({"name": "home", "proxy": "socks5://127.0.0.1:1080", "country": "Uruguay"})
        netexits.apply(netexits.Exit(name="home", proxy="socks5://127.0.0.1:1080"))
        netexits.set_locked(True)
        netexits._last_check = ("", 0.0, False)
        said = netexits.guard_browser("browser_navigate")
        self.assertIn("cannot be checked from here", said)
        self.assertNotIn("stopped answering", said)


class TheBrowserRestartIsNotAssumed(_Sandbox):
    """`restart_browser` runs on every `net_use`, so test it there.

    It is the mechanism behind the plugin's only promise about an *already
    open* browser. When it silently does nothing, `switch` still reports the
    new exit -- and the address in that sentence is the plugin's own egress
    through the new proxy, not the browser's, which is the exact failure the
    plugin exists to prevent, printed as a success.
    """

    def setUp(self) -> None:
        super().setUp()
        netexits.restart_browser = self._real_restart_browser
        self.binary = Path(self._dir.name) / "tools" / "chromium-1208" / "chrome-linux64" / "chrome"
        self.binary.parent.mkdir(parents=True, exist_ok=True)
        self.binary.touch()
        self.killed: list[tuple[int, int]] = []
        self._real_kill = netexits.os.kill
        netexits.os.kill = lambda pid, sig: self.killed.append((pid, sig))
        self.addCleanup(lambda: setattr(netexits.os, "kill", self._real_kill))

    _real_restart_browser = staticmethod(netexits.restart_browser)

    def _ps(self, *lines: str) -> None:
        class _Done:
            returncode = 0
            stdout = "\n".join(lines)
            stderr = ""

        netexits.subprocess.run = lambda *a, **k: _Done()

    def test_it_finds_the_parent_and_leaves_the_children(self) -> None:
        self._ps(f"  101 {self.binary} --remote-debugging-port=0",
                 f"  102 {self.binary} --type=renderer",
                 "  103 /usr/bin/chromium --some-other-browser")
        self.assertEqual(netexits.browser_processes(), [101])

    def test_no_bundled_binary_means_no_processes_rather_than_everything(self) -> None:
        self.binary.unlink()
        self._ps(f"  101 {self.binary} --remote-debugging-port=0")
        self.assertEqual(netexits._browser_binaries(), [])
        self.assertEqual(netexits.browser_processes(), [])

    def test_a_process_it_cannot_signal_is_not_counted_as_closed(self) -> None:
        """Both kills swallow PermissionError, so the count had to come from
        what actually went away."""
        self._ps(f"  101 {self.binary}")
        netexits.os.kill = lambda pid, sig: (_ for _ in ()).throw(PermissionError(1, "nope"))
        self.assertEqual(netexits.restart_browser(grace=0.0), 0)

    def test_what_went_away_is_what_is_counted(self) -> None:
        listing = [f"  101 {self.binary}", f"  102 {self.binary}"]

        def ps(*a, **k):
            class _Done:
                returncode = 0
                stdout = "\n".join(listing)
                stderr = ""
            return _Done()

        netexits.subprocess.run = ps
        # The first process goes away when signalled; the second does not.
        def kill(pid, sig):
            self.killed.append((pid, sig))
            if pid == 101 and listing:
                listing.remove(f"  101 {self.binary}")

        netexits.os.kill = kill
        self.assertEqual(netexits.restart_browser(grace=0.0), 1)

    def test_a_switch_that_closed_nothing_does_not_say_it_did(self) -> None:
        self._ps("")  # no browser running
        self.write_exits({"name": "mx", "proxy": MX_PROXY, "country": "Mexico"})
        self.seeing(ok=True, ip="201.0.0.5", country="MX", city="Mexico City")
        said = netexits.switch("mx")
        self.assertNotIn("Closed", said)

    def test_and_says_it_in_the_singular_when_it_closed_one(self) -> None:
        listing = [f"  101 {self.binary}"]
        netexits.subprocess.run = lambda *a, **k: type(
            "_D", (), {"returncode": 0, "stdout": "\n".join(listing), "stderr": ""}
        )()
        netexits.os.kill = lambda pid, sig: listing.clear()
        self.write_exits({"name": "mx", "proxy": MX_PROXY, "country": "Mexico"})
        self.seeing(ok=True, ip="201.0.0.5", country="MX", city="Mexico City")
        said = netexits.switch("mx")
        self.assertIn("Closed 1 browser process,", said)


class TheSandboxKillSwitchPath(_Sandbox):
    """On a Bot Screen host this is the *only* enforcement path that runs."""

    def setUp(self) -> None:
        super().setUp()
        os.environ[netexits.PROFILE_ENV] = "lab"
        self.addCleanup(lambda: os.environ.pop(netexits.PROFILE_ENV, None))
        path = Path(self._dir.name) / "profiles" / "lab" / "config.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('terminal:\n  backend: "docker"\n')
        netexits._docker = lambda *a, **k: (
            "hermes-abc123\tlab" if a[0] == "ps" else ("hermes-vpn-lab " if a[0] == "inspect" else "true")
        )
        # Sealing and unsealing go through `docker network`, which this
        # records so a test can see what the switch actually did.
        self.network_calls: list[tuple] = []
        real_try = netexits._docker_try
        netexits._docker_try = lambda *a, **k: (
            (self.network_calls.append(a) or (True, "")) if a[:1] == ("network",)
            else real_try(*a, **k)
        )
        self.addCleanup(lambda: setattr(netexits, "_docker_try", real_try))
        self.verifications: list[str] = []
        self._real_verify = netexits.verify_sandbox
        self.addCleanup(lambda: setattr(netexits, "verify_sandbox", self._real_verify))
        netexits.set_locked(True)

    def _verifier(self, ok: bool) -> None:
        def verify(container):
            self.verifications.append(container)
            return (True, "OK 1.2.3.4 JP") if ok else (False, "VPN-VERIFY FAIL(3): egress open")

        netexits.verify_sandbox = verify

    def test_disarming_gives_the_sandbox_the_way_out_it_promises(self) -> None:
        """Disarming used to change nothing in here. The sandbox is on an
        internal network, so there was no "directly" to leave by, and the
        sentence said there was. Now the seal follows the switch: a bot asked
        to drop the kill switch with its exit down gets what a host profile
        would get."""
        said = netexits.set_locked(False)
        self.assertIn("leaves by this host's own address", said)
        self.assertIn("a path off this host", said)
        connected = [a for a in self.network_calls if a[:2] == ("network", "connect")]
        self.assertTrue(connected, "the sandbox was never given a way out")
        self.assertIn("hermes-abc123", connected[0])

    def test_a_network_already_in_the_right_place_is_left_alone(self) -> None:
        """Docker's wording was being read as the answer: disconnecting what
        was already disconnected reported "could not be sealed again ()",
        with an empty reason and the sandbox exactly as wanted."""
        netexits._docker = lambda *a, **k: (
            "hermes-abc123\tlab" if a[0] == "ps"
            else ("hermes-vpn-lab " if a[0] == "inspect" else "true")
        )
        said = netexits.set_locked(True)
        self.assertNotIn("could not be sealed", said)
        self.assertEqual(
            [a for a in self.network_calls if a[:2] == ("network", "disconnect")],
            [], "it disconnected a network the sandbox was not on",
        )

    def test_disarming_does_not_take_the_browser_off_a_working_exit(self) -> None:
        """Disarming permits going direct; it does not go direct.

        An earlier draft rewrote the policy on the way down, so asking to
        lift a hold dropped a bot out of a healthy tunnel. `net_use direct`
        is the step that moves it, the same two steps the host has.
        """
        wrote: list = []
        real = netexits.write_sandbox_policy
        netexits.write_sandbox_policy = lambda c, direct: wrote.append(direct) or ""
        self.addCleanup(lambda: setattr(netexits, "write_sandbox_policy", real))
        netexits.set_locked(False)
        self.assertEqual(wrote, [], "the exit was taken out of the policy by a disarm")

    def test_where_says_it_is_off_the_tunnel_instead_of_unknown(self) -> None:
        """A bot in direct mode was told the location "could not be
        confirmed", which reads like a fault. There is nothing to confirm
        through: the verifier measures the tunnel and this sandbox is
        deliberately off it. So the question is put from inside instead."""
        netexits.set_locked(False)
        netexits._save_state(None)
        # `ps` still has to answer, or this profile stops looking like a
        # sandbox and the host path answers instead.
        netexits._docker_try = lambda *a, **k: (
            (True, "hermes-abc123\tlab") if a[:1] == ("ps",) else (True, "ip=201.0.113.9\nloc=DE\n")
        )
        netexits.TRACE_URL = "https://1.1.1.1/cdn-cgi/trace"
        said = netexits.describe_here()
        self.assertIn("off the tunnel", said)
        self.assertNotIn("could not confirm", said)
        self.assertIn("this host's own address", said)

    def test_the_direct_measurement_does_not_go_through_the_tunnel(self) -> None:
        """`vpn-migrate` writes `proxy = http://vpn-exit:8888` into the
        sandbox's ~/.curlrc so curl and pip go through the tunnel too. A bot
        in direct mode was therefore told it came out at the Mexican exit's
        address -- the tunnel's answer, presented as the direct one."""
        netexits.set_locked(False)
        netexits._save_state(None)
        netexits.TRACE_URL = "https://1.1.1.1/cdn-cgi/trace"
        asked: list = []
        netexits._docker_try = lambda *a, **k: (
            (True, "hermes-abc123\tlab") if a[:1] == ("ps",)
            else (asked.append(a) or (True, "ip=201.0.113.9\nloc=DE\n"))
        )
        netexits.describe_here()
        argv = " ".join(str(x) for x in asked[0])
        self.assertIn("--noproxy", argv)

    def test_and_it_is_still_a_measurement(self) -> None:
        """Reporting the host's address without asking would be the same
        assumption this plugin refuses everywhere else."""
        netexits.set_locked(False)
        netexits._save_state(None)
        netexits.TRACE_URL = "https://1.1.1.1/cdn-cgi/trace"
        netexits._docker_try = lambda *a, **k: (
            (True, "hermes-abc123\tlab") if a[:1] == ("ps",) else (False, "no curl in there")
        )
        said = netexits.describe_here()
        self.assertIn("off the tunnel", said)
        self.assertIn("did not come back", said)

    def test_disarming_names_the_exit_you_are_still_on(self) -> None:
        """People reach for this when something is already wrong, and "may
        now leave directly, if no exit is selected" left them to work out
        whether one was. The next page still goes through the dead proxy."""
        netexits._write_state(chosen={"name": "exit-mx", "proxy": MX_PROXY})
        said = netexits.set_locked(False)
        self.assertIn("still on exit-mx", said)
        self.assertIn("hermes vpn use direct", said)
        self.assertIn("fail like a broken page", said)

    def test_arming_seals_it_again(self) -> None:
        # The fixture's inspect answers "hermes-vpn-lab", so the sandbox has
        # to look attached for a disconnect to be worth making.
        netexits._docker = lambda *a, **k: (
            "hermes-abc123\tlab" if a[0] == "ps"
            else ("bridge hermes-vpn-lab " if a[0] == "inspect" else "true")
        )
        netexits.set_locked(False)
        self.network_calls.clear()
        said = netexits.set_locked(True)
        self.assertIn("tunnel-only network", said)
        self.assertTrue(
            [a for a in self.network_calls if a[:2] == ("network", "disconnect")],
            "the sandbox was left open after arming",
        )

    def test_a_confirmed_sandbox_may_browse(self) -> None:
        self._verifier(True)
        self.assertEqual(netexits.guard_browser("browser_navigate"), "")
        self.assertEqual(self.verifications, ["hermes-abc123"])

    def test_an_unconfirmed_sandbox_may_not(self) -> None:
        self._verifier(False)
        said = netexits.guard_browser("browser_navigate")
        self.assertIn("could not confirm its way out", said)
        self.assertIn("hermes-abc123", said)

    def test_the_verdict_is_cached_so_a_click_does_not_pay_for_a_subprocess(self) -> None:
        self._verifier(True)
        netexits.guard_browser("browser_navigate")
        netexits.guard_browser("browser_click")
        netexits.guard_browser("browser_navigate")
        self.assertEqual(len(self.verifications), 1)

    def test_the_cache_does_not_answer_for_the_host(self) -> None:
        """One slot holds both kinds of answer; the key is what separates them."""
        self._verifier(True)
        netexits.guard_browser("browser_navigate")          # caches sandbox:hermes-abc123
        self.assertTrue(netexits._last_check[0].startswith("sandbox:"))
        asked = []
        netexits.look = lambda proxy="": asked.append(proxy) or netexits.Sighting(
            ok=True, ip="201.0.0.5", country="MX"
        )
        netexits.exit_is_answering(MX_PROXY)
        self.assertEqual(asked, [MX_PROXY])  # asked again, not reused

    def test_an_expired_verdict_is_asked_again(self) -> None:
        self._verifier(True)
        self.assertTrue(netexits._sandbox_is_answering("hermes-abc123", max_age=0))
        self.assertTrue(netexits._sandbox_is_answering("hermes-abc123", max_age=0))
        self.assertEqual(len(self.verifications), 2)


class WhichProfileHermesSaysWeAre(_Sandbox):
    """Every test run takes the ImportError fallback; the host takes the other."""

    def _hermes_cli(self, value) -> None:
        import types

        package = types.ModuleType("hermes_cli")
        module = types.ModuleType("hermes_cli.profiles")
        if isinstance(value, Exception):
            def current_profile_name():
                raise value
        else:
            def current_profile_name():
                return value
        module.current_profile_name = current_profile_name
        package.profiles = module
        sys.modules["hermes_cli"] = package
        sys.modules["hermes_cli.profiles"] = module
        self.addCleanup(lambda: sys.modules.pop("hermes_cli", None))
        self.addCleanup(lambda: sys.modules.pop("hermes_cli.profiles", None))

    def test_hermes_own_answer_is_used_when_there_is_one(self) -> None:
        self._hermes_cli("lab")
        self.assertEqual(netexits.current_profile(), "lab")

    def test_a_non_string_answer_is_not_pasted_into_a_docker_filter(self) -> None:
        """It reaches `--filter label=hermes-profile=<this>`, so its repr
        matters: a Profile object would match no container and the plugin
        would decide it is on the host."""
        self._hermes_cli(object())
        self.assertIsInstance(netexits.current_profile(), str)
        self.assertEqual(netexits.current_profile(), "default")

    def test_an_exception_falls_back_to_the_path(self) -> None:
        self._hermes_cli(RuntimeError("no profile here"))
        self.assertEqual(netexits.current_profile(), "default")

    def test_an_empty_answer_falls_back_too(self) -> None:
        self._hermes_cli("")
        self.assertEqual(netexits.current_profile(), "default")


class TheLastResortPositions(_Sandbox):
    """The catch-alls that decide what happens when everything else failed."""

    def test_locked_answers_armed_when_it_cannot_tell(self) -> None:
        """`locked()` is asked by the middleware, so it must answer rather
        than raise — and not knowing is not a reason to act as if it is off."""
        netexits.state_file = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
        self.addCleanup(lambda: setattr(netexits, "state_file", self._real_state_file))
        self.assertTrue(netexits.locked())

    _real_state_file = staticmethod(netexits.state_file)

    def test_the_trace_endpoint_is_what_look_asks_first(self) -> None:
        netexits.TRACE_URL = "https://trace.invalid/"
        self.addCleanup(lambda: setattr(netexits, "TRACE_URL", ""))
        netexits._fetch = lambda url, proxy: ("ip=45.33.32.156\nloc=MX\n", "")
        self.addCleanup(lambda: setattr(netexits, "_fetch", self._real_fetch))
        seen = netexits.look(MX_PROXY)
        self.assertTrue(seen.ok)
        self.assertEqual(seen.ip, "45.33.32.156")
        self.assertEqual(seen.country, "MX")

    _real_fetch = staticmethod(netexits._fetch)

    def test_a_trace_naming_a_private_address_is_not_a_sighting(self) -> None:
        """A proxy answering with its own 10.x address would otherwise be a
        confirmed exit."""
        netexits.TRACE_URL = "https://trace.invalid/"
        self.addCleanup(lambda: setattr(netexits, "TRACE_URL", ""))
        netexits._fetch = lambda url, proxy: ("ip=10.99.0.2\nloc=MX\n", "")
        self.addCleanup(lambda: setattr(netexits, "_fetch", self._real_fetch))
        seen = netexits.look(MX_PROXY)
        self.assertFalse(seen.ok)
        self.assertIn("not a routable address", seen.detail)

    def test_a_trace_with_no_address_falls_through(self) -> None:
        netexits.TRACE_URL = "https://trace.invalid/"
        self.addCleanup(lambda: setattr(netexits, "TRACE_URL", ""))
        netexits._fetch = lambda url, proxy: ("fl=abc\nts=1\n", "")
        self.addCleanup(lambda: setattr(netexits, "_fetch", self._real_fetch))
        seen = netexits.look(MX_PROXY)
        self.assertFalse(seen.ok)
        self.assertIn("no ip in the trace", seen.detail)

    def test_a_missing_verifier_is_a_refusal_naming_the_path(self) -> None:
        netexits.VERIFY_HELPER = str(Path(self._dir.name) / "nothing")
        self.addCleanup(lambda: setattr(netexits, "VERIFY_HELPER", self._real_verify_helper))
        ok, said = netexits.verify_sandbox("c1")
        self.assertFalse(ok)
        self.assertIn("no verifier at", said)

    _real_verify_helper = netexits.VERIFY_HELPER

    def test_the_verifiers_reason_reaches_the_reader(self) -> None:
        """This is the sentence a person sees when a sandbox is leaking."""
        helper = Path(self._dir.name) / "verify"
        helper.write_text("#!/bin/sh\necho 'VPN-VERIFY FAIL(3): direct egress open' >&2\nexit 3\n")
        helper.chmod(0o755)
        netexits.VERIFY_HELPER = str(helper)
        self.addCleanup(lambda: setattr(netexits, "VERIFY_HELPER", self._real_verify_helper))
        ok, said = netexits.verify_sandbox("c1")
        self.assertFalse(ok)
        self.assertIn("direct egress open", said)

    def test_the_provider_name_and_the_file_to_pass_are_both_read(self) -> None:
        netexits._run_helper = lambda *a: "surfshark\twork.env\nmullvad\t.env\n"
        self.addCleanup(lambda: setattr(netexits, "_run_helper", self._real_helper))
        self.assertEqual(
            sorted(netexits.configured_providers()),
            [("mullvad", ""), ("surfshark", "work")],
        )
        said = netexits.describe_providers()
        self.assertIn("surfshark (pass provider: work)", said)

    _real_helper = staticmethod(netexits._run_helper)

    def test_a_one_column_helper_still_works(self) -> None:
        """An older vpn-exit prints only the provider's own name."""
        netexits._run_helper = lambda *a: "surfshark\n"
        self.addCleanup(lambda: setattr(netexits, "_run_helper", self._real_helper))
        self.assertEqual(netexits.configured_providers(), [("surfshark", "surfshark")])


class OneTestPerGuarantee(_Sandbox):
    """Each test here fails if the single line it is about is deleted.

    Keep that property when editing them. A test that still passes with its
    subject removed is not testing anything.
    """

    def test_armed_with_no_exit_refuses_the_browser_itself(self) -> None:
        """Armed with no exit at all, the guard refuses on its own.

        Don't let this one lean on a selected exit: with `guard_browser`'s
        no-exit branch gone, control reaches a lookup with no proxy, that
        lookup succeeds, and the guard says yes.
        """
        netexits.set_locked(True)
        os.environ.pop(netexits.BROWSER_ARGS_ENV, None)
        # As a direct, unproxied lookup behaves on a real host.
        netexits.look = lambda proxy="": netexits.Sighting(
            ok=True, ip="201.0.113.9", country="Germany"
        )
        said = netexits.guard_browser("browser_navigate")
        self.assertIn("no exit is selected", said)

    def test_and_an_empty_proxy_is_never_alive(self) -> None:
        """The same guarantee, one layer down, so it does not rest on one
        caller's `if`."""
        asked = []
        netexits.look = lambda proxy="": asked.append(proxy) or netexits.Sighting(ok=True, ip="1.2.3.4")
        self.assertFalse(netexits.exit_is_answering(""))
        self.assertFalse(netexits.exit_is_answering(netexits.DEAD_END_PROXY))
        self.assertEqual(asked, [], "it asked the internet about having no exit")

    def test_a_bypass_list_is_not_a_policy_detail(self) -> None:
        """`*` means the browser uses the exit for nothing, so it is a fault."""
        for listed in ("*", "<local>;*.com;*"):
            with self.subTest(listed=listed):
                bodies = netexits._policy_bodies(policy_reply(
                    (),
                    '{"ProxyMode":"fixed_servers","ProxyServer":"http://vpn-exit:8888",'
                    f'"ProxyBypassList":"{listed}",'
                    '"WebRtcIPHandling":"disable_non_proxied_udp"}',
                ))
                verdict, detail = netexits._policy_verdict(bodies, proxy=netexits.SANDBOX_PROXY)
                self.assertEqual(verdict, "wrong")
                self.assertIn("bypassed", detail)

    def test_a_second_file_that_only_bypasses_is_caught_too(self) -> None:
        bodies = netexits._policy_bodies(policy_reply(
            (), netexits.sandbox_policy_body(), '{"ProxyBypassList":"*"}'
        ))
        verdict, detail = netexits._policy_verdict(bodies, proxy=netexits.SANDBOX_PROXY)
        self.assertEqual(verdict, "wrong")
        self.assertIn("bypassed", detail)

    def test_the_legacy_spelling_is_refused_inside_the_sandbox_too(self) -> None:
        """The similarly-named test covers the *host* reader, a different
        function with its own comparison."""
        bodies = netexits._policy_bodies(policy_reply(
            (),
            '{"ProxyMode":"fixed_servers","ProxyServer":"http://vpn-exit:8888",'
            '"WebRtcIPHandlingPolicy":"disable_non_proxied_udp"}',
        ))
        verdict, detail = netexits._policy_verdict(bodies, proxy=netexits.SANDBOX_PROXY)
        self.assertEqual(verdict, "wrong")
        self.assertIn("Chrome ignores", detail)

    def test_a_policy_file_cannot_truncate_the_read_with_its_own_content(self) -> None:
        """The attack the nonce exists for, which no fixture ever planted: the
        delimiters frame a file anyone with root in that container can write."""
        stream = policy_reply(
            ("sh", "-c", "cat __abcdef0123456789__FILE"),   # a nonce the double echoes
            '{"_note":"harmless __READ__ marker in a comment"}',
            '{"ProxyMode":"direct","WebRtcIPHandling":"default"}',
        )
        bodies = netexits._policy_bodies(stream, "__abcdef0123456789__")
        self.assertEqual(len(bodies), 2, "a file's content hid the files after it")
        verdict, _detail = netexits._policy_verdict(bodies, proxy=netexits.SANDBOX_PROXY)
        self.assertEqual(verdict, "wrong")

    def test_a_locked_value_that_is_not_a_boolean_leaves_it_armed(self) -> None:
        """`null`, `0`, `[]`, `""` are not "disarmed" -- they are a file that
        cannot be read as one, and the whole-file corruption tests never
        reached this."""
        for value in (None, 0, [], "", {}):
            with self.subTest(value=value):
                netexits.state_file().write_text(json.dumps({"version": 1, "locked": value}))
                self.assertTrue(netexits.locked())
        netexits.state_file().write_text(json.dumps({"version": 1, "locked": False}))
        self.assertFalse(netexits.locked())

    def test_a_state_read_that_raises_leaves_it_armed(self) -> None:
        """The switch's last-resort position. `_read_state` swallows its own
        errors, so nothing in the suite could make it raise."""
        netexits._read_state = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
        self.addCleanup(lambda: setattr(netexits, "_read_state", self._real_read_state))
        self.assertTrue(netexits.locked())

    _real_read_state = staticmethod(netexits._read_state)

    def test_the_proxy_port_is_the_one_bound_to_8888(self) -> None:
        """The proxy is the mapping whose *container* port is 8888.

        gluetun publishes its control server too, so the first loopback
        mapping is not necessarily the proxy. Keep both in this fixture.
        """
        self.assertEqual(
            netexits._published_proxy_port("127.0.0.1:8000->8000/tcp, 127.0.0.1:8889->8888/tcp"),
            "8889",
        )
        self.assertEqual(
            netexits._published_proxy_port("127.0.0.1:8388->8388/tcp, 127.0.0.1:8891->8888/tcp"),
            "8891",
        )
        self.assertEqual(netexits._published_proxy_port("127.0.0.1:8000->8000/tcp"), "")

    def test_backend_docker_compose_is_not_a_sandbox(self) -> None:
        """`\\b` matched before the hyphen. The commented-out test passed
        because `sandbox_profiles` strips comments, not because of the regex."""
        for value, is_sandbox in (("docker", True), ("docker-compose", False),
                                  ('"docker"', True), ("dockerfoo", False)):
            with self.subTest(value=value):
                path = Path(self._dir.name) / "profiles" / "lab" / "config.yaml"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"terminal:\n  backend: {value}\n")
                netexits._docker = lambda *a, **k: ""
                found = [n for n, _s, _d in netexits.sandbox_profiles()]
                self.assertEqual(found, ["lab"] if is_sandbox else [], value)

    def test_the_flow_form_is_a_sandbox_too(self) -> None:
        path = Path(self._dir.name) / "profiles" / "lab" / "config.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('terminal: {backend: docker, image: hermes}\n')
        netexits._docker = lambda *a, **k: ""
        self.assertEqual([n for n, _s, _d in netexits.sandbox_profiles()], ["lab"])

    def test_a_stale_alive_does_not_outlive_the_exit(self) -> None:
        """The caching test asserted one lookup in five calls and nothing
        about the other side: that it is asked again once the answer is old."""
        asked = []
        netexits.look = lambda proxy="": asked.append(proxy) or netexits.Sighting(
            ok=True, ip="201.0.0.5", country="MX"
        )
        netexits.exit_is_answering(MX_PROXY, max_age=0)
        netexits.exit_is_answering(MX_PROXY, max_age=0)
        self.assertEqual(len(asked), 2)


class TheMechanismNotJustTheResult(_Sandbox):
    """Three mutations survived even the tests written for them.

    Each of those tests asserted the outcome, which a different line also
    produces. These assert the mechanism: the nonce really is unpredictable,
    and each of the two cache clears happens at the moment its own comment
    says it must.
    """

    def setUp(self) -> None:
        super().setUp()
        os.environ[netexits.PROFILE_ENV] = "lab"
        self.addCleanup(lambda: os.environ.pop(netexits.PROFILE_ENV, None))
        path = Path(self._dir.name) / "profiles" / "lab" / "config.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('terminal:\n  backend: "docker"\n')
        netexits._docker = lambda *a, **k: (
            "hermes-abc123\tlab" if a[0] == "ps" else ("hermes-vpn-lab " if a[0] == "inspect" else "true")
        )
        self.write_exits({"name": "exit-jp", "proxy": JP_PROXY, "country": "Japan"})
        self._real_verify = netexits.verify_sandbox
        self._real_helper = netexits._run_helper
        self.addCleanup(lambda: setattr(netexits, "verify_sandbox", self._real_verify))
        self.addCleanup(lambda: setattr(netexits, "_run_helper", self._real_helper))
        netexits.verify_sandbox = lambda c: (True, "OK 1.2.3.4 JP")

    def test_the_read_is_framed_with_something_a_file_cannot_contain(self) -> None:
        """A policy file quoting the delimiter must not truncate the stream.

        Truncation hides every file after it, and here the hidden one is the
        one that says `ProxyMode: direct`. Driven through
        `sandbox_policy_state` so the nonce is whatever the code generates,
        not whatever the test passes in.
        """
        seen_nonces = []

        def fake_try(*args, **kwargs):
            joined = " ".join(str(a) for a in args)
            found = re.search(r"__[0-9a-f]{16}__", joined)
            nonce = found.group(0) if found else "__"
            seen_nonces.append(nonce)
            # The first file's body carries the *fixed* delimiter, which is
            # what a hostile or careless policy file would contain.
            return True, (
                f'{nonce}FILE /x/aa.json\n{{"_note":"see __READ__ below"}}\n'
                f'{nonce}FILE /x/zz.json\n{{"ProxyMode":"direct","WebRtcIPHandling":"default"}}\n'
                f"{nonce}READ\n"
            )

        netexits._docker_try = fake_try
        verdict, detail = netexits.sandbox_policy_state("hermes-abc123")
        self.assertEqual(verdict, "wrong", "the second file was hidden by the first one's content")
        self.assertNotEqual(seen_nonces, ["__"], "the delimiter was predictable")
        self.assertRegex(seen_nonces[0], r"^__[0-9a-f]{16}__$")

    def test_the_old_verdict_is_gone_before_the_relay_moves(self) -> None:
        """Not merely gone by the end: a stale positive must not be able to
        answer a browser call in the window while the exit is changing."""
        netexits._docker_try = lambda *a, **k: (
            (True, netexits._docker(*a)) if a[:1] == ("ps",)
            else (True, policy_reply(a, netexits.sandbox_policy_body()))
        )
        netexits._last_check = ("sandbox:hermes-abc123", 1e18, True)
        during = []
        netexits._run_helper = lambda *a: during.append(netexits._last_check[0]) or "ok"
        netexits.switch("exit-jp")
        self.assertEqual(during, [""], "the cache still held a verdict while the relay moved")

    def test_and_gone_again_after_it_moved(self) -> None:
        """The verdict from before the switch cannot speak for after it."""
        netexits._docker_try = lambda *a, **k: (
            (True, netexits._docker(*a)) if a[:1] == ("ps",)
            else (True, policy_reply(a, netexits.sandbox_policy_body()))
        )
        # A positive planted by the helper call itself, as a concurrent browser
        # call would plant one.
        netexits._run_helper = lambda *a: setattr(
            netexits, "_last_check", ("sandbox:hermes-abc123", 1e18, True)
        ) or "ok"
        netexits.switch("exit-jp")
        self.assertEqual(netexits._last_check[0], "")

    def test_the_legacy_spelling_is_named_in_the_fault(self) -> None:
        """Not just "wrong": the reader has to learn *which* spelling, because
        the two differ by one word and Chrome ignores one in silence."""
        bodies = netexits._policy_bodies(policy_reply(
            (),
            '{"ProxyMode":"fixed_servers","ProxyServer":"http://vpn-exit:8888",'
            '"WebRtcIPHandlingPolicy":"disable_non_proxied_udp"}',
        ))
        _verdict, detail = netexits._policy_verdict(bodies, proxy=netexits.SANDBOX_PROXY)
        self.assertIn("WebRtcIPHandlingPolicy", detail)
        self.assertIn("Chrome ignores", detail)

    def test_the_default_credentials_file_needs_no_provider_name(self) -> None:
        """`.env` has no stem, so printing it gave "surfshark (pass provider: )"."""
        netexits._run_helper = lambda *a: "surfshark\t.env\n"
        self.addCleanup(lambda: setattr(netexits, "_run_helper", self._real_helper))
        self.assertEqual(netexits.configured_providers(), [("surfshark", "")])
        said = netexits.describe_providers()
        self.assertIn("surfshark", said)
        self.assertNotIn("pass provider: )", said)
        self.assertNotIn("(pass provider", said)


class FailoverIsAStandbyYouChose(_Sandbox):
    """Failover moves to the exit the person named, and nowhere else.

    It used to look for a peer in the same country and order the candidates
    by city and by provider. That was a great deal of inference for a
    decision someone can make once and mean, and a dropped tunnel is the
    worst moment to be guessing where they wanted to be. The standby is
    named in advance, kept running, and checked when it is named.
    """

    MX = "http://127.0.0.1:8891"
    AIR = "http://127.0.0.1:8892"
    TOR = "http://127.0.0.1:8899"

    def setUp(self) -> None:
        super().setUp()
        self.answers = {self.MX: True, self.AIR: True, self.TOR: True}
        netexits.look = self._looking
        netexits.discover_containers = lambda: [
            netexits.Exit(name="exit-mx", proxy=self.MX, country="Mexico",
                          source="gluetun", container="exit-mx", provider="surfshark"),
            netexits.Exit(name="exit-airvpn-madrid", proxy=self.AIR, country="Madrid",
                          source="gluetun", container="exit-airvpn-madrid",
                          provider="airvpn"),
            netexits.Exit(name="exit-tor", proxy=self.TOR, country="Tor",
                          source="labelled", container="exit-tor", provider="tor"),
        ]
        netexits._last_check = ("", 0.0, False)
        netexits._failover_note = ""
        netexits._run_helper = lambda *a: "surfshark\t.env\nairvpn\tairvpn.env\n"
        self.addCleanup(lambda: setattr(netexits, "_run_helper", self._real_run_helper))

    _real_run_helper = staticmethod(netexits._run_helper)

    def _looking(self, proxy: str = "") -> netexits.Sighting:
        ok = self.answers.get(proxy, False)
        return netexits.Sighting(
            ok=ok, ip="201.0.0.5" if ok else "", country="MX" if ok else "",
            city="Mexico City" if ok else "", detail="" if ok else "down",
        )

    def _on_mx_armed(self) -> None:
        netexits.switch("exit-mx")
        netexits.set_locked(True)
        netexits._last_check = ("", 0.0, False)

    def _mx_dies(self) -> None:
        self.answers[self.MX] = False
        netexits._last_check = ("", 0.0, False)

    def test_off_by_default(self) -> None:
        self.assertFalse(netexits.failover_armed())
        self.assertEqual(netexits.standby(), {})

    def test_arming_without_a_standby_asks_instead_of_promising(self) -> None:
        """It used to arm and promise a move it could not make."""
        self._on_mx_armed()
        said = netexits.set_failover(True)
        self.assertIn("Nothing is armed yet", said)
        self.assertIn("airvpn", said, "the other provider it could use is named")
        self.assertFalse(netexits.failover_armed())

    def test_and_says_whose_job_the_credentials_are_when_there_is_no_other(self) -> None:
        netexits._run_helper = lambda *a: "surfshark\t.env\n"
        self._on_mx_armed()
        said = netexits.set_failover(True)
        self.assertIn("hermes vpn provider", said)
        self.assertIn("never handled here", said)
        self.assertFalse(netexits.failover_armed())

    def test_a_standby_is_checked_when_it_is_named(self) -> None:
        """Nobody looks at a standby until the day it is needed."""
        self._on_mx_armed()
        self.answers[self.AIR] = False
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.set_standby("exit-airvpn-madrid")
        self.assertIn("did not answer", str(caught.exception))
        self.assertIn("has to be running", str(caught.exception))
        self.assertEqual(netexits.standby(), {})

    def test_naming_one_says_what_changes_if_it_takes_over(self) -> None:
        self._on_mx_armed()
        said = netexits.set_standby("exit-airvpn-madrid")
        self.assertIn("Madrid", said)
        self.assertIn("you are in Mexico", said)
        self.assertEqual(netexits.standby()["exit"], "exit-airvpn-madrid")

    def test_a_standby_on_the_same_subscription_is_named_as_such(self) -> None:
        netexits.discover_containers = lambda: [
            netexits.Exit(name="exit-mx", proxy=self.MX, country="Mexico",
                          source="gluetun", container="exit-mx", provider="surfshark"),
            netexits.Exit(name="exit-es", proxy=self.AIR, country="Spain",
                          source="gluetun", container="exit-es", provider="surfshark"),
        ]
        self._on_mx_armed()
        said = netexits.set_standby("exit-es")
        self.assertIn("a subscription that fails takes the standby with it", said)

    def test_tor_is_not_a_standby(self) -> None:
        self._on_mx_armed()
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.set_standby("exit-tor")
        self.assertIn("Tor is not a standby", str(caught.exception))
        self.assertIn("cookies", str(caught.exception))

    def test_the_exit_in_use_cannot_stand_in_for_itself(self) -> None:
        self._on_mx_armed()
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.set_standby("exit-mx")
        self.assertIn("cannot also be what takes over", str(caught.exception))

    def test_armed_it_moves_to_the_standby_and_says_so(self) -> None:
        self._on_mx_armed()
        netexits.set_standby("exit-airvpn-madrid")
        netexits.set_failover(True)
        self._mx_dies()
        self.assertEqual(netexits.guard_browser("browser_navigate"), "")
        self.assertEqual(netexits.current_proxy(), self.AIR)
        note = netexits.take_failover_note()
        self.assertIn("exit-mx", note)
        self.assertIn("exit-airvpn-madrid", note)
        self.assertEqual(netexits.take_failover_note(), "", "taken, not repeated")

    def test_a_move_out_of_tor_ends_tor_mode_first(self) -> None:
        """Otherwise the profile that collected cookies over Tor carries
        them onto a clearnet exit -- the linkage `set_standby` refuses Tor
        to prevent, run backwards -- while `doctor` keeps printing that the
        browser has a cleared profile."""
        self._on_mx_armed()
        netexits.set_standby("exit-airvpn-madrid")
        netexits.set_failover(True)
        netexits._write_state(tor_mode={"on": True, "javascript": False})
        self.assertTrue(netexits.tor_mode())
        self._mx_dies()
        netexits.guard_browser("browser_navigate")
        self.assertFalse(netexits.tor_mode(), "the mode followed the browser to clearnet")
        self.assertIn("Tor mode ended first", netexits.take_failover_note())

    def test_a_failed_failover_from_tor_leaves_the_mode_alone(self) -> None:
        """Verify before de-isolating. Leaving Tor mode first and then
        refusing on a dead standby deleted the profile and rewrote the
        browser arguments while the message said nothing had changed."""
        self._on_mx_armed()
        netexits.set_standby("exit-airvpn-madrid")
        netexits.set_failover(True)
        netexits._write_state(tor_mode={"on": True, "javascript": False})
        self._mx_dies()
        self.answers[self.AIR] = False
        refusal = netexits.guard_browser("browser_navigate")
        self.assertIn("did not answer either", refusal)
        self.assertTrue(netexits.tor_mode(), "the mode was not ended by a move that did not happen")

    def test_a_standby_that_is_down_too_is_refused_not_guessed_around(self) -> None:
        """And then the kill switch is what holds the browser."""
        self._on_mx_armed()
        netexits.set_standby("exit-airvpn-madrid")
        netexits.set_failover(True)
        self._mx_dies()
        self.answers[self.AIR] = False
        refusal = netexits.guard_browser("browser_navigate")
        self.assertIn("did not answer either", refusal)
        self.assertEqual(netexits.current_proxy(), self.MX, "nothing moved")

    def test_armed_with_no_standby_chosen_says_that_and_moves_nothing(self) -> None:
        self._on_mx_armed()
        netexits._write_state(failover=True)
        self._mx_dies()
        refusal = netexits.guard_browser("browser_navigate")
        self.assertIn("no standby exit has been chosen", refusal)
        self.assertEqual(netexits.current_proxy(), self.MX)

    def test_disarmed_the_refusal_reads_as_it_always_did(self) -> None:
        self._on_mx_armed()
        netexits.set_standby("exit-airvpn-madrid")
        self._mx_dies()
        refusal = netexits.guard_browser("browser_navigate")
        self.assertIn("stopped answering", refusal)
        self.assertNotIn("ailover", refusal)
        self.assertEqual(netexits.current_proxy(), self.MX)

    def test_an_exit_that_cannot_be_checked_is_not_swapped_out(self) -> None:
        """A SOCKS exit without curl, or a rate-limited lookup, reads the
        same as a dead one and is not evidence of anything."""
        self._on_mx_armed()
        netexits.set_standby("exit-airvpn-madrid")
        netexits.set_failover(True)
        netexits.look = lambda proxy="": netexits.Sighting(
            ok=False, detail="no verifiable answer", unverifiable=True
        )
        netexits._last_check = ("", 0.0, False)
        refusal = netexits.guard_browser("browser_navigate")
        self.assertIn("cannot be checked", refusal)
        self.assertNotIn("Failover", refusal)
        self.assertEqual(netexits.current_proxy(), self.MX)

    def test_a_flapping_tunnel_does_not_walk_the_browser_around(self) -> None:
        self._on_mx_armed()
        netexits.set_standby("exit-airvpn-madrid")
        netexits.set_failover(True)
        self._mx_dies()
        netexits.guard_browser("browser_navigate")
        self.assertEqual(netexits.current_proxy(), self.AIR)
        self.answers[self.AIR] = False
        netexits._last_check = ("", 0.0, False)
        refusal = netexits.guard_browser("browser_navigate")
        self.assertIn("waits", refusal)

    def test_the_move_is_recorded_for_doctor(self) -> None:
        self._on_mx_armed()
        netexits.set_standby("exit-airvpn-madrid")
        netexits.set_failover(True)
        self._mx_dies()
        netexits.guard_browser("browser_navigate")
        saved = json.loads(Path(netexits.state_file()).read_text())
        self.assertEqual(saved["last_failover"]["from"], "exit-mx")
        self.assertEqual(saved["last_failover"]["to"], "exit-airvpn-madrid")

    def test_arming_it_without_the_kill_switch_says_it_will_never_fire(self) -> None:
        netexits.switch("exit-mx")
        netexits.set_standby("exit-airvpn-madrid")
        said = netexits.set_failover(True)
        self.assertIn("never fire", said)

    def test_the_env_var_is_only_a_starting_position(self) -> None:
        os.environ[netexits.FAILOVER_ENV] = "on"
        self.assertTrue(netexits.failover_armed())
        netexits.set_failover(False)
        self.assertFalse(netexits.failover_armed(), "the state file wins over the env var")

    def test_an_unreadable_state_leaves_it_off(self) -> None:
        Path(netexits.state_file()).write_text("{ not json")
        self.assertTrue(netexits.locked(), "the kill switch ends armed")
        self.assertFalse(netexits.failover_armed(), "failover ends off")


class VaultReferenceResolution(unittest.TestCase):
    """A reference names where the config is; the plugin reads it host-side."""

    def test_a_file_reference_reads_the_file(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as handle:
            handle.write("[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/32\n")
            path = handle.name
        self.addCleanup(os.unlink, path)
        text = netexits.resolve_secret_ref(f"file:{path}")
        self.assertIn("PrivateKey = abc", text)

    def test_a_relative_file_reference_is_refused(self) -> None:
        with self.assertRaises(netexits.ExitError):
            netexits.resolve_secret_ref("file:airvpn.conf")

    def test_a_pass_reference_shells_out_to_pass(self) -> None:
        payload = "[Interface]\nPrivateKey = k\nAddress = 10.0.0.2/32\n"
        done = types.SimpleNamespace(returncode=0, stdout=payload, stderr="")
        with mock.patch.object(netexits.shutil, "which", return_value="/usr/bin/pass"), \
             mock.patch.object(netexits.subprocess, "run", return_value=done) as run:
            text = netexits.resolve_secret_ref("pass:vpn/airvpn")
        self.assertEqual(text, payload)
        self.assertEqual(run.call_args.args[0], ["/usr/bin/pass", "show", "vpn/airvpn"])

    def test_a_pass_reference_falls_back_to_gopass(self) -> None:
        done = types.SimpleNamespace(returncode=0, stdout="PrivateKey = k\n", stderr="")
        which = lambda name: "/usr/bin/gopass" if name == "gopass" else None
        with mock.patch.object(netexits.shutil, "which", side_effect=which), \
             mock.patch.object(netexits.subprocess, "run", return_value=done) as run:
            netexits.resolve_secret_ref("pass:vpn/airvpn")
        self.assertEqual(run.call_args.args[0][0], "/usr/bin/gopass")

    def test_a_pass_path_with_dotdot_is_refused(self) -> None:
        with self.assertRaises(netexits.ExitError):
            netexits.resolve_secret_ref("pass:../../etc/secret")

    def test_a_pass_name_beginning_with_a_dash_is_refused(self) -> None:
        """A leading dash would be parsed by pass/gopass as an option."""
        with self.assertRaises(netexits.ExitError):
            netexits.resolve_secret_ref("pass:-c")

    def test_a_file_path_with_dotdot_is_refused(self) -> None:
        with self.assertRaises(netexits.ExitError):
            netexits.resolve_secret_ref("file:/home/you/../../private/wg.conf")

    def test_env_references_are_refused(self) -> None:
        with self.assertRaises(netexits.ExitError) as caught:
            netexits.resolve_secret_ref("env:WIREGUARD_PRIVATE_KEY")
        self.assertIn("vault", str(caught.exception).lower())

    def test_a_raw_secret_is_not_a_reference(self) -> None:
        with self.assertRaises(netexits.ExitError):
            netexits.resolve_secret_ref("cHJpdmF0ZWtleQ==")

    def test_a_multiline_reference_is_refused(self) -> None:
        with self.assertRaises(netexits.ExitError):
            netexits.resolve_secret_ref("pass:one\npass:two")


class AddingAProviderFromAReference(unittest.TestCase):
    """The whole point: the key is stored without ever reaching the model."""

    def test_an_existing_provider_is_not_overwritten(self) -> None:
        with mock.patch.object(
            netexits, "configured_providers", return_value=[("airvpn", "airvpn")]
        ):
            with self.assertRaises(netexits.ExitError) as caught:
                netexits.add_provider_from_ref("airvpn", "file:/tmp/x.conf")
        self.assertIn("already", str(caught.exception))

    def test_a_reference_that_is_not_wireguard_is_refused(self) -> None:
        with mock.patch.object(netexits, "configured_providers", return_value=[]), \
             mock.patch.object(netexits, "resolve_secret_ref", return_value="hello world"):
            with self.assertRaises(netexits.ExitError) as caught:
                netexits.add_provider_from_ref("airvpn", "file:/tmp/x.conf")
        self.assertIn("WireGuard", str(caught.exception))

    def test_a_bad_provider_name_is_refused(self) -> None:
        with self.assertRaises(netexits.ExitError):
            netexits.add_provider_from_ref("Air VPN!", "file:/tmp/x.conf")

    def test_the_happy_path_feeds_the_helper_and_returns_only_names(self) -> None:
        config = "[Interface]\nPrivateKey = secret\nAddress = 10.0.0.2/32\n"
        with mock.patch.object(netexits, "configured_providers", return_value=[]), \
             mock.patch.object(netexits, "resolve_secret_ref", return_value=config), \
             mock.patch.object(
                 netexits, "_write_credentials_via_helper",
                 return_value="wrote /root/vpn-exits/airvpn.env (root only) with: "
                 "VPN_SERVICE_PROVIDER, WIREGUARD_PRIVATE_KEY",
             ) as writer:
            said = netexits.add_provider_from_ref("airvpn", "pass:vpn/airvpn")
        # The resolved config reached the helper, not the return value.
        self.assertEqual(writer.call_args.args[0], "airvpn")
        self.assertEqual(writer.call_args.args[1], config)
        self.assertNotIn("secret", said)
        self.assertIn("airvpn.env", said)


if __name__ == "__main__":
    unittest.main()
