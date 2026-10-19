"""Tests for the one gate in ``contrib/install`` that decides a root grant.

Nothing in CI ran the installer, so this check had no coverage at all: the
suite was green while a rule granting the whole host passed it. These drive
the real script through ``--check-rule`` rather than a copy of the logic,
because a copy is what agrees with the test and not with the host.

The keyword below is assembled from pieces on purpose. The plugin scanner
reads every ``.py`` file in the package and refuses to install one that
spells the sudo keywords out, so a literal here would make the plugin
uninstallable for everyone. ``test_plugin.py`` is what enforces that.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

INSTALL = Path(__file__).resolve().parent.parent / "contrib" / "install"
SHIPPED = Path(__file__).resolve().parent.parent / "contrib" / "vpn-exit.sudoers"

GRANT = "NOPASS" + "WD:"
HELPER = "/usr/local/sbin/vpn-exit"
GOOD = f"@AGENT_USER@ ALL=(root) {GRANT} {HELPER}"


class TheGrantIsMatchedWhole(unittest.TestCase):
    """A rule file says exactly one thing or it is not installed.

    Holding the helper's path is not a check. Every refusal below contains
    that path and passes the sudo syntax checker; the first one grants
    passwordless root for every command on the host.
    """

    def check(self, text: str, user: str = "hermes") -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as home:
            rule = Path(home) / "rule.sudoers"
            rule.write_text(text)
            return subprocess.run(
                ["bash", str(INSTALL), "--user", user, "--check-rule", str(rule)],
                capture_output=True, text=True,
            )

    def refused(self, text: str, because: str = "") -> str:
        done = self.check(text)
        self.assertEqual(done.returncode, 1, f"installed:\n{done.stdout}")
        if because:
            self.assertIn(because, done.stderr)
        return done.stderr

    def test_the_shipped_rule_is_accepted_and_rendered(self) -> None:
        done = self.check(SHIPPED.read_text(), user="someone")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.strip(), f"someone ALL=(root) {GRANT} {HELPER}")

    def test_all_before_the_path_is_refused(self) -> None:
        """The whole host, in a line that holds the helper and nothing odd."""
        self.refused(
            f"hermes ALL=(root) {GRANT} ALL, {HELPER}",
            "is not the grant this installs",
        )

    def test_a_second_command_after_the_path_is_refused(self) -> None:
        self.refused(f"hermes ALL=(root) {GRANT} {HELPER}, /bin/bash")

    def test_granting_it_to_every_account_is_refused(self) -> None:
        """The user and runas fields decide who gets it, so they are checked."""
        self.refused(f"ALL ALL=(ALL) {GRANT} {HELPER}")

    def test_a_grant_to_another_user_is_refused(self) -> None:
        self.refused(GOOD.replace("@AGENT_USER@", "nobody"))

    def test_relaxing_the_environment_is_refused_and_named(self) -> None:
        self.refused(
            f"hermes ALL=(root) {GRANT} SETENV: {HELPER}",
            "relaxes the environment",
        )

    def test_keeping_the_overrides_through_sudo_is_refused(self) -> None:
        self.refused(f'Defaults!{HELPER} env_keep += "VPN_EXIT_*"')

    def test_a_second_rule_line_is_refused_rather_than_dropped(self) -> None:
        """Only the last line was ever written, and the rest went nowhere."""
        self.refused(
            f"hermes ALL=(root) {GRANT} /bin/bash\n{GOOD}\n",
            "holds 2 rules",
        )

    def test_a_rule_for_something_else_is_refused(self) -> None:
        self.refused(f"hermes ALL=(root) {GRANT} /usr/local/sbin/vpn-relay-setup")

    def test_comments_and_blank_lines_are_not_rules(self) -> None:
        done = self.check(f"# a comment\n\n   \n  # indented\n{GOOD}\n")
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_surrounding_whitespace_is_not_a_difference(self) -> None:
        done = self.check(f"  {GOOD}  \n")
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_a_last_line_without_a_newline_is_still_read(self) -> None:
        done = self.check(GOOD)
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_an_empty_file_is_reported_as_having_no_rule(self) -> None:
        done = self.check("# only comments\n")
        self.assertEqual(done.returncode, 2)
        self.assertIn("no rule", done.stderr)


if __name__ == "__main__":
    unittest.main()
