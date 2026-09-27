"""Tests for the scope layer: the tool's actual security boundary.

Written against stdlib `unittest` so the suite runs with no third-party
install. `pytest` also collects these unchanged, which is what CI uses.

Each test names the attack or defect it prevents from returning.
"""

import unittest

from server import scope
from server.scope import ScopeError

# Verbs that would change device state. None may appear in the allowlist.
MUTATING_VERBS = (
    "configure",
    "delete",
    "commit",
    "set /",
    "reload",
    "write",
    "clear",
    "reset",
    "install",
    "copy",
    "start",
    "stop",
    "no shutdown",
    "rollback",
    "save",
)


class TestAllowlistIsClosed(unittest.TestCase):
    def test_unknown_command_id_is_rejected(self):
        with self.assertRaises(ScopeError) as caught:
            scope.validate("sudo_rm_rf", "output")
        self.assertIn("not in the allowlist", str(caught.exception))

    def test_raw_cli_string_is_rejected(self):
        """A caller must pass an id, not a command line.

        If free-form commands were accepted, 'allow only show commands' would be
        a regex that a determined prompt could talk its way around.
        """
        with self.assertRaises(ScopeError):
            scope.validate("show interface brief", "text")

    def test_mutating_command_is_rejected(self):
        for verb in ("configure", "commit", "delete", "reload"):
            with self.subTest(verb=verb):
                with self.assertRaises(ScopeError):
                    scope.validate(verb, "text")

    def test_no_allowlisted_command_carries_a_mutating_verb(self):
        """Structural guard: the allowlist cannot drift into writes.

        This is the test that would catch someone adding 'configure' to
        ALLOWED_COMMANDS months from now.
        """
        for command_id, spec in scope.ALLOWED_COMMANDS.items():
            with self.subTest(command_id=command_id):
                blob = f"{command_id} {spec['command']}".lower()
                for verb in MUTATING_VERBS:
                    self.assertNotIn(verb, blob, f"{command_id} contains mutating verb {verb!r}")

    def test_every_allowlisted_command_has_a_handler(self):
        from server.verify import _HANDLERS

        for command_id in scope.ALLOWED_COMMANDS:
            with self.subTest(command_id=command_id):
                self.assertIn(command_id, _HANDLERS)


class TestArgumentValidation(unittest.TestCase):
    def test_missing_required_argument_is_named(self):
        with self.assertRaises(ScopeError) as caught:
            scope.validate("srl_interface_brief", "text")
        self.assertIn("requires argument(s) ['interface']", str(caught.exception))

    def test_unexpected_argument_is_rejected_not_dropped(self):
        """Silently dropping an unknown argument would let an agent believe it
        constrained something it did not."""
        with self.assertRaises(ScopeError) as caught:
            scope.validate("srl_interface_brief", "text", interface="e1/1", oif="x")
        self.assertIn("does not accept", str(caught.exception))

    def test_wrong_type_is_rejected(self):
        with self.assertRaises(ScopeError):
            scope.validate("srl_interface_brief", 12345)
        with self.assertRaises(ScopeError):
            scope.validate("srl_interface_brief", "text", interface=7)

    def test_empty_required_argument_is_rejected(self):
        with self.assertRaises(ScopeError):
            scope.validate("srl_interface_brief", "text", interface="   ")

    def test_valid_request_is_normalised(self):
        request = scope.validate("srl_interface_brief", "text", interface="  ethernet-1/1  ")
        self.assertEqual(request["command_id"], "srl_interface_brief")
        self.assertEqual(request["arguments"]["interface"], "ethernet-1/1")
        self.assertEqual(request["platform"], "srl")


class TestOutputCap(unittest.TestCase):
    def test_oversize_output_is_rejected(self):
        with self.assertRaises(ScopeError) as caught:
            scope.validate("ping", "x" * (scope.MAX_OUTPUT_BYTES + 1))
        self.assertIn("cap", str(caught.exception))

    def test_output_just_under_the_cap_is_accepted(self):
        request = scope.validate("ping", "x" * (scope.MAX_OUTPUT_BYTES - 1))
        self.assertEqual(request["command_id"], "ping")


class TestRedaction(unittest.TestCase):
    def test_credential_assignment_is_scrubbed(self):
        for secret in ("password=hunter2", "secret: s3cr3t", "token=abc123"):
            with self.subTest(secret=secret):
                self.assertNotIn(
                    secret.split("=")[-1].split(":")[-1].strip(),
                    scope.redact(f"device said {secret}"),
                )

    def test_private_key_block_is_scrubbed(self):
        blob = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAxyz\n-----END RSA PRIVATE KEY-----"
        self.assertNotIn("MIIEowIBAAKCAQEAxyz", scope.redact(blob))

    def test_redaction_happens_before_truncation(self):
        """A secret straddling the cut must not survive as a fragment.

        Redacting after truncating would leave the head of the secret visible.
        """
        padding = "a" * (scope.MAX_REASON_CHARS - 5)
        text = f"{padding} password=hunter2"
        self.assertNotIn("hunter2", scope.redact(text))

    def test_long_text_is_truncated_with_a_notice(self):
        out = scope.redact("x" * 1000)
        self.assertIn("truncated", out)
        self.assertLess(len(out), 1000)


if __name__ == "__main__":
    unittest.main()
