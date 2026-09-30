"""Tests for the registry and the scope rules it drives.

The registry is the seam that makes the library expandable, so these tests are
mostly about the invariants that let it be trusted: no command can be a write,
and every advertised command is actually implemented and reachable.
"""

import inspect
import unittest

from netverify import COMMANDS, MAX_BYTES, ScopeError, describe_all, get, validate, verify
from netverify.registry import is_read_only, mutating_verbs_in
from tests import fixtures as fx


class TestRegistryIntegrity(unittest.TestCase):
    def test_no_command_contains_a_mutating_verb(self):
        """The structural guard against a command silently becoming a write.

        Uses the shared `is_read_only` implementation so the test, a future
        lint rule, and a reader checking the published contract cannot disagree
        about what the guard catches.
        """
        for spec in COMMANDS:
            with self.subTest(command=spec.id):
                self.assertTrue(
                    is_read_only(f"{spec.id} {spec.command}"),
                    f"{spec.id} contains a mutating verb: "
                    f"{mutating_verbs_in(f'{spec.id} {spec.command}')}",
                )

    def test_mutating_guard_actually_catches_a_write(self):
        """Negative control for the guard above.

        A guard that cannot fail is not a guard. Without this, someone could
        weaken MUTATING_VERBS into uselessness and the suite would still pass.
        """
        self.assertFalse(is_read_only("configure terminal"))
        self.assertIn("configure", mutating_verbs_in("configure terminal"))
        self.assertIn("commit", mutating_verbs_in("commit candidate"))

    def test_guard_does_not_fire_on_suffix_forms(self):
        """'installed' and 'saves' are not writes.

        Word boundaries are what make this true, and this is the test that keeps
        them. A guard that flags correct text gets ignored, which is worse than
        no guard.
        """
        for benign in (
            "whether a route is genuinely installed",
            "the peer saves state",
            "clear description of the interface",
        ):
            with self.subTest(text=benign):
                self.assertTrue(is_read_only(benign))

    def test_guard_is_for_cli_text_not_prose(self):
        """Documents the guard's one real limitation, deliberately.

        Some verbs are ambiguous by nature: 'start' is a write in 'start bgp'
        and an ordinary English word in 'start time of the session'. Word
        boundaries cannot separate those, and dropping 'start' from the list to
        make prose pass would trade a real safety check for a cosmetic one.

        So the contract is: this guard is applied to CLI text, never to a
        summary. The registry test above enforces that on every registered
        command, and this test pins the limitation so nobody later mistakes it
        for a bug.
        """
        self.assertIn("start", mutating_verbs_in("start bgp"))
        self.assertIn(
            "start",
            mutating_verbs_in("start time of the session"),
            "known, documented ambiguity",
        )

    def test_every_command_is_callable(self):
        for spec in COMMANDS:
            with self.subTest(command=spec.id):
                self.assertTrue(callable(spec.check))

    def test_checker_signature_matches_declared_arguments(self):
        """A required argument no checker reads would make a call impossible."""
        for spec in COMMANDS:
            params = set(inspect.signature(spec.check).parameters) - {"output"}
            with self.subTest(command=spec.id):
                self.assertEqual(
                    params,
                    set(spec.required) | set(spec.optional),
                    f"{spec.id} declares arguments its checker does not accept",
                )

    def test_registry_ids_are_sorted_and_unique(self):
        """Deterministic order is what lets clients cache the tool list."""
        ids = [spec.id for spec in COMMANDS]
        self.assertEqual(ids, sorted(ids), "COMMANDS must be sorted by id")
        self.assertEqual(len(ids), len(set(ids)), "duplicate command id")

    def test_describe_all_covers_every_command(self):
        described = {entry["id"] for entry in describe_all()}
        self.assertEqual(described, {spec.id for spec in COMMANDS})

    def test_describe_all_marks_everything_read_only(self):
        for entry in describe_all():
            with self.subTest(command=entry["id"]):
                self.assertTrue(entry["read_only"])
                self.assertFalse(entry["open_world"])

    def test_get_returns_none_for_unknown(self):
        self.assertIsNone(get("nope"))


class TestScopeRules(unittest.TestCase):
    def test_unknown_command_is_refused(self):
        with self.assertRaises(ScopeError) as caught:
            validate("sudo_rm_rf", "output")
        self.assertIn("not in the allowlist", str(caught.exception))

    def test_refusal_lists_the_legal_ids(self):
        """An agent that cannot enumerate the commands cannot use the tool."""
        with self.assertRaises(ScopeError) as caught:
            validate("nope", "x")
        for spec in COMMANDS:
            self.assertIn(spec.id, str(caught.exception))

    def test_raw_cli_string_is_refused(self):
        with self.assertRaises(ScopeError):
            validate("show interface brief", "text")

    def test_missing_required_argument_is_named(self):
        with self.assertRaises(ScopeError) as caught:
            validate("srl_interface_brief", "text")
        self.assertIn("requires argument(s) ['interface']", str(caught.exception))

    def test_unexpected_argument_is_refused_not_dropped(self):
        with self.assertRaises(ScopeError) as caught:
            validate("srl_interface_brief", "text", interface="e1/1", oif="x")
        self.assertIn("does not accept", str(caught.exception))

    def test_wrong_type_is_refused(self):
        with self.assertRaises(ScopeError):
            validate("srl_interface_brief", 12345)
        with self.assertRaises(ScopeError):
            validate("srl_interface_brief", "text", interface=7)

    def test_empty_required_argument_is_refused(self):
        with self.assertRaises(ScopeError):
            validate("srl_interface_brief", "text", interface="   ")

    def test_oversize_output_is_refused(self):
        with self.assertRaises(ScopeError) as caught:
            validate("ping", "x" * (MAX_BYTES + 1))
        self.assertIn("cap", str(caught.exception))

    def test_valid_request_is_normalised(self):
        request = validate("srl_interface_brief", "text", interface="  ethernet-1/1  ")
        self.assertEqual(request["arguments"]["interface"], "ethernet-1/1")
        self.assertEqual(request["platform"], "srl")


class TestSanitizationIsAlwaysOn(unittest.TestCase):
    def test_no_reason_in_the_corpus_carries_a_canary_secret(self):
        """Proves the sanitizer is load-bearing on the path every reason takes.

        Rather than asserting a marker string, this walks the real fixtures
        with a canary credential and asserts the secret never reaches a reason.
        A checker that forgot to redact fails here.
        """
        canary = "sup3rs3cr3tcanary"
        secret = f" password={canary}\n"
        cases = [
            ("srl_route_detail", fx.SRL_ROUTE_MISSING + secret, {"prefix": "10.0.0.2/32"}),
            ("frr_bgp_summary", fx.FRR_SUMMARY_UNHEALTHY + secret, {}),
            ("ping", fx.PING_TOTAL_LOSS + secret, {}),
            ("srl_interface_brief", fx.SRL_INTERFACE_DOWN + secret, {"interface": "e"}),
        ]
        for command, output, arguments in cases:
            with self.subTest(command=command):
                verdict = verify(command, output, **arguments)
                self.assertNotIn(canary, " ".join(verdict.reasons))
                self.assertNotIn(canary, verdict.observed)

    def test_outcome_separates_input_error_from_failure(self):
        """A malformed capture must never look like a broken router."""
        verdict = verify("frr_bgp_summary", fx.FRR_SUMMARY_MALFORMED)
        self.assertFalse(verdict.ok)
        self.assertEqual(verdict.outcome.value, "input_error")

    def test_network_failure_outcome_is_fail(self):
        verdict = verify("frr_bgp_summary", fx.FRR_SUMMARY_UNHEALTHY)
        self.assertFalse(verdict.ok)
        self.assertEqual(verdict.outcome.value, "fail")

    def test_verdict_dict_carries_the_outcome(self):
        payload = verify("ping", fx.PING_OK).to_dict()
        self.assertEqual(payload["outcome"], "pass")
        self.assertEqual(payload["reasons"], [])


if __name__ == "__main__":
    unittest.main()
