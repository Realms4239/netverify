"""Tests for the aggregate and comparative capabilities.

These are the capabilities most likely to be quietly wrong, because a wrong
answer from `compare_states` is a *confident* wrong answer rather than a
visible failure. Someone reviews a change, the diff says "unchanged", and the
interface that regressed is never looked at.
"""

import unittest

from netverify import COMMANDS, compare_states, self_check, synthesize_health, verify_many

PING_OK = "3 packets transmitted, 3 received, 0% packet loss"
PING_LOSS = "3 packets transmitted, 0 received, 100% packet loss"


def cap(*entries):
    return list(entries)


def interface(name, state):
    return {
        "command": "srl_interface_brief",
        "output": f"| {name} | enable | {state} |",
        "interface": name,
    }


class TestSynthesizeHealth(unittest.TestCase):
    def test_all_passing_is_healthy(self):
        health = synthesize_health(verify_many(cap({"command": "ping", "output": PING_OK})))
        self.assertEqual(health["status"], "healthy")
        self.assertEqual(health["passed"], 1)
        self.assertIsNone(health["worst"])

    def test_a_network_fault_is_unhealthy(self):
        health = synthesize_health(verify_many(cap({"command": "ping", "output": PING_LOSS})))
        self.assertEqual(health["status"], "unhealthy")
        self.assertEqual(health["failed"], 1)
        self.assertIsNotNone(health["worst"])

    def test_unreadable_output_is_indeterminate_not_healthy(self):
        """The dangerous distinction.

        Reporting "healthy" because no check *failed* would let a caller
        conclude the network is fine on the evidence of text that could not be
        read at all.
        """
        health = synthesize_health(
            verify_many(cap({"command": "frr_bgp_summary", "output": "not json"}))
        )
        self.assertEqual(health["status"], "indeterminate")
        self.assertEqual(health["input_errors"], 1)
        self.assertEqual(health["failed"], 0)

    def test_a_fault_outranks_an_input_error(self):
        health = synthesize_health(
            verify_many(
                cap(
                    {"command": "frr_bgp_summary", "output": "not json"},
                    {"command": "ping", "output": PING_LOSS},
                )
            )
        )
        self.assertEqual(health["status"], "unhealthy")
        self.assertEqual(health["input_errors"], 1)
        self.assertEqual(health["failed"], 1)

    def test_refusals_alone_give_partially_checked(self):
        health = synthesize_health(verify_many(cap({"command": "configure", "output": "x"})))
        self.assertEqual(health["status"], "partially_checked")

    def test_empty_batch_is_healthy_with_nothing_checked(self):
        """Degenerate but honest: zero checks is not a fault."""
        health = synthesize_health(verify_many([]))
        self.assertEqual(health["status"], "healthy")
        self.assertEqual(health["checked"], 0)

    def test_worst_offender_carries_its_own_reason(self):
        """Actionable without a second call - that is the point of `worst`."""
        health = synthesize_health(verify_many(cap({"command": "ping", "output": PING_LOSS})))
        self.assertTrue(health["worst"]["reasons"])


class TestCompareStates(unittest.TestCase):
    def test_identical_captures_show_no_change(self):
        diff = compare_states(
            verify_many(cap({"command": "ping", "output": PING_OK})),
            verify_many(cap({"command": "ping", "output": PING_OK})),
        )
        self.assertEqual(diff["regressions"], [])
        self.assertEqual(diff["unchanged"], 1)

    def test_a_pass_becoming_a_failure_is_a_regression(self):
        diff = compare_states(
            verify_many(cap({"command": "ping", "output": PING_OK})),
            verify_many(cap({"command": "ping", "output": PING_LOSS})),
        )
        self.assertEqual(len(diff["regressions"]), 1)
        self.assertEqual(diff["regressions"][0]["change"], "regressed")
        self.assertTrue(diff["regressions"][0]["verdict"]["reasons"])

    def test_a_failure_becoming_a_pass_is_a_recovery(self):
        diff = compare_states(
            verify_many(cap({"command": "ping", "output": PING_LOSS})),
            verify_many(cap({"command": "ping", "output": PING_OK})),
        )
        self.assertEqual(len(diff["recoveries"]), 1)
        self.assertEqual(diff["regressions"], [])

    def test_arguments_are_part_of_the_identity(self):
        """Two different interfaces are not the same check.

        A diff keyed on the command name alone would call an interface change
        "unchanged" - confidently, and wrongly.
        """
        diff = compare_states(
            verify_many(cap(interface("ethernet-1/1", "up"))),
            verify_many(cap(interface("ethernet-1/2", "down"))),
        )
        self.assertEqual(diff["unchanged"], 0)
        self.assertEqual([r["change"] for r in diff["regressions"]], ["added"])
        self.assertEqual([r["change"] for r in diff["removed"]], ["removed"])

    def test_same_interface_going_down_is_a_regression(self):
        """The case the identity rule must not break."""
        diff = compare_states(
            verify_many(cap(interface("ethernet-1/1", "up"))),
            verify_many(cap(interface("ethernet-1/1", "down"))),
        )
        self.assertEqual([r["change"] for r in diff["regressions"]], ["regressed"])
        self.assertEqual(diff["removed"], [])

    def test_a_dropped_check_is_reported_as_removed(self):
        diff = compare_states(
            verify_many(cap({"command": "ping", "output": PING_OK}, interface("e1", "up"))),
            verify_many(cap({"command": "ping", "output": PING_OK})),
        )
        self.assertEqual(len(diff["removed"]), 1)
        self.assertIn("srl_interface_brief", diff["removed"][0]["check"])

    def test_output_change_with_same_outcome_is_not_a_regression(self):
        """Only verdicts are compared, not raw text.

        A device reformatting its table between captures is not a network event,
        and reporting it as one would fill a change review with noise.
        """
        diff = compare_states(
            verify_many(cap({"command": "ping", "output": PING_OK})),
            verify_many(cap({"command": "ping", "output": "3 received, 0% loss"})),
        )
        self.assertEqual(diff["regressions"], [])
        self.assertEqual(diff["unchanged"], 1)

    def test_refusals_do_not_corrupt_the_comparison(self):
        mixed = cap(
            {"command": "ping", "output": PING_OK},
            {"command": "configure", "output": "x"},
        )
        diff = compare_states(
            verify_many(mixed),
            verify_many(cap({"command": "ping", "output": PING_OK})),
        )
        self.assertEqual(diff["unchanged"], 1)


class TestSelfCheck(unittest.TestCase):
    def test_guards_actually_hold(self):
        """The whole point: a self-report that is evidence, not assertion."""
        report = self_check()
        self.assertTrue(
            all(report["guards_verified"].values()),
            f"a guard does not hold: {report['guards_verified']}",
        )

    def test_reports_the_real_registry(self):
        report = self_check()
        self.assertEqual(report["commands"]["count"], len(COMMANDS))
        self.assertEqual(set(report["commands"]["ids"]), {s.id for s in COMMANDS})

    def test_does_not_claim_to_have_verified_parity(self):
        """It cannot verify parity without the network, so it must not say it did."""
        vendored = self_check()["vendored_parser"]
        self.assertFalse(vendored["parity_verified_here"])
        self.assertIn("not verified", vendored["parity_note"].lower())

    def test_version_agrees_with_the_package(self):
        """`integrity` duplicates the version to dodge a circular import.

        That duplication is only safe because something checks it. This is that.
        """
        import netverify
        from netverify import integrity

        self.assertEqual(netverify.__version__, integrity.__version__)

    def test_vendored_digest_is_present_and_pinned(self):
        vendored = self_check()["vendored_parser"]
        self.assertTrue(vendored["present"])
        self.assertEqual(len(vendored["sha256"]), 64)
        self.assertEqual(len(vendored["pinned_commit"]), 40)


if __name__ == "__main__":
    unittest.main()
