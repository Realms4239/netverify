"""Tests that each allowlisted command returns the correct verdict.

The point of these is that the MCP surface must not be able to answer
"healthy" about something that is not. Each negative fixture corresponds to a
real failure mode the flagship's parsers were written to catch.
"""

import unittest

from server import scope
from server.verify import verify
from tests import fixtures as fx


def run(command, output, **arguments):
    """Validate then verify, the same path the MCP tool takes."""
    return verify(scope.validate(command, output, **arguments))


class TestInterface(unittest.TestCase):
    def test_up_interface_passes(self):
        result = run("srl_interface_brief", fx.SRL_INTERFACE_UP, interface="ethernet-1/1")
        self.assertTrue(result["ok"], result["reasons"])

    def test_down_interface_fails(self):
        result = run("srl_interface_brief", fx.SRL_INTERFACE_DOWN, interface="ethernet-1/1")
        self.assertFalse(result["ok"])
        self.assertTrue(result["reasons"])

    def test_absent_interface_fails(self):
        """A name that is not in the table must not pass by default."""
        result = run("srl_interface_brief", fx.SRL_INTERFACE_UP, interface="ethernet-9/9")
        self.assertFalse(result["ok"])


class TestOspf(unittest.TestCase):
    def test_full_adjacency_passes(self):
        result = run("srl_ospf_neighbor", fx.SRL_OSPF_FULL, neighbor_router_id="10.1.12.2")
        self.assertTrue(result["ok"], result["reasons"])

    def test_exstart_fails(self):
        result = run("srl_ospf_neighbor", fx.SRL_OSPF_NOT_FULL, neighbor_router_id="10.1.12.2")
        self.assertFalse(result["ok"])

    def test_full_but_bad_neighbour_fails(self):
        """The `full` state alone is not enough if a bad neighbour exists."""
        poisoned = fx.SRL_OSPF_FULL.replace("Bad Neighbors : 0", "Bad Neighbors : 1")
        result = run("srl_ospf_neighbor", poisoned, neighbor_router_id="10.1.12.2")
        self.assertFalse(result["ok"])


class TestBgpNeighbor(unittest.TestCase):
    def test_established_passes(self):
        result = run(
            "srl_bgp_neighbor_detail",
            fx.SRL_BGP_ESTABLISHED,
            peer_ip="10.1.13.2",
            remote_as="65002",
        )
        self.assertTrue(result["ok"], result["reasons"])

    def test_active_peer_fails(self):
        result = run(
            "srl_bgp_neighbor_detail",
            fx.SRL_BGP_ACTIVE,
            peer_ip="10.1.13.2",
            remote_as="65002",
        )
        self.assertFalse(result["ok"])

    def test_wrong_expected_as_fails(self):
        """The peer is up, but not the AS the lab declared.

        This is the case that makes the tool worth having: a session that is
        Established against the *wrong* neighbour looks healthy on the device.
        """
        result = run(
            "srl_bgp_neighbor_detail",
            fx.SRL_BGP_ESTABLISHED,
            peer_ip="10.1.13.2",
            remote_as="65099",
        )
        self.assertFalse(result["ok"])


class TestFrrBgpSummary(unittest.TestCase):
    def test_healthy_summary_passes(self):
        result = run("frr_bgp_summary", fx.FRR_SUMMARY_HEALTHY)
        self.assertTrue(result["ok"], result["reasons"])

    def test_zero_prefix_count_fails(self):
        result = run("frr_bgp_summary", fx.FRR_SUMMARY_UNHEALTHY)
        self.assertFalse(result["ok"])
        self.assertIn("pfxRcd", " ".join(result["reasons"]))

    def test_empty_peer_map_is_not_reported_healthy(self):
        """The dangerous case: zero peers must never read as healthy."""
        result = run("frr_bgp_summary", fx.FRR_SUMMARY_EMPTY)
        self.assertFalse(result["ok"])

    def test_malformed_json_is_labelled_an_input_error(self):
        """A bad capture must not be reported as a network fault."""
        result = run("frr_bgp_summary", fx.FRR_SUMMARY_MALFORMED)
        self.assertFalse(result["ok"])
        self.assertIn("input error", " ".join(result["reasons"]))


class TestRoute(unittest.TestCase):
    def test_installed_route_passes(self):
        result = run("srl_route_detail", fx.SRL_ROUTE_INSTALLED, prefix="10.0.0.2/32")
        self.assertTrue(result["ok"], result["reasons"])

    def test_missing_route_fails_despite_echoed_prefix(self):
        """The defect the upstream parser exists for.

        The prefix appears in the output because the device echoes the query, so
        a substring check would wrongly pass. Asserted as a precondition so the
        reason this test exists stays visible.
        """
        self.assertIn("10.0.0.2/32", fx.SRL_ROUTE_MISSING, "precondition: prefix is echoed")
        result = run("srl_route_detail", fx.SRL_ROUTE_MISSING, prefix="10.0.0.2/32")
        self.assertFalse(result["ok"])
        self.assertTrue(result["reasons"])

    def test_failure_reason_quotes_the_prefix_when_no_row_is_found(self):
        """The branch that has no table row at all should name the prefix.

        This is the branch that produces a diagnosable reason: the device
        echoed the query and then showed nothing recognisable as a route.
        """
        echoed_only = '{ "command": "show ... prefix 10.0.0.2/32 detail" }\nnothing here\n'
        result = run("srl_route_detail", echoed_only, prefix="10.0.0.2/32")
        self.assertFalse(result["ok"])
        self.assertIn("10.0.0.2/32", " ".join(result["reasons"]))

    def test_response_always_identifies_the_prefix_checked(self):
        """Even when the reason is generic, the response says what was checked.

        Upstream's `no entries found` branch returns a fixed string with no
        prefix in it, so the prefix has to be recoverable from the `check` and
        `arguments` fields instead. Without this, an agent handed a failure could
        not tell which of several route checks went wrong.
        """
        result = run("srl_route_detail", fx.SRL_ROUTE_MISSING, prefix="10.0.0.2/32")
        self.assertFalse(result["ok"])
        self.assertIn("10.0.0.2/32", result["check"])
        self.assertEqual(result["arguments"]["prefix"], "10.0.0.2/32")


class TestPing(unittest.TestCase):
    def test_reachable_passes(self):
        self.assertTrue(run("ping", fx.PING_OK)["ok"])

    def test_total_loss_fails(self):
        self.assertFalse(run("ping", fx.PING_TOTAL_LOSS)["ok"])


class TestResultShape(unittest.TestCase):
    def test_every_result_has_the_same_keys(self):
        """A stable shape is what lets an agent branch on it reliably."""
        cases = [
            run("frr_bgp_summary", fx.FRR_SUMMARY_HEALTHY),
            run("frr_bgp_summary", fx.FRR_SUMMARY_EMPTY),
            run("ping", fx.PING_OK),
            run("srl_route_detail", fx.SRL_ROUTE_MISSING, prefix="10.0.0.2/32"),
        ]
        for result in cases:
            with self.subTest(command=result["command_id"]):
                for key in ("ok", "check", "observed", "reasons", "command_id"):
                    self.assertIn(key, result)
                self.assertIsInstance(result["reasons"], list)

    def test_passing_result_has_no_reasons(self):
        result = run("ping", fx.PING_OK)
        self.assertEqual(result["reasons"], [])

    def test_reasons_are_redacted(self):
        """A reason quotes device output, so it is an exfiltration path."""
        result = run(
            "srl_route_detail",
            fx.SRL_ROUTE_INSTALLED + "\n password=hunter2\n",
            prefix="9.9.9.9/32",
        )
        self.assertNotIn("hunter2", " ".join(result["reasons"]))


if __name__ == "__main__":
    unittest.main()
