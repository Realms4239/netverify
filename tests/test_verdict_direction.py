"""Which direction each verdict points, for the captures that are only *near* valid.

The distinction this file holds is the one the README calls the most dangerous
answer available, and its mirror image:

- Answering "healthy" about a router that is not healthy. Never.
- Answering "down" about a link the capture never showed. Also never, and this one
  is easier to do by accident: an operator pastes the slice of
  `show interface brief` that scrolled past, the interface they care about is above
  it, and a verifier that reads absence as failure pages someone about a healthy
  link at 3am.

Both directions are wrong, and a checker gets them right only by asking whether the
*capture* can answer the question before asking what the answer is.

That question is subtle enough that the first attempt was wrong in the other
direction. Presence was implemented as "is this interface mentioned anywhere in the
text", which passed `! ethernet-1/1 is down for maintenance` - a comment, with no
table and no state - and produced the fault claim "interface ethernet-1/1 is not
admin-enabled and up" from text containing no interface state at all. So presence
is now the *row*, mirroring the opening of the parser that will read it, and this
file pins both directions for every subject-taking command in the registry.

The two tables are the contract:

- `GENUINE_FAULTS` must be `fail`. Each describes a definite problem, and
  `input_error` would excuse it as a problem with the capture.
- `UNREADABLE` must be `input_error`. Each cannot answer the question, and `fail`
  would invent a fault.
"""

import unittest

from netverify import verify

#: The device rendered a table and the answer in it is not the healthy one.
GENUINE_FAULTS = [
    (
        "interface disabled and down",
        "srl_interface_brief",
        "| Interface    | Admin   | Oper |\n| ethernet-1/1 | disable | down |\n",
        {"interface": "ethernet-1/1"},
    ),
    (
        "interface up but admin disabled",
        "srl_interface_brief",
        "| ethernet-1/1 | disable | up |\n",
        {"interface": "ethernet-1/1"},
    ),
    (
        "sub-interface row, disabled",
        "srl_interface_brief",
        "| ethernet-1/1.0 | disable | down |\n",
        {"interface": "ethernet-1/1"},
    ),
    (
        "OSPF neighbour stuck in exstart",
        "srl_ospf_neighbor",
        "| ethernet-1/1.0 | 10.1.12.2 | exstart | 0 | 0 |\n",
        {"neighbor_router_id": "10.1.12.2"},
    ),
    (
        "OSPF neighbour full but with bad neighbours",
        "srl_ospf_neighbor",
        "| ethernet-1/1.0 | 10.1.12.2 | full | 3 | 0 |\n",
        {"neighbor_router_id": "10.1.12.2"},
    ),
    (
        "BGP peer present but idle",
        "srl_bgp_neighbor_detail",
        "Peer : 10.1.13.1, remote AS : 65013, local AS : 65001\n  Session state : Idle\n",
        {"peer_ip": "10.1.13.1", "remote_as": "65013"},
    ),
    (
        "BGP peer established with the wrong remote AS",
        "srl_bgp_neighbor_detail",
        "Peer : 10.1.13.1, remote AS : 65999, local AS : 65001\n  Session state : Established\n",
        {"peer_ip": "10.1.13.1", "remote_as": "65013"},
    ),
    (
        "route absent and the device says so",
        "srl_route_detail",
        "A:admin@leaf1# show network-instance default route-table\n"
        "No entries found for prefix 10.20.30.0/24\n",
        {"prefix": "10.20.30.0/24"},
    ),
    (
        "route present but unresolved",
        "srl_route_detail",
        "Prefix          Next hop\n10.20.30.0/24   unresolved\n",
        {"prefix": "10.20.30.0/24"},
    ),
    (
        "ping lost a packet of the three it sent",
        "ping",
        "3 packets transmitted, 2 received, 33.3333% packet loss\n",
        {},
    ),
    (
        "ping lost every packet",
        "ping",
        "3 packets transmitted, 0 received, 100% packet loss\n",
        {},
    ),
]

#: The capture cannot answer the question, so neither can the verifier.
UNREADABLE = [
    (
        "the interface appears only in a comment",
        "srl_interface_brief",
        "! ethernet-1/1 is down for maintenance\n",
        {"interface": "ethernet-1/1"},
    ),
    (
        "the interface appears only in a syslog line",
        "srl_interface_brief",
        "2026-09-27T10:00:00Z NOTICE mgmt: ethernet-1/1 flapped\n",
        {"interface": "ethernet-1/1"},
    ),
    (
        "the neighbour id appears only in a remark",
        "srl_ospf_neighbor",
        "remark: 10.1.12.2 decommissioned, table follows\n| ethernet-1/1.0 | 10.9.9.9 | full |\n",
        {"neighbor_router_id": "10.1.12.2"},
    ),
    (
        "the peer ip appears only in a shell comment",
        "srl_bgp_neighbor_detail",
        "# grep 10.1.13.1 /etc/frr/frr.conf\n",
        {"peer_ip": "10.1.13.1", "remote_as": "65013"},
    ),
    (
        "the prefix appears only as the echoed query",
        "srl_route_detail",
        "A:admin@leaf1# show route-table prefix 10.20.30.0/24\n\n",
        {"prefix": "10.20.30.0/24"},
    ),
]


class TestGenuineFaultsAreNotExcused(unittest.TestCase):
    """Tightening an absence check trades one error for another, so pin this side."""

    def test_each_capture_is_reported_as_a_fault(self):
        for label, command, output, arguments in GENUINE_FAULTS:
            with self.subTest(case=label, command=command):
                verdict = verify(command, output, audit=None, **arguments)
                self.assertFalse(verdict.ok, f"{label}: reported healthy")
                self.assertEqual(
                    verdict.outcome.value,
                    "fail",
                    f"{label}: reported {verdict.outcome.value!r}, which excuses a real "
                    f"fault as a problem with the capture",
                )
                self.assertTrue(
                    verdict.reasons,
                    f"{label}: a failure with no stated reason is unactionable",
                )

    def test_a_device_saying_it_has_no_such_route_is_a_fault_not_an_input_error(self):
        """The ordering a tightened presence test breaks if written carelessly.

        "No entries found" is the device *answering*: it rendered the table and the
        prefix is not in it. There is no route row to point at, so a presence test
        that runs before this one reads a rendered-but-empty table as an unreadable
        capture and tells the operator their paste was wrong - while a route is
        genuinely missing. The classification lives here rather than in the parser
        because the parser is vendored and pinned byte-for-byte to upstream.
        """
        verdict = verify(
            "srl_route_detail",
            "No entries found for prefix 10.20.30.0/24\n",
            audit=None,
            prefix="10.20.30.0/24",
        )

        self.assertEqual(verdict.outcome.value, "fail")

    def test_a_ping_is_read_as_a_ping(self):
        """The one command with no subject, so presence is the output's shape.

        An empty capture and a total loss both make `ping_succeeded` return False,
        and only one of them is a network fault.
        """
        self.assertEqual(verify("ping", "", audit=None).outcome.value, "input_error")
        self.assertEqual(verify("ping", "   \n\n", audit=None).outcome.value, "input_error")
        self.assertEqual(
            verify(
                "ping", "3 packets transmitted, 0 received, 100% packet loss", audit=None
            ).outcome.value,
            "fail",
        )


class TestUnreadableCapturesAreNotFaults(unittest.TestCase):
    """The direction that pages someone about a healthy link."""

    def test_each_capture_is_an_input_error(self):
        for label, command, output, arguments in UNREADABLE:
            with self.subTest(case=label, command=command):
                verdict = verify(command, output, audit=None, **arguments)
                self.assertEqual(
                    verdict.outcome.value,
                    "input_error",
                    f"{label}: a capture that cannot answer the question was reported "
                    f"as {verdict.outcome.value!r}",
                )

    def test_the_reason_says_it_is_not_a_network_fault(self):
        """The operator reads this to decide whether to wake someone up.

        `outcome` is for the caller; the reason is what a human sees, and it has to
        carry the same distinction or the field is decoration.
        """
        for label, command, output, arguments in UNREADABLE:
            with self.subTest(case=label):
                verdict = verify(command, output, audit=None, **arguments)
                joined = " ".join(verdict.reasons).lower()
                self.assertIn("not a network fault", joined, joined)

    def test_nothing_in_either_table_ever_reads_as_healthy(self):
        """Both tables are failures; only the *kind* differs.

        One assertion over every row at once, because "healthy" is the answer a
        presence test could produce by returning True too eagerly, and it is the one
        answer neither table may ever produce.
        """
        for label, command, output, arguments in GENUINE_FAULTS + UNREADABLE:
            with self.subTest(case=label, command=command):
                verdict = verify(command, output, audit=None, **arguments)
                self.assertNotEqual(verdict.outcome.value, "pass", f"{label}: reported healthy")
                self.assertFalse(verdict.ok, f"{label}: reported healthy")


if __name__ == "__main__":
    unittest.main()
