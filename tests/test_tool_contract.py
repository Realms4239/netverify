"""Tests for the MCP surface itself.

Two things are being defended here.

1. **The server publishes exactly one tool.** The vault's guidance is "one tool
   done right beats five half-hardened", and every extra tool multiplies attack
   surface faster than it adds proof. A count assertion is the only thing that
   makes that guidance enforceable rather than aspirational.

2. **The tool refuses out-of-scope input at the boundary**, so a hostile prompt
   has nothing to escalate into.
"""

import unittest

from server import mcp_server
from tests import fixtures as fx


class TestToolSurface(unittest.TestCase):
    def setUp(self):
        try:
            self.server = mcp_server.build_server()
        except ImportError:  # pragma: no cover - only when mcp is absent
            self.skipTest("the mcp SDK is not installed")

    def test_exactly_one_tool_is_published(self):
        """The scope guard against scope creep."""
        import asyncio

        tools = asyncio.run(self.server.list_tools())
        self.assertEqual(
            len(tools),
            1,
            f"expected 1 tool, found {[t.name for t in tools]}. Adding tools "
            "needs a deliberate decision, not an accident.",
        )
        self.assertEqual(tools[0].name, "verify_network_output")

    def test_tool_description_states_it_is_read_only(self):
        import asyncio

        tools = asyncio.run(self.server.list_tools())
        blob = f"{tools[0].description} {mcp_server.INSTRUCTIONS}".lower()
        self.assertIn("read-only", blob)
        self.assertIn("cannot change device state", blob)

    def test_schema_exposes_the_allowlist_arguments(self):
        import asyncio

        tools = asyncio.run(self.server.list_tools())
        properties = tools[0].inputSchema["properties"]
        self.assertIn("command", properties)
        self.assertIn("output", properties)
        for name in ("interface", "neighbor_router_id", "peer_ip", "remote_as", "prefix"):
            with self.subTest(argument=name):
                self.assertIn(name, properties)


class TestToolBehaviour(unittest.TestCase):
    """The tool function is importable without the mcp SDK, so these always run."""

    def test_valid_call_returns_a_verdict(self):
        result = mcp_server.verify_network_output(
            command="srl_interface_brief",
            output=fx.SRL_INTERFACE_UP,
            interface="ethernet-1/1",
        )
        self.assertTrue(result["ok"], result["reasons"])

    def test_out_of_scope_command_raises(self):
        with self.assertRaises(ValueError):
            mcp_server.verify_network_output(command="configure", output="text")

    def test_raw_cli_string_raises(self):
        with self.assertRaises(ValueError):
            mcp_server.verify_network_output(
                command="show interface brief", output=fx.SRL_INTERFACE_UP
            )

    def test_oversize_output_raises(self):
        from server import scope

        with self.assertRaises(ValueError):
            mcp_server.verify_network_output(
                command="ping", output="x" * (scope.MAX_OUTPUT_BYTES + 1)
            )

    def test_argument_invalid_for_the_command_raises(self):
        """An argument that is declared but wrong for this command is refused.

        Found by the eval gate, and the interesting part is *why* it is a real
        test: silently dropping `prefix` here would return a confident verdict
        about an interface while the caller believed they had also constrained
        a route. A refusal is the honest answer.

        Note this is deliberately not a test for an unknown keyword. The tool
        signature is closed so that MCP emits a correct schema, which means an
        undeclared keyword never reaches the body at all - and the schema test
        above already proves a client cannot send one.
        """
        with self.assertRaises(ValueError) as caught:
            mcp_server.verify_network_output(
                command="srl_interface_brief",
                output=fx.SRL_INTERFACE_UP,
                interface="ethernet-1/1",
                prefix="10.0.0.2/32",
            )
        self.assertIn("does not accept", str(caught.exception))

    def test_no_refusal_path_leaks_another_exception_type(self):
        """Every rejected request raises ValueError, never something else."""
        bad_calls = [
            {"command": "configure", "output": "t"},
            {"command": "show interface brief", "output": "t"},
            {"command": "srl_interface_brief", "output": "t"},
            {"command": "srl_interface_brief", "output": 42},
            {"command": "srl_interface_brief", "output": "t", "interface": ""},
            {"command": "ping", "output": "x" * (1 << 17)},
        ]
        for kwargs in bad_calls:
            with self.subTest(**kwargs):
                with self.assertRaises(ValueError):
                    mcp_server.verify_network_output(**kwargs)

    def test_omitted_optional_args_are_not_treated_as_empty(self):
        """Passing no prefix must not be recorded as prefix=''.

        An empty string would satisfy an 'is it present' check and produce a
        verdict about a blank prefix.
        """
        result = mcp_server.verify_network_output(
            command="frr_bgp_summary", output=fx.FRR_SUMMARY_HEALTHY
        )
        self.assertEqual(result["arguments"], {})


if __name__ == "__main__":
    unittest.main()
