"""Tests for the MCP surface: annotations, structured output, and refusals.

These cross the protocol seam, so they catch things the library tests cannot: a
tool that is not registered, a schema a client cannot use, an annotation that
lies about what the tool does.

The annotation tests matter more than they look. The specification says
annotations are *hints* that a client must not trust from an untrusted server -
but a host still uses them to decide whether a human must approve a call. An
annotation claiming `readOnlyHint: true` on a tool that mutates would be a real
vulnerability, so the claim is asserted rather than assumed.
"""

import unittest

from netverify import MAX_BYTES
from tests import fixtures as fx


class TestToolSurface(unittest.TestCase):
    def setUp(self):
        try:
            from server.app import build_server

            self.server = build_server()
        except ImportError:  # pragma: no cover - only when mcp is absent
            self.skipTest("the mcp SDK is not installed")

    def _tools(self):
        import asyncio

        return asyncio.run(self.server.list_tools())

    def test_the_expected_tools_are_published(self):
        """The exact tool set, pinned at the runtime layer too.

        `test_contract.py` freezes the same names; this repeats the assertion
        here so a change to `build_server` fails in the surface suite as well,
        rather than only in the contract suite where it is easier to overlook.
        """
        names = {t.name for t in self._tools()}
        self.assertEqual(
            names,
            {
                # Single-command verification, and the two that harden its input.
                "verify_network_output",
                "sanitize_device_output",
                "audit_device_output",
                # Batch and aggregate reasoning: the operator workflows.
                "verify_capture",
                "synthesize_health",
                "compare_captures",
                # Self-description.
                "self_check",
            },
            f"unexpected tool surface: {sorted(names)}",
        )

    def test_every_tool_declares_itself_read_only(self):
        """The annotations must match the implementation, not flatter it."""
        for tool in self._tools():
            with self.subTest(tool=tool.name):
                annotations = tool.annotations
                self.assertIsNotNone(annotations, f"{tool.name} has no annotations")
                self.assertTrue(annotations.read_only_hint)
                self.assertFalse(annotations.destructive_hint)
                self.assertTrue(annotations.idempotent_hint)
                self.assertFalse(annotations.open_world_hint)

    def test_every_tool_has_a_structured_output_schema(self):
        """Without outputSchema a client parses prose; with it, it validates."""
        for tool in self._tools():
            with self.subTest(tool=tool.name):
                self.assertIsNotNone(tool.output_schema, f"{tool.name} returns unstructured output")

    def test_verify_tool_schema_exposes_the_allowlist_arguments(self):
        tools = {t.name: t for t in self._tools()}
        properties = tools["verify_network_output"].input_schema["properties"]
        self.assertIn("command", properties)
        self.assertIn("output", properties)
        for name in ("interface", "neighbor_router_id", "peer_ip", "remote_as", "prefix"):
            with self.subTest(argument=name):
                self.assertIn(name, properties)

    def test_tools_are_listed_in_a_deterministic_order(self):
        """Deterministic ordering is what lets clients cache the list."""
        self.assertEqual([t.name for t in self._tools()], [t.name for t in self._tools()])

    def test_server_exposes_its_contract_and_threat_model(self):
        import asyncio

        uris = {str(r.uri) for r in asyncio.run(self.server.list_resources())}
        self.assertIn("netverify://contract", uris)
        self.assertIn("netverify://security", uris)

    def test_contract_resource_is_valid_json_and_honest(self):
        import asyncio
        import json

        contents = asyncio.run(self.server.read_resource("netverify://contract"))
        document = json.loads(contents[0].content)
        self.assertEqual(document["protocol_revision"], "2026-07-28")
        self.assertTrue(document["guarantees"]["read_only"])
        self.assertFalse(document["guarantees"]["holds_device_credentials"])
        self.assertFalse(document["guarantees"]["fetches_device_output"])
        self.assertTrue(document["guarantees"]["rate_limited"])
        # The published list must match the live registry, or the contract is a
        # lie an agent will act on.


class TestToolBehaviour(unittest.TestCase):
    """The tool functions are importable without the SDK, so these always run."""

    def test_valid_call_returns_a_verdict(self):
        from server.app import verify_network_output

        result = verify_network_output(
            command="srl_interface_brief",
            output=fx.SRL_INTERFACE_UP,
            interface="ethernet-1/1",
        )
        self.assertTrue(result["ok"], result["reasons"])
        self.assertEqual(result["outcome"], "pass")

    def test_out_of_scope_command_is_refused_as_a_tool_error(self):
        """A refusal must be recoverable by the model, not a crash.

        The SDK treats a raised `ToolError` as `is_error=True` with the message
        reaching the model, so it can correct the call. Anything else surfaces
        as `UnexpectedToolError` with a generic message and the reason lost -
        which is exactly the case where the model most needs to be told what it
        got wrong.
        """
        from mcp.server.mcpserver.exceptions import ToolError

        from server.app import verify_network_output

        with self.assertRaises(ToolError) as caught:
            verify_network_output(command="configure", output="text")
        self.assertIn("not in the allowlist", str(caught.exception))

    def test_scope_error_is_also_a_value_error(self):
        """The library stays SDK-free: refusals are ValueErrors, not SDK types.

        The translation to ToolError happens at the adapter, so importing
        netverify never requires the MCP SDK.
        """
        from netverify import ScopeError

        self.assertTrue(issubclass(ScopeError, ValueError))

    def test_oversize_output_is_refused(self):
        from mcp.server.mcpserver.exceptions import ToolError

        from server.app import verify_network_output

        with self.assertRaises(ToolError):
            verify_network_output(command="ping", output="x" * (MAX_BYTES + 1))

    def test_every_refusal_uses_the_same_exception_type(self):
        """One exception family, so a client catches one thing.

        Without this, a caller would have to know which rule fired to know what
        to catch, and a new rule could quietly introduce a second family.
        """
        from mcp.server.mcpserver.exceptions import ToolError

        from server.app import verify_network_output

        bad_calls = [
            {"command": "configure", "output": "t"},
            {"command": "show interface brief", "output": "t"},
            {"command": "srl_interface_brief", "output": "t"},
            {"command": "srl_interface_brief", "output": 42},
            {"command": "srl_interface_brief", "output": "t", "interface": ""},
        ]
        for kwargs in bad_calls:
            with self.subTest(**kwargs):
                with self.assertRaises(ToolError):
                    verify_network_output(**kwargs)

    def test_sanitize_tool_masks_a_secret(self):
        from server.app import sanitize_device_output

        result = sanitize_device_output("password=hunter2")
        self.assertNotIn("hunter2", result["safe_text"])
        self.assertFalse(result["clean"])

    def test_audit_tool_returns_no_text(self):
        """An inspection tool that echoes the text is not an inspection tool."""
        from server.app import audit_device_output

        result = audit_device_output("password=hunter2")
        self.assertNotIn("safe_text", result)
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["highest_severity"], "high")

    def test_capture_tool_keeps_results_in_place(self):
        """One bad entry must not abort the batch."""
        from server.app import verify_capture

        result = verify_capture(
            [
                {"command": "ping", "output": fx.PING_OK},
                {"command": "configure", "output": "text"},
                {"command": "ping", "output": fx.PING_TOTAL_LOSS},
            ]
        )
        self.assertEqual(result["ok_count"], 1)
        self.assertEqual(result["failed_count"], 1)
        self.assertEqual(result["refused_count"], 1)
        self.assertIn("refused", result["results"][1])
        self.assertTrue(result["results"][0]["ok"])
        self.assertFalse(result["results"][2]["ok"])


if __name__ == "__main__":
    unittest.main()
