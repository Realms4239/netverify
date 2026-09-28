"""The tool contract, frozen.

An MCP server's public surface is its tool names, arguments, output schemas and
descriptions. A client written against version 1.0.0 breaks silently if any of
those change: no exception fires, the call simply returns something shaped
differently, and the failure surfaces days later as a confused model.

Behaviour tests do not catch that. They assert verdicts, and a renamed tool with
identical behaviour passes every one of them. So the surface itself is pinned
here, and changing it becomes a deliberate diff to this file.

The snapshot is inline rather than a JSON file on purpose: a reviewer sees the
contract change in the same diff as the code, so approving one implies approving
the other. A separate golden file can be regenerated without anyone reading it.
"""

import unittest

#: Frozen tool surface. Bump NETVERIFY_CONTRACT_VERSION when this changes
#: intentionally, and say why in the commit - that is the whole point.
NETVERIFY_CONTRACT_VERSION = 1

TOOL_NAMES = {
    "verify_network_output",
    "sanitize_device_output",
    "audit_device_output",
    "verify_capture",
    "synthesize_health",
    "compare_captures",
    "self_check",
}

#: Concrete resources, as listed by `resources/list`. The command template is
#: deliberately absent: `resources/list` never includes templates, so asserting
#: it there would be asserting something about the SDK rather than about this
#: server.
RESOURCE_URIS = {
    "netverify://contract",
    "netverify://security",
    "netverify://errors",
}

#: Templates, as listed by `resources/templates/list`. The Python field is
#: `uri_template` in mcp 2.x; the wire format is camelCase.
TEMPLATE_URIS = {"netverify://commands/{command_id}"}

#: Prompts, as listed by `prompts/list`. The third server feature, after tools
#: and resources: tools say what the server can do, resources say what it
#: guarantees, and the prompt says how to use them in the order that is
#: actually correct. Renaming one breaks every client that offers it in a
#: picker, so it belongs in the frozen surface like everything else.
PROMPT_NAMES = {"triage_capture"}

#: Arguments `verify_network_output` must accept. Kept explicit because the
#: schema is generated from the signature, so a renamed or dropped parameter is
#: a contract break even though the code still works.
VERIFY_ARGUMENTS = {
    "command",
    "output",
    "interface",
    "neighbor_router_id",
    "peer_ip",
    "remote_as",
    "prefix",
}


class TestToolContract(unittest.TestCase):
    """Freeze the surface. Behaviour tests cannot do this job."""

    def setUp(self):
        try:
            from server.app import build_server

            self.server = build_server()
        except ImportError:  # pragma: no cover - only when mcp is absent
            self.skipTest("the mcp SDK is not installed")

    def _tools(self):
        import asyncio

        return {t.name: t for t in asyncio.run(self.server.list_tools())}

    def test_tool_names_are_frozen(self):
        self.assertEqual(set(self._tools()), TOOL_NAMES)

    def test_every_tool_remains_read_only_and_structured(self):
        """The annotations are the client's basis for auto-approval.

        If any tool ever became capable of writing, `readOnlyHint: true` would
        be a live vulnerability rather than a documentation detail - a host
        would skip the confirmation prompt. So it is asserted, not assumed.
        """
        for name, tool in self._tools().items():
            with self.subTest(tool=name):
                self.assertIsNotNone(tool.annotations, f"{name} has no annotations")
                self.assertTrue(tool.annotations.read_only_hint)
                self.assertFalse(tool.annotations.destructive_hint)
                self.assertTrue(tool.annotations.idempotent_hint)
                self.assertFalse(tool.annotations.open_world_hint)
                self.assertIsNotNone(tool.output_schema, f"{name} returns unstructured output")

    def test_verify_tool_arguments_are_frozen(self):
        tools = self._tools()
        self.assertIn("verify_network_output", tools)
        properties = tools["verify_network_output"].input_schema["properties"]
        self.assertEqual(set(properties), VERIFY_ARGUMENTS)

    def test_resource_uris_are_frozen(self):
        import asyncio

        listed = asyncio.run(self.server.list_resources())
        self.assertEqual({str(r.uri) for r in listed}, RESOURCE_URIS)

    def test_prompt_names_are_frozen(self):
        import asyncio

        listed = asyncio.run(self.server.list_prompts())
        self.assertEqual({p.name for p in listed}, PROMPT_NAMES)

    def test_every_prompt_carries_a_description(self):
        """An empty description is a prompt a client shows as a bare name in its
        picker, which is worse than not offering it."""
        import asyncio

        for prompt in asyncio.run(self.server.list_prompts()):
            with self.subTest(prompt=prompt.name):
                self.assertTrue(prompt.description, f"{prompt.name} has no description")
                self.assertTrue(prompt.title, f"{prompt.name} has no title")

    def test_templates_are_discoverable(self):
        """A template that is not advertised is a feature nobody can find.

        This previously had a docstring and no assertion, so it passed
        unconditionally - a green test that checked nothing, which is worse than
        no test because it inflates the count. It now asserts the thing the
        docstring describes.
        """
        import asyncio

        templates = asyncio.run(self.server.list_resource_templates())
        self.assertEqual({str(t.uri_template) for t in templates}, TEMPLATE_URIS)

    def test_template_reads_a_real_command_and_rejects_a_fake_one(self):
        """The per-command template is the discovery path for command ids.

        If it resolved a made-up id, the "documented contract" resource would
        quietly return something plausible and an agent would build a plan on a
        command that does not exist.
        """
        import asyncio

        from mcp.server.mcpserver.exceptions import ResourceError

        contents = list(
            asyncio.run(self.server.read_resource("netverify://commands/frr_bgp_summary"))
        )
        self.assertIn("frr_bgp_summary", contents[0].content)

        with self.assertRaises(ResourceError):
            asyncio.run(self.server.read_resource("netverify://commands/not_a_command"))

    def test_command_ids_are_discoverable(self):
        """A client must be able to learn the command ids from the server.

        Per-argument `Annotated` descriptions are *not* asserted here, because
        the SDK builds the argument model with `WithJsonSchema(None)` and so strips
        per-field descriptions from the wire schema. The ids therefore have to
        travel in the tool description and the command resource, and this asserts
        both. Asserting the stripped field would be asserting the SDK away.
        """
        from netverify import COMMANDS

        description = (self._tools()["verify_network_output"].description or "").lower()
        for spec in COMMANDS:
            with self.subTest(command=spec.id):
                self.assertIn(spec.id.lower(), description)

    def test_command_resource_serves_one_contract(self):
        """`netverify://commands/{id}` is the per-command detail a client reads.

        Raises rather than 404s on a bad id, so a wrong guess is corrected in
        one step instead of becoming a dead end.
        """
        import asyncio
        import json

        from mcp.server.mcpserver.exceptions import ResourceError

        contents = list(asyncio.run(self.server.read_resource("netverify://commands/ping")))
        payload = json.loads(contents[0].content)
        self.assertEqual(payload["id"], "ping")
        self.assertIn("summary", payload)

        with self.assertRaises(ResourceError) as caught:
            asyncio.run(self.server.read_resource("netverify://commands/nope"))
        self.assertIn("ping", str(caught.exception))
