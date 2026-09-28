"""Tests for the prompt surface.

The interesting test here is not "does the prompt render". It is the one that
asserts the prompt does not *become* a control. A prompt is instructions to a
model, and a rule that lives only in prompt text is a rule that disappears the
moment the file is deleted. So these tests check that the prompt points at tools
and resources rather than restating what they enforce.
"""

import unittest

from netverify import COMMANDS
from server.prompts import triage_capture


class TestPromptIsDiscoverable(unittest.TestCase):
    def setUp(self):
        try:
            from server.app import build_server
        except ImportError:  # pragma: no cover - only when mcp is absent
            self.skipTest("the mcp SDK is not installed")
        self.server = build_server()

    def test_exactly_one_prompt_is_published(self):
        """A prompt is a maintenance commitment; they do not get added casually."""
        import asyncio

        prompts = asyncio.run(self.server.list_prompts())
        self.assertEqual([p.name for p in prompts], ["triage_capture"])

    def test_prompt_is_renders_through_the_protocol(self):
        import asyncio

        rendered = asyncio.run(self.server.get_prompt("triage_capture", {}))
        text = rendered.messages[0].content.text
        self.assertIn("sanitize_device_output", text)
        self.assertIn("input_error", text)

    def test_prompt_focus_argument_is_optional_and_described(self):
        """A client UI can only offer a field it knows about."""
        import asyncio

        prompts = asyncio.run(self.server.list_prompts())
        arguments = prompts[0].arguments or []
        self.assertEqual([a.name for a in arguments], ["focus"])
        self.assertFalse(arguments[0].required)
        self.assertTrue(arguments[0].description)


class TestPromptTeachesTheRightOrder(unittest.TestCase):
    def test_sanitising_comes_before_verifying(self):
        """The order is the whole content of the prompt.

        Verifying first and sanitising afterwards reads well and defeats the
        purpose: the injection has already been quoted into the model's context
        by the time anyone notices.
        """
        text = triage_capture()
        self.assertLess(
            text.index("sanitize_device_output"),
            text.index("verify_capture"),
            "the prompt must sanitise before it verifies",
        )

    def test_outcome_is_read_before_ok(self):
        text = triage_capture()
        self.assertLess(
            text.index("`outcome` before"),
            text.index("Read `ok`") if "Read `ok`" in text else len(text),
        )

    def test_every_registered_command_is_named(self):
        """A client can discover ids from the contract, but the prompt should
        not send the model hunting for one it cannot see."""
        text = triage_capture()
        for spec in COMMANDS:
            with self.subTest(command=spec.id):
                self.assertIn(f"`{spec.id}`", text)

    def test_a_typo_in_focus_is_reported_not_echoed_as_a_command(self):
        """Otherwise the prompt sends the model looking for a command that does
        not exist, and the failure surfaces as a confusing allowlist error."""
        text = triage_capture("srl_bgp_summry")
        self.assertIn("not a registered command", text)

    def test_a_valid_focus_is_not_flagged(self):
        self.assertNotIn("not a registered command", triage_capture("frr_bgp_summary"))


class TestPromptIsNotAControl(unittest.TestCase):
    """The line this module must not cross.

    A prompt is addressed to a model. Anything the prompt states as a *rule*
    rather than as a pointer is a rule with two sources of truth, and the copy in
    prose is the one that drifts.
    """

    def test_prompt_does_not_restate_the_allowlist_as_a_rule(self):
        """It names the ids, but must not claim to be the thing that admits them."""
        text = triage_capture()
        self.assertIn("enforced in code", text)

    def test_prompt_does_not_assert_a_credential_free_server_as_itself_being_one(self):
        """The guarantee belongs to the server and the contract resource; the
        prompt may point at it, not restate it as a fact it is responsible for."""
        text = triage_capture().lower()
        for claim in ("this server holds no credentials", "we guarantee", "this prompt enforces"):
            with self.subTest(claim=claim):
                self.assertNotIn(claim, text)

    def test_prompt_points_at_the_contract_rather_than_describing_it(self):
        self.assertIn("netverify://contract", triage_capture())


if __name__ == "__main__":
    unittest.main()
