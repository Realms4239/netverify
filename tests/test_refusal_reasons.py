"""The refusal vocabulary, pinned.

A refusal *message* is prose: it gets reworded when someone improves it, and a
dashboard that groups by prose silently splits one operational fact into
several. The `reason` code is what a counter aggregates on, so the codes are
the contract - not the messages, and not the tool surface.

Three properties are worth a test each, and none of them is visible from the
behaviour tests:

- Every raise site names a code. A refusal that reaches a dashboard as
  `bad_argument` because nobody set a reason is a refusal nobody can act on,
  and the code that causes it passes every test that only checks behaviour.
- The vocabulary is defined once. `telemetry` re-exports these names, and a
  second copy of a string is a second place for the two to drift. The drift is
  silent: the counter still increments, under a label no dashboard queries.
- Labels stay bounded. `command` is set only for an id known to be in the
  allowlist, because an attacker who invents a fresh command name per request
  would otherwise mint a fresh time series per request against the metrics
  backend. That is a denial-of-service wearing a telemetry label.
"""

import unittest

from netverify import errors, telemetry
from netverify.limits import TokenBucket
from netverify.sanitize import MAX_BYTES
from netverify.verify import MAX_BATCH_ITEMS, validate, verify_many
from tests import fixtures as fx

#: Every code the library may raise, and the string each one must have. Written
#: as literals on purpose: a test that reads the value it is asserting on
#: verifies nothing. Changing a value here is a breaking change to every
#: dashboard query that groups by it.
PUBLISHED = {
    "REASON_NOT_IN_ALLOWLIST": "not_in_allowlist",
    "REASON_UNKNOWN_ARGUMENT": "unknown_argument",
    "REASON_MISSING_ARGUMENT": "missing_argument",
    "REASON_BAD_ARGUMENT": "bad_argument",
    "REASON_OVERSIZE_OUTPUT": "oversize_output",
    "REASON_OVERSIZE_BATCH": "oversize_batch",
    "REASON_NON_LIST_BATCH": "non_list_batch",
    "REASON_RATE_LIMITED": "rate_limited",
}

KNOWN = frozenset(PUBLISHED.values())


class TestCodesAreStable(unittest.TestCase):
    def test_each_code_is_the_published_string(self):
        for name, value in PUBLISHED.items():
            with self.subTest(code=name):
                self.assertEqual(getattr(errors, name), value)

    def test_telemetry_re_exports_the_same_objects_not_copies(self):
        """Identity, not equality: a copy is a second definition waiting to drift."""
        for name in PUBLISHED:
            with self.subTest(code=name):
                self.assertIs(getattr(telemetry, name), getattr(errors, name))

    def test_the_package_re_exports_every_code(self):
        import netverify

        for name in PUBLISHED:
            with self.subTest(code=name):
                self.assertIn(name, netverify.__all__)
                self.assertIs(getattr(netverify, name), getattr(errors, name))


class TestEveryRefusalNamesACode(unittest.TestCase):
    """One case per raise site. A new refusal with no code fails here."""

    def _reason(self, call, *args, **kwargs):
        with self.assertRaises(errors.ScopeError) as caught:
            call(*args, **kwargs)
        reason = caught.exception.reason
        self.assertIn(
            reason,
            KNOWN,
            f"{reason!r} is not a published refusal code, so the netverify.refused "
            "counter would carry a label no dashboard queries",
        )
        return caught.exception

    def test_a_command_that_is_not_a_string(self):
        self._reason(validate, 123, fx.PING_OK)

    def test_a_command_outside_the_allowlist(self):
        self._reason(validate, "show run everything", fx.PING_OK)

    def test_an_output_that_is_not_a_string(self):
        self._reason(validate, "ping", None)

    def test_an_oversize_output(self):
        self._reason(validate, "ping", "x" * (MAX_BYTES + 1))

    def test_an_argument_the_command_does_not_take(self):
        self._reason(validate, "srl_interface_brief", fx.SRL_INTERFACE_UP, vlan="100")

    def test_a_missing_required_argument(self):
        self._reason(validate, "srl_interface_brief", fx.SRL_INTERFACE_UP)

    def test_an_argument_value_of_the_wrong_type(self):
        self._reason(validate, "srl_interface_brief", fx.SRL_INTERFACE_UP, interface=7)

    def test_an_argument_value_of_the_wrong_shape(self):
        self._reason(
            validate, "srl_interface_brief", fx.SRL_INTERFACE_UP, interface="not an interface"
        )

    def test_an_argument_carrying_a_line_break(self):
        self._reason(
            validate,
            "srl_interface_brief",
            fx.SRL_INTERFACE_UP,
            interface="ethernet-1/1\nset / system information",
        )

    def test_a_batch_that_is_not_a_list(self):
        self._reason(verify_many, {"command": "ping", "output": fx.PING_OK})

    def test_a_batch_above_the_item_cap(self):
        self._reason(verify_many, [{} for _ in range(MAX_BATCH_ITEMS + 1)])

    def test_an_exhausted_budget(self):
        bucket = TokenBucket(1, 1.0)
        bucket.consume()
        self.assertEqual(self._reason(bucket.consume).reason, errors.REASON_RATE_LIMITED)

    def test_a_cost_above_the_burst_is_a_refusal_too(self):
        """A different message, the same code: both mean "you are out of budget".

        They differ for the caller - one can be retried, the other must be
        split - but a dashboard that wanted "unsatisfiable requests" as its own
        series would be reading a distinction no caller can act on.
        """
        bucket = TokenBucket(5, 100.0)
        self.assertEqual(self._reason(bucket.consume, 6.0).reason, errors.REASON_RATE_LIMITED)

    def test_a_refusal_returned_in_place_of_raised_also_carries_a_code(self):
        """One bad entry does not abort a batch, so its refusal is *returned*.

        An in-place refusal that arrived without a code would be counted as a
        generic `bad_argument` and read as a client mistake rather than the
        shape error it is.
        """
        results = verify_many(["not an object"], audit=None)
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], errors.ScopeError)
        self.assertEqual(results[0].reason, errors.REASON_BAD_ARGUMENT)

    def test_a_refusal_survives_the_public_verify_entry_point(self):
        """`verify` adds no reason of its own; the library's is passed through."""
        from netverify import verify

        with self.assertRaises(errors.ScopeError) as caught:
            verify("srl_interface_brief", fx.SRL_INTERFACE_UP, interface="!!")
        self.assertEqual(caught.exception.reason, errors.REASON_BAD_ARGUMENT)


class TestCommandLabelsStayBounded(unittest.TestCase):
    """`command` is the label a counter groups by, so it must be a closed set."""

    def _excuse(self, call, *args, **kwargs):
        with self.assertRaises(errors.ScopeError) as caught:
            call(*args, **kwargs)
        return caught.exception

    def test_a_known_id_is_labelled_with_itself(self):
        self.assertEqual(self._excuse(validate, "ping", None).command, "ping")

    def test_an_invented_id_is_never_labelled(self):
        """An attacker must not be able to mint a metric series per request."""
        exc = self._excuse(validate, "rm -rf /", fx.PING_OK)
        self.assertEqual(exc.reason, errors.REASON_NOT_IN_ALLOWLIST)
        self.assertIsNone(exc.command)

    def test_an_argument_refusal_names_the_command_it_was_about(self):
        exc = self._excuse(validate, "srl_interface_brief", fx.SRL_INTERFACE_UP, interface="!!")
        self.assertEqual(exc.command, "srl_interface_brief")

    def test_a_command_that_is_not_a_string_has_no_label(self):
        self.assertIsNone(self._excuse(validate, 123, fx.PING_OK).command)


class TestEveryCodeIsDocumentedWhereAgentsLook(unittest.TestCase):
    """The vocabulary is only useful if the resource an agent reads has it.

    `netverify://errors` is the one document a client is told to read before
    retrying a refused call. It listed message fragments before the codes
    existed; now that every refusal carries a code, an agent reading it should
    find the code, its fix, and whether retrying can help. A code the library
    can raise but the resource never mentions is a code no client can act on.
    """

    def setUp(self):
        try:
            from server.app import build_server
        except ImportError:  # pragma: no cover - only when mcp is absent
            self.skipTest("the mcp SDK is not installed")
        self.server = build_server()

    def _document(self):
        import asyncio
        import json

        contents = asyncio.run(self.server.read_resource("netverify://errors"))
        return json.loads(contents[0].content)

    def test_every_published_code_appears_with_a_fix(self):
        document = self._document()

        for code in sorted(KNOWN):
            with self.subTest(code=code):
                self.assertIn(code, document["reasons"])
                self.assertTrue(document["reasons"][code]["fix"])

    def test_rate_limiting_is_the_only_retryable_refusal(self):
        """Retryable is a promise: a client will act on it.

        Everything else is a mistake the caller must change, so telling them to
        retry would produce exactly the retry loop the bucket exists to stop.
        """
        document = self._document()

        retryable = {code for code, entry in document["reasons"].items() if entry["retryable"]}
        self.assertEqual(retryable, {errors.REASON_RATE_LIMITED})

    def test_every_category_names_the_code_it_describes(self):
        """The prose view and the code view are generated from one list."""
        document = self._document()

        for category in document["categories"]:
            with self.subTest(when=category["when"]):
                self.assertIn(category["reason"], KNOWN)
                self.assertEqual(
                    document["reasons"][category["reason"]]["fix"],
                    category["fix"],
                )

    def test_a_code_is_not_documented_twice(self):
        """Two categories sharing a code would make `reasons` lose one of them."""
        document = self._document()

        codes = [category["reason"] for category in document["categories"]]
        self.assertEqual(len(codes), len(set(codes)))


class TestBareErrorsStillWork(unittest.TestCase):
    """The metadata is optional, so old call sites and tests keep compiling."""

    def test_a_bare_scope_error_is_still_a_value_error(self):
        exc = errors.ScopeError("something is wrong")
        self.assertIsInstance(exc, ValueError)
        self.assertEqual(str(exc), "something is wrong")
        self.assertIsNone(exc.reason)
        self.assertIsNone(exc.command)

    def test_rate_limited_is_still_a_scope_error(self):
        self.assertTrue(issubclass(errors.RateLimited, errors.ScopeError))


if __name__ == "__main__":
    unittest.main()
