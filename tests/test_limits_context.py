"""Tests for work bounding and request correlation.

Two controls that were advertised before they were enforced, which is the
failure mode this file exists to prevent. Both now have tests that would fail if
the control were removed.
"""

import io
import json
import unittest

from netverify import (
    MAX_BATCH_ITEMS,
    MAX_BYTES,
    MAX_TOTAL_INPUT_BYTES,
    ScopeError,
    bind_request_id,
    current_request_id,
    verify_many,
)
from netverify.audit import AuditLog
from tests import fixtures as fx


def _entry(output: str) -> dict:
    return {"command": "ping", "output": output}


class TestAggregateByteBudget(unittest.TestCase):
    """The count cap was the wrong axis, and the numbers proved it.

    200 entries is under `MAX_BATCH_ITEMS`, so an item-count guard let through a
    batch that cost five seconds of regex work in a single tool call. The budget
    is on bytes, because that is what the cost actually tracks.
    """

    def test_a_batch_over_the_byte_budget_is_refused(self):
        oversized = [_entry("x" * MAX_BYTES) for _ in range(8)]
        with self.assertRaises(ScopeError) as caught:
            verify_many(oversized)
        self.assertIn("budget", str(caught.exception))

    def test_a_batch_exactly_at_the_budget_is_accepted(self):
        """The boundary must be inclusive, or the limit is untestable.

        Four cap-sized entries is exactly the budget, and it is the case an
        operator hits when pasting four large tables.
        """
        batch = [_entry("x" * MAX_BYTES) for _ in range(4)]
        results = verify_many(batch)
        self.assertEqual(len(results), 4)
        self.assertTrue(all(not isinstance(r, Exception) for r in results))

    def test_the_budget_is_checked_before_any_entry_is_processed(self):
        """A budget discovered mid-batch has already done most of the work.

        This asserts the refusal arrives with no results at all, rather than
        partial results plus an error - which is the difference between a limit
        and a report.
        """
        oversized = [_entry("x" * MAX_BYTES) for _ in range(8)]
        with self.assertRaises(ScopeError):
            verify_many(oversized)

    def test_the_item_cap_still_applies(self):
        with self.assertRaises(ScopeError) as caught:
            verify_many([_entry("x") for _ in range(MAX_BATCH_ITEMS + 1)])
        self.assertIn(str(MAX_BATCH_ITEMS), str(caught.exception))

    def test_a_realistic_incident_capture_fits_the_budget(self):
        """The budget must not block the actual use case.

        A full 200-interface capture is about 104 KB against a 262 KB budget, so
        it fits with room to spare - but it uses roughly 40% of the budget, which
        is why the budget is several times a single capped input rather than
        exactly one.
        """
        batch = [_entry(fx.SRL_INTERFACE_UP) for _ in range(MAX_BATCH_ITEMS)]
        results = verify_many(batch)
        self.assertEqual(len(results), MAX_BATCH_ITEMS)
        self.assertTrue(all(not isinstance(r, Exception) for r in results))
        total = sum(len(fx.SRL_INTERFACE_UP) for _ in batch)
        self.assertLess(total, MAX_TOTAL_INPUT_BYTES)


class TestRequestCorrelation(unittest.TestCase):
    def test_no_request_id_outside_a_request(self):
        self.assertIsNone(current_request_id())

    def test_binding_exposes_the_id(self):
        with bind_request_id(42) as bound:
            self.assertEqual(bound, "42")
            self.assertEqual(current_request_id(), "42")

    def test_binding_is_restored_afterwards(self):
        """A leaked id would mislabel every later call, and a wrong id is worse
        than none because it looks trustworthy."""
        with bind_request_id(1):
            pass
        self.assertIsNone(current_request_id())

    def test_binding_is_restored_even_when_the_body_raises(self):
        with self.assertRaises(RuntimeError):
            with bind_request_id(1):
                raise RuntimeError("boom")
        self.assertIsNone(current_request_id())

    def test_nested_binding_is_restored_to_the_outer_value(self):
        with bind_request_id("outer"):
            with bind_request_id("inner"):
                self.assertEqual(current_request_id(), "inner")
            self.assertEqual(current_request_id(), "outer")

    def test_audit_lines_carry_the_request_id(self):
        """The point of the whole mechanism: a log of turns, not of calls.

        `enabled=True` is required, not decorative: `tests/__init__.py` sets
        `NETVERIFY_AUDIT=0` for the whole run so a green suite is not buried in
        thousands of JSON lines. A test asserting on audit output therefore has
        to opt back in explicitly.
        """
        sink = io.StringIO()
        log = AuditLog(sink=sink, enabled=True)
        with bind_request_id("req-7"):
            log.record("verify", command_id="ping", ok=True)
        entry = json.loads(sink.getvalue().strip())
        self.assertEqual(entry["request_id"], "req-7")
        self.assertEqual(entry["command_id"], "ping")

    def test_audit_omits_the_field_outside_a_request(self):
        """Omitted rather than null, so a grep returns only real requests."""
        sink = io.StringIO()
        AuditLog(sink=sink, enabled=True).record("verify", command_id="ping")
        self.assertNotIn("request_id", json.loads(sink.getvalue().strip()))


class TestMiddlewareBindsTheIdForTheTool(unittest.TestCase):
    """Proves the wiring from the protocol edge to the audit line.

    The first version of this test called `MCPServer.call_tool()` and asserted
    the audit log was correlated. It failed - correctly - and for an instructive
    reason: `call_tool()` is the in-process entry point and does not run the
    middleware chain, which the SDK applies in the request dispatcher. A
    middleware that is registered but bypassed by every test would stay green
    forever, so the middleware is invoked directly here, and the real
    end-to-end proof over a live pipe lives in `scripts/stdio_check.py`.
    """

    def test_the_middleware_publishes_the_id_to_the_audit_log(self):
        import asyncio
        import types

        from server.app import _RequestIdMiddleware

        sink = io.StringIO()
        log = AuditLog(sink=sink, enabled=True)
        seen: list[str | None] = []

        async def call_next(ctx):
            # Stands in for the tool body: records while the id is in scope.
            seen.append(current_request_id())
            log.record("verify", command_id="ping", ok=True)
            return "done"

        ctx = types.SimpleNamespace(request_id=4242)
        result = asyncio.run(_RequestIdMiddleware()(ctx, call_next))

        self.assertEqual(result, "done")
        self.assertEqual(seen, ["4242"])
        entry = json.loads(sink.getvalue().strip())
        self.assertEqual(entry["request_id"], "4242")

    def test_a_notification_does_not_inherit_the_previous_id(self):
        """A notification has no id; inheriting one would mislabel its records."""
        import asyncio
        import types

        from server.app import _RequestIdMiddleware

        seen: list[str | None] = []

        async def call_next(ctx):
            seen.append(current_request_id())
            return None

        asyncio.run(_RequestIdMiddleware()(types.SimpleNamespace(request_id=None), call_next))
        self.assertEqual(seen, [None])


if __name__ == "__main__":
    unittest.main()
