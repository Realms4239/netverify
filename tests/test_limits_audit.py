"""Tests for the rate limiter and the audit log.

Both exist because the MCP specification requires them, but the tests are
written around the failure modes that actually bite: a clock that moves
backwards, a sink that breaks, and an audit log that becomes a second copy of
the secret it was written to catch.
"""

import contextlib
import io
import json
import sys
import unittest

from netverify.audit import AuditLog, _default_sink
from netverify.errors import RateLimited, ScopeError
from netverify.limits import TokenBucket


class TestTokenBucket(unittest.TestCase):
    def test_burst_then_refusal(self):
        clock = [0.0]
        bucket = TokenBucket(3, 1.0, clock=lambda: clock[0])
        for _ in range(3):
            self.assertTrue(bucket.try_consume())
        self.assertFalse(bucket.try_consume())
        with self.assertRaises(RateLimited) as caught:
            bucket.consume()
        # The refusal states the wait, so a client backs off precisely.
        self.assertIn("Retry in", str(caught.exception))

    def test_refill_restores_capacity(self):
        clock = [0.0]
        bucket = TokenBucket(2, 1.0, clock=lambda: clock[0])
        bucket.consume()
        bucket.consume()
        self.assertFalse(bucket.try_consume())
        clock[0] += 5.0
        self.assertTrue(bucket.try_consume())

    def test_refill_does_not_exceed_capacity(self):
        """Idle time must not bank an unbounded burst."""
        clock = [0.0]
        bucket = TokenBucket(2, 1.0, clock=lambda: clock[0])
        clock[0] += 10_000.0
        self.assertLessEqual(bucket.tokens, 2)

    def test_backwards_clock_cannot_mint_budget(self):
        """An NTP correction must not hand out free calls."""
        clock = [100.0]
        bucket = TokenBucket(1, 1.0, clock=lambda: clock[0])
        self.assertTrue(bucket.try_consume())
        clock[0] = 0.0
        self.assertFalse(bucket.try_consume())

    def test_rate_limited_is_a_scope_error(self):
        """One exception family, so a caller needs one `except`."""
        self.assertTrue(issubclass(RateLimited, ScopeError))

    def test_invalid_configuration_is_rejected(self):
        with self.assertRaises(ValueError):
            TokenBucket(0, 1.0)
        with self.assertRaises(ValueError):
            TokenBucket(1, 0.0)

    def test_cost_greater_than_capacity_is_always_refused(self):
        bucket = TokenBucket(5, 100.0)
        with self.assertRaises(RateLimited):
            bucket.consume(6.0)


class TestAuditLog(unittest.TestCase):
    def test_writes_json_lines(self):
        sink = io.StringIO()
        log = AuditLog(sink, clock=lambda: 1.0, enabled=True)
        log.record("verify", command_id="ping", ok=True, outcome="pass")
        entry = json.loads(sink.getvalue().strip())
        self.assertEqual(entry["event"], "verify")
        self.assertEqual(entry["command_id"], "ping")
        self.assertEqual(entry["ok"], True)

    def test_omits_absent_fields_rather_than_writing_nulls(self):
        sink = io.StringIO()
        AuditLog(sink, clock=lambda: 1.0, enabled=True).record("ping")
        entry = json.loads(sink.getvalue().strip())
        self.assertNotIn("ok", entry)
        self.assertNotIn("command_id", entry)

    def test_never_records_the_payload(self):
        """An audit log must not become a second copy of the secret."""
        sink = io.StringIO()
        AuditLog(sink, enabled=True).record("verify", command_id="ping", detail="a reason")
        entry = json.loads(sink.getvalue().strip())
        self.assertNotIn("output", entry)
        self.assertNotIn("payload", entry)

    def test_disabled_log_is_a_no_op(self):
        sink = io.StringIO()
        AuditLog(sink, enabled=False).record("verify")
        self.assertEqual(sink.getvalue(), "")

    def test_a_broken_sink_does_not_raise(self):
        """A logging failure must not take down the call it describes.

        The sink raises, and `record` reports the failure on stderr with a
        traceback rather than swallowing it. stderr is captured here so the
        expected report does not pollute the run - otherwise every suite run
        prints a traceback that looks like a real fault, which trains people to
        ignore the one that matters.
        """

        class Exploding(io.StringIO):
            def write(self, *_args):
                raise OSError("disk full")

        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            AuditLog(Exploding(), enabled=True).record("verify")

        # Not raised, *and* reported. Silently dropping an audit record would
        # turn a control into something nobody notices is missing.
        self.assertIn("audit sink failed", captured.getvalue())
        self.assertIn("disk full", captured.getvalue())

    def test_default_sink_is_stderr_not_stdout(self):
        """stdout is the protocol channel on stdio; a stray write corrupts it."""
        self.assertIs(_default_sink(), sys.stderr)


if __name__ == "__main__":
    unittest.main()
