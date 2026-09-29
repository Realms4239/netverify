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
import threading
import unittest

from netverify.audit import AuditLog, _default_sink
from netverify.errors import REASON_RATE_LIMITED, RateLimited, ScopeError
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


class TestTokenBucketUnderConcurrency(unittest.TestCase):
    """The bucket is one process-wide object and the SDK runs tools on threads.

    A lost update here is not a wrong number in a test: it is a caller getting
    budget nobody authorised. Each thread's debit must be serialised, so exactly
    `capacity` calls can succeed against a bucket with no refill - never more,
    however many threads arrive at once.
    """

    def _race(self, bucket, attempts, cost=1.0):
        """`attempts` threads all try to spend `cost`; return the win count."""
        barrier = threading.Barrier(attempts)
        wins = []
        lock = threading.Lock()

        def spend():
            barrier.wait()  # maximise the overlap rather than hope for it
            if bucket.try_consume(cost):
                with lock:
                    wins.append(1)

        threads = [threading.Thread(target=spend) for _ in range(attempts)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        return len(wins)

    def test_a_bucket_with_no_refill_is_never_oversold(self):
        # A zero refill is rejected by the constructor, so the clock is frozen
        # instead: the balance can only go down, which makes the expected total
        # exact rather than approximately right.
        clock = [0.0]
        bucket = TokenBucket(50, 1.0, clock=lambda: clock[0])
        self.assertEqual(self._race(bucket, 200), 50)

    def test_the_balance_stays_in_range_after_a_race(self):
        clock = [0.0]
        bucket = TokenBucket(50, 1.0, clock=lambda: clock[0])
        self._race(bucket, 200)
        self.assertGreaterEqual(bucket.tokens, 0.0)
        self.assertEqual(bucket.tokens, 0.0)

    def test_a_multi_token_request_is_all_or_nothing(self):
        """A 10-token request either takes 10 or takes nothing.

        Partial satisfaction would be a worse bug than over-issuing: the caller
        is told it was refused, or told it succeeded, and the balance is left
        inconsistent with both answers.
        """
        clock = [0.0]
        bucket = TokenBucket(100, 1.0, clock=lambda: clock[0])
        self.assertEqual(self._race(bucket, 40, cost=10.0), 10)
        self.assertEqual(bucket.tokens, 0.0)


class TestAuditLogUnderConcurrency(unittest.TestCase):
    """The audit log is the one process-wide sink, and it writes JSON lines.

    Two `write` calls that interleave produce one merged line: unparseable, so
    a record that proved a control worked has silently become unusable. The
    test asserts what an auditor needs - every line parses, and none is lost.
    """

    def test_every_concurrent_record_is_one_whole_line(self):
        sink = io.StringIO()
        log = AuditLog(sink, clock=lambda: 1.0, enabled=True)
        writers = 16
        per_writer = 25
        barrier = threading.Barrier(writers)

        def write_my_share():
            barrier.wait()
            for index in range(per_writer):
                log.record("verify", command_id="ping", ok=True, detail=f"{index}")

        threads = [threading.Thread(target=write_my_share) for _ in range(writers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        lines = [line for line in sink.getvalue().splitlines() if line]
        self.assertEqual(len(lines), writers * per_writer)
        for line in lines:
            with self.subTest(line=line[:60]):
                # A merged line fails to parse, which is the whole failure mode.
                entry = json.loads(line)
                self.assertEqual(entry["event"], "verify")
                self.assertEqual(entry["command_id"], "ping")

    def test_the_sink_is_never_held_open_by_a_failed_write(self):
        """A raising sink must not leave the lock held and wedge every later call."""

        class Flaky(io.StringIO):
            calls = 0

            def write(self, text):
                Flaky.calls += 1
                if Flaky.calls == 1:
                    raise OSError("transient")
                return super().write(text)

        log = AuditLog(Flaky(), clock=lambda: 1.0, enabled=True)
        with contextlib.redirect_stderr(io.StringIO()):
            log.record("verify")
            log.record("verify")
        # Reached rather than deadlocked: the second write went through.
        self.assertEqual(Flaky.calls, 2)


class TestTokenBucketIsThreadSafe(unittest.TestCase):
    """A refusal is a read of the balance too, so it is part of the same race.

    The bucket tests above cover the debit; this covers the other path. It also
    pins the new part: a `RateLimited` now carries a reason code, and the
    counter that reads it has to survive a bucket being drained by eight
    threads at once.
    """

    def test_a_refusal_under_contention_still_names_a_reason(self):
        clock = [0.0]
        bucket = TokenBucket(4, 1.0, clock=lambda: clock[0])
        reasons: list[str | None] = []
        lock = threading.Lock()
        barrier = threading.Barrier(8)

        def spend():
            barrier.wait()
            try:
                bucket.consume()
            except RateLimited as exc:
                with lock:
                    reasons.append(exc.reason)

        threads = [threading.Thread(target=spend) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(len(reasons), 4)
        self.assertEqual(set(reasons), {REASON_RATE_LIMITED})


if __name__ == "__main__":
    unittest.main()
