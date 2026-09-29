"""The two protocol extensions that are easy to claim and hard to notice working.

Both were requested items, and both fail *silently* if wired up wrongly:

- **Progress notifications.** The SDK injects a request context only into a
  parameter whose resolved type hint is a `Context`. Get the annotation subtly
  wrong - `Optional[Context[Any, Any]]`, a string, a `TYPE_CHECKING` import - and
  nothing is injected, no error is raised, and the tool simply never reports
  progress. So the injection is asserted against the SDK's own detection
  function rather than against behaviour, and the notification is then driven
  through the same worker-thread path the SDK uses.
- **Cache hints (SEP-2549).** A hint that never reaches the wire is a comment
  with an import. The assertion is therefore made on the *result object* the
  client receives - `ttl_ms` and `cache_scope` - because that is where a wrong
  key, a missing `scope`, or a hint the SDK dropped would show up.
"""

import asyncio
import functools
import time
import unittest


class RecordingContext:
    """Just enough context for the adapter: it only calls `report_progress`.

    A stub rather than a real `Context` on purpose. If the adapter ever starts
    reaching for something else - `request_context`, a session, a capability
    check - a stub fails loudly here instead of quietly working against a mock
    that grew the same shape.
    """

    def __init__(self, delay: float = 0.0) -> None:
        self.seen: list[tuple[float, float | None, str | None]] = []
        self.delay = delay

    async def report_progress(self, progress, total=None, message=None) -> None:
        if self.delay:
            # Real notifications are I/O. The sleep is what proves the adapter
            # *waits* rather than firing and forgetting - see the ordering test.
            await asyncio.sleep(self.delay)
        self.seen.append((progress, total, message))


def _captures(count: int = 3) -> list[dict[str, str]]:
    from tests import fixtures as fx

    return [{"command": "ping", "output": fx.PING_OK} for _ in range(count)]


class TestProgressNotifications(unittest.TestCase):
    def setUp(self):
        try:
            from server.app import verify_capture
        except ImportError:  # pragma: no cover - only when mcp is absent
            self.skipTest("the mcp SDK is not installed")
        self.verify_capture = verify_capture

    def test_the_sdk_can_actually_find_the_context_parameter(self):
        """The negative control: an annotation the SDK cannot read is a silent no-op.

        `Optional[Context[Any, Any]]` looks equivalent and is not - the SDK walks
        the union's arguments looking for a *class*, and a subscripted generic is
        not one. A plain `Context` inside the union is, which is why the
        annotation is written the way it is.
        """
        from mcp.server.mcpserver.utilities.context_injection import find_context_parameter

        self.assertEqual(find_context_parameter(self.verify_capture), "ctx")

    def test_one_notification_per_entry_reaching_the_wire(self):
        ctx = RecordingContext()

        self.verify_capture(_captures(4), ctx=ctx)

        self.assertEqual(
            [(progress, total) for progress, total, _ in ctx.seen],
            [(1, 4), (2, 4), (3, 4), (4, 4)],
        )
        self.assertEqual(ctx.seen[-1][2], "verified 4/4")

    def test_a_refused_entry_still_advances_the_count(self):
        """A progress channel that stalls on the interesting entries is worse than none."""
        from tests import fixtures as fx

        ctx = RecordingContext()
        self.verify_capture(
            [
                {"command": "ping", "output": fx.PING_OK},
                {"command": "no_such_command", "output": "anything"},
                {"command": "ping", "output": fx.PING_TOTAL_LOSS},
            ],
            ctx=ctx,
        )

        self.assertEqual([p for p, _, _ in ctx.seen], [1, 2, 3])

    def test_the_notification_is_finished_before_the_result_is_returned(self):
        """Ordering, asserted through a delay rather than by reading the code.

        Firing the notification and moving on would let the final result reach the
        client ahead of the last update, so a client rendering "3/3" under an
        answer that already arrived looks broken. A fire-and-forget bridge makes
        the batch take about as long as the verifications; blocking makes it take
        the notifications too.
        """
        delay = 0.02
        ctx = RecordingContext(delay=delay)

        started = time.perf_counter()
        self.verify_capture(_captures(3), ctx=ctx)
        elapsed = time.perf_counter() - started

        self.assertEqual(len(ctx.seen), 3)
        # A generous floor: three notifications at `delay` cannot finish in less.
        # Not the exact sum, because the floor only has to separate "waited" from
        # "did not", and a tight bound would be a flaky test on a loaded box.
        self.assertGreaterEqual(elapsed, delay * 2)

    def test_no_context_means_no_progress_and_no_failure(self):
        """The direct-call path (tests, REPL) has nobody to notify, and must work."""
        result = self.verify_capture(_captures(2))
        self.assertEqual(result["ok_count"], 2)

    def test_a_broken_progress_channel_does_not_fail_the_batch(self):
        """A client that hung up mid-batch is not a reason to lose 197 verdicts."""

        class Broken(RecordingContext):
            async def report_progress(self, progress, total=None, message=None):
                raise RuntimeError("the client went away")

        result = self.verify_capture(_captures(2), ctx=Broken())
        self.assertEqual(result["ok_count"], 2)

    def test_the_library_callback_is_plain_and_never_awaits(self):
        """The package cannot import `asyncio`, so the seam stays synchronous.

        `integrity.py` lists `asyncio` among the network-capable modules: it can
        open a socket, and a verifier with no route to the device has no business
        importing it. So `verify_many` takes a plain callable, and the only place
        a coroutine may appear is this adapter.
        """
        from netverify.verify import verify_many

        seen: list[tuple[int, int]] = []
        verify_many(
            [{"command": "ping", "output": "3 packets transmitted, 3 received, 0% loss"}],
            audit=None,
            progress=lambda done, total: seen.append((done, total)),
        )
        self.assertEqual(seen, [(1, 1)])

    def test_progress_survives_a_worker_thread_call(self):
        """The real dispatch path: the SDK runs sync tools off the event loop.

        `anyio.to_thread.run_sync` is exactly what `call_fn` does, so this
        reproduces the SDK's own call shape - including the absence of a running
        loop on the thread, which is what a naive `await` in the tool body would
        trip over.
        """
        import anyio

        ctx = RecordingContext()

        async def call_it():
            return await anyio.to_thread.run_sync(
                functools.partial(self.verify_capture, _captures(2), ctx)
            )

        result = asyncio.run(call_it())
        self.assertEqual(result["ok_count"], 2)
        self.assertEqual([p for p, _, _ in ctx.seen], [1, 2])


class TestCacheHints(unittest.TestCase):
    def setUp(self):
        try:
            from server.app import CACHE_HINTS, build_server

            self.hints = CACHE_HINTS
            self.server = build_server()
        except ImportError:  # pragma: no cover - only when mcp is absent
            self.skipTest("the mcp SDK is not installed")

    def test_every_cacheable_method_is_hinted(self):
        """All six, and no others.

        Not "at least one": the point of the declaration is that a client can
        cache the listings, and a hint on `tools/list` alone still leaves the
        agent re-reading the command catalogue on every turn.
        """
        from mcp_types.methods import CACHEABLE_METHODS

        self.assertEqual(set(self.hints), set(CACHEABLE_METHODS))

    def test_the_keys_are_methods_the_sdk_accepts(self):
        from mcp.server.caching import validate_cache_hints

        # Raises on a bad key. Asserted because a typo would otherwise produce a
        # hint that silently applies to nothing.
        self.assertEqual(set(validate_cache_hints(self.hints)), set(self.hints))

    def test_every_hint_is_public_and_non_stale(self):
        for method, hint in self.hints.items():
            with self.subTest(method=method):
                # `private` would be wrong: this server holds no per-session
                # state, and a shared cache is the entire benefit.
                self.assertEqual(hint.scope, "public")
                # A zero TTL means "immediately stale", i.e. a hint that lies
                # about being a hint.
                self.assertGreater(hint.ttl_ms, 0)

    def test_the_hint_survives_the_high_level_constructor(self):
        """The plumbing, not the mechanism.

        `MCPServer` forwards `cache_hints` to the low-level `Server`; a
        misspelled keyword or a future SDK that drops the argument would leave
        the declaration looking correct in this file and applying to nothing at
        runtime, and nothing else in the suite would notice.
        """
        self.assertEqual(self.server._lowlevel_server.cache_hints, dict(self.hints))  # noqa: SLF001

    def test_the_sdk_fills_the_fields_a_client_reads(self):
        """The mechanism the declaration feeds, exercised with our own hint.

        Not the same as observing a real response: the high-level `list_tools()`
        returns a plain list, and the low-level handler needs a full request
        context to build. So this drives the SDK's own `apply_cache_hint` with the
        hint we declared - which is what the server does per result - and
        asserts the two fields a client reads.
        """
        from mcp.server.caching import apply_cache_hint
        from mcp_types import ListToolsResult

        result = apply_cache_hint(ListToolsResult(tools=[]), self.hints["tools/list"])

        self.assertEqual(result.ttl_ms, 300_000)
        self.assertEqual(result.cache_scope, "public")

    def test_tool_calls_are_not_hinted(self):
        """`tools/call` takes caller data, so no verdict is ever served from cache.

        Not in the cacheable set at all, which is the strongest form of the
        guarantee: there is no hint here to get wrong.
        """
        from mcp_types.methods import CACHEABLE_METHODS

        self.assertNotIn("tools/call", CACHEABLE_METHODS)
        self.assertNotIn("tools/call", self.hints)


if __name__ == "__main__":
    unittest.main()
