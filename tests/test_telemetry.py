"""Guards on the observability story.

`netverify/telemetry.py` makes a specific claim: that the MCP SDK already wraps
every inbound message in a SERVER span, so this library only has to describe
its own work. That claim is load-bearing in two ways - it is what lets our
spans compose under the SDK's instead of floating as orphans, and it is what the
F2 Langfuse work will build on.

It was also, briefly, wrong in this test author's head: `MCPServer` is
constructed without `middleware=`, which looks like the OTel middleware is
absent. It is not. `MCPServer` *extends* the low-level server's default chain
rather than replacing it, and that chain starts with `OpenTelemetryMiddleware`.
Nothing asserted that, so the belief survived on plausibility alone.

These tests pin the mechanism. If a future SDK drops the default, or someone
reorders the chain so user middleware runs outside it, every span becomes an
orphan and every dashboard quietly empties - with no behaviour test failing.
That is the failure this file exists to prevent.
"""

import unittest


class TestMiddlewareIsRegistered(unittest.TestCase):
    """The claim in `telemetry.py`, checked rather than assumed."""

    def setUp(self):
        try:
            from server.app import build_server
        except ImportError:  # pragma: no cover - only when mcp is absent
            self.skipTest("the mcp SDK is not installed")
        self.server = build_server()

    def test_open_telemetry_middleware_is_in_the_chain(self):
        """If this fails, every netverify span is an orphan root trace."""
        from mcp.server._otel import OpenTelemetryMiddleware

        chain = list(self.server.middleware)
        self.assertTrue(
            any(isinstance(m, OpenTelemetryMiddleware) for m in chain),
            "no OpenTelemetryMiddleware in the server chain; our spans would be "
            "orphaned and client trace context would be ignored",
        )

    def test_telemetry_middleware_runs_outermost(self):
        """Order matters as much as presence.

        The SDK documents user middleware as running *inside* its built-ins, so
        that tool spans are children of the SERVER span rather than siblings. If
        that ever inverted, our spans would still exist but would sit outside
        the request, which is the same loss of correlation with none of the
        visibility.
        """
        from mcp.server._otel import OpenTelemetryMiddleware

        chain = list(self.server.middleware)
        otel_index = next(i for i, m in enumerate(chain) if isinstance(m, OpenTelemetryMiddleware))
        self.assertEqual(
            otel_index,
            0,
            f"OpenTelemetryMiddleware is at position {otel_index}, not outermost: {chain!r}",
        )

    def test_status_reports_the_sdk_emits_server_spans(self):
        """The self-report operators read, kept in step with reality."""
        from netverify.telemetry import status

        self.assertTrue(status()["sdk_emits_server_spans"])


class TestSpansNestUnderTheRequest(unittest.TestCase):
    """The real proof: our spans describe this library's work correctly.

    Registration is necessary but not sufficient. This asserts the attributes
    the SDK's conventions expect, and that a failing verdict is recorded as a
    result rather than an exception - the distinction the module docstring
    claims, and the one a dashboard counting errors would get wrong.

    Needs `opentelemetry-sdk`, which is a dev dependency only. Without it the
    API alone is enough to import but not to record spans, so the test skips
    rather than pretending to have checked something.
    """

    def setUp(self):
        try:
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import SimpleSpanProcessor
            from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
                InMemorySpanExporter,
            )
        except ImportError:  # pragma: no cover
            self.skipTest("opentelemetry-sdk is not installed")

        from opentelemetry import trace

        from netverify import telemetry, verify
        from tests import fixtures as fx

        self.verify = verify
        self.fixtures = fx

        # A fresh provider per test: the global one can only be set once per
        # process, so a leaked provider would make this pass or fail depending
        # on test order.
        self.exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(self.exporter))
        self._previous_provider = trace.get_tracer_provider()
        trace._TRACER_PROVIDER = provider  # noqa: SLF001 - the documented override

        # The module-level tracer is bound at import time, and the SDK's provider
        # is a no-op until one is installed, so a tracer captured earlier stays
        # silent forever. Production avoids this because `configure_from_env()`
        # installs a provider before any tool call; the test has to reproduce
        # that ordering explicitly or it would assert on an exporter that never
        # fires.
        self._previous_tracer = telemetry._TRACER  # noqa: SLF001
        telemetry._TRACER = provider.get_tracer(telemetry.TRACER_NAME)  # noqa: SLF001

    def tearDown(self):
        from opentelemetry import trace

        from netverify import telemetry

        trace._TRACER_PROVIDER = self._previous_provider  # noqa: SLF001
        telemetry._TRACER = self._previous_tracer  # noqa: SLF001

    def test_verify_span_carries_the_gen_ai_attributes(self):
        """A parallel attribute namespace would mean no standard dashboard works.

        So the names are asserted literally: `gen_ai.*` where the SDK's
        conventions apply, and `netverify.*` for what only this library knows.
        """
        self.verify("ping", self.fixtures.PING_OK, audit=None)

        spans = self.exporter.get_finished_spans()
        self.assertTrue(spans, "verify() recorded no span at all")

        ours = [s for s in spans if s.name.startswith("netverify")]
        self.assertTrue(ours, f"no netverify span among {[s.name for s in spans]}")

        attributes = dict(ours[0].attributes)
        self.assertIn("gen_ai.tool.name", attributes)
        self.assertIn("netverify.verdict.ok", attributes)
        self.assertIn("netverify.verdict.outcome", attributes)

    def test_a_failing_verdict_is_not_recorded_as_an_exception(self):
        """A down link is a result, not a crash.

        Recorded as an exception it would carry error status, and a dashboard
        counting errors would report a healthy network as broken.
        """
        self.verify("ping", self.fixtures.PING_TOTAL_LOSS, audit=None)

        ours = [s for s in self.exporter.get_finished_spans() if s.name.startswith("netverify")]
        self.assertTrue(ours)
        attributes = dict(ours[0].attributes)
        self.assertIs(attributes.get("netverify.verdict.ok"), False)
        self.assertEqual(len(ours[0].events), 0, "a failed check must not raise")


if __name__ == "__main__":
    unittest.main()
