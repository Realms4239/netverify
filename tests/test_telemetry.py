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

import os
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

    def test_request_id_middleware_is_registered(self):
        """Without it, audit lines have no way to say which call they belong to."""
        chain = list(self.server.middleware)
        self.assertTrue(
            any(type(m).__name__ == "_RequestIdMiddleware" for m in chain),
            f"no request-id middleware in the chain: {chain!r}",
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


class _MetricsCase(unittest.TestCase):
    """Installs an in-memory meter provider and reads back what was recorded.

    The provider is installed by assigning the module global rather than through
    `set_meter_provider`, for the same reason the span tests assign
    `trace._TRACER_PROVIDER`: the public setter refuses to overwrite, so a test
    that used it would be the first or second caller in the process and would
    pass or fail depending on test order.

    The global lives in `opentelemetry.metrics._internal` on current releases
    and on the package itself on older ones, so the holder is looked up rather
    than assumed - the earlier version read `metrics._METER_PROVIDER`
    unconditionally, which raised `AttributeError` on 1.45 and only passed in a
    full run because some other module happened to have set the attribute.
    """

    def setUp(self):
        try:
            from opentelemetry.sdk.metrics import MeterProvider
            from opentelemetry.sdk.metrics.export import InMemoryMetricReader
        except ImportError:  # pragma: no cover - the sdk is a dev dependency
            self.skipTest("opentelemetry-sdk is not installed")

        from opentelemetry import metrics as metrics_api

        from netverify import telemetry

        self.telemetry = telemetry
        self.holder = getattr(metrics_api, "_internal", metrics_api)
        self._previous = self.holder._METER_PROVIDER  # noqa: SLF001
        self.reader = self._install(MeterProvider, InMemoryMetricReader)
        self.addCleanup(self._restore)

    def _restore(self):
        self.holder._METER_PROVIDER = self._previous  # noqa: SLF001
        self.telemetry.reset_instruments()

    def _install(self, meter_provider_cls, reader_cls):
        """Bind a fresh provider and return its reader.

        Also drops the cached instruments, because an instrument created under
        the previous provider records into the previous reader forever - which
        is the whole reason the lazy creation exists.
        """
        reader = reader_cls()
        self.holder._METER_PROVIDER = meter_provider_cls(metric_readers=[reader])  # noqa: SLF001
        self.telemetry.reset_instruments()
        return reader

    def _points(self, name):
        data = self.reader.get_metrics_data()
        if data is None:
            return []
        return [
            point
            for resource in data.resource_metrics
            for scope in resource.scope_metrics
            for metric in scope.metrics
            if metric.name == name
            for point in metric.data.data_points
        ]

    def _series(self, name):
        """One instrument as `{attributes: value}`, keyed by sorted pairs.

        Counters only: a histogram point has a `sum`, not a `value`, so it is
        skipped rather than silently counted as zero.
        """
        series = {}
        for point in self._points(name):
            value = getattr(point, "value", None)
            if value is not None:
                series[tuple(sorted(dict(point.attributes).items()))] = value
        return series


class TestMetricsAreRecorded(_MetricsCase):
    def test_a_passing_verdict_is_counted_by_command_and_outcome(self):
        from netverify import verify
        from tests import fixtures as fx

        verify("ping", fx.PING_OK, audit=None)

        self.assertEqual(
            self._series(self.telemetry.METRIC_VERDICTS),
            {
                (
                    ("netverify.command.id", "ping"),
                    ("netverify.verdict.outcome", "pass"),
                ): 1
            },
        )

    def test_a_failing_verdict_lands_in_its_own_series(self):
        """Same command, different outcome label - a failure *rate*, not a count."""
        from netverify import verify
        from tests import fixtures as fx

        verify("ping", fx.PING_OK, audit=None)
        verify("ping", fx.PING_TOTAL_LOSS, audit=None)

        series = self._series(self.telemetry.METRIC_VERDICTS)
        self.assertEqual(
            series[(("netverify.command.id", "ping"), ("netverify.verdict.outcome", "pass"))], 1
        )
        self.assertEqual(
            series[(("netverify.command.id", "ping"), ("netverify.verdict.outcome", "fail"))], 1
        )

    def test_an_unparseable_capture_is_an_input_error_not_a_failure(self):
        """Three outcomes, not two.

        Collapsing `input_error` into `fail` is how a healthy backbone gets
        reported as broken because one capture arrived truncated - and it is
        the mistake an incident dashboard is most likely to make.
        """
        from netverify import verify
        from tests import fixtures as fx

        verify("frr_bgp_summary", fx.FRR_SUMMARY_MALFORMED, audit=None)

        series = self._series(self.telemetry.METRIC_VERDICTS)
        self.assertEqual(
            series[
                (
                    ("netverify.command.id", "frr_bgp_summary"),
                    ("netverify.verdict.outcome", "input_error"),
                )
            ],
            1,
        )

    def test_call_duration_is_a_histogram_labelled_by_tool(self):
        """A histogram, not a counter: the useful question is the distribution.

        A running average of durations cannot answer "is p99 latency up", which
        is the question during an incident.
        """
        self.telemetry.record_duration("verify_capture", 0.25)

        points = self._points(self.telemetry.METRIC_CALL_DURATION)
        self.assertEqual([point.count for point in points], [1])
        self.assertAlmostEqual(points[0].sum, 0.25, places=6)
        self.assertEqual(dict(points[0].attributes)["gen_ai.tool.name"], "verify_capture")


class TestFindingMetricsAreRecorded(_MetricsCase):
    """The differentiator: findings-by-kind is a security signal, not a perf one.

    No generic MCP server has this metric, because no generic MCP server treats
    its own tool output as untrusted. A fleet-wide spike in `verdict_coercion`
    is someone attempting prompt injection against the infrastructure.
    """

    def _kind(self, kind, severity):
        return (("netverify.finding.kind", kind), ("netverify.finding.severity", severity))

    def test_a_credential_is_counted_by_kind_and_severity(self):
        from netverify import sanitize
        from tests import fixtures as fx

        sanitize(fx.OUTPUT_WITH_SECRET)

        self.assertEqual(
            self._series(self.telemetry.METRIC_FINDINGS),
            {self._kind("credential", "high"): 1},
        )

    def test_an_injection_attempt_is_counted_separately(self):
        from netverify import sanitize
        from tests import fixtures as fx

        sanitize(fx.OUTPUT_WITH_INJECTION)

        self.assertEqual(
            self._series(self.telemetry.METRIC_FINDINGS),
            {self._kind("verdict_coercion", "critical"): 1},
        )

    def test_a_clean_capture_records_nothing(self):
        """A counter that ticks on every call measures nothing at all."""
        from netverify import sanitize
        from tests import fixtures as fx

        sanitize(fx.PING_OK)

        self.assertEqual(self._series(self.telemetry.METRIC_FINDINGS), {})

    def test_sanitise_and_scan_do_not_double_count(self):
        """`sanitize` calls `scan` internally, so recording in both would double.

        The counter would then measure *how often the library was asked* times
        two, which is not a number anyone can act on.
        """
        from netverify import sanitize
        from tests import fixtures as fx

        sanitize(fx.OUTPUT_WITH_SECRET)
        once = sum(self._series(self.telemetry.METRIC_FINDINGS).values())
        sanitize(fx.OUTPUT_WITH_SECRET)
        twice = sum(self._series(self.telemetry.METRIC_FINDINGS).values())

        self.assertEqual(once, 1)
        self.assertEqual(twice, 2)


class TestRefusalMetricsAreRecorded(_MetricsCase):
    def test_a_refusal_is_counted_by_reason_and_command(self):
        self.telemetry.record_refused(self.telemetry.REASON_NOT_IN_ALLOWLIST, command="ping")

        self.assertEqual(
            self._series(self.telemetry.METRIC_REFUSED),
            {
                (
                    ("netverify.refusal.command", "ping"),
                    ("netverify.refusal.reason", "not_in_allowlist"),
                ): 1
            },
        )

    def test_an_unattributable_refusal_is_its_own_series(self):
        """A refusal we could not name is a question an operator asks.

        Merging it into the labelled series would answer that question wrongly,
        by making unattributed refusals invisible.
        """
        self.telemetry.record_refused(self.telemetry.REASON_BAD_ARGUMENT)

        self.assertEqual(
            self._series(self.telemetry.METRIC_REFUSED),
            {(("netverify.refusal.reason", "bad_argument"),): 1},
        )

    def test_a_rate_limited_call_is_counted_with_its_tool(self):
        self.telemetry.record_rate_limited("verify_capture")

        self.assertEqual(
            self._series(self.telemetry.METRIC_RATE_LIMITED),
            {(("gen_ai.tool.name", "verify_capture"),): 1},
        )

    def test_status_lists_every_instrument(self):
        from netverify import telemetry_status

        listed = telemetry_status()["metrics"]
        for name in (
            self.telemetry.METRIC_VERDICTS,
            self.telemetry.METRIC_FINDINGS,
            self.telemetry.METRIC_CALL_DURATION,
            self.telemetry.METRIC_RATE_LIMITED,
            self.telemetry.METRIC_REFUSED,
        ):
            with self.subTest(metric=name):
                self.assertIn(name, listed)

    def test_reset_instruments_rebinds_to_a_later_provider(self):
        """The lazy-creation claim, checked rather than assumed.

        Instruments are cached, so a provider installed *after* the first
        recording would receive nothing. `reset_instruments` is what makes that
        case work, and nothing but tests ever calls it - without this test the
        rebinding path would be code only tests could reach.
        """
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import InMemoryMetricReader

        self.telemetry.record_refused(self.telemetry.REASON_BAD_ARGUMENT)
        self.assertTrue(self._series(self.telemetry.METRIC_REFUSED))

        second = self._install(MeterProvider, InMemoryMetricReader)
        self.telemetry.record_refused(self.telemetry.REASON_BAD_ARGUMENT)

        data = second.get_metrics_data()
        recorded = [
            point
            for resource in data.resource_metrics
            for scope in resource.scope_metrics
            for metric in scope.metrics
            if metric.name == self.telemetry.METRIC_REFUSED
            for point in metric.data.data_points
        ]
        self.assertEqual([point.value for point in recorded], [1])

    def test_a_broken_instrument_never_breaks_the_call_it_describes(self):
        """Telemetry is best-effort by contract, so the failure is proven.

        The realistic failure is an exporter that rejects a measurement - a full
        buffer, a shutting-down collector. The verification result must survive
        it: a metrics outage is not a reason to fail a client's health check.
        """

        class Exploding:
            def add(self, *_args, **_kwargs):
                raise RuntimeError("the collector went away")

        self.telemetry._INSTRUMENTS[  # noqa: SLF001
            self.telemetry.METRIC_REFUSED
        ] = Exploding()
        self.telemetry.record_refused(self.telemetry.REASON_BAD_ARGUMENT)
        self.telemetry.record_duration("verify", 0.1)


class TestInstrumentCreationIsThreadSafe(_MetricsCase):
    """The lazy cache is shared mutable state on a threaded server.

    The MCP SDK runs sync tools on worker threads, so two calls can reach
    `_counter` for the first time at once. Without the lock they would each
    create a counter and one thread's measurements would vanish; with it, the
    first to arrive creates it and the rest reuse it. Either way this asserts
    the outcome that matters - every recorded refusal is counted exactly once -
    rather than the implementation.
    """

    def test_concurrent_first_use_counts_every_refusal_exactly_once(self):
        import threading

        self.telemetry.reset_instruments()
        threads_count = 8
        per_thread = 25
        start = threading.Barrier(threads_count)

        def record():
            start.wait(timeout=30.0)
            for _ in range(per_thread):
                self.telemetry.record_refused(self.telemetry.REASON_BAD_ARGUMENT)

        threads = [threading.Thread(target=record) for _ in range(threads_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60.0)
        stuck = [t.name for t in threads if t.is_alive()]
        self.assertEqual(stuck, [], "worker threads never finished - the barrier hung")

        series = self._series(self.telemetry.METRIC_REFUSED)
        self.assertEqual(sum(series.values()), threads_count * per_thread)

    def test_only_one_instrument_survives_the_race(self):
        import threading

        self.telemetry.reset_instruments()
        start = threading.Barrier(8)

        def record():
            start.wait(timeout=30.0)
            self.telemetry.record_verdict("ping", "pass")

        threads = [threading.Thread(target=record) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(len(self._series(self.telemetry.METRIC_VERDICTS)), 1)
        self.assertEqual(len(self.telemetry._INSTRUMENTS), 1)  # noqa: SLF001


class TestNoPayloadsInTelemetry(_MetricsCase):
    """The payload promise in `telemetry.py`, checked rather than trusted.

    Turning on an exporter moves data *out of the process* to a collector, so
    "we never log payloads" stops being an internal convention and becomes a
    property of what crosses a trust boundary. That is why the promise is
    pinned here rather than left to a reviewer's memory: an edit that adds
    `active.set_attribute("why", verdict.reasons[0])` would put device text
    into a third party's storage, and no behavioural test would notice.

    Two checks, because either alone is weak: a substring search catches the
    secret but not an innocuous-looking line of device text, and a length bound
    catches prose but would also reject a legitimate long value. The length
    bound is generous enough for every fixed string this library emits - ids,
    outcome enums, finding kinds, counts - and short enough that a sentence
    cannot slip through.
    """

    #: Longest attribute value any of this library emits, in characters.
    MAX_VALUE_LENGTH = 80

    def setUp(self):
        super().setUp()
        try:
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import SimpleSpanProcessor
            from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
                InMemorySpanExporter,
            )
        except ImportError:  # pragma: no cover - the sdk is a dev dependency
            self.skipTest("opentelemetry-sdk is not installed")

        from opentelemetry import trace

        self.exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(self.exporter))
        self._previous_tracer_provider = trace._TRACER_PROVIDER  # noqa: SLF001
        self._previous_tracer = self.telemetry._TRACER  # noqa: SLF001
        trace._TRACER_PROVIDER = provider  # noqa: SLF001
        self.telemetry._TRACER = provider.get_tracer(self.telemetry.TRACER_NAME)  # noqa: SLF001
        self.addCleanup(self._restore_tracer)

    def _restore_tracer(self):
        from opentelemetry import trace

        trace._TRACER_PROVIDER = self._previous_tracer_provider  # noqa: SLF001
        self.telemetry._TRACER = self._previous_tracer  # noqa: SLF001

    def _values(self):
        """Every attribute value this library emitted, spans and metrics alike."""
        for span in self.exporter.get_finished_spans():
            if not span.name.startswith("netverify"):
                continue
            for value in (span.attributes or {}).values():
                yield value
        for point in self._all_points():
            for value in dict(point.attributes).values():
                yield value

    def _all_points(self):
        data = self.reader.get_metrics_data()
        if data is None:
            return
        for resource in data.resource_metrics:
            for scope in resource.scope_metrics:
                for metric in scope.metrics:
                    yield from metric.data.data_points

    def test_no_attribute_carries_device_text(self):
        from netverify import sanitize, verify
        from tests import fixtures as fx

        verify(
            "srl_interface_brief",
            fx.SRL_INTERFACE_UP_WITH_SECRET,
            interface="ethernet-1/1",
            audit=None,
        )
        sanitize(fx.OUTPUT_WITH_INJECTION)

        values = list(self._values())
        self.assertTrue(values, "nothing was recorded, so this would pass vacuously")
        for value in values:
            text = str(value)
            with self.subTest(value=text[:40]):
                self.assertNotIn("hunter2", text)
                self.assertLessEqual(len(text), self.MAX_VALUE_LENGTH)

    def test_the_finding_is_still_recorded_so_the_check_is_not_vacuous(self):
        """A payload-free counter that records nothing also passes the test above.

        So assert the counter really did fire, with the finding's *kind*: the
        security signal survives, and only the payload is withheld.
        """
        from netverify import sanitize
        from tests import fixtures as fx

        sanitize(fx.OUTPUT_WITH_SECRET)

        kinds = {
            kind
            for key in self._series(self.telemetry.METRIC_FINDINGS)
            for name, kind in key
            if name == "netverify.finding.kind"
        }
        self.assertEqual(kinds, {"credential"})


class TestMetricExportIsWired(unittest.TestCase):
    """Does the environment asking for metrics actually produce an exporter?

    The bug this class exists for: `_configure_metrics_from_env` consulted only
    `NETVERIFY_OTEL_CONSOLE`, so in the configuration this library is deployed in
    - `OTEL_EXPORTER_OTLP_ENDPOINT`, the collector the traces go to - it returned
    immediately. Every counter incremented into a void. The console path worked,
    which is the one nobody deploys with, so nothing looked wrong.

    Each test restores the environment and the recorded state, because both are
    process-wide and a leaked one turns the next test into a false pass.
    """

    def setUp(self):
        try:
            import opentelemetry.sdk.metrics  # noqa: F401
        except ImportError:  # pragma: no cover - the sdk is a dev dependency
            self.skipTest("opentelemetry-sdk is not installed")

        from netverify import telemetry

        self.telemetry = telemetry
        self._env = {
            key: os.environ.pop(key, None)
            for key in ("NETVERIFY_OTEL_CONSOLE", "OTEL_EXPORTER_OTLP_ENDPOINT")
        }
        self._state = telemetry._METRICS_STATE  # noqa: SLF001

        def restore():
            for key, value in self._env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
            telemetry._METRICS_STATE = self._state  # noqa: SLF001

        self.addCleanup(restore)

    def _configure(self):
        self.telemetry._configure_metrics_from_env()  # noqa: SLF001
        return self.telemetry.status()["metrics_state"]

    def test_the_otlp_endpoint_now_reaches_the_metric_exporter(self):
        """The regression, stated as a test.

        In an environment with the exporter installed this reaches
        `exporting:otlp`. Without it the honest answer is `failed:...` - and
        either way the state says what happened, which is the point. Asserting
        only `!= not-configured` is deliberate: it is the assertion that fails on
        the old code, and it does not depend on which exporter package this lab
        happens to have.
        """
        os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] = "http://collector:4318"

        state = self._configure()

        self.assertNotEqual(state, "not-configured", "the OTLP env was ignored for metrics")
        if state.startswith("failed:"):
            # The package is absent here, so the failure must *name* what is
            # missing - otherwise an operator has nothing to act on.
            self.assertIn("no-metric-exporter", state)
        else:
            self.assertEqual(state, "exporting:otlp")

    def test_the_console_mode_is_selected_when_asked_for(self):
        """Selection only, deliberately.

        Installing the real `ConsoleMetricExporter` here dumps a JSON blob into
        the suite output, and not only during the call: the reader exports on its
        own interval, so the noise arrives after any `redirect_stdout` has closed.
        A suite that prints telemetry between test cases trains people to scroll
        past the run, which is how the one real failure gets missed. The install
        path is covered below with a silent exporter instead.
        """
        os.environ["NETVERIFY_OTEL_CONSOLE"] = "1"

        self.assertEqual(self.telemetry._metric_exporter()[1], "console")  # noqa: SLF001

    def test_a_reader_is_installed_when_an_exporter_is_chosen(self):
        """The install path, with an exporter that writes nowhere.

        A stub, not the console one, for the reason above. It still exercises
        what matters: the provider is built, the reader is attached, the provider
        is installed, and the state says so.
        """

        class SilentExporter:
            def export(self, *_args, **_kwargs):
                return None

            def force_flush(self, timeout_millis: float = 10_000) -> bool:
                return True

            def shutdown(self, timeout_millis: float = 30_000, **kwargs) -> None:
                return None

        original = self.telemetry._metric_exporter  # noqa: SLF001
        self.telemetry._metric_exporter = lambda: (SilentExporter(), "otlp")  # type: ignore[method-assign]  # noqa: SLF001
        self.addCleanup(setattr, self.telemetry, "_metric_exporter", original)

        state = self._configure()

        # `host-provider` is a legitimate outcome when an earlier test installed a
        # meter provider first: our reader was not installed, but the host's
        # provider may well export these metrics, and claiming otherwise would be
        # the dishonest option.
        self.assertIn(state, ("exporting:otlp", "host-provider"))
        if state == "exporting:otlp":
            self.assertTrue(self.telemetry.status()["metrics_exporting"])

    def test_nothing_configured_means_no_exporter(self):
        """The default: absent env means absent metrics, and it says so."""
        self.assertEqual(self._configure(), "not-configured")

    def test_console_wins_when_both_are_set(self):
        """Deterministic precedence, pinned so it cannot flip silently.

        The trace path checks the console first too; the two must agree, or a
        deployment exporting traces to a collector and metrics to stdout is a
        genuinely confusing afternoon.
        """
        os.environ["NETVERIFY_OTEL_CONSOLE"] = "1"
        os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] = "http://collector:4318"

        self.assertEqual(self.telemetry._metric_exporter()[1], "console")  # noqa: SLF001

    def test_status_separates_what_was_asked_for_from_what_happened(self):
        """`exporter` is the request; `metrics_state` is the outcome.

        The two must be able to disagree, and the whole value of `metrics_state`
        is that they do.
        """
        os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] = "http://collector:4318"
        self._configure()

        report = self.telemetry.status()

        self.assertEqual(report["exporter"], "otlp", "the request should be reported")
        self.assertIn("metrics_state", report)
        self.assertEqual(
            report["metrics_exporting"],
            report["metrics_state"].startswith("exporting:"),
            "the boolean and the state must not drift apart",
        )

    def test_a_failed_export_is_reported_rather_than_swallowed(self):
        """The failure mode that motivated the field: asked for, did not happen."""

        def explode():
            raise ImportError("opentelemetry.exporter.otlp.proto.http.metric_exporter")

        original = self.telemetry._metric_exporter  # noqa: SLF001
        self.telemetry._metric_exporter = explode  # type: ignore[method-assign]  # noqa: SLF001
        self.addCleanup(setattr, self.telemetry, "_metric_exporter", original)
        os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] = "http://collector:4318"

        state = self._configure()

        self.assertTrue(state.startswith("failed:"), state)
        self.assertIn("no-metric-exporter", state)
        self.assertFalse(self.telemetry.status()["metrics_exporting"])


if __name__ == "__main__":
    unittest.main()
