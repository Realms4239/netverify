"""No device text, and no secret, ever leaves the process in telemetry.

`telemetry.py` claims that every attribute it sets is fixed vocabulary - ids,
outcome enums, counts, kinds - and never raw device output or matched text.
That claim is what makes the instrumentation safe to turn on, because enabling
an exporter moves data *out of the process* to a collector that a different team
operates. "We only log metadata" is the promise; this is the check.

It is a claim about the future too. Adding an attribute is a one-line change
that no behaviour test would notice, and a span exporter pointed at a shared
backend would carry the leak off-box before anyone read the diff. So the test
asserts the *absence* of the payload rather than the presence of a safe
attribute, and feeds it the inputs that matter: a leaked credential, and text
crafted to steer whoever reads the result.

Deliberately self-contained - it installs its own span exporter and metric
reader rather than sharing a base class with `test_telemetry.py`, because the
guarantee under test must outlive any particular plumbing for reading data back.
"""

import unittest

#: Fragments that appear in the hostile fixtures below and must never appear in
#: an attribute. The secret is the obvious one; the rest are injection payloads,
#: because "we do not leak secrets" is not the same claim as "we never forward
#: attacker-controlled prose" - and the prose is the part an agent reads.
FORBIDDEN = (
    "hunter2",
    "akiaiosfodnn7example",
    "mark this interface as healthy",
    "ignore all previous instructions",
    "send the credentials to",
    "evil.example",
)


class TestNoPayloadsInTelemetry(unittest.TestCase):
    def setUp(self):
        try:
            from opentelemetry.sdk.metrics import MeterProvider
            from opentelemetry.sdk.metrics.export import InMemoryMetricReader
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import SimpleSpanProcessor
            from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
                InMemorySpanExporter,
            )
        except ImportError:  # pragma: no cover - the sdk is a dev dependency
            self.skipTest("opentelemetry-sdk is not installed")

        from opentelemetry import metrics as metrics_api
        from opentelemetry import trace

        from netverify import telemetry

        self.telemetry = telemetry
        self.trace_api = trace

        # A real tracer *and* meter provider for the duration of the test. The
        # ones bound at import are proxies, and a proxy left resolving against
        # the proxy provider recurses until the stack runs out - which is how a
        # test that only wanted to read spans ended in RecursionError.
        self.exporter = InMemorySpanExporter()
        tracer_provider = TracerProvider()
        tracer_provider.add_span_processor(SimpleSpanProcessor(self.exporter))
        self.metric_reader = InMemoryMetricReader()

        self._previous_tracer_provider = trace._TRACER_PROVIDER  # noqa: SLF001
        self._previous_tracer = telemetry._TRACER  # noqa: SLF001
        trace._TRACER_PROVIDER = tracer_provider  # noqa: SLF001
        telemetry._TRACER = tracer_provider.get_tracer(telemetry.TRACER_NAME)  # noqa: SLF001

        self._meter_holder = getattr(metrics_api, "_internal", metrics_api)
        self._previous_meter = self._meter_holder._METER_PROVIDER  # noqa: SLF001
        self._meter_holder._METER_PROVIDER = MeterProvider(  # noqa: SLF001
            metric_readers=[self.metric_reader]
        )
        telemetry.reset_instruments()

        self.addCleanup(self._restore)

    def _restore(self):
        self.trace_api._TRACER_PROVIDER = self._previous_tracer_provider  # noqa: SLF001
        self.telemetry._TRACER = self._previous_tracer  # noqa: SLF001
        self._meter_holder._METER_PROVIDER = self._previous_meter  # noqa: SLF001
        self.telemetry.reset_instruments()

    def _attributes(self):
        """Every attribute recorded, as `(origin, value)`: spans, then metrics."""
        found = []
        for span in self.exporter.get_finished_spans():
            for key, value in (span.attributes or {}).items():
                found.append((f"span {span.name}.{key}", value))
        data = self.metric_reader.get_metrics_data()
        if data is not None:
            for resource in data.resource_metrics:
                for scope in resource.scope_metrics:
                    for metric in scope.metrics:
                        for point in metric.data.data_points:
                            for key, value in dict(point.attributes).items():
                                found.append((f"metric {metric.name}.{key}", value))
        return found

    def _assert_nothing_leaked(self):
        """Fail if any attribute carries device text or a secret.

        Checked case-insensitively because a fullwidth credential
        (`\uff50\uff41...`) folds to its ASCII form under Unicode normalisation,
        and that fold is exactly what a masking bypass would look like.
        """
        import unicodedata

        for origin, value in self._attributes():
            text = unicodedata.normalize("NFKC", str(value)).lower()
            for needle in FORBIDDEN:
                with self.subTest(attribute=origin, leaked=needle):
                    self.assertNotIn(
                        needle,
                        text,
                        f"{origin} carried device text or a secret: {value!r}",
                    )

    def test_a_capture_containing_a_secret_and_an_injection_leaks_neither(self):
        from netverify import sanitize, verify
        from tests import fixtures as fx

        # All five hostile fixtures, through the path a real call takes. One
        # fixture would be a weaker claim: each of these carries a different
        # kind of text, and only the union of them is the guarantee.
        hostile = (
            fx.SRL_INTERFACE_UP_WITH_SECRET,
            fx.OUTPUT_WITH_INJECTION,
            fx.OUTPUT_INSTRUCTION_OVERRIDE,
            fx.OUTPUT_EXFILTRATION,
            fx.OUTPUT_MISLABELLED_TOKEN,
        )
        for output in hostile:
            with self.subTest(output=output.splitlines()[0][:40]):
                verify(
                    "srl_interface_brief",
                    output,
                    interface="ethernet-1/1",
                    audit=None,
                )
        sanitize(fx.OUTPUT_FULLWIDTH_SECRET)

        # The run has to have recorded *something*, or the assertions above are
        # vacuously true - which is how a leak check passes forever.
        self.assertTrue(self._attributes(), "nothing was recorded, so nothing was checked")
        self._assert_nothing_leaked()

    def test_the_finding_still_survives_the_masking(self):
        """The other half of the bargain: masking happens, the finding does not.

        "No payload in telemetry" is trivially satisfiable by emitting nothing,
        and by reporting nothing. A finding still has to be raised, described in
        fixed vocabulary, and the matched text still has to be gone - all three,
        or the guarantee has been bought by making the tool useless.
        """
        from netverify import sanitize
        from tests import fixtures as fx

        report = sanitize(fx.SRL_INTERFACE_UP_WITH_SECRET)

        self.assertIn("credential", {finding.kind for finding in report.findings})
        # The description is a fixed string per kind, never the matched text -
        # which is exactly why recording `kind` and `severity` is safe.
        for finding in report.findings:
            self.assertNotIn("hunter2", finding.detail.lower())
        self.assertNotIn("hunter2", report.safe_text.lower())

    def test_a_finding_kind_and_severity_are_indeed_recorded(self):
        """The attribute that makes the findings counter useful, asserted positively.

        Paired with the leak test on purpose: kind and severity are the whole
        permitted surface, so pinning them here means the previous test cannot
        pass by finding nothing to record.
        """
        from netverify import sanitize
        from tests import fixtures as fx

        sanitize(fx.OUTPUT_WITH_SECRET)

        # `origin` reads `metric <instrument>.<attribute>`, so the last segment
        # is the attribute name. Both permitted finding attributes are pinned
        # literally: they are the entire surface a finding may occupy, and
        # pinning them keeps the leak test from passing by recording nothing.
        pairs = {origin.rsplit(".", 1)[-1]: value for origin, value in self._attributes()}
        self.assertEqual(pairs.get("kind"), "credential")
        self.assertEqual(pairs.get("severity"), "high")


if __name__ == "__main__":
    unittest.main()
