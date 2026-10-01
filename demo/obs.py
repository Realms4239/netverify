#!/usr/bin/env python3
"""Observability bootstrap for the live demo server.

Installs real OpenTelemetry SDK providers with in-memory exporters BEFORE the
netverify/server modules are imported, so every tracer and meter in the
process - the SDK's SERVER spans and this library's own instruments - resolves
against them. The dashboard then reads what actually flowed, not what the code
claims.

Why in-memory: the process is a local demonstration server, and the whole
point is that the numbers shown are the numbers recorded. The exporters are
the SDK's own `InMemorySpanExporter` and `InMemoryMetricReader`; an OTLP
endpoint stays available through the same environment variables the library
already honours, and this module reads them back honestly in `status()`.

The provider-swap trap the tests document is avoided structurally: the
provider is installed exactly once, before any instrument exists, and never
swapped or restored. `reset_instruments()` is called once after import so the
lazy instruments bind to this provider rather than to a no-op.
"""

from __future__ import annotations

import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from opentelemetry import metrics as _metrics_api  # noqa: E402
from opentelemetry import trace as _trace_api  # noqa: E402
from opentelemetry.sdk.metrics import MeterProvider  # noqa: E402
from opentelemetry.sdk.metrics.export import InMemoryMetricReader  # noqa: E402
from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import SimpleSpanProcessor  # noqa: E402
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (  # noqa: E402
    InMemorySpanExporter,
)

#: Module-level, so the HTTP layer can read what the process recorded.
span_exporter = InMemorySpanExporter()
metric_reader = InMemoryMetricReader()

_provider = TracerProvider(resource=None)
_provider.add_span_processor(SimpleSpanProcessor(span_exporter))
_trace_api.set_tracer_provider(_provider)
_metrics_api.set_meter_provider(MeterProvider(metric_readers=[metric_reader]))

#: Only NOW import the library - tracers and instruments bind to the provider
#: above, not to a no-op. The server stack itself is imported by the caller
#: (`demo/live_server.py`) immediately after this module, so it lands under the
#: same providers; this module needs none of it, so it imports none of it.
import netverify.telemetry as telemetry  # noqa: E402

telemetry.reset_instruments()


def snapshot_spans(since: int = 0) -> list[dict]:
    """Serialise finished spans from index `since`, oldest first.

    Attributes are passed through as the SDK recorded them. The library's
    payload discipline (tests/test_telemetry_payloads.py) guarantees no span
    attribute carries raw device output or a matched secret, so forwarding
    them to a dashboard cannot leak what the suite says they cannot contain.
    """
    spans = span_exporter.get_finished_spans()
    out = []
    for span in spans[since:]:
        ctx = span.get_span_context()
        start_ns = span.start_time or 0
        end_ns = span.end_time or start_ns
        out.append(
            {
                "name": span.name,
                "trace_id": format(ctx.trace_id, "032x"),
                "span_id": format(ctx.span_id, "016x"),
                "parent_id": format(span.parent.span_id, "016x") if span.parent else None,
                "duration_ms": round((end_ns - start_ns) / 1_000_000, 3),
                "t": time.strftime("%H:%M:%S", time.localtime(start_ns / 1e9)),
                "attributes": {k: v for k, v in dict(span.attributes or {}).items()},
            }
        )
    return out, len(spans)  # type: ignore[return-value]


def snapshot_metrics() -> list[dict]:
    """One collection of the current counter/histogram state."""
    data = metric_reader.get_metrics_data()
    if data is None:
        return []
    out = []
    for resource_metrics in data.resource_metrics:
        for scope_metrics in resource_metrics.scope_metrics:
            for metric in scope_metrics.metrics:
                for point in metric.data.data_points:
                    entry = {
                        "name": metric.name,
                        "attributes": {k: v for k, v in dict(point.attributes or {}).items()},
                    }
                    value = getattr(point, "value", None)
                    if value is None and hasattr(point, "count"):
                        # Histogram: show count and the mean, which is what a
                        # dashboard answers ("how slow is a verdict?") without
                        # shipping the full bucket layout.
                        count = point.count or 0
                        entry["value"] = count
                        entry["mean_ms"] = round((point.sum or 0) / count * 1000, 3) if count else 0
                        entry["is_histogram"] = True
                    else:
                        entry["value"] = value
                    out.append(entry)
    return out


def telemetry_status() -> dict:
    """The library's own status, plus what this process demonstrably has."""
    status = dict(telemetry.status())
    spans = span_exporter.get_finished_spans()
    status["spans_recorded"] = len(spans)
    status["host_provider"] = "in-memory (collected by this dashboard)"
    return status


def reset_span_cursor() -> int:
    """The index a caller should pass as `since` to see only new spans."""
    return len(span_exporter.get_finished_spans())
