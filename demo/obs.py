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
#: Bounded on purpose: the exporter holds every span it is given, and a
#: console left running for days would otherwise grow without limit - a
#: stress harness measures the growth, not the intention. 2000 spans is
#: roughly the last hour of active use; /api/telemetry serves the newest 120.
MAX_SPANS = 2000
span_exporter = InMemorySpanExporter(max_spans=MAX_SPANS)
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


def _serialise(span) -> dict:
    ctx = span.get_span_context()
    start_ns = span.start_time or 0
    end_ns = span.end_time or start_ns
    return {
        "name": span.name,
        "trace_id": format(ctx.trace_id, "032x"),
        "span_id": format(ctx.span_id, "016x"),
        "parent_id": format(span.parent.span_id, "016x") if span.parent else None,
        "duration_ms": round((end_ns - start_ns) / 1_000_000, 3),
        "t": time.strftime("%H:%M:%S", time.localtime(start_ns / 1e9)),
        "attributes": {k: v for k, v in dict(span.attributes or {}).items()},
    }


def recent_spans(limit: int = 120) -> list[dict]:
    """Serialise the most recent spans, oldest first, bounded by `limit`."""
    spans = span_exporter.get_finished_spans()
    return [_serialise(s) for s in spans[-limit:]]


def recent_span_ids(count: int = 50) -> set[str]:
    """The span ids of the last `count` spans: a window's "before" marker."""
    spans = span_exporter.get_finished_spans()
    return {format(s.get_span_context().span_id, "016x") for s in spans[-count:]}


def new_spans_since(prefix_ids: set[str]) -> list[dict]:
    """Spans that arrived after `prefix_ids` was taken, oldest first.

    The exporter is a bounded deque, so index cursors break the moment it
    wraps: `len` stops growing and an absolute slice goes stale. Span ids are
    content-free and collision-proof, so the window is marked by the ids
    present before the call and read back by walking the newest spans until
    one of those ids appears. Emission happens only inside the caller's lock,
    so the tail is exactly the window's work.
    """
    spans = span_exporter.get_finished_spans()
    collected: list = []
    for span in reversed(spans):
        if format(span.get_span_context().span_id, "016x") in prefix_ids:
            break
        collected.append(span)
    collected.reverse()
    return [_serialise(s) for s in collected]


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
    """The library's own status, plus what this process demonstrably has.

    `spans_recorded` is the size of the bounded recent window (at most
    `MAX_SPANS`), not a lifetime count - a leak would be exactly the thing
    this number refused to do.
    """
    status = dict(telemetry.status())
    status["spans_recorded"] = len(span_exporter.get_finished_spans())
    status["host_provider"] = "in-memory (collected by this dashboard)"
    return status
