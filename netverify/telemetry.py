"""Optional OpenTelemetry instrumentation.

The MCP SDK already wraps every inbound message in a SERVER span and reads the
global tracer provider, so exporting real traces costs a provider configuration
rather than an integration. What the SDK cannot do is describe *this* library's
work: which command was checked, whether the verdict passed, how many findings
the sanitizer produced. Those are the numbers an operator asks for during an
incident, and the numbers F2's Langfuse tracing will need.

The dependency is deliberately optional. `netverify` imports only the standard
library, and that is a product property rather than an accident: the library is
meant to be vendored into a lab box, an air-gapped CI runner, or a small machine
on an unreliable grid, and a dependency tree is a supply-chain surface in exactly
that setting. So this module imports OpenTelemetry defensively and degrades to a
no-op when it is absent. `IS_INSTRUMENTED` reports which mode is active, and
`self_check` surfaces it, so an operator is never guessing whether tracing is on.

Attribute names follow the OpenTelemetry GenAI semantic conventions already used
by the SDK (`gen_ai.operation.name`, `gen_ai.tool.name`) so our spans compose
with its parent rather than inventing a parallel vocabulary.

Metrics live here too, for the questions traces cannot answer. A span says what
happened to *this* call; during an incident the question is aggregate - "failure
rate by command across 400 interfaces", "are `verdict_coercion` findings spiking
fleet-wide". Those need counters and histograms, read off a meter, not spans.

The adversarial finding counters are the differentiator. Device output is
treated as hostile throughout this library, so findings-by-kind is a *security*
signal, not a perf metric: a spike in `verdict_coercion` or `exfiltration`
across a fleet means someone is attempting prompt injection against the
infrastructure. No generic MCP server has this metric, because no generic MCP
server treats its own tool output as untrusted.

Payload discipline: no span attribute and no metric attribute ever carries raw
device output, matched text, or a secret. `Finding.detail` is a fixed
description per kind, never the matched substring, so recording kind/severity
is safe - but that is currently true by construction, and
`tests/test_telemetry.py::TestNoPayloadsInTelemetry` pins it so a future edit
cannot silently move the trust boundary that "we never log payloads" depends
on. Enabling an OTel exporter moves data *out of the process* to a collector.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from typing import Any

# The refusal vocabulary lives in `errors.py`, next to the exception that
# carries it, and is re-exported here so a dashboard or an adapter reads one
# file. Imported rather than restated: two copies of a vocabulary drift, and
# the failure mode is a dashboard that silently splits one reason into two.
# `errors.py` imports nothing from this package, so this edge cannot cycle and
# the optional instrumentation stays non-load-bearing for validation.
from .errors import (
    REASON_BAD_ARGUMENT,
    REASON_MISSING_ARGUMENT,
    REASON_NON_LIST_BATCH,
    REASON_NOT_IN_ALLOWLIST,
    REASON_OVERSIZE_BATCH,
    REASON_OVERSIZE_OUTPUT,
    REASON_RATE_LIMITED,
    REASON_UNKNOWN_ARGUMENT,
)

__all__ = [
    "REASON_BAD_ARGUMENT",
    "REASON_MISSING_ARGUMENT",
    "REASON_NON_LIST_BATCH",
    "REASON_NOT_IN_ALLOWLIST",
    "REASON_OVERSIZE_BATCH",
    "REASON_OVERSIZE_OUTPUT",
    "REASON_RATE_LIMITED",
    "REASON_UNKNOWN_ARGUMENT",
]

try:  # pragma: no cover - exercised by whichever branch the env selects
    from opentelemetry import metrics as _metrics_api
    from opentelemetry import trace as _trace

    IS_INSTRUMENTED = True
except ImportError:  # pragma: no cover
    _metrics_api = None  # type: ignore[assignment]
    _trace = None  # type: ignore[assignment]
    IS_INSTRUMENTED = False

#: Tracer name. Namespaced so a trace viewer can filter to our spans among the
#: SDK's, which are emitted under "mcp-python-sdk".
TRACER_NAME = "netverify"

#: Meter name. Same namespace as the tracer, so traces and metrics correlate
#: by instrumentation scope in a viewer.
METER_NAME = "netverify"

#: Every attribute this module sets, in one place. A telemetry vocabulary that
#: only exists in the middle of call sites drifts, and then dashboards quietly
#: stop matching.
ATTR_OPERATION = "gen_ai.operation.name"
ATTR_TOOL = "gen_ai.tool.name"
ATTR_COMMAND_ID = "netverify.command.id"
ATTR_PLATFORM = "netverify.platform"
ATTR_VERDICT_OK = "netverify.verdict.ok"
ATTR_VERDICT_OUTCOME = "netverify.verdict.outcome"
ATTR_FINDINGS = "netverify.findings.count"
ATTR_CRITICAL_FINDINGS = "netverify.findings.critical"
ATTR_BATCH_SIZE = "netverify.batch.size"
ATTR_OUTPUT_BYTES = "netverify.output.bytes"
ATTR_INPUT_BYTES = "netverify.input.bytes"
#: Metric-only attributes: aggregates, never per-call spans.
ATTR_FINDING_KIND = "netverify.finding.kind"
ATTR_FINDING_SEVERITY = "netverify.finding.severity"
ATTR_REFUSAL_REASON = "netverify.refusal.reason"
ATTR_REFUSED_COMMAND = "netverify.refusal.command"

#: Metric instrument names, next to the attributes so dashboards read one file.
METRIC_VERDICTS = "netverify.verdicts"
METRIC_FINDINGS = "netverify.findings"
METRIC_CALL_DURATION = "netverify.call.duration"
METRIC_RATE_LIMITED = "netverify.rate_limited"
METRIC_REFUSED = "netverify.refused"

#: The `REASON_*` names imported at the top of this module are the values
#: `record_refused` labels with, so dashboards group by a stable code instead of
#: by prose that changes.
_TRACER = _trace.get_tracer(TRACER_NAME) if IS_INSTRUMENTED else None

#: Lazily created instruments. Created on first use, not at import, because
#: the global meter provider is usually installed *after* import
#: (`configure_from_env()` runs at server startup). An instrument created
#: before that binds to the no-op provider forever - the same trap the span
#: tests document for `_TRACER`. Lazy creation plus `reset_instruments`
#: keeps tests hermetic and production correct.
_METER: Any = None
_METER_LOCK = threading.Lock()
_INSTRUMENTS: dict[str, Any] = {}


def _meter() -> Any | None:
    """The library meter, or None when OpenTelemetry is absent."""
    global _METER
    if not IS_INSTRUMENTED or _metrics_api is None:
        return None
    if _METER is not None:
        return _METER
    with _METER_LOCK:
        if _METER is None:
            _METER = _metrics_api.get_meter(METER_NAME)
        return _METER


def _counter(name: str, description: str) -> Any | None:
    """One cached counter, or None when metrics are unavailable."""
    meter = _meter()
    if meter is None:
        return None
    with _METER_LOCK:
        existing = _INSTRUMENTS.get(name)
        if existing is None:
            existing = meter.create_counter(name, description=description, unit="1")
            _INSTRUMENTS[name] = existing
        return existing


def _histogram(name: str, description: str) -> Any | None:
    """One cached histogram, or None when metrics are unavailable."""
    meter = _meter()
    if meter is None:
        return None
    with _METER_LOCK:
        existing = _INSTRUMENTS.get(name)
        if existing is None:
            existing = meter.create_histogram(name, description=description, unit="s")
            _INSTRUMENTS[name] = existing
        return existing


def reset_instruments() -> None:
    """Drop cached instruments so the next recording re-creates them.

    The global meter provider is process-wide, so a test that installs an
    in-memory reader must call this first or it records into instruments
    bound to the previous provider. Production never calls this.
    """
    global _METER
    with _METER_LOCK:
        _METER = None
        _INSTRUMENTS.clear()


def _record(counter: Any | None, amount: int | float, attrs: dict[str, Any]) -> None:
    """Add one measurement without ever breaking the call it describes."""
    if counter is None:
        return
    try:
        counter.add(amount, dict(attrs))
    except Exception:  # noqa: BLE001 - telemetry must never break a call
        return


def record_verdict(command_id: str, outcome: str) -> None:
    """Count one verdict, by command and outcome (`pass`/`fail`/`input_error`)."""
    _record(
        _counter(METRIC_VERDICTS, "Verdicts by command and outcome."),
        1,
        {ATTR_COMMAND_ID: command_id, ATTR_VERDICT_OUTCOME: outcome},
    )


def record_findings(findings: Iterable[Any]) -> None:
    """Count sanitizer findings by kind and severity (the security signal)."""
    counter = _counter(
        METRIC_FINDINGS, "Sanitizer findings by kind and severity (security signal)."
    )
    if counter is None:
        return
    for finding in findings:
        kind = getattr(finding, "kind", None)
        severity = getattr(finding, "severity", None)
        _record(counter, 1, {ATTR_FINDING_KIND: kind, ATTR_FINDING_SEVERITY: severity})


def record_duration(tool: str, seconds: float) -> None:
    """Record one tool call duration, in seconds, labelled by tool."""
    histogram = _histogram(METRIC_CALL_DURATION, "Tool call duration in seconds.")
    if histogram is None:
        return
    try:
        histogram.record(float(seconds), {ATTR_TOOL: tool})
    except Exception:  # noqa: BLE001 - telemetry must never break a call
        return


def record_rate_limited(tool: str | None = None) -> None:
    """Count one token-bucket refusal, optionally labelled by tool."""
    attrs: dict[str, Any] = {}
    if tool is not None:
        attrs[ATTR_TOOL] = tool
    _record(_counter(METRIC_RATE_LIMITED, "Calls refused by the token bucket."), 1, attrs)


def record_refused(reason: str, command: str | None = None) -> None:
    """Count one scope refusal, by stable reason (never prose)."""
    attrs: dict[str, Any] = {ATTR_REFUSAL_REASON: reason}
    if command is not None:
        attrs[ATTR_REFUSED_COMMAND] = command
    _record(_counter(METRIC_REFUSED, "Calls refused by scope validation."), 1, attrs)


#: What actually happened to the metric pipeline, as opposed to what the
#: environment asked for. Read by `status()` so `self_check` can tell an operator
#: whether the counters are going anywhere, and written by
#: `_configure_metrics_from_env` because "the env var is set" and "a reader is
#: installed" are different claims - the difference is a missing exporter package,
#: which is the normal state in a lab.
#:
#: The four states, in the order an operator cares about:
#:
#: - `"exporting:<name>"` - we installed a reader, and it is exporting.
#: - `"host-provider"` - something else installed a meter provider first, so ours
#:   was not installed. Not a failure: the host's provider may well export. We
#:   cannot know, so we do not claim either way.
#: - `"not-configured"` - nobody asked for metrics. The correct default.
#: - `"failed:<reason>"` - asked for, and could not. Said out loud rather than
#:   swallowed, because a counter that silently goes nowhere is worse than one
#:   that is visibly absent.
_METRICS_STATE = "not-configured"


def _metric_exporter() -> tuple[Any, str] | None:
    """The metric exporter the environment asks for, or None for "no metrics".

    Chosen the same way `configure_from_env` chooses its span exporter, and for
    the same reason: the machine decides, not a hard-coded preference. An earlier
    version consulted only `NETVERIFY_OTEL_CONSOLE`, so in the deployment this
    exists for - `OTEL_EXPORTER_OTLP_ENDPOINT`, the collector F2 speaks to -
    traces were exported and every counter went nowhere, and the console path
    that did work is the one nobody deploys with.

    Returns `(exporter, name)`, or None when neither env var asks for metrics.
    Raises ImportError when the env asks for a mode whose exporter package is
    not installed; the caller turns that into a reported state rather than
    letting startup fail over optional instrumentation.
    """
    if os.environ.get("NETVERIFY_OTEL_CONSOLE") == "1":
        from opentelemetry.sdk.metrics.export import ConsoleMetricExporter

        return ConsoleMetricExporter(), "console"

    if os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
        # HTTP/protobuf, matching the span exporter in `configure_from_env`. The
        # two must agree: a traces-only OTLP collector and a metrics-only one
        # pointed at the same endpoint is a support ticket nobody enjoys.
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
            OTLPMetricExporter,
        )

        return OTLPMetricExporter(), "otlp"

    return None


def _configure_metrics_from_env() -> None:
    """Attach a metric reader when the environment asks for one.

    Best-effort and never raising: a missing exporter package degrades to
    in-process aggregation rather than breaking startup, and the reason is
    recorded in `_METRICS_STATE` so `status()` can report it instead of leaving
    an operator to guess.
    """
    global _METRICS_STATE

    if not IS_INSTRUMENTED or _metrics_api is None:  # pragma: no cover
        return

    try:
        chosen = _metric_exporter()
    except ImportError as exc:
        # `ImportError.name` for a missing subpackage is the *outermost* module
        # that could not be found - reaching for the metric exporter when no OTLP
        # package is installed reports `opentelemetry.exporter`, with no hint that
        # metrics were what we were after. So the state names both the intent and
        # the cause: a bare `failed:opentelemetry.exporter` would send an operator
        # looking at the wrong package.
        _METRICS_STATE = f"failed:no-metric-exporter ({exc.name or 'import failed'})"
        return
    except Exception as exc:  # noqa: BLE001 - telemetry must never break startup
        _METRICS_STATE = f"failed:{type(exc).__name__}"
        return

    if chosen is None:
        _METRICS_STATE = "not-configured"
        return
    exporter, name = chosen

    try:
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader

        provider = MeterProvider(
            metric_readers=[PeriodicExportingMetricReader(exporter, export_interval_millis=5_000)]
        )
        _metrics_api.set_meter_provider(provider)
    except Exception as exc:  # noqa: BLE001
        # `set_meter_provider` only sets once, and warns rather than raises when
        # a provider is already installed. So this is the "the host got there
        # first" case far more often than it is a real failure, and calling it a
        # failure would be a lie that sends someone hunting a bug that is not
        # there. The host's provider may well export these metrics itself.
        already = _metrics_api.get_meter_provider()
        if type(already).__name__ != "ProxyMeterProvider":
            _METRICS_STATE = "host-provider"
            return
        _METRICS_STATE = f"failed:{type(exc).__name__}"
        return

    _METRICS_STATE = f"exporting:{name}"


def configure_from_env() -> bool:
    """Attach an exporter if the environment asks for one. Returns whether tracing is live.

    Three modes, chosen by what is already on the machine rather than by adding
    a dependency:

    - `OTEL_EXPORTER_OTLP_ENDPOINT` set -> the OTLP exporter, which is what
      F2's Langfuse collector will speak.
    - `NETVERIFY_OTEL_CONSOLE=1` -> a console exporter, so tracing can be seen
      locally with nothing installed.
    - neither -> no provider is installed and the SDK's middleware stays a no-op,
      which is the correct default: a server that silently buffers spans nobody
      exports is worse than one that emits none.

    Returns False, rather than raising, when a configured exporter cannot be
    loaded. Telemetry must never be the reason a tool call fails.
    """
    if not IS_INSTRUMENTED:
        return False
    _configure_metrics_from_env()
    try:
        if os.environ.get("NETVERIFY_OTEL_CONSOLE") == "1":
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import (
                ConsoleSpanExporter,
                SimpleSpanProcessor,
            )

            provider = TracerProvider()
            provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
            _trace.set_tracer_provider(provider)
            return True

        if os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            provider = TracerProvider()
            provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
            _trace.set_tracer_provider(provider)
            return True
    except Exception:  # noqa: BLE001 - telemetry must never break a call
        return False
    return False


@contextmanager
def span(name: str, **attributes: Any) -> Iterator[Any]:
    """Record a span if OpenTelemetry is present, otherwise do nothing.

    Yields the active span, or `None` when uninstrumented, so a caller can set
    attributes that are only known once the work is done - a verdict, a count.
    Callers must therefore guard the `None` case rather than assume a span.

    Uses `record_exception=False` and `set_status_on_exception=False` because
    a failing tool call is not an exceptional condition - it is a *result* the
    operator wants to see counted. A failure is recorded through explicit
    attributes, because "this link is down" and "the server crashed" are
    different facts and an error-status span would blur them.
    """
    if _TRACER is None:
        yield None
        return
    with _TRACER.start_as_current_span(
        name,
        record_exception=False,
        set_status_on_exception=False,
        attributes={k: v for k, v in attributes.items() if v is not None},
    ) as active:
        yield active


def status() -> dict[str, Any]:
    """A small, serialisable description of the tracing and metrics state.

    `metrics_state` is the field that matters most and is the one an earlier
    version lacked. `exporter` below answers "what did the environment ask
    for"; this answers "did it happen". Those differ exactly when it matters -
    the env var is set, the exporter package is missing, and every counter is
    incrementing into a void that a dashboard will never show. An operator
    reading `self_check` should not have to know that to find out.
    """
    return {
        "instrumented": IS_INSTRUMENTED,
        "tracer": TRACER_NAME,
        "meter": METER_NAME,
        "metrics": [
            METRIC_VERDICTS,
            METRIC_FINDINGS,
            METRIC_CALL_DURATION,
            METRIC_RATE_LIMITED,
            METRIC_REFUSED,
        ],
        "metrics_state": _METRICS_STATE,
        "metrics_exporting": _METRICS_STATE.startswith("exporting:"),
        "sdk_emits_server_spans": True,
        "exporter": (
            "console"
            if os.environ.get("NETVERIFY_OTEL_CONSOLE") == "1"
            else "otlp"
            if os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
            else None
        ),
    }
