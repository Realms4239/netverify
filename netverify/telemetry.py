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
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

try:  # pragma: no cover - exercised by whichever branch the env selects
    from opentelemetry import trace as _trace

    IS_INSTRUMENTED = True
except ImportError:  # pragma: no cover
    _trace = None  # type: ignore[assignment]
    IS_INSTRUMENTED = False

#: Tracer name. Namespaced so a trace viewer can filter to our spans among the
#: SDK's, which are emitted under "mcp-python-sdk".
TRACER_NAME = "netverify"

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

_TRACER = _trace.get_tracer(TRACER_NAME) if IS_INSTRUMENTED else None


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
    """A small, serialisable description of the tracing state."""
    return {
        "instrumented": IS_INSTRUMENTED,
        "tracer": TRACER_NAME,
        "sdk_emits_server_spans": True,
        "exporter": (
            "console"
            if os.environ.get("NETVERIFY_OTEL_CONSOLE") == "1"
            else "otlp"
            if os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
            else None
        ),
    }
