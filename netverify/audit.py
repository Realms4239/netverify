"""Structured audit logging, and why it must go to stderr.

The MCP specification says servers SHOULD "log tool usage for audit purposes".
That is only useful if the log is actually trustworthy, and on a stdio MCP
server there is exactly one place it can go.

**stdout belongs to the protocol.** The stdio transport frames JSON-RPC on
stdout. A single stray `print()` there corrupts the message stream and the
client drops the connection with an unhelpful parse error. So every diagnostic
in this project writes to stderr, and `audit.py` exists partly to make that
impossible to get wrong: there is one writer, and it is stderr.

Format is JSON Lines. One object per line is greppable, streamable, and
truncation-tolerant - a half-written final line costs one record, not the
file. Free text is the alternative and it is not machine-readable, which
defeats the point of an audit log.

What is recorded, and equally what is not: the command, the verdict, the
timing, and whether the text was refused. Never the device output itself. An
audit log that stores the payloads it was meant to protect against becomes a
second copy of the secret it was written to catch, which is the classic way
logging turns a control into a liability.
"""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Any, TextIO


def _default_sink() -> TextIO:
    # stderr, always. stdout is the protocol channel on stdio.
    return sys.stderr


def _default_enabled() -> bool:
    """Whether audit logging is on unless told otherwise.

    Defaults to on, because an audit log nobody knows is off is still a control
    and can be turned on in one place. `NETVERIFY_AUDIT=0` silences it, which
    matters for the test suite - a green run should not be buried under
    thousands of JSON lines - and for anyone who wants the server quiet in a
    terminal.

    Read at construction rather than at write time so that setting it later in
    a test takes effect, which is what makes the suite able to assert on audit
    output at all.
    """
    return os.environ.get("NETVERIFY_AUDIT", "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


class AuditLog:
    """Append-only JSONL audit sink.

    Args:
        sink: where lines go. Defaults to stderr, which is the only safe
            default for a stdio MCP server.
        clock: injectable so tests can assert on deterministic output.
        enabled: set False to make this a no-op without changing call sites.
    """

    def __init__(
        self,
        sink: TextIO | None = None,
        *,
        clock: Any = time.time,
        enabled: bool | None = None,
    ) -> None:
        self._sink = sink if sink is not None else _default_sink()
        self._clock = clock
        self.enabled = _default_enabled() if enabled is None else enabled

    def record(
        self,
        event: str,
        *,
        command_id: str | None = None,
        ok: bool | None = None,
        outcome: str | None = None,
        duration_ms: float | None = None,
        findings: int | None = None,
        truncated: bool | None = None,
        detail: str | None = None,
    ) -> None:
        """Write one audit line. Never raises.

        A logging failure must not take down the tool call it was describing.
        """
        if not self.enabled:
            return
        entry: dict[str, Any] = {
            "ts": round(self._clock(), 3),
            "event": event,
        }
        for key, value in (
            ("command_id", command_id),
            ("ok", ok),
            ("outcome", outcome),
            ("duration_ms", None if duration_ms is None else round(duration_ms, 2)),
            ("findings", findings),
            ("truncated", truncated),
            ("detail", detail),
        ):
            if value is not None:
                entry[key] = value
        try:
            self._sink.write(json.dumps(entry, sort_keys=True) + "\n")
            self._sink.flush()
        except Exception as exc:  # noqa: BLE001
            # A logging failure must not take down the tool call it describes,
            # so it is caught - but not swallowed. Silently dropping an audit
            # record is how a control becomes invisible, so the failure is
            # reported on stderr, which is where diagnostics belong and is
            # distinct from the audit stream itself.
            #
            # `sys.stderr`, not `sys.__stderr__`. An earlier version reached for
            # the original stream to "be sure" the report was visible, which
            # quietly defeated `contextlib.redirect_stderr` and any host that
            # redirects stderr to a log file. Respecting the current stream is
            # both more correct and the only version a test can assert on.
            import traceback

            print(f"netverify: audit sink failed: {exc}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)


#: Process-wide default. The MCP layer reuses this so that every tool call is
#: audited without each tool having to thread a logger through.
DEFAULT = AuditLog()
