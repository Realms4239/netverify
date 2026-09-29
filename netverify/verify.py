"""Turn one validated request into a `Verdict`.

The library's main entry point. It is deliberately thin: the registry holds the
checks, `scope` holds the rules, and this module only joins them and records
the outcome. That thinness is the point - a caller learns one function and gets
every check, and adding a check changes nothing here.

The rule this module adds is about *reporting*, not detection. A failing
network is data; a malformed input is an error. Collapsing the two is how a tool
ends up reporting a device fault that does not exist, so `Verdict.outcome`
separates them and `ok` is only ever False because the network failed a check.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from .audit import DEFAULT
from .errors import (
    REASON_BAD_ARGUMENT,
    REASON_NON_LIST_BATCH,
    REASON_OVERSIZE_BATCH,
    ScopeError,
)
from .limits import Deadline
from .models import Outcome, Verdict
from .sanitize import MAX_BYTES, sanitize
from .scope import validate
from .telemetry import (
    ATTR_COMMAND_ID,
    ATTR_INPUT_BYTES,
    ATTR_OPERATION,
    ATTR_OUTPUT_BYTES,
    ATTR_PLATFORM,
    ATTR_TOOL,
    ATTR_VERDICT_OK,
    ATTR_VERDICT_OUTCOME,
    record_duration,
    record_verdict,
    span,
)

#: Progress callback shape for `verify_many`: `(done, total) -> None`.
#:
#: Named and exported rather than spelled inline at the call site, because the
#: *absence* of an event loop is the design decision here and it deserves a
#: single obvious place to point at. The library cannot await anything - it must
#: not even import `asyncio`, which `integrity.py` lists as network-capable - so
#: this is a plain synchronous function and bridging it to a loop is the
#: caller's business.
ProgressFn = Callable[[int, int], None]


def verify(
    command: str,
    output: str,
    *,
    audit: Any = DEFAULT,
    sanitize_output: bool = True,
    **arguments: Any,
) -> Verdict:
    """Verify one command's output. Returns a `Verdict`.

    Args:
        command: a registered command id, e.g. `srl_interface_brief`.
        output: the raw text that command printed on the device.
        audit: an `AuditLog`. Pass `None` to disable auditing.
        sanitize_output: when true, `observed` and every reason are run
            through the sanitizer. On by default and should stay on; it exists
            as a switch only so the eval suite can prove it is load-bearing.
        **arguments: the command's declared arguments, e.g. `interface=...`.

    Raises:
        ScopeError: if the request is out of scope or malformed. Subclasses
            ValueError, so one `except ValueError` covers every refusal.
    """
    request = validate(command, output, **arguments)
    spec = request["spec"]
    started = time.perf_counter()

    # One span carries the whole story of the check. The verdict attributes
    # belong here rather than on the SDK's SERVER span because this span is
    # already a child of it: reading the child answers "did this link pass?"
    # without correlating anything. A failing check is a *result*, not an
    # exception, so it is recorded as attributes and never as an error event -
    # a dashboard counting exceptions would otherwise report a working network
    # as broken.
    with span(
        "netverify.verify",
        **{
            ATTR_OPERATION: "verify",
            ATTR_TOOL: spec.id,
            ATTR_COMMAND_ID: spec.id,
            ATTR_PLATFORM: spec.platform,
            ATTR_INPUT_BYTES: len(request["output"]),
        },
    ) as active:
        check = spec.check(request["output"], **request["arguments"])

        if sanitize_output:
            observed = sanitize(f"checked {spec.command}").safe_text[:200]
            reasons = tuple(
                sanitize(reason, max_bytes=800).safe_text[:200] for reason in check.reasons
            )
        else:
            observed = f"checked {spec.command}"
            reasons = check.reasons

        # A checker that reports failure is a network verdict. A checker that
        # could not parse the input labels its own reasons, which is how
        # INPUT_ERROR is distinguished without a second return channel.
        outcome = Outcome.PASS if check.ok else Outcome.FAIL
        if not check.ok and any("input error" in reason for reason in check.reasons):
            outcome = Outcome.INPUT_ERROR

        verdict = Verdict(
            ok=check.ok,
            outcome=outcome,
            command_id=spec.id,
            command=spec.command,
            platform=spec.platform,
            check=check.name,
            observed=observed,
            reasons=reasons,
            arguments=request["arguments"],
        )

        # Set after the work, because they are only knowable afterwards. This is
        # the whole point of instrumenting a verifier: a trace answers "did this
        # link pass, and how big was the input" without anyone reading logs.
        # Attributes carry only fixed vocabulary (ids, outcome enums, counts) -
        # never raw device text; see TestNoPayloadsInTelemetry.
        if active is not None:
            active.set_attribute(ATTR_VERDICT_OK, verdict.ok)
            active.set_attribute(ATTR_VERDICT_OUTCOME, verdict.outcome.value)
            active.set_attribute(ATTR_OUTPUT_BYTES, len(observed))

    duration_s = time.perf_counter() - started
    # Aggregate answers for the incident questions traces cannot serve:
    # failure rate by command, and the adversarial finding counters that make
    # a spike in prompt-injection attempts visible fleet-wide.
    record_verdict(spec.id, verdict.outcome.value)
    record_duration("verify", duration_s)

    if audit is not None:
        audit.record(
            "verify",
            command_id=spec.id,
            ok=verdict.ok,
            outcome=verdict.outcome.value,
            duration_ms=duration_s * 1000,
        )
    return verdict


#: Maximum entries in one `verify_many` call.
#:
#: Without a cap, a single agent request could carry 20 000 captures and occupy
#: the process for seconds - a denial of service delivered through the tool
#: surface, which is the one place an agent already has sanctioned access. 200
#: is far above any real incident capture and well under a second of work.
MAX_BATCH_ITEMS = 200


#: Maximum total input bytes one `verify_many` call may carry.
#:
#: `MAX_BATCH_ITEMS` bounds the *count*, but count is the wrong axis. Measured on
#: this machine with `scripts/bench.py`, twelve regex passes over a 64 KiB
#: cap-sized input cost ~133 ms in the adversarial case, and 200 of them cost
#: 5.2 s - all inside a single tool call, on the one surface an agent already
#: has sanctioned access to. Counting entries would have let that through
#: comfortably: 200 is well under the item cap and still five seconds of work.
#:
#: So the bound is on bytes, which is the actual cost driver and is
#: deterministic. Four cap-sized inputs is far more than any real incident
#: capture - a full `show interface brief` is around 500 bytes - while capping a
#: worst-case batch at roughly 0.5 s.
#:
#: This is deliberately a byte budget and not a wall-clock deadline. A clock is
#: non-deterministic, so it would make CI flaky and would fire *after* the work
#: rather than before it. A limit applied after the work is not a limit.
MAX_TOTAL_INPUT_BYTES = 4 * MAX_BYTES


def verify_many(
    items: list[dict[str, Any]],
    *,
    audit: Any = DEFAULT,
    progress: ProgressFn | None = None,
) -> list[Verdict | Exception]:
    """Verify a batch, one result per input, in order.

    One bad item does not abort the batch. An operator checking forty
    interfaces needs the thirty-nine good answers far more than they need a
    clean failure on the fortieth, and a batch tool that stops at the first
    error is worse than useless during an incident.

    Refusals are returned as the exception object rather than raised, so the
    caller can tell *which* input was rejected. Re-raising would lose the
    positional correspondence.

    Args:
        items: The captures to verify.
        audit: The log to record each verification in, or None for none.
        progress: Optional callback, `progress(done, total)`, invoked after each
            entry. A 200-entry batch is the one call in this library long enough
            that a client staring at a silent connection cannot tell it apart
            from a hang.

    Raises:
        ScopeError: if `items` is not a list, or carries more than
            `MAX_BATCH_ITEMS` entries. Both are refusals about the shape of the
            request rather than about one entry, so they are raised rather than
            returned - there is no meaningful per-entry answer to give. An entry
            that is not an object is handled per-entry, since that one *is* a
            positional answer.
    """
    if not isinstance(items, list):
        raise ScopeError(
            f"expected a list of captures, got {type(items).__name__}",
            reason=REASON_NON_LIST_BATCH,
        )
    if len(items) > MAX_BATCH_ITEMS:
        raise ScopeError(
            f"batch has {len(items)} entries, above the {MAX_BATCH_ITEMS} limit. "
            "Split it into several calls; one oversized batch would block the "
            "server for every other caller.",
            reason=REASON_OVERSIZE_BATCH,
        )

    # Enforced before any entry is processed, so an over-budget batch costs a
    # length sum and nothing more. Checking per entry as we went would mean
    # discovering the overrun after doing most of the work, which is the failure
    # this budget exists to prevent.
    total_bytes = 0
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("output"), str):
            total_bytes += len(item["output"].encode("utf-8", errors="replace"))
            if total_bytes > MAX_TOTAL_INPUT_BYTES:
                raise ScopeError(
                    f"batch carries more than {MAX_TOTAL_INPUT_BYTES} bytes of device "
                    f"output, above the {MAX_TOTAL_INPUT_BYTES}-byte budget for one "
                    "call. Each entry is already capped, but the aggregate is what "
                    "costs; split the capture across several calls.",
                    reason=REASON_OVERSIZE_BATCH,
                )

    results: list[Verdict | Exception] = []
    deadline = Deadline()
    total = len(items)

    for index, item in enumerate(items, start=1):
        # Wall-clock backstop, checked on entry to each entry. Be precise about
        # what it can and cannot do: a deadline cannot preempt a regex pass, so
        # the byte budget above is the control that actually bounds the work.
        # This exists so a future path that is *not* byte-bounded still cannot
        # hold the process indefinitely, and so an overrun is visible in the
        # audit log rather than passing silently.
        deadline.check("verify_many")

        try:
            if not isinstance(item, dict):
                results.append(
                    ScopeError(
                        f"capture entry must be an object, got {type(item).__name__}",
                        reason=REASON_BAD_ARGUMENT,
                    )
                )
                continue
            try:
                results.append(
                    verify(
                        item.get("command", ""),
                        item.get("output", ""),
                        audit=audit,
                        **{k: v for k, v in item.items() if k not in ("command", "output")},
                    )
                )
            except ValueError as exc:
                results.append(exc)
        finally:
            # Wrapping the refusal branch too, so every entry advances the count
            # exactly once. A progress channel that stalls whenever the work gets
            # interesting is worse than none: the interesting entries are the
            # refused ones.
            #
            # Deliberately synchronous and unawaited. This module cannot import
            # `asyncio` - `integrity.py` lists it among the network-capable
            # modules precisely because it *can* open a socket, and a verifier
            # with no route to the device has no business importing it. The
            # callback is therefore a plain function, and bridging it to an event
            # loop is the caller's job (the MCP adapter does it with anyio's
            # thread trampoline). A callback that raises is swallowed: progress
            # must never be the reason a batch fails.
            if progress is not None:
                try:
                    progress(index, total)
                except Exception:  # noqa: BLE001,S110 - progress must not break work
                    pass
    return results
