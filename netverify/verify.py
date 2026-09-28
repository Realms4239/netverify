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
from typing import Any

from .audit import DEFAULT
from .errors import ScopeError
from .models import Outcome, Verdict
from .sanitize import sanitize
from .scope import validate
from .telemetry import (
    ATTR_COMMAND_ID,
    ATTR_INPUT_BYTES,
    ATTR_PLATFORM,
    span,
)


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

    # The verdict attributes are attached to the SDK's own SERVER span rather
    # than to a nested one. A failing check is a *result*, not an exception, and
    # recording it where the tool call is recorded means a trace answers "did
    # this link pass?" without anyone having to correlate two spans.
    with span(
        "netverify.verify",
        **{
            ATTR_COMMAND_ID: spec.id,
            ATTR_PLATFORM: spec.platform,
            ATTR_INPUT_BYTES: len(request["output"]),
        },
    ):
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

    if audit is not None:
        audit.record(
            "verify",
            command_id=spec.id,
            ok=verdict.ok,
            outcome=verdict.outcome.value,
            duration_ms=(time.perf_counter() - started) * 1000,
        )
    return verdict


#: Maximum entries in one `verify_many` call.
#:
#: Without a cap, a single agent request could carry 20 000 captures and occupy
#: the process for seconds - a denial of service delivered through the tool
#: surface, which is the one place an agent already has sanctioned access. 200
#: is far above any real incident capture and well under a second of work.
MAX_BATCH_ITEMS = 200


def verify_many(items: list[dict[str, Any]], *, audit: Any = DEFAULT) -> list[Verdict | Exception]:
    """Verify a batch, one result per input, in order.

    One bad item does not abort the batch. An operator checking forty
    interfaces needs the thirty-nine good answers far more than they need a
    clean failure on the fortieth, and a batch tool that stops at the first
    error is worse than useless during an incident.

    Refusals are returned as the exception object rather than raised, so the
    caller can tell *which* input was rejected. Re-raising would lose the
    positional correspondence.

    Raises:
        ScopeError: if `items` is not a list, or carries more than
            `MAX_BATCH_ITEMS` entries. Both are refusals about the shape of the
            request rather than about one entry, so they are raised rather than
            returned - there is no meaningful per-entry answer to give. An entry
            that is not an object is handled per-entry, since that one *is* a
            positional answer.
    """
    if not isinstance(items, list):
        raise ScopeError(f"expected a list of captures, got {type(items).__name__}")
    if len(items) > MAX_BATCH_ITEMS:
        raise ScopeError(
            f"batch has {len(items)} entries, above the {MAX_BATCH_ITEMS} limit. "
            "Split it into several calls; one oversized batch would block the "
            "server for every other caller."
        )

    results: list[Verdict | Exception] = []
    for item in items:
        if not isinstance(item, dict):
            results.append(
                ScopeError(f"capture entry must be an object, got {type(item).__name__}")
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
    return results
