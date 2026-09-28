"""Higher-level reasoning over verdicts.

Three capabilities live here, because a single verdict answers a narrow question
- "is this interface up?" - while the questions an operator actually asks are
comparative and aggregate:

- `synthesize_health` asks whether the backbone is healthy overall.
- `compare_states` asks what changed between two captures.
- `self_check` (in `integrity.py`) asks whether the server is running what it
  claims to be.

Each is a pure function over data the library already produced. None reaches a
device, none holds a credential, none can write anything - the same guarantees
the single-command path has, which is what lets them be exposed as tools without
reopening the excessive-agency surface.

The comparison logic is the interesting part. Diffing verdict lists by
`command_id` alone would report "unchanged" for two captures of *different*
interfaces, which is a confidently wrong answer rather than a vague one. So the
key includes the arguments, and a check present on only one side is reported as
`added` or `removed` rather than being silently ignored.
"""

from __future__ import annotations

from typing import Any

from .models import Outcome, Verdict


def _key(verdict: Verdict) -> tuple[str, tuple[tuple[str, str], ...]]:
    """Identity of a checked thing: the command plus the arguments it applied to.

    The arguments are part of the identity, not decoration. `show interface
    brief` for `ethernet-1/1` and for `ethernet-1/2` are the same command and
    completely different findings, so a key that ignored arguments would report
    an interface change as "unchanged".
    """
    return (
        verdict.command_id,
        tuple(sorted(verdict.arguments.items())),
    )


def _render(verdict: Verdict) -> str:
    inner = ", ".join(f"{k}={v}" for k, v in sorted(verdict.arguments.items()))
    return f"{verdict.command_id}({inner or '-'})"


def synthesize_health(results: list[Verdict | Exception]) -> dict[str, Any]:
    """Roll many verdicts into one answer, with the worst offender named.

    An operator at 3am does not want forty verdicts; they want "degraded" and
    "look at this first". Ordering matters: a network fault outranks an input
    error, because an input error is a problem with the capture while a network
    fault is a problem with the network. Collapsing them into one "not ok" would
    lose exactly the distinction the verdict model exists to preserve.
    """
    verdicts = [r for r in results if not isinstance(r, Exception)]
    refusals = [r for r in results if isinstance(r, Exception)]

    failed = [v for v in verdicts if not v.ok and v.outcome is Outcome.FAIL]
    input_errors = [v for v in verdicts if v.outcome is Outcome.INPUT_ERROR]

    if failed:
        status = "unhealthy"
    elif input_errors:
        # No network fault, but the capture is not trustworthy. Answering
        # "healthy" here is the single most misleading result available: the
        # caller would conclude the network is fine on the evidence of text
        # that could not be read.
        status = "indeterminate"
    elif refusals:
        status = "partially_checked"
    else:
        status = "healthy"

    # Most explanatory first, then stable by name so repeated runs diff cleanly.
    ranked = sorted(failed, key=lambda v: (not v.reasons, _render(v)))

    return {
        "status": status,
        "checked": len(verdicts),
        "passed": sum(1 for v in verdicts if v.ok),
        "failed": len(failed),
        "input_errors": len(input_errors),
        "refused": len(refusals),
        "worst": ranked[0].to_dict() if ranked else None,
        "failures": [v.to_dict() for v in ranked[:10]],
    }


def compare_states(
    before: list[Verdict | Exception], after: list[Verdict | Exception]
) -> dict[str, Any]:
    """Report what changed between two captures.

    The workflow this exists for is change review: snapshot a backbone, apply a
    change, snapshot again, ask what moved. That question is genuinely hard to
    answer by eye across forty interfaces, and answering it wrong is worse than
    not answering it.
    """
    before_map = {_key(v): v for v in before if not isinstance(v, Exception)}
    after_map = {_key(v): v for v in after if not isinstance(v, Exception)}

    regressions: list[dict[str, Any]] = []
    recoveries: list[dict[str, Any]] = []
    unchanged = 0

    for key, current in after_map.items():
        previous = before_map.get(key)
        if previous is None:
            regressions.append(
                {"check": _render(current), "change": "added", "verdict": current.to_dict()}
            )
            continue
        if previous.ok and not current.ok:
            # The case that matters. Name it first and carry its reasons, so a
            # reviewer sees the regression without opening anything else.
            regressions.append(
                {
                    "check": _render(current),
                    "change": "regressed",
                    "was": previous.outcome.value,
                    "verdict": current.to_dict(),
                }
            )
        elif not previous.ok and current.ok:
            recoveries.append({"check": _render(current), "change": "recovered"})
        elif previous.outcome is not current.outcome:
            regressions.append(
                {
                    "check": _render(current),
                    "change": "outcome_changed",
                    "was": previous.outcome.value,
                    "verdict": current.to_dict(),
                }
            )
        else:
            unchanged += 1

    removed = [
        {"check": _render(previous), "change": "removed"}
        for key, previous in before_map.items()
        if key not in after_map
    ]

    return {
        "regressions": regressions,
        "recoveries": recoveries,
        "removed": removed,
        "unchanged": unchanged,
        "compared_before": len(before_map),
        "compared_after": len(after_map),
    }
