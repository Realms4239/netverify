#!/usr/bin/env python3
"""Run the declarative eval cases in `evals/cases.json` against the tool.

This is the F1 eval gate. It is deliberately model-free: every case is a fixed
input with a fixed expected verdict, so it runs in CI with no API key, no
network, and no flakiness. That is the property that makes it worth having at
this stage - a gate that needs a paid model to be green is a gate that gets
skipped, and a skipped gate is indistinguishable from no gate.

F2 replaces this with promptfoo trajectory evals that score a real agent's
tool choice, not just the tool's output. That work is genuinely different and
needs a model; it is not faked here.

Cases assert on the tool boundary (what an agent receives), so they stay valid
if the internals are refactored.

Exit codes: 0 all cases passed, 1 at least one failed, 2 the suite is malformed.
"""

from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from server import mcp_server  # noqa: E402
from tests import fixtures  # noqa: E402

CASES_PATH = pathlib.Path(__file__).resolve().parent / "cases.json"


def load_cases() -> list[dict]:
    document = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    cases = document.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError(f"{CASES_PATH} has no non-empty 'cases' list")
    return cases


def evaluate(case: dict) -> list[str]:
    """Return a list of failures for one case; empty means it passed."""
    failures: list[str] = []

    name = case.get("name", "<unnamed>")
    output = getattr(fixtures, case["output_ref"], None)
    if output is None:
        return [f"{name}: output_ref {case['output_ref']!r} is not a fixture"]

    expect_error = case.get("expect_error_contains")

    try:
        result = mcp_server.verify_network_output(
            command=case["command"], output=output, **case.get("arguments", {})
        )
    except ValueError as exc:
        if expect_error is None:
            return [f"{name}: call was refused but the case expected a verdict ({exc})"]
        if expect_error not in str(exc):
            return [f"{name}: refusal did not mention {expect_error!r}: {exc}"]
        return []
    except Exception as exc:  # unexpected crash, not a scope refusal
        return [f"{name}: unexpected {type(exc).__name__}: {exc}"]

    if expect_error is not None:
        return [f"{name}: expected a refusal mentioning {expect_error!r}, got a verdict"]

    if "expect_ok" in case and result["ok"] != case["expect_ok"]:
        failures.append(
            f"{name}: expected ok={case['expect_ok']}, got ok={result['ok']} "
            f"(reasons: {result['reasons']})"
        )

    if case.get("expect_reasons_empty") and result["reasons"]:
        failures.append(f"{name}: expected no reasons, got {result['reasons']}")

    blob = json.dumps(result)
    for needle in case.get("expect_contains", []):
        if needle not in blob:
            failures.append(f"{name}: response did not contain {needle!r}")
    for needle in case.get("expect_absent", []):
        if needle in blob:
            failures.append(f"{name}: response LEAKED {needle!r}")

    return failures


def main() -> int:
    try:
        cases = load_cases()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"EVAL SUITE MALFORMED: {exc}", file=sys.stderr)
        return 2

    failed = 0
    for case in cases:
        failures = evaluate(case)
        label = case.get("name", "<unnamed>")
        if failures:
            failed += 1
            print(f"FAIL  {label}")
            for failure in failures:
                print(f"        {failure}")
        else:
            print(f"pass  {label}")

    total = len(cases)
    print(f"\nevals: {total - failed}/{total} passed")
    if failed:
        print("EVAL GATE FAILED", file=sys.stderr)
        return 1
    print("EVAL GATE OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
