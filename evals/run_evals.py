#!/usr/bin/env python3
"""Run the declarative eval cases in `evals/cases.json`.

This is the F1/F2 gate. It is deliberately model-free: every case is a fixed
input with a fixed expected result, so it runs in CI with no API key, no
network, and no flakiness. That is the property that makes it worth having at
this stage - a gate that needs a paid model to be green is a gate that gets
skipped, and a skipped gate is indistinguishable from no gate.

F2's promptfoo trajectory evals score a real agent's tool *choice*, which is
genuinely different work and does need a model. That is not faked here.

Cases assert on the tool boundary - what an agent receives - so they survive
refactors of the internals. A case names a `kind` and a fixture `output_ref`;
the runner resolves the fixture so the expected text lives in one place.

Exit codes: 0 all cases passed, 1 at least one failed, 2 the suite is malformed.
"""

from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from netverify import sanitize, scan, verify, verify_many  # noqa: E402
from tests import fixtures  # noqa: E402

CASES_DIR = pathlib.Path(__file__).resolve().parent / "cases"


def load_cases() -> list[dict]:
    """Load every case file in `evals/cases/`, sorted by filename.

    A directory rather than one file so the suite can be split by concern -
    verification, sanitisation, batching - without a 6k-line monolith, and so a
    new area gets its own file rather than being appended to the end of one.
    """
    cases: list[dict] = []
    for path in sorted(CASES_DIR.glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        found = document.get("cases", [])
        if not isinstance(found, list) or not found:
            raise ValueError(f"{path} has no non-empty 'cases' list")
        cases.extend(found)
    if not cases:
        raise ValueError(f"{CASES_DIR} contains no case files")
    return cases


def _output(case: dict) -> str:
    return getattr(fixtures, case["output_ref"])


def _assert_common(case: dict, blob: str, failures: list[str]) -> None:
    """Checks every case kind shares, so a leak is caught whatever the kind."""
    name = case.get("name", "<unnamed>")
    for needle in case.get("expect_contains", []):
        if needle not in blob:
            failures.append(f"{name}: result did not contain {needle!r}")
    for needle in case.get("expect_absent", []):
        if needle in blob:
            failures.append(f"{name}: result LEAKED {needle!r}")


def evaluate_verify(case: dict) -> list[str]:
    """Cases that call `verify` and assert on the verdict."""
    name = case.get("name", "<unnamed>")
    arguments = case.get("arguments", {})

    try:
        verdict = verify(case["command"], _output(case), **arguments)
    except ValueError as exc:
        expected = case.get("expect_error_contains")
        if expected is None:
            return [f"{name}: refused but a verdict was expected ({exc})"]
        if expected not in str(exc):
            return [f"{name}: refusal did not mention {expected!r}: {exc}"]
        return []
    except Exception as exc:  # noqa: BLE001
        return [f"{name}: unexpected {type(exc).__name__}: {exc}"]

    failures: list[str] = []
    if "expect_ok" in case and verdict.ok != case["expect_ok"]:
        failures.append(
            f"{name}: expected ok={case['expect_ok']}, got {verdict.ok} "
            f"(reasons: {verdict.reasons})"
        )
    if "expect_outcome" in case and verdict.outcome.value != case["expect_outcome"]:
        failures.append(
            f"{name}: expected outcome {case['expect_outcome']!r}, got {verdict.outcome.value!r}"
        )
    if case.get("expect_reasons_empty") and verdict.reasons:
        failures.append(f"{name}: expected no reasons, got {verdict.reasons}")
    if case.get("expect_mentions") and not all(
        needle in " ".join(verdict.reasons) for needle in case["expect_mentions"]
    ):
        failures.append(f"{name}: reasons did not mention {case['expect_mentions']}")

    _assert_common(case, json.dumps(verdict.to_dict()), failures)
    return failures


def evaluate_sanitize(case: dict) -> list[str]:
    """Cases that call `sanitize` and assert on safe text and findings."""
    name = case.get("name", "<unnamed>")
    report = sanitize(_output(case))

    failures: list[str] = []
    kinds = {f.kind for f in report.findings}
    for kind in case.get("expect_kinds", []):
        if kind not in kinds:
            failures.append(f"{name}: expected finding {kind!r}, got {sorted(kinds)}")
    for kind in case.get("expect_no_kinds", []):
        if kind in kinds:
            failures.append(f"{name}: unexpected finding {kind!r}")
    if "expect_clean" in case and report.clean != case["expect_clean"]:
        failures.append(f"{name}: expected clean={case['expect_clean']}")
    if "expect_truncated" in case and report.truncated != case["expect_truncated"]:
        failures.append(f"{name}: expected truncated={case['expect_truncated']}")

    _assert_common(case, report.safe_text, failures)
    return failures


def evaluate_scan(case: dict) -> list[str]:
    """Cases that call `scan`, which must never alter the text."""
    name = case.get("name", "<unnamed>")
    text = _output(case)
    before = text
    findings = scan(text)

    failures: list[str] = []
    if text != before:
        failures.append(f"{name}: scan() modified the text it was given")
    kinds = {f.kind for f in findings}
    for kind in case.get("expect_kinds", []):
        if kind not in kinds:
            failures.append(f"{name}: expected finding {kind!r}, got {sorted(kinds)}")
    if "expect_count" in case and len(findings) != case["expect_count"]:
        failures.append(f"{name}: expected {case['expect_count']} findings, got {len(findings)}")
    if "expect_highest_severity" in case:
        severities = {f.severity for f in findings}
        highest = (
            "critical"
            if "critical" in severities
            else "high"
            if "high" in severities
            else "medium"
            if "medium" in severities
            else None
        )
        if highest != case["expect_highest_severity"]:
            failures.append(
                f"{name}: expected highest severity "
                f"{case['expect_highest_severity']!r}, got {highest!r}"
            )
    return failures


def evaluate_batch(case: dict) -> list[str]:
    """Cases that call `verify_many` and assert the batch keeps its shape."""
    name = case.get("name", "<unnamed>")
    items = [
        {
            "command": entry["command"],
            "output": getattr(fixtures, entry["output_ref"]),
            **entry.get("arguments", {}),
        }
        for entry in case["items"]
    ]
    results = verify_many(items)

    failures: list[str] = []
    if len(results) != len(items):
        failures.append(f"{name}: got {len(results)} results for {len(items)} inputs")
    verdicts = sum(1 for r in results if not isinstance(r, Exception) and r.ok)
    refused = sum(1 for r in results if isinstance(r, Exception))
    if "expect_verdicts" in case and verdicts != case["expect_verdicts"]:
        failures.append(f"{name}: expected {case['expect_verdicts']} ok, got {verdicts}")
    if "expect_refused" in case and refused != case["expect_refused"]:
        failures.append(f"{name}: expected {case['expect_refused']} refused, got {refused}")
    return failures


_DISPATCH = {
    "verify": evaluate_verify,
    "sanitize": evaluate_sanitize,
    "scan": evaluate_scan,
    "batch": evaluate_batch,
}


def main() -> int:
    try:
        cases = load_cases()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"EVAL SUITE MALFORMED: {exc}", file=sys.stderr)
        return 2

    failed = 0
    for case in cases:
        kind = case.get("kind", "verify")
        handler = _DISPATCH.get(kind)
        if handler is None:
            failed += 1
            print(f"FAIL  {case.get('name', '<unnamed>')}: unknown case kind {kind!r}")
            continue
        failures = handler(case)
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
