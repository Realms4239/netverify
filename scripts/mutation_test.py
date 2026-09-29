#!/usr/bin/env python3
"""Mutation testing: prove the suite actually catches regressions.

A green suite is only worth something if it would go red when the code was
wrong. This applies realistic, single-line mutations to the library and asserts
that the test suite *fails* on each. Every mutant that survives is a gap: a place
where the code could be wrong and nothing would notice.

Same principle as the other negative controls here - the parity checker fed a
deliberately broken file, the mutating-verb guard fed `configure terminal`. A
checker that cannot fail is not a checker.

The mutations are ones a plausible refactor would introduce, not random bit
flips, because the question is "would a realistic mistake be caught", not
"does the suite hit some mutation score".

`Tolerated` marks a survivor that is acceptable *and says why*. That reasoning
matters as much as the pass: a tolerated mutant with no justification is
indistinguishable from a test gap, which is the ambiguity this script exists to
remove.

Exit codes: 0 no untolerated survivor, 1 at least one.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]

# (file, original, replacement, description, tolerated)
MUTATIONS: list[tuple[str, str, str, str, bool]] = [
    (
        "netverify/sanitize.py",
        '    safe = unicodedata.normalize("NFKC", text)',
        "    safe = text  # MUTANT: skip normalisation",
        "normalisation skipped, so confusables bypass every pattern",
        False,
    ),
    (
        "netverify/sanitize.py",
        "    for kind, pattern in _SECRET_PATTERNS:",
        "    for kind, pattern in _SECRET_PATTERNS[:2]:  # MUTANT",
        "most credential patterns stop being reported",
        False,
    ),
    (
        "netverify/sanitize.py",
        "        safe = safe[:start] + _apply_injection(kind, safe[start:end]) + safe[end:]",
        "        pass  # MUTANT: stop neutralising injections",
        "prompt injection reaches the model verbatim",
        False,
    ),
    (
        "netverify/sanitize.py",
        "    safe, truncated = _prepare(text, max_bytes)",
        "    safe, truncated = text, False  # MUTANT: no bound on work",
        "the size cap stops limiting CPU work",
        False,
    ),
    (
        "netverify/sanitize.py",
        "        if any(low <= start and end <= high for low, high in already_neutralised):",
        "        if False:  # MUTANT: re-bracket own output",
        "sanitize is no longer idempotent",
        False,
    ),
    (
        "netverify/sanitize.py",
        "    if len(encoded) <= max_bytes:",
        "    if True:  # MUTANT: never truncate",
        "sanitize output exceeds its documented cap",
        False,
    ),
    (
        "netverify/verify.py",
        "    if len(items) > MAX_BATCH_ITEMS:",
        "    if False:  # MUTANT: unbounded batch",
        "one agent call can pin the process",
        False,
    ),
    (
        "netverify/verify.py",
        "    if not isinstance(items, list):",
        "    if False:  # MUTANT",
        "a non-list batch escapes the error contract",
        False,
    ),
    (
        "netverify/scope.py",
        "    pattern = registry.ARGUMENT_PATTERNS.get(field)",
        "    pattern = None  # MUTANT: accept any argument",
        "argument validation disappears",
        False,
    ),
    (
        "netverify/scope.py",
        # Matches the check as it stands, which tests the *raw* value rather than
        # the stripped one. That rename was the fix for a leading tab being
        # silently stripped and accepted, so an anchor written against the old
        # stripped form no longer exists and the mutation reports as stale
        # rather than testing anything.
        '    if any(ch in value for ch in "\\r\\n\\t"):',
        "    if False:  # MUTANT: allow control characters",
        "control-character defence in depth is removed",
        # Now caught, and the reason is worth recording. It was previously
        # tolerated on the grounds that the argument patterns already reject any
        # value carrying an interior newline, so no test could distinguish the
        # mutant from correct behaviour. That is no longer true, because the
        # check now runs before `strip()`: a *leading* tab is not an interior
        # newline, so it passed the patterns and reached the verdict. The
        # mutant is caught by the tab regression test.
        False,
    ),
    (
        # The instrumentation cycle. These three exist because "we added a
        # counter" is a claim no behaviour test can check: a `record_*` call
        # removed, or a refusal reason left unset, changes nothing a caller
        # sees. Only a test that reads the instrument back would notice, so
        # without these mutations the new tests could be decorative.
        "netverify/scope.py",
        "            reason=REASON_NOT_IN_ALLOWLIST,",
        "            # MUTANT: refusal reason dropped",
        "a refusal reaches the metrics with no reason, so it lands in the generic bucket",
        False,
    ),
    (
        "netverify/telemetry.py",
        '    _record(\n        _counter(METRIC_VERDICTS, "Verdicts by command and outcome."),',
        "    _record(\n        None,  # MUTANT: verdict counter disabled",
        "verdicts stop being counted, so failure rate by command is unavailable",
        False,
    ),
    (
        "netverify/verify.py",
        "                    progress(index, total)",
        "                    pass  # MUTANT: no progress reported",
        "a long batch reports nothing, so a client cannot tell it from a hang",
        False,
    ),
]


def run_suite(root: pathlib.Path) -> bool:
    """Run the tests. Returns True when they pass."""
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", "."],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0


def main() -> int:
    # Work on a copy, so a surviving mutant cannot leave the real tree dirty.
    with tempfile.TemporaryDirectory() as tmp:
        work = pathlib.Path(tmp) / "netverify"
        shutil.copytree(
            ROOT,
            work,
            ignore=shutil.ignore_patterns(
                ".git", "__pycache__", ".ruff_cache", "*.log", ".pytest_cache"
            ),
        )

        # Refuse to start from a red baseline: measuring how many mutants a
        # suite catches means nothing if the suite was already failing.
        if not run_suite(work):
            print("REFUSING TO START: the suite is not green before mutation.")
            print("A mutation run against a red baseline proves nothing.")
            return 1

        print(f"baseline green; applying {len(MUTATIONS)} mutations\n")

        survived: list[str] = []
        tolerated = 0
        for index, (relative, original, replacement, description, ok) in enumerate(
            MUTATIONS, start=1
        ):
            target = work / relative
            text = target.read_text(encoding="utf-8")
            if original not in text:
                survived.append(f"{index:2d}. {relative}: anchor moved ({description})")
                print(f"{index:2d}. STALE  {description}")
                continue

            target.write_text(text.replace(original, replacement, 1), encoding="utf-8")
            try:
                caught = not run_suite(work)
            finally:
                target.write_text(text, encoding="utf-8")

            if caught:
                print(f"{index:2d}. caught    {description}")
            elif ok:
                tolerated += 1
                print(f"{index:2d}. tolerated {description}   (documented above)")
            else:
                print(f"{index:2d}. SURVIVED  {description}   <-- test gap")
                survived.append(f"{index:2d}. {relative}: {description}")

    print()
    if survived:
        print(f"MUTATION TEST FAILED: {len(survived)} mutant(s) survived")
        for item in survived:
            print(f"  - {item}")
        print(
            "\nA surviving mutant is a place the suite would not notice a bug. "
            "Either add a test that catches it, or mark it tolerated with the "
            "reason it is acceptable."
        )
        return 1

    print(
        f"MUTATION TEST OK: {len(MUTATIONS) - tolerated}/{len(MUTATIONS)} caught, "
        f"{tolerated} tolerated with a documented reason"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
