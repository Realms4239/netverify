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
        '    if any(ch in text for ch in "\\r\\n\\t"):',
        "    if False:  # MUTANT: allow control characters",
        "control-character defence in depth is removed",
        # Tolerated on purpose. The argument patterns already reject any value
        # carrying an interior newline, so a forged line cannot be produced
        # today - which is exactly why no test can distinguish this mutant from
        # correct behaviour. The explicit check is kept as defence in depth for a
        # future argument type with no pattern, where it would be the only guard.
        True,
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
