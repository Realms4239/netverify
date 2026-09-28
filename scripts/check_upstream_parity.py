#!/usr/bin/env python3
"""Fail the build if the vendored parser has drifted from its pinned upstream.

The vendored copy exists because the flagship's `pyats/parsers.py` is not a
distributable package, so it cannot be a dependency. A vendored copy is only
worth anything if it cannot silently diverge: a local edit here would make this
server disagree with the flagship's own CI assertions, and the two would then
report different verdicts about the same device output.

So the comparison is enforced, not documented. This script fetches the pinned
commit and diffs it against the vendored file, ignoring the provenance header.
Any difference is a build failure naming both sides.

Exit codes: 0 identical, 1 drifted, 2 could not verify (network/URL problem).
Exit 2 is deliberately distinct from 1: "we could not check" must never be
mistaken for "we checked and it is fine".

Usage:
    python scripts/check_upstream_parity.py
    python scripts/check_upstream_parity.py --offline   # header checks only
"""

from __future__ import annotations

import argparse
import difflib
import pathlib
import sys
import urllib.error
import urllib.request

REPO = "Realms4239/isp-network-as-code"
COMMIT = "71d3398207088ca67a15ddd3132cedfed81bd678"
UPSTREAM_PATH = "pyats/parsers.py"
RAW_URL = f"https://raw.githubusercontent.com/{REPO}/{COMMIT}/{UPSTREAM_PATH}"

VENDORED = pathlib.Path(__file__).resolve().parents[1] / "netverify" / "parsers" / "upstream.py"

#: Marker that ends the provenance header. Everything after it must match
#: upstream byte for byte.
HEADER_END = '"""Pure parsers for the pyATS assertions'


def split_header(text: str) -> tuple[str, str]:
    """Return (header, body) where body starts at the module docstring."""
    index = text.find(HEADER_END)
    if index == -1:
        raise SystemExit(
            f"vendored file {VENDORED} has no recognisable provenance header.\n"
            f"Expected to find {HEADER_END!r} after the header comments.\n"
            "The header defines the region this check compares, so it cannot be "
            "removed or reformatted."
        )
    return text[:index], text[index:]


def check_offline(header: str) -> list[str]:
    """Header self-consistency, verifiable with no network."""
    problems = []
    if COMMIT not in header:
        problems.append(f"header does not pin the expected commit {COMMIT}")
    if REPO not in header:
        problems.append(f"header does not name the source repo {REPO}")
    if UPSTREAM_PATH not in header:
        problems.append(f"header does not name the upstream path {UPSTREAM_PATH}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--offline",
        action="store_true",
        help="only check the header; skip the network comparison",
    )
    args = parser.parse_args()

    if not VENDORED.exists():
        print(f"FAIL: vendored file is missing: {VENDORED}", file=sys.stderr)
        return 1

    vendored_text = VENDORED.read_text(encoding="utf-8")
    try:
        header, vendored_body = split_header(vendored_text)
    except SystemExit as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    problems = check_offline(header)
    if problems:
        for problem in problems:
            print(f"FAIL: {problem}", file=sys.stderr)
        return 1
    print(f"header OK: pinned to {REPO}@{COMMIT[:7]} {UPSTREAM_PATH}")

    if args.offline:
        print("offline mode: skipped the upstream comparison")
        return 0

    # Bandit flags urlopen (B310) because a caller-controlled scheme could be
    # file:// or something custom. Here the URL is a module constant, but the
    # scheme is asserted anyway rather than suppressed with a bare nosec: if
    # RAW_URL is ever built from an env var or an argument, this fails closed
    # instead of quietly fetching a local file.
    if not RAW_URL.startswith("https://"):
        print(f"REFUSING: parity source must be https, got {RAW_URL!r}", file=sys.stderr)
        return 2

    try:
        with urllib.request.urlopen(RAW_URL, timeout=30) as response:  # nosec B310
            upstream_body = response.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(
            f"COULD NOT VERIFY: could not fetch {RAW_URL}\n  {exc}\n"
            "This is not a pass. Re-run with network access.",
            file=sys.stderr,
        )
        return 2

    if upstream_body == vendored_body:
        print(f"parity OK: vendored copy is byte-identical to {COMMIT[:7]}")
        return 0

    print(
        f"DRIFT: vendored copy differs from {REPO}@{COMMIT[:7]}\n"
        "Do not edit the vendored file to silence this. Either the pin needs\n"
        "reviewing (and the header commit updated) or the local edit must be\n"
        "reverted, because the two repos would otherwise disagree about the\n"
        "same device output.\n",
        file=sys.stderr,
    )
    diff = difflib.unified_diff(
        vendored_body.splitlines(keepends=True),
        upstream_body.splitlines(keepends=True),
        fromfile="vendored (server/vendor/pyats_parsers.py)",
        tofile=f"upstream ({UPSTREAM_PATH}@{COMMIT[:7]})",
        n=2,
    )
    sys.stderr.writelines(diff)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
