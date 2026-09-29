#!/usr/bin/env python3
"""Prove the built wheel is actually usable, not merely buildable.

Every other gate here runs against the checkout. That is a real gap: the one
thing packaging can break is packaging, and nothing else would notice. A wheel
that omits `skills/` still passes 247 tests, 46 evals, the mutation suite and
the stdio check - all of which run from the source tree, where `skills/` happens
to sit next to `server/`.

So this builds the wheel, installs it into a throwaway virtual environment, and
runs the installed package from a directory unrelated to the repository. Four
things can go wrong, and each is checked separately because the symptom is
otherwise identical - a server that starts and serves an empty catalogue:

    1. the data never made it into the wheel,
    2. it made it but `SKILLS_ROOT` resolves elsewhere in an installed layout
       (`parents[1] / "skills"` assumes a flat tree),
    3. it resolves but the catalogue is empty because parsing failed,
    4. the console entry points are missing or broken.

Assertion 2 is the one worth having. `server/skills.py` finds its data at
`Path(__file__).resolve().parents[1] / "skills"` - correct for an editable
checkout and for a wheel whose top level is a directory, and quietly wrong the
moment the package is vendored, frozen, or otherwise nested.

Exit codes: 0 the installed package works, 1 it does not, 2 it could not be
built or installed. 2 is distinct from 1 for the same reason as in
`check_upstream_parity.py`: "we could not check" is never reported as "we
checked and it is fine".

Usage:
    python scripts/check_wheel_install.py
    python scripts/check_wheel_install.py --offline   # no network; reports gaps
"""

from __future__ import annotations

import argparse
import os
import pathlib
import subprocess
import sys
import tempfile
import zipfile

import wheel_probe

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _run(args: list[str], cwd: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def _fail(stage: str, detail: str) -> None:
    print(f"WHEEL INSTALL CHECK FAILED at {stage}: {detail}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify the built wheel is usable.")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="skip installing the mcp extra (no network); reports it as unverified",
    )
    options = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="netverify-wheel-") as tmp:
        work = pathlib.Path(tmp)
        dist = work / "dist"
        venv = work / "venv"

        print("=== 1. build the wheel ===")
        built = _run(
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                ".",
                "--no-deps",
                "--no-build-isolation",
                "-w",
                str(dist),
            ],
            cwd=ROOT,
        )
        if built.returncode != 0:
            print(built.stdout[-1500:], file=sys.stderr)
            print(built.stderr[-1500:], file=sys.stderr)
            print("could not build a wheel; is setuptools available?", file=sys.stderr)
            return 2
        wheels = sorted(dist.glob("*.whl"))
        if len(wheels) != 1:
            _fail("build", f"expected one wheel, found {[w.name for w in wheels]}")
        wheel = wheels[0]
        print(f"  built {wheel.name}")

        print()
        print("=== 2. does the wheel contain the skill data? ===")
        with zipfile.ZipFile(wheel) as archive:
            names = archive.namelist()
        markdown = [n for n in names if n.endswith(".md")]
        print(f"  entries: {len(names)}")
        if not markdown:
            _fail(
                "wheel contents",
                "no .md in the wheel, so the shipped server would serve an empty "
                "skill catalogue while starting normally. Check package-data.",
            )
        for name in markdown:
            print(f"  found {name}")

        print()
        print("=== 3. install into a clean virtual environment ===")
        made = _run([sys.executable, "-m", "venv", str(venv)], cwd=work)
        if made.returncode != 0:
            print(made.stderr[-1500:], file=sys.stderr)
            return 2
        exe = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        installed = _run([str(exe), "-m", "pip", "install", "--no-index", str(wheel)], cwd=work)
        if installed.returncode != 0:
            print(installed.stderr[-1500:], file=sys.stderr)
            return 2
        print(f"  installed {wheel.name}")

        have_mcp = False
        if options.offline:
            print("  mcp extra: skipped (--offline); the server surface is unverified")
        else:
            have_mcp = (
                _run([str(exe), "-m", "pip", "install", "mcp==2.2.0"], cwd=work).returncode == 0
            )
            print(f"  mcp extra installed: {have_mcp}")
            if not have_mcp:
                print("  NOTE: the MCP skill surface is reported UNVERIFIED rather")
                print("        than passing. An offline run is not full coverage.")

        print()
        print("=== 4. run the INSTALLED package, outside the repository ===")
        # Copied beside the probe: it is imported by the clean interpreter, so it
        # must not be shadowed by this checkout's copy.
        (work / "wheel_probe.py").write_text(wheel_probe.PROBE, encoding="utf-8")
        (work / "probe.py").write_text("import wheel_probe\nwheel_probe.main()\n", encoding="utf-8")
        result = _run([str(exe), str(work / "probe.py")], cwd=work)
        print(result.stdout.rstrip())
        if result.stderr.strip():
            print(result.stderr.rstrip(), file=sys.stderr)
        if result.returncode != 0:
            _fail("installed package", "the probe failed; see the output above")
        if not have_mcp:
            print("  UNVERIFIED: the mcp extra was unavailable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
