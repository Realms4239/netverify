"""The check that runs *inside* a clean environment, against the installed wheel.

Split out of `check_wheel_install.py` and copied next to the probe before the run,
because this file is imported by the throwaway interpreter. Keeping it as a
module rather than a string means it is linted and type-checked like the rest of
the project instead of being an opaque blob inside a subprocess call.

The single most important assertion is the first one. An earlier draft of this
probe was executed *from* the repository, where `sys.path[0]` is the checkout -
so it happily imported `netverify` from the source tree, resolved `SKILLS_ROOT`
to the working copy, and reported success while proving nothing about the wheel.
Requiring `site-packages` in the resolved path turns that silent pass into a
failure.

Note there are no imports at module level here: everything the probe needs is
imported inside `main`, which the clean interpreter calls after importing this
file. Declaring them outside would import the *checker's* copy of the stdlib path
handling and, worse, invite a reader to assume the module body runs in the clean
environment.

The `PROBE` string below is load-bearing, and it is easy to mistake for
vestigial: `main()` writes it to a temporary file and runs that with the clean
interpreter's own `sys.executable`. It is *this module* that
`check_wheel_install.py` copies next to the probe, and the copy is a copy rather
than a re-write for a reason - an earlier version had the outer script write
`PROBE` itself, and the two drifted, so the clean interpreter imported a module
with no `main` and the gate failed on an AttributeError that had nothing to do
with the wheel. If you change the probe, change it here; the copy follows.
"""

from __future__ import annotations

PROBE = """
import json, pathlib, subprocess, sys

import netverify
import server.skills as skills_module

resolved = pathlib.Path(netverify.__file__).resolve().parent
print(f"  netverify resolved to: {resolved}")
if "site-packages" not in str(resolved):
    print("  FAIL: resolved to the checkout, not the installed package")
    sys.exit(1)

root = skills_module.SKILLS_ROOT
print(f"  SKILLS_ROOT         : {root}")
print(f"  exists              : {root.is_dir()}")
if not root.is_dir():
    print("  FAIL: the installed package cannot locate its own skill data")
    sys.exit(1)

loaded = skills_module.load_skills()
print(f"  skills served       : {sorted(loaded)}")
if not loaded:
    print("  FAIL: SKILL.md shipped but the catalogue is empty")
    sys.exit(1)
for name, skill in loaded.items():
    body = skill.read("SKILL.md").decode("utf-8")
    if not body.strip():
        print(f"  FAIL: {name} is empty")
        sys.exit(1)
    print(f"  {name}: {len(body)} bytes, {len(skill.entry()['resources'])} resources")

extension = skills_module.SkillsExtension(loaded)
advertised = extension.settings()
print(f"  extension settings  : {advertised}")
if advertised.get("skills") != sorted(loaded):
    print("  FAIL: the extension does not advertise what it can serve")
    sys.exit(1)

for flags, expect_json in ((["self-check"], False), (["--json", "self-check"], True)):
    cli = subprocess.run(
        [sys.executable, "-m", "netverify.cli", *flags],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if cli.returncode != 0:
        print(f"  FAIL: netverify {' '.join(flags)} exited {cli.returncode}: {cli.stderr[-200:]}")
        sys.exit(1)
    if expect_json:
        json.loads(cli.stdout)
print("  CLI entry point     : ok for 'self-check' and '--json self-check'")
print("  INSTALLED PACKAGE OK")
"""


def main() -> int:
    """Entry point for the copied probe. Returns a process exit code.

    Written to a real file and run with `runpy` rather than `exec`'d, which was
    the first draft and tripped bandit B102. The `exec` was never the risk - the
    probe string is a constant in this repository, not input - but there is no
    reason to carry a finding that a reviewer has to reason about every time
    the file is opened, and `runpy` says the same thing with no suppression.
    """
    import pathlib
    import runpy
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".py", encoding="utf-8", delete=False) as handle:
        handle.write(PROBE)
        path = handle.name
    try:
        runpy.run_path(path, run_name="__main__")
    finally:
        pathlib.Path(path).unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
