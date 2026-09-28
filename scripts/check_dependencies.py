"""Assert the zero-dependency claim by static import analysis.

`netverify` is meant to be vendorable into a lab box, an air-gapped CI runner,
or a small machine on an unreliable grid. A dependency tree is a supply-chain
surface in exactly that setting, so the claim is checked rather than trusted -
and this is the same check `scripts/` and CI rely on to notice the moment
OpenTelemetry or anything else stops being optional.
"""

import ast
import pathlib
import sys

STDLIB = set(sys.stdlib_module_names)

#: The project's own top-level packages. These are first-party, not third-party,
#: so they must not count against the zero-dependency claim. Without this, a
#: `from netverify import verify` inside the package is misread as an external
#: dependency - and the check would fail on the very package it exists to guard.
FIRST_PARTY = {"netverify", "server"}

#: Modules that are allowed to be non-stdlib inside `netverify/`. All are
#: imported defensively (see `netverify/telemetry.py`), so their absence
#: degrades to a no-op rather than breaking the import.
ALLOWED_OPTIONAL = {
    "opentelemetry",
}


def imports_of(path: pathlib.Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.add(node.module.split(".")[0])
    return found


def main() -> int:
    everything: set[str] = set()
    for path in sorted(pathlib.Path("netverify").rglob("*.py")):
        everything |= imports_of(path)

    non_stdlib = sorted(m for m in everything if m not in STDLIB and m not in FIRST_PARTY)
    required = [m for m in non_stdlib if m not in ALLOWED_OPTIONAL]
    optional = [m for m in non_stdlib if m in ALLOWED_OPTIONAL]
    first_party = sorted(everything & FIRST_PARTY)

    print(f"modules imported : {len(everything)}")
    print(f"first-party      : {first_party or 'none'}")
    print(f"non-stdlib       : {non_stdlib or 'none'}")
    print(f"optional, guarded: {optional or 'none'}")

    if required:
        print(f"\nFAIL: netverify/ requires third-party modules: {required}")
        print(
            "The zero-dependency guarantee is a product property, not an "
            "accident. Vendor it in something that cannot install packages "
            "before relaxing it."
        )
        return 1

    print("\nOK: netverify/ imports only the standard library")
    print("   (optional instrumentation is imported defensively)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
