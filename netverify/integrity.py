"""Self-description: can a caller verify what this server actually is?

Every other claim in this project is a claim about behaviour - read-only,
no credentials, byte-identical to a pinned commit. Those claims are only worth
something if a caller can check them, and most MCP servers cannot be checked at
all: an agent is asked to trust a description.

So this module makes the server auditable from the outside. `self_check`
reports the pinned upstream commit, the number and identity of every registered
check and detection pattern, the limits in force, and the tracing state. None of
it requires a credential, a network call, or trust in the caller.

Two things it deliberately does *not* do, and says so in its own output:

- It does not verify the vendored file against upstream. That needs the network
  and already runs in CI as its own job; claiming it here would be a green
  check that proves nothing.
- It does not assert the code is free of defects. It reports what is present so
  a reader can judge, and it says "unverified by design" for the one claim that
  would need the network.
"""

from __future__ import annotations

import hashlib
import pathlib
from typing import Any

from . import telemetry
from .limits import DEFAULT_DEADLINE_SECONDS
from .registry import ARGUMENT_PATTERNS, COMMANDS, MUTATING_VERBS
from .sanitize import _INJECTION_PATTERNS, _SECRET_PATTERNS, MAX_BYTES
from .scope import validate
from .verify import MAX_BATCH_ITEMS, MAX_TOTAL_INPUT_BYTES

#: The version string is duplicated here rather than read from the package's
#: `__init__`. That is not duplication for its own sake: `__init__` imports this
#: module, so reading `__version__` from it would be a circular import that fails
#: at module load. `test_integrity.py` asserts the two agree, so they cannot
#: quietly diverge.
__version__ = "1.2.0"

#: Modules that could open a socket or drive a network device. Their absence
#: from the package is what makes the "opens no sockets" claim checkable rather
#: than merely stated, and it is the property that lets netverify run inside a
#: lab with no route to the management network.
NETWORK_CAPABLE = frozenset(
    {
        "socket",
        "ssl",
        "http",
        "urllib",
        "requests",
        "httpx",
        "aiohttp",
        "paramiko",
        "netmiko",
        "ncclient",
        "ftplib",
        "telnetlib",
        "smtplib",
        "xmlrpc",
        "asyncio",
    }
)

#: Modules that read credentials or execute other programs. Same reasoning: a
#: server that imports these is a server that could hold or use a secret.
CREDENTIAL_CAPABLE = frozenset({"getpass", "pwd", "netrc", "keyring", "subprocess"})


#: Non-stdlib modules allowed to appear in the package. The instrumentation
#: imports these defensively, so their *absence* degrades to a no-op rather than
#: breaking the import - which is why their presence is not a dependency and the
#: zero-dependency claim survives them.
ALLOWED_OPTIONAL = frozenset({"opentelemetry", "opentelemetry_api"})

#: Modules the vendored parser is allowed to import, restated here so
#: `imported_roots` is not silently widened by the vendor's own imports.
VENDOR_ALLOWED = frozenset({"json", "re"})


def _third_party(roots: set[str]) -> set[str]:
    """Third-party roots present, excluding the ones that are permitted."""
    import sys

    stdlib = set(sys.stdlib_module_names)
    return {
        r
        for r in roots
        if r not in stdlib
        and r not in ALLOWED_OPTIONAL
        and r not in VENDOR_ALLOWED
        and r != "netverify"
    }


def imported_roots() -> set[str]:
    """Every top-level module imported anywhere in the package, by static scan.

    Static rather than live on purpose: `sys.modules` would report whatever the
    *host* process happened to have imported, which says more about the host
    than about netverify. Reading the source answers the question actually being
    asked.
    """
    import ast

    roots: set[str] = set()
    package = pathlib.Path(__file__).resolve().parent
    for path in sorted(package.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover - a broken file fails CI anyway
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                roots.add(node.module.split(".")[0])
    return roots


#: Pinned upstream, duplicated here deliberately rather than imported: the parity
#: script owns the pin, and `tests/test_integrity.py` asserts the two agree.
#: Importing the pin would make that assertion impossible to write, which is
#: exactly the drift this arrangement is meant to catch.
PINNED_COMMIT = "71d3398207088ca67a15ddd3132cedfed81bd678"
UPSTREAM_REPO = "Realms4239/isp-network-as-code"
UPSTREAM_PATH = "pyats/parsers.py"

VENDORED = pathlib.Path(__file__).resolve().parent / "parsers" / "upstream.py"


def vendored_digest() -> dict[str, Any]:
    """SHA-256 of the vendored parser, so drift is detectable without the network.

    A hash is a far weaker guarantee than the parity check - it cannot tell you
    *what* changed - but it is computed offline and lets two installations be
    compared to each other, which is the question a second operator is actually
    asking.
    """
    if not VENDORED.exists():
        return {"present": False, "sha256": None}
    digest = hashlib.sha256(VENDORED.read_bytes()).hexdigest()
    return {"present": True, "sha256": digest, "bytes": VENDORED.stat().st_size}


def self_check() -> dict[str, Any]:
    """Everything a caller needs to judge what this server is.

    Read-only, offline, and safe to call at any time. If this is wrong about
    the server, that is a defect worth reporting rather than a reason to
    distrust the other tools.
    """
    # Imported by module path, not as `from . import sanitize`. The package
    # `__init__` re-exports the *function* `sanitize`, so the attribute form
    # silently binds to that function and this raises AttributeError. The same
    # trap applies to any name that is both a submodule and a re-export.
    from .sanitize import sanitize as sanitize_text

    secret_kinds = [kind for kind, _ in _SECRET_PATTERNS]
    injection_kinds = [kind for kind, _ in _INJECTION_PATTERNS]

    # Prove the allowlist is intact rather than asserting it. A cheap live check
    # beats a claim: if `configure` were ever allowlisted, this would say so.
    guards = {
        "mutating_command_refused": _refuses("configure"),
        "raw_cli_string_refused": _refuses("show interface brief"),
        "known_secret_masked": "hunter2" not in sanitize_text("password=hunter2").safe_text,
    }

    roots = imported_roots()
    network_found = sorted(roots & NETWORK_CAPABLE)
    credential_found = sorted(roots & CREDENTIAL_CAPABLE)
    third_party = _third_party(roots)

    return {
        "server": {
            "name": "netverify",
            "version": __version__,
            "protocol_revision": "2026-07-28",
        },
        # Split deliberately. `declared` is what this server says about itself
        # and is only as good as the design; `verified` is what this function
        # just checked, in this process, with no network and no trust. They were
        # one field before, and the result was five literals that no code read -
        # so a claim could not fail, and a claim that cannot fail is a caption.
        "guarantees": {
            "declared": {
                "read_only": True,
                "holds_device_credentials": False,
                "opens_sockets": False,
                "fetches_device_output": False,
                "zero_runtime_dependencies": True,
                "untrusted_text_sanitised": True,
            },
            "verified": {
                "no_network_module_imported": not network_found,
                "no_credential_module_imported": not credential_found,
                "no_third_party_module_imported": not third_party,
                "mutating_command_refused": guards["mutating_command_refused"],
                "raw_cli_string_refused": guards["raw_cli_string_refused"],
                "known_secret_masked": guards["known_secret_masked"],
            },
            "network_modules_found": network_found,
            "credential_modules_found": credential_found,
            "third_party_modules_found": sorted(third_party),
        },
        "commands": {
            "count": len(COMMANDS),
            "ids": [spec.id for spec in COMMANDS],
            "platforms": sorted({spec.platform for spec in COMMANDS}),
            "arguments_typed": sorted(ARGUMENT_PATTERNS),
        },
        "detection": {
            "secret_patterns": secret_kinds,
            "injection_patterns": injection_kinds,
            "mutating_verbs_watched": len(MUTATING_VERBS),
        },
        "limits": {
            "max_output_bytes": MAX_BYTES,
            "max_batch_items": MAX_BATCH_ITEMS,
            # The byte budget is what actually bounds the work; the item cap
            # alone let a batch cost five seconds. Both are reported because a
            # limit a caller cannot see is a limit they cannot plan around.
            "max_total_input_bytes": MAX_TOTAL_INPUT_BYTES,
            "call_deadline_seconds": DEFAULT_DEADLINE_SECONDS,
            "call_deadline_enforced": True,
            "call_deadline_preemptive": False,
            "call_deadline_note": (
                "Checked at boundaries; it cannot interrupt a regex pass. The "
                "byte budget is the control that bounds the work."
            ),
        },
        "vendored_parser": {
            **vendored_digest(),
            "repo": UPSTREAM_REPO,
            "path": UPSTREAM_PATH,
            "pinned_commit": PINNED_COMMIT,
            "parity_verified_here": False,
            "parity_note": (
                "Not verified in this process: that needs the network. Run "
                "scripts/check_upstream_parity.py, which CI does on every push. "
                "The hash above lets two installations be compared offline."
            ),
        },
        "guards_verified": guards,
        "telemetry": telemetry.status(),
    }


def _refuses(command: str) -> bool:
    """Whether the scope layer refuses `command`. Used as a live self-test."""
    try:
        validate(command, "output")
    except ValueError:
        return True
    return False
