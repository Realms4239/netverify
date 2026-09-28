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
from .verify import MAX_BATCH_ITEMS

#: The version string is duplicated here rather than read from the package's
#: `__init__`. That is not duplication for its own sake: `__init__` imports this
#: module, so reading `__version__` from it would be a circular import that fails
#: at module load. `test_integrity.py` asserts the two agree, so they cannot
#: quietly diverge.
__version__ = "1.2.0"

#: Pinned upstream, duplicated here deliberately rather than imported: the parity
#: script owns the pin, and the test suite asserts the two agree. Importing it
#: would make that assertion impossible to write.
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

    return {
        "server": {
            "name": "netverify",
            "version": __version__,
            "protocol_revision": "2026-07-28",
        },
        "guarantees": {
            "read_only": True,
            "holds_device_credentials": False,
            "opens_sockets": False,
            "fetches_device_output": False,
            "zero_runtime_dependencies": True,
            "untrusted_text_sanitised": True,
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
            "call_deadline_seconds": DEFAULT_DEADLINE_SECONDS,
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
