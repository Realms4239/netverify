"""Narrow, read-only scope for the one exposed tool.

Design rule, taken from the flagship's own lesson: *the tool must be unable to
cause harm, not merely unlikely to.* Two properties give that here.

1. **No device credentials exist in this process.** The server never runs a
   command against a router, opens a socket, or shells out. It is a pure
   verifier over output text that a caller already has. An agent cannot misuse
   the tool to change device state, because the capability to do so is simply
   not present. This is strictly stronger than filtering dangerous commands.

2. **The command set is a closed allowlist.** A caller names a *command id*
   from `ALLOWED_COMMANDS`, never a free-form CLI string. There is no code path
   that accepts arbitrary device commands, so "allow only show commands" is
   enforced by the type of the input rather than by pattern-matching a string
   that could be evaded.

This is the F1 mitigation for OWASP LLM Top 10 Excessive Agency: least-privilege
by construction. Human approval for writes and audience-bound tokens arrive in
F3, and are deliberately absent here because there is nothing to write to.
"""

from __future__ import annotations

import re
from typing import Any

# --- limits ----------------------------------------------------------------

#: Hard cap on accepted device output. An agent's context is the real scarce
#: resource, and an unbounded string field is a trivial denial-of-service on the
#: caller: a few hundred KB of `show` output can evict every other tool result
#: from the window. 64 KiB is far above any real `show interface brief`.
MAX_OUTPUT_BYTES = 64 * 1024

#: Cap on how much of the output the redaction pass will echo back in a reason.
MAX_REASON_CHARS = 200


class ScopeError(ValueError):
    """Raised when a request violates the tool's declared scope.

    A `ValueError` subclass so callers can catch it as a validation error
    without importing this module's internals.
    """


# --- the closed allowlist --------------------------------------------------

# Each entry: the command id an agent may name, the exact read-only command it
# stands for (documentation + used in responses), and the arguments that
# command needs. `required` arguments must be supplied for the check to be
# meaningful; `optional` ones refine it.
ALLOWED_COMMANDS: dict[str, dict[str, Any]] = {
    "srl_interface_brief": {
        "command": "show interface brief",
        "platform": "srl",
        "summary": "Report admin/oper state for one interface.",
        "required": ("interface",),
        "optional": (),
    },
    "srl_ospf_neighbor": {
        "command": "show network-instance default protocols ospf neighbor",
        "platform": "srl",
        "summary": "Report whether an OSPF neighbour reached full adjacency.",
        "required": ("neighbor_router_id",),
        "optional": (),
    },
    "srl_bgp_neighbor_detail": {
        "command": "show ... bgp neighbor <ip> detail",
        "platform": "srl",
        "summary": "Report whether a named BGP peer is established with the expected AS.",
        "required": ("peer_ip", "remote_as"),
        "optional": (),
    },
    "frr_bgp_summary": {
        "command": "show ip bgp summary json",
        "platform": "frr",
        "summary": "Report BGP peer health from the FRR JSON summary.",
        "required": (),
        "optional": (),
    },
    "srl_route_detail": {
        "command": "show ... route-table ipv4-unicast prefix <prefix> detail",
        "platform": "srl",
        "summary": "Report whether a route is actually installed for a prefix.",
        "required": ("prefix",),
        "optional": (),
    },
    "ping": {
        "command": "ping <host> count 3",
        "platform": "any",
        "summary": "Report whether a ping reached the far end.",
        "required": (),
        "optional": (),
    },
}


#: Anything that looks like a credential assignment or a private key block.
#: Reasons returned by the parsers quote device output, and device output can
#: contain a `password` line, so a failure reason is an exfiltration path even
#: though the success path is inert. Redaction is applied to every reason
#: before it leaves this module.
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key|auth)\b\s*[:=]\s*\S+"),
        r"\1=<redacted>",
    ),
    (
        re.compile(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"),
        "<redacted-private-key>",
    ),
    (re.compile(r"(?i)\b(enable|ssh)\s+password\s+\S+"), r"\1 password <redacted>"),
)


def redact(text: str, limit: int = MAX_REASON_CHARS) -> str:
    """Scrub credential-shaped substrings, then truncate.

    Order matters: redaction runs before truncation, so a secret cannot be
    split across the cut boundary and left half-visible.
    """
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    if len(text) > limit:
        text = text[:limit] + f"... [{len(text) - limit} more chars truncated]"
    return text


def _require_text(value: Any, field: str) -> str:
    """Coerce a field to text, rejecting the types an agent should not send."""
    if not isinstance(value, str):
        raise ScopeError(f"{field} must be a string, got {type(value).__name__}")
    text = value.strip()
    if not text:
        raise ScopeError(f"{field} must not be empty")
    return text


def validate(command: Any, output: Any, **arguments: Any) -> dict[str, Any]:
    """Validate one tool request against the closed scope.

    Returns a normalised request dict. Raises `ScopeError` with a message that
    names the violated rule, because an agent that gets a precise refusal can
    correct itself, while one that gets a generic error retries blindly.
    """
    if not isinstance(command, str):
        raise ScopeError(f"command must be a string id, got {type(command).__name__}")

    command_id = command.strip()
    if command_id not in ALLOWED_COMMANDS:
        # The refusal lists the legal ids. That is safe to disclose: the ids are
        # this module's own public vocabulary, not a secret, and an agent that
        # cannot enumerate them is an agent that cannot use the tool at all.
        raise ScopeError(
            f"command {command_id!r} is not in the allowlist. "
            f"Allowed ids: {sorted(ALLOWED_COMMANDS)}"
        )

    spec = ALLOWED_COMMANDS[command_id]

    if not isinstance(output, str):
        raise ScopeError(f"output must be a string, got {type(output).__name__}")
    size = len(output.encode("utf-8", errors="replace"))
    if size > MAX_OUTPUT_BYTES:
        raise ScopeError(
            f"output is {size} bytes, above the {MAX_OUTPUT_BYTES}-byte cap. "
            "Trim the device output to the relevant command's result."
        )

    known = set(spec["required"]) | set(spec["optional"])
    unexpected = sorted(set(arguments) - known)
    if unexpected:
        # Rejecting unknown arguments matters: silently dropping them would let
        # an agent believe it constrained something it did not.
        raise ScopeError(
            f"command {command_id!r} does not accept argument(s) {unexpected}. "
            f"Accepted: {sorted(known)}"
        )

    missing = [name for name in spec["required"] if arguments.get(name) in (None, "")]
    if missing:
        raise ScopeError(
            f"command {command_id!r} requires argument(s) {missing}. "
            f"See 'command' in the allowlist for what it checks."
        )

    resolved = {name: _require_text(arguments[name], name) for name in sorted(known)}
    return {
        "command_id": command_id,
        "command": spec["command"],
        "platform": spec["platform"],
        "summary": spec["summary"],
        "output": output,
        "arguments": resolved,
    }
