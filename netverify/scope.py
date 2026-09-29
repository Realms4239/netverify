"""Input validation: the actual security boundary.

Design rule, taken from the flagship's own lesson: *the tool must be unable to
cause harm, not merely unlikely to.* Three properties give that.

1. **No device credentials exist in this process.** Nothing here opens a
   socket, shells out, or holds a credential. The server is a pure function
   over text the caller already has, so an agent cannot misuse it to change
   device state - that capability is absent, not filtered.

2. **The command set is a closed allowlist.** A caller names a command id from
   the registry, never a free-form CLI string. "Only read-only commands" is
   enforced by the type of the input rather than by a regex a prompt could talk
   its way around.

3. **Unknown arguments are refused, not dropped.** Silently ignoring an
   argument the caller believed was applied would let it think it had
   constrained something it did not.

Refusals name the rule they broke, because an agent that gets a precise reason
can correct itself, while one that gets a generic error retries blindly.
"""

from __future__ import annotations

from typing import Any

from . import registry
from .errors import (
    REASON_BAD_ARGUMENT,
    REASON_MISSING_ARGUMENT,
    REASON_NOT_IN_ALLOWLIST,
    REASON_OVERSIZE_OUTPUT,
    REASON_UNKNOWN_ARGUMENT,
    ScopeError,
)
from .sanitize import MAX_BYTES

__all__ = ["ScopeError", "validate", "MAX_BYTES"]


def _require_text(value: Any, field: str, *, command: str | None = None) -> str:
    """Coerce a field to text, rejecting the types an agent should not send.

    Three checks, in this order, and the order matters.

    1. **Control characters, on the raw value.** Whitespace, newlines and tabs
       are refused because arguments are interpolated into the verdict's
       `check` and `reasons` fields, so an argument carrying a newline lets a
       caller forge an extra line into text an agent may read as a separate
       finding. That is output injection, and secret redaction cannot stop it -
       a forged line is not a secret.

       Checked *before* stripping. Checking after meant a leading tab was
       removed by `strip()` and then accepted, while the rule printed right
       above said tabs were refused. No forged output resulted, because the
       stripped value is what gets quoted - but a control that documents one
       behaviour and implements another is exactly the defect class this project
       keeps finding. Plain spaces are still trimmed, because trailing
       whitespace in a JSON argument is a formatting habit, not an attack.

    2. **Shape**, via the registry's pattern: is this an address, an interface,
       a prefix?

    3. **Range**, via the registry's range check: is this a *possible* address?
       A shape check alone is not a validity check - a dotted quad of three
       digits per octet accepts `999.1.1.1`, and a two-digit mask accepts
       `/33` - and an impossible value used to be reported as a failed adjacency
       on a healthy backbone.

    Refusals name the rule they broke, because an agent that gets a precise
    reason can correct itself, while one that gets a generic error retries
    blindly.
    """
    if not isinstance(value, str):
        raise ScopeError(
            f"{field} must be a string, got {type(value).__name__}",
            reason=REASON_BAD_ARGUMENT,
            command=command,
        )

    # Before strip(), deliberately: see the docstring.
    if any(ch in value for ch in "\r\n\t"):
        raise ScopeError(
            f"{field} must not contain line breaks or tabs; it is quoted back in "
            f"the verdict, so a newline would forge a new line of output. Got: "
            f"{value[:40]!r}",
            reason=REASON_BAD_ARGUMENT,
            command=command,
        )

    text = value.strip()
    if not text:
        raise ScopeError(
            f"{field} must not be empty",
            reason=REASON_BAD_ARGUMENT,
            command=command,
        )

    pattern = registry.ARGUMENT_PATTERNS.get(field)
    if pattern is not None and not pattern.match(text):
        raise ScopeError(
            f"{field}={text!r} is not a valid {field.replace('_', ' ')}. "
            f"Expected something matching {pattern.pattern}.",
            reason=REASON_BAD_ARGUMENT,
            command=command,
        )

    # Only reached once the shape is right, so these can parse without guarding.
    in_range = registry.ARGUMENT_RANGES.get(field)
    if in_range is not None:
        problem = in_range(text)
        if problem is not None:
            raise ScopeError(
                f"{field}={text!r} is out of range: {problem}. "
                f"This is a bad argument, not a network fault - it has not been "
                f"checked against the device.",
                reason=REASON_BAD_ARGUMENT,
                command=command,
            )
    return text


def validate(command: Any, output: Any, **arguments: Any) -> dict[str, Any]:
    """Validate one request against the registry.

    Returns a normalised request dict. Raises `ScopeError` (a `ValueError`)
    with a message naming the violated rule.
    """
    if not isinstance(command, str):
        raise ScopeError(
            f"command must be a string id, got {type(command).__name__}",
            reason=REASON_BAD_ARGUMENT,
        )

    command_id = command.strip()
    spec = registry.get(command_id)
    if spec is None:
        # Safe to list the legal ids: they are this library's own public
        # vocabulary, and an agent that cannot enumerate them cannot use the
        # tool at all.
        raise ScopeError(
            f"command {command_id!r} is not in the allowlist. "
            f"Allowed ids: {sorted(registry.BY_ID)}",
            reason=REASON_NOT_IN_ALLOWLIST,
        )

    if not isinstance(output, str):
        raise ScopeError(
            f"output must be a string, got {type(output).__name__}",
            reason=REASON_BAD_ARGUMENT,
            command=command_id,
        )
    size = len(output.encode("utf-8", errors="replace"))
    if size > MAX_BYTES:
        raise ScopeError(
            f"output is {size} bytes, above the {MAX_BYTES}-byte cap. "
            "Trim the device output to the relevant command's result.",
            reason=REASON_OVERSIZE_OUTPUT,
            command=command_id,
        )

    known = spec.argument_names
    unexpected = sorted(set(arguments) - known)
    if unexpected:
        raise ScopeError(
            f"command {command_id!r} does not accept argument(s) {unexpected}. "
            f"Accepted: {sorted(known)}",
            reason=REASON_UNKNOWN_ARGUMENT,
            command=command_id,
        )

    missing = [name for name in spec.required if arguments.get(name) in (None, "")]
    if missing:
        raise ScopeError(
            f"command {command_id!r} requires argument(s) {missing}. It checks: {spec.summary}",
            reason=REASON_MISSING_ARGUMENT,
            command=command_id,
        )

    resolved = {
        name: _require_text(arguments[name], name, command=command_id) for name in sorted(known)
    }
    return {
        "spec": spec,
        "command_id": spec.id,
        "command": spec.command,
        "platform": spec.platform,
        "output": output,
        "arguments": resolved,
    }
