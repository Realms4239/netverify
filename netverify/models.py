"""Result types for every netverify operation.

These are the library's output contract. They are plain dataclasses rather than
pydantic models so that `netverify` keeps its zero-dependency guarantee: the
core must import on a bare Python 3.11 with nothing installed, because that is
what lets the test suite, the eval gate, and the whole verification core run
offline. The MCP layer converts them to JSON Schema on top.

`Verdict` is deliberately one shape for every command, so a caller can branch on
`ok` without knowing which check produced it. The one subtlety is
`input_error`: a malformed payload is not a network fault, and an agent that
conflates the two will report a broken router that is actually fine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Outcome(StrEnum):
    """Why a check produced the result it did.

    Split deliberately: `FAIL` means the network is unhealthy and `INPUT_ERROR`
    means the text could not be interpreted. Collapsing these into a boolean is
    how a tool ends up telling an operator their router is down when the real
    problem is a truncated paste.

    There is deliberately no `REFUSED` member. A refusal - unknown command,
    missing argument, oversize input - raises `ScopeError` instead of returning
    a `Verdict`, because a refusal is not a statement about the network and
    putting it in this enum would invite a caller to read it as one. Callers
    catch `ValueError` for refusals and branch on `ok` for everything else.
    """

    PASS = "pass"
    FAIL = "fail"
    INPUT_ERROR = "input_error"


@dataclass(frozen=True)
class Check:
    """One named assertion and its result."""

    name: str
    ok: bool
    reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "reasons": list(self.reasons)}


@dataclass(frozen=True)
class Verdict:
    """The library's primary return type.

    `ok` is the single field a caller should branch on. `outcome` exists for
    callers that need to tell a network fault from a bad input.
    """

    ok: bool
    outcome: Outcome
    command_id: str
    command: str
    platform: str
    check: str
    observed: str
    reasons: tuple[str, ...] = ()
    arguments: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "outcome": self.outcome.value,
            "command_id": self.command_id,
            "command": self.command,
            "platform": self.platform,
            "check": self.check,
            "observed": self.observed,
            "reasons": list(self.reasons),
            "arguments": dict(self.arguments),
        }


@dataclass(frozen=True)
class Finding:
    """One thing worth flagging in untrusted text.

    Used by both the secret redactor and the injection scanner, because from the
    caller's point of view they are the same shape: something in the text that
    must not be passed through verbatim.
    """

    kind: str
    severity: str
    detail: str
    offset: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "detail": self.detail,
            "offset": self.offset,
        }


@dataclass(frozen=True)
class SanitizeReport:
    """What sanitising a block of untrusted text found and did to it.

    `safe_text` is the text to actually use. `text` is deliberately NOT
    included: a sanitizer that returns both invites callers to use the wrong
    one.
    """

    safe_text: str
    findings: tuple[Finding, ...] = ()
    truncated: bool = False

    @property
    def clean(self) -> bool:
        return not self.findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "safe_text": self.safe_text,
            "findings": [f.to_dict() for f in self.findings],
            "truncated": self.truncated,
            "clean": self.clean,
        }
