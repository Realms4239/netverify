"""The command registry: one place to add a verification check.

This module is the seam that makes the library expandable. Before it existed,
adding a check meant editing two modules in lockstep - the allowlist and a
handler - and forgetting the second produced a command that was advertised but
unimplemented, or implemented but unreachable. Now a check is a single
`CommandSpec`, and the tool surface, the contract resource, the allowlist, and
the verifier all read from the same list.

Two properties are enforced by construction rather than by review:

- **Mutually exclusive verbs.** A test walks every command's text and asserts
  no mutating verb appears. A new command cannot silently become a write.
- **Pure checkers.** A checker receives the output text plus its declared
  arguments and returns a `Check`. It cannot open a socket or touch a device,
  because nothing it is given would let it. Least privilege here is a property
  of the type signature, not of a code review.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .models import Check
from .parsers import upstream

#: Verbs that would change device state. None may appear in a command's `id`
#: or `command` string. Enforced by a test, not by convention.
#:
#: These are checked against the CLI text only, never against `summary`. A
#: summary is prose and legitimately contains words like "installed" ("the route
#: is genuinely installed") and "clear" ("unambiguous"), so scanning prose
#: produces false positives that train people to ignore the guard. The CLI
#: string is the part that would actually be executed, so that is the part that
#: has to be clean.
MUTATING_VERBS: tuple[str, ...] = (
    "configure",
    "delete",
    "commit",
    "set /",
    "write",
    "reload",
    "reboot",
    "clear counters",
    "reset",
    "install",
    "copy running-config",
    "start",
    "stop",
    "rollback",
    "write memory",
    "shutdown",
    "no shutdown",
)


#: A dotted quad with each octet in 0-255, written out rather than left to a
#: numeric range check, because a regex cannot compare magnitudes and a
#: post-hoc `int()` check would have to re-parse what the pattern just matched.
#:
#: This exists because a shape check alone is not a validity check. `\d{1,3}`
#: accepts `999.1.1.1` and `10.1.12.256`; both were then reported as a failed
#: OSPF adjacency on a backbone that was healthy, which escalated through
#: `synthesize_health` to `status=unhealthy`. A mistyped octet is a refusal, not
#: a network fault.
_IPV4 = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}"


#: Per-argument range checks that a regex cannot express, keyed by field.
#:
#: Each takes the already shape-validated text and returns an error message, or
#: `None` when the value is in range. Kept separate from `ARGUMENT_PATTERNS`
#: because a pattern answers "is this shaped like an address" and this answers
#: "is this a possible address" - different questions, and only the first was
#: being asked.
#:
#: The bounds are the protocol's, not arbitrary: a prefix length is 0-32 for
#: IPv4, and a 4-byte ASN tops out at 2^32 - 1.
def _mask_in_range(text: str) -> str | None:
    mask = int(text.rsplit("/", 1)[1])
    if mask > 32:
        return f"an IPv4 prefix length is 0-32, not {mask}"
    return None


def _as_in_range(text: str) -> str | None:
    value = int(text)
    if value > 4294967295:
        return f"a 4-byte ASN is at most 4294967295, not {value}"
    return None


ARGUMENT_RANGES: dict[str, Any] = {
    "prefix": _mask_in_range,
    "remote_as": _as_in_range,
}


def _verb_patterns() -> tuple[tuple[str, re.Pattern[str]], ...]:
    """Compile `MUTATING_VERBS` into word-boundary matchers.

    Word boundaries are the whole point. A bare substring match makes
    `install` fire on "installed" and `save` fire on "saves", and a guard that
    cries wolf on correct code is a guard people learn to ignore. Multi-word
    entries like `set /` keep their spacing via a flexible whitespace class.
    """
    compiled = []
    for verb in MUTATING_VERBS:
        parts = [re.escape(part) for part in verb.split()]
        body = r"\s+".join(parts)
        compiled.append((verb, re.compile(rf"(?<![a-z0-9]){body}(?![a-z0-9])")))
    return tuple(compiled)


_MUTATING_PATTERNS = _verb_patterns()


def mutating_verbs_in(text: str) -> list[str]:
    """Return the mutating verbs present in `text`.

    One implementation, so the test, a future lint rule, and a reader checking
    the published contract all agree on what the guard catches.
    """
    lowered = text.lower()
    return [verb for verb, pattern in _MUTATING_PATTERNS if pattern.search(lowered)]


def is_read_only(cli_text: str) -> bool:
    """True when `cli_text` contains no verb that would change device state.

    Pass only the id and the CLI command. Do not pass a summary: a summary is
    prose and legitimately says a route is "installed", and scanning prose
    produces false positives that undermine the guard.
    """
    return not mutating_verbs_in(cli_text)


#: A checker gets output text plus its declared arguments and returns a Check.
#: Deliberately narrow: there is no client, no device handle, and no credential,
#: so a checker has no capability to misuse.
Checker = Callable[..., Check]


#: Per-argument validation patterns.
#:
#: A closed allowlist of command ids is not enough on its own. The command is
#: fixed, but its *arguments* were previously any string, and they are
#: interpolated into the verdict's `check` and `reasons` fields. A caller could
#: therefore pass `prefix="10.0.0.2/32\nFAKE: link is healthy"` and inject a
#: forged line into a field an agent may read as a separate finding. The secret
#: redaction caught the credential case, but nothing stopped the newline.
#:
#: So arguments are now typed. These are deliberately strict: they accept what a
#: real device reports and nothing else, and a refusal names the expected shape
#: so the model can correct itself in one step.
ARGUMENT_PATTERNS: dict[str, re.Pattern[str]] = {
    # Interface names across SR Linux: ethernet-1/1, ethernet-1/1.0, system0,
    # irb0, xe-0/0/0. Letters, digits, and a few separators - no whitespace, no
    # newlines, no quotes.
    "interface": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$"),
    # A dotted-quad router ID or loopback. Octets are range-checked, not merely
    # counted: `\d{1,3}` alone accepts `999.1.1.1` and `10.1.12.256`, and an
    # impossible address produced a confident `fail` on a healthy backbone.
    "neighbor_router_id": re.compile(rf"^{_IPV4}$"),
    "peer_ip": re.compile(rf"^{_IPV4}$"),
    # A 32-bit ASN in either plain or 4-byte notation, or the reserved ASN.
    # The digit count is a shape check only; the range is enforced by
    # `ARGUMENT_RANGES` below.
    "remote_as": re.compile(r"^(?:0|65535|[1-9]\d{0,9})$"),
    # IPv4 CIDR. Rejects IPv6 and anything with trailing text, which is what
    # would otherwise smuggle a newline into the reason string. The mask is
    # range-checked separately: `\d{1,2}` accepts `/33` and `/99`.
    "prefix": re.compile(rf"^{_IPV4}/\d{{1,2}}$"),
}


@dataclass(frozen=True)
class CommandSpec:
    """Everything the library knows about one verifiable command.

    `summary` is what an agent reads to decide whether to call, so it says what
    is checked and not what the tool does - the tool description covers that.
    """

    id: str
    command: str
    platform: str
    summary: str
    required: tuple[str, ...]
    optional: tuple[str, ...]
    check: Checker
    #: MCP annotation mirror. Read-only and idempotent hold for every command
    #: here by construction; `open_world` is false because the tool never
    #: contacts anything. Kept as data so the MCP layer cannot hardcode
    #: per-tool behaviour it might forget to update.
    open_world: bool = False

    @property
    def argument_names(self) -> frozenset[str]:
        return frozenset(self.required) | frozenset(self.optional)

    def describe(self) -> dict[str, Any]:
        """Machine-readable form, used by the contract resource and the docs."""
        return {
            "id": self.id,
            "command": self.command,
            "platform": self.platform,
            "summary": self.summary,
            "required_arguments": list(self.required),
            "optional_arguments": list(self.optional),
            "read_only": True,
            "open_world": self.open_world,
        }


def _redact(text: str, limit: int = 200) -> str:
    """Shorthand used by the checkers below.

    Reasons quote device output, and device output can contain a credential, so
    every reason goes through the sanitizer before it leaves the library. A
    checker that forgets is caught by the test asserting no reason in the whole
    corpus contains a canary secret.
    """
    from .sanitize import sanitize

    return sanitize(text, max_bytes=limit * 4).safe_text[:limit]


def _absent(name: str, subject: str) -> Check:
    """The capture did not contain the thing that was asked about.

    The distinction this exists to draw is the mirror image of the one the README
    calls most dangerous. That one is a verifier answering "healthy" about a
    router with no sessions. This is a verifier answering "down" about an
    interface the tool never saw - which is what happened, and it is an ordinary
    mistake to make: an operator pastes the slice of `show interface brief` that
    scrolled past, the interface they care about is above it, and the tool
    reports a network fault on a healthy link.

    The upstream parsers return a bare `bool`, so "not in the text" and "in the
    text and down" are indistinguishable to them - and they are *vendored*,
    pinned byte-identical to upstream by the parity gate, so the classification
    has to happen here, in the adapter that owns the meaning.

    `verify` maps any reason containing "input error" to `Outcome.INPUT_ERROR`, so
    the label is the contract rather than the exception type.
    """
    return Check(
        name=name,
        ok=False,
        reasons=(
            f"input error, not a network fault: this capture contains no {subject}, "
            f"so there is nothing to judge. Re-capture the command output that "
            f"includes it.",
        ),
    )


def _mentions(output: str, needle: str) -> bool:
    """Whether `output` mentions `needle` at all, as a whole token.

    Deliberately loose. This is an *absence* check, so a false positive is safe -
    the checker falls through to its real answer - while a false negative turns a
    readable capture into "not a network fault", which is the failure this change
    is about. So it errs towards "present".
    """
    return bool(re.search(rf"\b{re.escape(needle)}\b", output, re.IGNORECASE))


def _check_interface(output: str, interface: str) -> Check:
    name = f"interface {interface} is admin-enabled and oper-up"
    ok = upstream.srl_interface_is_up(output, interface)
    if ok:
        return Check(name=name, ok=True, reasons=())
    if not _mentions(output, interface):
        return _absent(name, f"row for interface {interface}")
    return Check(
        name=name,
        ok=False,
        reasons=(f"interface {interface} is not admin-enabled and up",),
    )


def _check_ospf(output: str, neighbor_router_id: str) -> Check:
    name = f"OSPF neighbour {neighbor_router_id} is full with zero bad neighbours"
    ok = upstream.srl_ospf_neighbor_is_full(output, neighbor_router_id)
    if ok:
        return Check(name=name, ok=True, reasons=())
    if not _mentions(output, neighbor_router_id):
        return _absent(name, f"row for neighbour {neighbor_router_id}")
    return Check(
        name=name,
        ok=False,
        reasons=(
            f"neighbour {neighbor_router_id} did not reach full with no bad "
            "neighbours; it may be stuck mid-handshake",
        ),
    )


def _check_bgp_neighbor(output: str, peer_ip: str, remote_as: str) -> Check:
    name = f"BGP peer {peer_ip} is established with remote AS {remote_as}"
    ok = upstream.srl_bgp_peer_established(output, peer_ip, remote_as)
    if ok:
        return Check(name=name, ok=True, reasons=())
    if not _mentions(output, peer_ip):
        return _absent(name, f"entry for peer {peer_ip}")
    return Check(
        name=name,
        ok=False,
        reasons=(
            f"peer {peer_ip} is not established with remote AS {remote_as}; "
            "check the session state and that the expected AS is configured",
        ),
    )


def _check_route(output: str, prefix: str) -> Check:
    name = f"route {prefix} is installed"
    ok, reasons = upstream.srl_route_is_installed(output, prefix)
    if ok:
        return Check(name=name, ok=True, reasons=())
    if not _mentions(output, prefix):
        return _absent(name, f"entry for prefix {prefix}")
    return Check(
        name=name,
        ok=False,
        # Upstream already explains what it saw. Redacted because that text
        # quotes device output.
        reasons=tuple(_redact(r) for r in reasons),
    )


def _check_ping(output: str) -> Check:
    """Ping has no subject to look for, so presence means "is this ping output?".

    `ping_succeeded` is a bare bool over text that may be anything at all, so an
    empty capture and a 100% loss both answer False. The first is a paste
    mistake; the second is a network fault, and reporting the first as the second
    pages somebody about a device that answers.
    """
    name = "ping reached the far end with no total loss"
    ok = upstream.ping_succeeded(output)
    if ok:
        return Check(name=name, ok=True, reasons=())
    if not re.search(r"packets transmitted", output, re.IGNORECASE):
        return _absent(name, "ping output (no 'packets transmitted' summary line)")
    return Check(
        name=name,
        ok=False,
        reasons=("no successful reply was recorded; total or partial loss",),
    )


def _check_frr_bgp_summary(output: str) -> Check:
    """Aggregate FRR peer health.

    An empty peer map is reported as a failure on purpose. Upstream
    deliberately returns `{}` for "no neighbours" because its callers assert on
    emptiness, but a verifier that answers "healthy" about a router with zero
    BGP sessions is the most dangerous possible answer. The conservative
    direction wins.
    """
    try:
        peers = upstream.frr_bgp_peers(output)
    except AssertionError as exc:
        return Check(
            name="FRR BGP peers are established with nonzero prefix counts",
            ok=False,
            # Labelled as an input error so the caller reports a bad capture
            # rather than a broken router.
            reasons=(f"input error, not a network fault: {_redact(str(exc))}",),
        )

    if not peers:
        return Check(
            name="FRR BGP peers are established with nonzero prefix counts",
            ok=False,
            reasons=(
                "no BGP peers present. If this router is expected to peer, the "
                "session is down; if it is not, this command was run against the "
                "wrong node.",
            ),
        )

    unhealthy: list[str] = []
    for peer_ip, peer in sorted(peers.items()):
        peer_ok, peer_reasons = upstream.frr_peer_is_healthy(peer)
        if not peer_ok:
            unhealthy.append(f"peer {peer_ip}: " + "; ".join(_redact(r) for r in peer_reasons))
    return Check(
        name="FRR BGP peers are established with nonzero prefix counts",
        ok=not unhealthy,
        reasons=tuple(unhealthy),
    )


#: The registry. Stable and alphabetical by id, because the MCP specification
#: asks servers to return tools deterministically so clients can cache the list
#: and keep prompt-cache hit rates up.
COMMANDS: tuple[CommandSpec, ...] = (
    CommandSpec(
        id="frr_bgp_summary",
        command="show ip bgp summary json",
        platform="frr",
        summary="Whether every BGP peer is Established with nonzero prefix counts.",
        required=(),
        optional=(),
        check=_check_frr_bgp_summary,
    ),
    CommandSpec(
        id="ping",
        command="ping <host> count 3",
        platform="any",
        summary="Whether the far end replied with no total loss.",
        required=(),
        optional=(),
        check=_check_ping,
    ),
    CommandSpec(
        id="srl_bgp_neighbor_detail",
        command="show ... bgp neighbor <ip> detail",
        platform="srl",
        summary="Whether one named BGP peer is Established with the expected AS.",
        required=("peer_ip", "remote_as"),
        optional=(),
        check=_check_bgp_neighbor,
    ),
    CommandSpec(
        id="srl_interface_brief",
        command="show interface brief",
        platform="srl",
        summary="Whether one interface is administratively enabled and up.",
        required=("interface",),
        optional=(),
        check=_check_interface,
    ),
    CommandSpec(
        id="srl_ospf_neighbor",
        command="show network-instance default protocols ospf neighbor",
        platform="srl",
        summary=("Whether one OSPF neighbour reached full adjacency with no bad neighbours."),
        required=("neighbor_router_id",),
        optional=(),
        check=_check_ospf,
    ),
    CommandSpec(
        id="srl_route_detail",
        command="show ... route-table ipv4-unicast prefix <prefix> detail",
        platform="srl",
        summary=(
            "Whether a route is genuinely installed for a prefix, rather than "
            "merely echoed back by the device."
        ),
        required=("prefix",),
        optional=(),
        check=_check_route,
    ),
)

BY_ID: dict[str, CommandSpec] = {spec.id: spec for spec in COMMANDS}


def get(command_id: str) -> CommandSpec | None:
    """Return the spec for `command_id`, or None if it is not registered."""
    return BY_ID.get(command_id)


def describe_all() -> list[dict[str, Any]]:
    """Every command as a dict, for the contract resource and the docs."""
    return [spec.describe() for spec in COMMANDS]
