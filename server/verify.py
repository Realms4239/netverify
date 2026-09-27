"""Turn one allowlisted command's output into a structured verdict.

Every check here delegates to a vendored flagship parser. The rule this module
adds is about *reporting*, not detection: a failing network is a normal result
that must be returned as data, while a malformed input is an error that must be
distinguishable from a failure.

The distinction matters for the agent on the other side of the tool call. If a
malformed FRR payload and a genuinely unhealthy peer both surfaced as
`ok: false`, the agent would report a device fault that does not exist. So
`ok` is only ever False because the *network* failed a check, and every reason
string says what was actually seen.

Nothing in this module raises for a bad verdict; it is a verifier, not a gate.
The only exception it absorbs is the upstream parsers' `AssertionError` on
malformed JSON, which is converted into a diagnosable non-ok result.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .scope import redact
from .vendor import pyats_parsers as p


def _bool_check(name: str, call: Callable[[], bool], observed: str) -> dict[str, Any]:
    """Wrap a boolean upstream parser into the common result shape."""
    ok = bool(call())
    return {
        "ok": ok,
        "check": name,
        "observed": redact(observed),
        "reasons": [] if ok else [f"{name} did not hold"],
    }


def _check_interface(request: dict[str, Any]) -> dict[str, Any]:
    interface = request["arguments"]["interface"]
    return _bool_check(
        f"interface {interface} is admin-enabled and oper-up",
        lambda: p.srl_interface_is_up(request["output"], interface),
        f"checked 'show interface brief' for {interface}",
    )


def _check_ospf(request: dict[str, Any]) -> dict[str, Any]:
    router_id = request["arguments"]["neighbor_router_id"]
    return _bool_check(
        f"OSPF neighbour {router_id} is full with zero bad neighbours",
        lambda: p.srl_ospf_neighbor_is_full(request["output"], router_id),
        f"checked OSPF neighbour detail for {router_id}",
    )


def _check_bgp_neighbor(request: dict[str, Any]) -> dict[str, Any]:
    peer_ip = request["arguments"]["peer_ip"]
    remote_as = request["arguments"]["remote_as"]
    return _bool_check(
        f"BGP peer {peer_ip} is established with remote AS {remote_as}",
        lambda: p.srl_bgp_peer_established(request["output"], peer_ip, remote_as),
        f"checked 'show ... bgp neighbor {peer_ip} detail'",
    )


def _check_route(request: dict[str, Any]) -> dict[str, Any]:
    prefix = request["arguments"]["prefix"]
    ok, reasons = p.srl_route_is_installed(request["output"], prefix)
    return {
        "ok": ok,
        "check": f"route {prefix} is installed",
        "observed": redact(f"checked route-table detail for {prefix}"),
        # Upstream already explains what it saw; redact because that text quotes
        # device output.
        "reasons": [redact(reason) for reason in reasons],
    }


def _check_ping(request: dict[str, Any]) -> dict[str, Any]:
    return _bool_check(
        "ping reached the far end with no total loss",
        lambda: p.ping_succeeded(request["output"]),
        "checked ping summary for 3 received or 0% loss",
    )


def _check_frr_bgp_summary(request: dict[str, Any]) -> dict[str, Any]:
    """Aggregate FRR peer health.

    An empty peer map is reported as *not ok* on purpose. Upstream deliberately
    returns `{}` for "no neighbours" because its callers assert on emptiness,
    but a network-state verifier that answers "healthy" about a router with
    zero BGP sessions is the most dangerous possible answer here. Reporting it
    as a failure keeps the conservative direction.
    """
    try:
        peers = p.frr_bgp_peers(request["output"])
    except AssertionError as exc:
        # Malformed JSON is an input problem, not a network fault. Say so, so
        # the agent reports a bad capture rather than a broken router.
        return {
            "ok": False,
            "check": "FRR BGP peers are established with nonzero prefix counts",
            "observed": "FRR output could not be parsed as a BGP summary",
            "reasons": [f"input error, not a network fault: {redact(str(exc))}"],
        }

    if not peers:
        return {
            "ok": False,
            "check": "FRR BGP peers are established with nonzero prefix counts",
            "observed": "FRR reported a peer map with no peers",
            "reasons": [
                "no BGP peers present. If this router is expected to peer, "
                "the session is down; if it is not expected to peer, this "
                "command was run against the wrong node."
            ],
        }

    unhealthy: list[str] = []
    for peer_ip, peer in sorted(peers.items()):
        ok, reasons = p.frr_peer_is_healthy(peer)
        if not ok:
            unhealthy.append(f"peer {peer_ip}: " + "; ".join(redact(r) for r in reasons))

    return {
        "ok": not unhealthy,
        "check": "FRR BGP peers are established with nonzero prefix counts",
        "observed": redact(f"checked {len(peers)} BGP peer(s)"),
        "reasons": unhealthy,
    }


_HANDLERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "srl_interface_brief": _check_interface,
    "srl_ospf_neighbor": _check_ospf,
    "srl_bgp_neighbor_detail": _check_bgp_neighbor,
    "frr_bgp_summary": _check_frr_bgp_summary,
    "srl_route_detail": _check_route,
    "ping": _check_ping,
}


def verify(request: dict[str, Any]) -> dict[str, Any]:
    """Run the check for a validated request and return the full result.

    The request must already have passed `scope.validate`. Re-checking that a
    handler exists keeps a typo in `_HANDLERS` from becoming a KeyError
    surfacing as an opaque tool crash.
    """
    command_id = request["command_id"]
    handler = _HANDLERS.get(command_id)
    if handler is None:
        raise KeyError(f"no handler wired for allowlisted command {command_id!r}")

    return {
        "command_id": command_id,
        "command": request["command"],
        "platform": request["platform"],
        "arguments": request["arguments"],
        **handler(request),
    }
