"""MCP server exposing exactly one read-only tool: `verify_network_output`.

Scope of this stage (F1) is deliberately small. The vault's own guidance is
"one tool done right beats five half-hardened", and every extra tool multiplies
attack surface faster than it adds proof. So this server publishes a single
tool, and a test asserts that it stays a single tool.

The tool is a *verifier*, not a *fetcher*. It does not connect to a device and
does not hold credentials, so there is no prompt an agent can write that turns
it into a way to touch the network. What it does is take output text a caller
already collected and return a structured verdict, using the flagship's
already-tested parsers.

`mcp` is imported lazily inside `build_server()` so that the scope and verify
layers - which hold all the actual logic and all the security properties - stay
importable and testable with no third-party dependency at all.
"""

from __future__ import annotations

from typing import Any

from . import scope
from .verify import verify

SERVER_NAME = "isp-verifier"
SERVER_VERSION = "0.1.0"

INSTRUCTIONS = """\
Read-only verification of ISP backbone device output.

Call `verify_network_output` with a `command` id from the allowlist and the raw
text of that command's output. It returns a verdict: `ok`, what was checked,
what was observed, and why any check failed.

The command ids are: srl_interface_brief, srl_ospf_neighbor,
srl_bgp_neighbor_detail, frr_bgp_summary, srl_route_detail, ping.

This server cannot change device state and holds no device credentials, so it
is safe to call freely. It does not fetch output: collect that yourself and
pass it in. A result with `ok: false` means the network failed a check; a
rejected call means the request was out of scope or malformed. Those are
different problems - do not report a scope error as a device fault.\
"""


def verify_network_output(
    command: str,
    output: str,
    interface: str | None = None,
    neighbor_router_id: str | None = None,
    peer_ip: str | None = None,
    remote_as: str | None = None,
    prefix: str | None = None,
) -> dict[str, Any]:
    """Verify one read-only device command's output. Returns a verdict.

    Args:
        command: Allowlisted command id, e.g. `srl_interface_brief`.
        output: The raw text that command printed on the device.
        interface: Interface name, for `srl_interface_brief`.
        neighbor_router_id: OSPF router ID, for `srl_ospf_neighbor`.
        peer_ip: BGP peer address, for `srl_bgp_neighbor_detail`.
        remote_as: Expected remote AS, for `srl_bgp_neighbor_detail`.
        prefix: IPv4 prefix, for `srl_route_detail`.

    Returns:
        A dict with `ok`, `check`, `observed`, and `reasons`.

    Raises:
        ValueError: If the command id is not allowlisted, an argument is
            missing, an argument is not valid for that command, or the output
            is over the size cap.

    Note on unknown keyword arguments: this signature is deliberately explicit
    and closed, because it is what produces a correct MCP tool schema. A
    `**kwargs` catch-all was tried and rejected - FastMCP folds it into the
    schema as a property literally named `kwargs` and marks it *required*,
    which would force every client to send it. So an unrecognised keyword is
    rejected by Python as a TypeError at the call boundary instead, before this
    body runs. That is acceptable precisely because it is unreachable through
    MCP: a client cannot send a parameter the schema does not declare. For
    library callers, the invariant worth testing is the one below - an argument
    that *is* declared but is not valid for the chosen command - which is what
    `scope.validate` refuses.
    """
    arguments = {
        name: value
        for name, value in (
            ("interface", interface),
            ("neighbor_router_id", neighbor_router_id),
            ("peer_ip", peer_ip),
            ("remote_as", remote_as),
            ("prefix", prefix),
        )
        if value is not None
    }
    # ScopeError is a ValueError, so a caller sees one exception family for
    # every rejected request regardless of which rule rejected it.
    request = scope.validate(command, output, **arguments)
    return verify(request)


def build_server() -> Any:
    """Construct the FastMCP server with the single tool registered."""
    from mcp.server.fastmcp import FastMCP

    server = FastMCP(name=SERVER_NAME, instructions=INSTRUCTIONS)
    server.add_tool(
        verify_network_output,
        name="verify_network_output",
        description=(
            "Verify raw output from one read-only ISP backbone show command. "
            "Read-only and credential-free: this cannot change device state. "
            "Returns a structured verdict with reasons."
        ),
    )
    return server


def main() -> None:
    """Serve over stdio, the transport local MCP clients spawn."""
    build_server().run()


if __name__ == "__main__":
    main()
