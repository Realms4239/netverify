# ---------------------------------------------------------------------------
# VENDORED FILE - DO NOT EDIT BY HAND.
#
# Source:  https://github.com/Realms4239/isp-network-as-code
# Path:    pyats/parsers.py
# Commit:  71d3398207088ca67a15ddd3132cedfed81bd678
# Reason:  Project F1 wraps the flagship's *tested* pure parsing functions
#          rather than reimplementing them. The upstream module is not a
#          distributable package (no pyproject package config, no release),
#          so it cannot be pip-installed as a dependency.
#
# This copy is byte-identical to upstream below this header. That is enforced:
#   python scripts/check_upstream_parity.py
# fails the build if the pinned upstream changes, so a silent divergence is
# impossible. The header lives outside the compared region, which is every
# line from the module docstring onward.
#
# Upstream carries no LICENSE file. It is vendored here from the same author's
# own public repository. If the flagship ever adds a license, this vendored
# copy inherits it and the header above must be updated to say so.
# ---------------------------------------------------------------------------


"""Pure parsers for the pyATS assertions in test_network.py.

Every function here takes device *output text* and returns a verdict. None of
them touch a device, a testbed, or the network, which is what makes the
assertions in test_network.py testable offline. test_network.py calls these and
only translates a failure into an aetest assertion message.

Why this module exists: the assertions were previously written inline against
`dev.execute(...)`, so nothing about them could be verified without a live
Containerlab. Real defects were found that way (a wrong FRR JSON path, a loop
variable bound to the wrong value); tests/test_pyats_parsers.py pins them.

CLI output is treated as text, never parsed with Genie parsers: SR Linux and
FRR are not Genie-supported platforms, so a Genie parser would silently return
empty structures. Every regex is therefore anchored on the vendor's documented
column format and tolerant of surrounding whitespace.
"""

import json
import re

# --- SR Linux -------------------------------------------------------------


# `show interface brief` renders a table whose Interface / Admin / Oper
# columns contain e.g. "| ethernet-1/1 | enable | up |".
def srl_interface_is_up(output: str, interface: str) -> bool:
    """True when `interface` is administratively enabled and operationally up."""
    pattern = (
        rf"\|\s*{re.escape(interface)}(?:\.\d+)?\s*\|\s*"
        r"enable\s*\|\s*(?:up|up\s*\S*)\s*\|"
    )
    return bool(re.search(pattern, output, re.IGNORECASE))


# `show network-instance default protocols ospf neighbor` renders rows like
#   | ethernet-1/1.0 | 10.1.12.2 | full | ... |
# followed by a "Bad Neighbors : 0" summary line.
def srl_ospf_neighbor_is_full(output: str, neighbor_router_id: str) -> bool:
    """True when the neighbour reached `full` and nothing is stuck in ExStart."""
    row = rf"\|\s*ethernet-1/1\.0\s*\|\s*{re.escape(neighbor_router_id)}\s*\|\s*full\s*\|"
    if not re.search(row, output, re.IGNORECASE):
        return False
    return bool(re.search(r"Bad\s*Neighbors\s*:\s*0", output, re.IGNORECASE))


# `show ... bgp neighbor <ip> detail` renders "Peer : <ip>, remote AS : <as>,"
# The establishment wording varies across SR Linux releases, so accept the
# prose form and the "BGP state : Established" form rather than pinning one.
_SRL_BGP_ESTABLISHED = (
    r"session-state\s+is\s+established"
    r"|bgp\s+state\s*:\s*established"
    r"|peer\s+state\s*:\s*established"
)


def srl_bgp_peer_established(output: str, peer_ip: str, remote_as: str) -> bool:
    """True when the named peer is present, has the expected AS, and is up."""
    peer_line = (
        rf"Peer\s*:\s*{re.escape(peer_ip)}\s*,\s*remote\s*AS\s*:\s*{re.escape(remote_as)}\s*[,;]"
    )
    if not re.search(peer_line, output, re.IGNORECASE):
        return False
    return bool(re.search(_SRL_BGP_ESTABLISHED, output, re.IGNORECASE))


# --- FRRouting ------------------------------------------------------------

# `show ip bgp summary json` nests peers under an address-family block:
#   {"ipv4Unicast": {"peers": {"10.1.13.1": {...}}}}
#
# Some builds return the peer map at the top level instead, so both layouts are
# accepted. The previous code read only the top level, so a perfectly healthy
# lab reported an empty peer set and the assertion failed for the wrong reason.
def frr_bgp_peers(summary_text: str) -> dict:
    """Return the FRR BGP peer map, tolerating the address-family nesting."""
    try:
        payload = json.loads(summary_text)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"FRR did not return valid BGP summary JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise AssertionError(
            f"FRR BGP summary JSON should be an object, got {type(payload).__name__}"
        )
    if isinstance(payload.get("peers"), dict):
        return payload["peers"]
    for afi in ("ipv4Unicast", "ipv4Multicast", "ipv6Unicast", "ipv4"):
        block = payload.get(afi)
        if isinstance(block, dict) and isinstance(block.get("peers"), dict):
            return block["peers"]
    # An absent peer map is a legitimate reading: BGP simply has no neighbours.
    # Callers assert on emptiness, so return {} rather than raising.
    return {}


def frr_peer_is_healthy(peer: dict) -> tuple:
    """Return (ok, reasons) for one FRR BGP peer entry."""
    reasons = []
    if peer.get("state") != "Established":
        reasons.append(f"state is {peer.get('state')!r}, expected 'Established'")
    for key in ("pfxRcd", "pfxSnt"):
        try:
            value = int(peer.get(key, 0))
        except (TypeError, ValueError):
            value = 0
        if value <= 0:
            reasons.append(f"{key} is {peer.get(key)!r}, expected a nonzero prefix count")
    return (not reasons, reasons)


# --- routes and reachability ---------------------------------------------


def srl_route_is_installed(output: str, prefix: str) -> tuple:
    """Return (ok, reasons) for `show ... prefix <prefix> detail` output.

    Why this is not a substring test. The command line itself contains the
    prefix, and SR Linux echoes the query back before the table. So
    `prefix in output` is true for a prefix that has NO route installed, which
    makes the assertion unable to fail. The FRR path above already learned this
    and requires a real route entry; this is the same reasoning for the
    vendor-CLI side.

    A real answer contains a table row: the prefix followed by a next hop, or
    the word `active`/`resolved` in the entry. An empty table renders as
    "No entries found" or a header with no data rows.

    Returns (ok, reasons) so the caller can report what was actually seen.
    """
    if not output.strip():
        return (False, ["device returned no output"])

    if re.search(r"no\s+(?:entries|routes|matches)\s+found", output, re.IGNORECASE):
        return (False, ["device reported no entries found"])

    # Work line by line. A table row starts (after optional decoration) with
    # the prefix and carries a next hop or an explicit active/resolved marker.
    # Requiring that marker is what separates a real route row from the echoed
    # command line and the header row, both of which contain the prefix.
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("|"):
            stripped = stripped[1:].strip()
        if not stripped.startswith(prefix):
            continue
        remainder = stripped[len(prefix):]
        if re.search(r"\b(?:\d+\.\d+\.\d+\.\d+|active|resolved)\b", remainder, re.IGNORECASE):
            return (True, [])

    head = " ".join(output.split())[:120]
    return (False, [f"no route row for {prefix} (saw: {head!r})"])


def ping_succeeded(output: str) -> bool:
    """True when a ping shows 3 received or 0% loss.

    SR Linux prints a "3 received" style summary while the FRR container's
    busybox ping prints "0% packet loss". Accept either so one helper serves
    both node families.

    The loss percentage is matched with a leading boundary that is not a digit:
    without it, "0% packet loss" also matches inside "100% packet loss", which
    would report a total ping failure as a success. An explicit 100% loss is
    checked first and always fails.
    """
    if re.search(r"100\s*%\s*(?:packet\s*)?loss", output, re.IGNORECASE):
        return False
    if re.search(r"\b3\s+received\b", output, re.IGNORECASE):
        return True
    # (?<!\d) prevents matching the "0%" tail of "100%".
    return bool(re.search(r"(?<!\d)0\s*%\s*(?:packet\s*)?loss", output, re.IGNORECASE))
