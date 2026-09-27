"""Device output fixtures modelled on real SR Linux and FRR output.

These are deliberately *not* invented strings. Each one reproduces the column
layout the vendored parsers anchor on, because a fixture that is easier to
parse than the real thing would let a broken parser pass. The `srl_route_missing`
case in particular reproduces the echoed command line, which is the exact defect
the upstream parser exists to handle.
"""

# --- SR Linux: show interface brief ----------------------------------------

SRL_INTERFACE_UP = """
+-------------------------------+-----------+------------------+
| Interface                     | Admin     | Oper             |
+-------------------------------+-----------+------------------+
| ethernet-1/1                  | enable    | up               |
| ethernet-1/1.0                | enable    | up               |
| ethernet-1/2                  | enable    | up               |
| system0                       | enable    | up               |
+-------------------------------+-----------+------------------+
"""

SRL_INTERFACE_DOWN = """
+-------------------------------+-----------+------------------+
| Interface                     | Admin     | Oper             |
+-------------------------------+-----------+------------------+
| ethernet-1/1                  | enable    | down             |
| ethernet-1/2                  | enable    | up               |
+-------------------------------+-----------+------------------+
"""

# --- SR Linux: OSPF neighbours ---------------------------------------------

SRL_OSPF_FULL = """
+-------------------------------+------------------+----------+
| Interface                     | Neighbor ID      | State    |
+-------------------------------+------------------+----------+
| ethernet-1/1.0                | 10.1.12.2        | full     |
+-------------------------------+------------------+----------+
 OSPF Instance default
    Router ID : 10.0.0.1
    Number of neighbors : 1
    Full adjacencies : 1
    Bad Neighbors : 0
"""

SRL_OSPF_NOT_FULL = """
+-------------------------------+------------------+----------+
| Interface                     | Neighbor ID      | State    |
+-------------------------------+------------------+----------+
| ethernet-1/1.0                | 10.1.12.2        | exstart  |
+-------------------------------+------------------+----------+
 OSPF Instance default
    Bad Neighbors : 1
"""

# --- SR Linux: BGP neighbour detail ---------------------------------------

SRL_BGP_ESTABLISHED = """
 BGP neighbor detail
    Peer : 10.1.13.2, remote AS : 65002, description : eBGP to FRR01
    BGP state : Established, ...
    session-state is established
"""

SRL_BGP_ACTIVE = """
 BGP neighbor detail
    Peer : 10.1.13.2, remote AS : 65002, description : eBGP to FRR01
    BGP state : Active, ...
    session-state is active
"""

# --- SR Linux: route table detail -----------------------------------------
# The device echoes the queried prefix back before the table, so the prefix
# ALWAYS appears in the output. A substring test therefore cannot fail, which is
# why the upstream check requires a real table row.

SRL_ROUTE_INSTALLED = """
{ "command": "show ... prefix 10.0.0.2/32 detail" }
+------------------------+------------------+----------+
| Prefix                | Next hop         | Attrs     |
+------------------------+------------------+----------+
| 10.0.0.2/32           | 10.1.12.2        | active    |
+------------------------+------------------+----------+
"""

SRL_ROUTE_MISSING = """
{ "command": "show ... prefix 10.0.0.2/32 detail" }
 No entries found
"""

# --- FRR: show ip bgp summary json ----------------------------------------

FRR_SUMMARY_HEALTHY = """
{
  "ipv4Unicast": {
    "peers": {
      "10.1.13.1": {
        "state": "Established",
        "pfxRcd": 4,
        "pfxSnt": 4
      }
    }
  }
}
"""

FRR_SUMMARY_UNHEALTHY = """
{
  "ipv4Unicast": {
    "peers": {
      "10.1.13.1": {
        "state": "Established",
        "pfxRcd": 0,
        "pfxSnt": 4
      }
    }
  }
}
"""

FRR_SUMMARY_EMPTY = '{ "ipv4Unicast": { "peers": {} } }'

FRR_SUMMARY_MALFORMED = "not json at all"

# --- ping ------------------------------------------------------------------

PING_OK = "3 packets transmitted, 3 received, 0% packet loss"
PING_TOTAL_LOSS = "3 packets transmitted, 0 received, 100% packet loss"

#: Device output carrying a credential, to prove reasons are redacted.
SRL_INTERFACE_UP_WITH_SECRET = SRL_INTERFACE_UP + "\n set / system information password=hunter2\n"

#: A route table plus a credential line appended, for the leak eval. The route
#: is deliberately not the one queried, so the verdict is a failure and a reason
#: is produced - which is the path that could echo the secret.
SRL_ROUTE_INSTALLED_WITH_SECRET = (
    SRL_ROUTE_INSTALLED + "\n set / system information password=hunter2\n"
)

#: OSPF reports `full` while also reporting a bad neighbour. Both states present
#: at once is the contradiction that must not be reported as healthy.
SRL_OSPF_FULL_BUT_BAD_NEIGHBOR = SRL_OSPF_FULL.replace("Bad Neighbors : 0", "Bad Neighbors : 1")
