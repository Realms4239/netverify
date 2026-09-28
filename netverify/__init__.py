"""netverify - verify ISP backbone device output, safely, with no credentials.

The product is this library. The MCP server in `server/` is a thin adapter over
it, and everything here works with no MCP client, no network, and no
third-party packages.

    >>> from netverify import verify
    >>> v = verify("srl_interface_brief", output_text, interface="ethernet-1/1")
    >>> v.ok, v.outcome.value
    (True, 'pass')

Three properties are the reason to use this rather than a regex:

1. **No credentials, no sockets.** Nothing here can reach a device. The
   verification core is a pure function over text you already have, so there is
   no capability to misuse.
2. **A closed allowlist.** Commands are registry ids, not CLI strings, so
   "read-only" is enforced by the input type. See `registry.py`.
3. **Untrusted text is sanitised before it is reported.** Device output is
   attacker-reachable, so a failure reason may quote a secret or an injected
   instruction. `sanitize.py` masks and neutralises both.

Adding a check means adding one `CommandSpec` to `registry.py`. Nothing else
changes.
"""

from .analysis import compare_states, synthesize_health
from .errors import RateLimited, ScopeError
from .integrity import self_check
from .limits import DEFAULT_DEADLINE_SECONDS, Deadline, DeadlineExceeded, TokenBucket
from .models import Check, Finding, Outcome, SanitizeReport, Verdict
from .registry import COMMANDS, CommandSpec, describe_all, get
from .sanitize import MAX_BYTES, sanitize, scan
from .scope import validate
from .telemetry import configure_from_env
from .telemetry import status as telemetry_status
from .verify import MAX_BATCH_ITEMS, verify, verify_many

__version__ = "1.2.0"

__all__ = [
    "COMMANDS",
    "Check",
    "CommandSpec",
    "DEFAULT_DEADLINE_SECONDS",
    "Deadline",
    "DeadlineExceeded",
    "Finding",
    "MAX_BATCH_ITEMS",
    "MAX_BYTES",
    "Outcome",
    "RateLimited",
    "SanitizeReport",
    "ScopeError",
    "TokenBucket",
    "Verdict",
    "compare_states",
    "configure_from_env",
    "describe_all",
    "get",
    "sanitize",
    "scan",
    "self_check",
    "synthesize_health",
    "telemetry_status",
    "validate",
    "verify",
    "verify_many",
]
