"""Exception types the library raises.

Kept in their own module so `scope`, `verify`, and the MCP adapter can all
import them without a circular dependency. `ScopeError` subclasses
`ValueError` deliberately: every rejection the library issues is a validation
failure, so a caller can catch one type regardless of which rule fired, and
the MCP layer converts it to a tool-execution error without special-casing.
"""

from __future__ import annotations

#: Stable refusal reasons for the `netverify.refused` counter. Defined here,
#: next to the exception that carries them, rather than in `telemetry.py`: this
#: module imports nothing from the package, so every other module can depend on
#: it - including the optional instrumentation, which re-exports these names
#: rather than restating them. The dependency therefore runs one way, from the
#: thing that may be absent to the thing that must always be there, and a
#: missing OpenTelemetry install can never be the reason validation fails to
#: import. Messages are human prose and change; these codes are the vocabulary
#: a dashboard groups by.
REASON_NOT_IN_ALLOWLIST = "not_in_allowlist"
REASON_UNKNOWN_ARGUMENT = "unknown_argument"
REASON_MISSING_ARGUMENT = "missing_argument"
REASON_BAD_ARGUMENT = "bad_argument"
REASON_OVERSIZE_OUTPUT = "oversize_output"
REASON_OVERSIZE_BATCH = "oversize_batch"
REASON_NON_LIST_BATCH = "non_list_batch"
REASON_RATE_LIMITED = "rate_limited"


class ScopeError(ValueError):
    """Raised when a request violates the declared scope.

    A `ValueError` subclass so callers can treat every refusal - unknown
    command, missing argument, oversize payload - as one family.

    Two optional attributes carry what a dashboard needs and prose cannot:

    - `reason` is a stable machine-readable code for the `netverify.refused`
      counter. Messages are human prose and change; dashboards cannot group by
      prose, so every raise site names one of the `REASON_*` codes above.
    - `command` is the registry id the refusal was about, once that id is known
      to be in the allowlist. It is deliberately *not* set for
      `not_in_allowlist`: there the id is whatever the caller invented, and a
      caller that mints a fresh name per request would mint a new metric series
      per request. Bounded labels are what makes a counter usable.

    Both stay optional so tests and callers can still construct a bare
    `ScopeError("...")`.
    """

    def __init__(
        self,
        message: str = "",
        *,
        reason: str | None = None,
        command: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.command = command


class RateLimited(ScopeError):
    """Raised when a caller exceeds the configured request budget.

    Subclasses `ScopeError` so a rate-limited call is still catchable as a
    validation failure, while remaining distinguishable: a client should back
    off rather than retry with different arguments.
    """
