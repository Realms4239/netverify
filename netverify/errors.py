"""Exception types the library raises.

Kept in their own module so `scope`, `verify`, and the MCP adapter can all
import them without a circular dependency. `ScopeError` subclasses
`ValueError` deliberately: every rejection the library issues is a validation
failure, so a caller can catch one type regardless of which rule fired, and
the MCP layer converts it to a tool-execution error without special-casing.
"""

from __future__ import annotations


class ScopeError(ValueError):
    """Raised when a request violates the declared scope.

    A `ValueError` subclass so callers can treat every refusal - unknown
    command, missing argument, oversize payload - as one family.
    """


class RateLimited(ScopeError):
    """Raised when a caller exceeds the configured request budget.

    Subclasses `ScopeError` so a rate-limited call is still catchable as a
    validation failure, while remaining distinguishable: a client should back
    off rather than retry with different arguments.
    """
