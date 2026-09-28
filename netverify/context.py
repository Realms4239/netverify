"""Ambient request identity, for correlating work with the call that asked for it.

The problem: an agent turn produces dozens of tool calls, and when something goes
wrong the only useful question is "which of those calls did this?". Without a
correlation id, an audit log answers "a verify failed" but not "this verify,
during that turn".

The constraint: the id originates in the MCP layer (`ServerRequestContext.request_id`)
but is needed deep in the library, where nothing should know about MCP. Threading
it through every function signature would put a protocol concern into the
library's interface, which is exactly the coupling this project avoids.

So it travels in a `ContextVar`. That is the standard answer for exactly this
problem: it is task-local, it propagates into nested calls for free, and it
needs no signature change. It is also standard library, so `netverify` keeps its
zero-dependency guarantee - a `contextvars` import cannot break that.

The alternative, a `Context` parameter on every tool, was rejected: it would
make the tool functions unimportable without the SDK installed, which is the
property that lets the whole library be tested offline.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Any

#: The JSON-RPC id of the request currently being served, as a string, or None
#: when there is no enclosing request (a library call from a REPL, a test, a
#: batch run). Stringified because JSON-RPC ids may be int or str and an audit
#: log that mixes the two types is harder to grep.
_request_id: ContextVar[str | None] = ContextVar("netverify_request_id", default=None)


def current_request_id() -> str | None:
    """The id of the request in scope, or None outside a request."""
    return _request_id.get()


@contextmanager
def bind_request_id(request_id: Any) -> Iterator[str | None]:
    """Bind `request_id` for the duration of the block.

    Restores the previous value on exit, including when the body raises. That
    matters more than it looks: the server is long-lived, so a leaked id would
    silently mislabel every later call as belonging to an earlier request -
    and a wrong correlation id is worse than none, because it looks trustworthy.

    `None` is bound explicitly rather than skipped, so a nested call cannot
    inherit an outer id it should not have.
    """
    token: Token[str | None] = _request_id.set(None if request_id is None else str(request_id))
    try:
        yield _request_id.get()
    finally:
        _request_id.reset(token)
