"""stdio framing guard: one malformed line must not wedge the session.

The SDK's stdin reader does this with a line it cannot parse:

    except Exception as exc:
        await read_stream_writer.send(exc)

The parser's *exception object* travels the same stream a message would, and
the session has no answer for it: the first malformed line on stdin - a log
line pasted into the wrong pipe, a framing bug in a driver - ends every
responsibility the server had while the process stays alive and looks
healthy. Verified against the real transport (scripts/stdio_check.py, and
the stress harness): after one garbage line, `tools/list` is never answered
again. A client cannot tell that from a wedged server, because it *is* one.

The guard sits between the wire and the SDK. It validates the JSON-RPC
framing of every line with the SDK's own validator; a line that is not a
protocol message is rewritten into a well-formed request the server refuses
with a proper error response (`_netverify/parse_error` -> -32601), so the
client is told, the wire stays protocol-clean, and the session never meets
an exception it cannot answer.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import mcp_types as types

#: The method a malformed line is rewritten to. Unknown to the server on
#: purpose: the dispatch answers it with `Method not found` (-32601), which
#: is the closest thing to "your line was not protocol" that JSON-RPC has.
PARSE_ERROR_METHOD = "_netverify/parse_error"

#: The envelope every request must carry on this protocol revision. Without
#: it the rewritten line would be refused before dispatch, which is still an
#: answer - but a dispatch-level refusal names the method, which reads better.
_META = {
    "_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {
            "name": "netverify-framing-guard",
            "version": "1.0.0",
        },
        "io.modelcontextprotocol/clientCapabilities": {},
    }
}


async def framing_guard(inner: Any) -> AsyncIterator[str]:
    """Yield only protocol-valid lines from `inner`; rewrite the rest.

    `inner` is any text stream yielding newline-terminated lines (the
    SDK wraps exactly such a stream when it owns stdin). Valid JSON-RPC
    passes through untouched - the SDK re-validates and dispatches. A blank
    line is dropped (the protocol is line-delimited JSON; an empty line
    carries no id to answer). Anything else is rewritten as a well-formed
    request the server refuses with a proper error response.
    """
    while True:
        line = await inner.readline()
        if not line:
            return
        if not line.strip():
            continue
        try:
            types.jsonrpc_message_adapter.validate_json(line, by_name=False)
        except Exception:
            # Not protocol. Answer it (so the client is told), then drop it -
            # the one thing it must never do is reach the session as an
            # exception, because an exception gets silence.
            yield (
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": -1,
                        "method": PARSE_ERROR_METHOD,
                        "params": dict(_META),
                    }
                )
                + "\n"
            )
            continue
        yield line
