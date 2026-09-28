"""Request budgeting: a token bucket, no dependencies, no background thread.

The MCP specification requires servers to "rate limit tool invocations". For a
server whose tools are pure functions over caller-supplied text, that is not
about protecting a database - it is about bounding the work an agent can cause
in one turn, and about refusing politely instead of degrading.

A token bucket is the right shape here rather than a fixed window: an agent
loop tends to burst (retry, re-check, summarise), and a fixed window punishes
the burst that follows a transient failure, which is exactly when you least
want a refusal. The bucket absorbs a burst and still enforces a sustained rate.

`time.monotonic` is used rather than `time.time` so that a clock adjustment,
an NTP correction, or a daylight-saving step cannot hand out free budget or
lock a caller out.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from .errors import RateLimited


class TokenBucket:
    """A monotonic token bucket.

    Args:
        capacity: maximum burst, in calls.
        refill_per_second: sustained rate. A caller that never bursts can make
            this many calls per second indefinitely.
        clock: injectable for tests. The deletion test says a real seam needs
            two adapters; there are two - the real clock and the test's fake -
            so this earns its parameter.
    """

    def __init__(
        self,
        capacity: int,
        refill_per_second: float,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if capacity < 1:
            raise ValueError("capacity must be at least 1")
        if refill_per_second <= 0:
            raise ValueError("refill_per_second must be positive")
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self._clock = clock
        self._tokens = float(capacity)
        self._updated = clock()

    def _refill(self) -> None:
        now = self._clock()
        elapsed = max(0.0, now - self._updated)
        self._updated = now
        self._tokens = min(self.capacity, self._tokens + elapsed * self.refill_per_second)

    def try_consume(self, cost: float = 1.0) -> bool:
        """Take `cost` tokens if available. Returns whether it succeeded."""
        self._refill()
        if self._tokens >= cost:
            self._tokens -= cost
            return True
        return False

    def consume(self, cost: float = 1.0) -> None:
        """Take `cost` tokens or raise `RateLimited`.

        The refusal states the wait, so a client can back off precisely rather
        than guessing - but only when a wait can actually help.

        A cost larger than `capacity` is different in kind. The balance is
        clamped to `capacity` by `_refill`, so such a deficit never closes: no
        amount of waiting makes the call succeed. The original message said
        "Retry in 0.10s" for a cost of 31 against a capacity of 30, which is
        arithmetic that cannot come true. Telling a caller to retry an
        impossible request is how a rate limiter becomes an infinite retry loop,
        which is the failure this class exists to prevent. So the two cases get
        different messages: a wait when waiting helps, and an instruction to
        split the request when it does not.
        """
        if self.try_consume(cost):
            return
        self._refill()
        if cost > self.capacity:
            raise RateLimited(
                f"request costs {cost:g} tokens, above the maximum burst of "
                f"{self.capacity}. No amount of waiting will serve it, because "
                f"the budget is capped at {self.capacity}. Split it into "
                f"several smaller calls."
            )
        deficit = cost - self._tokens
        wait = max(0.0, deficit / self.refill_per_second)
        raise RateLimited(
            f"request budget exhausted. The limit is {self.refill_per_second:g} "
            f"calls/second with a burst of {self.capacity}. Retry in "
            f"{wait:.2f}s."
        )

    @property
    def tokens(self) -> float:
        """Current balance. Exposed for the health resource and for tests."""
        self._refill()
        return self._tokens


# --- call deadline ---------------------------------------------------------

#: Default budget for a single tool call, in seconds. Comfortably above the
#: measured worst case (a full 64 KiB sanitise is ~2 ms) and far below anything a
#: user or a host would notice as a stall.
DEFAULT_DEADLINE_SECONDS = 5.0


class DeadlineExceeded(TimeoutError):
    """Raised when a call exceeded its cooperative budget.

    A `TimeoutError` subclass so a host that already treats timeouts specially
    handles it without knowing about this module.
    """


class Deadline:
    """A monotonic budget for one call.

    The MCP specification lists timeouts as a SHOULD. For a server that talks to
    a network the timeout protects a socket from hanging. netverify talks to
    nothing, so this protects against something narrower and more specific: a
    pathological input shape that makes the regexes work far longer than the
    size cap suggests.

    The size limit bounds the *input*; this bounds the *call*. Those are
    different guarantees, and this is the one a host cares about, because it is
    the one that decides whether a single tool call can stall a session.

    Deliberately **cooperative**: it measures elapsed time and the caller checks
    it between stages. It does not preempt. Preempting pure Python would mean
    either signals, which do not compose with a threaded MCP server, or
    subprocesses, which would mean passing caller-supplied text to a child
    process. Being explicit about what it does not do is more useful than
    implying a guarantee it cannot keep.
    """

    def __init__(self, seconds: float = DEFAULT_DEADLINE_SECONDS) -> None:
        if seconds <= 0:
            raise ValueError("deadline must be positive")
        self.seconds = seconds
        self.started = time.monotonic()

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started

    @property
    def remaining(self) -> float:
        return max(0.0, self.seconds - self.elapsed)

    @property
    def exceeded(self) -> bool:
        return self.remaining <= 0.0

    def check(self, stage: str) -> None:
        """Raise if the budget is gone. Named for the error message.

        The stage name earns its place: when a deadline does fire, the only
        useful question is which part of the work was slow, and "verify" alone
        does not answer it.
        """
        if self.exceeded:
            raise DeadlineExceeded(
                f"{stage} exceeded its {self.seconds:g}s budget "
                f"({self.elapsed:.2f}s elapsed). This usually means an input shape "
                "the size cap did not anticipate; please report it."
            )
