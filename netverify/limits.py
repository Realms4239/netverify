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
        than guessing.
        """
        if self.try_consume(cost):
            return
        self._refill()
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
