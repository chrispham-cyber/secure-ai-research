"""Deterministic token-bucket rate limiter (ROADMAP Phase 3, Week 12).

A per-instance call budget that bounds **excessive agency**: each permitted operation consumes
a token; an empty bucket raises before any work happens. With ``refill_per_second == 0.0`` it
is a fixed budget of ``capacity`` calls; a positive refill makes it a classic token bucket.
Time comes from an injected ``clock`` (default ``time.monotonic``), so tests are fully
deterministic — no wall-clock, no sleep.

A time-windowed *network* rate limit and per-client quotas are a Phase-5 (network-exposed)
concern; this is the in-posture primitive the agent boundary uses today and the scaffold
Phase 4 wires to a real agent.
"""

from __future__ import annotations

import time
from collections.abc import Callable


class RateLimitExceeded(Exception):
    """Raised when a call is refused because the bucket lacks the requested tokens."""


class RateLimiter:
    """Token bucket: starts full at ``capacity``, refills at ``refill_per_second`` (capped)."""

    def __init__(
        self,
        capacity: int,
        refill_per_second: float = 0.0,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._capacity = float(capacity)
        self._refill_per_second = float(refill_per_second)
        self._clock = clock
        self._tokens = float(capacity)
        self._last = clock()

    def acquire(self, tokens: int = 1) -> None:
        """Consume ``tokens`` from the bucket, or raise ``RateLimitExceeded`` if it lacks them.

        Refill is proportional to elapsed time since the last call and capped at ``capacity``,
        so no amount of waiting grants a burst larger than the bucket.
        """
        now = self._clock()
        self._tokens = min(
            self._capacity, self._tokens + (now - self._last) * self._refill_per_second
        )
        self._last = now
        if self._tokens >= tokens:
            self._tokens -= tokens
        else:
            raise RateLimitExceeded
