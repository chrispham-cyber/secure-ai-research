"""Deterministic token-bucket rate limiter (ROADMAP Phase 3, Week 12).

The excessive-agency guard: a per-session call budget (optionally refilling) that bounds how
much a future agent can do. Deterministic under an injected clock — no wall-clock, no sleep.
"""

import pytest

from secure_ai_research.agents.rate_limit import RateLimiter, RateLimitExceeded


def test_budget_without_refill_exhausts():
    rl = RateLimiter(capacity=2)  # refill_per_second defaults to 0.0 → pure budget of 2
    rl.acquire()
    rl.acquire()
    with pytest.raises(RateLimitExceeded):
        rl.acquire()


def test_zero_capacity_denies_first_call():
    with pytest.raises(RateLimitExceeded):
        RateLimiter(capacity=0).acquire()


def test_refill_with_injected_clock_restores_then_caps():
    now = [0.0]
    rl = RateLimiter(capacity=2, refill_per_second=1.0, clock=lambda: now[0])
    rl.acquire()
    rl.acquire()
    with pytest.raises(RateLimitExceeded):
        rl.acquire()  # bucket empty at t=0

    now[0] = 1.0
    rl.acquire()  # exactly one token refilled after 1s
    with pytest.raises(RateLimitExceeded):
        rl.acquire()

    now[0] = 999.0
    rl.acquire()
    rl.acquire()  # refill is capped at capacity (2), not 999 — no unbounded burst
    with pytest.raises(RateLimitExceeded):
        rl.acquire()
