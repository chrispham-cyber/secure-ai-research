# Phase 3 slice 4 (FINAL) — Excessive-agency guards + close the live-fetch existence side-channel

**Date:** 2026-11-19 · **Status:** design (approach chosen by Chris: Option B — guards + close the side-channel now) · **ROADMAP:** Phase 3, Week 12

## 1. Intent / why

ROADMAP Week 12: *"Excessive-agency guards: read-only tools, arg validation, rate limits."* Two of the three — read-only tools and arg validation — already shipped in Week 9 (`AgentToolset`: role bound at construction, per-arg shape validation, no payload echo, zero audit on reject). So the genuinely new work is **(a) a rate / call-budget guard** to bound how much a (future) agent can do, and **(b) closing the one tracked open security item**: the timing/egress existence side-channel on the opt-in live-fetch path, flagged at Week 10 to be closed "before any network-exposed live-fetch." Chris chose **Option B** (both, now) over deferring the side-channel (Option A) or a threat-model-only pass (Option C); this design opens with a short excessive-agency threat frame so the guards built are justified, not mechanical.

## 2. Excessive-agency threat frame (agent → service boundary; no LLM yet)

*Actors:* a future model/agent handed an `AgentToolset`; trusted application code (constructs the toolset with a verified role); `ResearchService` + the curated corpus. *Assets:* the corpus (incl. any `RESTRICTED` docs), the append-only audit log, external NVD egress (network + a possible API key), compute. *Threats and where they are handled:*

| STRIDE / agency risk | Threat | Handled |
|---|---|---|
| **E** elevation / confused deputy | model changes the principal it runs as | Week 9 — role bound at construction, no role arg |
| **T** tampering / injection | model sends malformed / hostile tool args | Week 9 — shape validation, no echo, zero audit on reject |
| **D** DoS / resource exhaustion / **excessive agency** | model issues unbounded tool calls | **this slice — rate limiter / call budget** |
| **I** information disclosure (existence oracle) | live-fetch *fires or not* reveals a `RESTRICTED` doc's presence (absent id → 1 fetch; present-but-RESTRICTED → 0 fetch; distinguishable by latency/egress even though the response is byte-identical) | **this slice — live-fetch becomes a senior-only capability** |
| egress / over-collection + corpus write-amplification | an agent drives excessive external NVD fetches; each fetch also *mutates* the corpus (indexes the fetched doc) | bounded by the rate limiter **and** by senior-only gating (fewer principals can fetch) |

**In-posture note:** a time-windowed *network* rate limit and per-client quotas are Phase-5 (network-exposed) concerns. In-posture we ship a deterministic token-bucket primitive (capacity + optional refill, **injected clock**) usable as a per-session budget — the enforceable guard today and the scaffold Phase 4 wires to a real agent. "Read-only" is nuanced: retrieval is read-only, but **live-fetch writes** (indexes fetched docs), which is exactly why it is privileged.

## 3. Goals

1. **Close the existence side-channel (I):** live-fetch-on-miss fires only for a role that can retrieve *every* PUBLIC document regardless of sensitivity — i.e. a role with no "present-but-hidden" class. Today that is `senior_analyst` (the `_RESTRICTED_ROLES`). A lower-privilege `research_analyst` never triggers a fetch, so for them an absent id and a present-but-`RESTRICTED` id are identical in **both** response (already byte-identical) **and** fetch behavior (now both zero fetches) — no timing/egress oracle. For `senior_analyst` no PUBLIC doc is ever hidden, so a `NOT_FOUND` only ever means genuinely-absent → the fetch-or-not signal carries no withheld-existence information.
2. **Excessive-agency guard (D):** a deterministic `RateLimiter` (token bucket: `capacity`, `refill_per_second`, injected `clock`) + a `RateLimitExceeded` exception; `AgentToolset` accepts an optional limiter and, when set, acquires one token **before** arg validation / delegation — on an empty bucket it raises `RateLimitExceeded` without delegating, without echoing the arg, and with **zero** audit records (same discipline as the Week-9 validation reject).
3. **Read-only surface, pinned:** document that the toolset exposes retrieval only, and pin its public tool surface with a test so a future mutating method cannot be added silently.
4. ROADMAP Week-12 line ticked; roles.md documents live-fetch as a senior-only capability and the closure invariant.

## 4. Non-goals

- **No time-windowed network rate limiting, per-IP/client quotas, or concurrency caps** — Phase 5 (network-exposed). We ship the deterministic primitive only.
- **No OIDC / real auth** — X-Role stays the Phase-5 concern.
- **No change to retrieval assembly, chunking, build_report, loaders, or the schema.** The side-channel fix is confined to the `_research` fetch gate + an authz policy helper; the guard is confined to `agents/`.
- **No LLM / no model-facing wiring** — the limiter is scaffolding; Phase 4 wires it to an agent.

## 5. Anti-goals (failure even if green)

- A closure that leaves any role able to distinguish present-but-hidden from absent by **response or timing/egress** (e.g. "fetch for both then discard the present one" re-introduces a *response* oracle: absent→served vs present-RESTRICTED→NOT_FOUND). The only leak-free closure is: the role that may fetch has no hidden class.
- A rate limiter whose reject path still delegates, echoes the arg, or writes an audit record.
- Silently weakening the existing fetch *mechanism* tests instead of migrating them to the now-required fetch-eligible role and adding explicit closure tests.
- A limiter that breaks existing `AgentToolset` callers (it must be **opt-in**, default off / unlimited).

## 6. Constraints

- Python 3.12, stdlib + pydantic, no new dependency. Deterministic, offline, hermetic. PUBLIC/synthetic only.
- `ruff`/`black`/`mypy` clean, line length 100. Attribution footer on every commit.
- Backward compatible: default-constructed `AgentToolset` behaves exactly as before (no limiter).

## 7. Design (the "how" decided)

### 7.1 Side-channel closure — `retrieval/authz.py` + `research_service._research`

Add to `authz.py`, co-located with the sensitivity policy it derives from:

```python
# Live-fetch does network egress and WRITES (indexes the fetched doc), and — absent this gate —
# the fire-or-not signal reveals whether a RESTRICTED doc is present. So it is a privileged
# capability: only a role for which authorize() never withholds a PUBLIC document (no
# present-but-hidden class) may trigger it. That set is _RESTRICTED_ROLES today; widen ONLY in
# lockstep with any new sensitivity tier, or the existence oracle reopens.
_FETCH_ROLES = _RESTRICTED_ROLES

def may_live_fetch(role: str) -> bool:
    """Whether ``role`` may trigger opt-in live fetch-on-miss (see _FETCH_ROLES)."""
    return role.strip() in _FETCH_ROLES
```

In `_research`, change the fetch guard (currently `if fetch_missing is not None and doc_id not in self._docs:`) to also require `may_live_fetch(role)`:

```python
if fetch_missing is not None and may_live_fetch(role) and doc_id not in self._docs:
```

Nothing else in `_research` changes; the authorize-before-retrieve flow, the `doc_id not in self._docs` present-but-unauthorized guard, the one-audit-record discipline, and the FETCH_ERROR backstop all stay. `research_service` imports `may_live_fetch` from `authz` (the policy module; `_authorize` stays injected — see §9 ruling on the coupling).

### 7.2 Rate limiter — `agents/rate_limit.py`

```python
class RateLimitExceeded(Exception): ...

class RateLimiter:
    def __init__(self, capacity: int, refill_per_second: float = 0.0, *, clock=time.monotonic): ...
    def acquire(self, tokens: int = 1) -> None:
        """Consume ``tokens``; raise RateLimitExceeded if the bucket lacks them."""
```

Token bucket: starts full at `capacity`; `acquire` refills by `elapsed * refill_per_second` (capped at `capacity`) using the injected monotonic `clock`, then consumes or raises. `refill_per_second=0.0` ⇒ a pure per-session budget of `capacity` calls. Deterministic under an injected fake clock; stdlib only.

### 7.3 `AgentToolset` wiring — `agents/functions.py`

`__init__` gains `rate_limiter: RateLimiter | None = None` (stored as `self._rate_limiter`). Each of the three tools calls `self._rate_limiter.acquire()` **first** when a limiter is set — before shape validation and before the service call — so an over-budget call raises `RateLimitExceeded` and never delegates, echoes, or audits. Default `None` ⇒ unlimited ⇒ existing callers unchanged. Read-only is documented in the class docstring (retrieval only; live-fetch, the one write, is senior-gated in the service).

### 7.4 Docs

`infrastructure/identity/roles.md`: add that opt-in live-fetch is a `senior_analyst` capability (network egress + corpus write) and that this closes the existence side-channel; note the widen-in-lockstep invariant. ROADMAP Week 12 ticked.

## 8. Consequences / behavior changes (call out)

- **`research_analyst` can no longer trigger live-fetch-on-miss.** On the live `GET /research/cve/{id}` with `SAIR_ALLOW_LIVE_FETCH` on, an analyst requesting a CVE absent from the corpus now gets `NOT_FOUND` (404) instead of a fetched answer; `senior_analyst` still fetches. This is the intended privilege boundary (and the closure). In the default deps-wired corpus there are **no** RESTRICTED docs, so this changes only *who* can pull new CVEs, not any existing fixture answer.
- **Existing fetch-*mechanism* tests migrate to `senior_analyst`** (they exercise FETCH_ERROR / CveNotFound→NOT_FOUND / cache behavior — all now reached via the fetch-eligible role), plus **new closure tests**: `research_analyst` triggers zero fetches for both an absent id and a present-RESTRICTED id (byte-identical response **and** equal fetch count). The CLI `fetch_cve` and the live endpoint test move their fetch cases to `senior_analyst`.

## 9. What's left to the builder / rulings

- Exact `capacity`/`refill` defaults in tests; the limiter's internal float math (monotonic, non-negative).
- **Ruling (coupling):** `research_service` imports `may_live_fetch` from `authz` directly rather than taking it as an injected predicate, mirroring how it already imports the concrete policy, while `_authorize` stays injected for test doubles. Cost if wrong: a custom injected authorizer with different role semantics would not be reflected in fetch-eligibility — acceptable because the service is always wired with the real `authorize`; revisit if that stops being true. Ledger it.

## 10. Review focus (for the final whole-branch review)

1. **The closure is leak-free (I):** verify that after the change, for `research_analyst`, an absent id and a present-but-`RESTRICTED` id are identical in response **and** in fetch invocation count (0), and that `senior_analyst` has no present-but-hidden class — so no response/timing/egress oracle remains on any path. Confirm the fix is in the `_research` fetch gate only.
2. **Rate-limit reject discipline (D):** over-budget call raises `RateLimitExceeded` with no delegation, no arg echo, and **zero** audit records; limiter is deterministic under the injected clock; default-None preserves existing behavior.
3. **Blast radius:** src changes confined to `authz.py` (+helper), `research_service.py` (one-line gate + import), `agents/rate_limit.py` (new), `agents/functions.py` (optional limiter). No retrieval/chunking/build_report/schema/loader change.
4. **Test migration is honest:** fetch-mechanism tests moved to `senior_analyst` still assert the same mechanism; the new analyst-no-fetch closure tests genuinely fail if the gate is removed.
5. Backward compatibility: all prior AgentToolset and research_analyst non-fetch tests still pass unchanged.
