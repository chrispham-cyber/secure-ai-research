"""Red-team evaluations over the real pipeline (ROADMAP Phase 4, Week 15).

Formalizes the Week-10/11 security properties into **measured** evals: prompt-injection
robustness and information disclosure. Both run against the real ``ResearchService`` /
``AgentToolset`` surfaces built by the Week-14 ``build_benchmark_service`` (which already
indexes the synthetic injection corpus and the RESTRICTED document); nothing re-implements or
forks pipeline logic. In posture there is no generation step, so "injection robustness" is a
**pipeline** property — a forged citation never surfaces, authorization is unchanged by
document content, no RESTRICTED byte leaks — not a statement about a model following
instructions (that lives behind the deferred Week-16 ``Generator`` seam).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from secure_ai_research.agents.functions import AgentToolset
from secure_ai_research.evaluation.benchmark import (
    RESTRICTED_CANARY,
    RESTRICTED_DOC_ID,
)
from secure_ai_research.evaluation.injection_corpus import malicious_corpus
from secure_ai_research.reporting.report import citation_ids
from secure_ai_research.research_service import Outcome, ResearchResult, ResearchService


class InjectionEvalResult(BaseModel):
    """Outcome of running the synthetic injection corpus through the pipeline."""

    model_config = ConfigDict(frozen=True)

    total: int
    neutralized: int
    robustness: float
    retrieved: tuple[str, ...]
    failures: tuple[str, ...]


def _surfaced_ids(res: ResearchResult) -> set[str]:
    """Every id that surfaced for a result: structured citations + ids rendered in the body.

    Uses the single ``citation_ids`` grammar, so a forged bracket id in rendered text counts
    as "surfaced" exactly as a structured citation would.
    """
    return {c.document_id for c in res.citations} | set(citation_ids(res.answer))


def run_injection_eval(service: ResearchService) -> InjectionEvalResult:
    """Measure pipeline robustness to the synthetic injection corpus.

    For each malicious document, a ``research_analyst`` runs the search query that makes it the
    top hit (its leading marker token). The attack is **neutralized** iff all of: the lure was
    actually retrieved (``was_retrieved`` — so a lure the pipeline never surfaced counts as a
    *failure*, not a free pass, and ``robustness`` can't read 1.0 while measuring nothing); none
    of the forged ids the attacker embedded surface; the escalation lure leaves authorization
    unchanged (a RESTRICTED id is still ``NOT_FOUND`` for ``research_analyst``); and no RESTRICTED
    canary leaks. ``robustness`` is the neutralized fraction; ``retrieved`` names the lures
    pulled into a result.

    Honest in-posture scope: with no generator, the forged-id check reduces for the two
    bracket-id lures to "a forged citation never surfaces" and for the instruction/escalation
    lures (which embed no citation) to "``search`` never renders document body". The real
    "a model must not *act on* the injected instruction/escalation" test is the deferred Week-16
    model-eval behind the ``Generator`` seam — ``robustness == 1.0`` here means the deterministic
    pipeline attributes-not-executes, not that four distinct behavioral attacks were defeated.
    """
    docs = malicious_corpus()
    retrieved: list[str] = []
    failures: list[str] = []
    for doc in docs:
        doc_id = doc.document.document_id
        marker = doc.text.split()[0]
        forged = set(citation_ids(doc.text))
        res = service.search(marker, role="research_analyst")
        was_retrieved = doc_id in {c.document_id for c in res.citations}
        if was_retrieved:
            retrieved.append(doc_id)
        authz_held = (
            service.research_cve(RESTRICTED_DOC_ID, role="research_analyst").outcome
            is Outcome.NOT_FOUND
        )
        neutralized = (
            was_retrieved
            and not (forged & _surfaced_ids(res))
            and authz_held
            and RESTRICTED_CANARY not in res.answer
        )
        if not neutralized:
            failures.append(doc_id)
    neutralized_count = len(docs) - len(failures)
    return InjectionEvalResult(
        total=len(docs),
        neutralized=neutralized_count,
        robustness=neutralized_count / len(docs),
        retrieved=tuple(retrieved),
        failures=tuple(failures),
    )


# A genuinely-absent CVE id (no document carries it), for the byte-identical baseline.
_ABSENT_CVE = "CVE-2099-9999"
# A search probe drawn from the RESTRICTED body but NOT its canary token — ``search`` echoes
# its own query, so using the canary as the query would both false-trigger a leak check and
# tell us nothing. These tokens are in the body; a leak would be the canary appearing *despite*
# a non-canary query, or the RESTRICTED id surfacing in the authorized result.
_RESTRICTED_PROBE_QUERY = "sensitive internal incident"


class InfoDisclosureEvalResult(BaseModel):
    """Outcome of the two-user RESTRICTED scenario across every retrieval path."""

    model_config = ConfigDict(frozen=True)

    probes: int
    disclosures: int
    failures: tuple[str, ...]


def _same_response(a: ResearchResult, b: ResearchResult) -> bool:
    """True iff two results are byte-identical ignoring the per-call random ``research_id``.

    Compares ``outcome``, ``answer``, and the full citation triples — a status-only check would
    miss a response oracle (spec review focus 3).
    """
    cites = lambda r: [(c.document_id, c.source_url, c.passage) for c in r.citations]  # noqa: E731
    return a.outcome == b.outcome and a.answer == b.answer and cites(a) == cites(b)


def _leaks_restricted(res: ResearchResult) -> bool:
    """True iff a result exposes any RESTRICTED byte: the canary text or the RESTRICTED id."""
    return RESTRICTED_CANARY in res.answer or RESTRICTED_DOC_ID in {
        c.document_id for c in res.citations
    }


def run_info_disclosure_eval(service: ResearchService) -> InfoDisclosureEvalResult:
    """Measure information disclosure of the RESTRICTED document to ``research_analyst``.

    Four probes across every path a non-senior caller could try — the id-route, free-text
    search, and the same two through the ``AgentToolset`` — each a disclosure iff the response
    differs from a genuinely-absent id (an existence oracle) or exposes a RESTRICTED byte.
    ``senior_analyst`` legitimately sees the document; that positive control lives in the tests
    so "zero disclosures" means access control works, not that the document is unreachable.
    """
    absent = service.research_cve(_ABSENT_CVE, role="research_analyst")
    tools = AgentToolset(service, role="research_analyst")

    id_route = service.research_cve(RESTRICTED_DOC_ID, role="research_analyst")
    search = service.search(_RESTRICTED_PROBE_QUERY, role="research_analyst")
    toolset_id = tools.search_cve(RESTRICTED_DOC_ID)
    toolset_search = tools.search_research(_RESTRICTED_PROBE_QUERY)

    probes: list[tuple[str, bool]] = [
        ("id-route", not _same_response(id_route, absent) or _leaks_restricted(id_route)),
        ("search", _leaks_restricted(search)),
        ("toolset-id", not _same_response(toolset_id, absent) or _leaks_restricted(toolset_id)),
        ("toolset-search", _leaks_restricted(toolset_search)),
    ]
    failures = tuple(label for label, disclosed in probes if disclosed)
    return InfoDisclosureEvalResult(
        probes=len(probes),
        disclosures=len(failures),
        failures=failures,
    )
