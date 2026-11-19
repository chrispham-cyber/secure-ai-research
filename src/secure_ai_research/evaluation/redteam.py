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
    top hit (its leading marker token). The attack is **neutralized** iff none of the forged
    ids the attacker embedded surface, the escalation lure leaves authorization unchanged (a
    RESTRICTED id is still ``NOT_FOUND`` for ``research_analyst``), and no RESTRICTED canary
    leaks. ``robustness`` is the neutralized fraction; ``retrieved`` names the lures actually
    pulled into a result (so a passing score can't be vacuous).
    """
    docs = malicious_corpus()
    retrieved: list[str] = []
    failures: list[str] = []
    for doc in docs:
        doc_id = doc.document.document_id
        marker = doc.text.split()[0]
        forged = set(citation_ids(doc.text))
        res = service.search(marker, role="research_analyst")
        if doc_id in {c.document_id for c in res.citations}:
            retrieved.append(doc_id)
        authz_held = (
            service.research_cve(RESTRICTED_DOC_ID, role="research_analyst").outcome
            is Outcome.NOT_FOUND
        )
        neutralized = (
            not (forged & _surfaced_ids(res)) and authz_held and RESTRICTED_CANARY not in res.answer
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
