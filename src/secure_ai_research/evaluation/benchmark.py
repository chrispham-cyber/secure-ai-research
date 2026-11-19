"""Evaluation benchmark: offline corpus + runner (ROADMAP Phase 4, Week 14).

Builds a deterministic, **offline** ``ResearchService`` over the committed PUBLIC/synthetic
fixtures (NVD + ATT&CK + KEV + Sigma) plus the Week-11 injection corpus and one synthetic
RESTRICTED document, then executes benchmark ``EvalItem``s against the *real* pipeline — never a
re-implementation of authorization, retrieval, or report assembly — to produce ``EvalResult``s.

No ``fetch_missing`` is wired, so the service has no network path: an absent id is ``NOT_FOUND``,
never a live fetch, and two runs of the benchmark produce identical results.
"""

from __future__ import annotations

import re
import tempfile
from collections import Counter
from datetime import date
from importlib.resources import files
from pathlib import Path

from secure_ai_research.evaluation.benchmark_items import benchmark_items
from secure_ai_research.evaluation.injection_corpus import malicious_corpus
from secure_ai_research.evaluation.metrics import aggregate
from secure_ai_research.evaluation.records import EvalItem, EvalResult
from secure_ai_research.ingestion import attack, kev, nvd, sigma
from secure_ai_research.ingestion.ingested import IngestedDocument
from secure_ai_research.ingestion.schema import (
    Classification,
    DocumentType,
    ResearchDocument,
    Sensitivity,
)
from secure_ai_research.reporting.report import citation_ids
from secure_ai_research.research_service import ResearchService
from secure_ai_research.retrieval.authz import authorize
from secure_ai_research.retrieval.embeddings import HashingEmbedder
from secure_ai_research.retrieval.vectorstore import InMemoryVectorStore

# ATT&CK technique id shape, for routing an ``authz`` item whose query is a technique id.
_T_ID = re.compile(r"T\d{4}(?:\.\d{3})?")

# A synthetic within-PUBLIC RESTRICTED document: PUBLIC classification, RESTRICTED sensitivity,
# a CVE-shaped id so it is reachable via the ``research_cve`` id-route. Only ``senior_analyst``
# may retrieve it; every other authorized role gets NOT_FOUND, byte-identical to an absent id.
RESTRICTED_DOC_ID = "CVE-2099-7001"
RESTRICTED_CANARY = "restricted-canary-9c21"

_PLACEHOLDER_HASH = "sha256:" + "0" * 64


def _sample(name: str) -> bytes:
    return files("secure_ai_research.ingestion").joinpath("samples", name).read_bytes()


def _restricted_doc() -> IngestedDocument:
    document = ResearchDocument(
        document_id=RESTRICTED_DOC_ID,
        source="NVD",
        document_type=DocumentType.ADVISORY,
        classification=Classification.PUBLIC,
        created_at=date(2026, 1, 1),
        source_url="https://example.test/restricted/CVE-2099-7001",  # type: ignore[arg-type]
        integrity_hash=_PLACEHOLDER_HASH,
        sensitivity=Sensitivity.RESTRICTED,
    )
    text = f"{RESTRICTED_CANARY} sensitive internal incident detail for senior analysts only"
    return IngestedDocument(document=document, text=text)


def build_benchmark_service(audit_path: Path) -> ResearchService:
    """Return an offline ``ResearchService`` with the full benchmark corpus indexed.

    Same wiring as the production default (``HashingEmbedder`` + in-memory store + the
    deny-by-default ``authorize`` gate) but with **no** ``fetch_missing`` callable, so the
    service is fully offline and deterministic.
    """
    service = ResearchService(
        HashingEmbedder(),
        InMemoryVectorStore(),
        authorize,
        audit_path,
    )
    service.index(nvd.load(_sample("nvd_sample.json")))
    service.index(attack.load(_sample("attack_sample.json")))
    service.index(kev.load(_sample("kev_sample.json")))
    service.index(sigma.load(_sample("sigma_sample.json")))
    service.index(malicious_corpus())
    service.index([_restricted_doc()])
    return service


def run_item(service: ResearchService, item: EvalItem) -> EvalResult:
    """Execute one ``EvalItem`` against the real pipeline and capture an ``EvalResult``.

    The item's ``kind`` selects the entrypoint: ``cve``/``attack`` take the id-routes,
    ``search``/``injection`` take free-text search, and ``authz`` routes by the shape of its
    query (a CVE id or ATT&CK id goes to the matching id-route, anything else to search).

    ``retrieved_ids`` is the ids the pipeline retrieved (``res.citations``). ``cited_ids`` is
    what the pipeline *cited*: for an id-route that is what the assembled report body cites
    (parsed with the single citation grammar), for a search route it is the ranked returned ids
    themselves (the search answer carries no in-body citations).
    """
    kind = item.kind
    if kind == "cve":
        res, is_id_route = service.research_cve(item.query, role=item.role), True
    elif kind == "attack":
        res, is_id_route = service.research_attack(item.query, role=item.role), True
    elif kind in ("search", "injection"):
        res, is_id_route = service.search(item.query, role=item.role), False
    elif kind == "authz":
        if item.query.startswith("CVE-"):
            res, is_id_route = service.research_cve(item.query, role=item.role), True
        elif _T_ID.fullmatch(item.query):
            res, is_id_route = service.research_attack(item.query, role=item.role), True
        else:
            res, is_id_route = service.search(item.query, role=item.role), False
    else:  # pragma: no cover - defensive; ItemKind is a closed Literal
        raise ValueError(f"unknown EvalItem kind: {kind!r}")

    retrieved_ids = tuple(c.document_id for c in res.citations)
    cited_ids = tuple(citation_ids(res.answer)) if is_id_route else retrieved_ids
    return EvalResult(
        item=item,
        outcome=res.outcome,
        cited_ids=cited_ids,
        retrieved_ids=retrieved_ids,
        answer=res.answer,
    )


def run_benchmark(service: ResearchService, items: list[EvalItem]) -> list[EvalResult]:
    """Run every item in list order (deterministic) and return the results."""
    return [run_item(service, item) for item in items]


def main() -> int:
    """Run the full benchmark on a throwaway audit log and print the aggregate.

    Reproduces the Week-14 metrics: ``python -m secure_ai_research.evaluation.benchmark``.
    """
    items = benchmark_items()
    with tempfile.TemporaryDirectory() as tmp:
        service = build_benchmark_service(Path(tmp) / "audit.jsonl")
        results = run_benchmark(service, items)
    agg = aggregate(results)
    by_kind = dict(Counter(item.kind for item in items))
    print(f"benchmark: {len(items)} items | by kind: {by_kind}")
    print(f"aggregate: {agg}")
    for key in ("grounding", "citation_accuracy", "refusal_accuracy", "n_total", "n_answered"):
        print(f"  {key}={agg[key]}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
