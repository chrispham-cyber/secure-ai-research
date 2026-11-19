"""Evaluation benchmark: offline corpus + runner (ROADMAP Phase 4, Week 14).

Builds a deterministic, **offline** ``ResearchService`` over the committed PUBLIC/synthetic
fixtures (NVD + ATT&CK + KEV + Sigma) plus the Week-11 injection corpus and one synthetic
RESTRICTED document, then executes benchmark ``EvalItem``s against the *real* pipeline — never a
re-implementation of authorization, retrieval, or report assembly — to produce ``EvalResult``s.

No ``fetch_missing`` is wired, so the service has no network path: an absent id is ``NOT_FOUND``,
never a live fetch, and two runs of the benchmark produce identical results.
"""

from __future__ import annotations

from datetime import date
from importlib.resources import files
from pathlib import Path

from secure_ai_research.evaluation.injection_corpus import malicious_corpus
from secure_ai_research.ingestion import attack, kev, nvd, sigma
from secure_ai_research.ingestion.ingested import IngestedDocument
from secure_ai_research.ingestion.schema import (
    Classification,
    DocumentType,
    ResearchDocument,
    Sensitivity,
)
from secure_ai_research.research_service import ResearchService
from secure_ai_research.retrieval.authz import authorize
from secure_ai_research.retrieval.embeddings import HashingEmbedder
from secure_ai_research.retrieval.vectorstore import InMemoryVectorStore

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
