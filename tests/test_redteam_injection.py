"""Injection-robustness red-team eval over the real pipeline (Phase 4, Week 15)."""

import pytest

from secure_ai_research.evaluation.benchmark import build_benchmark_service
from secure_ai_research.evaluation.injection_corpus import malicious_corpus
from secure_ai_research.evaluation.redteam import run_injection_eval
from secure_ai_research.research_service import ResearchService
from secure_ai_research.retrieval.authz import authorize
from secure_ai_research.retrieval.embeddings import HashingEmbedder
from secure_ai_research.retrieval.vectorstore import InMemoryVectorStore


@pytest.fixture
def service(tmp_path):
    return build_benchmark_service(tmp_path / "a.jsonl")


def test_injection_robustness_is_total_neutralization(service):
    r = run_injection_eval(service)
    assert r.total == len(malicious_corpus())
    assert r.failures == ()
    assert r.neutralized == r.total
    assert r.robustness == 1.0


def test_injection_eval_actually_retrieves_every_lure(service):  # Review Focus 2 (non-vacuous)
    r = run_injection_eval(service)
    assert set(r.retrieved) == {d.document.document_id for d in malicious_corpus()}


def test_injection_forged_ids_never_surface(service):
    # The forged/impersonated bracket ids embedded in the payloads must not appear as
    # structured citations or rendered text for research_analyst.
    r = run_injection_eval(service)
    assert r.robustness == 1.0 and r.failures == ()


def test_robustness_is_not_vacuous_when_lures_unretrieved(tmp_path):
    # If the pipeline never retrieves a lure, "neutralized" is unproven — the metric the
    # Week-16 gate consumes must count that as a failure, not a free 1.0. This service has a
    # routine doc (so authz is intact: a RESTRICTED id is NOT_FOUND, not DENIED) but NO
    # injection corpus, so no lure is retrievable; robustness must be 0.0, not a vacuous 1.0.
    from datetime import date

    from secure_ai_research.ingestion.ingested import IngestedDocument
    from secure_ai_research.ingestion.schema import (
        Classification,
        DocumentType,
        ResearchDocument,
    )

    svc = ResearchService(HashingEmbedder(), InMemoryVectorStore(), authorize, tmp_path / "a.jsonl")
    svc.index(
        [
            IngestedDocument(
                document=ResearchDocument(
                    document_id="CVE-2000-0001",
                    source="NVD",
                    document_type=DocumentType.ADVISORY,
                    classification=Classification.PUBLIC,
                    created_at=date(2000, 1, 1),
                    source_url="https://example.test/CVE-2000-0001",  # type: ignore[arg-type]
                    integrity_hash="sha256:" + "0" * 64,
                ),
                text="a routine public advisory unrelated to any injection marker",
            )
        ]
    )
    r = run_injection_eval(svc)
    assert r.retrieved == ()
    assert set(r.failures) == {d.document.document_id for d in malicious_corpus()}
    assert r.robustness == 0.0
