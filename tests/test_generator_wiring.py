"""Generator seam wired into the id-route (Phase 5, Slice 1a, Task 1).

The default path (JoinGenerator) must stay byte-identical — answer AND audit record — to
pre-change output (RF4). An injected generator fills ``model_output`` and its identity lands
in the audit record; a generator that raises ``GeneratorError`` becomes a FETCH_ERROR with one
audit record, never a silent fallback (design §10 Q1).
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from secure_ai_research.audit.record import read_records
from secure_ai_research.evaluation.benchmark import build_benchmark_service
from secure_ai_research.ingestion.ingested import IngestedDocument
from secure_ai_research.ingestion.schema import (
    Classification,
    DocumentType,
    ResearchDocument,
    Sensitivity,
)
from secure_ai_research.research_service import Outcome, ResearchService
from secure_ai_research.retrieval.authz import authorize
from secure_ai_research.retrieval.embeddings import HashingEmbedder
from secure_ai_research.retrieval.vectorstore import InMemoryVectorStore

_TARGET = "CVE-2099-0001"

# Golden captured from pre-change code (characterization — RF4).
_GOLDEN_ANSWER = (
    "# Research report: Correlate CVE-2099-0001 against public sources\n\n"
    "CVE-2099-0001 is a synthetic SQL injection in the example login form that lets an "
    "unauthenticated attacker read arbitrary rows from the accounts database. This record "
    "is fictional test data. [CVE-2099-0001]\n\n"
    "Sources: CVE-2099-0001"
)
_GOLDEN_MODEL_OUTPUT = (
    "CVE-2099-0001 is a synthetic SQL injection in the example login form that lets an "
    "unauthenticated attacker read arbitrary rows from the accounts database. This record "
    "is fictional test data. [CVE-2099-0001]"
)

# A grounded line the fakes return: shares tokens with the passage so it also survives the
# Task-3 faithfulness floor once that lands.
_FAKE_LINE = "CVE-2099-0001 synthetic SQL injection summary [CVE-2099-0001]"


class _RecordingGen:
    """Records its call and returns a fixed grounded line."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def generate(self, prompt: str, passages) -> str:
        self.calls.append((prompt, tuple(passages)))
        return _FAKE_LINE


class _IdentityGen:
    model_id = "ollama"
    model_version = "mistral:latest"
    prompt_template_version = "v1"

    def generate(self, prompt: str, passages) -> str:
        return _FAKE_LINE


class _FailingGen:
    def generate(self, prompt: str, passages) -> str:
        from secure_ai_research.generation.ports import GeneratorError

        raise GeneratorError("boom")


def _mini_service(tmp_path: Path, generator) -> ResearchService:
    """A ResearchService over one ROUTINE PUBLIC CVE doc, with ``generator`` injected."""
    doc = ResearchDocument(
        document_id=_TARGET,
        source="NVD",
        document_type=DocumentType.ADVISORY,
        classification=Classification.PUBLIC,
        created_at=date(2026, 1, 1),
        source_url="https://example.test/CVE-2099-0001",  # type: ignore[arg-type]
        integrity_hash="sha256:" + "0" * 64,
        sensitivity=Sensitivity.ROUTINE,
    )
    svc = ResearchService(
        HashingEmbedder(),
        InMemoryVectorStore(),
        authorize,
        tmp_path / "a.jsonl",
        generator=generator,
    )
    svc.index([IngestedDocument(document=doc, text=_GOLDEN_MODEL_OUTPUT)])
    return svc


def test_default_generator_is_byte_identical_characterization(tmp_path):  # RF4
    audit = tmp_path / "audit.jsonl"
    svc = build_benchmark_service(audit)
    res = svc.research_cve(_TARGET, role="research_analyst")
    assert res.outcome is Outcome.OK
    assert res.answer == _GOLDEN_ANSWER
    rec = read_records(audit)[-1]
    assert rec.model_id == "retrieval-only"
    assert rec.model_version == ""
    assert rec.prompt_template_version == ""
    assert rec.conclusion == "retrieval-only: assembled from cited passages"
    assert rec.model_output == _GOLDEN_MODEL_OUTPUT


def test_injected_generator_fills_model_output(tmp_path):
    gen = _RecordingGen()
    svc = _mini_service(tmp_path, gen)
    res = svc.research_cve(_TARGET, role="research_analyst")
    assert res.outcome is Outcome.OK
    assert gen.calls, "generator was not called"
    assert _FAKE_LINE in res.answer
    rec = read_records(tmp_path / "a.jsonl")[-1]
    assert rec.model_output == _FAKE_LINE


def test_injected_generator_identity_lands_in_audit(tmp_path):
    svc = _mini_service(tmp_path, _IdentityGen())
    res = svc.research_cve(_TARGET, role="research_analyst")
    assert res.outcome is Outcome.OK
    rec = read_records(tmp_path / "a.jsonl")[-1]
    assert rec.model_id == "ollama"
    assert rec.model_version == "mistral:latest"
    assert rec.prompt_template_version == "v1"
    assert rec.conclusion == "ollama: assembled from cited passages"


def test_generator_failure_is_fetch_error(
    tmp_path,
):  # design §10 Q1 — fail-closed, no silent fallback
    svc = _mini_service(tmp_path, _FailingGen())
    res = svc.research_cve(_TARGET, role="research_analyst")
    assert res.outcome is Outcome.FETCH_ERROR
    assert res.answer == ""
    assert len(read_records(tmp_path / "a.jsonl")) == 1


class _BrokenGen:
    """Fails with a non-GeneratorError (e.g. a urllib ValueError from a bad host scheme)."""

    def generate(self, prompt: str, passages) -> str:
        raise ValueError("unknown url type: 'localhost'")


class _AdversarialGen:
    """Emits an uncited line, a forged-citation line, and a valid-id + invented-text line."""

    def generate(self, prompt: str, passages) -> str:
        return (
            "Ungrounded assertion with no citation at all\n"
            "Forged finding [CVE-9999-9999]\n"
            "Totally invented remote exploit [CVE-2099-0001]"
        )


def test_generator_non_generator_error_is_fetch_error(
    tmp_path,
):  # review: defense-in-depth invariant
    # A generator failing with anything OTHER than GeneratorError must STILL become FETCH_ERROR
    # with exactly one audit record — never an unhandled 500 that leaves no audit trail (mirrors
    # the injected-fetcher path's `except Exception`). Here the failure is a bare ValueError.
    svc = _mini_service(tmp_path, _BrokenGen())
    res = svc.research_cve(_TARGET, role="research_analyst")
    assert res.outcome is Outcome.FETCH_ERROR
    assert res.answer == ""
    assert len(read_records(tmp_path / "a.jsonl")) == 1


def test_adversarial_generator_output_never_survives(tmp_path):  # spec anti-goal A1, end-to-end
    # Enforcement runs through build_report on the service's answer: an uncited line, a forged
    # (non-retrieved) citation, and a valid-id-but-invented claim must all be dropped.
    svc = _mini_service(tmp_path, _AdversarialGen())
    res = svc.research_cve(_TARGET, role="research_analyst")
    assert res.outcome is Outcome.OK
    assert "Ungrounded assertion" not in res.answer
    assert "CVE-9999-9999" not in res.answer
    assert "Totally invented remote exploit" not in res.answer
    assert "No cited findings." in res.answer
