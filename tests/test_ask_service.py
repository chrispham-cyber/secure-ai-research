"""`ResearchService.ask()` — grounded free-form QA over the whole corpus (Phase 5, Slice 1b).

ask() is a sibling of search(): it reuses the shared authorize-before-retrieve _retrieve_corpus,
then 1a's synthesis block (generator → fail-closed → build_report citation + faithfulness gate).
These tests pin the spec's anti-goals A1 (nothing ungrounded survives) and A2 (no RESTRICTED
disclosure), G4 (empty hits = OK with no generation), G6 (KEV/Sigma lines are citable), the
fail-closed contract, and the audit identity — all against the real pipeline (fakes only stand in
for the model). Deterministic; no network.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from secure_ai_research.audit.record import read_records
from secure_ai_research.evaluation.benchmark import (
    RESTRICTED_CANARY,
    RESTRICTED_DOC_ID,
    build_benchmark_service,
)
from secure_ai_research.generation.ports import GeneratorError
from secure_ai_research.ingestion.ingested import IngestedDocument
from secure_ai_research.ingestion.schema import (
    Classification,
    DocumentType,
    ResearchDocument,
    Sensitivity,
)
from secure_ai_research.research_service import Citation, Outcome, ResearchService
from secure_ai_research.retrieval.authz import authorize
from secure_ai_research.retrieval.embeddings import HashingEmbedder
from secure_ai_research.retrieval.ports import ChunkHit
from secure_ai_research.retrieval.vectorstore import InMemoryVectorStore


class _FixedLineGen:
    """Returns one fixed line regardless of prompt/passages."""

    def __init__(self, line: str) -> None:
        self._line = line

    def generate(self, prompt: str, passages) -> str:
        return self._line


class _RecordingGen:
    """Records every call so a test can assert the generator was (not) invoked."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def generate(self, prompt: str, passages) -> str:
        self.calls.append((prompt, tuple(passages)))
        return "noop [CVE-0000-0000]"


class _AdversarialAskGen:
    """Emits an uncited line, a forged (now-citable KEV-shape, non-retrieved) line, and a
    valid-retrieved-id + nonsense-claim line — all three must be dropped by build_report."""

    def generate(self, prompt: str, passages) -> str:
        return (
            "ungrounded no citation here\n"
            "forged [KEV-CVE-9999-9999]\n"
            "zzxqfabricated nonsense qqwz [KEV-CVE-2021-44228]"
        )


class _FailingGen:
    def generate(self, prompt: str, passages) -> str:
        raise GeneratorError("boom")


class _BrokenGen:
    """Fails with a non-GeneratorError (mirrors a urllib ValueError from a bad host scheme)."""

    def generate(self, prompt: str, passages) -> str:
        raise ValueError("unknown url type: 'localhost'")


class _IdentityAskGen:
    model_id = "ollama"
    model_version = "mistral:latest"
    prompt_template_version = "v1"

    def generate(self, prompt: str, passages) -> str:
        return "Apache Log4j2 Remote Code Execution vulnerability [KEV-CVE-2021-44228]"


class _ZeroScoreStore(InMemoryVectorStore):
    """Returns every authorized chunk at score 0.0, so the relevance floor drops them all —
    a deterministic 'nothing matched' the HashingEmbedder cannot otherwise guarantee."""

    def query(self, embedding, *, allowed_document_ids, limit):
        return [ChunkHit(did, "irrelevant", 0.0) for did in sorted(allowed_document_ids)][:limit]


def _mini_zero_service(tmp_path: Path, generator) -> ResearchService:
    """A one-document ROUTINE PUBLIC service over a zero-score store (every query → empty hits)."""
    doc = ResearchDocument(
        document_id="CVE-2099-0001",
        source="NVD",
        document_type=DocumentType.ADVISORY,
        classification=Classification.PUBLIC,
        created_at=date(2026, 1, 1),
        source_url="https://example.test/CVE-2099-0001",  # type: ignore[arg-type]
        integrity_hash="sha256:" + "0" * 64,
        sensitivity=Sensitivity.ROUTINE,
    )
    svc = ResearchService(
        HashingEmbedder(), _ZeroScoreStore(), authorize, tmp_path / "a.jsonl", generator=generator
    )
    svc.index([IngestedDocument(document=doc, text="some widget text")])
    return svc


def test_ask_synthesizes_grounded_cited_answer(tmp_path):
    svc = build_benchmark_service(tmp_path / "a.jsonl")  # default JoinGenerator
    res = svc.ask("log4j", role="research_analyst")
    assert res.outcome is Outcome.OK
    assert res.answer.startswith('# Research report: Answer question: "log4j"')
    assert res.citations and all(isinstance(c, Citation) for c in res.citations)


def test_ask_kev_or_sigma_grounded_line_survives(tmp_path):  # G6 end-to-end through ask()
    line = "Apache Log4j2 Remote Code Execution vulnerability [KEV-CVE-2021-44228]"
    svc = build_benchmark_service(tmp_path / "a.jsonl", generator=_FixedLineGen(line))
    res = svc.ask("log4j", role="research_analyst")
    assert res.outcome is Outcome.OK
    assert "KEV-CVE-2021-44228" in {c.document_id for c in res.citations}
    assert line in res.answer


def test_ask_empty_hits_is_ok_without_generation(tmp_path):  # G4
    gen = _RecordingGen()
    svc = _mini_zero_service(tmp_path, gen)
    res = svc.ask("anything", role="research_analyst")
    assert res.outcome is Outcome.OK
    assert "No cited findings." in res.answer
    assert res.citations == []
    assert gen.calls == []  # generator never invoked on an empty context
    assert len(read_records(tmp_path / "a.jsonl")) == 1


def test_ask_denied_role(tmp_path):
    svc = build_benchmark_service(tmp_path / "a.jsonl")
    res = svc.ask("log4j", role="guest")
    assert res.outcome is Outcome.DENIED
    assert res.answer == "" and res.citations == []
    assert len(read_records(tmp_path / "a.jsonl")) == 1


def test_ask_does_not_disclose_restricted_doc(tmp_path):  # A2
    svc = build_benchmark_service(
        tmp_path / "a.jsonl", generator=_FixedLineGen(f"leak [{RESTRICTED_DOC_ID}]")
    )
    res = svc.ask("incident", role="research_analyst")
    assert RESTRICTED_DOC_ID not in res.answer
    assert RESTRICTED_CANARY not in res.answer
    assert RESTRICTED_DOC_ID not in {c.document_id for c in res.citations}
    senior = build_benchmark_service(tmp_path / "b.jsonl")
    assert senior.ask("incident", role="senior_analyst").outcome is Outcome.OK


def test_ask_adversarial_output_never_survives(tmp_path):  # A1
    svc = build_benchmark_service(tmp_path / "a.jsonl", generator=_AdversarialAskGen())
    res = svc.ask("log4j", role="research_analyst")
    assert res.outcome is Outcome.OK
    assert "ungrounded" not in res.answer
    assert "KEV-CVE-9999-9999" not in res.answer
    assert "zzxqfabricated" not in res.answer


def test_ask_generator_failure_is_fetch_error(tmp_path):
    svc = build_benchmark_service(tmp_path / "a.jsonl", generator=_FailingGen())
    res = svc.ask("log4j", role="research_analyst")
    assert res.outcome is Outcome.FETCH_ERROR
    assert res.answer == ""
    assert len(read_records(tmp_path / "a.jsonl")) == 1


def test_ask_non_generator_error_is_fetch_error(tmp_path):
    svc = build_benchmark_service(tmp_path / "a.jsonl", generator=_BrokenGen())
    res = svc.ask("log4j", role="research_analyst")
    assert res.outcome is Outcome.FETCH_ERROR
    assert len(read_records(tmp_path / "a.jsonl")) == 1


def test_ask_audit_identity_and_conclusion(tmp_path):
    svc = build_benchmark_service(tmp_path / "a.jsonl", generator=_IdentityAskGen())
    res = svc.ask("log4j", role="research_analyst")
    assert res.outcome is Outcome.OK
    rec = read_records(tmp_path / "a.jsonl")[-1]
    assert rec.model_id == "ollama"
    assert rec.conclusion == "ollama: assembled from cited passages"
