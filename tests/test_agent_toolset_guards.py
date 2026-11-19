"""AgentToolset excessive-agency guards (ROADMAP Phase 3, Week 12).

The toolset is read-only (retrieval only) and, when given a ``RateLimiter``, bounds how many
tool calls an agent may make — refusing an over-budget call *before* it validates args,
delegates to the service, or writes any audit record (the same discipline as the Week-9
argument-shape reject: fail loud, no delegation, no echo, zero audit).
"""

from datetime import date

import pytest

from secure_ai_research.agents.functions import AgentToolset
from secure_ai_research.agents.rate_limit import RateLimiter, RateLimitExceeded
from secure_ai_research.audit.record import read_records
from secure_ai_research.ingestion.ingested import IngestedDocument
from secure_ai_research.ingestion.schema import Classification, DocumentType, ResearchDocument
from secure_ai_research.research_service import Outcome, ResearchService
from secure_ai_research.retrieval.authz import authorize
from secure_ai_research.retrieval.embeddings import HashingEmbedder
from secure_ai_research.retrieval.vectorstore import InMemoryVectorStore

_HASH = "sha256:" + "0" * 64


def _service(audit_path) -> ResearchService:
    svc = ResearchService(HashingEmbedder(), InMemoryVectorStore(), authorize, audit_path)
    doc = ResearchDocument(
        document_id="CVE-2099-0001",
        source="test",
        document_type=DocumentType.VULNERABILITY,
        classification=Classification.PUBLIC,
        created_at=date(2099, 1, 1),
        source_url="https://example.test/x",  # type: ignore[arg-type]
        integrity_hash=_HASH,
    )
    svc.index([IngestedDocument(document=doc, text="CVE-2099-0001 rce in the widget parser")])
    return svc


def test_rate_limit_blocks_over_budget_without_delegating_or_auditing(tmp_path):
    audit = tmp_path / "audit.jsonl"
    toolset = AgentToolset(
        _service(audit), role="research_analyst", rate_limiter=RateLimiter(capacity=1)
    )
    assert toolset.search_cve("CVE-2099-0001").outcome is Outcome.OK  # 1st call: allowed
    audited = len(read_records(audit))
    with pytest.raises(RateLimitExceeded):
        toolset.search_cve("CVE-2099-0001")  # 2nd call: over budget
    assert len(read_records(audit)) == audited  # the refused call never reached the service


def test_rate_limit_fires_before_arg_validation(tmp_path):
    # A zero-capacity limiter refuses even a structurally invalid arg — the budget is checked
    # first, so a hostile/malformed request cannot even probe the validator.
    toolset = AgentToolset(
        _service(tmp_path / "a.jsonl"),
        role="research_analyst",
        rate_limiter=RateLimiter(capacity=0),
    )
    with pytest.raises(RateLimitExceeded):
        toolset.search_cve("not-a-valid-cve-id")  # RateLimitExceeded, never ValueError


def test_default_toolset_is_unlimited(tmp_path):
    toolset = AgentToolset(_service(tmp_path / "a.jsonl"), role="research_analyst")  # no limiter
    for _ in range(5):
        assert toolset.search_cve("CVE-2099-0001").outcome is Outcome.OK  # never raises


def test_toolset_public_surface_is_read_only():
    # Characterization guard (passes on current code): pins the public tool surface so a
    # future *mutating* method trips this test rather than shipping silently.
    public = {
        name
        for name in vars(AgentToolset)
        if not name.startswith("_") and callable(getattr(AgentToolset, name))
    }
    assert public == {"search_cve", "search_attack", "search_research"}
