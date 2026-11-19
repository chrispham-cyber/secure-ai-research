"""Two-user information-disclosure test (ROADMAP Phase 3, Week 10).

Proves the ABAC sensitivity tier at the boundary that matters: over one corpus holding a
ROUTINE and a RESTRICTED document, the wider-scope ``senior_analyst`` can retrieve the
restricted one and ``research_analyst`` cannot — on *any* path. A lower-privilege analyst
sees NOT_FOUND (indistinguishable from a genuinely absent id: no existence oracle) on the
id-route, and the restricted document's id and its body-only secret token never appear in
the analyst's search answer or citations. Asserted at the service layer and end-to-end
through the Week-9 ``AgentToolset`` boundary.

The restricted document is a synthetic, PUBLIC-but-RESTRICTED internal advisory. Its
*query* tokens (``zerberus breach playbook``) are what a searcher types; its *secret* token
(``exfil-canary-7f3a``) lives only in the body and is what must never leak — kept distinct
from the query because ``search`` echoes the query back in its answer string.
"""

from datetime import date

from secure_ai_research.agents.functions import AgentToolset
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

_HASH = "sha256:" + "0" * 64
_SECRET = "exfil-canary-7f3a"  # present only in the restricted document body
_QUERY = "zerberus breach playbook"  # shares tokens only with the restricted document


def _doc(doc_id: str, text: str, sensitivity: Sensitivity) -> IngestedDocument:
    document = ResearchDocument(
        document_id=doc_id,
        source="test",
        document_type=DocumentType.VULNERABILITY,
        classification=Classification.PUBLIC,
        sensitivity=sensitivity,
        created_at=date(2099, 1, 1),
        source_url="https://example.test/x",  # type: ignore[arg-type]
        integrity_hash=_HASH,
    )
    return IngestedDocument(document=document, text=text)


def _service(tmp_path, *, fetch_missing=None) -> ResearchService:
    svc = ResearchService(
        HashingEmbedder(),
        InMemoryVectorStore(),
        authorize,
        tmp_path / "audit.jsonl",
        fetch_missing=fetch_missing,
    )
    svc.index(
        [
            _doc(
                "CVE-2021-44228",
                "CVE-2021-44228 log4j remote code execution in logging library",
                Sensitivity.ROUTINE,
            ),
            _doc(
                "CVE-2099-5000",
                f"CVE-2099-5000 zerberus breach playbook {_SECRET}",
                Sensitivity.RESTRICTED,
            ),
        ]
    )
    return svc


def test_senior_can_retrieve_restricted(tmp_path):
    svc = _service(tmp_path)
    result = svc.research_cve("CVE-2099-5000", role="senior_analyst")
    assert result.outcome is Outcome.OK
    assert any(c.document_id == "CVE-2099-5000" for c in result.citations)


def test_analyst_cannot_retrieve_restricted_no_oracle(tmp_path):
    svc = _service(tmp_path)
    restricted = svc.research_cve("CVE-2099-5000", role="research_analyst")  # present, forbidden
    absent = svc.research_cve("CVE-1999-0001", role="research_analyst")  # genuinely absent
    assert restricted.outcome is absent.outcome is Outcome.NOT_FOUND
    assert restricted.citations == absent.citations == []
    assert restricted.answer == absent.answer  # byte-identical: no existence oracle


def test_restricted_secret_never_reaches_analyst_search(tmp_path):
    svc = _service(tmp_path)
    analyst = svc.search(_QUERY, role="research_analyst")
    assert all(c.document_id != "CVE-2099-5000" for c in analyst.citations)
    assert _SECRET not in analyst.answer
    assert all(_SECRET not in c.passage for c in analyst.citations)

    senior = svc.search(_QUERY, role="senior_analyst")
    assert any(c.document_id == "CVE-2099-5000" for c in senior.citations)


def test_two_users_through_agent_toolset(tmp_path):
    svc = _service(tmp_path)
    senior = AgentToolset(svc, role="senior_analyst").search_cve("CVE-2099-5000")
    analyst = AgentToolset(svc, role="research_analyst").search_cve("CVE-2099-5000")
    assert senior.outcome is Outcome.OK
    assert analyst.outcome is Outcome.NOT_FOUND


def test_restricted_present_doc_is_never_fetched_for_analyst(tmp_path):
    # Content-safety on the opt-in live-fetch path: a present-but-RESTRICTED doc must never
    # be handed to fetch-on-miss (which could re-serve it). _research's `doc_id not in docs`
    # guard skips the fetch for any id already in the corpus, so the analyst gets NOT_FOUND,
    # no secret leaks, and the fetcher is never invoked for the withheld id.
    calls: list[str] = []

    def _record(cve_id: str) -> list[IngestedDocument]:
        calls.append(cve_id)
        return []

    svc = _service(tmp_path, fetch_missing=_record)
    result = svc.research_cve("CVE-2099-5000", role="research_analyst")
    assert result.outcome is Outcome.NOT_FOUND
    assert _SECRET not in result.answer
    assert calls == []
