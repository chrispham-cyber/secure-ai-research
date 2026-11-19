"""Fetch one real CVE and research it through the existing pipeline.

``research_from_source`` is the reusable, source-agnostic core: it takes any ``CveSource``
(real, caching, or a test double), runs its bytes through ``nvd.load`` and a fresh
``ResearchService``, and returns the cited result. The default FastAPI app does not use
this path — it stays offline and fixture-backed.
"""

from pathlib import Path

from secure_ai_research.ingestion import nvd
from secure_ai_research.ingestion.source import CveSource
from secure_ai_research.research_service import ResearchResult, ResearchService
from secure_ai_research.retrieval.authz import authorize
from secure_ai_research.retrieval.embeddings import HashingEmbedder
from secure_ai_research.retrieval.vectorstore import InMemoryVectorStore


def research_from_source(
    cve_id: str, *, role: str, source: CveSource, audit_path: Path
) -> ResearchResult:
    svc = ResearchService(HashingEmbedder(), InMemoryVectorStore(), authorize, audit_path)
    svc.index(nvd.load(source.fetch_raw(cve_id)))
    return svc.research_cve(cve_id, role=role)
