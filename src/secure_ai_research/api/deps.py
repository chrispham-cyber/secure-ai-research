"""FastAPI dependencies (ROADMAP Phase 2).

Builds the default ``ResearchService`` — deterministic ``HashingEmbedder`` + in-memory
vector store, the deny-by-default authorization gate, and the packaged synthetic NVD
corpus — and caches it for the process. Tests override this dependency with a service
bound to a temp audit log, so the real audit path is never touched under test.
"""

from __future__ import annotations

from functools import lru_cache
from importlib.resources import files

from secure_ai_research.config import get_settings
from secure_ai_research.ingestion import nvd
from secure_ai_research.research_service import ResearchService
from secure_ai_research.retrieval.authz import authorize
from secure_ai_research.retrieval.embeddings import HashingEmbedder
from secure_ai_research.retrieval.vectorstore import InMemoryVectorStore


@lru_cache
def get_service() -> ResearchService:
    """Return the process-wide ResearchService with the synthetic corpus indexed."""
    service = ResearchService(
        HashingEmbedder(),
        InMemoryVectorStore(),
        authorize,
        get_settings().audit_log_path,
    )
    raw = files("secure_ai_research.ingestion").joinpath("samples", "nvd_sample.json").read_bytes()
    service.index(nvd.load(raw))
    return service
