"""FastAPI dependencies (ROADMAP Phase 2).

Builds the default ``ResearchService`` — deterministic ``HashingEmbedder`` + in-memory
vector store, the deny-by-default authorization gate, and the packaged synthetic NVD
corpus — and caches it for the process. Tests override this dependency with a service
bound to a temp audit log, so the real audit path is never touched under test.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import lru_cache
from importlib.resources import files

from secure_ai_research.config import get_settings
from secure_ai_research.ingestion import attack, kev, nvd
from secure_ai_research.ingestion.ingested import IngestedDocument
from secure_ai_research.ingestion.nvd_source import CachingCveSource, NvdApiSource
from secure_ai_research.ingestion.source import CveUnavailable
from secure_ai_research.research_service import ResearchService
from secure_ai_research.retrieval.authz import authorize
from secure_ai_research.retrieval.embeddings import HashingEmbedder
from secure_ai_research.retrieval.vectorstore import InMemoryVectorStore


@lru_cache
def get_service() -> ResearchService:
    """Return the process-wide ResearchService with the synthetic corpus indexed.

    When ``SAIR_ALLOW_LIVE_FETCH`` is true, the service is given a ``fetch_missing``
    callable so a request for a CVE absent from the corpus is fetched from NVD and cached
    on disk. When false (the default) no fetch callable is built and the endpoint stays
    entirely offline — no network path exists.
    """
    settings = get_settings()

    fetch_missing: Callable[[str], list[IngestedDocument]] | None = None
    if settings.allow_live_fetch:
        caching = CachingCveSource(
            NvdApiSource(api_key=settings.nvd_api_key, timeout=settings.nvd_fetch_timeout),
            settings.nvd_cache_dir,
        )

        def _fetch_missing(cve_id: str) -> list[IngestedDocument]:
            # caching.fetch_raw raises CveNotFound / CveUnavailable; a cache *hit* returns
            # bytes unvalidated, so re-parse here and map any failure to CveUnavailable
            # (a corrupt cache file must be a 503, never an unhandled 500).
            raw_bytes = caching.fetch_raw(cve_id)
            try:
                return nvd.load(raw_bytes)
            except Exception as exc:
                raise CveUnavailable(
                    f"cached NVD record for {cve_id} is unparseable: {exc}"
                ) from exc

        fetch_missing = _fetch_missing

    service = ResearchService(
        HashingEmbedder(),
        InMemoryVectorStore(),
        authorize,
        settings.audit_log_path,
        fetch_missing=fetch_missing,
    )
    raw = files("secure_ai_research.ingestion").joinpath("samples", "nvd_sample.json").read_bytes()
    service.index(nvd.load(raw))
    attack_raw = (
        files("secure_ai_research.ingestion").joinpath("samples", "attack_sample.json").read_bytes()
    )
    service.index(attack.load(attack_raw))
    kev_raw = (
        files("secure_ai_research.ingestion").joinpath("samples", "kev_sample.json").read_bytes()
    )
    service.index(kev.load(kev_raw))
    return service
