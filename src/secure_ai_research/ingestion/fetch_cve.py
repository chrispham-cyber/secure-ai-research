"""Fetch one real CVE and research it through the existing pipeline.

``research_from_source`` is the reusable, source-agnostic core: it takes any ``CveSource``
(real, caching, or a test double), runs its bytes through ``nvd.load`` and a fresh
``ResearchService``, and returns the cited result. The default FastAPI app does not use
this path — it stays offline and fixture-backed.
"""

import argparse
from pathlib import Path

from secure_ai_research.config import get_settings
from secure_ai_research.ingestion import nvd
from secure_ai_research.ingestion.nvd_source import CachingCveSource, NvdApiSource
from secure_ai_research.ingestion.source import CveSource
from secure_ai_research.research_service import Outcome, ResearchResult, ResearchService
from secure_ai_research.retrieval.authz import authorize
from secure_ai_research.retrieval.embeddings import HashingEmbedder
from secure_ai_research.retrieval.vectorstore import InMemoryVectorStore


def research_from_source(
    cve_id: str, *, role: str, source: CveSource, audit_path: Path
) -> ResearchResult:
    svc = ResearchService(HashingEmbedder(), InMemoryVectorStore(), authorize, audit_path)
    svc.index(nvd.load(source.fetch_raw(cve_id)))
    return svc.research_cve(cve_id, role=role)


def main(argv: list[str] | None = None, *, source: CveSource | None = None) -> int:
    """CLI: ``python -m secure_ai_research.ingestion.fetch_cve CVE-XXXX [--role ...]``.

    ``source`` is injectable so tests stay hermetic; in production it defaults to a
    caching NVD client that hits the network only on a cache miss.
    """
    parser = argparse.ArgumentParser(
        prog="fetch_cve", description="Fetch one CVE from NVD and research it."
    )
    parser.add_argument("cve_id")
    parser.add_argument("--role", default="research_analyst")
    args = parser.parse_args(argv)

    settings = get_settings()
    if source is None:
        source = CachingCveSource(
            NvdApiSource(api_key=settings.nvd_api_key, timeout=settings.nvd_fetch_timeout),
            settings.nvd_cache_dir,
        )
    res = research_from_source(
        args.cve_id, role=args.role, source=source, audit_path=settings.audit_log_path
    )
    print(f"[{res.outcome.value}] {res.answer}")
    return 0 if res.outcome is Outcome.OK else 1


if __name__ == "__main__":
    raise SystemExit(main())
