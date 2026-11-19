"""End-to-end cross-source correlation demo (ROADMAP Phase 2, Week 8).

Builds the full in-posture corpus offline (NVD + MITRE ATT&CK + CISA KEV + SigmaHQ fixtures,
the same loaders ``api/deps`` wires, minus the env-bound live fetch) and shows that a single
pivot — a CVE or an ATT&CK technique — pulls the *related* evidence from across those sources
through the real authorize-before-retrieve search path, with one audit record per pivot.

Run it::

    python -m secure_ai_research.demo.correlation

Correlation criterion: the in-posture :class:`HashingEmbedder` is a deterministic bag-of-words
placeholder (a real embedding model is the deferred Ollama line); it ranks the genuine matches at
the top but returns a noisy tail of documents sharing only a common token. The demo therefore keeps
the retrieved documents whose passage *explicitly references the pivot identifier* — the honest,
``limit``-independent way to show genuine cross-source correlation. Retrieval, scope, ranking, and
authorization are all done by :meth:`ResearchService.search`; the reference filter is only the
demo's analytical selection, not a re-ranking.
"""

from __future__ import annotations

import re
import tempfile
from importlib.resources import files
from pathlib import Path

from secure_ai_research.ingestion import attack, kev, nvd, sigma
from secure_ai_research.research_service import ResearchService
from secure_ai_research.retrieval.authz import authorize
from secure_ai_research.retrieval.embeddings import HashingEmbedder
from secure_ai_research.retrieval.vectorstore import InMemoryVectorStore

_SEARCH_LIMIT = 10  # > corpus size, so every referencing document is in the candidate set
_PIVOTS: list[tuple[str, str]] = [
    ("Log4Shell", "CVE-2021-44228"),
    ("Command and Scripting Interpreter", "T1059"),
]
_TECHNIQUE = re.compile(r"T\d")


def _source_of(document_id: str) -> str:
    """Map a document id's namespace to a human-readable source label."""
    if document_id.startswith("KEV-"):
        return "CISA KEV (known-exploited)"
    if document_id.startswith("SIGMA-"):
        return "SigmaHQ (detection)"
    if document_id.startswith("CVE-"):
        return "NVD (vulnerability)"
    if _TECHNIQUE.match(document_id):
        return "MITRE ATT&CK (technique)"
    return "other"


def build_offline_corpus(audit_path: Path) -> ResearchService:
    """Assemble the four-fixture Phase-2 corpus offline (no live fetch)."""
    service = ResearchService(HashingEmbedder(), InMemoryVectorStore(), authorize, audit_path)
    pkg = files("secure_ai_research.ingestion")
    for name, loader in (
        ("nvd_sample.json", nvd.load),
        ("attack_sample.json", attack.load),
        ("kev_sample.json", kev.load),
        ("sigma_sample.json", sigma.load),
    ):
        service.index(loader(pkg.joinpath("samples", name).read_bytes()))
    return service


def correlate(service: ResearchService, pivot: str) -> dict[str, list[str]]:
    """Retrieve for ``pivot`` and group the documents that reference it by source."""
    res = service.search(pivot, role="research_analyst", limit=_SEARCH_LIMIT)
    grouped: dict[str, list[str]] = {}
    for citation in res.citations:
        if pivot in citation.passage:  # the document genuinely references the pivot id
            grouped.setdefault(_source_of(citation.document_id), []).append(citation.document_id)
    return dict(sorted(grouped.items()))


def build_correlation_report(service: ResearchService, pivots: list[tuple[str, str]]) -> str:
    """Render a deterministic correlation report for each (label, pivot)."""
    lines: list[str] = ["# Phase-2 cross-source correlation", ""]
    for label, pivot in pivots:
        grouped = correlate(service, pivot)
        lines.append(f"## {label} — {pivot}")
        if grouped:
            for source, ids in grouped.items():
                lines.append(f"  - {source}: {', '.join(ids)}")
        else:
            lines.append("  (no correlated documents)")
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        service = build_offline_corpus(Path(tmp) / "audit.jsonl")
        print(build_correlation_report(service, _PIVOTS))


if __name__ == "__main__":
    main()
