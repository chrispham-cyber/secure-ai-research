"""Research routers (ROADMAP Phase 2).

``GET /research/cve/{cve_id}`` is implemented: it runs the authorize-before-retrieve
pipeline and returns a cited answer, 403 when the caller's role may not retrieve, 404
when the CVE is not retrievable in the caller's scope (absent or unauthorized — the
same response either way, no existence oracle), and 422 (by path validation) when the
id is malformed. ``/attack`` and ``/search`` remain 501 pending later roadmap phases.
"""

from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Depends, Header, HTTPException, Path
from fastapi.responses import JSONResponse

from secure_ai_research.api.deps import get_service
from secure_ai_research.research_service import Outcome, ResearchService

router = APIRouter(prefix="/research", tags=["research"])

_NOT_IMPLEMENTED = "Not implemented — ROADMAP Phase 2 (weeks 5-8): evidence-grounded RAG"


@router.get("/cve/{cve_id}")
def research_cve(
    cve_id: str = Path(pattern=r"^CVE-\d{4}-\d{4,}$"),
    x_role: str = Header(default=""),
    service: ResearchService = Depends(get_service),
) -> JSONResponse:
    """Correlate a CVE against public sources, grounded in cited passages."""
    res = service.research_cve(cve_id, role=x_role)
    if res.outcome is Outcome.OK:
        return JSONResponse(
            status_code=200,
            content={
                "answer": res.answer,
                "citations": [asdict(c) for c in res.citations],
                "research_id": res.research_id,
            },
        )
    if res.outcome is Outcome.DENIED:
        return JSONResponse(
            status_code=403,
            content={"detail": "role not authorized", "research_id": res.research_id},
        )
    return JSONResponse(
        status_code=404,
        content={"detail": f"no document for {cve_id}", "research_id": res.research_id},
    )


@router.get("/attack/{technique_id}")
def research_attack(technique_id: str) -> dict[str, str]:
    """Explain an ATT&CK technique with cited sources (planned — Phase 2)."""
    raise HTTPException(status_code=501, detail=_NOT_IMPLEMENTED)


@router.post("/search")
def research_search() -> dict[str, str]:
    """Evidence-grounded semantic search over the corpus (planned — Phase 2)."""
    raise HTTPException(status_code=501, detail=_NOT_IMPLEMENTED)
