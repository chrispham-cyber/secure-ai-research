"""Research routers (ROADMAP Phase 2).

``GET /research/cve/{cve_id}`` is implemented: it runs the authorize-before-retrieve
pipeline and returns a cited answer, 403 when the caller's role may not retrieve, 404
when the CVE is not retrievable in the caller's scope (absent or unauthorized — the
same response either way, no existence oracle), and 422 (by path validation) when the
id is malformed. ``GET /research/attack/{technique_id}`` mirrors it for MITRE ATT&CK
techniques (fixture-backed, no fetch — so no 503). ``/search`` remains 501 pending a
later roadmap phase.
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
    """Correlate a CVE against public sources, grounded in cited passages.

    SECURITY: ``X-Role`` is a Phase-1 **self-asserted development stub, not an
    authentication control** — a client sets it freely (threat T1). It exists only
    to exercise the authorization boundary; Phase 5 replaces it with verified OIDC
    roles, downstream authz unchanged (see ``infrastructure/identity/roles.md``). Do
    not expose this route on a real network until then.
    """
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
    if res.outcome is Outcome.FETCH_ERROR:
        return JSONResponse(
            status_code=503,
            content={"detail": "upstream source unavailable", "research_id": res.research_id},
        )
    return JSONResponse(
        status_code=404,
        content={"detail": f"no document for {cve_id}", "research_id": res.research_id},
    )


@router.get("/attack/{technique_id}")
def research_attack(
    technique_id: str = Path(pattern=r"^T\d{4}(\.\d{3})?$"),
    x_role: str = Header(default=""),
    service: ResearchService = Depends(get_service),
) -> JSONResponse:
    """Explain a MITRE ATT&CK technique, grounded in cited passages.

    Fixture-backed only — no live fetch — so the outcomes are 200 / 403 / 404 (and
    422 by path validation); there is no 503 path here, unlike ``/cve``.

    SECURITY: ``X-Role`` is a Phase-1 **self-asserted development stub, not an
    authentication control** — a client sets it freely (threat T1). It exists only
    to exercise the authorization boundary; Phase 5 replaces it with verified OIDC
    roles, downstream authz unchanged (see ``infrastructure/identity/roles.md``). Do
    not expose this route on a real network until then.
    """
    res = service.research_attack(technique_id, role=x_role)
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
        content={"detail": f"no document for {technique_id}", "research_id": res.research_id},
    )


@router.post("/search")
def research_search() -> dict[str, str]:
    """Evidence-grounded semantic search over the corpus (planned — Phase 2)."""
    raise HTTPException(status_code=501, detail=_NOT_IMPLEMENTED)
