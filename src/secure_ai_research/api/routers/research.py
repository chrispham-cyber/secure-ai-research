"""Research routers (ROADMAP Phase 2).

``GET /research/cve/{cve_id}`` is implemented: it runs the authorize-before-retrieve
pipeline and returns a cited answer, 403 when the caller's role may not retrieve, 404
when the CVE is not retrievable in the caller's scope (absent or unauthorized — the
same response either way, no existence oracle), and 422 (by path validation) when the
id is malformed. ``GET /research/attack/{technique_id}`` mirrors it for MITRE ATT&CK
techniques (fixture-backed, no fetch — so no 503). ``POST /research/search`` ranks cited
passages across the whole authorized corpus (200 / 403, and 422 by body validation — no
404/503, since an empty result is a valid 200). ``POST /research/ask`` adds grounded LLM
synthesis over the same retrieval (200 / 403 / 422, plus 503 when the generator fails —
still no 404, since an empty retrieval is a valid 200 answered "No cited findings.").
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Path
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, StringConstraints

from secure_ai_research.api.deps import get_service
from secure_ai_research.research_service import Outcome, ResearchService

router = APIRouter(prefix="/research", tags=["research"])


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


class SearchRequest(BaseModel):
    """Body for ``POST /research/search``. A violation is a 422 raised by validation
    before the handler runs — so a malformed request never calls the service and writes
    no audit record."""

    query: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=512)]
    limit: int = Field(default=5, ge=1, le=20)


@router.post("/search")
def research_search(
    req: SearchRequest,
    x_role: str = Header(default=""),
    service: ResearchService = Depends(get_service),
) -> JSONResponse:
    """Ranked, cited search over the authorized corpus.

    Returns 200 with a ranked best-passage-per-document result list (empty results are a
    valid 200, not 404) and 403 when the caller's role may retrieve nothing. Each result
    carries a 1-based ``rank``; the internal cosine score is never surfaced.

    SECURITY: ``X-Role`` is a Phase-1 **self-asserted development stub, not an
    authentication control** — a client sets it freely (threat T1). It exists only to
    exercise the authorization boundary; Phase 5 replaces it with verified OIDC roles,
    downstream authz unchanged (see ``infrastructure/identity/roles.md``). Do not expose
    this route on a real network until then.
    """
    res = service.search(req.query, role=x_role, limit=req.limit)
    if res.outcome is Outcome.DENIED:
        return JSONResponse(
            status_code=403,
            content={"detail": "role not authorized", "research_id": res.research_id},
        )
    results = [{"rank": i + 1, **asdict(c)} for i, c in enumerate(res.citations)]
    return JSONResponse(
        status_code=200,
        content={
            "query": req.query,
            "count": len(results),
            "results": results,
            "research_id": res.research_id,
        },
    )


class AskRequest(BaseModel):
    """Body for ``POST /research/ask``. A violation is a 422 raised by validation before the
    handler runs — so a malformed request never calls the service and writes no audit record.
    Mirrors ``SearchRequest`` exactly."""

    query: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=512)]
    limit: int = Field(default=5, ge=1, le=20)


@router.post("/ask")
def research_ask(
    req: AskRequest,
    x_role: str = Header(default=""),
    service: ResearchService = Depends(get_service),
) -> JSONResponse:
    """Answer a free-text question with a grounded, cited report over the authorized corpus.

    Returns 200 with the synthesised answer and its citations (an empty retrieval is a valid
    200 whose answer reads ``No cited findings.``, never a 404), 403 when the caller's role may
    retrieve nothing, and 503 when the configured generator fails (fail-closed — no fabricated
    answer). 422 is raised by body validation before the handler, so a malformed request writes
    no audit record. The citations carry the cited id, source url, and passage — never the
    internal retrieval score.

    SECURITY: ``X-Role`` is a Phase-1 **self-asserted development stub, not an authentication
    control** — a client sets it freely (threat T1). It exists only to exercise the
    authorization boundary; Phase 5 replaces it with verified OIDC roles, downstream authz
    unchanged (see ``infrastructure/identity/roles.md``). Do not expose this route on a real
    network until then.
    """
    res = service.ask(req.query, role=x_role, limit=req.limit)
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
        status_code=200,
        content={
            "answer": res.answer,
            "citations": [asdict(c) for c in res.citations],
            "research_id": res.research_id,
        },
    )
