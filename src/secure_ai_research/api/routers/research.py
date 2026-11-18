"""Research routers — **not implemented in Phase 1**.

Every endpoint returns 501 with a pointer to the roadmap phase that will build
evidence-grounded retrieval. They exist now so the API surface — and the audit
and authorization wiring around it — can be reviewed before any retrieval or
inference code lands. A stub that returns a plausible answer would be worse than
no endpoint: it would look grounded while citing nothing.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/research", tags=["research"])

_NOT_IMPLEMENTED = "Not implemented — ROADMAP Phase 2 (weeks 5-8): evidence-grounded RAG"


@router.get("/cve/{cve_id}")
def research_cve(cve_id: str) -> dict[str, str]:
    """Correlate a CVE against public sources (planned — Phase 2)."""
    raise HTTPException(status_code=501, detail=_NOT_IMPLEMENTED)


@router.get("/attack/{technique_id}")
def research_attack(technique_id: str) -> dict[str, str]:
    """Explain an ATT&CK technique with cited sources (planned — Phase 2)."""
    raise HTTPException(status_code=501, detail=_NOT_IMPLEMENTED)


@router.post("/search")
def research_search() -> dict[str, str]:
    """Evidence-grounded semantic search over the corpus (planned — Phase 2)."""
    raise HTTPException(status_code=501, detail=_NOT_IMPLEMENTED)
