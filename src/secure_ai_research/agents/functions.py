"""Agent-callable tools (ROADMAP Phase 3, Week 9).

Core rule: **the model may *request* a tool; the application independently decides whether
it is permitted — the checks live outside the LLM.** The model's output is treated as an
untrusted request, not an authorized command.

`AgentToolset` is the boundary object that enforces this. Trusted application code constructs
it with a **verified role** (never a value the model supplied); the model is handed the
instance and may call its tools with **data arguments only**. The role is bound at
construction and immutable — no tool method takes or honors a role argument — so a model
cannot grant itself access or change the principal it runs as. Each tool validates its
argument shape and then delegates to the ``ResearchService`` authorize-before-retrieve path,
which applies RBAC + ABAC and writes exactly one audit record per call.

This is the guard against excessive agency and confused-deputy escalation (threat-model
T7/T9); see [`infrastructure/identity/roles.md`](../../../infrastructure/identity/roles.md).
"""

from __future__ import annotations

import re

from secure_ai_research.research_service import ResearchResult, ResearchService

_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
_TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
_QUERY_MAX = 512


class AgentToolset:
    """A role-bound tool belt handed to a model.

    The ``role`` is fixed by trusted code at construction; tool methods take data arguments
    only. A structurally invalid argument is rejected (fail-loud, without echoing the raw
    value) before any retrieval or audit, so a malformed or hostile request from the model
    never reaches the service.
    """

    def __init__(self, service: ResearchService, *, role: str) -> None:
        self._service = service
        self._role = role

    def search_cve(self, cve_id: str) -> ResearchResult:
        """Correlate a CVE against public sources, if the bound role is permitted."""
        if not _CVE_ID.fullmatch(cve_id):
            raise ValueError("search_cve: cve_id is not a valid CVE identifier")
        return self._service.research_cve(cve_id, role=self._role)

    def search_attack(self, technique_id: str) -> ResearchResult:
        """Explain a MITRE ATT&CK technique, if the bound role is permitted."""
        if not _TECHNIQUE_ID.fullmatch(technique_id):
            raise ValueError("search_attack: technique_id is not a valid ATT&CK technique id")
        return self._service.research_attack(technique_id, role=self._role)

    def search_research(self, query: str) -> ResearchResult:
        """Evidence-grounded search over the authorized corpus, if the bound role is permitted."""
        cleaned = query.strip()
        if not 1 <= len(cleaned) <= _QUERY_MAX:
            raise ValueError(f"search_research: query must be 1-{_QUERY_MAX} characters")
        return self._service.search(cleaned, role=self._role)
