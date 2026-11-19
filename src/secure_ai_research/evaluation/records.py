"""Typed evaluation records (ROADMAP Phase 4, Week 13).

An ``EvalItem`` is one labeled benchmark case; an ``EvalResult`` pairs it with what the
**real** pipeline returned (outcome, citations, answer) so a metric can be computed over
structured fields rather than a flattened answer string. Both are frozen (immutable,
hashable) so a benchmark is a stable, comparable value.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from secure_ai_research.research_service import Outcome

ItemKind = Literal["cve", "attack", "search", "authz", "injection"]


class EvalItem(BaseModel):
    """One labeled benchmark case: a query + role + what the pipeline should do with it."""

    model_config = ConfigDict(frozen=True)

    id: str
    kind: ItemKind
    query: str
    role: str
    expected_outcome: Outcome
    gold_document_ids: frozenset[str]
    must_not_appear: frozenset[str] = frozenset()
    note: str = ""


class EvalResult(BaseModel):
    """An ``EvalItem`` paired with the real pipeline's response to it."""

    model_config = ConfigDict(frozen=True)

    item: EvalItem
    outcome: Outcome
    cited_ids: tuple[str, ...]
    retrieved_ids: tuple[str, ...]
    answer: str
