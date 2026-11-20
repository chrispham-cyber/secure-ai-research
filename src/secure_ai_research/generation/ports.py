"""Generation ports (ROADMAP Phase 4 Week 16 — deferred seam).

The Protocol a future text generator implements so the evaluation harness can measure model
behavior (grounding, refusal, injection-following) without the rest of the system knowing which
backend produced the text. No concrete generator exists in posture — the platform is
deterministic and offline — so this seam is wired and tested with fakes; a real Ollama/LLM
adapter implements the same shape in Phase 5, exactly as the retrieval ports decouple
``ResearchService`` from a concrete embedder/vector store today.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable


@runtime_checkable
class Generator(Protocol):
    """Produces an answer string from a prompt and the retrieved passages it may ground on."""

    def generate(self, prompt: str, passages: Sequence[str]) -> str: ...
