"""Deterministic join generator (Phase 5, Slice 1a).

The default ``Generator``: it does not call a model. ``generate`` returns the id-tagged
passages joined by newlines — byte-for-byte the string the id-route assembled before the
Generator seam existed — so the deterministic/offline posture, the audit record, and the
Phase-4 1.0 evaluation gate are unchanged when no real generator is configured.

Its identity attributes report ``retrieval-only`` / empty, exactly the values the audit record
carried pre-change, so a default-path ``ResearchRecord`` stays byte-identical.
"""

from __future__ import annotations

from collections.abc import Sequence


class JoinGenerator:
    """Non-model generator: joins the id-tagged passages, preserving pre-seam output."""

    model_id = "retrieval-only"
    model_version = ""
    prompt_template_version = ""

    def generate(self, prompt: str, passages: Sequence[str]) -> str:
        return "\n".join(passages)
