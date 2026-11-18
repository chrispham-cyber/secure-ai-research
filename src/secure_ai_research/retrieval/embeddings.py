"""Embeddings — **stub** (ROADMAP Phase 2).

Embed chunks with the local model named in settings. Embedding runs on the host
via Ollama; no chunk text is sent to a third-party service.
"""

from __future__ import annotations


def embed(chunks: list[str]) -> list[list[float]]:
    """Embed chunks into vectors with the local embedding model (not yet implemented)."""
    raise NotImplementedError(
        "Embeddings — ROADMAP Phase 2 (weeks 5-8): embed chunks with the local Ollama "
        "model from settings; no text leaves the host"
    )
