"""Embeddings (ROADMAP Phase 2).

``HashingEmbedder`` is a deterministic, dependency-free embedder used for hermetic
tests and the default app wiring this slice: it hashes word tokens into a
fixed-dimension bag-of-words vector and L2-normalizes it, so cosine similarity
reflects shared tokens. ``OllamaEmbedder`` is the real local-model adapter wired
in a later slice; it fails loud until then. No chunk text ever leaves the host.
"""

from __future__ import annotations

import hashlib
import math
import re

DIM = 256


def _bucket(token: str) -> int:
    return int.from_bytes(hashlib.sha1(token.encode("utf-8")).digest()[:4], "big") % DIM


class HashingEmbedder:
    """Deterministic bag-of-words hashing embedder (implements ``Embedder``)."""

    def embed(self, chunks: list[str]) -> list[list[float]]:
        out: list[list[float]] = []
        for text in chunks:
            vec = [0.0] * DIM
            for token in re.findall(r"[a-z0-9]+", text.lower()):
                vec[_bucket(token)] += 1.0
            norm = math.sqrt(sum(v * v for v in vec))
            out.append([v / norm for v in vec] if norm else vec)
        return out


class OllamaEmbedder:
    """Local embeddings via Ollama — real adapter, next slice."""

    def __init__(self) -> None:
        raise NotImplementedError(
            "Local embeddings via Ollama — ROADMAP Phase 2 (weeks 5-8): the next "
            "slice wires the real nomic-embed-text adapter; no text leaves the host"
        )
