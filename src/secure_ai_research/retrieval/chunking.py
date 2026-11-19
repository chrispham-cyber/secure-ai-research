"""Chunking (ROADMAP Phase 2).

Split document text into deterministic, overlapping retrieval units small enough
to embed. Splitting is on whitespace boundaries so a chunk never ends mid-word;
the overlap carries a little context across the seam.
"""

from __future__ import annotations


def chunk(text: str, *, size: int = 800, overlap: int = 150) -> list[str]:
    """Split ``text`` into overlapping chunks of at most ``size`` characters.

    Words are kept whole. Consecutive chunks overlap by roughly ``overlap``
    characters' worth of trailing words. Empty / whitespace-only text yields
    ``[]``. A single word longer than ``size`` becomes its own (oversized) chunk.
    """
    words = text.split()
    if not words:
        return []
    chunks: list[str] = []
    start = 0
    while start < len(words):
        cur: list[str] = []
        i = start
        while i < len(words) and sum(len(w) for w in cur) + len(cur) + len(words[i]) <= size:
            cur.append(words[i])
            i += 1
        if not cur:  # a single word longer than size
            cur = [words[start]]
            i = start + 1
        chunks.append(" ".join(cur))
        if i >= len(words):
            break
        back = 0  # step back ~overlap characters' worth of whole words
        while back < len(cur) - 1 and sum(len(w) for w in cur[-(back + 1) :]) <= overlap:
            back += 1
        start = i - back
    return chunks
