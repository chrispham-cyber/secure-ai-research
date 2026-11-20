"""Report rendering (ROADMAP Phase 2).

Render a research record into a human-reviewable report. Every claim must point
back to a retrieved document id: a line with no ``[id]`` citation — or one citing
an id that was not retrieved — is dropped, never shown as fact. The audit record
is the source of truth; the report is a view over it.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from secure_ai_research.audit.record import ResearchRecord

# A citation is a document id in square brackets that the renderer attaches to a
# claim. Matching only the id shape (not any `[...]`) keeps bracket tokens in the
# passage body — buf[256], [CWE-79], markdown links like [Phishing](url), tactic
# ids like [TA0001] — from being mistaken for citations and silently dropping a
# legitimately cited line. Four id schemes flow through build_report: NVD CVE ids,
# MITRE ATT&CK technique ids (T#### and sub-techniques T####.###), CISA KEV ids
# (KEV-CVE-…, namespaced in kev.py), and Sigma rule ids (SIGMA-<uuid>, namespaced in
# sigma.py). The KEV-CVE- alternative precedes bare CVE- so the longer id wins; the
# `[`-anchor already prevents a bare-CVE match inside [KEV-CVE-…]. Widening is purely
# additive — the id-routes and search emit no KEV/Sigma bracket tokens, so their
# output and the Phase-4 metric inputs are unchanged (Slice 1b design §11).
_CITATION = re.compile(
    r"\[(KEV-CVE-\d{4}-\d{4,}|SIGMA-[0-9a-fA-F-]+|CVE-\d{4}-\d{4,}|T\d{4}(?:\.\d{3})?)\]"
)


def citation_ids(text: str) -> list[str]:
    """Return the CVE/ATT&CK citation ids in ``text`` (the single citation grammar).

    Shared by ``build_report`` and the Phase-4 evaluator so a metric measures exactly the
    citation semantics the report renders — one grammar, never a forked copy.
    """
    return _CITATION.findall(text)


_WORD = re.compile(r"[a-z0-9]+")


def _content_tokens(text: str) -> set[str]:
    """Lowercased alphanumeric word tokens of ``text`` with citation tokens removed.

    The shared ``[id]`` is stripped first, so a claim and its passage are not counted as
    overlapping merely because both name the id being cited.
    """
    return set(_WORD.findall(_CITATION.sub(" ", text).lower()))


def _is_faithful(
    line: str, cited: list[str], passages: Mapping[str, Sequence[str]], min_overlap: float
) -> bool:
    """True if ``line``'s claim tokens overlap at least one cited passage by ``min_overlap``.

    Overlap = |claim ∩ passage| / |claim|, maximized over the passages of the ids the line
    cites. A line with no claim tokens (citation only) is vacuously faithful.
    """
    claim = _content_tokens(line)
    if not claim:
        return True
    best = 0.0
    for cid in cited:
        for passage in passages.get(cid, ()):
            passage_tokens = _content_tokens(passage)
            if not passage_tokens:
                continue
            overlap = len(claim & passage_tokens) / len(claim)
            best = max(best, overlap)
    return best >= min_overlap


def build_report(
    record: ResearchRecord,
    passages: Mapping[str, Sequence[str]] | None = None,
    *,
    min_overlap: float = 0.3,
) -> str:
    """Render ``record`` into a cited report, dropping uncited — and unfaithful — claims.

    A claim line is kept only if it carries at least one ``[id]`` citation and **every** id it
    cites is in ``record.retrieved_doc_ids``. When ``passages`` (id -> its retrieved passage
    texts) is given, a surviving line is additionally dropped unless its claim tokens overlap at
    least one cited passage by ``min_overlap`` — a lenient floor that targets wholesale
    invention ("valid id + unsupported claim"), not paraphrase. ``passages=None`` disables the
    faithfulness check, giving byte-identical output to the pre-floor renderer. With no surviving
    claims the body reads ``No cited findings.``.
    """
    allowed = set(record.retrieved_doc_ids)
    kept: list[str] = []
    for raw_line in record.model_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        cited = citation_ids(line)
        if not (cited and all(cid in allowed for cid in cited)):
            continue
        if passages is not None and not _is_faithful(line, cited, passages, min_overlap):
            continue
        kept.append(line)
    body = "\n".join(kept) if kept else "No cited findings."
    sources = ", ".join(record.retrieved_doc_ids)
    return f"# Research report: {record.objective}\n\n{body}\n\nSources: {sources}"
