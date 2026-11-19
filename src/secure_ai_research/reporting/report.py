"""Report rendering (ROADMAP Phase 2).

Render a research record into a human-reviewable report. Every claim must point
back to a retrieved document id: a line with no ``[id]`` citation — or one citing
an id that was not retrieved — is dropped, never shown as fact. The audit record
is the source of truth; the report is a view over it.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from secure_ai_research.audit.record import ResearchRecord

# A citation is a document id in square brackets that the renderer attaches to a
# claim. Matching only the id shape (not any `[...]`) keeps bracket tokens in the
# passage body — buf[256], [CWE-79], markdown links like [Phishing](url), tactic
# ids like [TA0001] — from being mistaken for citations and silently dropping a
# legitimately cited line. Two id schemes flow through build_report: NVD CVE ids
# and MITRE ATT&CK technique ids (T#### and sub-techniques T####.###).
_CITATION = re.compile(r"\[(CVE-\d{4}-\d{4,}|T\d{4}(?:\.\d{3})?)\]")


def build_report(record: ResearchRecord) -> str:
    """Render ``record`` into a cited report, dropping uncited claims.

    A claim line is kept only if it carries at least one ``[id]`` citation and
    **every** id it cites is in ``record.retrieved_doc_ids``. With no surviving
    claims the body reads ``No cited findings.``.
    """
    allowed = set(record.retrieved_doc_ids)
    kept: list[str] = []
    for raw_line in record.model_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        cited = _CITATION.findall(line)
        if cited and all(cid in allowed for cid in cited):
            kept.append(line)
    body = "\n".join(kept) if kept else "No cited findings."
    sources = ", ".join(record.retrieved_doc_ids)
    return f"# Research report: {record.objective}\n\n{body}\n\nSources: {sources}"
