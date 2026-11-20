"""The three compliance docs ship filled, not as templates (Phase 5, Slice 6).

A light gate: no leftover template boilerplate. Substantive accuracy is covered by review and,
for the evidence matrix, by tests/test_control_evidence.py."""

from __future__ import annotations

from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_DOCS = [
    "documentation/system-security-plan/system-security-plan.md",
    "documentation/risk-assessment/risk-register.md",
    "documentation/assessment-evidence/control-evidence-matrix.md",
]
_MARKERS = [
    "TEMPLATE",
    "_…_",
    "Unfilled template",
    "Fill in Phase 5",
    "Fill each section in Phase 5",
]


@pytest.mark.parametrize("doc", _DOCS)
def test_no_unfilled_template_markers(doc):
    text = (_REPO / doc).read_text(encoding="utf-8")
    present = [m for m in _MARKERS if m in text]
    assert present == [], f"{doc} still has template markers: {present}"
