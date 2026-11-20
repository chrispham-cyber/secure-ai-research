"""The control->evidence matrix is CI-enforced: every cited path exists, every cited node
collects. Filling the matrix with live citations is what turns this GREEN (Phase 5, Slice 6)."""

from __future__ import annotations

from pathlib import Path

from secure_ai_research.compliance.evidence import (
    missing_files,
    parse_evidence_matrix,
    uncollectable_nodes,
)

_REPO = Path(__file__).resolve().parents[1]
_MATRIX = _REPO / "documentation/assessment-evidence/control-evidence-matrix.md"


def test_every_cited_path_exists_and_every_cited_node_collects():
    citations = parse_evidence_matrix(_MATRIX.read_text(encoding="utf-8"))
    # not vacuous: the matrix must actually cite the system's controls, not an empty template
    assert len(citations.files) >= 8, "evidence matrix cites too few files — is it filled?"
    assert len(citations.test_nodes) >= 6, "evidence matrix cites too few tests — is it filled?"
    assert missing_files(citations.files, _REPO) == []
    assert uncollectable_nodes(citations.test_nodes, _REPO) == []
