"""The control->evidence matrix is CI-enforced: every cited path exists, every cited node
collects. Filling the matrix with live citations is what turns this GREEN (Phase 5, Slice 6)."""

from __future__ import annotations

from pathlib import Path

from secure_ai_research.compliance.evidence import (
    missing_files,
    parse_evidence_matrix,
    skip_marked_nodes,
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
    # no cited test is silently disabled (skip/xfail collects + never fails → stale evidence)
    assert skip_marked_nodes(citations.test_nodes, _REPO) == []


def test_audit_detection_claim_is_backed_by_detection_tests():
    # AU-10 claims verify_chain "detects edit/reorder/forgery". A clean-chain verify does
    # not substantiate detection — the row must cite the tests that demonstrate it.
    citations = parse_evidence_matrix(_MATRIX.read_text(encoding="utf-8"))
    required = {
        "tests/test_audit_signing.py::test_tampered_record_detected",  # edit
        "tests/test_audit_signing.py::test_reordered_records_detected",  # reorder
        "tests/test_audit_signing.py::test_flipped_hmac_detected",  # forgery
    }
    missing = sorted(required - citations.test_nodes)
    assert missing == [], f"AU-10 detection claim not backed by cited tests: {missing}"
