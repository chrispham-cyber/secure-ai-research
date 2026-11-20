"""Evidence-matrix citation parser + checkers (Phase 5, Slice 6)."""

from __future__ import annotations

from secure_ai_research.compliance.evidence import Citations, parse_evidence_matrix

_MATRIX = """
| Control | Claim | Evidence artifact | Where | Verified by |
|---------|-------|-------------------|-------|-------------|
| AC-3 | Authorize | `src/sair/authz.py` | `tests/test_a.py::test_denied` | test |
| SI-10 | NVD URL | see `https://nvd.nist.gov/x` | `tests/test_n.py::test_u[CVE-1]` | test |
| SC-7 | Loopback | `sslmode=require` enforced | config review | review |
"""


def test_parse_extracts_paths_and_nodes_ignoring_prose_and_urls():
    c = parse_evidence_matrix(_MATRIX)
    assert isinstance(c, Citations)
    assert c.files == frozenset({"src/sair/authz.py"})
    # a parametrized node id ([CVE-1]) still classifies as a node
    assert c.test_nodes == frozenset(
        {"tests/test_a.py::test_denied", "tests/test_n.py::test_u[CVE-1]"}
    )
    # a URL with '/' is NOT a repo path; prose 'sslmode=require' is neither a path nor a node
    assert not any("nvd.nist.gov" in f for f in c.files)
    assert "sslmode=require" not in c.files
