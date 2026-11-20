"""Evidence-matrix citation parser + checkers (Phase 5, Slice 6)."""

from __future__ import annotations

from pathlib import Path

from secure_ai_research.compliance.evidence import (
    Citations,
    missing_files,
    parse_evidence_matrix,
    uncollectable_nodes,
)

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


def test_missing_files_lists_only_absent(tmp_path):
    (tmp_path / "there.py").write_text("x = 1\n")
    assert missing_files(["there.py", "gone.py"], tmp_path) == ["gone.py"]


def test_missing_files_empty_when_all_present(tmp_path):
    (tmp_path / "a.py").write_text("")
    assert missing_files(["a.py"], tmp_path) == []


def test_uncollectable_nodes_flags_absent_node(tmp_path):
    (tmp_path / "test_tmp.py").write_text("def test_ok():\n    pass\n")
    assert uncollectable_nodes(["test_tmp.py::test_ok"], tmp_path) == []
    assert uncollectable_nodes(["test_tmp.py::test_nope"], tmp_path) == ["test_tmp.py::test_nope"]


def test_uncollectable_nodes_empty_input():
    assert uncollectable_nodes([], Path(".")) == []
