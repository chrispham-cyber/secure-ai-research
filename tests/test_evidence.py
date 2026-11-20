"""Evidence-matrix citation parser + checkers (Phase 5, Slice 6)."""

from __future__ import annotations

from pathlib import Path

from secure_ai_research.compliance.evidence import (
    Citations,
    missing_files,
    parse_evidence_matrix,
    skip_marked_nodes,
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


def test_skip_marked_nodes_flags_skip_and_xfail_but_not_skipif_or_plain(tmp_path):
    # A cited test disabled with @skip/@xfail collects (linter green) and never fails the
    # suite (CI green) while exercising nothing — silent stale evidence. Flag it.
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_marks.py").write_text(
        "import pytest\n\n"
        "@pytest.mark.skip(reason='disabled')\n"
        "def test_skipped():\n    assert True\n\n"
        "@pytest.mark.xfail\n"
        "def test_xf():\n    assert False\n\n"
        "@pytest.mark.skipif(False, reason='env gate')\n"
        "def test_skipif():\n    assert True\n\n"
        "def test_ok():\n    assert True\n",
        encoding="utf-8",
    )
    nodes = [
        "tests/test_marks.py::test_skipped",
        "tests/test_marks.py::test_xf",
        "tests/test_marks.py::test_skipif",  # env gate — legitimate, not flagged
        "tests/test_marks.py::test_ok",
    ]
    assert skip_marked_nodes(nodes, tmp_path) == [
        "tests/test_marks.py::test_skipped",
        "tests/test_marks.py::test_xf",
    ]


def test_skip_marked_nodes_empty_input():
    assert skip_marked_nodes([], Path(".")) == []
