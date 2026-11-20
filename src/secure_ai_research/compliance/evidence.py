"""Parse and verify the control->evidence matrix.

The matrix (``documentation/assessment-evidence/control-evidence-matrix.md``) cites, in
backticks, the repo paths and pytest node ids that evidence each control. This module turns those
citations into sets and checks them against the working tree, so a renamed or deleted artifact
fails CI instead of leaving a dead citation behind. Pure + offline.
"""

from __future__ import annotations

import re
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import NamedTuple

_BACKTICKED = re.compile(r"`([^`]+)`")
_NODE = re.compile(r"tests/.+\.py::.+")


class Citations(NamedTuple):
    """Checkable citations pulled from the evidence matrix."""

    files: frozenset[str]
    test_nodes: frozenset[str]


def parse_evidence_matrix(markdown: str) -> Citations:
    """Extract cited repo paths and pytest node ids from the matrix markdown.

    Only markdown table-data rows are read. Within a row, each backticked token is classified:
    a pytest node id (``tests/....py::...``) is a test node; a remaining token containing ``/`` is
    a repo path. Tokens with ``://`` (a URL) or whitespace (prose) are ignored, so a cited NVD URL
    or a phrase like ``sslmode=require`` is not mistaken for a file.
    """
    files: set[str] = set()
    nodes: set[str] = set()
    for line in markdown.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        if set(stripped) <= {"|", "-", ":", " "}:  # header separator row
            continue
        for token in _BACKTICKED.findall(line):
            if "://" in token or any(c.isspace() for c in token):
                continue
            if _NODE.fullmatch(token):
                nodes.add(token)
            elif "/" in token:
                files.add(token)
    return Citations(frozenset(files), frozenset(nodes))


def missing_files(files: Iterable[str], repo_root: Path) -> list[str]:
    """Return the cited paths (repo-root-relative) that do not exist, sorted."""
    return sorted(f for f in files if not (repo_root / f).exists())


def uncollectable_nodes(nodes: Iterable[str], repo_root: Path) -> list[str]:
    """Return the cited pytest node ids that pytest cannot collect, sorted.

    Collection (not execution) is the check: a node that collects exists and imports cleanly, and
    the same CI run that invokes this also runs those tests, so a *failing* cited test is caught by
    the suite, never silently. One batched ``--collect-only`` runs first; only if that is non-zero
    does it fall back to per-node runs to name precisely which citations are dead.
    """
    node_list = list(nodes)
    if not node_list:
        return []
    if _collect_ok(node_list, repo_root):
        return []
    return sorted(n for n in node_list if not _collect_ok([n], repo_root))


def _collect_ok(nodes: list[str], repo_root: Path) -> bool:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", *nodes],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0
