"""Parse and verify the control->evidence matrix.

The matrix (``documentation/assessment-evidence/control-evidence-matrix.md``) cites, in
backticks, the repo paths and pytest node ids that evidence each control. This module turns those
citations into sets and checks them against the working tree, so a renamed or deleted artifact
fails CI instead of leaving a dead citation behind. Pure + offline.
"""

from __future__ import annotations

import re
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
