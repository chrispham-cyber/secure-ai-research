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


_SKIP_MARK = re.compile(r"\bpytest\.mark\.(?:skip|xfail)\b")


def skip_marked_nodes(nodes: Iterable[str], repo_root: Path) -> list[str]:
    """Return the cited nodes disabled with ``@pytest.mark.skip``/``xfail``, sorted.

    Collection plus the suite miss one case: a cited test disabled with ``@skip``/``@xfail`` still
    collects (so :func:`uncollectable_nodes` stays clean) and never fails the suite, yet exercises
    nothing — the control's evidence has gone stale silently. A static scan of each cited test's
    decorator block closes that hole. ``skipif`` (a legitimate environment gate) is not flagged.
    """
    flagged: list[str] = []
    for node in nodes:
        file_part, _, test_part = node.partition("::")
        func = test_part.split("[", 1)[0]  # drop any parametrize suffix
        try:
            lines = (repo_root / file_part).read_text(encoding="utf-8").splitlines()
        except OSError:
            continue  # a missing/unreadable file is uncollectable_nodes' job, not this one
        idx = _def_line(lines, func)
        if idx is None:
            continue
        j = idx - 1
        while j >= 0:  # walk the contiguous decorator block directly above the def
            stripped = lines[j].strip()
            if stripped.startswith("@"):
                if _SKIP_MARK.search(lines[j]):
                    flagged.append(node)
                    break
                j -= 1
            elif stripped == "":
                j -= 1
            else:
                break
    return sorted(flagged)


def _def_line(lines: list[str], func: str) -> int | None:
    needle = f"def {func}("
    for i, line in enumerate(lines):
        if line.lstrip().startswith(needle):
            return i
    return None
