"""Portfolio-currency guard: the front-door docs must reflect the finished platform.

The README and the now-real module docstrings described the Phase-1 scaffold long after
Phases 2-5 shipped. These checks pin the README's status/coverage/evidence claims and the
module docstrings to reality, and keep every relative link in the README resolvable. The one
honest fail-loud stub (``OllamaEmbedder``) is named with "fail-loud stub", not "documented
stub", so the docstring ban below does not flag it."""

from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_README = (_REPO / "README.md").read_text(encoding="utf-8")
_NORM = " ".join(_README.split())
_NOW_REAL = ["reporting", "ingestion", "agents", "ai_security", "retrieval", "evaluation"]


def test_readme_status_is_current():
    # the stale Phase-1 status line is gone (em-dash U+2014, as in the file)
    assert "Phase 1 — foundation scaffold" not in _NORM


def test_research_endpoints_not_described_as_501():
    # /research/* are implemented; the 501 claim (line-wrapped in the old README) is gone
    assert "501 Not Implemented" not in _NORM


def test_readme_shows_ci_and_coverage():
    assert "actions/workflows/ci.yml/badge.svg" in _README
    assert "485" in _README  # unit-test count (the -m "not integration" suite)


def test_readme_surfaces_compliance_evidence():
    assert "documentation/assessment-evidence/control-evidence-matrix.md" in _README


def test_readme_signing_claim_is_honest_about_pending_ceremony():
    # The cosign signing mechanism is wired + tested, but NO signature is committed
    # yet (the one-time key ceremony is pending) and the CI verify gate skips until
    # then. The README must not present the signature gate as already active, and
    # must name the ceremony hedge wherever it mentions signing.
    assert "cosign" in _NORM.lower()  # signing is documented
    assert "signature gates run in CI" not in _NORM  # the false present-tense claim
    assert "ceremony" in _NORM.lower()  # ...with the wired-but-pending hedge present


def test_now_real_module_docstrings_are_not_stale():
    # bans the substring "documented stub" (covers "documented stub(s)[ and test designs]");
    # the honest OllamaEmbedder note in retrieval uses "fail-loud stub", which does not match.
    for mod in _NOW_REAL:
        init = _REPO / "src/secure_ai_research" / mod / "__init__.py"
        text = init.read_text(encoding="utf-8").lower()
        assert "documented stub" not in text, f"{mod}/__init__.py still calls itself a stub"


def test_readme_names_generator_seam():
    # the generation opt-in seam must name its env var fully, like the other four SAIR_* seams
    assert "SAIR_GENERATOR" in _README


def test_readme_relative_links_resolve():
    # every relative markdown link resolves on disk (external http(s) and #anchors skipped)
    targets = re.findall(r"\]\(([^)]+)\)", _README)
    missing = []
    for t in targets:
        if t.startswith("http") or t.startswith("#"):
            continue
        path = t.split("#", 1)[0]
        if path and not (_REPO / path).exists():
            missing.append(t)
    assert missing == [], f"README has broken relative links: {missing}"
