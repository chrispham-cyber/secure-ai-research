"""Runnable benchmark aggregate + methodology doc (Phase 4, Week 14)."""

from pathlib import Path

from secure_ai_research.evaluation.benchmark import main


def test_main_prints_guaranteed_invariants(capsys):
    rc = main()
    out = capsys.readouterr().out
    assert rc == 0
    assert "refusal_accuracy=1.0" in out or "'refusal_accuracy': 1.0" in out
    assert "grounding=1.0" in out or "'grounding': 1.0" in out


def test_methodology_doc_exists_and_names_reproduce_command():
    doc = Path("docs/phase4-evaluation-methodology.md").read_text()
    assert "python -m secure_ai_research.evaluation.benchmark" in doc
    assert "citation_accuracy" in doc and "grounding" in doc and "refusal" in doc
