"""make_vector_store factory + SAIR_VECTOR_STORE setting (Phase 5, Slice 2, Task 3).

The default is the deterministic ``InMemoryVectorStore`` so the platform stays offline/hermetic
unless pgvector is explicitly selected. The pgvector branch is exercised only in the integration
tests (it connects), never constructed here.
"""

from __future__ import annotations

from secure_ai_research.config import Settings
from secure_ai_research.retrieval.factory import make_vector_store
from secure_ai_research.retrieval.vectorstore import InMemoryVectorStore


def test_default_is_in_memory():
    assert isinstance(make_vector_store(Settings(vector_store="memory")), InMemoryVectorStore)


def test_pgvector_setting_parses_from_env(monkeypatch):
    monkeypatch.setenv("SAIR_VECTOR_STORE", "pgvector")
    assert Settings().vector_store == "pgvector"


def test_default_settings_select_memory(monkeypatch):
    monkeypatch.delenv("SAIR_VECTOR_STORE", raising=False)
    assert Settings().vector_store == "memory"  # unchanged default — byte-identical wiring
