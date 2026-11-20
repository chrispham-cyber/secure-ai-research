"""Hermetic guards for the PgVectorStore adapter (Phase 5, Slice 2, Task 4).

These never touch Postgres and must hold whether or not the ``pgvector`` extra is installed
(the integration run installs it in the same venv). They pin two posture guarantees:

1. importing the vectorstore module must NOT import ``psycopg`` (lazy-import inside __init__);
2. constructing ``PgVectorStore`` without the extra fails loud with a ``VectorStoreError`` that
   names the extra to install — never a bare ImportError and never silent.
"""

from __future__ import annotations

import builtins
import importlib
import sys

import pytest

from secure_ai_research.retrieval.ports import VectorStoreError
from secure_ai_research.retrieval.vectorstore import PgVectorStore

_DSN = "postgresql://sair:sair@localhost:5432/sair"


def test_importing_vectorstore_does_not_import_psycopg():
    # Lazy-import posture: the module's top level must not pull psycopg in. If another test in
    # this process already imported psycopg, this guarantee can't be observed here — the
    # missing-extra test below enforces the real invariant (import lives inside __init__).
    if "psycopg" in sys.modules:
        pytest.skip("psycopg already loaded by another test in this process")
    sys.modules.pop("secure_ai_research.retrieval.vectorstore", None)
    importlib.import_module("secure_ai_research.retrieval.vectorstore")
    assert "psycopg" not in sys.modules


def test_missing_extra_raises_clear_vector_store_error(monkeypatch):
    # Force ImportError for psycopg regardless of whether it is installed, proving the adapter
    # fails loud with a remediation message (VectorStoreError, not a bare ImportError, not silent).
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "psycopg" or name.startswith("psycopg"):
            raise ImportError("No module named 'psycopg'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(VectorStoreError) as exc:
        PgVectorStore(_DSN)
    assert "pgvector" in str(exc.value).lower()  # names the extra to install
