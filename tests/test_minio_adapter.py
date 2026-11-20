"""Hermetic guards for the MinioObjectStore adapter (Phase 5, Slice 3, Task 3).

These never touch MinIO and must hold whether or not the ``minio`` extra is installed (the
integration run installs it in the same venv). They pin two posture guarantees mirroring the
pgvector adapter's guards:

1. importing the objectstore module must NOT import ``minio`` (lazy-import inside __init__);
2. constructing ``MinioObjectStore`` without the extra fails loud with an ``ObjectStoreError`` that
   names the extra to install — never a bare ImportError and never silent.
"""

from __future__ import annotations

import builtins
import importlib
import sys

import pytest

from secure_ai_research.storage.objectstore import MinioObjectStore
from secure_ai_research.storage.ports import ObjectStoreError


def test_importing_objectstore_does_not_import_minio():
    # Lazy-import posture: the module's top level must not pull minio in. If another test in this
    # process already imported minio, this can't be observed here — the missing-extra test below
    # enforces the real invariant (the import lives inside __init__).
    if "minio" in sys.modules:
        pytest.skip("minio already loaded by another test in this process")
    sys.modules.pop("secure_ai_research.storage.objectstore", None)
    importlib.import_module("secure_ai_research.storage.objectstore")
    assert "minio" not in sys.modules


def test_missing_extra_raises_clear_object_store_error(monkeypatch):
    # Force ImportError for minio regardless of whether it is installed, proving the adapter fails
    # loud with a remediation message (ObjectStoreError, not a bare ImportError, not silent).
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "minio" or name.startswith("minio."):
            raise ImportError("No module named 'minio'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ObjectStoreError) as exc:
        MinioObjectStore("localhost:9000", "key", "secret", "sair-raw")
    assert "minio" in str(exc.value).lower()  # names the extra to install
