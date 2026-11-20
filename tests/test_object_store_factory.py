"""``make_object_store`` maps ``Settings`` to a concrete ObjectStore (Phase 5, Slice 3, Task 4).

Default is the dependency-free in-memory store; ``SAIR_OBJECT_STORE=minio`` routes to the real
adapter. The minio branch is proven WITHOUT a live connection by patching the lazily-imported
adapter class — so the test stays hermetic and fast (no 20s connect-retry).
"""

from __future__ import annotations

from secure_ai_research.config import Settings
from secure_ai_research.storage.factory import make_object_store
from secure_ai_research.storage.objectstore import InMemoryObjectStore


def test_default_is_in_memory():
    assert isinstance(make_object_store(Settings()), InMemoryObjectStore)


def test_minio_selected_by_env(monkeypatch):
    monkeypatch.setenv("SAIR_OBJECT_STORE", "minio")
    captured: dict[str, tuple] = {}

    class _FakeMinio:
        def __init__(self, endpoint, access_key, secret_key, bucket, **kw):  # noqa: ANN001,ANN204
            captured["args"] = (endpoint, access_key, secret_key, bucket)

    # the factory lazily imports MinioObjectStore from this module → patch it there, so no live
    # client is ever built.
    monkeypatch.setattr("secure_ai_research.storage.objectstore.MinioObjectStore", _FakeMinio)
    store = make_object_store(Settings())
    assert isinstance(store, _FakeMinio)
    assert captured["args"][3] == "sair-raw"  # bucket comes from settings, not hardcoded
