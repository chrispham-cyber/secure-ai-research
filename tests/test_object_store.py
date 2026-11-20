"""Unit tests for the ObjectStore seam's in-memory implementation (Phase 5, Slice 3, Task 1).

These are hermetic and dependency-free: the in-memory store is the default/offline provenance
sink and the test double the rest of the suite builds on. The real MinioObjectStore (Task 3) has
its own guards and integration tests.
"""

from __future__ import annotations

import pytest

from secure_ai_research.storage.objectstore import InMemoryObjectStore
from secure_ai_research.storage.ports import ObjectStoreError


def test_put_then_get_round_trips():
    store = InMemoryObjectStore()
    key = "sha256:" + "a" * 64
    store.put(key, b"canonical-bytes")
    assert store.get(key) == b"canonical-bytes"


def test_put_is_idempotent_overwrite():
    # Content-addressed keys mean a boot re-index re-puts the same bytes; a second put of the
    # same key must overwrite, not error or duplicate.
    store = InMemoryObjectStore()
    store.put("k", b"one")
    store.put("k", b"two")
    assert store.get("k") == b"two"


def test_get_missing_key_raises_object_store_error():
    with pytest.raises(ObjectStoreError):
        InMemoryObjectStore().get("absent")
