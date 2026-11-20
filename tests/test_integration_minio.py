"""Integration tests for the real MinioObjectStore adapter (Phase 5, Slice 3, Task 3).

Marked ``integration`` → excluded from the default hermetic run and from CI; run with
``-m integration`` against a live MinIO (``docker compose up -d minio``) with the ``minio`` extra
installed (``pip install -e '.[minio]'``). They SKIP cleanly when the minio SDK or a reachable
MinIO is absent.

IMPORTANT: ``minio`` is imported only INSIDE functions, never at module top — deselected files are
still collected (imported), so a top-level ``import minio`` would break the hermetic run.
"""

from __future__ import annotations

import uuid

import pytest

from secure_ai_research.storage.objectstore import MinioObjectStore
from secure_ai_research.storage.ports import ObjectStoreError

pytestmark = pytest.mark.integration

_ENDPOINT = "localhost:9000"
_ACCESS = "minioadmin"
_SECRET = "minioadmin"


def _require_minio() -> None:
    pytest.importorskip("minio")
    from minio import Minio

    try:
        Minio(_ENDPOINT, access_key=_ACCESS, secret_key=_SECRET, secure=False).list_buckets()
    except Exception as exc:  # noqa: BLE001 - any failure means "minio not available here"
        pytest.skip(f"MinIO not reachable: {type(exc).__name__}")


@pytest.fixture
def bucket() -> str:
    _require_minio()
    # A fresh bucket per test keeps runs isolated without a cross-test truncate.
    return "sair-test-" + uuid.uuid4().hex[:12]


def test_put_then_get_round_trips(bucket: str) -> None:
    store = MinioObjectStore(_ENDPOINT, _ACCESS, _SECRET, bucket)
    key = "sha256:" + "a" * 64
    store.put(key, b"canonical-provenance-bytes")
    assert store.get(key) == b"canonical-provenance-bytes"


def test_ensure_bucket_is_idempotent(bucket: str) -> None:
    MinioObjectStore(_ENDPOINT, _ACCESS, _SECRET, bucket)  # creates the bucket
    MinioObjectStore(_ENDPOINT, _ACCESS, _SECRET, bucket)  # bucket_exists → no make, no error


def test_put_is_idempotent_overwrite(bucket: str) -> None:
    store = MinioObjectStore(_ENDPOINT, _ACCESS, _SECRET, bucket)
    store.put("k", b"one")
    store.put("k", b"two")  # same object name → overwrite, not a second object
    assert store.get("k") == b"two"


def test_bad_endpoint_raises_object_store_error() -> None:
    _require_minio()  # minio must be importable + a real server up; the endpoint below is bad
    with pytest.raises(ObjectStoreError):
        MinioObjectStore("127.0.0.1:1", "x", "y", "nope")
