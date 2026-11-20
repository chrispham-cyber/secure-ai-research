"""Object-store implementations behind the :class:`ObjectStore` seam (Phase 5, Slice 3).

``InMemoryObjectStore`` is the deterministic, dependency-free default — the offline provenance
sink wired by default and the double the rest of the suite builds on. ``MinioObjectStore`` (added
in Task 3) is the opt-in real adapter that lazily imports the ``minio`` SDK; importing this module
never pulls ``minio`` in, so the default path and the hermetic suite stay dependency-free.
"""

from __future__ import annotations

import io
from typing import Any

from secure_ai_research.storage.ports import ObjectStoreError


class InMemoryObjectStore:
    """Dict-backed ObjectStore (implements ``ObjectStore``): deterministic, offline, no network."""

    def __init__(self) -> None:
        self._objects: dict[str, bytes] = {}

    def put(self, key: str, data: bytes) -> None:
        self._objects[key] = data

    def get(self, key: str) -> bytes:
        try:
            return self._objects[key]
        except KeyError as exc:
            raise ObjectStoreError(f"object not found: {key}") from exc


class MinioObjectStore:
    """MinIO/S3-backed ObjectStore (implements ``ObjectStore``).

    Opt-in backend selected by ``SAIR_OBJECT_STORE=minio``. The ``minio`` SDK is imported lazily
    (inside ``__init__``), so importing this module never pulls it in and the default in-memory
    path stays dependency-free. A missing ``minio`` extra, or any bucket/put/get fault, is raised
    as an ``ObjectStoreError`` carrying only an exception-type tag — never object bytes or a
    backend message — so the service fails closed and nothing leaks into the audit trail.

    Content-addressed: the object name is the key with ``:`` → ``/``, so an ``integrity_hash``
    ``sha256:<hex>`` lands at ``sha256/<hex>``. ``put`` is an idempotent overwrite.
    """

    def __init__(
        self,
        endpoint: str,
        access_key: str,
        secret_key: str,
        bucket: str,
        *,
        secure: bool = False,
    ) -> None:
        self._bucket = bucket
        self._client = self._make_client(endpoint, access_key, secret_key, secure)
        self._ensure_bucket()

    @staticmethod
    def _make_client(endpoint: str, access_key: str, secret_key: str, secure: bool) -> Any:
        """Build the MinIO client, or fail loud with remediation if the extra is absent."""
        try:
            from minio import Minio
        except ImportError as exc:
            raise ObjectStoreError(
                "minio extra not installed: pip install '.[minio]'"
            ) from exc
        return Minio(endpoint, access_key=access_key, secret_key=secret_key, secure=secure)

    def _ensure_bucket(self) -> None:
        try:
            if not self._client.bucket_exists(self._bucket):
                self._client.make_bucket(self._bucket)
        except Exception as exc:
            raise ObjectStoreError(f"bucket init failed ({type(exc).__name__})") from exc

    @staticmethod
    def _name(key: str) -> str:
        return key.replace(":", "/")

    def put(self, key: str, data: bytes) -> None:
        try:
            self._client.put_object(
                self._bucket, self._name(key), io.BytesIO(data), length=len(data)
            )
        except Exception as exc:
            raise ObjectStoreError(f"put failed ({type(exc).__name__})") from exc

    def get(self, key: str) -> bytes:
        try:
            resp = self._client.get_object(self._bucket, self._name(key))
            try:
                return bytes(resp.read())
            finally:
                resp.close()
                resp.release_conn()
        except Exception as exc:
            raise ObjectStoreError(f"get failed ({type(exc).__name__})") from exc
