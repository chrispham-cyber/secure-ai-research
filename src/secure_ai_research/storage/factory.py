"""Object-store selection (Phase 5, Slice 3).

Maps ``Settings`` to a concrete ``ObjectStore``. The default is the deterministic, dependency-free
``InMemoryObjectStore`` so the platform stays offline/hermetic unless MinIO is explicitly
configured via ``SAIR_OBJECT_STORE=minio`` (which requires the ``minio`` extra). The real adapter
is imported lazily, inside the minio branch only, so the default path and the hermetic suite never
import the ``minio`` SDK.
"""

from __future__ import annotations

from secure_ai_research.config import Settings
from secure_ai_research.storage.objectstore import InMemoryObjectStore
from secure_ai_research.storage.ports import ObjectStore


def make_object_store(settings: Settings) -> ObjectStore:
    """Return the store that ``settings.object_store`` selects (default: in-memory)."""
    if settings.object_store == "minio":
        from secure_ai_research.storage.objectstore import MinioObjectStore

        return MinioObjectStore(
            settings.minio_endpoint,
            settings.minio_access_key,
            settings.minio_secret_key,
            settings.minio_bucket,
            secure=settings.minio_secure,
        )
    return InMemoryObjectStore()
