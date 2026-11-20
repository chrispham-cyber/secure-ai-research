"""Object-store implementations behind the :class:`ObjectStore` seam (Phase 5, Slice 3).

``InMemoryObjectStore`` is the deterministic, dependency-free default — the offline provenance
sink wired by default and the double the rest of the suite builds on. ``MinioObjectStore`` (added
in Task 3) is the opt-in real adapter that lazily imports the ``minio`` SDK; importing this module
never pulls ``minio`` in, so the default path and the hermetic suite stay dependency-free.
"""

from __future__ import annotations

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
