"""The ObjectStore seam: its Protocol and error type (Phase 5, Slice 3).

A content-addressed store for the raw provenance payloads behind every document's integrity hash.
The ``key`` is a document's ``integrity_hash`` verbatim (``sha256:<64hex>``); ``put`` is an
idempotent overwrite (the same key always carries the same bytes). Any missing object or any
backend/connection fault is raised as :class:`ObjectStoreError` carrying an exception-type tag
only — never a backend message or payload — so the service can fail closed without leaking.
"""

from __future__ import annotations

from typing import Protocol


class ObjectStore(Protocol):
    """Content-addressed blob store for raw provenance payloads."""

    def put(self, key: str, data: bytes) -> None: ...

    def get(self, key: str) -> bytes: ...


class ObjectStoreError(Exception):
    """A missing object, or any store/connection fault (exception-type tag only, no leak)."""
