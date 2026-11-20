"""SecretProvider seam contract."""

from __future__ import annotations

from typing import Protocol, runtime_checkable


class SecretError(Exception):
    """A secret is unset, empty, or (in prod) too weak. Never carries the secret value."""


@runtime_checkable
class SecretProvider(Protocol):
    """Resolves named secrets from some backing store (env, file, ...)."""

    def get(self, name: str) -> str | None:
        """Return the resolved secret, or None when unset/unknown."""
        ...

    def require(self, name: str) -> str:
        """Return the resolved secret, or raise :class:`SecretError` when unset/empty."""
        ...
