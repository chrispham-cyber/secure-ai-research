"""Cipher seam contract."""

from __future__ import annotations

from typing import Protocol, runtime_checkable


class CipherError(Exception):
    """An at-rest cipher could not be built or applied. Type-tag only — never a key/plaintext."""


@runtime_checkable
class Cipher(Protocol):
    """Reversibly transforms bytes at rest."""

    def encrypt(self, data: bytes) -> bytes:
        """Return the ciphertext for ``data``."""
        ...

    def decrypt(self, token: bytes) -> bytes:
        """Return the plaintext for ``token``, or raise :class:`CipherError`."""
        ...
