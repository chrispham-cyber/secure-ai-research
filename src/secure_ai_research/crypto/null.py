"""Identity cipher: the default, dependency-free, byte-identical-to-plaintext path."""

from __future__ import annotations


class NullCipher:
    """Returns its input unchanged — audit lines stay plaintext (signed) JSON."""

    def encrypt(self, data: bytes) -> bytes:
        return data

    def decrypt(self, token: bytes) -> bytes:
        return token
