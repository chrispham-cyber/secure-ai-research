"""Opt-in authenticated at-rest cipher (Fernet / AES-128-CBC + HMAC), behind the ``crypto`` extra.

``cryptography`` is imported lazily inside ``__init__`` so importing this module never pulls the
dependency: the hermetic default suite collects it but never loads ``cryptography``.
"""

from __future__ import annotations

from secure_ai_research.crypto.ports import CipherError


class FernetCipher:
    """Wraps a ``cryptography.fernet.Fernet`` built from a url-safe base64 key string."""

    def __init__(self, key: str) -> None:
        try:
            from cryptography.fernet import Fernet
        except ImportError as exc:  # extra not installed
            raise CipherError(
                "cipher 'fernet' requires the [crypto] extra: pip install -e '.[crypto]'"
            ) from exc
        try:
            self._fernet = Fernet(key.encode("ascii"))
        except Exception as exc:  # malformed key — never echo the key value
            raise CipherError("invalid Fernet key") from exc

    def encrypt(self, data: bytes) -> bytes:
        return self._fernet.encrypt(data)

    def decrypt(self, token: bytes) -> bytes:
        from cryptography.fernet import InvalidToken

        try:
            return self._fernet.decrypt(token)
        except InvalidToken as exc:
            raise CipherError("decrypt failed") from exc
