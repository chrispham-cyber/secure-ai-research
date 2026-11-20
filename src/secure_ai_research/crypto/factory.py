"""Selects the at-rest Cipher from settings: ``none`` (default) or ``fernet``."""

from __future__ import annotations

from secure_ai_research.config import Settings
from secure_ai_research.crypto.null import NullCipher
from secure_ai_research.crypto.ports import Cipher
from secure_ai_research.secret.ports import SecretProvider


def make_cipher(settings: Settings, provider: SecretProvider) -> Cipher:
    if settings.cipher == "fernet":
        # Lazy import keeps `cryptography` off the default path.
        from secure_ai_research.crypto.fernet import FernetCipher

        return FernetCipher(provider.require("audit_encryption_key"))
    return NullCipher()
