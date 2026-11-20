"""Selects the SecretProvider from settings: ``env`` (default) or ``file``."""

from __future__ import annotations

from secure_ai_research.config import Settings
from secure_ai_research.secret.env import EnvSecretProvider
from secure_ai_research.secret.file import FileSecretProvider
from secure_ai_research.secret.ports import SecretProvider


def make_secret_provider(settings: Settings) -> SecretProvider:
    if settings.secret_provider == "file":
        return FileSecretProvider(settings.secret_dir)
    return EnvSecretProvider(settings)
