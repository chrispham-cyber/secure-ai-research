"""Environment-backed SecretProvider: reads the already-parsed ``Settings`` (today's behaviour)."""

from __future__ import annotations

from secure_ai_research.config import Settings
from secure_ai_research.secret.ports import SecretError

# Explicit name -> Settings attribute map. No getattr on arbitrary input: an unknown name is a
# miss (None), never an attribute probe into the settings object.
_NAME_TO_ATTR: dict[str, str] = {
    "db_url": "db_url",
    "minio_access_key": "minio_access_key",
    "minio_secret_key": "minio_secret_key",
    "auth_dev_secret": "auth_dev_secret",
    "audit_signing_key": "audit_signing_key",
    "audit_encryption_key": "audit_encryption_key",
}


class EnvSecretProvider:
    """Resolves managed secrets from the ``SAIR_*``-populated :class:`Settings`."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def get(self, name: str) -> str | None:
        attr = _NAME_TO_ATTR.get(name)
        if attr is None:
            return None
        value = getattr(self._settings, attr)
        return value if value else None

    def require(self, name: str) -> str:
        value = self.get(name)
        if not value:
            raise SecretError(f"secret {name} is unset")
        return value
