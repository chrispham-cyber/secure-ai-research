"""Fail-closed-in-prod secret gate + redaction helper.

``verify_secrets`` is a no-op in dev (the default) so the platform runs on well-known
placeholders. In prod mode (``require_strong_secrets``) it refuses any *active* placeholder or
too-short secret, naming the setting but never the value, and overrides ``auth_allow_dev_secret``
(a prod deployment must not ship a dev auth secret). Only secrets of an *enabled* backend are
checked, so the default offline config is not tripped by the pgvector/minio placeholders.
"""

from __future__ import annotations

from collections.abc import Iterable

from secure_ai_research.config import Settings
from secure_ai_research.secret.ports import SecretError, SecretProvider

# The well-known dev placeholders (config defaults). A secret containing any of these, or shorter
# than _MIN_LEN, is "weak". ``sair:sair@`` is the credential embedded in the default db_url DSN.
PLACEHOLDERS: frozenset[str] = frozenset(
    {
        "sair:sair@",
        "minioadmin",
        "dev-insecure-change-me-not-for-production",
        "dev-audit-signing-key-change-me-not-for-production",
    }
)
_MIN_LEN = 16


def _is_weak(value: str | None) -> bool:
    if not value or len(value) < _MIN_LEN:
        return True
    return any(placeholder in value for placeholder in PLACEHOLDERS)


def redact(text: str, secrets: Iterable[str]) -> str:
    """Replace every non-empty secret substring in ``text`` with ``***``."""
    for secret in secrets:
        if secret:
            text = text.replace(secret, "***")
    return text


def verify_secrets(settings: Settings, provider: SecretProvider) -> None:
    """Raise :class:`SecretError` (naming the setting, never the value) on a weak active secret.

    No-op unless ``settings.require_strong_secrets``. Always checks the auth and audit-signing
    secrets; checks a backend's secret only when that backend is active.
    """
    if not settings.require_strong_secrets:
        return

    # auth_dev_secret is checked regardless of auth_allow_dev_secret: prod overrides the opt-in.
    checks: list[str] = ["auth_dev_secret", "audit_signing_key"]
    if settings.vector_store == "pgvector":
        checks.append("db_url")
    if settings.object_store == "minio":
        checks.extend(("minio_access_key", "minio_secret_key"))
    if settings.cipher == "fernet":
        checks.append("audit_encryption_key")

    for name in checks:
        if _is_weak(provider.get(name)):
            raise SecretError(
                f"{name} is a placeholder or too weak for production; "
                f"set a strong SAIR_{name.upper()}"
            )
