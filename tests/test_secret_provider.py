"""Secret-management seam (Phase 5, Slice 5, Task 1): env / file providers."""

from __future__ import annotations

import pytest

from secure_ai_research.config import Settings
from secure_ai_research.secret.env import EnvSecretProvider
from secure_ai_research.secret.file import FileSecretProvider
from secure_ai_research.secret.ports import SecretError


def test_env_provider_returns_configured_secret():
    s = Settings(minio_secret_key="s3kr3t-value-1234")
    assert EnvSecretProvider(s).get("minio_secret_key") == "s3kr3t-value-1234"


def test_env_provider_require_raises_on_empty():
    with pytest.raises(SecretError):
        EnvSecretProvider(Settings(audit_encryption_key="")).require("audit_encryption_key")


def test_file_provider_reads_and_missing_is_none(tmp_path):
    (tmp_path / "audit_signing_key").write_text("file-key-value-123456\n")
    p = FileSecretProvider(tmp_path)
    assert p.get("audit_signing_key") == "file-key-value-123456"
    assert p.get("absent") is None
