"""Fail-closed-in-prod secret gate (Phase 5, Slice 5, Task 1)."""

from __future__ import annotations

import pytest

from secure_ai_research.config import Settings
from secure_ai_research.secret.factory import make_secret_provider
from secure_ai_research.secret.ports import SecretError
from secure_ai_research.secret.verify import redact, verify_secrets


def test_verify_secrets_noop_in_dev():
    verify_secrets(Settings(), make_secret_provider(Settings()))  # no raise


def test_verify_secrets_raises_on_placeholder_audit_key_in_prod():
    # auth_dev_secret made strong so the audit key is the lone weak secret that trips the gate.
    s = Settings(require_strong_secrets=True, auth_dev_secret="y" * 32)
    with pytest.raises(SecretError):
        verify_secrets(s, make_secret_provider(s))


def test_verify_secrets_message_names_setting_not_value():
    s = Settings(require_strong_secrets=True, auth_dev_secret="y" * 32)
    try:
        verify_secrets(s, make_secret_provider(s))
    except SecretError as exc:
        assert s.audit_signing_key not in str(exc)
        assert "audit_signing_key" in str(exc)
    else:
        pytest.fail("expected SecretError")


def test_verify_secrets_skips_inactive_backend():
    # db_url/minio are placeholders but their backends are OFF (memory) -> ignored.
    s = Settings(require_strong_secrets=True, audit_signing_key="x" * 32, auth_dev_secret="y" * 32)
    verify_secrets(s, make_secret_provider(s))  # no raise


def test_verify_secrets_checks_db_url_when_pgvector():
    s = Settings(
        require_strong_secrets=True,
        vector_store="pgvector",
        audit_signing_key="x" * 32,
        auth_dev_secret="y" * 32,
    )
    with pytest.raises(SecretError):  # db_url still carries the sair:sair@ placeholder
        verify_secrets(s, make_secret_provider(s))


def test_verify_secrets_overrides_auth_allow_dev_secret():
    s = Settings(
        require_strong_secrets=True,
        auth_allow_dev_secret=True,
        audit_signing_key="x" * 32,
    )
    with pytest.raises(SecretError):  # prod refuses the dev auth secret despite the opt-in
        verify_secrets(s, make_secret_provider(s))


def test_verify_secrets_file_provider_checks_the_source_each_consumer_uses(tmp_path):
    # Only the audit secret is wired through the SecretProvider seam; make_object_store reads
    # Settings directly. With strong secrets in the files but the minio placeholder still in
    # Settings, the gate must fail on the source the consumer ACTUALLY uses (env), not give a false
    # green off the file it validated.
    for name in ("audit_signing_key", "auth_dev_secret", "minio_access_key", "minio_secret_key"):
        (tmp_path / name).write_text("strong-file-value-0123456789")
    s = Settings(
        require_strong_secrets=True,
        secret_provider="file",
        secret_dir=tmp_path,
        object_store="minio",
        auth_dev_secret="z" * 32,  # strong in Settings too, so minio is the lone weak env secret
    )
    with pytest.raises(SecretError, match="minio"):
        verify_secrets(s, make_secret_provider(s))


def test_redact_replaces_known_secret():
    assert "s3kr3t" not in redact("token=s3kr3t end", ["s3kr3t"])
