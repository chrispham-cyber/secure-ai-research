"""In-transit posture checks + DSN sslmode knob (Phase 5, Slice 5, Task 4)."""

from __future__ import annotations

from secure_ai_research.config import Settings
from secure_ai_research.transit import apply_sslmode, check_transit_posture


def test_loopback_posture_has_no_warnings():
    assert check_transit_posture(Settings()) == []


def test_non_loopback_pgvector_without_ssl_warns():
    s = Settings(vector_store="pgvector", db_url="postgresql://u:p@db.example.com:5432/x")
    assert any("sslmode" in w or "pgvector" in w.lower() for w in check_transit_posture(s))


def test_sslmode_require_clears_pgvector_warning():
    s = Settings(
        vector_store="pgvector",
        db_url="postgresql://u:p@db.example.com:5432/x",
        db_sslmode="require",
    )
    assert check_transit_posture(s) == []


def test_non_loopback_minio_without_tls_warns():
    s = Settings(
        object_store="minio", minio_endpoint="minio.example.com:9000", minio_secure=False
    )
    assert check_transit_posture(s) != []


def test_apply_sslmode_appends_when_absent_and_preserves_when_present():
    assert apply_sslmode("postgresql://u:p@h/x", "require").endswith("sslmode=require")
    assert (
        apply_sslmode("postgresql://u:p@h/x?sslmode=verify-full", "require").count("sslmode") == 1
    )
