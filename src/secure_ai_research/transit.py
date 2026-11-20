"""In-transit encryption posture (Phase 5, Slice 5, Task 4).

The platform does not terminate TLS itself: uvicorn or a reverse proxy owns the client<->app hop
(``SAIR_REQUIRE_HTTPS`` documents the intent). What this module does is *flag* an active backend
whose link leaves the loopback host without TLS, and apply the one DSN knob we can set ourselves
(``sslmode``). It is advisory — ``check_transit_posture`` returns human-readable warnings; the
startup gate decides whether to log or refuse them.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from secure_ai_research.config import Settings

_LOOPBACK = {"localhost", "127.0.0.1", "::1", ""}


def _is_loopback(host: str) -> bool:
    return host in _LOOPBACK


def apply_sslmode(db_url: str, sslmode: str) -> str:
    """Append ``sslmode=<sslmode>`` to a Postgres DSN, unless empty or already present."""
    if not sslmode or "sslmode=" in db_url:
        return db_url
    separator = "&" if "?" in db_url else "?"
    return f"{db_url}{separator}sslmode={sslmode}"


def check_transit_posture(settings: Settings) -> list[str]:
    """Return one warning per active, non-loopback backend whose transport lacks TLS.

    Only *active* backends are checked (vector_store/object_store/auth), so the default offline
    config returns ``[]`` even though its placeholder DSNs point at loopback.
    """
    warnings: list[str] = []

    if settings.vector_store == "pgvector":
        host = urlsplit(settings.db_url).hostname or ""
        has_tls = "sslmode=require" in settings.db_url or settings.db_sslmode == "require"
        if not _is_loopback(host) and not has_tls:
            warnings.append(
                f"pgvector DSN host {host!r} is not loopback and has no TLS; "
                "set SAIR_DB_SSLMODE=require"
            )

    if settings.object_store == "minio":
        host = settings.minio_endpoint.split(":")[0]
        if not _is_loopback(host) and not settings.minio_secure:
            warnings.append(
                f"MinIO endpoint {host!r} is not loopback and not TLS; set SAIR_MINIO_SECURE=true"
            )

    if settings.auth == "oidc":
        parts = urlsplit(settings.oidc_issuer)
        if not _is_loopback(parts.hostname or "") and parts.scheme == "http":
            warnings.append(
                f"OIDC issuer {settings.oidc_issuer!r} uses http over a non-loopback host; use https"
            )

    return warnings
