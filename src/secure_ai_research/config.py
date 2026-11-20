"""Typed configuration for the research platform.

All values come from environment variables (prefix ``SAIR_``) or a local ``.env``
file, with dev-friendly defaults that match ``docker-compose.yml`` so the stack
runs with zero configuration. Secrets here are well-known *dev* placeholders;
real deployments override them via the environment and never commit a ``.env``.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Platform settings, populated from ``SAIR_*`` env vars / ``.env``."""

    model_config = SettingsConfigDict(
        env_prefix="SAIR_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        # ``model_registry_path`` would otherwise collide with pydantic's
        # protected ``model_`` namespace.
        protected_namespaces=(),
    )

    db_url: str = "postgresql://sair:sair@localhost:5432/sair"
    # Vector-store backend behind the VectorStore seam. "memory" (default) is the deterministic
    # in-memory store — offline/hermetic, no dependency; "pgvector" uses Postgres/pgvector at
    # db_url (opt-in, requires the `pgvector` extra). Default keeps the platform offline.
    vector_store: Literal["memory", "pgvector"] = "memory"
    # Object-store backend behind the ObjectStore seam. "memory" (default) is the deterministic
    # in-memory provenance sink — offline/hermetic, no dependency; "minio" persists raw canonical
    # payloads to MinIO/S3 at minio_* (opt-in, requires the `minio` extra). Default keeps the
    # platform offline.
    object_store: Literal["memory", "minio"] = "memory"
    minio_endpoint: str = "localhost:9000"
    minio_access_key: str = "minioadmin"
    minio_secret_key: str = "minioadmin"
    minio_bucket: str = "sair-raw"
    ollama_host: str = "http://localhost:11434"
    embedding_model: str = "nomic-embed-text"
    # Text-generation backend behind the Generator seam. "join" (default) is the deterministic
    # non-LLM generator — byte-identical to the pre-LLM id-route; "ollama" calls a local model.
    generator: Literal["join", "ollama"] = "join"
    generation_model: str = "mistral:latest"
    model_registry_path: Path = Path("infrastructure/model-runtime/model-registry.json")
    audit_log_path: Path = Path("audit/research-records.jsonl")

    # NVD fetch (opt-in). Defaults keep the platform offline — nothing auto-fetches;
    # the base URL is a pinned constant in nvd_source.py, not a setting.
    nvd_api_key: str | None = None
    nvd_cache_dir: Path = Path("data/nvd-cache")
    nvd_fetch_timeout: float = 30.0
    # Opt-in: when true, the live /research/cve/{id} endpoint may fetch a CVE absent from
    # the corpus from NVD. Default false keeps the endpoint fully offline/fixture-backed.
    allow_live_fetch: bool = False

    # This repository handles public/synthetic data only. The classification is
    # pinned to PUBLIC on purpose; an LLM never decides a document's class.
    data_classification: Literal["PUBLIC"] = "PUBLIC"

    # --- Identity / authentication (Slice 4) ---
    # Auth mode. "local" (default) verifies a Bearer HS256 token with auth_dev_secret — offline,
    # stdlib, no Keycloak needed, and the role is *authenticated* not self-asserted. "oidc"
    # verifies an RS256 token against a Keycloak realm (opt-in, requires the `oidc` extra).
    # "insecure" restores the pre-Slice-4 self-asserted X-Role header (dev only; factory warns).
    auth: Literal["local", "oidc", "insecure"] = "local"
    # Shared secret for `local` HS256 verification. The default is a well-known placeholder; the
    # identity factory fails closed on it (and on any secret < 16 chars) unless
    # auth_allow_dev_secret is set, so a real deployment must override SAIR_AUTH_DEV_SECRET.
    auth_dev_secret: str = "dev-insecure-change-me-not-for-production"
    auth_allow_dev_secret: bool = False
    # The token claim carrying the role string (both local and oidc).
    auth_role_claim: str = "role"
    # OIDC/Keycloak resource-server settings (used only when auth == "oidc").
    oidc_issuer: str = "http://localhost:8080/realms/sair"
    oidc_jwks_url: str = "http://localhost:8080/realms/sair/protocol/openid-connect/certs"
    oidc_audience: str = "sair-api"
    oidc_timeout: float = 5.0


@lru_cache
def get_settings() -> Settings:
    """Return a cached :class:`Settings` instance."""
    return Settings()
