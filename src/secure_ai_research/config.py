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
    minio_endpoint: str = "localhost:9000"
    minio_access_key: str = "minioadmin"
    minio_secret_key: str = "minioadmin"
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


@lru_cache
def get_settings() -> Settings:
    """Return a cached :class:`Settings` instance."""
    return Settings()
