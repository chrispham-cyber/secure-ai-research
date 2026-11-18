"""FastAPI application — Phase-1 skeleton.

Exposes only what is real in the starter scaffold:

* ``GET /health``  — liveness.
* ``GET /version`` — provenance: package version, git SHA, and the names in the
  approved-model registry (read from disk; no model weights required).
* ``/research/*``  — present but **501 Not Implemented**, pointing at the roadmap.

Nothing here performs retrieval or inference yet. The point of shipping the
skeleton first is that the audit trail and authorization gate are reviewable
before any answer-producing code exists.
"""

from __future__ import annotations

import os
import subprocess

from fastapi import FastAPI

from secure_ai_research import __version__
from secure_ai_research.ai_security.model_integrity.verify_model import load_registry
from secure_ai_research.api.routers import research
from secure_ai_research.config import get_settings


def git_sha() -> str:
    """Return the running build's short commit SHA.

    Prefers ``SAIR_GIT_SHA`` (set at deploy time), falls back to ``git
    rev-parse``, and returns ``"unknown"`` when neither is available — so the
    endpoint never raises just because provenance is missing.
    """
    env_sha = os.environ.get("SAIR_GIT_SHA")
    if env_sha:
        return env_sha
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return result.stdout.strip() or "unknown"


app = FastAPI(
    title="Secure AI Research Platform",
    version=__version__,
    summary="Phase-1 auditable skeleton. Public / synthetic data only.",
)
app.include_router(research.router)


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok"}


@app.get("/version")
def version() -> dict[str, object]:
    """Build provenance: package version, git SHA, and registered model names."""
    settings = get_settings()
    try:
        models = [record.name for record in load_registry(settings.model_registry_path)]
    except (OSError, ValueError):
        models = []
    return {"version": __version__, "git_sha": git_sha(), "models": models}
