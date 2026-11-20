"""FastAPI application.

* ``GET /health``  — liveness.
* ``GET /version`` — provenance: package version, git SHA, and the names in the
  approved-model registry (read from disk; no model weights required).
* ``GET /research/cve/{cve_id}`` / ``GET /research/attack/{technique_id}`` — look up a
  single record.
* ``POST /research/search`` — retrieve the passages relevant to a query.
* ``POST /research/ask`` — draft a cited answer.

The audit trail and the authorization gate are the backbone: every analysis path emits a
signed, hash-chained record, and no document reaches model context before the caller is
authorized for it.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from secure_ai_research import __version__
from secure_ai_research.ai_security.model_integrity.verify_model import load_registry
from secure_ai_research.api.deps import get_service
from secure_ai_research.api.routers import research
from secure_ai_research.audit.signing import verify_chain
from secure_ai_research.config import get_settings
from secure_ai_research.crypto.factory import make_cipher
from secure_ai_research.secret.factory import make_secret_provider
from secure_ai_research.secret.verify import verify_secrets
from secure_ai_research.transit import check_transit_posture


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


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup security gate.

    Dev (the default) is a no-op: ``verify_secrets`` returns, transit posture is loopback-clean,
    and the prod-only chain check is skipped — so a bare ``with TestClient(app)`` never couples to
    the on-disk audit log. Prod (``SAIR_REQUIRE_STRONG_SECRETS``/``SAIR_REQUIRE_HTTPS``) fails the
    boot — rather than a first-request 500 — on a weak secret, an insecure transit posture, a
    misconfigured service, or an unverifiable audit log head.
    """
    settings = get_settings()
    provider = make_secret_provider(settings)
    # Fail closed in prod on any active placeholder/weak secret (no-op in dev).
    verify_secrets(settings, provider)
    # Refuse boot if an active backend's transport lacks TLS and the deployment asked to be strict.
    warnings = check_transit_posture(settings)
    if warnings and (settings.require_https or settings.require_strong_secrets):
        raise RuntimeError("insecure transit posture: " + "; ".join(warnings))
    # Build the service eagerly so a misconfiguration is a boot failure, not a runtime 500.
    get_service()
    # Prod only: refuse to start on a broken/legacy audit log head.
    if settings.require_strong_secrets:
        result = verify_chain(
            settings.audit_log_path,
            provider.require("audit_signing_key"),
            cipher=make_cipher(settings, provider),
        )
        if not result.ok:
            raise RuntimeError(f"audit log failed verification: {result.reason}")
    yield


app = FastAPI(
    title="Secure AI Research Platform",
    version=__version__,
    summary="Phase-1 auditable skeleton. Public / synthetic data only.",
    lifespan=lifespan,
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
