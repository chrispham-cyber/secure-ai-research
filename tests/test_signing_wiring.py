"""Wiring guards for SBOM signing: Makefile targets, the CI verify job, and the
keyed-offline security posture (public key only -- no OIDC token minting, no
private key committable). String-level and hermetic: never runs cosign or CI.
"""

from __future__ import annotations

from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_CI = (_REPO / ".github/workflows/ci.yml").read_text()
_MK = (_REPO / "Makefile").read_text()


def test_makefile_has_sign_and_verify_targets():
    assert "\nsbom-sign:" in _MK and "\nsbom-verify:" in _MK


def test_ci_has_sbom_verify_job():
    assert "sbom-verify:" in _CI
    assert "cosign-installer" in _CI


def test_sbom_verify_job_is_public_key_only():
    # Keyed-offline posture: CI verifies with the committed public key and never
    # mints an OIDC identity token (which keyless Sigstore/Rekor would require).
    assert "id-token" not in _CI


def test_gitignore_blocks_private_keys():
    gi = (_REPO / ".gitignore").read_text()
    assert "*.key" in gi
    assert "*.pem" in gi
