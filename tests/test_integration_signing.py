"""Real cosign sign/verify round trip for the release SBOM.

Integration-only: skips cleanly when the cosign binary is not on PATH, so the
default ``-m "not integration"`` suite (and CI) never needs cosign or network.
Mirrors the skip-clean pattern of tests/test_integration_minio.py.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from secure_ai_research.supply_chain import signing

pytestmark = pytest.mark.integration

_REPO = Path(__file__).resolve().parents[1]


def _require_cosign() -> None:
    if not signing.cosign_available():
        pytest.skip("cosign binary not on PATH")


def test_round_trip_sign_and_verify(tmp_path, monkeypatch):
    _require_cosign()
    monkeypatch.setenv("COSIGN_PASSWORD", "")
    subprocess.run(
        ["cosign", "generate-key-pair"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    key = tmp_path / "cosign.key"
    sbom_dir = tmp_path / "sbom"
    sbom_dir.mkdir()
    (sbom_dir / "release-sbom.cdx.json").write_bytes(
        (_REPO / "sbom/release-sbom.cdx.json").read_bytes()
    )
    (sbom_dir / "cosign.pub").write_bytes((tmp_path / "cosign.pub").read_bytes())

    signing.sign_release_sbom(tmp_path, str(key))
    assert signing.signing_artifacts_state(tmp_path) == (True, True)
    assert signing.verify_release_sbom(tmp_path) is True

    # Tamper with one byte of the signed SBOM -> verification must fail.
    target = sbom_dir / "release-sbom.cdx.json"
    data = bytearray(target.read_bytes())
    data[0] ^= 0xFF
    target.write_bytes(bytes(data))
    with pytest.raises(signing.SigningError):
        signing.verify_release_sbom(tmp_path)


def test_committed_signature_verifies_when_present():
    _require_cosign()
    if signing.signing_artifacts_state(_REPO) != (True, True):
        pytest.skip("no committed signature yet (key ceremony pending)")
    assert signing.verify_release_sbom(_REPO) is True
