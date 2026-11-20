"""Hermetic guards for the SBOM signing module.

cosign is an external binary; these tests never invoke it. They pin the offline
command shapes, the PATH probe, the all-or-nothing committed-artifact rule, and
that importing the module pulls in nothing heavy. The real sign/verify round
trip lives in tests/test_integration_signing.py behind the integration marker.
"""

from __future__ import annotations

import sys
from pathlib import Path

from secure_ai_research.supply_chain import signing
from secure_ai_research.supply_chain.signing import (
    cosign_available,
    sign_command,
    signing_artifacts_state,
    verify_command,
)

_REPO = Path(__file__).resolve().parents[1]


def test_sign_command_is_offline():
    cmd = sign_command("cosign.key", "sbom/x.json", "sbom/x.json.sig")
    assert cmd == [
        "cosign",
        "sign-blob",
        "--key",
        "cosign.key",
        "--tlog-upload=false",
        "--yes",
        "--output-signature",
        "sbom/x.json.sig",
        "sbom/x.json",
    ]


def test_verify_command_ignores_transparency_log():
    cmd = verify_command("sbom/cosign.pub", "sbom/x.json.sig", "sbom/x.json")
    assert cmd == [
        "cosign",
        "verify-blob",
        "--key",
        "sbom/cosign.pub",
        "--insecure-ignore-tlog=true",
        "--signature",
        "sbom/x.json.sig",
        "sbom/x.json",
    ]


def test_cosign_available_reflects_path(monkeypatch):
    monkeypatch.setattr(signing.shutil, "which", lambda _: "/usr/bin/cosign")
    assert cosign_available() is True
    monkeypatch.setattr(signing.shutil, "which", lambda _: None)
    assert cosign_available() is False


def test_signing_artifacts_state_tmp(tmp_path):
    assert signing_artifacts_state(tmp_path) == (False, False)
    (tmp_path / "sbom").mkdir()
    (tmp_path / "sbom" / "cosign.pub").write_text("k")
    assert signing_artifacts_state(tmp_path) == (False, True)


def test_committed_signing_artifacts_are_all_or_nothing():
    sig_present, pub_present = signing_artifacts_state(_REPO)
    assert (
        sig_present == pub_present
    ), "commit sbom/cosign.pub and sbom/release-sbom.cdx.json.sig together, or neither"


def test_module_imports_nothing_heavy():
    import secure_ai_research.supply_chain.signing  # noqa: F401

    assert "sigstore" not in sys.modules
    assert "cryptography" not in sys.modules
