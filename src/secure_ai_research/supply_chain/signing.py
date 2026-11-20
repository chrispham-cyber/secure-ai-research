"""Keyed, offline SBOM signing via the cosign binary.

Nothing here is imported on the default runtime path and no new runtime
dependency is added: this module shells out to the external ``cosign`` CLI
exactly as :mod:`secure_ai_research.supply_chain.sbom` shells out to
``cyclonedx-py``. The default ``-m "not integration"`` suite never invokes
cosign -- the pure command builders and the artifact-state probe are hermetic,
and the real sign/verify round trip is an integration test that skips when
cosign is absent.

Posture: keyed signatures with ``--tlog-upload=false`` (no transparency log, no
network); verification with ``--insecure-ignore-tlog=true`` against a committed
public key. See docs/superpowers/specs/2026-11-20-sbom-signing-design.md.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

_SBOM = "sbom/release-sbom.cdx.json"
_SIG = _SBOM + ".sig"
_PUB = "sbom/cosign.pub"


class SigningError(RuntimeError):
    """Signing or verification failed (never carries key material)."""


def sign_command(key_ref: str, sbom: str, sig: str) -> list[str]:
    """Offline keyed sign-blob: no transparency-log upload, no interactive prompt."""
    return [
        "cosign",
        "sign-blob",
        "--key",
        key_ref,
        "--tlog-upload=false",
        "--yes",
        "--output-signature",
        sig,
        sbom,
    ]


def verify_command(pub: str, sig: str, sbom: str) -> list[str]:
    """Offline verify-blob against a public key, ignoring the transparency log."""
    return [
        "cosign",
        "verify-blob",
        "--key",
        pub,
        "--insecure-ignore-tlog=true",
        "--signature",
        sig,
        sbom,
    ]


def cosign_available() -> bool:
    """True when the cosign binary is on PATH."""
    return shutil.which("cosign") is not None


def _nonempty(path: Path) -> bool:
    return path.is_file() and path.stat().st_size > 0


def signing_artifacts_state(repo_root: Path) -> tuple[bool, bool]:
    """``(signature_present, public_key_present)``, each file non-empty."""
    return _nonempty(repo_root / _SIG), _nonempty(repo_root / _PUB)


def _run(cmd: list[str], repo_root: Path) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(cmd, cwd=repo_root, capture_output=True, text=True, check=False)
    except FileNotFoundError as exc:  # cosign not installed
        raise SigningError("cosign not found on PATH") from exc


def sign_release_sbom(repo_root: Path, key_ref: str) -> None:
    """Sign the committed release SBOM bytes, writing the detached ``.sig``.

    ``key_ref`` is a cosign key reference (a path or a ``COSIGN_KEY``-style
    value); its contents are never logged. Raises :class:`SigningError` on any
    non-zero exit.
    """
    result = _run(sign_command(key_ref, _SBOM, _SIG), repo_root)
    if result.returncode != 0:
        raise SigningError(f"cosign sign-blob failed (exit {result.returncode})")


def verify_release_sbom(repo_root: Path) -> bool:
    """Verify the committed ``.sig`` against the committed public key + SBOM.

    Returns ``True`` on success; raises :class:`SigningError` on a non-zero exit
    (a stale or forged signature). Requires cosign -- used by the integration
    test and the CI ``sbom-verify`` job, never by the hermetic suite.
    """
    result = _run(verify_command(_PUB, _SIG, _SBOM), repo_root)
    if result.returncode != 0:
        raise SigningError(f"cosign verify-blob failed (exit {result.returncode})")
    return True


def main() -> None:
    key_ref = os.environ.get("COSIGN_KEY") or (sys.argv[1] if len(sys.argv) > 1 else "")
    if not key_ref:
        raise SigningError("no cosign key: set COSIGN_KEY or pass a key path argument")
    sign_release_sbom(Path.cwd(), key_ref)


if __name__ == "__main__":
    main()
