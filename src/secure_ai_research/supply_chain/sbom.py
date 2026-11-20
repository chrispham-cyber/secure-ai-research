"""Reproducible release SBOM: parse the lock, canonicalize, digest, check completeness.

The pure helpers here take no network and no subprocess; SBOM *generation* (which shells out
to ``cyclonedx-py``) is added alongside them. The digest is taken over a canonical
``{name, version, purl}`` projection so it is stable across a cyclonedx-py formatting bump but
sensitive to any real component add/remove/version change.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

_RELEASE_SBOM_PATH = "sbom/release-sbom.cdx.json"
_MANIFEST_PATH = "sbom/sbom.manifest.json"
_TOOL = "cyclonedx-py requirements --output-reproducible"


class SbomError(RuntimeError):
    """Raised when the SBOM cannot be generated (non-zero CLI exit, missing tool/lock)."""


_NAME_SEP = re.compile(r"[-_.]+")


def _normalize(name: str) -> str:
    """PEP 503 normalized distribution name: lowercase, runs of ``-_.`` collapsed to ``-``."""
    return _NAME_SEP.sub("-", name).strip().lower()


def pinned_requirements(requirements_path: Path) -> set[str]:
    """Normalized distribution names required in a requirements lock.

    Recognizes ``name==version``, PEP 508 direct references (``name @ url``), and
    editable/VCS installs carrying ``#egg=<name>``. Skips blank lines, comments,
    ``-r``/``-c`` includes, ``--hash=``/index option lines, and environment markers
    (``; python_version ...``). An optional ``[extras]`` suffix is dropped before
    normalization.
    """
    names: set[str] = set()
    for raw in Path(requirements_path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            # -e/--editable VCS or path installs carry the name in "#egg=<name>";
            # every other option line (-r/-c/--hash/--index-url) is not a dependency.
            egg = re.search(r"#egg=([A-Za-z0-9._-]+)", line)
            if egg:
                names.add(_normalize(egg.group(1)))
            continue
        spec = line.split(";", 1)[0].strip()  # drop environment marker
        if "==" in spec:
            name = spec.split("==", 1)[0]
        elif "@" in spec:
            name = spec.split("@", 1)[0]  # PEP 508 direct reference: name @ url
        else:
            continue
        name = name.split("[", 1)[0].strip()  # drop [extras]
        if name:
            names.add(_normalize(name))
    return names


def canonical_components(sbom_bytes: bytes) -> list[dict]:
    """Stable ``{name, version, purl}`` projection of the SBOM components, sorted.

    This is the projection the digest is taken over: order-independent and insensitive to tool
    formatting, but sensitive to any component add/remove/version change.
    """
    doc = json.loads(sbom_bytes)
    projected = [
        {
            "name": c.get("name", ""),
            "version": c.get("version", ""),
            "purl": c.get("purl", ""),
        }
        for c in doc.get("components", [])
    ]
    return sorted(projected, key=lambda c: (c["name"], c["version"], c["purl"]))


def sbom_digest(sbom_bytes: bytes) -> str:
    """SHA-256 hexdigest of the canonical component projection.

    Scope is deliberate: this pins the dependency set (name/version/purl) for
    drift detection, not the whole SBOM file -- git provides whole-file integrity
    for the committed ``sbom/`` artifacts, and widening into volatile fields
    (license, externalReferences) would flap the gate on benign tool output.
    """
    canonical = json.dumps(canonical_components(sbom_bytes), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def missing_components(requirements_path: Path, sbom_bytes: bytes) -> list[str]:
    """Normalized pinned names with no matching normalized SBOM component name, sorted."""
    doc = json.loads(sbom_bytes)
    present = {_normalize(c.get("name", "")) for c in doc.get("components", [])}
    pinned = pinned_requirements(requirements_path)
    return sorted(pinned - present)


def read_manifest(path: Path) -> dict:
    """Load the committed integrity manifest."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def generate_release_sbom(requirements_path: Path, repo_root: Path) -> bytes:
    """Generate the reproducible release SBOM from a pinned requirements lock.

    Shells out to ``cyclonedx-py`` via ``sys.executable -m cyclonedx_py`` (the same interpreter,
    hence the same virtualenv — no PATH or binary-location guessing, no new runtime import). The
    ``--output-reproducible`` flag strips the volatile ``timestamp``/``serialNumber`` so two runs
    are byte-identical. No network. Non-zero exit → :class:`SbomError`.
    """
    cmd = [
        sys.executable,
        "-m",
        "cyclonedx_py",
        "requirements",
        str(requirements_path),
        "--output-reproducible",
        "--of",
        "json",
        "-o",
        "-",
    ]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(repo_root),
            capture_output=True,
            check=False,
        )
    except OSError as exc:  # pragma: no cover - cyclonedx-py is a dev dependency, always present
        raise SbomError(f"could not run cyclonedx-py: {exc}") from exc
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip() or f"exit {proc.returncode}"
        raise SbomError(f"cyclonedx-py failed for {requirements_path}: {detail}")
    return proc.stdout


def write_release_artifacts(repo_root: Path) -> None:
    """Regenerate the release SBOM + rewrite the integrity manifest under ``repo_root/sbom/``.

    This is the re-attest step: run it whenever a runtime dependency changes so the committed
    SBOM and its SHA-256 pin match the lock again.
    """
    repo_root = Path(repo_root)
    sbom_bytes = generate_release_sbom(repo_root / "requirements.txt", repo_root)
    sbom_file = repo_root / _RELEASE_SBOM_PATH
    sbom_file.parent.mkdir(parents=True, exist_ok=True)
    sbom_file.write_bytes(sbom_bytes)

    manifest = {
        "source": "requirements.txt",
        "tool": _TOOL,
        "sbom_sha256": sbom_digest(sbom_bytes),
        "component_count": len(json.loads(sbom_bytes).get("components", [])),
        "sbom_file": _RELEASE_SBOM_PATH,
    }
    manifest_text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    (repo_root / _MANIFEST_PATH).write_text(manifest_text, encoding="utf-8")


if __name__ == "__main__":  # pragma: no cover - CLI entry point (make sbom-release)
    write_release_artifacts(Path.cwd())
