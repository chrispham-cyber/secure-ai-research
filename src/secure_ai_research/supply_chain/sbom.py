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
from pathlib import Path


class SbomError(RuntimeError):
    """Raised when the SBOM cannot be generated (non-zero CLI exit, missing tool/lock)."""


_NAME_SEP = re.compile(r"[-_.]+")


def _normalize(name: str) -> str:
    """PEP 503 normalized distribution name: lowercase, runs of ``-_.`` collapsed to ``-``."""
    return _NAME_SEP.sub("-", name).strip().lower()


def pinned_requirements(requirements_path: Path) -> set[str]:
    """Normalized distribution names pinned (``name==version``) in a requirements lock.

    Skips blank lines, comments, ``-r``/``-c``/``-e`` includes, ``--hash=`` continuation lines,
    and environment markers (``; python_version ...``). An optional ``[extras]`` suffix is
    dropped before normalization.
    """
    names: set[str] = set()
    for raw in Path(requirements_path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        spec = line.split(";", 1)[0].strip()  # drop environment marker
        if "==" not in spec:
            continue
        name = spec.split("==", 1)[0].strip()
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
    """SHA-256 hexdigest of the canonical component projection."""
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
