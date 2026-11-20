"""Compose base images must be digest-pinned (supply-chain hardening follow-up).

A hermetic, text-only gate over ``docker-compose.yml`` (no Docker at test time):
every ``image:`` reference must carry an ``@sha256:<64 hex>`` digest, or its
repository must be on an explicit, documented allowlist.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_COMPOSE = _REPO / "docker-compose.yml"

# Images that cannot be digest-pinned, with the reason each is exempt.
_ALLOWLIST = {"minio/minio"}  # retired from public registries (see Slice 3); tag-only

_IMAGE = re.compile(r"^\s*image:\s*(\S+)", re.MULTILINE)
_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")


def _image_refs() -> list[str]:
    return _IMAGE.findall(_COMPOSE.read_text(encoding="utf-8"))


def _repo(ref: str) -> str:
    """Repository name: drop the ``@digest`` then the ``:tag``."""
    return ref.split("@", 1)[0].rsplit(":", 1)[0]


def test_compose_images_are_digest_pinned():
    refs = _image_refs()
    assert refs, "no image: lines found in docker-compose.yml"
    for ref in refs:
        if _repo(ref) in _ALLOWLIST:
            continue
        assert _DIGEST.search(ref), f"image not digest-pinned: {ref}"


def test_allowlist_is_not_a_blanket_skip():
    # The predicate must reject an un-pinned tag and a malformed/short digest,
    # and accept only a well-formed 64-hex digest; the allowlist is explicit.
    assert not _DIGEST.search("otel/x:1.0")
    assert not _DIGEST.search("otel/x:1.0@sha256:deadbeef")  # too short
    assert _DIGEST.search("otel/x:1.0@sha256:" + "a" * 64)
    assert _ALLOWLIST and "minio/minio" in _ALLOWLIST
