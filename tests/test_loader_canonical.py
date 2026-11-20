"""Every loader must retain the exact canonical bytes it hashes (Phase 5, Slice 3, Task 2).

The object store persists raw provenance keyed by ``integrity_hash``; for that key to mean
anything, the bytes stored under it must be the very bytes the loader hashed. This pins, per
loader, that ``IngestedDocument.canonical`` is present and satisfies its own hash.
"""

from __future__ import annotations

import hashlib
from importlib.resources import files

import pytest

from secure_ai_research.ingestion import attack, kev, nvd, sigma

_PREFIX = "sha256:"


def _sample(name: str) -> bytes:
    return files("secure_ai_research.ingestion").joinpath("samples", name).read_bytes()


@pytest.mark.parametrize(
    "load_fn, sample",
    [
        (nvd.load, "nvd_sample.json"),
        (attack.load, "attack_sample.json"),
        (kev.load, "kev_sample.json"),
        (sigma.load, "sigma_sample.json"),
    ],
)
def test_loader_retains_canonical_matching_its_hash(load_fn, sample):
    docs = load_fn(_sample(sample))
    assert docs, "sample must yield at least one document"
    for d in docs:
        assert d.canonical, "loader must retain non-empty canonical bytes"
        expected = d.document.integrity_hash.removeprefix(_PREFIX)
        assert hashlib.sha256(d.canonical).hexdigest() == expected
