"""Dev lock pins: the virtualenv advisory fix and the SBOM generator major.

Hermetic text check over the committed ``requirements-dev.txt`` — guards the
PYSEC-2026-4374..4383 fix (virtualenv >= 21.14.9) and the cyclonedx-bom 9.x
bump that unblocked it against a silent future re-lock reverting either.
"""

from __future__ import annotations

import re
from pathlib import Path

from packaging.version import Version

_LOCK = Path(__file__).resolve().parents[1] / "requirements-dev.txt"


def _pinned(name: str) -> Version:
    m = re.search(rf"(?mi)^{re.escape(name)}==([^\s;]+)", _LOCK.read_text(encoding="utf-8"))
    assert m, f"{name} not pinned in requirements-dev.txt"
    return Version(m.group(1))


def test_virtualenv_advisory_is_fixed():
    # PYSEC-2026-4374..4383 fixed in 21.14.9
    assert _pinned("virtualenv") >= Version("21.14.9")


def test_sbom_generator_major_is_9x():
    v = _pinned("cyclonedx-bom")
    assert Version("9.0") <= v < Version("10.0")
