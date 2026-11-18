"""Verify a model file's SHA-256 against the recorded value in the model registry.

Treat models as software dependencies: pin a hash, verify before use. A missing
recorded hash or a mismatch fails **loudly** (non-zero exit) — a model is never
silently treated as verified.

CLI::

    python -m secure_ai_research.ai_security.model_integrity.verify_model \\
        --registry infrastructure/model-runtime/model-registry.json \\
        --model-path path/to/model.safetensors --id example/local-llm

Exit status: 0 match · 1 mismatch or no recorded hash · 2 usage / unknown id.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from pydantic import BaseModel


class ModelRecord(BaseModel):
    """One approved-model registry entry (provenance + integrity + approval)."""

    name: str
    version: str
    publisher: str
    license: str
    source: str
    sha256: str | None = None
    format: str = "safetensors"
    approval_status: str = "UNVERIFIED"


def sha256_file(path: Path, *, chunk_size: int = 65536) -> str:
    """Return the lowercase hex SHA-256 of ``path`` (no ``sha256:`` prefix)."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_file(path: Path, expected_sha256: str) -> bool:
    """True iff ``path``'s SHA-256 equals ``expected_sha256``.

    A leading ``sha256:`` on the expected value is tolerated.
    """
    expected = expected_sha256.removeprefix("sha256:").lower()
    return sha256_file(path) == expected


def load_registry(path: Path) -> list[ModelRecord]:
    """Load the model registry (``{"models": [...]}`` or a bare list)."""
    data = json.loads(Path(path).read_text())
    models = data["models"] if isinstance(data, dict) else data
    return [ModelRecord(**entry) for entry in models]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="verify_model",
        description="Verify a model file against the approved-model registry.",
    )
    parser.add_argument("--registry", required=True, type=Path)
    parser.add_argument("--model-path", required=True, type=Path)
    parser.add_argument("--id", required=True, help="model name (record id) in the registry")
    args = parser.parse_args(argv)

    records = {record.name: record for record in load_registry(args.registry)}
    record = records.get(args.id)
    if record is None:
        print(f"error: model id not in registry: {args.id}", file=sys.stderr)
        return 2
    if record.sha256 is None:
        print(f"UNVERIFIED: no recorded sha256 for {args.id}", file=sys.stderr)
        return 1

    actual = sha256_file(args.model_path)
    if verify_file(args.model_path, record.sha256):
        print(f"OK: {args.id} matches sha256:{actual}")
        return 0
    expected = record.sha256.removeprefix("sha256:")
    print(f"MISMATCH: {args.id} expected sha256:{expected} got sha256:{actual}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
