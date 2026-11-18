import json
from pathlib import Path

from secure_ai_research.ai_security.model_integrity.verify_model import (
    load_registry,
    main,
    sha256_file,
    verify_file,
)

FIXTURE = Path(__file__).parent / "fixtures" / "sample_model.bin"
KNOWN = "da2f8afef3be91fdf62d0fc49a2f2599ff31ed4ed3421edb1b31792320a902ac"


def test_sha256_file_matches_known():
    assert sha256_file(FIXTURE) == KNOWN


def test_verify_match():
    assert verify_file(FIXTURE, KNOWN) is True


def test_verify_mismatch_fails():
    assert verify_file(FIXTURE, "00" * 32) is False


def test_load_registry_synthetic():
    records = load_registry(Path("infrastructure/model-runtime/model-registry.json"))
    assert len(records) >= 1
    assert any(r.approval_status == "UNVERIFIED" for r in records)


def test_cli_mismatch_returns_1(tmp_path):
    reg = tmp_path / "reg.json"
    reg.write_text(
        json.dumps(
            {
                "models": [
                    {
                        "name": "x",
                        "version": "0",
                        "publisher": "p",
                        "license": "L",
                        "source": "s",
                        "sha256": "00" * 32,
                        "format": "safetensors",
                        "approval_status": "UNVERIFIED",
                    }
                ]
            }
        )
    )
    rc = main(["--registry", str(reg), "--model-path", str(FIXTURE), "--id", "x"])
    assert rc == 1
