import json
from datetime import date
from importlib.resources import files

import pytest

from secure_ai_research.ingestion import nvd
from secure_ai_research.ingestion.ingested import IngestedDocument
from secure_ai_research.ingestion.schema import Classification, DocumentType


def _fixture_bytes() -> bytes:
    return files("secure_ai_research.ingestion").joinpath("samples", "nvd_sample.json").read_bytes()


def test_load_parses_fixture_into_documents():
    docs = nvd.load(_fixture_bytes())
    assert len(docs) == 2
    first = docs[0]
    assert isinstance(first, IngestedDocument)
    d = first.document
    assert d.document_id == "CVE-2099-0001"
    assert d.source == "NVD"
    assert d.document_type == DocumentType.VULNERABILITY
    assert d.classification == Classification.PUBLIC
    assert str(d.source_url) == "https://nvd.nist.gov/vuln/detail/CVE-2099-0001"
    assert d.created_at == date(2099, 1, 15)
    assert d.integrity_hash.startswith("sha256:")
    assert len(d.integrity_hash) == len("sha256:") + 64
    assert "SQL injection" in first.text


def test_load_integrity_hash_is_canonical():
    # Same CVE, keys in different insertion order -> identical integrity hash.
    descs = [{"lang": "en", "value": "x"}]
    a = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2099-0001",
                    "published": "2099-01-15T00:00:00.000",
                    "descriptions": descs,
                }
            }
        ]
    }
    b = {
        "vulnerabilities": [
            {
                "cve": {
                    "descriptions": descs,
                    "published": "2099-01-15T00:00:00.000",
                    "id": "CVE-2099-0001",
                }
            }
        ]
    }
    ha = nvd.load(json.dumps(a).encode())[0].document.integrity_hash
    hb = nvd.load(json.dumps(b).encode())[0].document.integrity_hash
    assert ha == hb


def test_load_rejects_bad_json():
    with pytest.raises(ValueError):
        nvd.load(b"not json")


def test_load_rejects_missing_english_description():
    feed = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2099-0003",
                    "published": "2099-01-01T00:00:00.000",
                    "descriptions": [{"lang": "es", "value": "x"}],
                }
            }
        ]
    }
    with pytest.raises(ValueError) as exc:
        nvd.load(json.dumps(feed).encode())
    assert "CVE-2099-0003" in str(exc.value)


def test_load_rejects_non_date_published_naming_id():
    feed = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2099-1234",
                    "published": "not-a-date",
                    "descriptions": [{"lang": "en", "value": "x"}],
                }
            }
        ]
    }
    with pytest.raises(ValueError) as exc:
        nvd.load(json.dumps(feed).encode())
    assert "CVE-2099-1234" in str(exc.value)


def test_load_rejects_missing_cve_key_naming_position():
    feed = {"vulnerabilities": [{"not_cve": {}}]}
    with pytest.raises(ValueError) as exc:
        nvd.load(json.dumps(feed).encode())
    assert "index 0" in str(exc.value)


def test_load_rejects_english_description_missing_value_naming_id():
    feed = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2099-5678",
                    "published": "2099-01-01T00:00:00.000",
                    "descriptions": [{"lang": "en"}],
                }
            }
        ]
    }
    with pytest.raises(ValueError) as exc:
        nvd.load(json.dumps(feed).encode())
    assert "CVE-2099-5678" in str(exc.value)


def test_load_rejects_duplicate_ids():
    one = {
        "cve": {
            "id": "CVE-2099-0004",
            "published": "2099-01-01T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "x"}],
        }
    }
    feed = {"vulnerabilities": [one, one]}
    with pytest.raises(ValueError) as exc:
        nvd.load(json.dumps(feed).encode())
    assert "CVE-2099-0004" in str(exc.value)
