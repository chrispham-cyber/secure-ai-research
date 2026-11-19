import json
import re

import pytest

from secure_ai_research.ingestion import kev
from secure_ai_research.ingestion.schema import Classification, DocumentType

_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


def _catalog(*entries):
    return json.dumps(
        {"title": "KEV", "count": len(entries), "vulnerabilities": list(entries)}
    ).encode()


def _entry(cve_id="CVE-2021-44228", **over):
    e = {
        "cveID": cve_id,
        "vendorProject": "Apache",
        "product": "Log4j2",
        "vulnerabilityName": "Apache Log4j2 RCE",
        "dateAdded": "2021-12-10",
        "shortDescription": "JNDI lookup remote code execution.",
        "requiredAction": "Apply updates.",
        "dueDate": "2021-12-24",
        "knownRansomwareCampaignUse": "Unknown",
    }
    e.update(over)
    return e


def test_load_parses_entry():
    [doc] = kev.load(_catalog(_entry()))
    assert doc.document.document_id == "KEV-CVE-2021-44228"
    assert doc.document.source == "CISA KEV"
    assert doc.document.document_type is DocumentType.ADVISORY
    assert doc.document.classification is Classification.PUBLIC
    assert str(doc.document.source_url) == _CATALOG_URL
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", doc.document.integrity_hash)
    assert "CVE-2021-44228" in doc.text and "Log4j2" in doc.text


def test_document_id_is_namespaced():
    # Must be KEV-prefixed, never the bare CVE id, so it cannot collide with an NVD doc.
    [doc] = kev.load(_catalog(_entry("CVE-2099-0001")))
    assert doc.document.document_id == "KEV-CVE-2099-0001"


def test_text_includes_ransomware_only_when_known():
    [known] = kev.load(_catalog(_entry(knownRansomwareCampaignUse="Known")))
    [unknown] = kev.load(_catalog(_entry(knownRansomwareCampaignUse="Unknown")))
    assert "ransomware" in known.text.lower()
    assert "ransomware" not in unknown.text.lower()


def test_load_missing_cveid_raises():
    bad = _entry()
    del bad["cveID"]
    with pytest.raises(ValueError):
        kev.load(_catalog(bad))


@pytest.mark.parametrize("bad_id", ["CVE-21-1", "2021-44228", "", "CVE-2021-abc"])
def test_load_malformed_cveid_raises(bad_id):
    with pytest.raises(ValueError):
        kev.load(_catalog(_entry(bad_id)))


def test_load_invalid_dateadded_raises():
    with pytest.raises(ValueError, match="CVE-2021-44228"):
        kev.load(_catalog(_entry(dateAdded="not-a-date")))


def test_load_duplicate_cveid_raises():
    with pytest.raises(ValueError, match="CVE-2021-44228"):
        kev.load(_catalog(_entry(), _entry()))


def test_load_malformed_json_raises():
    with pytest.raises(ValueError):
        kev.load(b"{ not valid json")


def test_integrity_hash_is_key_order_independent():
    a = {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "vulnerabilityName": "x"}
    b = dict(reversed(list(a.items())))
    assert (
        kev.load(_catalog(a))[0].document.integrity_hash
        == kev.load(_catalog(b))[0].document.integrity_hash
    )
