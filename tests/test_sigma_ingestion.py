import inspect
import json
import re

import pytest

from secure_ai_research.ingestion import sigma
from secure_ai_research.ingestion.schema import Classification, DocumentType

_REPO_URL = "https://github.com/SigmaHQ/sigma"


def _rules(*rules):
    return json.dumps(list(rules)).encode()


def _rule(rule_id="e2072cab-8c9a-459b-b63c-40ae79e27031", **over):
    r = {
        "title": "Suspicious PowerShell Execution",
        "id": rule_id,
        "status": "stable",
        "description": "Detects suspicious command interpreter use.",
        "date": "2021/12/14",
        "tags": ["attack.execution", "attack.t1059", "attack.t1059.001"],
        "logsource": {"product": "windows", "category": "process_creation"},
        "level": "high",
    }
    r.update(over)
    return r


def test_load_parses_rule():
    [doc] = sigma.load(_rules(_rule()))
    assert doc.document.document_id == "SIGMA-e2072cab-8c9a-459b-b63c-40ae79e27031"
    assert doc.document.source == "Sigma"
    assert doc.document.document_type is DocumentType.DETECTION
    assert doc.document.classification is Classification.PUBLIC
    assert str(doc.document.source_url) == _REPO_URL
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", doc.document.integrity_hash)
    assert "Suspicious PowerShell Execution" in doc.text


def test_document_id_is_namespaced():
    [doc] = sigma.load(_rules(_rule("11111111-2222-3333-4444-555555555555")))
    assert doc.document.document_id == "SIGMA-11111111-2222-3333-4444-555555555555"


def test_attack_tag_becomes_technique_token():
    [doc] = sigma.load(_rules(_rule(tags=["attack.execution", "attack.t1059", "attack.t1059.001"])))
    assert "T1059" in doc.text
    assert "T1059.001" in doc.text


def test_cve_tag_becomes_cve_token():
    [doc] = sigma.load(_rules(_rule(tags=["cve.2021.44228"])))
    assert "CVE-2021-44228" in doc.text


def test_cve_tag_accepts_dash_format():
    # Current SigmaHQ taxonomy writes the CVE tag as cve.YYYY-NNNN (dash); the loader must
    # still emit the canonical CVE-YYYY-NNNN token so a CVE search surfaces the detection.
    [doc] = sigma.load(_rules(_rule(tags=["cve.2021-44228"])))
    assert "CVE-2021-44228" in doc.text


def test_date_accepts_slash_and_dash():
    [slash] = sigma.load(_rules(_rule(date="2021/12/14")))
    [dash] = sigma.load(_rules(_rule(date="2021-12-14")))
    assert str(slash.document.created_at) == "2021-12-14"
    assert str(dash.document.created_at) == "2021-12-14"


def test_deprecated_and_unsupported_skipped():
    docs = sigma.load(
        _rules(
            _rule("aaaaaaaa-0000-0000-0000-000000000001", status="deprecated"),
            _rule("aaaaaaaa-0000-0000-0000-000000000002", status="unsupported"),
            _rule("aaaaaaaa-0000-0000-0000-000000000003", status="stable"),
        )
    )
    assert [d.document.document_id for d in docs] == ["SIGMA-aaaaaaaa-0000-0000-0000-000000000003"]


def test_load_missing_id_raises():
    bad = _rule()
    del bad["id"]
    with pytest.raises(ValueError):
        sigma.load(_rules(bad))


def test_load_missing_title_raises():
    with pytest.raises(ValueError, match="e2072cab"):
        sigma.load(_rules(_rule(title="")))


def test_load_bad_date_raises():
    with pytest.raises(ValueError, match="e2072cab"):
        sigma.load(_rules(_rule(date="not-a-date")))


def test_load_duplicate_id_raises():
    with pytest.raises(ValueError, match="e2072cab"):
        sigma.load(_rules(_rule(), _rule()))


def test_load_malformed_json_raises():
    with pytest.raises(ValueError):
        sigma.load(b"{ not valid json")


def test_runtime_has_no_yaml_import():
    # Runtime stays stdlib-only; YAML is a build-time-only concern.
    assert "import yaml" not in inspect.getsource(sigma)
