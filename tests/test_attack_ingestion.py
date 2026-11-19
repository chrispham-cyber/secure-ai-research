import json
import re

import pytest

from secure_ai_research.ingestion import attack
from secure_ai_research.ingestion.schema import Classification, DocumentType


def _bundle(*objects):
    return json.dumps({"type": "bundle", "id": "bundle--x", "objects": list(objects)}).encode()


def _ap(
    ext_id,
    name="Command and Scripting Interpreter",
    desc="Adversaries abuse interpreters.",
    created="2017-05-31T21:30:18.931Z",
    revoked=False,
    deprecated=False,
):
    obj = {
        "type": "attack-pattern",
        "id": f"attack-pattern--{ext_id}",
        "name": name,
        "description": desc,
        "created": created,
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": ext_id,
                "url": f"https://attack.mitre.org/techniques/{ext_id}",
            }
        ],
    }
    if revoked:
        obj["revoked"] = True
    if deprecated:
        obj["x_mitre_deprecated"] = True
    return obj


def test_load_parses_technique():
    [doc] = attack.load(_bundle(_ap("T1059")))
    assert doc.document.document_id == "T1059"
    assert doc.document.document_type is DocumentType.TECHNIQUE
    assert doc.document.source == "MITRE ATT&CK"
    assert doc.document.classification is Classification.PUBLIC
    assert str(doc.document.source_url) == "https://attack.mitre.org/techniques/T1059/"
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", doc.document.integrity_hash)
    assert "Command and Scripting Interpreter" in doc.text and "abuse interpreters" in doc.text


def test_load_parses_subtechnique():
    [doc] = attack.load(_bundle(_ap("T1059.001", name="PowerShell")))
    assert doc.document.document_id == "T1059.001"
    assert str(doc.document.source_url) == "https://attack.mitre.org/techniques/T1059/001/"


def test_load_skips_revoked_and_deprecated():
    docs = attack.load(
        _bundle(_ap("T1059"), _ap("T1064", revoked=True), _ap("T1066", deprecated=True))
    )
    assert [d.document.document_id for d in docs] == ["T1059"]


def test_load_ignores_non_attack_pattern():
    other = {"type": "course-of-action", "id": "course-of-action--y", "name": "Mitigation"}
    docs = attack.load(_bundle(other, _ap("T1059")))
    assert [d.document.document_id for d in docs] == ["T1059"]


def test_load_missing_mitre_external_id_raises():
    bad = {
        "type": "attack-pattern",
        "id": "attack-pattern--z",
        "name": "x",
        "description": "y",
        "created": "2017-05-31T21:30:18.931Z",
        "external_references": [{"source_name": "capec"}],
    }
    with pytest.raises(ValueError, match="attack-pattern--z"):
        attack.load(_bundle(bad))


def test_load_duplicate_technique_id_raises():
    with pytest.raises(ValueError, match="T1059"):
        attack.load(_bundle(_ap("T1059"), _ap("T1059")))


def test_load_invalid_created_raises():
    with pytest.raises(ValueError, match="T1059"):
        attack.load(_bundle(_ap("T1059", created="not-a-date")))


def test_load_malformed_json_raises():
    with pytest.raises(ValueError):
        attack.load(b"{ not valid json")


@pytest.mark.parametrize("bad_id", ["TA0001", "T10", "T1059.1", "t1059", ""])
def test_load_malformed_technique_id_raises(bad_id):
    # Spec §7.1 / §4 anti-goal: a mis-shaped mitre-attack external_id must fail loud,
    # not be silently indexed (the loader is fail-loud for every other malformation).
    with pytest.raises(ValueError, match="malformed technique id"):
        attack.load(_bundle(_ap(bad_id)))


def test_integrity_hash_is_key_order_independent():
    a = {
        "type": "attack-pattern",
        "id": "attack-pattern--T1059",
        "name": "n",
        "description": "d",
        "created": "2017-05-31T21:30:18.931Z",
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}],
    }
    b = dict(reversed(list(a.items())))
    assert (
        attack.load(_bundle(a))[0].document.integrity_hash
        == attack.load(_bundle(b))[0].document.integrity_hash
    )
