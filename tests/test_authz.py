from datetime import date

from secure_ai_research.ingestion.schema import (
    Classification,
    DocumentType,
    ResearchDocument,
    Sensitivity,
)
from secure_ai_research.retrieval.authz import authorize


def _doc(sensitivity: Sensitivity = Sensitivity.ROUTINE) -> ResearchDocument:
    return ResearchDocument(
        document_id="CVE-2099-0001",
        source="NVD",
        document_type=DocumentType.VULNERABILITY,
        classification=Classification.PUBLIC,
        created_at=date(2099, 1, 1),
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2099-0001",  # type: ignore[arg-type]
        integrity_hash="sha256:" + "0" * 64,
        sensitivity=sensitivity,
    )


def test_permitted_roles():
    assert authorize("research_analyst", _doc()) is True
    assert authorize("senior_analyst", _doc()) is True


def test_denied_roles():
    for role in ["security_auditor", "model_admin", "data_steward", "administrator", "unknown", ""]:
        assert authorize(role, _doc()) is False


def test_role_is_stripped():
    assert authorize("  research_analyst  ", _doc()) is True


def test_routine_retrievable_by_both():
    assert authorize("research_analyst", _doc()) is True
    assert authorize("senior_analyst", _doc()) is True


def test_restricted_requires_senior():
    restricted = _doc(sensitivity=Sensitivity.RESTRICTED)
    assert authorize("senior_analyst", restricted) is True
    assert authorize("research_analyst", restricted) is False


def test_restricted_denied_role_still_denied():
    restricted = _doc(sensitivity=Sensitivity.RESTRICTED)
    for role in ("security_auditor", "administrator", ""):
        assert authorize(role, restricted) is False
