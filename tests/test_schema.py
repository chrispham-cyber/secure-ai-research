import pytest
from pydantic import ValidationError

from secure_ai_research.ingestion.schema import ResearchDocument, VerificationStatus

VALID = dict(
    document_id="CVE-2026-0001",
    source="NVD",
    document_type="vulnerability",
    classification="PUBLIC",
    created_at="2026-11-18",
    source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
    integrity_hash="sha256:" + "a" * 64,
)


def test_valid_document_roundtrips():
    doc = ResearchDocument(**VALID)
    assert ResearchDocument.model_validate_json(doc.model_dump_json()) == doc


def test_non_public_classification_rejected():
    with pytest.raises(ValidationError):
        ResearchDocument(**{**VALID, "classification": "CUI"})


def test_bad_integrity_hash_rejected():
    with pytest.raises(ValidationError):
        ResearchDocument(**{**VALID, "integrity_hash": "deadbeef"})


def test_defaults():
    doc = ResearchDocument(**VALID)
    assert doc.verification_status is VerificationStatus.UNVERIFIED
    assert doc.reviewed_by is None


def test_default_sensitivity_is_routine():
    from secure_ai_research.ingestion.schema import Sensitivity

    doc = ResearchDocument(**VALID)
    assert doc.sensitivity is Sensitivity.ROUTINE
