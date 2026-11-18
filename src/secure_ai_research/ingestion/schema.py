"""Document-metadata schema for research records.

Mirrors the metadata example in the design/roadmap (§4.2). Two invariants matter:

* ``classification`` accepts **PUBLIC only** — this repository handles public /
  synthetic data, and a non-public value is rejected at validation, never stored.
* ``integrity_hash`` must be a ``sha256:<64 hex>`` string, so every record is
  tied to a verifiable content hash.
"""

from __future__ import annotations

from datetime import date
from enum import StrEnum

from pydantic import AnyUrl, BaseModel, Field


class Classification(StrEnum):
    """Handling class. PUBLIC only in this repository — see module docstring."""

    PUBLIC = "PUBLIC"


class VerificationStatus(StrEnum):
    """Whether a human has verified the record."""

    UNVERIFIED = "UNVERIFIED"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"


class DocumentType(StrEnum):
    """Kind of source document."""

    VULNERABILITY = "vulnerability"
    ADVISORY = "advisory"
    TECHNIQUE = "technique"
    DETECTION = "detection"
    PAPER = "paper"
    OTHER = "other"


class ResearchDocument(BaseModel):
    """A single public research document with provenance and integrity metadata."""

    document_id: str
    source: str
    document_type: DocumentType
    classification: Classification
    created_at: date
    source_url: AnyUrl
    integrity_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    verification_status: VerificationStatus = VerificationStatus.UNVERIFIED
    reviewed_by: str | None = None
