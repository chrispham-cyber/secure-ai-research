"""Pipeline-internal carrier pairing document metadata with its source text.

:class:`~secure_ai_research.ingestion.schema.ResearchDocument` stays metadata-only
(it is the committed, audited record shape). The retrieval pipeline additionally
needs the source text to chunk and embed, so ingestion returns this pair rather
than mutating the schema.
"""

from __future__ import annotations

from dataclasses import dataclass

from secure_ai_research.ingestion.schema import ResearchDocument


@dataclass(frozen=True)
class IngestedDocument:
    """A :class:`ResearchDocument` together with the text to index for it.

    ``canonical`` carries the exact source bytes the loader hashed for
    ``document.integrity_hash`` (empty only for records built outside a loader), so the object
    store can durably retain the raw provenance payload behind every hash. See Slice 3.
    """

    document: ResearchDocument
    text: str
    canonical: bytes = b""
