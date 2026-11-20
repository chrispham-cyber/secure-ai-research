"""CISA KEV (Known Exploited Vulnerabilities) ingestion (ROADMAP Phase 2).

Parse the public CISA KEV catalog JSON into :class:`IngestedDocument` records —
one per ``vulnerabilities[]`` entry, each PUBLIC and pinned to a ``sha256:`` hash
of its canonical source object. The document id is **namespaced** ``KEV-{cveID}``
so a KEV record never collides with an NVD document for the same CVE and is
reachable through corpus search rather than the single-document CVE id route.

Fail-loud: a malformed catalog, a missing or malformed ``cveID``, a missing or
invalid ``dateAdded``, or a duplicate ``cveID`` each raise ``ValueError`` naming
the offending entry. A research corpus is never silently built from bad input.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date
from typing import Any

from secure_ai_research.ingestion.ingested import IngestedDocument
from secure_ai_research.ingestion.schema import Classification, DocumentType, ResearchDocument

_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")
_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


def load(raw: bytes) -> list[IngestedDocument]:
    """Parse raw CISA KEV catalog bytes into PUBLIC, hash-pinned research documents."""
    catalog = json.loads(raw)  # json.JSONDecodeError is a ValueError subclass
    documents: list[IngestedDocument] = []
    seen: set[str] = set()
    for entry in catalog.get("vulnerabilities", []):
        cve_id = str(entry.get("cveID", ""))
        if not _CVE_ID.fullmatch(cve_id):
            raise ValueError(f"malformed or missing cveID in KEV entry: {cve_id!r}")
        if cve_id in seen:
            raise ValueError(f"duplicate cveID in KEV catalog: {cve_id}")
        seen.add(cve_id)
        try:
            created_at = date.fromisoformat(str(entry["dateAdded"])[:10])
        except (KeyError, ValueError, TypeError) as exc:
            raise ValueError(f"invalid 'dateAdded' for {cve_id}: {exc}") from exc
        canonical = json.dumps(
            entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        integrity_hash = "sha256:" + hashlib.sha256(canonical).hexdigest()
        document = ResearchDocument(
            document_id=f"KEV-{cve_id}",
            source="CISA KEV",
            document_type=DocumentType.ADVISORY,
            classification=Classification.PUBLIC,
            created_at=created_at,
            source_url=_CATALOG_URL,  # type: ignore[arg-type]
            integrity_hash=integrity_hash,
        )
        documents.append(
            IngestedDocument(document=document, text=_text(cve_id, entry), canonical=canonical)
        )
    return documents


def _text(cve_id: str, entry: dict[str, Any]) -> str:
    """Compose a searchable one-paragraph summary beginning with the CVE id."""
    parts = [
        cve_id,
        str(entry.get("vulnerabilityName", "")),
        f"{entry.get('vendorProject', '')} {entry.get('product', '')}".strip(),
        str(entry.get("shortDescription", "")),
        f"Required action: {entry.get('requiredAction', '')}".strip(),
    ]
    if entry.get("knownRansomwareCampaignUse") == "Known":
        parts.append("Known ransomware campaign use.")
    return " ".join(p for p in parts if p.strip())
