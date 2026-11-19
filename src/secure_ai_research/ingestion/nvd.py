"""NVD ingestion (ROADMAP Phase 2).

Parse an NVD 2.0 CVE feed into :class:`IngestedDocument` records: one per CVE,
classification pinned to PUBLIC, each carrying a ``sha256:`` integrity hash of
its **canonical** source payload so downstream retrieval can prove provenance.

Fail-loud: malformed JSON, a CVE with no English description, or a duplicate id
raises ``ValueError`` — a research corpus is never silently built from bad input.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date
from typing import Any

from secure_ai_research.ingestion.ingested import IngestedDocument
from secure_ai_research.ingestion.schema import (
    Classification,
    DocumentType,
    ResearchDocument,
)


def load(raw: bytes) -> list[IngestedDocument]:
    """Parse raw NVD 2.0 feed bytes into research documents.

    Raises ``ValueError`` on malformed JSON, a CVE lacking an English
    description, or a duplicate CVE id.
    """
    feed = json.loads(raw)  # json.JSONDecodeError is a ValueError subclass
    documents: list[IngestedDocument] = []
    seen: set[str] = set()
    for item in feed.get("vulnerabilities", []):
        cve = item["cve"]
        cve_id = cve["id"]
        if cve_id in seen:
            raise ValueError(f"duplicate CVE id in feed: {cve_id}")
        seen.add(cve_id)
        text = _english_description(cve, cve_id)
        canonical = json.dumps(
            cve, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        integrity_hash = "sha256:" + hashlib.sha256(canonical).hexdigest()
        document = ResearchDocument(
            document_id=cve_id,
            source="NVD",
            document_type=DocumentType.VULNERABILITY,
            classification=Classification.PUBLIC,
            created_at=date.fromisoformat(cve["published"][:10]),
            source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",  # type: ignore[arg-type]
            integrity_hash=integrity_hash,
        )
        documents.append(IngestedDocument(document=document, text=text))
    return documents


def _english_description(cve: dict[str, Any], cve_id: str) -> str:
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            return str(desc["value"])
    raise ValueError(f"no English description for {cve_id}")
