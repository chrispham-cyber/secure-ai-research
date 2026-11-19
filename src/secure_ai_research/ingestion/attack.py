"""MITRE ATT&CK ingestion (ROADMAP Phase 2).

Parse an ATT&CK STIX 2.1 bundle into :class:`IngestedDocument` records — one per
technique (``attack-pattern``) — classification pinned to PUBLIC, each carrying a
``sha256:`` integrity hash of its **canonical** source object so downstream
retrieval can prove provenance. Revoked and deprecated techniques are skipped:
they are not current ATT&CK and must never answer a live query.

Fail-loud: malformed JSON, an attack-pattern with no ``mitre-attack`` external id,
a non-date ``created``, or a duplicate technique id raises ``ValueError`` naming
the offending id — a research corpus is never silently built from bad input.
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
    """Parse raw ATT&CK STIX bundle bytes into research documents.

    One :class:`IngestedDocument` per non-revoked, non-deprecated ``attack-pattern``.
    Raises ``ValueError`` (naming the offending STIX id) on malformed JSON, a missing
    ``mitre-attack`` external id, a non-date ``created``, or a duplicate technique id.
    """
    bundle = json.loads(raw)  # json.JSONDecodeError is a ValueError subclass
    documents: list[IngestedDocument] = []
    seen: set[str] = set()
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        # Revoked/deprecated techniques are not current ATT&CK — omit, do not error.
        if obj.get("revoked") is True or obj.get("x_mitre_deprecated") is True:
            continue
        technique_id = _external_id(obj)
        if technique_id in seen:
            raise ValueError(f"duplicate technique id in bundle: {technique_id}")
        seen.add(technique_id)
        try:
            created_at = date.fromisoformat(str(obj["created"])[:10])
        except (KeyError, ValueError, TypeError) as exc:
            raise ValueError(f"invalid 'created' date for {technique_id}: {exc}") from exc
        canonical = json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        integrity_hash = "sha256:" + hashlib.sha256(canonical).hexdigest()
        source_url = "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"
        text = f"{obj['name']}: {obj['description']}"
        document = ResearchDocument(
            document_id=technique_id,
            source="MITRE ATT&CK",
            document_type=DocumentType.TECHNIQUE,
            classification=Classification.PUBLIC,
            created_at=created_at,
            source_url=source_url,  # type: ignore[arg-type]
            integrity_hash=integrity_hash,
        )
        documents.append(IngestedDocument(document=document, text=text))
    return documents


def _external_id(obj: dict[str, Any]) -> str:
    """Return the technique's ATT&CK id (e.g. ``T1059``) from its external references.

    Raises ``ValueError`` naming the STIX id when no ``mitre-attack`` reference carries
    an ``external_id`` — a technique with no ATT&CK id cannot be cited or linked.
    """
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            ext = ref.get("external_id")
            if ext is None:
                raise ValueError(f"mitre-attack reference for {obj.get('id')} has no external_id")
            return str(ext)
    raise ValueError(f"no mitre-attack external id for {obj.get('id')}")
