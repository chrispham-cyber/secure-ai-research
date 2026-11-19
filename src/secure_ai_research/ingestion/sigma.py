"""Sigma detection-rule ingestion (ROADMAP Phase 2).

Parse public SigmaHQ detection rules into :class:`IngestedDocument` records so
retrieval can tie a vulnerability or technique to the detections that cover it.
One document per rule, PUBLIC, pinned to a ``sha256:`` hash of its canonical
source object; the document id is **namespaced** ``SIGMA-{id}`` so a rule never
collides with an NVD/ATT&CK/KEV document and is reachable through corpus search
rather than a single-document id route.

Each rule's text carries **canonical correlation tokens** derived from its tags:
an ``attack.tNNNN[.NNN]`` tag becomes ``TNNNN[.NNN]`` and a ``cve.YYYY-NNNN`` tag
(the current SigmaHQ form; the older ``cve.YYYY.NNNN`` is also accepted) becomes
``CVE-YYYY-NNNN``, so a search for a technique or CVE id surfaces the
detection beside the ATT&CK / NVD / KEV documents.

Input is a JSON **array** of rule objects — Sigma rules are authored in YAML, but
this module is stdlib-only at runtime, so the rules are converted to JSON at build
time (see ``samples/sigma_sample.json``). Rules with ``status`` ``deprecated`` or
``unsupported`` are skipped. Fail-loud: malformed JSON, a missing ``id`` or
``title``, a missing/invalid ``date``, or a duplicate ``id`` each raise
``ValueError`` naming the offending rule.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date
from typing import Any

from secure_ai_research.ingestion.ingested import IngestedDocument
from secure_ai_research.ingestion.schema import Classification, DocumentType, ResearchDocument

_SKIP_STATUS = {"deprecated", "unsupported"}
_REPO_URL = "https://github.com/SigmaHQ/sigma"
_ATTACK_TAG = re.compile(r"attack\.t(\d{4})(\.\d{3})?", re.IGNORECASE)
# cve.YYYY-NNNN (current SigmaHQ) or the older cve.YYYY.NNNN
_CVE_TAG = re.compile(r"cve\.(\d{4})[.-](\d+)", re.IGNORECASE)


def load(raw: bytes) -> list[IngestedDocument]:
    """Parse a JSON array of Sigma rules into PUBLIC, hash-pinned research documents."""
    rules = json.loads(raw)  # json.JSONDecodeError is a ValueError subclass
    documents: list[IngestedDocument] = []
    seen: set[str] = set()
    for rule in rules:
        if rule.get("status") in _SKIP_STATUS:
            continue
        rule_id = str(rule.get("id", "")).strip()
        title = str(rule.get("title", "")).strip()
        if not rule_id:
            raise ValueError(f"Sigma rule missing 'id' (title={title!r})")
        if rule_id in seen:
            raise ValueError(f"duplicate Sigma rule id: {rule_id}")
        seen.add(rule_id)
        if not title:
            raise ValueError(f"Sigma rule {rule_id} missing 'title'")
        try:
            created_at = date.fromisoformat(str(rule["date"]).replace("/", "-")[:10])
        except (KeyError, ValueError, TypeError) as exc:
            raise ValueError(f"invalid 'date' for Sigma rule {rule_id}: {exc}") from exc
        canonical = json.dumps(
            rule, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        integrity_hash = "sha256:" + hashlib.sha256(canonical).hexdigest()
        document = ResearchDocument(
            document_id=f"SIGMA-{rule_id}",
            source="Sigma",
            document_type=DocumentType.DETECTION,
            classification=Classification.PUBLIC,
            created_at=created_at,
            source_url=_REPO_URL,  # type: ignore[arg-type]
            integrity_hash=integrity_hash,
        )
        documents.append(IngestedDocument(document=document, text=_text(rule)))
    return documents


def _text(rule: dict[str, Any]) -> str:
    """Compose searchable text: title, description, correlation tokens, logsource, tags."""
    tags = [str(t) for t in rule.get("tags", [])]
    tokens: list[str] = []
    for t in tags:
        m = _ATTACK_TAG.fullmatch(t)
        if m:
            tokens.append("T" + m.group(1) + (m.group(2) or ""))
            continue
        c = _CVE_TAG.fullmatch(t)
        if c:
            tokens.append(f"CVE-{c.group(1)}-{c.group(2)}")
    ls = rule.get("logsource", {}) or {}
    parts = [
        str(rule.get("title", "")),
        str(rule.get("description", "")),
        " ".join(tokens),
        " ".join(str(ls.get(k, "")) for k in ("product", "category", "service")),
        f"severity: {rule.get('level', '')}",
        " ".join(t.replace(".", " ") for t in tags),
    ]
    return " ".join(p for p in (s.strip() for s in parts) if p)
