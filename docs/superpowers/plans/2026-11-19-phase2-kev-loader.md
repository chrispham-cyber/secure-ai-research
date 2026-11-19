# CISA KEV loader + index Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ingest the public CISA KEV (Known Exploited Vulnerabilities) catalog into the retrieval corpus so `POST /research/search` surfaces the KEV entry for a CVE alongside its NVD and ATT&CK evidence.

**Architecture:** A new stdlib-only `ingestion/kev.py` loader mirroring `ingestion/attack.py` (canonical SHA-256, fail-loud `ValueError` naming the CVE id), emitting one `IngestedDocument` per catalog entry with a **namespaced** `document_id = f"KEV-{cveID}"` (so it never collides with an NVD CVE doc and is reachable via search, not the single-doc CVE id-route). A small committed fixture built from the live catalog is indexed by `deps.get_service` beside NVD + ATT&CK. `_research`, the id-routes, `build_report`, and `search` are untouched.

**Tech Stack:** Python 3.12, stdlib only (`json`, `hashlib`, `re`, `datetime`). No new runtime dependency.

**Spec:** `docs/superpowers/specs/2026-11-19-phase2-kev-loader-design.md`

## Global Constraints

- **stdlib-only, no new runtime dependency.** Deterministic, offline.
- PUBLIC/synthetic only. Tests hermetic — no network outside `@pytest.mark.integration` (there is none here; loader tests use synthetic in-test JSON).
- The fixture is built from **untrusted downloaded bytes in an isolated empty dir**, processed with `python -I`; fetch with a **generic User-Agent, no PII** (never the user's name/email). CISA KEV is a U.S. Government work (public domain, 17 U.S.C. §105); attribution is courtesy.
- **Do NOT modify** `_research`, the `/cve` or `/attack` routes, `build_report`, or `search` — KEV is purely additional corpus.
- `ruff`/`black`/`mypy` clean; line length 100.
- Every commit ends with the attribution footer:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` / `Claude-Session: https://claude.ai/code/session_01P3qwAqqTLRSC3U34YkGnFU`.

## Review Focus

1. **Fail-loud coverage** — malformed JSON / missing `cveID` / `cveID` not `^CVE-\d{4}-\d{4,}$` / missing-or-invalid `dateAdded` / duplicate `cveID` each raise `ValueError` naming the CVE id — Task 1 `test_load_*_raises`.
2. **No blast radius** — indexing KEV leaves the CVE id-route byte-identical: a `KEV-CVE-…` doc never satisfies `research_cve`'s `allowed & {cve_id}` — Task 2 `test_kev_does_not_shadow_cve_route` + full suite green.
3. **document_id namespacing** — the id is `KEV-{cveID}`, never the bare CVE id, so it cannot collide with an NVD/ATT&CK id — Task 1 `test_document_id_is_namespaced`.
4. **Citation/provenance integrity** — `source="CISA KEV"`, `source_url` is the CISA catalog, `integrity_hash` is of the exact entry object — Task 1 `test_load_parses_entry` + `test_integrity_hash_is_key_order_independent`.
5. **Determinism/hermeticity** — no network at import/query time; fixture committed; suite passes offline — structural (loader tests use synthetic JSON); no new test.

---

### Task 1: `ingestion/kev.py` loader

**Files:**
- Create: `src/secure_ai_research/ingestion/kev.py`
- Test: `tests/test_kev_ingestion.py`

**Interfaces:**
- Consumes: `IngestedDocument`, `ResearchDocument`, `Classification`, `DocumentType` (existing).
- Produces: `load(raw: bytes) -> list[IngestedDocument]` — one document per `vulnerabilities[]` entry, `document_id=f"KEV-{cveID}"`, `source="CISA KEV"`, `document_type=DocumentType.ADVISORY`, `classification=PUBLIC`, `created_at=dateAdded`, `source_url` = the CISA catalog URL, `integrity_hash` = `sha256:` + canonical hash of the entry. Fail-loud `ValueError` on the §Review-Focus-1 malformations.

- [ ] **Step 1: Write the failing tests** in `tests/test_kev_ingestion.py`

```python
import json
import re

import pytest

from secure_ai_research.ingestion import kev
from secure_ai_research.ingestion.schema import Classification, DocumentType

_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


def _catalog(*entries):
    return json.dumps({"title": "KEV", "count": len(entries), "vulnerabilities": list(entries)}).encode()


def _entry(cve_id="CVE-2021-44228", **over):
    e = {
        "cveID": cve_id,
        "vendorProject": "Apache",
        "product": "Log4j2",
        "vulnerabilityName": "Apache Log4j2 RCE",
        "dateAdded": "2021-12-10",
        "shortDescription": "JNDI lookup remote code execution.",
        "requiredAction": "Apply updates.",
        "dueDate": "2021-12-24",
        "knownRansomwareCampaignUse": "Unknown",
    }
    e.update(over)
    return e


def test_load_parses_entry():
    [doc] = kev.load(_catalog(_entry()))
    assert doc.document.document_id == "KEV-CVE-2021-44228"
    assert doc.document.source == "CISA KEV"
    assert doc.document.document_type is DocumentType.ADVISORY
    assert doc.document.classification is Classification.PUBLIC
    assert str(doc.document.source_url) == _CATALOG_URL
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", doc.document.integrity_hash)
    assert "CVE-2021-44228" in doc.text and "Log4j2" in doc.text


def test_document_id_is_namespaced():
    # Must be KEV-prefixed, never the bare CVE id, so it cannot collide with an NVD doc.
    [doc] = kev.load(_catalog(_entry("CVE-2099-0001")))
    assert doc.document.document_id == "KEV-CVE-2099-0001"


def test_text_includes_ransomware_only_when_known():
    [known] = kev.load(_catalog(_entry(knownRansomwareCampaignUse="Known")))
    [unknown] = kev.load(_catalog(_entry(knownRansomwareCampaignUse="Unknown")))
    assert "ransomware" in known.text.lower()
    assert "ransomware" not in unknown.text.lower()


def test_load_missing_cveid_raises():
    bad = _entry()
    del bad["cveID"]
    with pytest.raises(ValueError):
        kev.load(_catalog(bad))


@pytest.mark.parametrize("bad_id", ["CVE-21-1", "2021-44228", "", "CVE-2021-abc"])
def test_load_malformed_cveid_raises(bad_id):
    with pytest.raises(ValueError):
        kev.load(_catalog(_entry(bad_id)))


def test_load_invalid_dateadded_raises():
    with pytest.raises(ValueError, match="CVE-2021-44228"):
        kev.load(_catalog(_entry(dateAdded="not-a-date")))


def test_load_duplicate_cveid_raises():
    with pytest.raises(ValueError, match="CVE-2021-44228"):
        kev.load(_catalog(_entry(), _entry()))


def test_load_malformed_json_raises():
    with pytest.raises(ValueError):
        kev.load(b"{ not valid json")


def test_integrity_hash_is_key_order_independent():
    a = {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "vulnerabilityName": "x"}
    b = dict(reversed(list(a.items())))
    assert kev.load(_catalog(a))[0].document.integrity_hash == kev.load(_catalog(b))[0].document.integrity_hash
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/test_kev_ingestion.py -q`
Expected: FAIL — `ModuleNotFoundError: secure_ai_research.ingestion.kev` (module does not exist yet).

- [ ] **Step 3: Implement the loader** in `src/secure_ai_research/ingestion/kev.py`

Mirror `ingestion/attack.py` (module docstring, fail-loud style, canonical hash). Module constants (`_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")`, `_CATALOG_URL = "…"`) go **after** all imports (avoid E402). Body:

```python
def load(raw: bytes) -> list[IngestedDocument]:
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
        documents.append(IngestedDocument(document=document, text=_text(cve_id, entry)))
    return documents


def _text(cve_id: str, entry: dict[str, Any]) -> str:
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
```

Imports: `from __future__ import annotations`; `import hashlib`, `import json`, `import re`; `from datetime import date`; `from typing import Any`; `from secure_ai_research.ingestion.ingested import IngestedDocument`; `from secure_ai_research.ingestion.schema import Classification, DocumentType, ResearchDocument`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/test_kev_ingestion.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/secure_ai_research/ingestion/kev.py tests/test_kev_ingestion.py
git commit   # feat(ingestion): CISA KEV catalog loader  (+ footer)
```

---

### Task 2: Build the fixture + index KEV in `deps`

**Files:**
- Create: `src/secure_ai_research/ingestion/samples/kev_sample.json` (built from the live catalog)
- Modify: `src/secure_ai_research/ingestion/samples/ATTRIBUTION.md` (append a CISA KEV section)
- Modify: `src/secure_ai_research/api/deps.py` (import `kev`; index `kev_sample.json` after ATT&CK)
- Test: `tests/test_api.py` (KEV CVE searchable via the live endpoint), `tests/test_research_service.py` (KEV coexists with NVD without shadowing the CVE id-route)

**Interfaces:**
- Consumes: `kev.load` (Task 1); `deps.get_service`; the running app's `POST /research/search`.
- Produces: KEV documents in the default process corpus.

- [ ] **Step 1: Build the fixture from the live catalog** (one-time, build-time only)

In an **isolated empty dir** under the scratchpad, download the catalog with a generic UA and extract a few entries with `python -I`:
```bash
D=$(mktemp -d) && curl -sS -A "secure-ai-research-fixture-builder" \
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
  -o "$D/kev.json"
```
Then, with `python -I`, select ~3 entries — **CVE-2021-44228** (Log4Shell; also the NVD live-fetch test CVE), at least one with `knownRansomwareCampaignUse == "Known"`, and one other — keeping each entry's fields verbatim, and write them as `{"title","catalogVersion","dateReleased","count","vulnerabilities":[...3...]}` to `src/secure_ai_research/ingestion/samples/kev_sample.json`. Confirm the real field names match the spec (`cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,requiredAction,dueDate,knownRansomwareCampaignUse`); if the live shape differs, adjust the loader + a ledger ruling.

Sanity check: `.venv/bin/python -c "from secure_ai_research.ingestion import kev; from importlib.resources import files; print([d.document.document_id for d in kev.load(files('secure_ai_research.ingestion').joinpath('samples','kev_sample.json').read_bytes())])"` prints the `KEV-CVE-…` ids with no error.

- [ ] **Step 2: Append the CISA KEV section to `ATTRIBUTION.md`**

Credit `kev_sample.json` to CISA (source URL + retrieval date 2026-11-19 + a note it is a U.S. Government work in the public domain, 17 U.S.C. §105).

- [ ] **Step 3: Write the failing tests**

In `tests/test_research_service.py` (reuses `_docs`, `authorize`, `HashingEmbedder`, `InMemoryVectorStore`, `ResearchService`, `Outcome`; add `from secure_ai_research.ingestion import kev` and reuse the `_mk`/`_catalog` idea inline):
```python
def test_kev_does_not_shadow_cve_route(tmp_path):
    # A KEV doc for the same CVE as an NVD fixture doc coexists (namespaced id) and the
    # CVE id-route still returns the NVD document, never the KEV one.
    import json
    audit = tmp_path / "a.jsonl"
    svc = ResearchService(HashingEmbedder(), InMemoryVectorStore(), authorize, audit)
    svc.index(_docs())  # NVD CVE-2099-0001 / CVE-2099-0002
    kev_raw = json.dumps({"vulnerabilities": [
        {"cveID": "CVE-2099-0001", "dateAdded": "2099-01-01", "vulnerabilityName": "dup",
         "shortDescription": "s", "requiredAction": "a"}]}).encode()
    svc.index(kev.load(kev_raw))  # must NOT raise (KEV id is KEV-CVE-2099-0001)
    res = svc.research_cve("CVE-2099-0001", role="research_analyst")
    assert res.outcome is Outcome.OK
    assert all(c.document_id == "CVE-2099-0001" for c in res.citations)  # never KEV-…
```

In `tests/test_api.py` (real `get_service`, mirroring the existing `test_deps_*` env+cache_clear pattern):
```python
def test_deps_kev_entry_is_searchable(tmp_path, monkeypatch):
    monkeypatch.setenv("SAIR_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    get_settings.cache_clear()
    get_service.cache_clear()
    try:
        resp = client.post(
            "/research/search", json={"query": "CVE-2021-44228"},
            headers={"X-Role": "research_analyst"},
        )
        assert resp.status_code == 200
        assert any(r["document_id"] == "KEV-CVE-2021-44228" for r in resp.json()["results"])
    finally:
        get_service.cache_clear()
        get_settings.cache_clear()
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/test_research_service.py::test_kev_does_not_shadow_cve_route tests/test_api.py::test_deps_kev_entry_is_searchable -q`
Expected: FAIL — `test_deps_kev_entry_is_searchable` returns 200 but no `KEV-CVE-2021-44228` result (KEV not indexed yet); the coexistence test passes already if the loader is correct (it exercises the loader, not the wiring) — acceptable, it is the wiring test that must go RED.

- [ ] **Step 5: Wire KEV into `deps.get_service`** in `src/secure_ai_research/api/deps.py`

Change the import to `from secure_ai_research.ingestion import attack, kev, nvd` and, after the ATT&CK index block, add:
```python
    kev_raw = files("secure_ai_research.ingestion").joinpath("samples", "kev_sample.json").read_bytes()
    service.index(kev.load(kev_raw))
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/test_api.py tests/test_research_service.py -q`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/secure_ai_research/ingestion/samples/kev_sample.json src/secure_ai_research/ingestion/samples/ATTRIBUTION.md src/secure_ai_research/api/deps.py tests/test_api.py tests/test_research_service.py
git commit   # feat(ingestion): index CISA KEV fixture at startup  (+ footer)
```

---

## Final checks (before review)

- [ ] `.venv/bin/pytest -q` — full suite green (hermetic).
- [ ] `.venv/bin/ruff check .` && `.venv/bin/black --check .` && `.venv/bin/mypy` — clean.
