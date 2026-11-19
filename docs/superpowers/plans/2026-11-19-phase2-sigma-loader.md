# Sigma detection-rule loader + index Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ingest a few public SigmaHQ detection rules into the retrieval corpus so `POST /research/search` surfaces the detection rule for a CVE or ATT&CK technique alongside its NVD / KEV / ATT&CK evidence.

**Architecture:** A new stdlib-only `ingestion/sigma.py` loader mirroring `ingestion/kev.py` (canonical SHA-256, fail-loud `ValueError` naming the rule), emitting one `IngestedDocument` per Sigma rule with a **namespaced** `document_id = f"SIGMA-{id}"` and `DocumentType.DETECTION`. Each rule's text carries **canonical correlation tokens** — an `attack.tNNNN[.NNN]` tag → `TNNNN[.NNN]`, a `cve.YYYY.NNNN` tag → `CVE-YYYY-NNNN` — so a technique/CVE search surfaces the detection. The fixture is Sigma YAML converted to JSON **at build time** (runtime stays yaml-free); indexed by `deps.get_service` beside NVD + ATT&CK + KEV. `_research`, the id-routes, `build_report`, and `search` are untouched.

**Tech Stack:** Python 3.12, stdlib only at runtime (`json`, `hashlib`, `re`, `datetime`). PyYAML used at build time only (dev/pre-commit transitive — never imported by `src/`).

**Spec:** `docs/superpowers/specs/2026-11-19-phase2-sigma-loader-design.md`

## Global Constraints

- **stdlib-only at runtime, no new runtime dependency.** No `import yaml` (or other non-stdlib) in any `src/` module. Deterministic, offline.
- PUBLIC/synthetic only. Tests hermetic — loader tests use synthetic in-test JSON.
- Fixture built from **untrusted downloaded bytes in an isolated empty dir**, `python -I` + `yaml.safe_load` (never `yaml.load`), generic User-Agent, no PII. SigmaHQ rules are DRL-1.1 — attribution required.
- **Do NOT modify** `_research`, the `/cve` or `/attack` routes, `build_report`, or `search`.
- `ruff`/`black`/`mypy` clean; line length 100.
- Every commit ends with the attribution footer: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` / `Claude-Session: https://claude.ai/code/session_01P3qwAqqTLRSC3U34YkGnFU`.

## Review Focus

1. **Fail-loud coverage** — malformed JSON / missing `id` / missing `title` / missing-or-invalid `date` / duplicate `id` each raise `ValueError` naming the rule; `status` deprecated/unsupported skipped — Task 1 `test_*_raises` + `test_deprecated_and_unsupported_skipped`.
2. **Correlation works** — `attack.t1059`→`T1059`, `attack.t1059.001`→`T1059.001`, `cve.2021.44228`→`CVE-2021-44228` appear in the text — Task 1 `test_attack_tag_becomes_technique_token` + `test_cve_tag_becomes_cve_token`.
3. **No blast radius / no id-route leak** — a Sigma rule whose text mentions a CVE must NOT be returned by `GET /research/cve/{id}` (its id is `SIGMA-…`, outside `allowed & {cve_id}`) — Task 2 `test_sigma_text_cve_does_not_leak_into_cve_route` + full suite green.
4. **Runtime stays stdlib-only** — no `import yaml` in `src/` — Task 1 `test_runtime_has_no_yaml_import`.
5. **document_id namespacing** — id is `SIGMA-{id}`, never bare — Task 1 `test_document_id_is_namespaced`.

---

### Task 1: `ingestion/sigma.py` loader

**Files:**
- Modify (overwrite stub): `src/secure_ai_research/ingestion/sigma.py`
- Modify: `tests/test_stubs.py` (retire the `sigma.load` stub-contract entry — Sigma is now implemented)
- Test: `tests/test_sigma_ingestion.py`

**Interfaces:**
- Consumes: `IngestedDocument`, `ResearchDocument`, `Classification`, `DocumentType` (existing).
- Produces: `load(raw: bytes) -> list[IngestedDocument]` — one document per rule in the input JSON **array**, `document_id=f"SIGMA-{id}"`, `source="Sigma"`, `document_type=DocumentType.DETECTION`, `classification=PUBLIC`, `created_at` from `date` (slash-normalized), `source_url="https://github.com/SigmaHQ/sigma"`, `integrity_hash` = `sha256:` + canonical hash. Skips `status` deprecated/unsupported. Fail-loud per Review-Focus-1.

- [ ] **Step 1: Write the failing tests** in `tests/test_sigma_ingestion.py`

```python
import json
import re

import pytest

from secure_ai_research.ingestion import sigma
from secure_ai_research.ingestion.schema import Classification, DocumentType

_REPO_URL = "https://github.com/SigmaHQ/sigma"


def _rules(*rules):
    return json.dumps(list(rules)).encode()


def _rule(rule_id="e2072cab-8c9a-459b-b63c-40ae79e27031", **over):
    r = {
        "title": "Suspicious PowerShell Execution",
        "id": rule_id,
        "status": "stable",
        "description": "Detects suspicious command interpreter use.",
        "date": "2021/12/14",
        "tags": ["attack.execution", "attack.t1059", "attack.t1059.001"],
        "logsource": {"product": "windows", "category": "process_creation"},
        "level": "high",
    }
    r.update(over)
    return r


def test_load_parses_rule():
    [doc] = sigma.load(_rules(_rule()))
    assert doc.document.document_id == "SIGMA-e2072cab-8c9a-459b-b63c-40ae79e27031"
    assert doc.document.source == "Sigma"
    assert doc.document.document_type is DocumentType.DETECTION
    assert doc.document.classification is Classification.PUBLIC
    assert str(doc.document.source_url) == _REPO_URL
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", doc.document.integrity_hash)
    assert "Suspicious PowerShell Execution" in doc.text


def test_document_id_is_namespaced():
    [doc] = sigma.load(_rules(_rule("11111111-2222-3333-4444-555555555555")))
    assert doc.document.document_id == "SIGMA-11111111-2222-3333-4444-555555555555"


def test_attack_tag_becomes_technique_token():
    [doc] = sigma.load(_rules(_rule(tags=["attack.execution", "attack.t1059", "attack.t1059.001"])))
    assert "T1059" in doc.text
    assert "T1059.001" in doc.text


def test_cve_tag_becomes_cve_token():
    [doc] = sigma.load(_rules(_rule(tags=["cve.2021.44228"])))
    assert "CVE-2021-44228" in doc.text


def test_date_accepts_slash_and_dash():
    [slash] = sigma.load(_rules(_rule(date="2021/12/14")))
    [dash] = sigma.load(_rules(_rule(date="2021-12-14")))
    assert str(slash.document.created_at) == "2021-12-14"
    assert str(dash.document.created_at) == "2021-12-14"


def test_deprecated_and_unsupported_skipped():
    docs = sigma.load(
        _rules(
            _rule("aaaaaaaa-0000-0000-0000-000000000001", status="deprecated"),
            _rule("aaaaaaaa-0000-0000-0000-000000000002", status="unsupported"),
            _rule("aaaaaaaa-0000-0000-0000-000000000003", status="stable"),
        )
    )
    assert [d.document.document_id for d in docs] == ["SIGMA-aaaaaaaa-0000-0000-0000-000000000003"]


def test_load_missing_id_raises():
    bad = _rule()
    del bad["id"]
    with pytest.raises(ValueError):
        sigma.load(_rules(bad))


def test_load_missing_title_raises():
    with pytest.raises(ValueError, match="e2072cab"):
        sigma.load(_rules(_rule(title="")))


def test_load_bad_date_raises():
    with pytest.raises(ValueError, match="e2072cab"):
        sigma.load(_rules(_rule(date="not-a-date")))


def test_load_duplicate_id_raises():
    with pytest.raises(ValueError, match="e2072cab"):
        sigma.load(_rules(_rule(), _rule()))


def test_load_malformed_json_raises():
    with pytest.raises(ValueError):
        sigma.load(b"{ not valid json")


def test_runtime_has_no_yaml_import():
    import secure_ai_research.ingestion.sigma as mod

    src = __import__("inspect").getsource(mod)
    assert "import yaml" not in src  # runtime stays stdlib-only; YAML is build-time only
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/test_sigma_ingestion.py -q`
Expected: FAIL — `sigma.load` is the existing `NotImplementedError` stub, so every test errors with `NotImplementedError` (feature not implemented). (A stub exists; this task overwrites it — see Step 3.)

- [ ] **Step 3: Implement the loader** in `src/secure_ai_research/ingestion/sigma.py` (overwrite the stub)

Mirror `ingestion/kev.py`. Module constants **after** imports (avoid E402):
`_SKIP_STATUS = {"deprecated", "unsupported"}`, `_REPO_URL = "https://github.com/SigmaHQ/sigma"`,
`_ATTACK_TAG = re.compile(r"attack\.t(\d{4})(\.\d{3})?", re.IGNORECASE)`,
`_CVE_TAG = re.compile(r"cve\.(\d{4})\.(\d+)", re.IGNORECASE)`. Body:

```python
def load(raw: bytes) -> list[IngestedDocument]:
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
```

Imports: `from __future__ import annotations`; `import hashlib`, `import json`, `import re`; `from datetime import date`; `from typing import Any`; `from secure_ai_research.ingestion.ingested import IngestedDocument`; `from secure_ai_research.ingestion.schema import Classification, DocumentType, ResearchDocument`.

- [ ] **Step 4: Retire the Sigma stub-contract entry** in `tests/test_stubs.py`

`sigma.load` is now implemented, so its `STUB_CALLS` entry (which asserts it raises `NotImplementedError`) is wrong. Remove the `(sigma.load, (b"",), {})` tuple **and** the now-unused `from secure_ai_research.ingestion import sigma` import line. (Same retirement the KEV slice did for `kev.load`.)

- [ ] **Step 5: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/test_sigma_ingestion.py tests/test_stubs.py -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/secure_ai_research/ingestion/sigma.py tests/test_sigma_ingestion.py tests/test_stubs.py
git commit   # feat(ingestion): Sigma detection-rule loader  (+ footer)
```

---

### Task 2: Build the fixture + index Sigma in `deps`

**Files:**
- Create: `src/secure_ai_research/ingestion/samples/sigma_sample.json` (built from real SigmaHQ YAML)
- Modify: `src/secure_ai_research/ingestion/samples/ATTRIBUTION.md` (append a SigmaHQ section)
- Modify: `src/secure_ai_research/api/deps.py` (import `sigma`; index `sigma_sample.json` after KEV)
- Test: `tests/test_api.py` (a Sigma rule surfaces via `/research/search`), `tests/test_research_service.py` (a Sigma rule's CVE text does not leak into the CVE id-route)

**Interfaces:**
- Consumes: `sigma.load` (Task 1); `deps.get_service`; `POST /research/search`.
- Produces: Sigma documents in the default process corpus.

- [ ] **Step 1: Build the fixture from real SigmaHQ rules** (one-time, build-time only)

In an **isolated empty dir** under the scratchpad, download **2 rules** with a generic UA: one tagged
`attack.t1059` (e.g. a `process_creation` command-interpreter rule) and one tied to **CVE-2021-44228**
(a Log4j/Log4Shell rule carrying `cve.2021.44228`). Use the SigmaHQ `raw.githubusercontent.com` URLs
(find exact paths by browsing `github.com/SigmaHQ/sigma`). Convert with `python -I` + `yaml.safe_load`
into a JSON **array** written to `src/secure_ai_research/ingestion/samples/sigma_sample.json`. Confirm
each rule has `id`, `title`, `date`, and the expected tag; if a chosen rule lacks it, pick another
(ledger ruling if the real shape forces a change).

Sanity check: `.venv/bin/python -c "from secure_ai_research.ingestion import sigma; from importlib.resources import files; docs=sigma.load(files('secure_ai_research.ingestion').joinpath('samples','sigma_sample.json').read_bytes()); print([d.document.document_id for d in docs]); print(['T1059' in d.text or 'CVE-2021-44228' in d.text for d in docs])"` — prints `SIGMA-…` ids and shows the correlation tokens present.

- [ ] **Step 2: Append the SigmaHQ section to `ATTRIBUTION.md`**

Credit `sigma_sample.json` to **SigmaHQ** — repo URL, the two rule paths, retrieval date 2026-11-19, and the Detection Rule License (DRL) 1.1.

- [ ] **Step 3: Write the failing tests**

In `tests/test_research_service.py` (add `from secure_ai_research.ingestion import sigma`; reuses `_docs`, `authorize`, `HashingEmbedder`, `InMemoryVectorStore`, `ResearchService`, `Outcome`):
```python
def test_sigma_text_cve_does_not_leak_into_cve_route(tmp_path):
    # A Sigma rule whose text mentions a CVE (via a cve.* tag) is reachable by SEARCH but must never
    # be returned by the CVE id-route: its id is SIGMA-…, outside research_cve's allowed & {cve_id}.
    import json

    audit = tmp_path / "a.jsonl"
    svc = ResearchService(HashingEmbedder(), InMemoryVectorStore(), authorize, audit)
    svc.index(_docs())  # NVD CVE-2099-0001
    sigma_raw = json.dumps(
        [{"title": "t", "id": "dddddddd-0000-0000-0000-000000000001", "status": "stable",
          "date": "2099-01-01", "tags": ["cve.2099.0001"], "logsource": {"product": "x"}}]
    ).encode()
    svc.index(sigma.load(sigma_raw))  # text contains "CVE-2099-0001"
    res = svc.research_cve("CVE-2099-0001", role="research_analyst")
    assert res.outcome is Outcome.OK
    assert all(c.document_id == "CVE-2099-0001" for c in res.citations)  # never SIGMA-…
```

In `tests/test_api.py` (real `get_service`, mirroring the `test_deps_*` env+cache_clear pattern):
```python
def test_deps_sigma_rule_is_searchable(tmp_path, monkeypatch):
    monkeypatch.setenv("SAIR_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    get_settings.cache_clear()
    get_service.cache_clear()
    try:
        resp = client.post(
            "/research/search", json={"query": "T1059"},
            headers={"X-Role": "research_analyst"},
        )
        assert resp.status_code == 200
        assert any(r["document_id"].startswith("SIGMA-") for r in resp.json()["results"])
    finally:
        get_service.cache_clear()
        get_settings.cache_clear()
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/test_research_service.py::test_sigma_text_cve_does_not_leak_into_cve_route tests/test_api.py::test_deps_sigma_rule_is_searchable -q`
Expected: FAIL — `test_deps_sigma_rule_is_searchable` returns 200 but no `SIGMA-` result (Sigma not indexed in deps yet). The leak test passes already (exercises the Task-1 loader + existing index behavior, not the wiring) — acceptable; the wiring test carries the RED.

- [ ] **Step 5: Wire Sigma into `deps.get_service`** in `src/secure_ai_research/api/deps.py`

Change the import to `from secure_ai_research.ingestion import attack, kev, nvd, sigma` and, after the KEV index block, add:
```python
    sigma_raw = (
        files("secure_ai_research.ingestion").joinpath("samples", "sigma_sample.json").read_bytes()
    )
    service.index(sigma.load(sigma_raw))
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/test_api.py tests/test_research_service.py -q`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/secure_ai_research/ingestion/samples/sigma_sample.json src/secure_ai_research/ingestion/samples/ATTRIBUTION.md src/secure_ai_research/api/deps.py tests/test_api.py tests/test_research_service.py
git commit   # feat(ingestion): index SigmaHQ fixture at startup  (+ footer)
```

---

## Final checks (before review)

- [ ] `.venv/bin/pytest -q` — full suite green (hermetic).
- [ ] `.venv/bin/ruff check .` && `.venv/bin/black --check .` && `.venv/bin/mypy` — clean.
- [ ] `grep -rn "import yaml" src/` — no hits (runtime stdlib-only).
