# ATT&CK Technique Endpoint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `GET /research/attack/{technique_id}` a real cited, audited endpoint that answers for a MITRE ATT&CK technique through the same pipeline as the CVE path.

**Architecture:** Approach 1 (sibling wrappers over a shared private `_research` core). A new stdlib-`json` STIX loader turns a real ATT&CK bundle into `IngestedDocument`s (one per technique); `ResearchService` grows a generic `_research` core that `research_cve` and a new `research_attack` both wrap; the citation regex and the route are extended; a real MITRE fixture is indexed at startup. No new runtime deps, no network on the attack path.

**Tech Stack:** Python 3.12, stdlib only (`json`, `hashlib`, `re`, `datetime`), FastAPI, pydantic. `.venv/bin/python`, `.venv/bin/pytest -q`.

**Spec:** `docs/superpowers/specs/2026-11-19-phase2-attack-endpoint-design.md`

## Global Constraints

- stdlib only; **no new runtime dependency**. (STIX is JSON → `json`.)
- `classification` is **PUBLIC only** (schema-enforced); `integrity_hash` is `sha256:<64 hex>`.
- Authorize-before-retrieve; **exactly one audit record per request**; no existence oracle (absent and present-but-unauthorized both → NOT_FOUND).
- The attack path **never fetches** — a miss is NOT_FOUND (404), never FETCH_ERROR (503); `research_attack` passes no fetcher, so `self._fetch_missing` (a CVE fetcher) is never called with a technique id.
- The CVE path (service, route, `fetch_cve`, its tests) keeps its behavior **unchanged**.
- Lint/type clean at line length 100: `.venv/bin/ruff check .`, `.venv/bin/black --check .`, `.venv/bin/mypy` (`files=["src"]`). isort within a group: plain `import x` before `from x import y`, then alphabetical.
- Default test suite stays **hermetic** (no network in any non-`integration` test). Test command: `.venv/bin/pytest -q`.
- Every commit ends with the attribution footer:
  ```
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01P3qwAqqTLRSC3U34YkGnFU
  ```

## Review Focus

- **Sub-technique ids** (`T1059.001`): must round-trip through the path pattern, the loader, the citation regex, and the source URL (`…/techniques/T1059/001/`). A reasonable user queries a sub-technique and expects 200 + the right link. → Task 1 (`test_load_parses_subtechnique`), Task 4 (`test_attack_subtechnique_200`).
- **Revoked / deprecated techniques** in the real bundle: must be skipped at load, so a revoked id answers 404, never a stale technique. → Task 1 (`test_load_skips_revoked_and_deprecated`), Task 5 (`test_deps_revoked_technique_is_404`).
- **Tactic-style / malformed ids** (`TA0001`, `T123`, `t1059`, `1059`): rejected with 422 at the route before any service call or audit record. → Task 4 (`test_attack_malformed_is_422`).
- **Markdown in descriptions** (`[Name](url)`, `(Citation: X)`): a stray bracket token must not be read as a citation and must not drop a legitimately `[T####]`-cited line. → Task 2 (`test_markdown_brackets_not_citations`).
- **Un-indexed well-formed id with a CVE fetcher wired** (`SAIR_ALLOW_LIVE_FETCH` on): `research_attack` must return NOT_FOUND with one audit record and **never** invoke the fetcher. → Task 3 (`test_research_attack_never_fetches`).

---

### Task 1: ATT&CK STIX loader

**Files:**
- Modify: `src/secure_ai_research/ingestion/attack.py` (replace the `NotImplementedError` stub)
- Modify: `tests/test_stubs.py` (remove the now-real `attack.load` row)
- Test: `tests/test_attack_ingestion.py` (create)

**Interfaces:**
- Consumes: `IngestedDocument(document, text)`; `ResearchDocument(document_id, source, document_type, classification, created_at, source_url, integrity_hash)`; `DocumentType.TECHNIQUE`, `Classification.PUBLIC`.
- Produces: `load(raw: bytes) -> list[IngestedDocument]` — one `IngestedDocument` per non-revoked `attack-pattern`, `document_id` = the `mitre-attack` `external_id` (e.g. `T1059`, `T1059.001`), `source="MITRE ATT&CK"`, `document_type=TECHNIQUE`, `source_url="https://attack.mitre.org/techniques/<id-with-dots-as-slashes>/"`, `text=f"{name}: {description}"`, `integrity_hash="sha256:"+sha256(canonical).hexdigest()` over `json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=False)`. Fail-loud `ValueError` (naming the STIX id or feed index) on malformed JSON, missing `mitre-attack` external id, missing/invalid `created`, or a duplicate technique id.

- [ ] **Step 1: Write the failing tests** in `tests/test_attack_ingestion.py`

Build small inline STIX bundles (real-shape) in each test. Key tests and assertions:

```python
def _bundle(*objects):
    return json.dumps({"type": "bundle", "id": "bundle--x", "objects": list(objects)}).encode()

def _ap(ext_id, name="Command and Scripting Interpreter", desc="Adversaries abuse interpreters.",
        created="2017-05-31T21:30:18.931Z", revoked=False, deprecated=False):
    obj = {"type": "attack-pattern", "id": f"attack-pattern--{ext_id}", "name": name,
           "description": desc, "created": created,
           "external_references": [{"source_name": "mitre-attack", "external_id": ext_id,
                                    "url": f"https://attack.mitre.org/techniques/{ext_id}"}]}
    if revoked: obj["revoked"] = True
    if deprecated: obj["x_mitre_deprecated"] = True
    return obj

def test_load_parses_technique():
    [doc] = attack.load(_bundle(_ap("T1059")))
    assert doc.document.document_id == "T1059"
    assert doc.document.document_type is DocumentType.TECHNIQUE
    assert doc.document.source == "MITRE ATT&CK"
    assert doc.document.classification is Classification.PUBLIC
    assert str(doc.document.source_url) == "https://attack.mitre.org/techniques/T1059/"
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", doc.document.integrity_hash)
    assert "Command and Scripting Interpreter" in doc.text and "abuse interpreters" in doc.text

def test_load_parses_subtechnique():
    [doc] = attack.load(_bundle(_ap("T1059.001", name="PowerShell")))
    assert doc.document.document_id == "T1059.001"
    assert str(doc.document.source_url) == "https://attack.mitre.org/techniques/T1059/001/"

def test_load_skips_revoked_and_deprecated():
    docs = attack.load(_bundle(_ap("T1059"), _ap("T1064", revoked=True), _ap("T1066", deprecated=True)))
    assert [d.document.document_id for d in docs] == ["T1059"]

def test_load_ignores_non_attack_pattern():
    other = {"type": "course-of-action", "id": "course-of-action--y", "name": "Mitigation"}
    docs = attack.load(_bundle(other, _ap("T1059")))
    assert [d.document.document_id for d in docs] == ["T1059"]

def test_load_missing_mitre_external_id_raises():
    bad = {"type": "attack-pattern", "id": "attack-pattern--z", "name": "x", "description": "y",
           "created": "2017-05-31T21:30:18.931Z", "external_references": [{"source_name": "capec"}]}
    with pytest.raises(ValueError, match="attack-pattern--z"):
        attack.load(_bundle(bad))

def test_load_duplicate_technique_id_raises():
    with pytest.raises(ValueError, match="T1059"):
        attack.load(_bundle(_ap("T1059"), _ap("T1059")))

def test_load_invalid_created_raises():
    with pytest.raises(ValueError, match="T1059"):
        attack.load(_bundle(_ap("T1059", created="not-a-date")))

def test_load_malformed_json_raises():
    with pytest.raises(ValueError):
        attack.load(b"{ not valid json")

def test_integrity_hash_is_key_order_independent():
    a = {"type": "attack-pattern", "id": "attack-pattern--T1059", "name": "n", "description": "d",
         "created": "2017-05-31T21:30:18.931Z",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}]}
    b = dict(reversed(list(a.items())))
    assert attack.load(_bundle(a))[0].document.integrity_hash == attack.load(_bundle(b))[0].document.integrity_hash
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/test_attack_ingestion.py -q`
Expected: FAIL — `NotImplementedError` from the stub.

- [ ] **Step 3: Implement `load(raw: bytes) -> list[IngestedDocument]`** in `src/secure_ai_research/ingestion/attack.py`

Mirror `nvd.load` (`ingestion/nvd.py`): `json.loads`; iterate `bundle.get("objects", [])`; keep `obj.get("type") == "attack-pattern"`; skip when `obj.get("revoked") is True` or `obj.get("x_mitre_deprecated") is True`; derive the id via a helper `_external_id(obj)` that returns the `external_id` of the `external_references` entry whose `source_name == "mitre-attack"` and raises `ValueError` naming `obj.get("id")` when absent; dedup ids in a `seen` set (fail-loud on repeat); `created_at = date.fromisoformat(str(obj["created"])[:10])` in a try/except → `ValueError` naming the id; `source_url = "https://attack.mitre.org/techniques/" + external_id.replace(".", "/") + "/"`; `text = f"{obj['name']}: {obj['description']}"`; canonical hash exactly as `nvd.load`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/test_attack_ingestion.py -q`
Expected: PASS (all).

- [ ] **Step 5: Remove the stale stub assertion**

Run: `.venv/bin/pytest tests/test_stubs.py -q`
Expected: FAIL — the parametrized `(attack.load, (b"",), {})` row no longer raises `NotImplementedError`.
Then delete only that one row from the parametrize list in `tests/test_stubs.py` (keep the `attack, kev, sigma` import and the `kev.load` / `sigma.load` / `functions.search_attack` rows). Re-run: `.venv/bin/pytest tests/test_stubs.py -q` → PASS.

- [ ] **Step 6: Commit**

```bash
git add src/secure_ai_research/ingestion/attack.py tests/test_attack_ingestion.py tests/test_stubs.py
git commit   # feat(ingestion): real ATT&CK STIX technique loader   (+ attribution footer)
```

---

### Task 2: Citation regex covers ATT&CK ids

**Files:**
- Modify: `src/secure_ai_research/reporting/report.py:22` (the `_CITATION` pattern)
- Test: `tests/test_report.py`

**Interfaces:**
- Produces: `_CITATION` now matches a CVE id **or** a technique id (`T####` / `T####.###`) inside `[...]`. `build_report` behavior otherwise unchanged.

- [ ] **Step 1: Write the failing tests** in `tests/test_report.py`

```python
def test_technique_cited_line_survives():
    rec = _record(retrieved_doc_ids=["T1059"], model_output="Adversaries abuse interpreters [T1059]")
    assert "[T1059]" in build_report(rec)

def test_subtechnique_cited_line_survives():
    rec = _record(retrieved_doc_ids=["T1059.001"], model_output="PowerShell abuse [T1059.001]")
    assert "[T1059.001]" in build_report(rec)

def test_markdown_brackets_not_citations():
    # A tactic id, a short id, and a markdown link are NOT citations; the line still
    # survives on its real [T1566] citation and is not dropped by the stray brackets.
    rec = _record(retrieved_doc_ids=["T1566"],
                  model_output="See [Phishing](https://x) and tactic [TA0001] and [T12]: phishing [T1566]")
    assert "[T1566]" in build_report(rec)

def test_uncited_technique_line_dropped():
    rec = _record(retrieved_doc_ids=["T1059"], model_output="Claim citing [T9999]")
    assert "No cited findings." in build_report(rec)
```

Use the existing `test_report.py` record helper if present; otherwise build a `ResearchRecord` inline with the fields the module already uses.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/test_report.py -q`
Expected: FAIL — technique lines dropped (regex matches only CVE ids).

- [ ] **Step 3: Extend the pattern** in `report.py`

Change `_CITATION` to `re.compile(r"\[(CVE-\d{4}-\d{4,}|T\d{4}(?:\.\d{3})?)\]")`. Update the adjacent comment to note ATT&CK ids are now covered.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/test_report.py -q`
Expected: PASS (new + existing CVE citation tests).

- [ ] **Step 5: Commit**

```bash
git add src/secure_ai_research/reporting/report.py tests/test_report.py
git commit   # feat(reporting): recognize ATT&CK technique ids as citations   (+ footer)
```

---

### Task 3: `research_attack` over a shared `_research` core

**Files:**
- Modify: `src/secure_ai_research/research_service.py` (extract `_research`; `research_cve` and new `research_attack` become wrappers)
- Test: `tests/test_research_service.py`

**Interfaces:**
- Consumes: Task 2's regex (so a technique answer body is non-empty).
- Produces: `_research(self, doc_id: str, *, role: str, objective: str, fetch_missing: Callable[[str], list[IngestedDocument]] | None = None) -> ResearchResult`; `research_cve(self, cve_id, *, role) -> ResearchResult` (wrapper, unchanged behavior); `research_attack(self, technique_id, *, role) -> ResearchResult`.

- [ ] **Step 1: Write the failing tests** in `tests/test_research_service.py`

Add a technique-doc helper and tests:

```python
def _technique_doc(tid="T1059"):
    doc = ResearchDocument(
        document_id=tid, source="MITRE ATT&CK", document_type=DocumentType.TECHNIQUE,
        classification=Classification.PUBLIC, created_at=date(2017, 5, 31),
        source_url=f"https://attack.mitre.org/techniques/{tid}/",  # type: ignore[arg-type]
        integrity_hash="sha256:" + "0" * 64)
    return IngestedDocument(doc, f"{tid}: adversaries abuse command and scripting interpreters")

def _svc_tech(audit, *, fetch=None):
    svc = ResearchService(HashingEmbedder(), InMemoryVectorStore(), authorize, audit, fetch_missing=fetch)
    svc.index([_technique_doc("T1059")])
    return svc

def test_research_attack_returns_cited_answer(tmp_path):
    audit = tmp_path / "a.jsonl"
    res = _svc_tech(audit).research_attack("T1059", role="research_analyst")
    assert res.outcome is Outcome.OK
    assert "T1059" in res.answer
    assert [c for c in res.citations if c.document_id == "T1059"]
    recs = read_records(audit)
    assert len(recs) == 1
    assert recs[0].data_source_ids == ["MITRE ATT&CK"]

def test_research_attack_denied(tmp_path):
    res = _svc_tech(tmp_path / "a.jsonl").research_attack("T1059", role="")
    assert res.outcome is Outcome.DENIED

def test_research_attack_absent_is_not_found(tmp_path):
    audit = tmp_path / "a.jsonl"
    res = _svc_tech(audit).research_attack("T9999", role="research_analyst")
    assert res.outcome is Outcome.NOT_FOUND
    assert len(read_records(audit)) == 1

def test_research_attack_never_fetches(tmp_path):
    # A CVE fetcher is wired, but the attack path must never call it, even on a miss.
    spy = _FakeFetch(docs=[_one_doc("CVE-2099-7777")])
    res = _svc_tech(tmp_path / "a.jsonl", fetch=spy).research_attack("T9999", role="research_analyst")
    assert res.outcome is Outcome.NOT_FOUND
    assert spy.calls == 0
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/test_research_service.py -q`
Expected: FAIL — `research_attack` does not exist (`AttributeError`).

- [ ] **Step 3: Extract the core and add the wrappers** in `research_service.py`

Move the current body of `research_cve` (the lines from `rid = …` through the final `return ResearchResult(Outcome.OK, …)`) into a new `_research(self, doc_id, *, role, objective, fetch_missing=None)`, substituting `doc_id` for `cve_id` throughout, taking `objective` from the parameter (delete the local `objective = f"Correlate …"` line), and using the **local** `fetch_missing` parameter in the fetch-on-miss branch (its `is not None` guard and the `fetch_missing(doc_id)` call) in place of `self._fetch_missing`. Then:
```python
def research_cve(self, cve_id, *, role):
    return self._research(cve_id, role=role,
                          objective=f"Correlate {cve_id} against public sources",
                          fetch_missing=self._fetch_missing)

def research_attack(self, technique_id, *, role):
    return self._research(technique_id, role=role,
                          objective=f"Explain ATT&CK technique {technique_id} with cited public sources")
```

- [ ] **Step 4: Run the full service suite to verify new pass + CVE unchanged**

Run: `.venv/bin/pytest tests/test_research_service.py -q`
Expected: PASS — the 4 new tests and **every** existing CVE/fetch-on-miss test (the refactor is behavior-preserving for `research_cve`).

- [ ] **Step 5: Commit**

```bash
git add src/secure_ai_research/research_service.py tests/test_research_service.py
git commit   # feat(service): research_attack via shared _research core   (+ footer)
```

---

### Task 4: Wire `GET /research/attack/{technique_id}`

**Files:**
- Modify: `src/secure_ai_research/api/routers/research.py:65-68` (replace the 501 stub)
- Test: `tests/test_api.py`

**Interfaces:**
- Consumes: `ResearchService.research_attack(technique_id, *, role)` (Task 3); `Outcome`.
- Produces: `GET /research/attack/{technique_id}` → 200 (answer/citations/research_id), 403 (DENIED), 404 (NOT_FOUND / malformed-but-valid-pattern absent), 422 (path pattern reject). No 503 (attack path never returns FETCH_ERROR).

- [ ] **Step 1: Write the failing tests** in `tests/test_api.py`

Define a `_technique_doc(tid)` helper in `test_api.py` (same shape as the one in `test_research_service.py`: a `TECHNIQUE` `ResearchDocument`, `source="MITRE ATT&CK"`, `source_url=f"https://attack.mitre.org/techniques/{tid}/"`, `integrity_hash="sha256:"+"0"*64`, paired with `IngestedDocument(doc, f"{tid}: adversaries abuse …")`), plus a helper that overrides `get_service` with a service holding it indexed, then:

```python
def _override_tech_service(tmp_path, tid="T1059"):
    svc = ResearchService(HashingEmbedder(), InMemoryVectorStore(), authorize, tmp_path / "audit.jsonl")
    svc.index([_technique_doc(tid)])   # _technique_doc mirrors the service-test helper
    app.dependency_overrides[get_service] = lambda: svc
    return svc

def test_attack_permitted_returns_cited_answer(tmp_path):
    _override_tech_service(tmp_path, "T1059")
    resp = client.get("/research/attack/T1059", headers={"X-Role": "research_analyst"})
    assert resp.status_code == 200
    assert any(c["document_id"] == "T1059" for c in resp.json()["citations"])
    assert resp.json()["research_id"]

def test_attack_subtechnique_200(tmp_path):
    _override_tech_service(tmp_path, "T1059.001")
    resp = client.get("/research/attack/T1059.001", headers={"X-Role": "research_analyst"})
    assert resp.status_code == 200

def test_attack_missing_role_denied(tmp_path):
    _override_tech_service(tmp_path)
    assert client.get("/research/attack/T1059").status_code == 403

def test_attack_absent_is_404(tmp_path):
    _override_tech_service(tmp_path)
    assert client.get("/research/attack/T9999", headers={"X-Role": "research_analyst"}).status_code == 404

@pytest.mark.parametrize("bad", ["TA0001", "T123", "t1059", "1059", "T1059.1"])
def test_attack_malformed_is_422(tmp_path, bad):
    _override_tech_service(tmp_path)
    assert client.get(f"/research/attack/{bad}", headers={"X-Role": "research_analyst"}).status_code == 422
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/test_api.py -q`
Expected: FAIL — route returns 501 (and 422 cases may already pass once the pattern exists; the 200/403/404 cases fail).

- [ ] **Step 3: Implement the route** in `research.py`

Replace the stub with a handler mirroring `research_cve`: signature `research_attack(technique_id: str = Path(pattern=r"^T\d{4}(\.\d{3})?$"), x_role: str = Header(default=""), service: ResearchService = Depends(get_service)) -> JSONResponse`, same SECURITY docstring about the `X-Role` stub; call `service.research_attack(technique_id, role=x_role)`; map `OK→200` (answer, citations via `asdict`, research_id), `DENIED→403` ("role not authorized"), else `→404` (`f"no document for {technique_id}"`). Keep `/search` as the 501 stub.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/test_api.py -q`
Expected: PASS (new attack tests; existing CVE/health/search tests unchanged).

- [ ] **Step 5: Commit**

```bash
git add src/secure_ai_research/api/routers/research.py tests/test_api.py
git commit   # feat(api): wire GET /research/attack/{technique_id}   (+ footer)
```

---

### Task 5: Index the real ATT&CK fixture at startup

**Files:**
- Create: `src/secure_ai_research/ingestion/samples/attack_sample.json` (real MITRE slice)
- Create: `src/secure_ai_research/ingestion/samples/ATTRIBUTION.md`
- Modify: `src/secure_ai_research/api/deps.py` (index the attack fixture after the NVD fixture)
- Test: `tests/test_api.py`

**Interfaces:**
- Consumes: `attack.load` (Task 1); the wired route (Task 4); `ResearchService.index`.
- Produces: the process service serves real ATT&CK techniques; a revoked id in the bundle is absent.

- [ ] **Step 1: Build the fixture from real MITRE data**

Download the enterprise ATT&CK STIX 2.1 bundle to the scratch dir, then with a script run `.venv/bin/python -I` (untrusted download — isolate, pass the path as an argument) extract these `attack-pattern` objects by `mitre-attack` `external_id` and write a `{"type":"bundle","id":"bundle--sair-attack-sample","objects":[…]}` containing **only** the fields `attack.load` reads (`type`, `id`, `name`, `description`, `created`, `external_references`, and the `revoked`/`x_mitre_deprecated` flags where present):
- `T1059` (Command and Scripting Interpreter) — parent technique
- `T1059.001` (PowerShell) — sub-technique
- `T1566` (Phishing)
- one **revoked** technique present in the bundle (e.g. `T1064` Scripting, `revoked: true`) — exercises the skip path with real data
Source: `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json`. Verify none of the kept descriptions contains a bare `[T####]`/`[CVE-…]` token (`grep -nE '\[(T[0-9]{4}|CVE-)' ` the written fixture; re-pick or trim if it does — per design §10).

- [ ] **Step 2: Write `ATTRIBUTION.md`**

Credit: "MITRE ATT&CK®. © The MITRE Corporation. This fixture contains a small excerpt of the ATT&CK for Enterprise STIX data, used under the ATT&CK Terms of Use (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). Source: https://github.com/mitre-attack/attack-stix-data."

- [ ] **Step 3: Write the failing tests** in `tests/test_api.py`

Drive the **real** `get_service` (no override) with a tmp audit path:

```python
def test_deps_indexes_attack_fixture(tmp_path, monkeypatch):
    monkeypatch.setenv("SAIR_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    get_settings.cache_clear(); get_service.cache_clear()
    try:
        resp = client.get("/research/attack/T1059", headers={"X-Role": "research_analyst"})
        assert resp.status_code == 200
        assert any(c["document_id"] == "T1059" for c in resp.json()["citations"])
    finally:
        get_service.cache_clear(); get_settings.cache_clear()

def test_deps_revoked_technique_is_404(tmp_path, monkeypatch):
    monkeypatch.setenv("SAIR_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    get_settings.cache_clear(); get_service.cache_clear()
    try:
        resp = client.get("/research/attack/T1064", headers={"X-Role": "research_analyst"})
        assert resp.status_code == 404
    finally:
        get_service.cache_clear(); get_settings.cache_clear()
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/test_api.py -q`
Expected: FAIL — `get_service` does not index the attack fixture (T1059 → 404).

- [ ] **Step 5: Index the fixture** in `deps.py`

Add `from secure_ai_research.ingestion import attack` (grouped with the existing `nvd` import). After `service.index(nvd.load(raw))`, add:
```python
attack_raw = files("secure_ai_research.ingestion").joinpath("samples", "attack_sample.json").read_bytes()
service.index(attack.load(attack_raw))
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/test_api.py -q`
Expected: PASS (T1059 → 200, T1064 → 404).

- [ ] **Step 7: Commit**

```bash
git add src/secure_ai_research/ingestion/samples/attack_sample.json \
        src/secure_ai_research/ingestion/samples/ATTRIBUTION.md \
        src/secure_ai_research/api/deps.py tests/test_api.py
git commit   # feat(api): index real ATT&CK fixture at startup   (+ footer)
```

---

## Final checks (before review)

- [ ] `.venv/bin/pytest -q` — full suite green (hermetic).
- [ ] `.venv/bin/ruff check .` && `.venv/bin/black --check .` && `.venv/bin/mypy` — clean.
