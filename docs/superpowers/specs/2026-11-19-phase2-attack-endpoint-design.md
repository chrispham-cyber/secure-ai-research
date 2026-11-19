# Phase 2 — ATT&CK technique endpoint (design)

**Status:** awaiting human approval before planning (brainstorming output; builder-check done — "nothing important left", 2 author-resolved items in §10)
**Date:** 2026-11-19
**Repo:** `secure-ai-research` (local git, no remote)
**Supersedes/extends:** the Phase-2 NVD retrieval slice + fetch-on-miss endpoint slice (both merged to `main`).

## 1. Intent and why

Make `GET /research/attack/{technique_id}` a **real, cited, audited** endpoint that answers
for a MITRE ATT&CK technique by running the *same* evidence-grounded pipeline the CVE path
already uses: authorize-before-retrieve → scope-filtered nearest-neighbor retrieval →
deterministic cited assembly (no LLM) → exactly one append-only audit record.

Why now: the CVE path proved the pipeline end to end for one source/id type. ROADMAP Phase 2
(weeks 6 and 8) calls for ingesting **MITRE ATT&CK** and wiring `/research/*` live. This slice
proves the pipeline **generalizes to a second source and a second id scheme** (ATT&CK technique
ids, e.g. `T1059`, `T1059.001`) without weakening any security property, and turns the last
retrieval stub on the read path into working code.

## 2. Goals

- `GET /research/attack/{technique_id}` returns a cited answer (200) for an indexed technique the
  caller's role may retrieve, grounded only in retrieved passages, with one audit record.
- A real `ingestion/attack.py` parses a **MITRE ATT&CK STIX 2.1 bundle** into `IngestedDocument`
  records — one per technique — hash-pinned, `PUBLIC`, fail-loud on bad input, mirroring `nvd.load`.
- The corpus the live app serves includes a **small slice of real MITRE ATT&CK data** (committed
  fixture), indexed at startup beside the NVD fixture.
- The CVE path (service, route, tests, `fetch_cve` CLI) keeps working **unchanged** in behavior.
- `build_report` keeps/renders technique citations (`[T1059]`) exactly as it does CVE citations.
- The whole default test suite stays **hermetic** (no network); `stdlib-only`, no new runtime deps.

## 3. Non-goals (deliberately out of this slice)

- **Fetch-on-miss for ATT&CK.** ATT&CK ships as one bulk bundle, not a per-id API; there is no
  clean "fetch this one technique" call. The attack endpoint is **fixture-backed only**; a miss is
  a plain 404. (The CVE fetch-on-miss machinery is untouched and does not apply here.)
- Cross-source correlation (CVE ↔ technique in one answer) — a later phase.
- KEV (`kev.py`) and Sigma (`sigma.py`) ingestion — remain stubs.
- Real embeddings / Ollama — `HashingEmbedder` stays.
- STIX object types other than `attack-pattern` (mitigations, groups, software, data-sources,
  relationships) — ignored this slice.
- Sub-technique → parent linking, tactic/mitigation enrichment in the answer body.

## 4. Anti-goals (would make this a failure even if it "works")

- **Breaking or changing the CVE path's behavior** (its public result, status codes, or audit).
- A technique **miss returning 503** instead of 404, or any attack request reaching the NVD
  fetcher — calling `self._fetch_missing` (a CVE fetcher) with a technique id must never happen.
- A new runtime dependency, or a non-hermetic default suite (network in a non-`integration` test).
- Silently building the corpus from bad STIX (must fail loud, naming the offending object).
- An uncited line surviving into a technique answer, or a non-`PUBLIC` document being stored.

## 5. Constraints (Global — every task inherits these)

- Python 3.12; **stdlib only**, no new runtime deps (STIX is JSON → `json`; `hashlib`, `re`, `datetime`).
- Offline/hermetic by default: `addopts = ["-m","not integration"]` already excludes network tests;
  this slice adds **no** network path (no live ATT&CK fetch).
- `classification` is **PUBLIC only** (schema-enforced); `integrity_hash` is `sha256:<64 hex>`.
- Authorize-before-retrieve; exactly **one audit record per request**; no existence oracle (absent and
  present-but-unauthorized both → 404).
- Lint/type clean at line length 100: `.venv/bin/ruff check .`, `.venv/bin/black --check .`,
  `.venv/bin/mypy` (`files=["src"]`; tests not type-checked).
- Test command: `.venv/bin/pytest -q`. Attribution footer required on every commit.
- `X-Role` remains the documented Phase-1 self-asserted stub (OIDC is Phase 5); the attack route
  carries the same SECURITY docstring as the CVE route.

## 6. Approaches considered

Most of the work is identical across approaches (STIX parser, citation-regex extension, route
wiring, committed fixture + indexing). They differ **only** in how `ResearchService` exposes the
technique path:

- **Approach 1 — sibling wrappers over a shared private core (CHOSEN).** Extract the current
  `research_cve` body into a generic private `_research(doc_id, *, role, objective, fetch_missing=None)`.
  `research_cve` becomes a one-line wrapper forwarding `self._fetch_missing`; add `research_attack`
  as a one-line wrapper passing **no** fetcher. The CVE method's name, signature, callers, and tests
  are untouched; the core is reused by a future KEV/search path. Lowest blast radius on just-merged code.
- **Approach 2 — one generic public method.** Rename `research_cve` → `research(doc_id, …)` and update
  the CVE route, `fetch_cve.research_from_source`, and the CVE tests to call it. A single entry point,
  but it churns code merged yesterday for no behavior gain.

**Human picked Approach 1** (2026-11-19). Reason: keep the working CVE path provably unchanged; the
private core still gives the clean reuse that Approach 2's rename was after, without the churn.

## 7. The decided design (how)

### 7.1 `ingestion/attack.py` — STIX 2.1 technique loader
`load(raw: bytes) -> list[IngestedDocument]`, replacing the stub. Using stdlib `json`:
- `bundle = json.loads(raw)` (a `JSONDecodeError` is a `ValueError` → fail-loud, consistent with `nvd.load`).
- Iterate `bundle.get("objects", [])`; keep objects with `type == "attack-pattern"`.
- **Skip** any object where `revoked is True` or `x_mitre_deprecated is True` (not an error — omitted).
- **Technique id:** from `external_references`, the entry with `source_name == "mitre-attack"`, field
  `external_id`. Missing it → `ValueError` naming the STIX `id`. Validate `^T\d{4}(\.\d{3})?$`.
- **Dedup:** a repeated technique id in the bundle → fail-loud `ValueError` (mirror `nvd.load`'s `seen`).
- **Text:** `f"{name}: {description}"` (parity with NVD's description-only text; tactics/mitigations
  omitted from the body this slice).
- **created_at:** `date.fromisoformat(str(obj["created"])[:10])`; missing/malformed → `ValueError` naming the id.
- **integrity_hash:** `"sha256:" + sha256(canonical).hexdigest()`, `canonical = json.dumps(obj,
  sort_keys=True, separators=(",",":"), ensure_ascii=False).encode("utf-8")` — same recipe as `nvd.load`.
- **ResearchDocument:** `document_id = <external_id>`, `source = "MITRE ATT&CK"`,
  `document_type = DocumentType.TECHNIQUE`, `classification = PUBLIC`,
  `source_url = "https://attack.mitre.org/techniques/" + external_id.replace(".", "/") + "/"`.
- Return `[IngestedDocument(document, text), …]`.

### 7.2 `ResearchService` — Approach 1
- New private `_research(self, doc_id: str, *, role: str, objective: str,
  fetch_missing: Callable[[str], list[IngestedDocument]] | None = None) -> ResearchResult`: the
  **current `research_cve` body verbatim**, with `cve_id` → `doc_id`, the objective taken from the
  param, and the fetch-on-miss branch using the **local `fetch_missing`** parameter (not
  `self._fetch_missing`). All invariants (authz-first, `scope = allowed & {doc_id}`, one audit record,
  the `except Exception → FETCH_ERROR` backstop) carry over unchanged.
- `research_cve(self, cve_id, *, role)` → `self._research(cve_id, role=role,
  objective=f"Correlate {cve_id} against public sources", fetch_missing=self._fetch_missing)`.
- `research_attack(self, technique_id, *, role)` → `self._research(technique_id, role=role,
  objective=f"Explain ATT&CK technique {technique_id} with cited public sources")` — **no** fetcher,
  so an un-indexed technique can never reach `self._fetch_missing` and always resolves to NOT_FOUND.

### 7.3 `reporting/report.py`
`_CITATION = re.compile(r"\[(CVE-\d{4}-\d{4,}|T\d{4}(?:\.\d{3})?)\]")`. CVE behavior unchanged; a
technique-cited line is now kept iff every id it cites is in `retrieved_doc_ids`.

### 7.4 Route `GET /research/attack/{technique_id}`
Replace the 501 stub with the CVE route's shape:
`technique_id: str = Path(pattern=r"^T\d{4}(\.\d{3})?$")`, `x_role: str = Header(default="")`,
`service = Depends(get_service)`. Call `service.research_attack(technique_id, role=x_role)`; map
`OK→200` (answer + citations + research_id), `DENIED→403`, else `→404`. No 503 branch (this path
never fetches, so `research_attack` never returns FETCH_ERROR). Same SECURITY docstring about the
`X-Role` stub. `/research/search` stays 501.

### 7.5 Fixture + wiring
- `src/secure_ai_research/ingestion/samples/attack_sample.json`: a **real** STIX 2.1 `bundle` with a
  handful of `attack-pattern` objects copied from MITRE's published `enterprise-attack` bundle
  (e.g. T1059 + a sub-technique + two others; include at least one `revoked`/deprecated object so the
  skip path is exercised by the real fixture). Attribution recorded in `samples/ATTRIBUTION.md`
  (MITRE ATT&CK®, with the dataset URL and license note).
- `api/deps.get_service`: after indexing the NVD fixture, also
  `service.index(attack.load(files("secure_ai_research.ingestion").joinpath("samples",
  "attack_sample.json").read_bytes()))`. CVE and technique ids are disjoint, so the fail-loud
  duplicate check in `index()` is never tripped.

## 8. What's left to the builder

- Exact test list and RED/GREEN steps (the plan covers this): `attack.load` unit tests (parse the real
  slice; skip revoked/deprecated; fail-loud on missing `external_id`/`created`/duplicate; stable hash),
  report-regex tests (technique kept, CVE still kept, bracket tokens like `[TA0001]`/`[T9]` not mistaken),
  `research_attack` service tests (cited OK + one record; DENIED; absent technique → NOT_FOUND; a
  technique request **never** invokes the CVE `fetch_missing` even when one is wired), route tests
  (200/403/404/422), a deps test that a known fixture technique answers 200.
- Selecting the specific real techniques to commit and writing `ATTRIBUTION.md`.
- Whether `research_attack` should accept the `TAxxxx` tactic form — **no**: this slice is techniques
  only; the path pattern rejects non-`T####` ids with 422.

## 9. Open questions for the human
None. The builder-check (fresh reviewer, 2026-11-19) returned **"nothing important left"** — no
decision changes what gets built that the human must make. The two small items it raised are
author calls, recorded in §10.

## 10. Builder-check resolutions (author calls)

1. **Stub test must be updated.** Implementing `attack.load` means removing the
   `(attack.load, (b"",), {})` row from the parametrized `test_all_stubs_raise_notimplemented` in
   `tests/test_stubs.py` (the `attack`/`kev`/`sigma` import line stays — `kev`/`sigma` remain stubs).
   Verified: the `functions.search_attack` row (same test) is a **Phase-3 agent-tool stub**, not this
   route, and `tests/test_api.py::test_research_search_501` is the `/research/search` route — **both
   stay unchanged**. No existing test asserts the attack *route* returns 501, so only that one loader
   row changes. The plan owns this edit (it is part of making the loader real).

2. **Real ATT&CK descriptions carry markdown.** Technique descriptions contain `[Name](url)` links
   and `(Citation: …)` markers. The citation regex matches only the exact id shape inside brackets
   (`[CVE-…]` / `[T####(.###)]`), so `[PowerShell](…)` and `(Citation: …)` are **not** mistaken for
   citations — description text is kept verbatim (as §7.1 says). Residual edge: a description that
   contained a **bare** `[T####]` or `[CVE-…]` token would be read as a citation and could drop that
   passage's line if the referenced id is not in scope. Mitigation (author call): when curating the
   committed fixture (§7.5), choose/verify techniques whose descriptions carry no bare id-in-brackets
   token — ATT&CK normally uses `[Name](url)` links, so this is typically a non-issue; a quick grep of
   the chosen objects for `\[(T\d{4}|CVE-)` during fixture selection confirms it.
