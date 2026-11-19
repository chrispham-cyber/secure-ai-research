# Phase 2 — CISA KEV loader + index design

**Status:** approved by precedent (Chris, 2026-11-19 — "run all phase 2" in-posture batch, per-slice design-approval pause waived; design decisions below are my calls, recorded for review).
**Slice 2 of the in-posture Phase-2 completion batch** (search ✅ → **CISA KEV** → Sigma → end-to-end demo).

## 1. Intent / why

The corpus can already answer about an NVD CVE and a MITRE ATT&CK technique. **CISA KEV** (Known
Exploited Vulnerabilities) adds the "is this actively exploited in the wild?" signal — the one fact
that most changes how an analyst prioritises a CVE. This slice ingests the public CISA KEV catalog
into the same retrieval corpus so a free-text `POST /research/search` surfaces the KEV entry for a
CVE alongside its NVD and ATT&CK evidence. It is the second of three loaders feeding the slice-4
cross-source correlation demo.

It mirrors the just-merged ATT&CK loader slice almost exactly: a stdlib-only JSON loader, a small
committed fixture built from real public data via `python -I`, wired into `deps.get_service`.

## 2. Goals

- A stdlib-only `ingestion/kev.py` with `load(raw: bytes) -> list[IngestedDocument]`: one
  `IngestedDocument` per KEV entry, PUBLIC, each carrying a `sha256:` integrity hash of its
  **canonical** source object (byte-for-byte the `attack.py` hashing idiom).
- **Fail-loud** (`ValueError` naming the offending CVE id) on malformed JSON, a missing `cveID`, a
  `cveID` not matching `^CVE-\d{4}-\d{4,}$`, a missing/invalid `dateAdded`, or a duplicate `cveID` —
  a research corpus is never silently built from bad input.
- A committed fixture `ingestion/samples/kev_sample.json` (a few real entries incl. CVE-2021-44228)
  + `samples/ATTRIBUTION.md` updated to credit CISA; indexed by `deps.get_service` beside NVD + ATT&CK.
- **Deterministic, offline/hermetic, no new runtime dependency.** The CVE id appears in each KEV
  document's text so a search for the CVE id (or the vendor/product) surfaces the KEV entry.

## 3. Non-goals

- **No new endpoint.** KEV is additional corpus for the existing `POST /research/search`, not a
  `/research/kev/{id}` route. (If a dedicated KEV id-route is ever wanted, that is its own slice.)
- **No linkage into the CVE id-route.** `GET /research/cve/{id}` stays single-document and NVD-centric
  (its scope is `allowed & {cve_id}`); a KEV document is namespaced (`KEV-CVE-…`) so it is reachable
  via search, never via the CVE id-route. KEV↔CVE correlation is a *search* concern (slice 4).
- **No fetch-on-miss / no network at runtime.** Fixture-backed like ATT&CK; the catalog is fetched
  once at *build* time to make the fixture, never by the running app.
- **No business logic** over KEV fields (due-date math, ransomware alerting, BOD-22-01 compliance).
- **No pydantic model** for the KEV schema — plain `dict` parsing with explicit validation, like
  `attack.py`. No new `DocumentType`; KEV reuses the existing `ADVISORY` value.

## 4. Anti-goals (a failure even if it "works")

- **Silent corpus poisoning:** a malformed/partial catalog is indexed instead of raising. Every
  malformation named in §2 must fail loud, naming the CVE id.
- **document_id collision:** a KEV id equal to an NVD or ATT&CK document_id (would raise at
  `index()` time, or — worse, if that guard regressed — conflate two sources under one id). The
  `KEV-` prefix prevents it by construction.
- **The CVE / ATT&CK id-routes changing behavior** because KEV got indexed. Indexing more documents
  must leave `GET /research/cve/{id}` and `GET /research/attack/{id}` byte-identical in behavior
  (their scope intersects a single id that no `KEV-…` id can match).
- **Citation integrity break:** a KEV document whose `source_url`/`source` do not match its content,
  or whose integrity hash is not of the exact source object.

## 5. Constraints

- Python 3.12, **stdlib-only**, no new runtime dependency. Deterministic, offline.
- PUBLIC/synthetic only. Tests hermetic (no network outside `@pytest.mark.integration`).
- Fixture built from untrusted downloaded bytes in an **isolated empty dir**, processed with
  `python -I`; fetch with a **generic User-Agent, no PII** (never the user's name/email). The CISA
  KEV catalog is a US-Government work (public domain, 17 U.S.C. §105); attribution is courtesy.
- `ruff`/`black`/`mypy` clean; line length 100. Attribution footer on every commit.

## 6. Approaches considered

- **Approach 1 — dedicated `ingestion/kev.py`, namespaced `KEV-` document_id (CHOSEN).** A new
  loader mirroring `attack.py`: parse the catalog JSON, one `IngestedDocument` per `vulnerabilities[]`
  entry, `document_id = f"KEV-{cveID}"`, canonical-hash + fail-loud exactly as ATT&CK. Wire into
  `deps`. Smallest, most consistent with the two existing loaders; `_research`, the id-routes,
  `build_report`, and `search` are all untouched.
- **Approach 2 — reuse the bare CVE id as the KEV document_id.** Rejected: collides with an NVD
  document for the same CVE (`index()` raises "already indexed"), and conflates two distinct public
  sources under one corpus id. The whole value of a multi-source corpus is that NVD and KEV are
  *separate* citable documents.
- **Approach 3 — a generic "JSON catalog" loader abstraction** shared by NVD/ATT&CK/KEV. Rejected as
  premature (YAGNI): the three sources have different shapes and validation rules; a shared
  abstraction would be mostly conditionals and would re-open the two proven loaders for no gain.

**Why Approach 1:** it is the established pattern, adds KEV as clean additional corpus with zero blast
radius on the proven paths, and keeps the KEV↔CVE relationship where it belongs — in search.

## 7. The design (decided)

### 7.1 `ingestion/kev.py`

`load(raw: bytes) -> list[IngestedDocument]`. Flow per the ATT&CK precedent:

1. `catalog = json.loads(raw)` (a `json.JSONDecodeError` is a `ValueError` — malformed JSON fails loud).
2. For each `entry` in `catalog.get("vulnerabilities", [])`:
   - `cve_id = entry.get("cveID")`; if missing or not matching `^CVE-\d{4}-\d{4,}$` →
     `ValueError` naming the entry (`cveID` value or, if absent, the `vulnerabilityName`).
   - Duplicate `cveID` within the catalog → `ValueError`.
   - `created_at = date.fromisoformat(str(entry["dateAdded"])[:10])`; missing/invalid → `ValueError`
     naming the CVE id.
   - `integrity_hash = "sha256:" + sha256(json.dumps(entry, sort_keys=True, separators=(",",":"),
     ensure_ascii=False).encode())` — the canonical hash of the **exact KEV entry object**.
   - `text` = a one-paragraph summary composed from the entry (see §7.2) — always begins with the
     `cveID` so a search by CVE id surfaces it.
   - `ResearchDocument(document_id=f"KEV-{cve_id}", source="CISA KEV",
     document_type=DocumentType.ADVISORY, classification=PUBLIC, created_at=…,
     source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog", integrity_hash=…)`.
3. Return the list (order = catalog order).

`DocumentType.ADVISORY` (my call): a KEV entry is CISA's authoritative *directive/advisory* that a
vulnerability is being exploited — distinct from the raw NVD `VULNERABILITY` record for the same CVE.
The type is internal metadata (not surfaced in any API response, not used in authz or ranking), so
this has no user-visible effect today; it just keeps a meaningful per-source taxonomy
(NVD=vulnerability, CISA KEV=advisory, Sigma=detection, ATT&CK=technique).

### 7.2 Document text

Composed from the entry with `.get(..., "")` fallbacks so a missing optional field never crashes
(only `cveID` and `dateAdded` are strictly required). Includes, in order: `cveID`,
`vulnerabilityName`, `vendorProject` + `product`, `shortDescription`, `requiredAction`, and — when
`knownRansomwareCampaignUse == "Known"` — a "known ransomware campaign use" phrase. This makes a KEV
document findable by CVE id, by vendor/product, and by topic words from its description.

### 7.3 `source_url`

All KEV documents share the catalog URL `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`
— CISA publishes no per-entry page, and this is the honest provenance for `source="CISA KEV"`. (The
per-CVE NVD page is *not* used here: that is NVD's provenance, not CISA's.)

### 7.4 Fixture + wiring

- `ingestion/samples/kev_sample.json`: a few real entries (incl. **CVE-2021-44228** Log4Shell, which
  also exercises the NVD live-fetch path and the correlation story, and at least one
  `knownRansomwareCampaignUse: "Known"` entry) sliced from the live catalog via `python -I` in an
  isolated dir. Kept small (single-digit KB), like `attack_sample.json`.
- `samples/ATTRIBUTION.md`: a CISA KEV section — source URL, retrieval date, and a note that the
  catalog is a U.S. Government work in the public domain (attribution courtesy).
- `api/deps.get_service`: index `kev_sample.json` after the NVD and ATT&CK fixtures.

## 8. What is left to the builder

- The exact `text` composition string (fields in §7.2).
- The KEV `load()` validation order and error messages (mirror `attack.py`'s fail-loud style).
- Building the fixture from the live catalog (confirm the real field names at build time — the KEV
  schema is stable: `vulnerabilities[].{cveID,vendorProject,product,vulnerabilityName,dateAdded,
  shortDescription,requiredAction,dueDate,knownRansomwareCampaignUse,notes}`; adjust via a ruling if
  the live shape differs).
- Test cases: loader (parses an entry; namespaced id; canonical hash shape; fail-loud on malformed
  JSON / missing cveID / malformed cveID / bad dateAdded / duplicate cveID) and a deps/startup test
  that a KEV CVE is retrievable via `POST /research/search` (and that the NVD/ATT&CK id-routes still
  answer unchanged — the no-blast-radius guarantee).

## 9. Review focus (for the final reviewer)

1. **Fail-loud coverage** — every §2 malformation raises `ValueError` naming the CVE id; nothing is
   silently indexed.
2. **No blast radius** — indexing KEV leaves `GET /research/cve/{id}` and `GET /research/attack/{id}`
   behavior byte-identical; `_research`, `build_report`, and `search` are untouched.
3. **document_id namespacing** — no `KEV-…` id can equal an NVD CVE id or an ATT&CK technique id, so
   `index()` never raises on a real catalog and no source is conflated.
4. **Citation/provenance integrity** — `source="CISA KEV"`, `source_url` is the CISA catalog, and the
   integrity hash is of the exact entry object.
5. **Determinism / hermeticity** — no network at import or query time; the fixture is committed; tests
   pass offline.
