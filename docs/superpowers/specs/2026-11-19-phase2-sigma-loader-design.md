# Phase 2 — Sigma detection-rule loader + index design

**Status:** approved by precedent (Chris, 2026-11-19 — "run all phase 2" in-posture batch, per-slice
design-approval pause waived; design decisions below are my calls, recorded for review).
**Slice 3 of the in-posture Phase-2 completion batch** (search ✅ → CISA KEV ✅ → **Sigma** → demo).

## 1. Intent / why

The corpus answers about an NVD CVE, a MITRE ATT&CK technique, and whether a CVE is known-exploited
(CISA KEV). **Sigma** adds the defender's answer: *how would I detect this?* A Sigma rule ties a
vulnerability or technique to a concrete detection. This slice ingests a few public SigmaHQ rules so
`POST /research/search` surfaces the detection rule for a CVE or technique alongside its NVD / KEV /
ATT&CK evidence — the last loader feeding the slice-4 cross-source correlation demo.

It mirrors the merged KEV and ATT&CK loader slices: a stdlib-only loader, a small committed fixture
built from real public data at build time, wired into `deps.get_service`. The one new wrinkle —
Sigma rules are authored in **YAML**, and this repo is stdlib-only at runtime — is resolved by
converting the rules to JSON **at build time** so the runtime loader stays pure `json`.

## 2. Goals

- A stdlib-only `ingestion/sigma.py` with `load(raw: bytes) -> list[IngestedDocument]`: one
  `IngestedDocument` per Sigma rule, PUBLIC, each carrying a `sha256:` integrity hash of its
  **canonical** source object (byte-for-byte the KEV/ATT&CK hashing idiom). Input is a JSON **array**
  of rule objects (the build-time conversion of the rules' YAML).
- Each rule's text carries **canonical correlation tokens** derived from its `tags`: an
  `attack.tNNNN[.NNN]` tag → `TNNNN[.NNN]`, a `cve.YYYY.NNNN` tag → `CVE-YYYY-NNNN`, so a search for a
  technique id or CVE id surfaces the detection rule beside the ATT&CK/NVD/KEV documents. This is the
  correlation payoff and the reason the slice exists.
- **Fail-loud** (`ValueError` naming the rule's `id`, or `title` if `id` is absent) on malformed JSON,
  a missing `id`, a missing `title`, a missing/invalid `date`, or a duplicate `id`. Rules whose
  `status` is `deprecated` or `unsupported` are **skipped** (mirrors the ATT&CK revoked/deprecated
  skip), never half-indexed.
- A committed fixture `ingestion/samples/sigma_sample.json` (a few real SigmaHQ rules, at least one
  tied to CVE-2021-44228 and at least one tagged `attack.t1059`, to seed the correlation demo) +
  `samples/ATTRIBUTION.md` updated to credit SigmaHQ (DRL 1.1); indexed by `deps.get_service` beside
  NVD + ATT&CK + KEV.
- **Deterministic, offline/hermetic, no new runtime dependency.**

## 3. Non-goals

- **No new endpoint.** Sigma is additional corpus for `POST /research/search`, not a `/research/sigma/{id}` route.
- **No linkage into the id-routes.** `GET /research/cve/{id}` and `GET /research/attack/{id}` stay
  single-document (scope `allowed & {id}`); a Sigma document is namespaced (`SIGMA-{uuid}`) so it is
  reachable via search, never via an id-route. Detection↔CVE/technique correlation is a *search* concern (slice 4).
- **No runtime YAML.** The fixture is converted YAML→JSON at build time; the running app never parses
  YAML and takes no new dependency. No network at runtime.
- **No Sigma rule execution / backend conversion** (no translating `detection:` into a SIEM query).
  The rule is ingested as a *document*, not compiled.
- **No pydantic model** for the Sigma schema — plain `dict` parsing with explicit validation, like
  `kev.py`/`attack.py`. No new `DocumentType`; Sigma reuses the existing `DETECTION` value.

## 4. Anti-goals (a failure even if it "works")

- **Silent corpus poisoning:** a malformed rule, or a rule missing `id`/`title`/`date`, is indexed
  instead of raising. Every malformation in §2 must fail loud, naming the rule.
- **Broken correlation:** a rule tagged `attack.t1059` / `cve.2021.44228` whose text does **not**
  surface `T1059` / `CVE-2021-44228`, so a search for the technique or CVE misses the detection — the
  slice would add data that doesn't connect, defeating its purpose.
- **document_id collision / id-route drift:** a Sigma id equal to an NVD/ATT&CK/KEV id, or the
  CVE/ATT&CK id-routes changing behavior because Sigma got indexed. The `SIGMA-` prefix (over a UUID)
  prevents collision by construction; indexing more documents must leave the id-routes byte-identical.
- **Runtime dependency creep:** `import yaml` (or anything non-stdlib) in `sigma.py`.

## 5. Constraints

- Python 3.12, **stdlib-only at runtime**, no new runtime dependency (PyYAML is a dev/pre-commit
  transitive only; it may be used at **build** time to make the fixture, never imported by `src/`).
  Deterministic, offline.
- PUBLIC/synthetic only. Tests hermetic (no network outside `@pytest.mark.integration`; there is none here).
- Fixture built from untrusted downloaded bytes in an **isolated empty dir**, processed with
  `python -I` and `yaml.safe_load` (never `yaml.load`); fetch with a **generic User-Agent, no PII**.
  SigmaHQ rules are licensed under the **Detection Rule License (DRL) 1.1**; attribution required.
- `ruff`/`black`/`mypy` clean; line length 100. Attribution footer on every commit.

## 6. Approaches considered

- **Approach 1 — dedicated `ingestion/sigma.py`, stdlib-JSON loader over a build-time-converted
  fixture, namespaced `SIGMA-{id}`, tags normalized to T####/CVE tokens (CHOSEN).** Mirrors KEV/ATT&CK:
  smallest, consistent, zero blast radius, keeps the runtime yaml-free.
- **Approach 2 — runtime YAML parsing (`import yaml` in `sigma.py`, ship the native `.yml`).**
  Rejected: PyYAML is **not** a declared runtime dependency (only `pre_commit` pulls it in), so a
  runtime `import yaml` breaks the stdlib-only / no-new-runtime-dep posture that every prior Phase-2
  slice held. The source format's authenticity is not worth a runtime dependency.
- **Approach 3 — ingest rules without tag normalization**, relying on the raw `tags` strings landing
  in the text. Rejected: although the HashingEmbedder's lowercasing + `[a-z0-9]+` tokenization would
  *partially* match (`attack.t1059` → token `t1059` ≈ query `T1059`), it is fragile and the citations
  / audit would show `attack.t1059` rather than the corpus's canonical `T1059`. Explicit canonical
  tokens make correlation robust and the provenance legible — and correlation is the slice's whole point.

**Why Approach 1:** established pattern, clean additional corpus, runtime stays stdlib-only, and the
detection↔CVE/technique relationship lands where it belongs — in search.

## 7. The design (decided)

### 7.1 `ingestion/sigma.py`

`load(raw: bytes) -> list[IngestedDocument]`:

1. `rules = json.loads(raw)` — expects a JSON **array** of rule objects (a `JSONDecodeError` is a
   `ValueError`; malformed JSON fails loud).
2. For each `rule` in `rules`:
   - `status = rule.get("status")`; if in `{"deprecated", "unsupported"}` → **skip** (not indexed).
   - `rule_id = rule.get("id")`; if missing/empty → `ValueError` naming the rule (`title` if present).
   - Duplicate `rule_id` → `ValueError`.
   - `title = rule.get("title")`; if missing/empty → `ValueError` naming `rule_id`.
   - `created_at = date.fromisoformat(str(rule["date"]).replace("/", "-")[:10])` — Sigma's `date` is
     `YYYY/MM/DD` (older) or `YYYY-MM-DD`; normalize `/`→`-`. Missing/invalid → `ValueError` naming `rule_id`.
   - `integrity_hash = "sha256:" + sha256(json.dumps(rule, sort_keys=True, separators=(",",":"),
     ensure_ascii=False).encode())` — canonical hash of the **exact rule object**.
   - `text` = §7.2.
   - `ResearchDocument(document_id=f"SIGMA-{rule_id}", source="Sigma",
     document_type=DocumentType.DETECTION, classification=PUBLIC, created_at=…,
     source_url="https://github.com/SigmaHQ/sigma", integrity_hash=…)`.
3. Return the list (order = input order).

`source_url` is the single SigmaHQ repo URL for every rule (mirrors KEV's single-catalog-URL choice —
a Sigma rule's own `references` point at external threat intel, not the rule's provenance, and the
rule YAML does not contain its own repo path, so a per-rule blob URL is not derivable in the loader).

### 7.2 Document text (and tag → correlation-token normalization)

Composed with `.get(..., "")` fallbacks (only `id`/`title`/`date` are strictly required). In order:
`title`, `description`, **correlation tokens**, `logsource` values (product/category/service), and
`level`. Correlation tokens come from `rule.get("tags", [])`:

- a tag matching `^attack\.t(\d{4})(\.\d{3})?$` (case-insensitive) → `T<digits>` (e.g. `attack.t1059.001` → `T1059.001`);
- a tag matching `^cve\.(\d{4})\.(\d+)$` → `CVE-<year>-<num>` (e.g. `cve.2021.44228` → `CVE-2021-44228`);
- every tag is **also** appended with its dots replaced by spaces, so tactic names etc. (`attack.execution`
  → `execution`) contribute topical words. (The embedder lowercases, so token case never matters —
  canonical tokens are for correlation robustness and legibility, not case.)

### 7.3 Fixture + wiring

- `ingestion/samples/sigma_sample.json`: a JSON array of a few real SigmaHQ rules — **at least one
  tagged with an ATT&CK technique that is in our fixture (`attack.t1059`)** and **at least one tied to
  CVE-2021-44228** (Log4Shell — already in the KEV fixture and the NVD live-fetch path) — converted
  from their upstream YAML via `yaml.safe_load` + `json.dump` in an isolated dir with `python -I`.
  Kept small.
- `samples/ATTRIBUTION.md`: a SigmaHQ section — source repo, the specific rule paths + retrieval date,
  and the DRL-1.1 license.
- `api/deps.get_service`: index `sigma_sample.json` after the NVD, ATT&CK, and KEV fixtures.

## 8. What is left to the builder

- The exact `text` assembly string and the two tag regexes (§7.2).
- The `load()` validation order / error messages (mirror `kev.py`'s fail-loud style).
- Choosing and building the fixture rules from SigmaHQ (confirm each rule has `id`/`title`/`date` and
  the expected `tags`; if a chosen rule lacks a needed tag, pick another — a ledger ruling if the real
  shape forces a change).
- Test cases: loader (parses a rule; namespaced `SIGMA-` id; `DETECTION` type; canonical hash shape;
  **tag→`T####` and tag→`CVE-…` tokens present in text**; `deprecated`/`unsupported` skipped;
  fail-loud on malformed JSON / missing id / missing title / bad date / duplicate id) and a
  deps/startup test that the Sigma rule for a technique/CVE is retrievable via `POST /research/search`
  (and the NVD/ATT&CK/KEV id-routes still answer unchanged — the no-blast-radius guarantee).

## 9. Review focus (for the final reviewer)

1. **Fail-loud coverage** — every §2 malformation raises `ValueError` naming the rule; deprecated/
   unsupported skipped; nothing silently indexed.
2. **Correlation works** — a rule tagged `attack.t1059` / `cve.2021.44228` surfaces `T1059` /
   `CVE-2021-44228` in its text (so search ties detection to technique/CVE).
3. **No blast radius** — indexing Sigma leaves `GET /research/cve/{id}` and `GET /research/attack/{id}`
   byte-identical; `_research`, `build_report`, `search` untouched; no `SIGMA-…` id can satisfy an id-route.
4. **Runtime stays stdlib-only** — no `import yaml` (or other non-stdlib) in `sigma.py` or any `src/` module.
5. **Citation/provenance integrity** — `source="Sigma"`, `source_url` the SigmaHQ repo, integrity hash
   of the exact rule object; determinism/hermeticity (no network at import/query, fixture committed).
