# Secure AI-Assisted Cybersecurity Research — Starter Repo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Scaffold a GitHub-ready `secure-ai-research/` repository: full section-9 tree, written artifacts (architecture, STRIDE threat model, 24-week roadmap, research ledger), runnable dev config, documented stubs, and a few real tested primitives — on public/synthetic data only.

**Architecture:** One installable Python package `secure_ai_research` under `src/`, with importable domain sub-packages; hyphenated domain folders at repo root are docs-only. A small set of real, tested modules (config, metadata schema, model-integrity verifier, audit emitter, FastAPI health/version skeleton); everything RAG is a loud `NotImplementedError` stub pointing at the roadmap phase that builds it. Dev stack via docker-compose (Postgres+pgvector, MinIO, Ollama) brought up by `make up`; CI runs units/lint/type/SBOM/secret-scan only.

**Tech Stack:** Python 3.12, FastAPI, Pydantic v2 + pydantic-settings, psycopg + pgvector, Postgres 16, MinIO, Ollama; pytest, ruff, black, mypy, pip-tools, pip-audit, cyclonedx-bom, pre-commit, gitleaks; docker-compose, devcontainer; GitHub Actions.

**Spec:** `/private/tmp/claude-501/-Users-fox-Chris-CyberBase/dfc6f702-fe22-4732-a505-5449e60a7b1b/scratchpad/secure-ai-research-starter-design.md` (copied into the repo at `docs/superpowers/specs/2026-11-18-secure-ai-research-starter-design.md` by Task 1). The design doc in turn derives every contract from the roadmap Chris pasted (its §3A maps artifact → paste-section); where a task names a paste section, read it from the design doc's mapping.

## Global Constraints

- **Python 3.12**; type-hinted; passes `ruff`, `black --check`, `mypy src`.
- **Dependency source of truth = pip-tools-compiled `requirements.txt` / `requirements-dev.txt`** (what CI, pip-audit, SBOM, Dependabot read). `pyproject.toml` declares top-level deps. uv optional. Lock target = Linux. Pin exact versions ≥2 weeks old at build time.
- **Public/synthetic data only.** `ResearchDocument.classification` enum accepts **`PUBLIC` only**. Authorization disclaimer appears in `README.md`, `SECURITY.md`, and every per-directory README.
- **Never commit** real secrets, API keys, datasets, or model weights. `.gitignore` blocks `data/`, `models/`, `.env`, `*.key`, `*.pem`, volume dirs. gitleaks runs in pre-commit and CI.
- **Real code lives under `src/secure_ai_research/<domain>/`** (importable, snake_case); hyphenated root folders (`research-assistant/`, `ai-security/`, …) are **docs-only**. Paths written as `research-assistant/ingestion/schema.py` in prose name the *concern*; the code is at `src/secure_ai_research/ingestion/schema.py`.
- **Stubs fail loud:** every unimplemented function raises `NotImplementedError("<what> — ROADMAP Phase <n> (weeks <a>-<b>): <key design rule>")`. No stub returns fabricated or placeholder data.
- **CI = units + checks only** (`pytest -m "not integration"`, ruff, black, mypy, pip-audit, cyclonedx SBOM, gitleaks). No compose, no network calls in tests. `make up` is a documented manual smoke check; it does **not** auto-pull an Ollama model.
- **Docs in Markdown; diagrams in Mermaid.** Core docs full/dense; per-dir READMEs short-but-real; Phase-5 docs are real templates (headings + guidance prompts), not filled in.
- **License: Apache-2.0.** Commit frequently; Conventional Commits.
- Attribution footer on each commit per the session reminder (`Co-Authored-By: Claude Opus 4.8 …` + `Claude-Session:` line).

## Review Focus

Input classes / failure modes the spec implies; each is pinned to a task's test below.

1. **Non-PUBLIC classification in a document record** (e.g. `classification: "CUI"`) → must be **rejected** at validation, never stored. → Task 3 test `test_non_public_classification_rejected`.
2. **`GET /version` with no model weights on disk / placeholder hash in registry** → must return **200** listing the synthetic registry entry, not crash. → Task 6 test `test_version_ok_without_weights`.
3. **Model verifier given a file whose SHA-256 ≠ registry value** → returns **False / non-zero exit, loudly**; never silently "verified". → Task 4 test `test_verify_mismatch_fails`.
4. **A RAG stub invoked at runtime** → raises `NotImplementedError` with a roadmap pointer; never returns `None`/fake data. → Task 7 test `test_all_stubs_raise_notimplemented`.
5. **Audit emit when the log directory does not exist / appended twice** → creates parents and appends one valid JSONL line per call (no corruption, no overwrite). → Task 5 tests `test_emit_creates_path` + `test_emit_appends`.

---

### Task 1: Repository skeleton & toolchain baseline

**Files:**
- Create: `secure-ai-research/` (new dir, `git init`)
- Create: `src/secure_ai_research/__init__.py` (`__version__ = "0.1.0"`)
- Create: `pyproject.toml`, `.gitignore`, `.editorconfig`, `.pre-commit-config.yaml`, `LICENSE`, `CHANGELOG.md`
- Create: `.github/workflows/ci.yml`, `.github/dependabot.yml`
- Create: `tests/test_smoke.py`
- Create: `docs/superpowers/specs/2026-11-18-secure-ai-research-starter-design.md` (copy of the spec), `docs/superpowers/plans/2026-11-18-secure-ai-research-starter.md` (copy of this plan)
- Test: `tests/test_smoke.py`

**Interfaces:**
- Produces: installable package `secure_ai_research` exposing `__version__: str`; a green lint/type/test toolchain every later task relies on.

- [ ] **Step 1: `git init secure-ai-research` and `cd` into it.** All later paths are relative to this repo root.
- [ ] **Step 2: Write `tests/test_smoke.py`**

```python
def test_package_imports_and_has_version():
    import secure_ai_research
    assert secure_ai_research.__version__ == "0.1.0"
```

- [ ] **Step 3: Run it to verify it fails** — `pytest tests/test_smoke.py -q` → FAIL (module not found).
- [ ] **Step 4: Create `src/secure_ai_research/__init__.py`** with `__version__ = "0.1.0"`.
- [ ] **Step 5: Create `pyproject.toml`** — `[project]` name `secure-ai-research`, requires-python `>=3.12`; `[build-system]` setuptools; `[tool.setuptools.packages.find]` where `src`; runtime deps (fastapi, uvicorn[standard], pydantic>=2, pydantic-settings, python-dotenv, httpx); optional `[project.optional-dependencies] dev` (pytest, ruff, black, mypy, pip-tools, pip-audit, cyclonedx-bom, pre-commit); `[tool.ruff]`, `[tool.black]`, `[tool.mypy]`, `[tool.pytest.ini_options]` (with `markers = ["integration: needs live services"]`). Pin exact versions in `requirements*.txt` (Step 7).
- [ ] **Step 6: `pip install -e .[dev]`**, then run `pytest -q` → the smoke test PASSES.
- [ ] **Step 7: Compile pins** — author `requirements.in` / `requirements-dev.in`, run `pip-compile` to produce pinned `requirements.txt` / `requirements-dev.txt` (Linux target).
- [ ] **Step 8: Create `.gitignore`** (python, `data/`, `models/`, `.env`, `*.key`, `*.pem`, `.venv/`, volume dirs, `*.sbom.json`), `.editorconfig`, `LICENSE` (Apache-2.0, 2026 Chris Pham), `CHANGELOG.md` (keep-a-changelog seeded `0.1.0 — scaffold`).
- [ ] **Step 9: Create `.pre-commit-config.yaml`** — ruff, black, end-of-file-fixer, trailing-whitespace, check-added-large-files, detect-private-key, gitleaks. Run `pre-commit run --all-files` → passes.
- [ ] **Step 10: Create `.github/workflows/ci.yml`** — on push/PR: setup-python 3.12, `pip install -r requirements-dev.txt && pip install -e .`, then `ruff check .`, `black --check .`, `mypy src`, `pytest -m "not integration" -q`, `pip-audit`, `cyclonedx-py` (emit SBOM artifact), gitleaks action. Create `.github/dependabot.yml` (pip, weekly).
- [ ] **Step 11: Copy the spec and this plan** into `docs/superpowers/specs/` and `docs/superpowers/plans/`.
- [ ] **Step 12: Commit** — `chore: scaffold repo, toolchain, CI baseline`.

---

### Task 2: Config loader

**Files:** Create `src/secure_ai_research/config.py`; Test `tests/test_config.py`.

**Interfaces:**
- Produces: `class Settings(BaseSettings)` (env prefix `SAIR_`) with fields `db_url: str`, `minio_endpoint: str`, `minio_access_key: str`, `minio_secret_key: str`, `ollama_host: str = "http://localhost:11434"`, `embedding_model: str = "nomic-embed-text"`, `model_registry_path: Path`, `audit_log_path: Path`, `data_classification: Literal["PUBLIC"] = "PUBLIC"`; and `def get_settings() -> Settings` (lru_cached, reads `.env`).

- [ ] **Step 1: Write `tests/test_config.py`** — `test_defaults_load` (env-provided required fields → Settings populated; `ollama_host` default correct); `test_env_prefix_override` (monkeypatch `SAIR_OLLAMA_HOST` → reflected); `test_classification_is_public` (`data_classification == "PUBLIC"`).
- [ ] **Step 2: Run → FAIL** (`pytest tests/test_config.py -q`).
- [ ] **Step 3: Implement `Settings` + `get_settings()`** in `config.py` using pydantic-settings; `Path` fields default under `./data/` and `./audit/` (both git-ignored).
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** — `feat(config): typed settings loader`.

---

### Task 3: Document-metadata schema (REAL)

**Files:** Create `src/secure_ai_research/ingestion/__init__.py`, `src/secure_ai_research/ingestion/schema.py`; Test `tests/test_schema.py`.

**Interfaces:**
- Produces: enums `Classification` (`PUBLIC` only), `VerificationStatus` (`UNVERIFIED|VERIFIED|REJECTED`), `DocumentType` (`vulnerability|advisory|technique|detection|paper|other`); `class ResearchDocument(BaseModel)` with fields from design §6 / paste §4.2: `document_id: str`, `source: str`, `document_type: DocumentType`, `classification: Classification`, `created_at: date`, `source_url: AnyUrl`, `integrity_hash: str` (pattern `^sha256:[0-9a-f]{64}$`), `verification_status: VerificationStatus = UNVERIFIED`, `reviewed_by: str | None = None`.

- [ ] **Step 1: Write `tests/test_schema.py`** —
  - `test_valid_document_roundtrips` — a PUBLIC doc with a well-formed `sha256:` hash validates and `model_dump_json()`/reload is stable.
  - `test_non_public_classification_rejected` *(Review Focus 1)* — constructing with `classification="CUI"` raises `ValidationError`.
  - `test_bad_integrity_hash_rejected` — `integrity_hash="deadbeef"` (no prefix / wrong length) raises `ValidationError`.
  - `test_defaults` — omitted `verification_status` is `UNVERIFIED`, `reviewed_by` is `None`.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** the enums + `ResearchDocument` with a `Field(pattern=...)` on `integrity_hash`; `Classification` enum enforces PUBLIC-only.
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** — `feat(ingestion): public-only research-document metadata schema`.

---

### Task 4: Model registry + integrity verifier (REAL)

**Files:** Create `src/secure_ai_research/ai_security/__init__.py`, `src/secure_ai_research/ai_security/model_integrity/__init__.py`, `.../model_integrity/verify_model.py`; Create `infrastructure/model-runtime/model-registry.json` (one synthetic entry); Test `tests/test_verify_model.py` (+ fixture `tests/fixtures/sample_model.bin`).

**Interfaces:**
- Produces: `def sha256_file(path: Path) -> str` (lowercase hex, no prefix); `def verify_file(path: Path, expected_sha256: str) -> bool`; `class ModelRecord(BaseModel)` (name, version, publisher, license, source, `sha256: str | None`, format, approval_status); `def load_registry(path: Path) -> list[ModelRecord]`; `def main(argv: list[str] | None = None) -> int` (CLI: `--registry`, `--model-path`, `--id`; prints result, returns 0 on match / 1 on mismatch / 2 on usage error).

- [ ] **Step 1: Add fixture** `tests/fixtures/sample_model.bin` (a few known bytes) and compute its real SHA-256 for the test.
- [ ] **Step 2: Write `tests/test_verify_model.py`** —
  - `test_sha256_file_matches_known` — `sha256_file(fixture)` equals the precomputed hex.
  - `test_verify_match` — `verify_file(fixture, known_hex) is True`.
  - `test_verify_mismatch_fails` *(Review Focus 3)* — `verify_file(fixture, "00"*32)` is `False`.
  - `test_load_registry_synthetic` — loads `model-registry.json`, yields ≥1 `ModelRecord` with `approval_status == "UNVERIFIED"`.
  - `test_cli_mismatch_returns_1` — `main([...])` with wrong hash returns `1`.
- [ ] **Step 3: Run → FAIL.**
- [ ] **Step 4: Implement** `sha256_file` (stream in chunks), `verify_file`, `ModelRecord`, `load_registry`, `main`. Create `model-registry.json` with one **synthetic** entry (name `"example/local-llm"`, version `"0.0.0-synthetic"`, publisher `"synthetic"`, license `"UNKNOWN"`, source `"local"`, `sha256: null`, format `"safetensors"`, approval_status `"UNVERIFIED"`).
- [ ] **Step 5: Run → PASS.**
- [ ] **Step 6: Commit** — `feat(ai-security): model-integrity SHA-256 verifier + synthetic registry`.

---

### Task 5: Audit / research-record emitter (REAL)

**Files:** Create `src/secure_ai_research/audit/__init__.py`, `.../audit/record.py`; Test `tests/test_audit.py`.

**Interfaces:**
- Produces: `class ResearchRecord(BaseModel)` with the paste-§5.5 fields (`research_id, analyst_id, timestamp, objective, data_source_ids: list[str], document_hashes: list[str], model_id, model_version, prompt_template_version, retrieved_doc_ids: list[str], tool_invocations: list[dict], model_output: str, validation_results: dict, reviewer: str | None, conclusion: str`); `def emit(record: ResearchRecord, path: Path) -> None` (append one JSON line, `mkdir(parents=True, exist_ok=True)`); `def read_records(path: Path) -> list[ResearchRecord]`.

- [ ] **Step 1: Write `tests/test_audit.py`** —
  - `test_emit_creates_path` *(Review Focus 5)* — emit to a path under a non-existent dir (`tmp_path/"nope"/"audit.jsonl"`) creates it and the file exists.
  - `test_emit_appends` *(Review Focus 5)* — two `emit` calls → `read_records` returns 2 records in order (no overwrite).
  - `test_roundtrip_fields` — a record survives emit→read with all fields equal.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** `ResearchRecord`, `emit` (open mode `"a"`, write `model_dump_json()` + `"\n"`), `read_records`.
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** — `feat(audit): JSONL research-record emitter`.

---

### Task 6: FastAPI skeleton — health / version / 501 research routers (REAL)

**Files:** Create `src/secure_ai_research/api/__init__.py`, `.../api/main.py`, `.../api/routers/research.py`; Test `tests/test_api.py`.

**Interfaces:**
- Consumes: `__version__` (Task 1), `get_settings()` (Task 2), `load_registry()` + `model_registry_path` (Tasks 2/4).
- Produces: `app: FastAPI`; `def git_sha() -> str` (env `SAIR_GIT_SHA`, else `git rev-parse --short HEAD`, else `"unknown"`).
- Routes: `GET /health` → `{"status":"ok"}`; `GET /version` → `{"version", "git_sha", "models": [record.name,…]}`; `GET /research/cve/{cve_id}`, `GET /research/attack/{technique_id}`, `POST /research/search` → **501** with detail pointing at ROADMAP Phase 2.

- [ ] **Step 1: Write `tests/test_api.py`** (FastAPI `TestClient`) —
  - `test_health_ok` — `GET /health` → 200, `{"status":"ok"}`.
  - `test_version_ok_without_weights` *(Review Focus 2)* — `GET /version` → 200; `version == "0.1.0"`; `models` contains `"example/local-llm"` (synthetic registry, no weights on disk).
  - `test_research_cve_501` — `GET /research/cve/CVE-2026-0001` → 501 and detail mentions "Phase 2".
  - `test_research_search_501` — `POST /research/search` → 501.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** `main.py` (app, health, version using `git_sha()` + registry from settings) and `routers/research.py` (three endpoints raising `HTTPException(status_code=501, detail="Not implemented — ROADMAP Phase 2 (weeks 5-8): evidence-grounded RAG")`). Wire the registry path from `get_settings()` with the repo's `model-registry.json` as default.
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** — `feat(api): Phase-1 auditable API skeleton (health/version/501 routers)`.

---

### Task 7: RAG domain stubs (loud NotImplementedError)

**Files:** Create stub modules + `__init__.py`s under `src/secure_ai_research/`: `ingestion/{nvd,kev,attack,sigma}.py`, `retrieval/{chunking,embeddings,vectorstore,authz}.py`, `evaluation/metrics.py`, `reporting/report.py`, `agents/functions.py`; Test `tests/test_stubs.py`.

**Interfaces:**
- Produces: documented callables that each `raise NotImplementedError("<concern> — ROADMAP Phase <n> (weeks <a>-<b>): <rule>")`. Key rules to embed verbatim in docstrings: `retrieval/authz.py` → "authorization is applied **before** retrieval, never after generation"; `agents/functions.py` (`search_cve`, `search_attack`, `search_research`) → "the model may *request* a function; the application independently decides if it is permitted (checks live outside the LLM)".

- [ ] **Step 1: Write `tests/test_stubs.py`** —
  - `test_all_stubs_raise_notimplemented` *(Review Focus 4)* — parametrized over every stub callable: calling it raises `NotImplementedError` whose message contains `"ROADMAP Phase"`.
  - `test_all_stubs_have_docstrings` — each stub's `__doc__` is non-empty.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** the stub modules with precise signatures (e.g. `def load(raw: bytes) -> list[ResearchDocument]`, `def chunk(text: str) -> list[str]`, `def embed(chunks: list[str]) -> list[list[float]]`, `def retrieve(query: str, *, role: str) -> list[ResearchDocument]`, `def authorize(role: str, doc: ResearchDocument) -> bool`, `def score(predictions, gold) -> dict`, `def build_report(...) -> str`, `search_cve/search_attack/search_research(...)`), each body = `raise NotImplementedError(...)` + roadmap-pointer docstring.
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** — `feat: documented RAG/agent stubs with roadmap pointers`.

---

### Task 8: Dev infrastructure — compose, Dockerfile, devcontainer, Makefile, scripts

**Files:** Create `docker-compose.yml`, `infrastructure/containers/Dockerfile`, `.env.example`, `.devcontainer/devcontainer.json` (+ `.devcontainer/Dockerfile`), `Makefile`, `scripts/{bootstrap.sh,gen-sbom.sh,hash-model.sh,new_research_record.py}`; Test `tests/test_scripts.py` + extend CI.

**Interfaces:**
- Consumes: the app package (for the `app` service + `new_research_record.py`), `ResearchRecord` (Task 5).
- Produces: `make` targets `up,down,logs,test,lint,fmt,typecheck,sbom,pull-model,new-record,hash-model,help`; a compose file valid under `docker compose config`.

- [ ] **Step 1: Write `tests/test_scripts.py`** — `test_new_research_record_emits_template`: running `scripts/new_research_record.py` (via `subprocess`, `-I`) prints JSON that parses into a `ResearchRecord` with blank/default fields.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement**:
  - `docker-compose.yml` — services `db` (`pgvector/pgvector:pg16`), `minio`, `ollama`, `app` (build `infrastructure/containers/Dockerfile`, runs `uvicorn secure_ai_research.api.main:app`); `keycloak` + `otel-collector` under `profiles: [identity]` / `[monitoring]`. Healthchecks; named volumes; **no model auto-pull**.
  - `.env.example` — every `SAIR_*` knob with safe placeholders, no real secrets.
  - `Dockerfile` (app) + `.devcontainer/` (python 3.12, installs `.[dev]`).
  - `Makefile` with the targets above (`pull-model` → `ollama pull`; `new-record` → the script; `sbom` → cyclonedx; `test` → `pytest -m "not integration"`).
  - `scripts/new_research_record.py` (uses `ResearchRecord`), `bootstrap.sh`, `gen-sbom.sh`, `hash-model.sh` (wraps the verifier CLI).
- [ ] **Step 4: Verify** — `docker compose config -q` exits 0; `python -c "import json,sys; json.load(open('.devcontainer/devcontainer.json'))"` ok (strip comments if JSONC); `make help` lists targets; `pytest tests/test_scripts.py -q` PASSES; `shellcheck scripts/*.sh`.
- [ ] **Step 5: Extend `.github/workflows/ci.yml`** with a `compose-validate` job (`docker compose config -q`).
- [ ] **Step 6: Commit** — `feat(infra): docker-compose stack, devcontainer, Makefile, scripts`.

---

### Task 9: Architecture documents

**Files:** Create `architecture/system-design.md`, `architecture/trust-boundaries.md`, `architecture/data-flow.md`.

- [ ] **Step 1: Write `system-design.md`** — the 6-layer architecture + tech table + model-selection strategy (design §5 / paste §3–4). Include a Mermaid layer diagram.
- [ ] **Step 2: Write `trust-boundaries.md`** — Public/CUI/Classified separation, what must never cross, "no shared DB/endpoints/creds", "removing names ≠ declassified" (paste §2–3, §7). Mermaid boundary diagram.
- [ ] **Step 3: Write `data-flow.md`** — ingestion + RAG + audit DFD as a Mermaid flowchart with trust-boundary subgraphs; enumerate external entities, processes, data stores.
- [ ] **Step 4: Verify** — files render (Mermaid fences well-formed); internal links resolve; public/synthetic disclaimer present.
- [ ] **Step 5: Commit** — `docs(architecture): system design, trust boundaries, data flow`.

---

### Task 10: Threat model (STRIDE)

**Files:** Create `architecture/threat-model.md`.

- [ ] **Step 1:** Produce the STRIDE threat model via the `threat-model` skill (or by hand to the same shape): scope + assumptions, the data-flow elements from Task 9, a STRIDE table (Spoofing/Tampering/Repudiation/Info-disclosure/DoS/Elevation) per element, risk ranking, and mitigations **mapped to this repo's controls** (schema PUBLIC-only, authz-before-retrieval, stubs-fail-loud, audit emitter, SBOM/verifier, gitleaks). Call out the AI-specific threats from paste §5 (prompt injection, unauthorized retrieval, model/dataset integrity, excessive agency).
- [ ] **Step 2: Verify** — every STRIDE category appears for ≥1 element; each high risk has a named mitigation that exists (or is a roadmap pointer); disclaimer present.
- [ ] **Step 3: Commit** — `docs(architecture): STRIDE threat model`.

---

### Task 11: Program documents — README, ROADMAP, SECURITY, CONTRIBUTING, ledger, key reference docs

**Files:** Create `README.md`, `ROADMAP.md`, `SECURITY.md`, `CONTRIBUTING.md`, `RESEARCH-LEDGER.md`, `infrastructure/identity/roles.md`, `infrastructure/model-runtime/models.md`, `security-controls/audit/audit-record-schema.md`, `security-controls/supply-chain/sbom.md`.

- [ ] **Step 1: `README.md`** — overview, the four principles (paste §1), quickstart (`git clone` → `pip install -e .[dev]` → `make up` → `curl /health`), repo map, status (Phase-1 scaffold), **SAFETY/authorization disclaimer** (public/synthetic only; not approved for CUI/classified; no ATO/CMMC claim). Quickstart commands must match the Task 8 Makefile targets.
- [ ] **Step 2: `ROADMAP.md`** — the 24-week / 6-phase plan (paste §6): per phase objective, weekly tasks, deliverables, as `- [ ]` checkboxes.
- [ ] **Step 3: `SECURITY.md`** — repo security policy, public/synthetic scope, supply-chain stance (pinned deps, SBOM, verifier), how to report issues.
- [ ] **Step 4: `CONTRIBUTING.md`** — dev workflow, Conventional Commits, `pre-commit`, `make test/lint`, the "keep public artifacts separate from protected materials" rule.
- [ ] **Step 5: `RESEARCH-LEDGER.md`** — (a) progress table (phase/week → status/artifacts), seeded with the scaffold entry dated 2026-11-18; (b) the per-analysis **research-record schema** (paste §5.5) + how to append one with `make new-record`.
- [ ] **Step 6: Reference docs** — `roles.md` (the 6 RBAC/ABAC roles, paste §5.1, + "a model never inherits the analyst's privileges", + the Phase-1 **dev-auth pattern**: an `X-Role:` request header maps to a role, documented as the throwaway stub to be replaced by Keycloak in Phase 5, design §7.4); `models.md` (model-selection table + registry fields, paste §4.1/§5.3); `audit-record-schema.md` (the record fields + logging-must-not-copy-protected-content rule); `sbom.md` (how `make sbom` works + supply-chain checklist, paste §5.3).
- [ ] **Step 7: Verify** — all internal links resolve; quickstart matches Makefile; disclaimer in README + SECURITY.
- [ ] **Step 8: Commit** — `docs: README, roadmap, security, contributing, research ledger, reference docs`.

---

### Task 12: Per-directory READMEs, Phase-5 templates, capstone outline, sample data

**Files:** Create short-but-real `README.md` in every remaining section-9 directory — `research-assistant/{ingestion,retrieval,evaluation,reporting}/`, `ai-security/{prompt-injection,information-disclosure,model-integrity,agent-security}/`, `cyber-research/{cve,threat-intelligence,malware-analysis,digital-forensics,siem}/`, `security-controls/{access-control,audit,encryption,supply-chain,incident-response}/`, `infrastructure/{containers,network,identity,monitoring,model-runtime}/`, `evaluation/{benchmarks,test-cases,results,methodology}/`. Create templates `documentation/{system-security-plan,risk-assessment,sbom,assessment-evidence}/README.md` (+ template files). Create `reports/research-papers/paper-outline.md` (paste §6 capstone structure), `reports/technical/report-template.md`. Create `evaluation/benchmarks/sample-benchmark.jsonl` (5 synthetic public CVE/ATT&CK questions in the ≥50 format) and `ai-security/prompt-injection/CORPUS.md` (note: synthetic malicious docs live under git-ignored `data/`, clearly labelled).

- [ ] **Step 1:** Write each per-dir README (3–10 lines: purpose, which roadmap phase/week fills it, the key principle — e.g. cyber-research dirs: "tools generate evidence; AI interprets it", evaluation: the relevant metrics/acceptance criteria). Each carries the public/synthetic disclaimer line.
- [ ] **Step 2:** Write the Phase-5 templates as real skeletons (headings + guidance prompts, paste §5/§6/§20), not filled in.
- [ ] **Step 3:** Write the capstone `paper-outline.md` and `report-template.md`.
- [ ] **Step 4:** Write `sample-benchmark.jsonl` (5 items: `{id, question, answer_type, source_ids, acceptance}`) and `CORPUS.md`.
- [ ] **Step 5: Verify** — a script assertion that **every directory enumerated in this task** contains a `README.md` (dirs documented by other artifacts — e.g. `architecture/`, `infrastructure/containers/` — are exempt); all `*.jsonl` lines are valid JSON; disclaimers present.
- [ ] **Step 6: Commit** — `docs: per-directory READMEs, Phase-5 templates, capstone outline, sample benchmark`.

---

### Task 13: Final assembly & whole-repo verification

**Files:** touch `CHANGELOG.md`; no new code.

- [ ] **Step 1:** Fresh-clone smoke (in a temp dir): `pip install -e .[dev]` → `pytest -m "not integration" -q` all pass; `ruff check .` + `black --check .` + `mypy src` clean; `pre-commit run --all-files` passes (gitleaks finds nothing); `docker compose config -q` exits 0; `make sbom` emits a CycloneDX file.
- [ ] **Step 2:** Confirm Review-Focus tests 1–5 exist and pass; confirm every section-9 directory has a README (Task 12 check).
- [ ] **Step 3:** Update `CHANGELOG.md` `0.1.0`; final commit `chore: 0.1.0 starter scaffold complete`.
- [ ] **Step 4:** (If Chris wants it on GitHub) print the `gh repo create` command; do not push without his go-ahead.

---

## Notes for the executor

- Work top-to-bottom; Tasks 2–7 depend on Task 1's toolchain; Task 6 depends on 2+4; Task 8 depends on 5; docs Tasks 9–12 depend only on Task 1. Tasks 9–12 can be parallelized if execution is subagent-driven.
- Keep bodies idiomatic; the plan fixes signatures, test names/assertions, and the spec's exact values — you choose implementation details within them.
- Never commit `.env`, `data/`, `models/`, or weights. If a step needs network (pip-compile, docker pull, gitleaks action), note it; tests must not require network.
