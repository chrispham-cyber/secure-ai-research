# Design: Secure AI-Assisted Cybersecurity Research Platform — starter repository

**Date:** 2026-11-18
**Author:** Chris Pham (with Claude)
**Status:** Draft for approval
**Scope chosen:** Approach A — docs + scaffold starter (no working RAG yet)

---

## 1. Intent and the why

Chris pasted a complete 24-week roadmap for a *Secure AI-Assisted Cybersecurity
and Intelligence Research* platform and asked for its named "next development
artifact": **a GitHub-ready starter repository** carrying architecture
documentation, a threat model, implementation milestones, development
configuration, and a research progress ledger.

The *why*: give Chris a clean, self-contained, version-controlled starting point
he can `git clone`, `make up`, and begin **Phase 1** from immediately — with the
thinking (architecture, trust boundaries, threat model, control mapping) already
written down, the directory tree laid out, and the dev toolchain reproducible.
The repo is the foundation for Chris's stated specialization: *Secure AI Systems
Engineering and AI-Assisted Cybersecurity Research*, and the base for the roadmap's
flagship Project 1 (AI Threat Intelligence Research Assistant).

This is a **learning-and-research scaffold on public/synthetic data only**. It is
explicitly *not* approved for CUI or classified information, and makes no claim of
ATO or CMMC compliance.

## 2. Goals, non-goals, anti-goals

**Goals**
- A single, lean, `git init`-ed repo at `CyberBase/secure-ai-research/` matching
  the roadmap's section-9 tree.
- All *written* deliverables done and real: top-level README/ROADMAP/SECURITY/
  CONTRIBUTING, the four `architecture/` docs, a STRIDE **threat model**, the
  24-week **milestones**, and a **research progress ledger**.
- **Runnable dev configuration**: `docker-compose` brings up Postgres+pgvector,
  MinIO, and Ollama; a minimal FastAPI **skeleton** answers `/health` and
  `/version`; `make`, devcontainer, pinned deps, pre-commit, and CI all work.
- Every code package present as a **documented stub** whose unimplemented
  functions raise `NotImplementedError` and point to the roadmap phase that
  builds them.
- A few **genuinely real** low-risk primitives so CI is green and the security
  posture is demonstrated (see §6): the document-metadata Pydantic schema, a
  SHA-256 model-integrity verifier, a config loader, an audit-record emitter,
  and the health/version endpoint — all with tests.
- CI green on a fresh clone with only Docker + Python installed.

**Non-goals (deliberately deferred to later roadmap phases)**
- The working RAG pipeline: ingestion, chunking, embeddings, retrieval, LLM
  answer generation (roadmap Phase 2, weeks 5–8).
- Standing up Keycloak, Wazuh, Elastic, OpenTelemetry collectors as live
  services (documented + optional compose profiles, **off by default**).
- Integrating heavy external tools (Ghidra, Volatility, Autopsy, SIEM). The repo
  documents the *integration seams*, it does not vendor the tools.
- Any model fine-tuning, GPU serving (vLLM), or benchmark *execution*.

**Anti-goals (would make this a failure even if it "works")**
- A repo that *reads as* official, approved, or cleared for controlled data.
  It must be unmistakably public/synthetic-only, everywhere it matters.
- Stubs that silently return fake/plausible data (would undermine the whole
  "distinguish evidence from assumption" principle). Stubs must fail loudly.
- Committing real secrets, API keys, data dumps, or model weights.
- Dragging the 522k-file `CyberBase` workspace into the repo; it stays isolated.

## 3. Constraints

- **Isolation:** new repo, its own git history; nothing above `secure-ai-research/`
  is touched. `data/`, `models/`, `.env`, and secrets are git-ignored.
- **Reproducible from a bare machine:** `git clone` → `make up` must work with only
  Docker and Python 3.12 present. No network calls baked into tests.
- **Honest scaffold:** each unimplemented function names the roadmap phase/week
  that implements it; no stub fabricates results.
- **Public/synthetic data only**, enforced by `.gitignore` + prominent notices in
  README, SECURITY, and the per-dir READMEs.
- **Lean:** target ≈ 80–110 files, all text/config; no vendored binaries or datasets
  beyond tiny clearly-labelled synthetic samples.

## 3A. Source material (authoritative inputs)

The **single source of truth is the roadmap Chris pasted** (present in Claude's
conversation context). Every real schema, table, and written artifact derives
directly from it — nothing is invented. The build sequences the canonical docs
first so later tasks reference in-repo files, and each delegated task that needs a
contract gets it **inlined in its prompt** (the roadmap is not a file a fresh
subagent would otherwise have). Mapping:

| Repo artifact | Comes from (pasted roadmap) |
|---|---|
| `ROADMAP.md`, milestones, per-dir "phase/week" pointers | §6 (24-week / 6-phase roadmap) |
| section-9 directory tree | §9 (recommended repository structure) |
| `ingestion/schema.py` (document-metadata) | §4.2 metadata JSON example |
| `RESEARCH-LEDGER.md` per-analysis record + `audit/` emitter | §5.5 research-record schema |
| `evaluation/` 10 metrics + acceptance criteria | §10 (how to measure success) |
| `infrastructure/identity/roles.md` (6 roles) | §5.1 example roles table |
| `security-controls/*` NIST family mapping | §5.3 + §17 control families / supply-chain |
| model-selection table, registry fields | §4.1 model selection + §5.3 model record |
| capstone paper outline | §6 Phase-6 paper structure |
| four principles, authorization disclaimers | §1 and §7 |

This resolves the "where's the roadmap" gap: the contracts are pinned to paste
sections, not reinvented.

## 4. Approaches considered

- **A — Docs + scaffold starter (CHOSEN).** Full section-9 tree, all written
  artifacts, runnable dev config + API skeleton, documented stubs, a handful of
  real low-risk primitives with tests. Matches the roadmap's named deliverables
  exactly; clone-and-start Phase 1. *Trade-off:* nothing retrieves/answers yet.
- **B — Scaffold + one working vertical slice.** All of A plus a real path:
  ingest a KEV/NVD sample → pgvector → Ollama-backed CVE endpoint with citations.
  *Rejected for now:* front-runs the roadmap's Phase 2 and depends on Ollama + a
  pulled model + DB being up locally, making the "starter" heavier and less
  deterministic. Chris can green-light it as the explicit next step.
- **C — Docs only.** Just the written artifacts, no tree/config. *Rejected:*
  under-delivers on "a repository"; not GitHub-ready in any practical sense.

**Chris chose A.**

## 5. Repository layout (what each thing is)

```
secure-ai-research/
├── README.md                 # overview, 4 principles, quickstart, repo map, SAFETY notice
├── ROADMAP.md                # 24-week / 6-phase plan, objectives + deliverables, checkboxes
├── RESEARCH-LEDGER.md        # progress ledger (phase/week table) + per-analysis record schema
├── SECURITY.md               # repo security policy, public/synthetic-only scope, supply-chain stance
├── CONTRIBUTING.md           # dev workflow, branch/commit conventions, test/lint, data-separation rule
├── CHANGELOG.md              # keep-a-changelog, seeded 0.1.0
├── LICENSE                   # Apache-2.0 (my call, easily swapped)
├── Makefile                  # up/down/ingest-sample/test/lint/fmt/eval/sbom/new-record targets
├── pyproject.toml            # metadata + pinned deps + ruff/black/mypy/pytest config
├── requirements.txt          # pinned, pip-tools-compiled lock (SBOM-friendly)
├── docker-compose.yml        # postgres+pgvector, minio, ollama, app skeleton; keycloak/otel = profiles
├── .env.example              # every config knob, NO real secrets
├── .gitignore                # python, data/, models/, .env, secrets, volumes
├── .pre-commit-config.yaml   # ruff, black, gitleaks, detect-private-key, large-file guard
├── .devcontainer/            # devcontainer.json + Dockerfile (reproducible dev env)
├── .github/
│   ├── workflows/ci.yml      # ruff + black --check + mypy + pytest + pip-audit + cyclonedx SBOM + gitleaks
│   ├── dependabot.yml        # dependency updates (supply-chain)
│   └── ISSUE_TEMPLATE/       # research-task / security-finding templates
│
├── architecture/
│   ├── system-design.md      # 6-layer architecture, tech choices, model-selection strategy
│   ├── trust-boundaries.md   # Public / CUI / Classified separation; what must never cross
│   ├── data-flow.md          # DFD (Mermaid) for ingestion + RAG + audit
│   └── threat-model.md       # STRIDE (built via the threat-model skill)
│
├── infrastructure/
│   ├── containers/           # Dockerfile for the app skeleton + notes
│   ├── network/              # host-only dev net, firewall/allowlist guidance
│   ├── identity/             # roles.md (6 roles RBAC/ABAC matrix), Keycloak dev notes
│   ├── monitoring/           # audit-schema.md, otel-collector-config.yaml (stub), SIEM notes
│   └── model-runtime/        # models.md: Ollama usage, model registry concept, selection table
│
├── research-assistant/
│   ├── ingestion/            # schema.py (REAL Pydantic doc-metadata) + loader stubs (nvd/kev/attack/sigma)
│   ├── retrieval/            # chunking/embeddings/vectorstore/authz stubs; authz-before-retrieval pattern
│   ├── evaluation/           # metrics.py stub (10 metrics) + benchmarks/ with a 5-item SAMPLE in the ≥50 format
│   └── reporting/            # report.py stub + report template
│
├── ai-security/
│   ├── prompt-injection/     # test-suite design + synthetic malicious-doc corpus note (clearly labelled)
│   ├── information-disclosure/  # two-user access-control eval design + stub
│   ├── model-integrity/      # verify_model.py (REAL SHA-256 check) + dataset-integrity test design
│   └── agent-security/       # search_cve/search_attack/search_research read-only stubs + permission-outside-LLM pattern
│
├── cyber-research/
│   ├── cve/ threat-intelligence/ malware-analysis/ digital-forensics/ siem/
│   │                         # each: README on the integration + "tools generate evidence, AI interprets" principle
│
├── security-controls/
│   ├── access-control/ audit/ encryption/ supply-chain/ incident-response/
│   │                         # each: README mapping to NIST families (AC/AU/SC/SI/SR/IR); sbom.md; audit-record-schema.md
│
├── evaluation/
│   ├── benchmarks/ test-cases/ results/ methodology/
│   │                         # benchmark format, methodology, placeholder results, acceptance criteria
│
├── documentation/
│   ├── system-security-plan/ risk-assessment/ sbom/ assessment-evidence/
│   │                         # Phase-5 templates (SSP, risk register, SBOM, assessment evidence)
│
├── reports/
│   ├── technical/ research-papers/ security-assessments/
│   │                         # capstone paper outline template + report template
│
├── src/secure_ai_research/   # installable package root for the above code modules
│   ├── __init__.py  config.py (REAL loader)  api/ (FastAPI skeleton: /health /version /research/*→501)
│   └── audit/ (REAL audit-record emitter)
│
├── scripts/                  # bootstrap.sh, gen-sbom.sh, hash-model.sh, new_research_record.py
└── tests/                    # tests for the REAL bits (schema, verifier, config, audit, health endpoint)
```

*Note on package layout (decisive):* the roadmap's section-9 uses hyphenated
domain folders (`research-assistant/`, `ai-security/`, …) that are **not valid
Python import names**. Resolution: **all real/runnable Python lives under
`src/secure_ai_research/<domain>/`** (importable; CLIs run via `python -m`), and
the hyphenated domain folders are **docs-only** (README + design notes pointing at
the code). The file paths in §6 name *the concern each file implements*, not a
literal code location — e.g. "`ai-security/model-integrity/verify_model.py`" means
the model-integrity verifier, which actually lives at
`src/secure_ai_research/ai_security/model_integrity/verify_model.py`.

## 6. Real vs stub — the exact line

**Real (works, has tests, CI covers it):**
- `research-assistant/ingestion/schema.py` — Pydantic v2 models for the
  document-metadata schema from the roadmap (document_id, source, classification
  enum = PUBLIC only accepted in this repo, integrity_hash, verification_status,
  reviewed_by, …). Validates and round-trips.
- `…/ai_security/model_integrity/verify_model.py` — compute SHA-256 of a file and
  compare to a recorded value in a model-registry JSON; CLI + function.
  Unit-tested against a tiny in-repo fixture with a known hash (no real weights).
- `src/secure_ai_research/config.py` — load config from env/`.env`, typed.
- `src/secure_ai_research/audit/` — emit a structured research/audit record
  (the §5.5 schema) as JSON Lines; no network.
- `src/secure_ai_research/api/` — FastAPI app: `GET /health`, `GET /version`
  (returns package version + git SHA + registered model ids from the registry
  file — the registry ships one **synthetic** entry, so `/version` works with no
  weights on disk), and `/research/*` routers that return **501 Not Implemented**
  with a message pointing at the roadmap phase. This is the Phase-1 "auditable
  API" skeleton, **not** the RAG.
- `scripts/new_research_record.py` — emit a blank research-record template.

**Stub (documented, raises `NotImplementedError` with a roadmap pointer):**
- All ingestion loaders (nvd/kev/attack/sigma), all retrieval (chunking,
  embeddings, vectorstore, authz), evaluation metrics, reporting, the three
  agent functions, and every `ai-security/` test harness beyond the real
  verifier. Each stub's docstring names the phase/week that implements it and
  the key design rule (e.g. retrieval/authz.py: "authorization is applied
  *before* retrieval, never after generation").

## 7. Decisions I'm making (Chris can override any)

1. **Location / VCS:** `CyberBase/secure-ai-research/`, fresh `git init`, isolated history.
2. **Stack:** Python 3.12, FastAPI, Pydantic v2, psycopg + pgvector, Postgres 16,
   MinIO, Ollama — as the roadmap specifies. **Dependency source of truth =
   pip-tools-compiled `requirements.txt`** (what CI, pip-audit, SBOM and Dependabot
   read); `pyproject.toml` declares top-level deps; uv is an optional faster
   installer over the same pins. Lock target = **Linux** (CI + devcontainer +
   Docker are all Linux, so an Apple-Silicon host still matches).
3. **License:** Apache-2.0 (patent grant suits security tooling). *Flagged —
   genuinely your call; swap in one line.*
4. **Dev auth:** header-based role stub for Phase 1 (`X-Role: research_analyst`),
   with Keycloak documented as the Phase-5 target behind an optional compose
   profile — not stood up by default.
5. **API skeleton** (health/version/501 routers) is included as the Phase-1 API
   boundary; it is the line between A and B — no retrieval/LLM logic ships.
6. **Docs:** Markdown; diagrams in Mermaid (renders natively on GitHub).
7. **Threat model:** a hand-written **STRIDE** deliverable at
   `architecture/threat-model.md` (Claude produces it via the `threat-model`
   skill; a builder without that skill writes STRIDE by hand to the same shape —
   it's a document, not a tool dependency).
8. **CI = unit tests + checks only, no compose, no network:** ruff, black --check,
   mypy, pytest (unit; integration tests that need Postgres/MinIO/Ollama are
   `@pytest.mark.integration` and skipped in CI), pip-audit, cyclonedx SBOM,
   gitleaks. Bringing the stack up (`make up`) is a **documented manual smoke
   check**, not a CI gate.
9. **Data posture:** public/synthetic only; disclaimer in README + SECURITY +
   per-dir READMEs; `.gitignore` blocks `data/`, `models/`, `.env`, secrets.
10. **Compose extras:** Keycloak + OTel collector defined as **profiles**
    (`--profile identity`, `--profile monitoring`), off by default, so a bare
    `make up` stays light (just postgres+pgvector, minio, ollama, app).
11. **`make up` stays offline-friendly:** it does **not** auto-pull an Ollama
    model; `make pull-model` (or a documented `ollama pull`) is opt-in. The model
    registry ships one **synthetic** example entry so `/version` and the verifier
    work with no weights present.
12. **Doc-depth bar:** the core written docs (README, ROADMAP, system-design,
    trust-boundaries, data-flow, threat-model, RESEARCH-LEDGER, SECURITY) are
    **full and dense**; per-directory READMEs are **short but real** (what it's
    for, which phase/week fills it, the key rule, pointers — not empty, not
    essays); Phase-5 documents (SSP, risk register, assessment evidence) are
    **real templates** (headings + guidance prompts), not filled in.

## 8. Verification (how we'll know it's done)

- Fresh clone → `make up` brings up postgres+pgvector, minio, ollama (no model
  auto-pulled); `curl /health` returns ok and `/version` lists the synthetic
  registry entry. *(manual smoke check, not a CI gate)*
- `make test` (unit) and `make lint` pass locally; the CI workflow (unit + lint +
  type + pip-audit + SBOM + gitleaks, no compose) is green on a fresh clone with
  only Python.
- `pre-commit run --all-files` passes (incl. gitleaks finding nothing).
- `make sbom` emits a CycloneDX SBOM.
- Every stub raises `NotImplementedError` with a roadmap pointer (a test asserts
  the stubs are wired and documented, not that they do work).
- README quickstart, when followed literally, works.

## 9. Left to the builder

- Exact pinned dependency **versions** and service **image tags** (pick current
  stable, ≥2 weeks old) at build time.
- Whether the importable package is `src/secure_ai_research/` with domain
  sub-packages, or the domain folders themselves (either satisfies the design).
- Minor doc wording and the exact 5-item sample-benchmark questions.
- Precise set of pre-commit hooks beyond the named core.
```
