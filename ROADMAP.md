# Roadmap

A 24-week, six-phase plan to go from this foundation scaffold to a working,
evaluated, and hardened evidence-grounded AI research assistant.

> **Scope: PUBLIC / synthetic data only** throughout. No phase introduces controlled data;
> see [architecture/trust-boundaries.md](architecture/trust-boundaries.md).

Each phase lists its **objective**, **weekly tasks**, and **deliverables**. Checkboxes
track progress; Phase 1 is largely complete in this starter repo.

---

## Phase 1 — Foundation (weeks 1–4)

**Objective:** a clone-and-start repository with the architecture, threat model, dev
infrastructure, and the real security primitives, so later phases build on solid ground.

- [x] Week 1 — Repo scaffold, toolchain (ruff/black/mypy/pytest), pinned deps, pre-commit, CI
- [x] Week 1 — Typed config loader; document-metadata schema (`PUBLIC`-only)
- [x] Week 2 — Model-integrity SHA-256 verifier + model registry; append-only audit emitter
- [x] Week 2 — FastAPI skeleton: `/health`, `/version`, `/research/*`→501
- [x] Week 3 — Architecture docs (system design, trust boundaries, data flow)
- [x] Week 3 — STRIDE threat model mapped to repo controls
- [x] Week 4 — Dev infrastructure: docker-compose stack, devcontainer, Makefile, scripts
- [x] Week 4 — Program docs: README, roadmap, security, contributing, research ledger

**Deliverables:** this repository, green CI, documented stubs for everything deferred.

## Phase 2 — Evidence-grounded RAG (weeks 5–8)

**Objective:** turn the stubs into a working, cited retrieval pipeline on public data.

- [x] Week 5 — Ingestion loaders: NVD, CISA KEV → `ResearchDocument` with content hashes
- [ ] Week 5 — Object store (MinIO) for raw payloads; pgvector schema + migrations — _deferred: infra outside the in-posture offline/stdlib envelope_
- [x] Week 6 — Ingestion: MITRE ATT&CK, Sigma; chunking that preserves citation boundaries
- [ ] Week 6 — Local embeddings via Ollama; upsert chunks+embeddings to pgvector — _deferred: `Embedder`/`VectorStore` Protocol seams in place (HashingEmbedder + InMemoryVectorStore in posture)_
- [x] Week 7 — **Authorize-before-retrieve** gate; nearest-neighbor retrieval within scope
- [ ] Week 7 — Model inference constrained to retrieved passages (local generation model) — _deferred: retrieval-only in posture; no LLM synthesis_
- [x] Week 8 — Cited report rendering (drop uncited claims); wire `/research/*` endpoints live
- [x] Week 8 — Emit an audit record per analysis; end-to-end CVE-correlation demo — see `docs/phase2-correlation-demo.md`

**Deliverables:** a working `/research/cve/{id}` answer with citations and an audit trail.

## Phase 3 — AI-specific security (weeks 9–12)

**Objective:** make the agentic and access-control boundaries real and tested.

- [ ] Week 9 — Agent tool functions (`search_cve/attack/research`) with permission checks **outside** the LLM
- [ ] Week 10 — Role model + ABAC on retrieval; deny-by-default; two-user information-disclosure test
- [ ] Week 11 — Prompt-injection test harness + synthetic malicious-document corpus (clearly labeled)
- [ ] Week 12 — Excessive-agency guards: read-only tools, argument validation, rate limits

**Deliverables:** passing access-control and injection test suites; agent security notes.

## Phase 4 — Evaluation & red-teaming (weeks 13–16)

**Objective:** measure grounding, citation accuracy, refusal, and robustness — not vibes.

- [ ] Week 13 — Evaluation metrics (grounding, citation accuracy, refusal); uncited answers score zero
- [ ] Week 14 — Benchmark suite (≥50 items) in the repo format; methodology write-up
- [ ] Week 15 — Prompt-injection and information-disclosure red-team evals; acceptance criteria
- [ ] Week 16 — Results dashboard; regression gate wired into CI (unit-level)

**Deliverables:** a reproducible benchmark + results and documented acceptance thresholds.

## Phase 5 — Hardening & compliance (weeks 17–20)

**Objective:** replace dev stubs with real identity, encryption, and assurance artifacts.

- [ ] Week 17 — Keycloak/OIDC identity (replaces the `X-Role` dev stub); RBAC/ABAC enforcement
- [ ] Week 18 — Encryption at rest/in transit; secret management; audit WORM/signing
- [ ] Week 19 — System Security Plan, risk register, assessment-evidence templates filled in
- [ ] Week 20 — SBOM in the release pipeline; supply-chain checklist signed off

**Deliverables:** SSP + risk assessment + signed SBOM; identity behind the optional profile made default.

## Phase 6 — Capstone & integration (weeks 21–24)

**Objective:** integrate the broader cyber-research tooling and publish the capstone.

- [ ] Week 21 — Integration seams: CVE/threat-intel/malware/forensics/SIEM "evidence in, AI interprets"
- [ ] Week 22 — End-to-end research workflow across sources; security assessment of the platform
- [ ] Week 23 — Capstone research paper (structure in `reports/research-papers/`)
- [ ] Week 24 — Demo, final review, retrospective; backlog for v2

**Deliverables:** capstone paper, security assessment, demo, and a maintained threat model.

---

Progress and per-analysis records are tracked in [RESEARCH-LEDGER.md](RESEARCH-LEDGER.md).
