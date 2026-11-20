# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Phases 2–5 of the [roadmap](ROADMAP.md): the platform grew from the Phase-1 scaffold into a
complete, tested, evidence-grounded pipeline with its security controls and assurance
artifacts in place. Public/synthetic data only; version intentionally held at `0.1.0`.

### Added
- **Evidence-grounded RAG (Phase 2).** Chunking, embeddings (deterministic `HashingEmbedder`
  default), vector store (in-memory default + opt-in pgvector), and the research endpoints —
  `GET /research/cve/{cve_id}`, `GET /research/attack/{technique_id}`, `POST /research/search`,
  `POST /research/ask`; answers cite their retrieved sources, with authorization enforced
  before retrieval.
- **AI-specific security (Phase 3).** SHA-256 model-integrity verifier, a prompt-injection
  robustness harness, and agent authority checks enforced outside the LLM.
- **Evaluation & red-teaming (Phase 4).** Retrieval/answer-grounding metrics, a synthetic
  benchmark harness, and a scored red-team / injection suite.
- **Deploy & assurance (Phase 5).** Signed-token (OIDC/JWT) identity retiring the dev
  `X-Role` header in prod; a tamper-evident audit log (SHA-256 hash-chain + HMAC); an opt-in
  at-rest cipher seam (`NullCipher` default, Fernet behind `[crypto]`); a reproducible
  CycloneDX SBOM with a SHA-256 integrity manifest; and the assurance docs — STRIDE threat
  model, NIST control→evidence matrix, risk register, and system security plan.

### Security
- Opt-in `SAIR_*` seams keep the default path deterministic, offline, and dependency-free;
  all published ports bind to `127.0.0.1`; a fail-closed secret gate refuses boot on weak
  prod secrets.

## [0.1.0] — 2026-11-18

Initial starter scaffold (Phase-1 foundation). Public/synthetic data only; not
approved for CUI or classified information.

### Added
- Repository tree and Python package (`secure_ai_research`).
- Toolchain: ruff, black, mypy, pytest, pre-commit, pinned requirements, CI.
- Real primitives: config loader, document-metadata schema, model-integrity
  verifier, audit/research-record emitter, FastAPI health/version skeleton.
- Documented `NotImplementedError` stubs for all RAG/agent code, each pointing at
  the ROADMAP phase that implements it.
- Dev stack: docker-compose (Postgres+pgvector, MinIO, Ollama), devcontainer,
  Makefile, scripts. All published ports bound to `127.0.0.1`.
- Supply-chain tooling: CycloneDX SBOM (`make sbom`), pip-audit, gitleaks,
  Dependabot, model-hash pinning.
- Docs: README, SECURITY, CONTRIBUTING, architecture (system design, trust
  boundaries, data flow), STRIDE threat model, 24-week roadmap, research ledger,
  per-directory READMEs, Phase-5 assurance templates, capstone outline.
- Sample synthetic benchmark (`evaluation/benchmarks/sample-benchmark.jsonl`) and
  prompt-injection corpus policy.

_This is a work in progress; see [ROADMAP.md](ROADMAP.md)._
