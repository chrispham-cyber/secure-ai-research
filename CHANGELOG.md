# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
