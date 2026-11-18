# Secure AI Research Platform

An **evidence-grounded AI research assistant for cybersecurity** — and a study in
building one *securely*. It ingests public threat knowledge (CVEs, exploited-vulnerability
catalogs, MITRE ATT&CK, detections), retrieves the passages relevant to an analyst's
question, and uses a **locally hosted** model to draft an answer in which **every claim
cites a retrieved source**. The security of the system is treated as a first-class
concern, not an afterthought.

> ## ⚠️ Safety & authorization
>
> **This repository is a learning-and-research scaffold on PUBLIC / synthetic data only.**
> It is **not** approved for CUI, classified, or otherwise controlled information, and it
> makes **no** claim of ATO, CMMC, or any accreditation. Do not place controlled data in
> these services. The classification-lane separation is documented in
> [architecture/trust-boundaries.md](architecture/trust-boundaries.md); this repo operates
> entirely in the PUBLIC lane.

**Status:** **Phase 1 — foundation scaffold.** The architecture, threat model, dev
infrastructure, and a handful of real, tested primitives (document schema, config loader,
audit emitter, model-integrity verifier, API skeleton) are in place. The retrieval and
inference pipeline is present as **documented stubs** that fail loudly with a pointer to
the roadmap phase that builds them. See [ROADMAP.md](ROADMAP.md).

## The four principles

Every design decision serves one of these (see
[architecture/system-design.md](architecture/system-design.md)):

1. **Confidentiality** — data and credentials never cross a boundary they weren't cleared
   for. Authorization is enforced *before* retrieval, so the model never receives a
   document the caller may not see.
2. **Integrity** — inputs are validated and provenance-tracked: documents carry a
   `sha256:` hash, models are verified against a pinned hash before use, dependencies are
   pinned and scanned.
3. **Auditability** — every AI-assisted analysis emits an append-only record (who, which
   model and prompt, which sources, what conclusion) so the work can be reconstructed.
4. **Human accountability** — the model drafts; a person decides. The model may *request*
   a tool call, but the application decides whether it is permitted. Uncited claims are
   omitted, never presented as fact.

## Quickstart

Requires **Docker** and **Python 3.12**.

```bash
git clone <this-repo> secure-ai-research
cd secure-ai-research

# 1. Dev environment (venv + dev deps + pre-commit hooks + .env)
./scripts/bootstrap.sh
#   equivalently: python3 -m venv .venv && .venv/bin/pip install -e '.[dev]' && cp env.example .env

# 2. Run the checks (lint, types, unit tests)
make test
make lint

# 3. Bring up the local stack (Postgres+pgvector, MinIO, Ollama, app) — all on 127.0.0.1
make up

# 4. Hit the Phase-1 API
curl http://127.0.0.1:8000/health      # {"status":"ok"}
curl http://127.0.0.1:8000/version     # version, git SHA, registered model names

# 5. (optional) pull the local embedding model into Ollama
make pull-model

# 6. Stop the stack
make down
```

Run `make help` for every target. `/research/*` endpoints intentionally return **501 Not
Implemented** with a roadmap pointer — the answering pipeline lands in Phase 2.

## Repository map

```
secure-ai-research/
├── README.md ROADMAP.md SECURITY.md CONTRIBUTING.md RESEARCH-LEDGER.md CHANGELOG.md LICENSE
├── architecture/            # system design, trust boundaries, data flow, STRIDE threat model
├── src/secure_ai_research/   # the installable package (real code + documented stubs)
│   ├── config.py             # typed settings loader (real)
│   ├── api/                  # FastAPI skeleton: /health, /version, /research/*→501 (real)
│   ├── ingestion/            # schema.py (real) + nvd/kev/attack/sigma loaders (stubs)
│   ├── retrieval/            # chunking, embeddings, vectorstore, authz (stubs)
│   ├── ai_security/          # model_integrity/verify_model.py (real SHA-256 verifier)
│   ├── audit/                # append-only research-record emitter (real)
│   ├── agents/               # agent tool functions (stubs; checks live outside the LLM)
│   ├── evaluation/ reporting/ # metrics + cited-report rendering (stubs)
├── infrastructure/          # containers, identity (roles), model-runtime (registry), otel
├── security-controls/       # audit, supply-chain, access-control, encryption, IR (controls → NIST)
├── scripts/                 # bootstrap, gen-sbom, hash-model, new_research_record
├── tests/                   # tests for the real primitives
├── docker-compose.yml Makefile pyproject.toml requirements*.txt env.example
└── .devcontainer/ .github/   # reproducible dev env + CI (lint/type/test/pip-audit/SBOM/gitleaks)
```

## What's real vs. stubbed

| Real (tested, in CI) | Stubbed (fail loud, roadmap pointer) |
|----------------------|--------------------------------------|
| Document-metadata schema (`PUBLIC`-only) | Ingestion loaders (NVD/KEV/ATT&CK/Sigma) |
| SHA-256 model-integrity verifier + registry | Chunking, embeddings, vectorstore, authz |
| Config loader · audit-record emitter | Evaluation metrics · report rendering |
| FastAPI `/health`, `/version`, 501 routers | Agent tool functions |

## Documentation

- **[ROADMAP.md](ROADMAP.md)** — the 24-week / 6-phase plan.
- **[architecture/](architecture/)** — [system design](architecture/system-design.md),
  [trust boundaries](architecture/trust-boundaries.md),
  [data flow](architecture/data-flow.md), [threat model](architecture/threat-model.md).
- **[SECURITY.md](SECURITY.md)** · **[CONTRIBUTING.md](CONTRIBUTING.md)** ·
  **[RESEARCH-LEDGER.md](RESEARCH-LEDGER.md)**
- **Reference:** [roles](infrastructure/identity/roles.md),
  [model runtime](infrastructure/model-runtime/models.md),
  [audit-record schema](security-controls/audit/audit-record-schema.md),
  [SBOM & supply chain](security-controls/supply-chain/sbom.md).

## License

[Apache-2.0](LICENSE). This is a personal learning/research project by Chris Pham.
