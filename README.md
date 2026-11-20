# Secure AI Research Platform

![CI](https://github.com/chrispham-cyber/secure-ai-research/actions/workflows/ci.yml/badge.svg)
<!-- This repo is private; the CI badge renders for authenticated viewers with repo access,
     and resolves publicly if the repo is ever made public. -->

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

**Status:** the platform is built through **Phase 5** of the [roadmap](ROADMAP.md) — the
full evidence-grounded pipeline (ingestion → retrieval → cited generation → audit), the
AI-specific controls, the evaluation/red-team harness, and the deploy-and-assurance layer
(OIDC identity, tamper-evident signed audit chain, at-rest cipher seam, reproducible SBOM,
STRIDE threat model, and a NIST control→evidence matrix) are all implemented and tested.
The **default path is deterministic, offline, and stdlib-only** — the hermetic suite needs
no network, database, or model — and every piece of real infrastructure (pgvector, MinIO,
an OIDC provider, Fernet-at-rest, a live Ollama model) sits behind an **opt-in `SAIR_*`
seam**. The one remaining fail-loud stub is `OllamaEmbedder` (local *embedding* via Ollama);
the default `HashingEmbedder` is real and deterministic.

**Tests:** **467 hermetic unit tests** (run in CI with no live services) + **20 integration
tests** (opt-in, exercised against real Postgres/MinIO/Ollama/Keycloak). Every pushed commit
runs lint · type · unit · supply-chain in [CI](.github/workflows/ci.yml).

## The four principles

Every design decision serves one of these (see
[architecture/system-design.md](architecture/system-design.md)):

1. **Confidentiality** — data and credentials never cross a boundary they weren't cleared
   for. Authorization is enforced *before* retrieval, so the model never receives a
   document the caller may not see.
2. **Integrity** — inputs are validated and provenance-tracked: documents carry a
   `sha256:` hash, models are verified against a pinned hash before use, dependencies are
   pinned and scanned.
3. **Auditability** — every AI-assisted analysis emits an append-only, hash-chained and
   HMAC-signed record (who, which model and prompt, which sources, what conclusion) so the
   work can be reconstructed and tampering is detectable.
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

# 4. Hit the API
curl http://127.0.0.1:8000/health      # {"status":"ok"}
curl http://127.0.0.1:8000/version     # version, git SHA, registered model names

# 5. (optional) pull the local embedding model into Ollama
make pull-model

# 6. Stop the stack
make down
```

Run `make help` for every target. The research endpoints are live:

```bash
curl http://127.0.0.1:8000/research/cve/CVE-2021-44228        # GET  a single CVE record
curl http://127.0.0.1:8000/research/attack/T1190              # GET  an ATT&CK technique
curl -X POST http://127.0.0.1:8000/research/search  -d '{"query":"log4j rce","k":5}'
curl -X POST http://127.0.0.1:8000/research/ask     -d '{"question":"How is CVE-2021-44228 exploited?"}'
```

`POST /research/ask` returns a drafted answer in which every claim cites a retrieved source;
authorization is enforced before any document is retrieved into model context.

## What's implemented

Nearly everything the pipeline needs is real, tested, and exercised in CI. The default
backends are deterministic and offline; the live backends are opt-in seams.

| Area | Real (tested, in CI) | Default backend | Opt-in backend (seam) |
|------|----------------------|-----------------|------------------------|
| Ingestion | Document schema + NVD/KEV/ATT&CK/Sigma loaders | bundled synthetic samples | live NVD fetch |
| Retrieval | Chunking, embeddings, vector store, **authorize-before-retrieve** | in-memory store + `HashingEmbedder` | `SAIR_VECTOR_STORE=pgvector` |
| Generation | Cited-answer synthesis, drop-uncited-claims | deterministic join | live `SAIR_` Ollama model |
| Agents | Tool functions with authority checks **outside** the LLM | — | — |
| Evaluation | Retrieval/answer metrics + synthetic benchmark + injection harness | offline | — |
| Reporting | Cited-report rendering + citation-faithfulness gate | offline | — |
| Identity | Signed-token identity; `X-Role` dev header retired in prod | local HS256 | `SAIR_AUTH=oidc` |
| Object store | Raw-payload provenance sink | in-memory | `SAIR_OBJECT_STORE=minio` |
| Audit at rest | Hash-chain + HMAC signing | `NullCipher` | `SAIR_CIPHER=fernet` |

**The one remaining fail-loud stub:** `OllamaEmbedder` (local embedding via Ollama) raises
until its slice wires the real adapter — guarded by
`tests/test_stubs.py::test_ollama_embedder_stub_raises_on_construction`. The default
`HashingEmbedder` is real, so the pipeline runs end-to-end offline today.

## Security & compliance

Security is documented as rigorously as it is built. The assurance artifacts are first-class:

- **[STRIDE threat model](architecture/threat-model.md)** — T1–T19 across every
  trust-boundary crossing, with [data-flow](architecture/data-flow.md) and
  [trust-boundary](architecture/trust-boundaries.md) diagrams.
- **[Risk register](documentation/risk-assessment/risk-register.md)** — R1–R19 (likelihood ×
  impact), each linked to the control that treats it, with accepted risks named and owned.
- **[Control → evidence matrix](documentation/assessment-evidence/control-evidence-matrix.md)**
  — every security claim maps to a NIST control, a source file, and a CI-run test:
  **AC-3** (authorize-before-retrieve), **AU-10** (tamper-evident audit chain),
  **IA-2** (signed-token identity), **IA-5** (fail-closed secret gate),
  **SC-8** (in-transit posture gate), **SC-28** (at-rest cipher seam). The matrix is itself
  CI-enforced — `tests/test_control_evidence.py` fails if a cited path or test disappears.
- **[System Security Plan](documentation/system-security-plan/system-security-plan.md)** —
  scope, boundary, and control narrative for the PUBLIC lane.
- **[SBOM & supply chain](documentation/sbom/sbom-guide.md)** — a reproducible CycloneDX SBOM
  built from the pinned lock, with a SHA-256 integrity manifest, `pip-audit`, gitleaks, and
  Dependabot; the drift/completeness gate runs in CI.

**Opt-in seams** keep the default path dependency-free while letting a real deployment turn on
real infrastructure: `SAIR_VECTOR_STORE=pgvector`, `SAIR_OBJECT_STORE=minio`,
`SAIR_AUTH=oidc`, `SAIR_CIPHER=fernet`. All published ports bind to `127.0.0.1`.

## Repository map

```
secure-ai-research/
├── README.md ROADMAP.md SECURITY.md CONTRIBUTING.md RESEARCH-LEDGER.md CHANGELOG.md LICENSE
├── architecture/            # system design, trust boundaries, data flow, STRIDE threat model
├── documentation/           # risk register, SSP, control→evidence matrix, SBOM guide
├── src/secure_ai_research/   # the installable package
│   ├── config.py             # typed settings loader
│   ├── api/                  # FastAPI app: /health, /version, /research/{cve,attack,search,ask}
│   ├── ingestion/            # document schema + nvd/kev/attack/sigma loaders
│   ├── retrieval/            # chunking, embeddings, vectorstore, authorize-before-retrieve
│   ├── generation/           # cited-answer synthesis (deterministic default + Ollama seam)
│   ├── ai_security/          # model-integrity SHA-256 verifier + registry
│   ├── audit/                # append-only, hash-chained, HMAC-signed research-record log
│   ├── agents/               # agent tool functions (authority checks live outside the LLM)
│   ├── evaluation/ reporting/ # metrics + injection harness + cited-report rendering
│   ├── identity/ secret/ crypto/ transit/ # OIDC identity, secret gate, at-rest cipher, transit posture
│   └── supply_chain/         # reproducible SBOM + integrity manifest
├── infrastructure/          # containers, identity (roles), model-runtime (registry), otel
├── security-controls/       # audit, supply-chain, access-control, encryption, IR (controls → NIST)
├── scripts/                 # bootstrap, gen-sbom, hash-model, new_research_record
├── tests/                   # 467 hermetic unit tests + 20 opt-in integration tests
├── docker-compose.yml Makefile pyproject.toml requirements*.txt env.example
└── .devcontainer/ .github/   # reproducible dev env + CI (lint/type/test/pip-audit/SBOM/gitleaks)
```

## Documentation

- **[ROADMAP.md](ROADMAP.md)** — the 24-week / 6-phase plan and what each phase delivered.
- **[architecture/](architecture/)** — [system design](architecture/system-design.md),
  [trust boundaries](architecture/trust-boundaries.md),
  [data flow](architecture/data-flow.md), [threat model](architecture/threat-model.md).
- **[documentation/](documentation/)** — [risk register](documentation/risk-assessment/risk-register.md),
  [control→evidence matrix](documentation/assessment-evidence/control-evidence-matrix.md),
  [system security plan](documentation/system-security-plan/system-security-plan.md),
  [SBOM guide](documentation/sbom/sbom-guide.md).
- **[SECURITY.md](SECURITY.md)** · **[CONTRIBUTING.md](CONTRIBUTING.md)** ·
  **[RESEARCH-LEDGER.md](RESEARCH-LEDGER.md)** · **[CHANGELOG.md](CHANGELOG.md)**
- **Reference:** [roles](infrastructure/identity/roles.md),
  [model runtime](infrastructure/model-runtime/models.md),
  [audit-record schema](security-controls/audit/audit-record-schema.md),
  [SBOM & supply chain](security-controls/supply-chain/sbom.md).

## License

[Apache-2.0](LICENSE). This is a personal learning/research project by Chris Pham.
