# Data-Flow Diagram

> **Scope: PUBLIC / synthetic data only.** This repository runs in the PUBLIC lane; see
> [trust-boundaries.md](trust-boundaries.md).

This is the data-flow diagram (DFD) for the three flows the platform cares about —
**ingestion**, **retrieval-augmented answering (RAG)**, and **audit** — with trust
boundaries drawn as subgraphs. It is the basis for the STRIDE analysis in
[threat-model.md](threat-model.md): STRIDE is applied at each boundary crossing below.

> **Phase 1 note.** The ingestion and RAG processes are documented **stubs** today
> (they raise `NotImplementedError` with a roadmap pointer). The audit emitter, the
> document schema, the model-integrity verifier, and the API skeleton are real. The DFD
> shows the intended Phase-2 flow so the boundaries can be reviewed before the code
> lands.

## Diagram

```mermaid
flowchart TB
    analyst["Analyst<br/>(external entity)"]
    reviewer["Human reviewer<br/>(external entity)"]

    subgraph INET["Trust boundary: Internet"]
        feeds["Public threat feeds<br/>NVD · KEV · ATT&amp;CK · Sigma<br/>(external entity)"]
    end

    subgraph HOST["Trust boundary: host / compose network"]
        ingest["P1 Ingestion &amp; validation"]
        chunk["P2 Chunk &amp; embed"]
        subgraph AUTHZB["Trust boundary: authorization gate"]
            authz["P3 Authorize (role, doc)"]
            retrieve["P4 Retrieve"]
        end
        infer["P5 Model inference<br/>(local Ollama)"]
        report["P6 Report render"]
        audit["P7 Audit emit"]

        obj[("D1 Object store<br/>raw payloads · MinIO")]
        vec[("D2 Vector + metadata DB<br/>pgvector")]
        reg[("D3 Model registry<br/>JSON + sha256")]
        log[("D4 Audit log<br/>JSONL, append-only")]
    end

    feeds -->|"raw bytes"| ingest
    ingest -->|"ResearchDocument + hash"| obj
    ingest -->|"validated docs"| chunk
    chunk -->|"chunks + embeddings"| vec

    analyst -->|"query + role"| authz
    authz -->|"permitted scope"| retrieve
    vec -->|"candidate docs"| retrieve
    retrieve -->|"cited passages"| infer
    reg -->|"verified model"| infer
    infer -->|"draft + citations"| report
    report -->|"cited report"| reviewer

    ingest -.->|"record"| audit
    retrieve -.->|"record"| audit
    infer -.->|"record"| audit
    audit --> log
```

## External entities

| ID | Entity | Role in the flow |
|----|--------|------------------|
| — | **Analyst** | Submits a question and a role; receives a cited report. Untrusted input source. |
| — | **Public threat feeds** | NVD, CISA KEV, MITRE ATT&CK, Sigma. Untrusted external data crossing the internet boundary. |
| — | **Human reviewer** | Reviews and accepts/rejects the AI-drafted conclusion. The accountability backstop. |

## Processes

| ID | Process | Security-relevant job | Code |
|----|---------|----------------------|------|
| P1 | Ingestion & validation | Validate each item into a `PUBLIC` `ResearchDocument`; attach a `sha256:` content hash. | `ingestion/*` |
| P2 | Chunk & embed | Split text preserving citation boundaries; embed locally. | `retrieval/chunking.py`, `retrieval/embeddings.py` |
| P3 | Authorize | Decide, **before** retrieval, which documents the role may see. | `retrieval/authz.py` |
| P4 | Retrieve | Nearest-neighbor search within the authorized scope only. | `retrieval/vectorstore.py` |
| P5 | Model inference | Draft an answer constrained to retrieved passages, on a hash-verified local model. | `ai_security/model_integrity/`, Ollama |
| P6 | Report render | Emit a report where every claim cites a retrieved document id; drop uncited claims. | `reporting/report.py` |
| P7 | Audit emit | Append a reconstructable record of the analysis. | `audit/record.py` (real) |

## Data stores

| ID | Store | Contents | Notes |
|----|-------|----------|-------|
| D1 | Object store (MinIO) | Raw source payloads | Keyed by content hash; never user-writable directly. |
| D2 | Vector + metadata DB (pgvector) | Documents, chunks, embeddings, classification | Query path is authorization-filtered. |
| D3 | Model registry | Approved models + pinned `sha256` | No weights in the repo; one synthetic entry ships. |
| D4 | Audit log | Append-only JSON Lines | `research/audit` records; integrity matters more than confidentiality here. |

## Boundary crossings to analyze (STRIDE)

1. **feeds → P1 (internet → host):** untrusted external data. *Spoofing / Tampering* —
   verify source TLS and pin content hashes; treat all input as hostile.
2. **analyst → P3 (user → authorization gate):** untrusted query + asserted role.
   *Spoofing / Elevation of privilege* — authenticate the role; never trust a
   self-asserted header in production.
3. **P3 → P4 (authorization gate):** the confidentiality boundary. *Information
   disclosure* — a bug here leaks documents into the model's context.
4. **P5 model inference:** *Tampering* (model swap) — the integrity verifier pins the
   model hash. *Information disclosure* (prompt injection via retrieved text) — evaluate
   in Layer 6.
5. **P6 → reviewer (machine → human):** *Repudiation* — the audit record (P7 → D4) is
   what makes the analysis non-repudiable and reviewable.

Each crossing is enumerated with its STRIDE threats and mitigations in
[threat-model.md](threat-model.md).
