# Research Ledger

Two things live here: a **progress ledger** for the platform build, and the
**per-analysis research-record** schema with how to append one.

> **Scope: PUBLIC / synthetic data only.** Records in this platform describe analyses over
> public/synthetic data.

## Part A — Build progress

| Phase | Weeks | Status | Artifacts / notes |
|-------|-------|--------|-------------------|
| 1 — Foundation | 1–4 | **In progress** (scaffold complete) | This repository: architecture docs, STRIDE threat model, dev infra, real schema/config/audit/verifier/API skeleton, green CI. Seeded **2026-11-18**. |
| 2 — Evidence-grounded RAG | 5–8 | Not started | Ingestion, chunking, embeddings, pgvector, authorize-before-retrieve, cited reports. |
| 3 — AI-specific security | 9–12 | Not started | Agent tools (checks outside LLM), ABAC, injection + disclosure tests. |
| 4 — Evaluation & red-teaming | 13–16 | Not started | Grounding/citation metrics, ≥50-item benchmark, acceptance criteria. |
| 5 — Hardening & compliance | 17–20 | Not started | Keycloak/OIDC, encryption, audit WORM, SSP/risk/assessment artifacts. |
| 6 — Capstone & integration | 21–24 | Not started | Tool integration, capstone paper, security assessment, demo. |

Update the **Status** and **Artifacts** cells as phases progress; keep the dated seed row.
The phase schedule is [ROADMAP.md](ROADMAP.md).

## Part B — Per-analysis research record

Every AI-assisted analysis emits one **append-only** record so the work can be
reconstructed and reviewed. The record is the schema in
[`src/secure_ai_research/audit/record.py`](src/secure_ai_research/audit/record.py) and is
documented field-by-field in
[security-controls/audit/audit-record-schema.md](security-controls/audit/audit-record-schema.md).

### Fields

| Field | Meaning |
|-------|---------|
| `research_id` | Unique id for this analysis. |
| `analyst_id` | Who ran it. |
| `timestamp` | When (UTC). |
| `objective` | The question/goal. |
| `data_source_ids` | Which sources were in scope. |
| `document_hashes` | `sha256:` hashes of the source documents used. |
| `model_id`, `model_version` | Which model produced the draft. |
| `prompt_template_version` | Which prompt template was used. |
| `retrieved_doc_ids` | Exactly which documents retrieval returned. |
| `tool_invocations` | Which tools the agent requested, and with what arguments. |
| `model_output` | The model's draft. |
| `validation_results` | Checks run against the draft (e.g. citations present). |
| `reviewer` | The human who reviewed it. |
| `conclusion` | The accepted conclusion. |

### Appending a record

```bash
# Print a blank template, fill it in, and append it to the audit log:
make new-record >> audit/research-records.jsonl
#   (make new-record runs scripts/new_research_record.py)
```

`audit/` is git-ignored — records stay local and are never committed. The log is JSON
Lines (one record per line), append-only, so the trail cannot be silently rewritten. The
logging rule that protects higher lanes — **never copy protected prompts or content into
an unauthorized store** — is stated in the
[audit-record schema](security-controls/audit/audit-record-schema.md).
