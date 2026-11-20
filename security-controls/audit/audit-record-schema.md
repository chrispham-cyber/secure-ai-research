# Audit-Record Schema

> **Scope: PUBLIC / synthetic data only.**

Maps to **NIST AU** (Audit and Accountability). Every AI-assisted analysis emits one
**append-only** JSON Lines record so the work can be reconstructed and reviewed. The record
is defined in
[`src/secure_ai_research/audit/record.py`](../../src/secure_ai_research/audit/record.py)
and written by `emit()`.

## Fields

| Field | Type | Meaning |
|-------|------|---------|
| `research_id` | str | Unique id for this analysis. |
| `analyst_id` | str | Who ran it. |
| `timestamp` | datetime (UTC) | When it ran. |
| `objective` | str | The question or goal. |
| `data_source_ids` | list[str] | Which sources were in scope. |
| `document_hashes` | list[str] | `sha256:` hashes of the documents used (provenance). |
| `model_id` | str | Model that produced the draft. |
| `model_version` | str | Version of that model. |
| `prompt_template_version` | str | Which prompt template was used. |
| `retrieved_doc_ids` | list[str] | Exactly which documents retrieval returned. |
| `tool_invocations` | list[dict] | Tools the agent requested, with arguments. |
| `model_output` | str | The model's draft. |
| `validation_results` | dict | Checks run against the draft (e.g. citations present). |
| `reviewer` | str \| None | Human who reviewed it. |
| `conclusion` | str | The accepted conclusion. |

Defaults: `verification`/list/dict fields default to empty; `reviewer` defaults to `None`;
strings default to `""`. See the schema source for exact definitions.

## Why these fields

Together they answer **who** did **what**, **with which model and prompt**, over **which
sources**, producing **what conclusion**, reviewed by **whom**. That is enough to
reconstruct an analysis independently — the basis for non-repudiation (threat T12).

## Integrity, not just presence

- Records are **append-only** JSON Lines; the emitter never rewrites earlier lines.
- `audit/` is git-ignored — records stay local and are never committed.
- Stronger integrity (restrictive filesystem permissions, WORM storage, hash-chaining or
  signing) is a **Phase 5** enhancement (threat T13).

## The rule: logging must not copy protected content into an unauthorized store

Audit records are themselves data with a classification. **The audit log must never copy
protected prompts, retrieved content, or outputs into a store that is not cleared for that
classification.** In a higher lane this means:

- The audit store lives in the **same lane** as the data it records; it is never shipped to
  a lower-lane or shared logging system.
- If a field could contain controlled content (`model_output`, retrieved snippets), the
  higher-lane deployment stores a **reference or hash**, not the raw content, when the log
  sink is less trusted than the data.
- In this PUBLIC repo the content is public/synthetic, so records may hold it directly —
  but the code and process are written so the rule holds when it matters.

## Appending a record

```bash
make new-record >> audit/research-records.jsonl
```

See [RESEARCH-LEDGER.md](../../RESEARCH-LEDGER.md) for the per-analysis workflow.
