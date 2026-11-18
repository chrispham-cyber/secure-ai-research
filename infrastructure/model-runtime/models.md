# Model Runtime & Registry

> **Scope: PUBLIC / synthetic data only.** No model weights are committed to this
> repository.

Model choice here is a **security and provenance** decision, not only a quality one.

## Selection strategy

- **Local-first (Ollama).** Embedding and generation run on-host so source text and
  prompts never leave the machine. This is what makes the confidentiality principle
  enforceable end-to-end.
- **Right model per task.** A small, fast **embedding** model indexes the corpus; a larger
  **generation** model drafts answers. Both are named in configuration, not hard-coded.
- **Verify before use.** Every model is checked against a pinned SHA-256 in the registry
  before it is loaded; a missing or mismatched hash fails loudly.
- **Swappable by review.** Upgrading a model is a reviewed change to the registry (new
  hash, re-approval), not a code change.

### Selection table (starter defaults)

| Task | Model (default) | Runtime | Notes |
|------|-----------------|---------|-------|
| Embeddings | `nomic-embed-text` | Ollama (local) | Set via `SAIR_EMBEDDING_MODEL`. Indexes chunks into pgvector. |
| Generation | *(choose in Phase 2)* | Ollama (local) | A local instruct model; pin its hash in the registry before use. |
| Integrity check | n/a | `verify_model` CLI | Hashes a model file and compares to the registry. |

## The model registry

`infrastructure/model-runtime/model-registry.json` is the list of **approved** models.
Each entry:

| Field | Meaning |
|-------|---------|
| `name` | Model identifier (e.g. `example/local-llm`). |
| `version` | Version / tag. |
| `publisher` | Who published it. |
| `license` | License of the weights. |
| `source` | Where it came from (registry/URL/local). |
| `sha256` | Pinned content hash (`null` until recorded — the verifier then refuses it). |
| `format` | e.g. `safetensors`, `gguf`. |
| `approval_status` | `UNVERIFIED` / `VERIFIED` / approved — a human decision. |

The repo ships **one clearly-labeled synthetic entry** so `/version` and the verifier work
with no weights on disk.

## Verifying a model

```bash
# via the wrapper script:
./scripts/hash-model.sh --registry infrastructure/model-runtime/model-registry.json \
    --model-path path/to/model.safetensors --id example/local-llm

# or directly:
python -m secure_ai_research.ai_security.model_integrity.verify_model \
    --registry infrastructure/model-runtime/model-registry.json \
    --model-path path/to/model.safetensors --id example/local-llm
```

Exit status: **0** match · **1** mismatch or no recorded hash · **2** usage / unknown id.
Implementation:
[`verify_model.py`](../../src/secure_ai_research/ai_security/model_integrity/verify_model.py).
This is the control against model tampering/swap (threats T8/T16 in the
[threat model](../../architecture/threat-model.md)).

## Pulling the embedding model

`make pull-model` runs `ollama pull` **inside** the ollama service (no weights enter git).
It is opt-in; `make up` does not auto-pull.
