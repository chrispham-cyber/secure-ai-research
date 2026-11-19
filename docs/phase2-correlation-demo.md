# Phase 2 — end-to-end CVE-correlation demo

This demo closes the Phase-2 (evidence-grounded RAG) objective: it shows the assembled corpus tying a
single pivot — a CVE or a MITRE ATT&CK technique — to the *related* evidence across every ingested
source, through the real authorize-before-retrieve pipeline, with an audit record per query.

## What it shows

The Phase-2 corpus ingests four public sources into one retrieval index:

| Source | Document | id namespace |
|---|---|---|
| NVD | vulnerability record | `CVE-…` (synthetic fixture; real records via opt-in live fetch) |
| CISA KEV | known-exploited advisory | `KEV-CVE-…` |
| MITRE ATT&CK | technique | `T####[.###]` |
| SigmaHQ | detection rule | `SIGMA-<uuid>` |

The demo runs two pivots through `ResearchService.search(...)` (the same authorize-before-retrieve
path the `/research/search` endpoint uses) and keeps the retrieved documents that explicitly
reference the pivot identifier:

```
# Phase-2 cross-source correlation

## Log4Shell — CVE-2021-44228
  - CISA KEV (known-exploited): KEV-CVE-2021-44228
  - SigmaHQ (detection): SIGMA-3eb91f0a-0060-424a-a676-59f5fdd75610

## Command and Scripting Interpreter — T1059
  - MITRE ATT&CK (technique): T1059
  - SigmaHQ (detection): SIGMA-ca2092a1-c273-4878-9b4b-0d60115bf5ea
```

So one query about **Log4Shell** returns both *that it is known-exploited in the wild* (CISA KEV) and
*how to detect an exploitation attempt* (a SigmaHQ rule) — a vulnerability correlated with its
advisory and its detection. One query about **T1059** returns both the ATT&CK technique and the
SigmaHQ detection that covers it — a technique correlated with its detection.

Every search also emits one audit record; for the Log4Shell pivot the record's `data_source_ids` is
`["CISA KEV", "Sigma"]`, so the cross-source correlation is visible in the audit trail itself.

## Run it

```bash
# print the correlation report
python -m secure_ai_research.demo.correlation

# the hermetic test that pins the correlation and the audit trail
.venv/bin/pytest tests/test_correlation_demo.py -q
```

Both are offline, deterministic, and need no services running.

## In-posture caveats

This demo stays inside the project's in-posture envelope (deterministic, offline, stdlib-only); the
infrastructure-heavy parts of the Phase-2 roadmap are deferred behind the existing Protocol seams:

- **Retrieval-only, no LLM synthesis.** The audit record's `model_id` is `retrieval-only`; the demo
  correlates and cites evidence, it does not generate a natural-language answer. A local generation
  model (constrained to the retrieved passages) is deferred.
- **Deterministic placeholder embeddings.** Ranking uses the in-posture `HashingEmbedder`
  (bag-of-words, 256-dim) — deterministic but semantically shallow: it ranks the genuine matches at
  the top but returns a noisy tail of documents sharing only a common token. The demo therefore keeps
  the documents whose passage *references the pivot identifier*, which is a `limit`-independent,
  honest correlation criterion. Real embeddings (Ollama) + pgvector are deferred; the
  `Embedder`/`VectorStore` Protocol seams are already in place.
- **NVD via opt-in live fetch.** The committed NVD fixture is synthetic, so the Log4Shell pivot does
  not include an `NVD (vulnerability)` row here. With `SAIR_ALLOW_LIVE_FETCH` enabled (default off),
  `GET /research/cve/CVE-2021-44228` fetches the real NVD record on miss, adding the third source.
- **No object store.** MinIO for raw payloads is deferred.
