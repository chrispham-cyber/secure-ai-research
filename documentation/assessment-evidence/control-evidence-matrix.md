# Control → Evidence Matrix

> Scope: PUBLIC / synthetic data only. This records evidence for the controls the platform
> actually implements. It is **not** an authorization package and claims **no ATO / CMMC /
> baseline completeness** — only the mapped controls below are claimed.

Each control claimed in the [SSP](../system-security-plan/system-security-plan.md) needs an
artifact that evidences it — a source file plus a test, a config, or a CI job. "Implemented"
without evidence is a claim, not assurance. Every backticked repo path and `pytest` node id below
is machine-checked by `tests/test_control_evidence.py`: a renamed or deleted artifact fails CI,
so this matrix cannot drift from the code.

| Control | Claim | Evidence (source) | Verified by | Status |
|---------|-------|-------------------|-------------|--------|
| **AC-3** Access enforcement | Authorize-before-retrieve: RBAC + within-PUBLIC sensitivity (ABAC) tier, decided before any document is read | `src/secure_ai_research/retrieval/authz.py` | `tests/test_authz.py::test_denied_roles` | met |
| **AU-10** Non-repudiation | Tamper-evident audit chain: SHA-256 hash-chain + HMAC envelope, `verify_chain` detects edit/reorder/forgery | `src/secure_ai_research/audit/signing.py` | `tests/test_audit_signing.py::test_emitted_chain_verifies` (clean), `tests/test_audit_signing.py::test_tampered_record_detected` (edit), `tests/test_audit_signing.py::test_reordered_records_detected` (reorder), `tests/test_audit_signing.py::test_flipped_hmac_detected` (forgery) | met |
| **IA-2** Identification & authentication | Signed-token (OIDC/JWT) identity; the spoofable `X-Role` dev header is retired in prod | `src/secure_ai_research/identity/tokens.py` | `tests/test_identity_tokens.py::test_rejects_bad_signature` | met |
| **IA-5** Authenticator / secret management | Fail-closed-in-prod secret gate refuses boot on placeholder/weak secrets, checking the source each consumer actually reads | `src/secure_ai_research/secret/verify.py` | `tests/test_verify_secrets.py::test_verify_secrets_raises_on_placeholder_audit_key_in_prod` | met |
| **SC-8** Transmission confidentiality | In-transit posture gate flags any active non-loopback backend without TLS (TLS-enforcing sslmode allowlist) | `src/secure_ai_research/transit.py` | `tests/test_transit.py::test_non_loopback_pgvector_without_ssl_warns` | partial — flags, does not terminate TLS (uvicorn/proxy owns that hop) |
| **SC-28** Protection of information at rest | Cipher seam over the audit log; `NullCipher` default, opt-in `FernetCipher` behind the `[crypto]` extra | `src/secure_ai_research/crypto/factory.py` | `tests/test_crypto_cipher.py::test_make_cipher_default_is_null` | partial — encryption is opt-in |
| **SC-5** Denial-of-service protection | Deterministic token-bucket call-budget charged before any agent tool validates/delegates | `src/secure_ai_research/agents/rate_limit.py` | `tests/test_rate_limit.py::test_budget_without_refill_exhausts` | met |
| **SI-10** Information input validation | Prompt-injection neutralization: labelled corpus + pipeline-safety harness drop forged citations / impersonation | `src/secure_ai_research/evaluation/injection_corpus.py` | `tests/test_injection_harness.py::test_forged_citation_id_absent_from_report` | met |
| **SI-7** Software / model integrity | SHA-256 model-hash verification against a pinned registry | `src/secure_ai_research/ai_security/model_integrity/verify_model.py` | `tests/test_verify_model.py::test_verify_mismatch_fails` | met |
| **CM-2 / CM-6** Baseline & configuration | Pinned dependencies, pre-commit hooks, and a CI suite that runs the whole test battery incl. this matrix | `.github/workflows/ci.yml` | config review (every CI run) | partial — no formal baseline doc |
| **SR-3** Supply-chain protection | Reproducible release SBOM from the pinned lock, SHA-256-pinned in a committed manifest; a dependency change that is not re-attested fails CI (guide: `documentation/sbom/sbom-guide.md`) | `src/secure_ai_research/supply_chain/sbom.py` | `tests/test_sbom.py::test_sbom_covers_every_pinned_runtime_dependency`, `tests/test_sbom.py::test_committed_sbom_matches_regeneration` | met |
| **IR-8** Incident response | Incident-response runbook under the security-controls set | `security-controls/incident-response/README.md` | doc review | partial — runbook present, not exercised |

## Guidance

Prefer evidence that re-generates (a test, a CI job) over a static screenshot, and link the exact
file or node. For each row, the `Status` is honest: **met** has a passing cited test or concrete
config; **partial** is a real but opt-in or incomplete control; **planned** is not yet built (and
names the slice that will). Update this matrix whenever a control's implementation or its evidence
moves — `tests/test_control_evidence.py` will fail until the citation is live again.
