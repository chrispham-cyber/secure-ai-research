# Risk Register

> Scope: PUBLIC / synthetic data only. Seeded from the STRIDE
> [threat model](../../architecture/threat-model.md) (T1–T19); Likelihood × Impact on a 1–3 scale
> → Low (1–2) / Med (3–4) / High (6) / Critical (9), matching the threat model. Treatment status
> reflects the controls shipped through Phase 5 Slice 5; where a threat model said "→ Phase 5",
> the register records what is now built.

| ID | Asset | Threat (ref) | L | I | Risk | Treatment | Owner | Status |
|----|-------|--------------|---|---|------|-----------|-------|--------|
| R1 | Role boundary | Caller asserts a role they do not hold (T1) | 3 | 2 | High | Mitigate: signed-token OIDC identity (Slice 4) retires the `X-Role` stub in prod; authorize-before-retrieve bounds blast radius | Owner | Mitigated (prod); dev header accepted locally |
| R2 | Confidentiality boundary | Caller retrieves documents above their role (T2) | 2 | 3 | High | Mitigate: `authorize()` enforced before `retrieve()` + two-user disclosure test | Owner | Mitigated |
| R3 | Corpus provenance | Public feed impersonated/tampered in transit (T3) | 2 | 2 | Med | Mitigate: in-transit posture gate (TLS allowlist) + content hashing + source allowlist | Owner | Partial |
| R4 | Corpus integrity | Malicious document poisons the corpus / stored injection (T4) | 2 | 3 | High | Mitigate: retrieved text handled as untrusted data; prompt-injection harness; integrity hashing | Owner | Mitigated |
| R5 | Ingestion availability | Oversized/malformed feed exhausts ingestion (T5) | 2 | 1 | Low | Mitigate: bounded input size + timeouts | Owner | Partial |
| R6 | Confidentiality boundary | Authorization bug leaks a document into model context (T6) | 2 | 3 | High | Mitigate: information-disclosure two-user eval + deny-by-default | Owner | Mitigated |
| R7 | Agent authority | Confused deputy: model requests data for a higher role (T7) | 2 | 3 | High | Mitigate: role bound to the request outside the LLM (`AgentToolset`); arg-validate before delegate | Owner | Mitigated |
| R8 | Model integrity | Model swapped for a backdoored one (T8) | 1 | 3 | Med | Mitigate: SHA-256 `verify_model` before use; fail loud on missing/mismatched hash | Owner | Mitigated |
| R9 | Model context | Prompt injection in retrieved text exfiltrates context / drives a tool call (T9) | 2 | 3 | High | Mitigate: authorize-before-retrieve keeps unauthorized content out of context; injection harness drops forged citations/impersonation. Instruction-following robustness is Phase-4+ scope | Owner | Mitigated (structural); residual noted |
| R10 | Host availability | Unbounded generation exhausts the host (T10) | 2 | 1 | Low | Mitigate: context/output limits + agent call-budget rate limiter | Owner | Partial |
| R11 | Report integrity | Report presents uncited/hallucinated claims as fact (T11) | 2 | 2 | Med | Mitigate: drop-uncited-claims + citation faithfulness gate + human review before acceptance | Owner | Mitigated |
| R12 | Accountability | Analyst denies an analysis, or a record is never written (T12) | 2 | 2 | Med | Mitigate: emit on every analysis path + tamper-evident signing (Slice 5) | Owner | Mitigated |
| R13 | Audit integrity | Audit log edited to hide an action (T13) | 1 | 3 | Med | Mitigate: append-only + SHA-256 hash-chain + HMAC (`verify_chain`) | Owner | Mitigated (tamper-evidence) |
| R14 | Object-store confidentiality | Raw payloads read by an unauthorized party (T14) | 1 | 2 | Low | Mitigate: loopback binding; real credentials for shared deploy; at-rest Cipher seam (opt-in) | Owner | Partial |
| R15 | Datastore boundary | Direct DB access bypasses the authz gate (T15) | 2 | 3 | High | Mitigate: app-mediated access only; loopback binding; least-privilege DB roles | Owner | Partial |
| R16 | Model registry | Registry edited to point at a malicious model / blank a hash (T16) | 1 | 3 | Med | Mitigate: version-controlled + code review; verifier fails loud on null hash; signed registry planned | Owner | Partial |
| R17 | Supply chain | Compromised dependency or CI step injects code (T17) | 2 | 3 | High | Mitigate: pinned reqs, `pip-audit`, CycloneDX SBOM, Dependabot; formal SBOM-in-release in Slice 7 | Owner | Mitigated (formalization planned) |
| R18 | Secret hygiene | A committed secret enables service impersonation (T18) | 2 | 3 | High | Mitigate: gitleaks + detect-private-key pre-commit + fail-closed secret gate (Slice 5) | Owner | Mitigated |
| R19 | Network exposure | A published service is reachable from the LAN and abused (T19) | 1 | 2 | Low | Mitigate: all ports bound to `127.0.0.1`; transit posture gate before any `0.0.0.0` exposure | Owner | Mitigated (loopback posture) |

## Treatment notes
Each Mitigate above links the control that implements it (see the
[control→evidence matrix](../assessment-evidence/control-evidence-matrix.md) for the exact file +
test). **Accepted risks**, with owner and reason:
- **Opt-in live-fetch timing side-channel** (Owner: platform owner) — the senior-analyst-only
  fetch-on-miss path has a timing difference between absent and present-but-RESTRICTED documents.
  Default off; no response-level oracle (NOT_FOUND is byte-identical). Triaged Minor in Phase 3/5
  and accepted.
- **Audit tamper-evidence is not WORM** (Owner: platform owner) — the hash-chain + HMAC make
  edits/reordering detectable, but tail-truncation is undetectable without an external head-hash
  anchor, and the HMAC is symmetric (a key-holder can rewrite history). Accepted for the PUBLIC
  single-tenant posture; an external anchor is future work.

Review on every threat-model re-review trigger.
