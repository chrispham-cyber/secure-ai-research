# Risk Register — TEMPLATE

> _Scope: PUBLIC / synthetic data only. Unfilled template._

> Fill in Phase 5 (week 19). Seed it from the [STRIDE threat
> model](../../architecture/threat-model.md): each threat (T1…) becomes one or more rows.
> Likelihood × Impact on a 1–3 scale → Low/Med/High/Critical, matching the threat model.

| ID | Asset | Threat (ref) | Likelihood | Impact | Risk | Treatment (mitigate/transfer/accept/eliminate) | Owner | Status |
|----|-------|--------------|-----------|--------|------|-----------------------------------------------|-------|--------|
| R1 | Corpus integrity | Data poisoning (T4) | _2_ | _3_ | _High_ | _Mitigate: schema validation + content hashes + injection eval_ | _…_ | _Open_ |
| R2 | Confidentiality boundary | Unauthorized retrieval (T2/T6) | _2_ | _3_ | _High_ | _Mitigate: authorize-before-retrieve + disclosure test_ | _…_ | _Open_ |
| R3 | Model | Model swap (T8) | _1_ | _3_ | _Med_ | _Mitigate: SHA-256 verifier + registry_ | _…_ | _Open_ |
| R… | _…_ | _…_ | _…_ | _…_ | _…_ | _…_ | _…_ | _…_ |

## Treatment notes
_For each Accept, record the accepting owner and the reason. For each Mitigate, link the
control that implements it. Review on every threat-model re-review trigger._
