# Model integrity

> _Scope: PUBLIC / synthetic data only._

Verify a model against a pinned SHA-256 in the registry before use. (Verifier is implemented today.)

**Fills in:** Phase 1, ongoing — see [ROADMAP.md](../../ROADMAP.md).

**Principle:** never load a model whose hash is not pinned; a missing or mismatched hash fails loud.
