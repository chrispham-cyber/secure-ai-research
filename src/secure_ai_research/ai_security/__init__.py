"""AI-security tooling: model-integrity verification.

Implemented: ``model_integrity.verify_model`` — a SHA-256 verifier that fails loud on a
missing or mismatched model hash before the model is used. The companion AI-specific
controls live beside the code they protect: the prompt-injection robustness harness in
:mod:`secure_ai_research.evaluation` (``injection_corpus``/``redteam``) and the
agent-authority checks in :mod:`secure_ai_research.agents`.
"""
