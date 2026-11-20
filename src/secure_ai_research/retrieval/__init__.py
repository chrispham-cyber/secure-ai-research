"""Retrieval pipeline: chunk -> embed -> store -> authorize -> retrieve.

Implemented: chunking, embeddings (the deterministic ``HashingEmbedder`` default; the
``OllamaEmbedder`` live adapter is the one remaining fail-loud stub), the vector store
(in-memory default, opt-in pgvector), and authorization. The ordering is deliberate: see
:mod:`secure_ai_research.retrieval.authz` — authorization is applied **before**
retrieval, never after generation.
"""
