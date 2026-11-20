"""Ingestion: load public cybersecurity sources into validated research records.

Implemented: the validated-record :mod:`~secure_ai_research.ingestion.schema` plus the
NVD/KEV/ATT&CK/Sigma loaders. The default path reads bundled synthetic samples offline;
live NVD fetch is an opt-in seam.
"""
