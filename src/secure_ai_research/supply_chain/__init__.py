"""Supply-chain integrity: reproducible release SBOM + SHA-256 pin (Phase 5, Slice 7).

The release bill of materials is built from the pinned runtime lock (``requirements.txt``)
via the dev-time ``cyclonedx-py`` CLI, projected to a canonical component set, and pinned by
a committed SHA-256 manifest. Nothing here is imported on the default runtime path and no new
runtime dependency is added: generation shells out to the CLI exactly as
``compliance.evidence`` shells out to ``pytest``.
"""
