"""FastAPI surface for the platform.

Exposes liveness and provenance (``/health``, ``/version``) and the live research
endpoints (``/research/cve``, ``/research/attack``, ``/research/search``,
``/research/ask``); authorization is enforced before any document is retrieved into
model context.
"""
