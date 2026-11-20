"""Generator selection (Phase 5, Slice 1a, Task 4).

Maps ``Settings`` to a concrete ``Generator``. The default is the deterministic
``JoinGenerator`` so the platform stays offline/deterministic unless a real model is explicitly
configured via ``SAIR_GENERATOR=ollama``.
"""

from __future__ import annotations

from secure_ai_research.config import Settings
from secure_ai_research.generation.join import JoinGenerator
from secure_ai_research.generation.ollama import OllamaGenerator
from secure_ai_research.generation.ports import Generator


def make_generator(settings: Settings) -> Generator:
    """Return the generator named by ``settings.generator`` (default: ``JoinGenerator``)."""
    if settings.generator == "ollama":
        return OllamaGenerator(settings.generation_model, settings.ollama_host)
    return JoinGenerator()
