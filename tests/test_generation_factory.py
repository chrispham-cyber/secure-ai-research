"""Generator selection: Settings field + make_generator factory (Phase 5, Slice 1a, Task 4)."""

from __future__ import annotations

from secure_ai_research.config import Settings
from secure_ai_research.generation.factory import make_generator
from secure_ai_research.generation.join import JoinGenerator
from secure_ai_research.generation.ollama import OllamaGenerator


def test_settings_generator_defaults_to_join():
    settings = Settings()
    assert settings.generator == "join"
    assert settings.generation_model == "mistral:latest"


def test_factory_defaults_to_join():
    assert isinstance(make_generator(Settings()), JoinGenerator)


def test_factory_builds_ollama_when_selected():
    gen = make_generator(Settings(generator="ollama", generation_model="mistral:latest"))
    assert isinstance(gen, OllamaGenerator)
    assert gen.model_version == "mistral:latest"
