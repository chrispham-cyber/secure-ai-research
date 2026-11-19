from pathlib import Path

from secure_ai_research.config import Settings, get_settings


def test_defaults_load():
    s = Settings()
    assert s.ollama_host == "http://localhost:11434"
    assert s.embedding_model == "nomic-embed-text"
    assert s.data_classification == "PUBLIC"


def test_env_prefix_override(monkeypatch):
    monkeypatch.setenv("SAIR_OLLAMA_HOST", "http://ollama:11434")
    s = Settings()
    assert s.ollama_host == "http://ollama:11434"


def test_classification_is_public():
    assert Settings().data_classification == "PUBLIC"


def test_get_settings_is_cached():
    assert get_settings() is get_settings()


def test_settings_nvd_defaults(monkeypatch):
    monkeypatch.delenv("SAIR_NVD_API_KEY", raising=False)
    s = Settings()
    assert s.nvd_api_key is None
    assert s.nvd_cache_dir == Path("data/nvd-cache")
    assert s.nvd_fetch_timeout == 30.0


def test_settings_nvd_api_key_from_env(monkeypatch):
    monkeypatch.setenv("SAIR_NVD_API_KEY", "env-key")
    assert Settings().nvd_api_key == "env-key"
