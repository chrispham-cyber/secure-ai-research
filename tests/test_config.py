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
