"""OllamaGenerator — real local-LLM adapter, exercised hermetically (Phase 5, Slice 1a, Task 2).

Every test here injects ``_post`` (the HTTP seam), so no live Ollama is contacted; the real
transport runs only under ``-m integration`` (Task 5). The adapter is fail-closed: transport
failure, a non-2xx response, an undecodable body, or an empty/whitespace completion all raise
``GeneratorError`` — never a silent ``""`` that would degrade to "No cited findings" (RF1).
"""

from __future__ import annotations

import json
import urllib.error

import pytest

from secure_ai_research.generation.ollama import OllamaGenerator
from secure_ai_research.generation.ports import Generator, GeneratorError


def _ok(body: bytes) -> bytes:
    return b'{"response": "a grounded line [CVE-2021-44228]"}'


def test_satisfies_generator_protocol():
    assert isinstance(OllamaGenerator("mistral:latest", _post=_ok), Generator)


def test_identity_attrs():
    gen = OllamaGenerator("mistral:latest", _post=_ok)
    assert gen.model_id == "ollama"
    assert gen.model_version == "mistral:latest"
    assert gen.prompt_template_version


def test_generate_returns_response_text():
    gen = OllamaGenerator("mistral:latest", _post=_ok)
    out = gen.generate("explain CVE-2021-44228", ["Log4j issue [CVE-2021-44228]"])
    assert out == "a grounded line [CVE-2021-44228]"


def test_request_sets_temperature_zero_and_model():
    captured: dict[str, bytes] = {}

    def fake(body: bytes) -> bytes:
        captured["body"] = body
        return b'{"response": "ok [CVE-1]"}'

    gen = OllamaGenerator("mistral:latest", _post=fake)
    gen.generate("explain CVE-1", ["CVE-1 is a synthetic flaw [CVE-1]"])
    payload = json.loads(captured["body"])
    assert payload["model"] == "mistral:latest"
    assert payload["options"]["temperature"] == 0
    assert payload["stream"] is False
    assert "CVE-1 is a synthetic flaw [CVE-1]" in payload["prompt"]
    assert "explain CVE-1" in payload["prompt"]


def test_empty_response_raises():  # RF1
    gen = OllamaGenerator("mistral:latest", _post=lambda b: b'{"response": "   "}')
    with pytest.raises(GeneratorError):
        gen.generate("q", ["p [CVE-1]"])


def test_missing_response_key_raises():
    gen = OllamaGenerator("mistral:latest", _post=lambda b: b'{"done": true}')
    with pytest.raises(GeneratorError):
        gen.generate("q", ["p [CVE-1]"])


def test_undecodable_body_raises():
    gen = OllamaGenerator("mistral:latest", _post=lambda b: b"not json at all")
    with pytest.raises(GeneratorError):
        gen.generate("q", ["p [CVE-1]"])


def test_transport_failure_raises():
    def boom(body: bytes) -> bytes:
        raise urllib.error.URLError("connection refused")

    gen = OllamaGenerator("mistral:latest", _post=boom)
    with pytest.raises(GeneratorError):
        gen.generate("q", ["p [CVE-1]"])
