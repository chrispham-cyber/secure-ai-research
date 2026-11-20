"""Ollama text-generation adapter (Phase 5, Slice 1a, Task 2).

A real local LLM behind the ``Generator`` seam: it POSTs the prompt + retrieved passages to a
local Ollama server (``/api/generate``, ``stream=false``, ``temperature=0``) and returns the
completion. No new runtime dependency — transport is stdlib ``urllib.request`` against a
keyless localhost service.

Fail-closed: transport failure, a non-2xx status, an undecodable body, or an empty/whitespace
completion all raise ``GeneratorError``. ``ResearchService`` maps that to ``FETCH_ERROR`` with
one audit record, so a model outage never degrades into a silently-empty answer (design §10 Q1).

The HTTP call is isolated behind the ``_post`` seam (body bytes -> response bytes) so the unit
tests run without a live server; the real transport runs only under ``-m integration``. This
adapter builds a request prompt from untrusted passage text — it does not claim immunity to
instructions embedded in that text (that is Slice 1b / Phase 4's concern); the downstream
``build_report`` citation + faithfulness filters remain the control on what reaches the user.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence

from secure_ai_research.generation.ports import GeneratorError

_PROMPT_TEMPLATE_VERSION = "v1"

_INSTRUCTIONS = (
    "You are a security research assistant. Using ONLY the numbered passages below, answer the "
    "question as one claim per line. End each line with the [DOC-ID] exactly as it appears in "
    "the passage that supports it. Cite only these passages. Do not add any preamble, heading, "
    "or closing remark."
)


class OllamaGenerator:
    """Generates grounded text from a local Ollama model, fail-closed on any fault."""

    model_id = "ollama"
    prompt_template_version = _PROMPT_TEMPLATE_VERSION

    def __init__(
        self,
        model: str,
        host: str = "http://localhost:11434",
        *,
        timeout: float = 60.0,
        _post: Callable[[bytes], bytes] | None = None,
    ) -> None:
        self._model = model
        self.model_version = model
        self._url = host.rstrip("/") + "/api/generate"
        self._timeout = timeout
        self._post = _post if _post is not None else self._http_post

    def generate(self, prompt: str, passages: Sequence[str]) -> str:
        body = json.dumps(
            {
                "model": self._model,
                "prompt": self._build_prompt(prompt, passages),
                "stream": False,
                "options": {"temperature": 0},
            }
        ).encode("utf-8")

        try:
            raw = self._post(body)
        except GeneratorError:
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise GeneratorError(f"ollama request failed ({type(exc).__name__})") from exc

        try:
            text = json.loads(raw)["response"]
        except (ValueError, KeyError, TypeError) as exc:
            raise GeneratorError(f"ollama response undecodable ({type(exc).__name__})") from exc

        if not isinstance(text, str) or not text.strip():
            raise GeneratorError("ollama returned an empty response")
        return text

    def _build_prompt(self, question: str, passages: Sequence[str]) -> str:
        numbered = "\n".join(f"{i}. {p}" for i, p in enumerate(passages, start=1))
        return f"{_INSTRUCTIONS}\n\nPassages:\n{numbered}\n\nQuestion: {question}"

    def _http_post(self, body: bytes) -> bytes:
        req = urllib.request.Request(
            self._url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310 (localhost)
            return resp.read()
