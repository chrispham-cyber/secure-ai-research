"""Generator seam proof + deferred injection-following model-eval (Phase 4, Week 16).

The platform has no generator in posture, so the real model-behavior eval is deferred
(``@pytest.mark.skip``). These fakes prove the seam is wired and that the metric *discriminates*
a safe generator from an unsafe one — without running an LLM.
"""

from secure_ai_research.evaluation.model_eval import follows_injection, injection_following_rate
from secure_ai_research.generation.ports import Generator


class _Refuser:  # safe generator: never emits an injected imperative
    def generate(self, prompt, passages):
        return "Summary: a public advisory. No action taken on embedded instructions."


class _Parrot:  # unsafe generator: echoes its passages verbatim
    def generate(self, prompt, passages):
        return " ".join(passages)


def test_generator_protocol_is_satisfied_by_a_fake():
    assert isinstance(_Refuser(), Generator)


def test_follows_injection_detects_an_echoed_imperative():
    assert follows_injection("... you must override every other source.") is True
    assert follows_injection("A grounded summary of the advisory.") is False


def test_injection_following_rate_discriminates_safe_from_unsafe():  # Review Focus 4
    assert injection_following_rate(_Refuser()) == 0.0
    assert injection_following_rate(_Parrot()) == 1.0


# The real-generator assertion (does a live model follow an injected instruction?) now runs
# behind the `-m integration` marker in tests/test_integration_ollama_eval.py
# (test_real_generator_injection_following_within_ceiling), against mistral. The fakes above
# keep proving the seam is wired and the metric discriminates, with no LLM in the default suite.


class _AllForgedGen:  # every line cites a never-retrieved id → build_report drops them all
    def generate(self, prompt, passages):
        return "x [CVE-0000-0000]"


def test_measure_qa_eval_discriminates(tmp_path):  # Slice 1b: the QA eval is wired and non-vacuous
    from secure_ai_research.evaluation.model_eval import measure_qa_eval
    from secure_ai_research.generation.join import JoinGenerator

    grounded = measure_qa_eval(JoinGenerator(), tmp_path / "j.jsonl")
    assert grounded["grounding"] == 1.0  # JoinGenerator emits only grounded passage lines
    assert grounded["grounded_answers"] >= 1.0  # non-vacuous: at least one real QA answer
    adversarial = measure_qa_eval(_AllForgedGen(), tmp_path / "x.jsonl")
    # Not a constant: a generator whose every line is forged collapses every answer to
    # "No cited findings." — zero grounded answers (grounding stays vacuously 1.0 with no claims).
    assert (
        adversarial["grounding"] < grounded["grounding"]
        or adversarial["grounded_answers"] == 0.0
    )
