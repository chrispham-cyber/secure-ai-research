# Capstone Paper — Outline

> _Scope: PUBLIC / synthetic data only._

Structure for the Phase-6 (weeks 23–24) capstone: *Building an Evidence-Grounded AI
Research Assistant for Cybersecurity, Securely.* Each section lists what it must establish.

## Abstract
_The problem (ungrounded AI in security research), the approach (authorization-first,
evidence-grounded RAG with a local model), and the result in 150–250 words._

## 1. Introduction
_Why AI-assisted cyber research is attractive and why naive use is dangerous
(hallucination, data leakage, prompt injection). State the thesis and contributions._

## 2. Background & threat landscape
_RAG, agentic tool use, and the AI-specific threats: prompt injection, unauthorized
retrieval, model/dataset integrity, excessive agency. Reference the
[threat model](../../architecture/threat-model.md)._

## 3. System design
_The six layers, trust boundaries, and the four principles (confidentiality, integrity,
auditability, human accountability). Reference
[architecture/system-design.md](../../architecture/system-design.md)._

## 4. Security analysis
_Walk the STRIDE threats and the controls that answer them: authorize-before-retrieve,
permission-checks-outside-the-LLM, model verification, append-only audit, supply chain._

## 5. Evaluation methodology
_What is measured — grounding, citation accuracy, refusal, injection resistance,
cross-user disclosure — and the acceptance criteria. Reference
[evaluation/methodology/](../../evaluation/methodology/)._

## 6. Results
_Benchmark results and red-team outcomes, tied to exact model and prompt-template
versions. Tables/figures from [evaluation/results/](../../evaluation/results/)._

## 7. Limitations & threats to validity
_Synthetic/public-only scope, single-lane deployment, dev-auth stub, what the evaluation
does not cover._

## 8. Related work
_Prior secure-RAG, LLM-security, and threat-intelligence-automation work._

## 9. Conclusion & future work
_What was shown; the path to multi-lane, hardened deployment._

## References · Appendices
_Sources; appendices for the full benchmark, prompts, and the audit-record schema._
