#!/usr/bin/env bash
# Verify a model file against the approved-model registry.
# Passes all arguments through to the model-integrity verifier CLI.
# PUBLIC / synthetic data only.
#
# Example:
#   ./scripts/hash-model.sh --registry infrastructure/model-runtime/model-registry.json \
#       --model-path path/to/model.safetensors --id example/local-llm
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

exec .venv/bin/python -m secure_ai_research.ai_security.model_integrity.verify_model "$@"
