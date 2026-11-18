#!/usr/bin/env bash
# Bootstrap a local dev environment for the Secure AI Research Platform.
# PUBLIC / synthetic data only.
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e '.[dev]'
.venv/bin/pre-commit install

if [ ! -f .env ]; then
  cp env.example .env
  echo "Created .env from env.example (edit it before starting the stack)."
fi

echo "Bootstrap complete. Activate the venv with: source .venv/bin/activate"
