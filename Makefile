# Secure AI Research Platform — developer tasks.
# PUBLIC / synthetic data only.  Run `make help` for the list of targets.
.DEFAULT_GOAL := help

PY ?= .venv/bin/python
COMPOSE ?= docker compose
EMBEDDING_MODEL ?= nomic-embed-text
ARGS ?=
COSIGN_KEY ?= cosign.key

.PHONY: help up down logs test lint fmt typecheck sbom sbom-release sbom-sign sbom-verify pull-model new-record hash-model

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-13s\033[0m %s\n", $$1, $$2}'

up: ## Start the local stack (db, minio, ollama, app)
	$(COMPOSE) up -d

down: ## Stop the stack and remove its containers
	$(COMPOSE) down

logs: ## Tail stack logs
	$(COMPOSE) logs -f

test: ## Run unit tests (skips integration)
	$(PY) -m pytest -m "not integration"

lint: ## Lint with ruff
	$(PY) -m ruff check .

fmt: ## Format with black, then ruff --fix
	$(PY) -m black .
	$(PY) -m ruff check --fix .

typecheck: ## Type-check with mypy
	$(PY) -m mypy src

sbom: ## Generate a CycloneDX SBOM of the current environment (sbom.json, dev convenience)
	./scripts/gen-sbom.sh

sbom-release: ## Generate the reproducible release SBOM + rewrite the integrity manifest (sbom/)
	./.venv/bin/python -m secure_ai_research.supply_chain.sbom

sbom-sign: ## Sign the release SBOM bytes with cosign (needs cosign + COSIGN_KEY, COSIGN_PASSWORD)
	COSIGN_KEY=$(COSIGN_KEY) ./.venv/bin/python -m secure_ai_research.supply_chain.signing

sbom-verify: ## Verify the committed release SBOM signature (needs cosign; uses sbom/cosign.pub)
	./.venv/bin/python -c "from pathlib import Path; from secure_ai_research.supply_chain.signing import verify_release_sbom; verify_release_sbom(Path.cwd())"

pull-model: ## Pull the embedding model into the ollama service
	$(COMPOSE) exec ollama ollama pull $(EMBEDDING_MODEL)

new-record: ## Print a blank research-record template (JSON)
	$(PY) scripts/new_research_record.py

hash-model: ## Verify a model file: make hash-model ARGS="--registry R --model-path M --id ID"
	./scripts/hash-model.sh $(ARGS)
