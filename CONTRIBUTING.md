# Contributing

Thanks for your interest. This is a personal learning/research project, but it is built to
professional standards and contributions that keep it that way are welcome.

> **Before anything else:** this repo is **PUBLIC / synthetic data only**. Never commit
> controlled data, real secrets, credentials, or model weights. See [SECURITY.md](SECURITY.md).

## Development setup

```bash
./scripts/bootstrap.sh        # venv + dev deps + pre-commit hooks + .env from env.example
source .venv/bin/activate
```

## Workflow

1. **Branch** off the default branch (e.g. `feat/ingestion-nvd`, `fix/authz-scope`).
2. **Test-driven.** Write a failing test first, then the code to pass it. New behavior
   needs a test; bug fixes need a regression test.
3. **Keep it green.** Before pushing:
   ```bash
   make fmt         # black + ruff --fix
   make lint        # ruff
   make typecheck   # mypy
   make test        # pytest -m "not integration"
   ```
   `pre-commit` runs ruff, black, gitleaks, and the file guards on every commit.
4. **Open a PR** describing *what* and *why*; link the roadmap phase if relevant.

## Commit messages — Conventional Commits

```
<type>(<scope>): <summary>
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `ci`, `build`. Examples:

```
feat(ingestion): NVD loader with content-hash provenance
fix(retrieval): apply authorization before vector search
docs(architecture): clarify the audit boundary
```

## Code standards

- **Python 3.12**, typed. `mypy` runs over `src/`.
- **Format/lint:** black (line length 100) + ruff (E/F/I/UP/B). CI enforces both.
- **Stubs fail loud.** An unimplemented function raises `NotImplementedError` naming the
  roadmap phase that builds it — it never returns fake/plausible data.
- **Security rules that are not negotiable:** authorization is applied *before* retrieval;
  permission checks for agent tools live *outside* the LLM; retrieved text is treated as
  untrusted data; every AI-assisted analysis emits an audit record.

## Keep public and protected materials separate

This platform is designed to run per classification lane. Even though this repo is
PUBLIC-only, develop as if the rule were enforced:

- Never mix a higher-classification artifact into this repo or its services.
- Do not add code paths that "downgrade" a document's classification.
- `data/`, `models/`, `audit/`, and `.env*` are git-ignored — keep them that way.

## Tests that need live services

Tests requiring Postgres/MinIO/Ollama are marked `@pytest.mark.integration` and are
**skipped in CI** and by `make test`. Run them locally against `make up` with
`pytest -m integration`.
