# Dev container for the Secure AI Research Platform.
# PUBLIC / synthetic data only.
FROM mcr.microsoft.com/devcontainers/python:3.12

# System packages useful for local dev: shellcheck lints the shell scripts, make
# runs the developer tasks.
RUN apt-get update \
    && apt-get install -y --no-install-recommends shellcheck make \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies are installed at container-create time via postCreateCommand
# (pip install -e '.[dev]'), so they track pyproject.toml without an image rebuild.
