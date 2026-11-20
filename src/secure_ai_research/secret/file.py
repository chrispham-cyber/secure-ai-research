"""File-backed SecretProvider: reads Docker/systemd-style per-secret files under a directory."""

from __future__ import annotations

from pathlib import Path

from secure_ai_research.secret.ports import SecretError


class FileSecretProvider:
    """Resolves a secret ``name`` from ``<directory>/<name>`` (trailing whitespace stripped)."""

    def __init__(self, directory: Path) -> None:
        self._dir = Path(directory)

    def get(self, name: str) -> str | None:
        path = self._dir / name
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        return value or None

    def require(self, name: str) -> str:
        value = self.get(name)
        if not value:
            raise SecretError(f"secret {name} is unset")
        return value
