"""Hermetic guards for the OIDC provider (Phase 5, Slice 4, Task 3).

Mirror the minio/pgvector adapter guards, and hold whether or not the ``[oidc]`` extra is
installed (the integration run installs it in the same venv):

1. importing the oidc module must NOT import ``jwt`` (the lazy import lives inside ``identify``);
2. exercising it without the extra fails closed with :class:`IdentityUnavailable` naming the extra
   — never a bare ``ImportError`` and never an unhandled 500.

Real RS256/JWKS decode is proven only by the live Keycloak integration test (Task 7).
"""

from __future__ import annotations

import builtins
import importlib
import sys

import pytest

from secure_ai_research.identity.oidc import OidcIdentityProvider
from secure_ai_research.identity.ports import IdentityUnavailable


def test_importing_oidc_module_does_not_import_jwt():
    # If another test in this process already imported jwt, this can't be observed here — the
    # missing-extra test below enforces the real invariant (the import lives inside identify).
    if "jwt" in sys.modules:
        pytest.skip("jwt already loaded by another test in this process")
    sys.modules.pop("secure_ai_research.identity.oidc", None)
    importlib.import_module("secure_ai_research.identity.oidc")
    assert "jwt" not in sys.modules


def test_missing_extra_raises_identity_unavailable(monkeypatch):
    # Force ImportError for jwt regardless of whether it is installed, proving the provider fails
    # closed (IdentityUnavailable → 503) with a remediation message, not a bare ImportError.
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "jwt" or name.startswith("jwt."):
            raise ImportError("No module named 'jwt'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    provider = OidcIdentityProvider("iss", "http://localhost:8080/jwks", "sair-api")
    with pytest.raises(IdentityUnavailable) as exc:
        provider.identify(authorization="Bearer x.y.z", x_role="")
    assert "oidc" in str(exc.value).lower()  # names the extra to install
