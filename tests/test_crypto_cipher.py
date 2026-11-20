"""At-rest Cipher seam (Phase 5, Slice 5, Task 2): NullCipher default, opt-in FernetCipher."""

from __future__ import annotations

import importlib
import sys

import pytest

from secure_ai_research.config import Settings
from secure_ai_research.crypto.factory import make_cipher
from secure_ai_research.crypto.fernet import FernetCipher
from secure_ai_research.crypto.null import NullCipher
from secure_ai_research.crypto.ports import CipherError
from secure_ai_research.secret.factory import make_secret_provider


def test_null_cipher_is_identity():
    c = NullCipher()
    assert c.decrypt(c.encrypt(b"audit line")) == b"audit line"


def test_make_cipher_default_is_null():
    assert isinstance(make_cipher(Settings(), make_secret_provider(Settings())), NullCipher)


def test_fernet_bad_key_or_missing_extra_raises_cipher_error():
    # Missing [crypto] extra -> extra error; present -> invalid-key error. Both CipherError.
    with pytest.raises(CipherError):
        FernetCipher("not-a-valid-fernet-key")


def test_fernet_error_message_has_no_key():
    try:
        FernetCipher("not-a-valid-fernet-key-SECRET123")
    except CipherError as exc:
        assert "SECRET123" not in str(exc)
    else:
        pytest.fail("expected CipherError")


def test_cryptography_not_imported_on_default_path():
    importlib.import_module("secure_ai_research.crypto.factory")
    make_cipher(Settings(), make_secret_provider(Settings()))
    assert "cryptography" not in sys.modules


@pytest.mark.integration
def test_fernet_round_trip():
    pytest.importorskip("cryptography")
    from cryptography.fernet import Fernet

    c = FernetCipher(Fernet.generate_key().decode())
    assert c.decrypt(c.encrypt(b"secret audit line")) == b"secret audit line"
