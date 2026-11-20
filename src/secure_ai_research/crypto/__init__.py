"""At-rest encryption seam (Phase 5, Slice 5).

A ``Cipher`` wraps bytes at rest. The default ``NullCipher`` is identity (plaintext-signed audit
lines, byte-identical to the unencrypted format); the opt-in ``FernetCipher`` encrypts them and
lazily imports ``cryptography`` (the ``crypto`` extra), so the hermetic default never loads it.
"""
