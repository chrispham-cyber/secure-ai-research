"""Secret-management seam (Phase 5, Slice 5).

A ``SecretProvider`` centralizes where secrets come from (env by default, opt-in file), and
``verify_secrets`` is a prod-only fail-closed gate that refuses placeholder/weak secrets at
startup. Named ``secret`` (singular) to avoid shadowing the stdlib ``secrets`` module.
"""
