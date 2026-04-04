"""
Fernet-based field encryption helpers.

Usage:
    from pentools.crypto import fernet_encrypt, fernet_decrypt
    from pentools.crypto import encrypt_sensitive_params, decrypt_sensitive_params

The key is loaded from settings.FIELD_ENCRYPTION_KEY (a Fernet key string).
If the key is absent, all helpers are no-ops so the system degrades gracefully.
"""
from __future__ import annotations

import logging
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings

logger = logging.getLogger(__name__)


def _fernet() -> Fernet | None:
    key = getattr(settings, "FIELD_ENCRYPTION_KEY", "") or ""
    if not key:
        return None
    try:
        raw = key.encode() if isinstance(key, str) else key
        return Fernet(raw)
    except Exception as exc:
        logger.error("FIELD_ENCRYPTION_KEY is invalid — encryption disabled: %s", exc)
        return None


def fernet_encrypt(plaintext: str) -> str:
    """Return the Fernet-encrypted form of *plaintext*.

    Returns *plaintext* unchanged if no key is configured or if the value is
    already encrypted (starts with the Fernet token prefix ``gAAAAA``).
    """
    if not plaintext:
        return plaintext
    # Idempotency guard: already looks like a Fernet token
    if plaintext.startswith("gAAAAA"):
        return plaintext
    f = _fernet()
    if not f:
        return plaintext
    return f.encrypt(plaintext.encode()).decode()


def fernet_decrypt(ciphertext: str) -> str:
    """Return the plaintext for a Fernet-encrypted *ciphertext*.

    Falls back to returning *ciphertext* unchanged when:
    - No key is configured.
    - The value is not a valid Fernet token (e.g. pre-migration plaintext row).
    """
    if not ciphertext:
        return ciphertext
    f = _fernet()
    if not f:
        return ciphertext
    try:
        return f.decrypt(ciphertext.encode()).decode()
    except (InvalidToken, Exception):
        # Pre-migration plaintext value — return as-is
        return ciphertext


# ── Param-dict encrypt/decrypt ─────────────────────────────────────────────

def encrypt_sensitive_params(params: dict, module) -> dict:
    """Return a copy of *params* with ``sensitive=True`` values Fernet-encrypted."""
    f = _fernet()
    if not f:
        return params
    result = dict(params)
    sensitive_keys = _sensitive_keys(module)
    for key in sensitive_keys:
        v = result.get(key)
        if v and isinstance(v, str):
            result[key] = fernet_encrypt(v)
    return result


def decrypt_sensitive_params(params: dict, module) -> dict:
    """Return a copy of *params* with ``sensitive=True`` values decrypted to plaintext."""
    f = _fernet()
    if not f:
        return params
    result = dict(params)
    sensitive_keys = _sensitive_keys(module)
    for key in sensitive_keys:
        v = result.get(key)
        if v and isinstance(v, str):
            result[key] = fernet_decrypt(v)
    return result


def _sensitive_keys(module) -> set[str]:
    schema = getattr(module, "PARAMETER_SCHEMA", None) or []
    return {field.key for field in schema if getattr(field, "sensitive", False)}
