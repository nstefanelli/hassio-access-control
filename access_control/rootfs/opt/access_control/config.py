from __future__ import annotations

import hashlib
import os
import secrets

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


SECRET_KEY_SOURCE_DATABASE = "database"
SECRET_KEY_SOURCE_ENVIRONMENT = "environment"
_SECRET_FINGERPRINT_PREFIX = "pbkdf2_sha256"
_SECRET_FINGERPRINT_ITERATIONS = 480_000


def secret_key_fingerprint(secret_key: str) -> str:
    """Return a slow, salted verifier used to detect key mismatches.

    A raw SHA-256 digest would let someone holding only SQLite test weak
    environment-key guesses at hashing speed.  This verifier deliberately costs
    the same order of work as deriving the application's Fernet key.
    """
    salt = os.urandom(16)
    verifier = hashlib.pbkdf2_hmac(
        "sha256",
        secret_key.encode(),
        salt,
        iterations=_SECRET_FINGERPRINT_ITERATIONS,
    )
    return (
        f"{_SECRET_FINGERPRINT_PREFIX}$"
        f"{_SECRET_FINGERPRINT_ITERATIONS}$"
        f"{salt.hex()}${verifier.hex()}"
    )


def _matches_secret_key_fingerprint(secret_key: str, stored: str) -> bool:
    """Verify current fingerprints and the legacy raw-SHA format."""
    try:
        algorithm, iterations_raw, salt_hex, verifier_hex = stored.split("$", 3)
    except ValueError:
        # Backward compatibility only. Runtime initialization replaces this
        # legacy fast verifier after the supplied key has matched once.
        legacy = hashlib.sha256(secret_key.encode()).hexdigest()
        return secrets.compare_digest(legacy, stored)
    if algorithm != _SECRET_FINGERPRINT_PREFIX:
        return False
    try:
        iterations = int(iterations_raw)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(verifier_hex)
    except (ValueError, TypeError):
        return False
    if iterations != _SECRET_FINGERPRINT_ITERATIONS or len(salt) != 16:
        return False
    actual = hashlib.pbkdf2_hmac(
        "sha256",
        secret_key.encode(),
        salt,
        iterations=iterations,
    )
    return secrets.compare_digest(actual, expected)


def resolve_secret_key(
    *,
    stored_key: str | None,
    source: str | None,
    stored_fingerprint: str | None,
    environment_key: str | None,
) -> tuple[str, str]:
    """Resolve the configured encryption/session key without changing modes.

    The key source is selected once, during first-run setup.  An environment
    variable added later must not silently replace the database key: doing so
    makes every encrypted credential unreadable.  Databases created before the
    source marker existed are treated as database-key installations.

    Returns ``(secret_key, normalized_source)`` and raises ``RuntimeError`` for
    a missing/mismatched environment key or corrupt source metadata.
    """
    normalized = source or SECRET_KEY_SOURCE_DATABASE
    if normalized == SECRET_KEY_SOURCE_DATABASE:
        if not stored_key:
            raise RuntimeError(
                "Database-managed secret key is missing; restore access_control.db "
                "from backup."
            )
        return stored_key, normalized

    if normalized == SECRET_KEY_SOURCE_ENVIRONMENT:
        if not environment_key:
            raise RuntimeError(
                "ACCESS_CONTROL_SECRET_KEY is required because this installation "
                "was initialized in environment-key mode."
            )
        if not stored_fingerprint:
            raise RuntimeError(
                "Environment-key fingerprint is missing from the database; restore "
                "a consistent database/key backup."
            )
        if not _matches_secret_key_fingerprint(
            environment_key, stored_fingerprint
        ):
            raise RuntimeError(
                "ACCESS_CONTROL_SECRET_KEY does not match the key used during "
                "first-run setup."
            )
        return environment_key, normalized

    raise RuntimeError(f"Unsupported secret_key_source: {normalized!r}")


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from a password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def encrypt_value(value: str, key: bytes) -> str:
    """Encrypt a string value using Fernet symmetric encryption."""
    f = Fernet(key)
    return f.encrypt(value.encode()).decode()


def decrypt_value(encrypted: str, key: bytes) -> str:
    """Decrypt a Fernet-encrypted string value."""
    f = Fernet(key)
    return f.decrypt(encrypted.encode()).decode()


def hash_password(password: str) -> str:
    """Hash a password with a random salt using PBKDF2-SHA256.

    Returns a string in the format "salt_hex:hash_hex".
    """
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        iterations=480000,
    )
    return f"{salt.hex()}:{key.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Verify a password against a stored "salt_hex:hash_hex" string."""
    try:
        salt_hex, hash_hex = stored.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, AttributeError):
        return False

    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        iterations=480000,
    )
    return secrets.compare_digest(key, expected)


def generate_api_key() -> str:
    """Generate a cryptographically secure random API key."""
    return secrets.token_urlsafe(32)


def hash_api_key(key: str) -> str:
    """Return the SHA-256 hex digest of an API key for storage."""
    return hashlib.sha256(key.encode()).hexdigest()
