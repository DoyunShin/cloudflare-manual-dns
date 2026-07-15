"""Symmetric encryption and scoped-token generation/parsing helpers."""

import hashlib
import secrets
from hmac import compare_digest

from cryptography.fernet import Fernet

from cfproxy.config import get_settings

_TOKEN_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_LOOKUP_ID_LEN = 16
_SECRET_LEN = 40


def _generate_random_string(length: int) -> str:
    """Generate a random string using the token alphabet.

    Args:
        length(int): Number of characters to generate.

    Return:
        value(str): Random string composed of `[A-Za-z0-9]` characters.
    """
    return "".join(secrets.choice(_TOKEN_ALPHABET) for _ in range(length))


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a plaintext string using the configured Fernet key.

    Args:
        plaintext(str): The value to encrypt.

    Return:
        ciphertext(str): The Fernet-encrypted token as a string.
    """
    fernet = Fernet(get_settings().proxy_secret_key.encode())
    return fernet.encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    """Decrypt a ciphertext string produced by `encrypt_secret`.

    Args:
        ciphertext(str): The Fernet-encrypted token as a string.

    Return:
        plaintext(str): The decrypted original value.
    """
    fernet = Fernet(get_settings().proxy_secret_key.encode())
    return fernet.decrypt(ciphertext.encode()).decode()


def hash_token(full: str) -> str:
    """Compute the SHA-256 hex digest of a scoped token string.

    Args:
        full(str): The full scoped token string.

    Return:
        digest(str): Hex-encoded SHA-256 digest.
    """
    return hashlib.sha256(full.encode()).hexdigest()


def verify_token(full: str, token_hash: str) -> bool:
    """Verify a scoped token string against a stored hash in constant time.

    Args:
        full(str): The full scoped token string presented by the caller.
        token_hash(str): The stored SHA-256 hex digest to compare against.

    Return:
        is_valid(bool): True if the token matches the stored hash.
    """
    return compare_digest(hash_token(full), token_hash)


def generate_scoped_token() -> dict:
    """Generate a new scoped token and its derived fields.

    Return:
        token(dict): Dict with keys "lookup_id", "secret", "full", "token_hash",
            "token_prefix".
    """
    brand = get_settings().token_brand
    lookup_id = _generate_random_string(_LOOKUP_ID_LEN)
    secret = _generate_random_string(_SECRET_LEN)
    full = f"{brand}_{lookup_id}_{secret}"
    return {
        "lookup_id": lookup_id,
        "secret": secret,
        "full": full,
        "token_hash": hash_token(full),
        "token_prefix": f"{brand}_{lookup_id[:6]}",
    }


def parse_scoped_token(full: str) -> tuple[str, str] | None:
    """Parse a scoped token string into its lookup id and secret components.

    Args:
        full(str): The full scoped token string.

    Return:
        parsed(tuple[str, str] | None): `(lookup_id, secret)` or None if malformed.
    """
    parts = full.split("_")
    if len(parts) != 3:
        return None
    _, lookup_id, secret = parts
    if len(lookup_id) != _LOOKUP_ID_LEN or len(secret) != _SECRET_LEN:
        return None
    if not lookup_id.isalnum() or not secret.isalnum():
        return None
    return lookup_id, secret
