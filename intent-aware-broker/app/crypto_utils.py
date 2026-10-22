
import os
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def get_encryption_key() -> bytes:
    """Load the 256-bit encryption key from the environment."""
    encoded_key = os.getenv("BROKER_ENCRYPTION_KEY")

    if not encoded_key:
        raise RuntimeError(
            "BROKER_ENCRYPTION_KEY is missing from the environment."
        )

    try:
        key = base64.urlsafe_b64decode(encoded_key)
    except Exception as exc:
        raise RuntimeError("Invalid encryption key encoding.") from exc

    if len(key) != 32:
        raise RuntimeError("Encryption key must be 32 bytes (256 bits).")

    return key


def encrypt_text(plaintext: str) -> str:
    """Encrypt text using AES-256-GCM."""
    if not isinstance(plaintext, str):
        raise TypeError("Plaintext must be a string.")

    key = get_encryption_key()
    aesgcm = AESGCM(key)

    # AES-GCM requires a unique nonce for every encryption with a key.
    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext.encode("utf-8"),
        None,
    )

    # Store the nonce with the ciphertext; the nonce is not secret.
    combined = nonce + ciphertext

    return base64.urlsafe_b64encode(combined).decode("utf-8")


def decrypt_text(encrypted_text: str) -> str:
    """Decrypt text and verify its authentication tag."""
    key = get_encryption_key()
    aesgcm = AESGCM(key)

    combined = base64.urlsafe_b64decode(encrypted_text)

    if len(combined) < 12 + 16:
        raise ValueError("Invalid encrypted data.")

    nonce = combined[:12]
    ciphertext = combined[12:]

    # Authentication fails if the ciphertext was altered or the wrong key
    # was used. Do not bypass this error.
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext.decode("utf-8")
