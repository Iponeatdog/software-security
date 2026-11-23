
"""
Week 3 — Secure cryptography examples.
Uses Argon2id for password hashing, AES-GCM for encryption,
environment-based key management, and cryptographically secure tokens.
"""

import os
import secrets

from argon2 import PasswordHasher
from Crypto.Cipher import AES  # pip install pycryptodome


# Secure password hashing using Argon2id
password_hasher = PasswordHasher()


def store_password(pw: str) -> str:
    """Hash a password securely using Argon2id with a unique salt."""
    return password_hasher.hash(pw)


def verify_password(pw: str, stored_hash: str) -> bool:
    """Verify a password against its stored Argon2id hash."""
    try:
        return password_hasher.verify(stored_hash, pw)
    except Exception:
        return False


# Load the AES-256 key from an environment variable.
# Generate one with: python -c "import secrets; print(secrets.token_hex(32))"
def get_encryption_key() -> bytes:
    key_hex = os.environ.get("AES_KEY")

    if not key_hex:
        raise ValueError("AES_KEY environment variable is not set.")

    try:
        key = bytes.fromhex(key_hex)
    except ValueError as exc:
        raise ValueError("AES_KEY must be valid hexadecimal.") from exc

    if len(key) != 32:
        raise ValueError("AES_KEY must contain exactly 32 bytes (64 hex characters).")

    return key


# Secure encryption using AES-GCM (authenticated encryption)
def encrypt(data: bytes) -> tuple[bytes, bytes, bytes]:
    """Return nonce, ciphertext, and authentication tag."""
    key = get_encryption_key()
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    return cipher.nonce, ciphertext, tag


def decrypt(nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """Decrypt and authenticate data using AES-GCM."""
    key = get_encryption_key()
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    return cipher.decrypt_and_verify(ciphertext, tag)


# Secure password-reset token using a cryptographically secure generator
def reset_token() -> str:
    return secrets.token_urlsafe(32)


if __name__ == "__main__":
    # Password hashing and verification
    stored_hash = store_password("password123")
    print("Argon2id hash:", stored_hash)
    print("Password verified:", verify_password("password123", stored_hash))

    # AES-GCM encryption and decryption
    nonce, ciphertext, tag = encrypt(b"Secret message")
    print("Ciphertext:", ciphertext.hex())
    print("Decrypted:", decrypt(nonce, ciphertext, tag).decode())

    # Secure reset token
    print("Reset token:", reset_token())
