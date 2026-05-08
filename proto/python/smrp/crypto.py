"""Cryptographic primitives for SMRP — X25519, ChaCha20-Poly1305, HKDF-SHA-256, Ed25519."""
from __future__ import annotations

# Phase 2: implementations will use pynacl and cryptography.
# Stubs only — all functions raise NotImplementedError.


def generate_ephemeral_keypair() -> tuple[bytes, bytes]:
    """Return *(private_key_bytes, public_key_bytes)* for X25519."""
    raise NotImplementedError


def x25519_shared_secret(private_key: bytes, peer_public_key: bytes) -> bytes:
    """Perform an X25519 Diffie-Hellman operation."""
    raise NotImplementedError


def hkdf_sha256(
    ikm: bytes,
    length: int,
    salt: bytes | None = None,
    info: bytes = b"",
) -> bytes:
    """Derive *length* bytes via HKDF-SHA-256."""
    raise NotImplementedError


def chacha20_poly1305_seal(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes = b"",
) -> bytes:
    """Encrypt and authenticate *plaintext*; return ciphertext + 16-byte tag."""
    raise NotImplementedError


def chacha20_poly1305_open(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    aad: bytes = b"",
) -> bytes:
    """Decrypt and verify *ciphertext*; raise ValueError on tag mismatch."""
    raise NotImplementedError


def ed25519_generate_keypair() -> tuple[bytes, bytes]:
    """Return *(signing_key_bytes, verify_key_bytes)* for Ed25519."""
    raise NotImplementedError


def ed25519_sign(signing_key: bytes, message: bytes) -> bytes:
    """Return a 64-byte Ed25519 signature over *message*."""
    raise NotImplementedError


def ed25519_verify(verify_key: bytes, message: bytes, signature: bytes) -> None:
    """Verify an Ed25519 *signature*; raise ValueError on failure."""
    raise NotImplementedError
