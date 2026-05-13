"""Ed25519 signing helpers for Mycelio v0.

The directory's **root key** signs every server-side response chain.
Peers in the mycelium can relay these signed responses but cannot forge
new ones — this is what makes the network safe.

A response signature covers `sha256(frame_1 || frame_2 || ... || frame_N)`
where each `frame_i` is the fully encoded frame including its 14-byte
header. The signature is then emitted as a final `SIG` frame on the
same stream.
"""
from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from mycelio.frame import Frame, encode_frame


class SignatureError(Exception):
    """Raised when a signature fails to verify or a key is malformed."""


# ---------------------------------------------------------------------------
# Keypair helpers
# ---------------------------------------------------------------------------


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh Ed25519 keypair.

    Returns (private_seed_32_bytes, public_key_32_bytes). Persist the
    seed somewhere safe — it's all you need to reconstruct the signing
    key.
    """
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    pub = priv.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    return seed, pub


def public_from_private(seed: bytes) -> bytes:
    """Derive the 32-byte public key from a 32-byte private seed."""
    if len(seed) != 32:
        raise SignatureError(f"private seed must be 32 bytes, got {len(seed)}")
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    return priv.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )


# ---------------------------------------------------------------------------
# Sign / verify a frame chain
# ---------------------------------------------------------------------------


def hash_frame_chain(frames: list[Frame]) -> bytes:
    """SHA-256 over the concatenation of fully-encoded frames in order.

    This is the digest that gets signed. Order matters; canonical map
    encoding (sorted field IDs) guarantees the byte stream is identical
    on both sides.
    """
    h = hashlib.sha256()
    for f in frames:
        h.update(encode_frame(f))
    return h.digest()


def sign_chain(private_seed: bytes, frames: list[Frame]) -> bytes:
    """Sign a chain of frames. Returns a 64-byte Ed25519 signature."""
    if len(private_seed) != 32:
        raise SignatureError(f"private seed must be 32 bytes, got {len(private_seed)}")
    if not frames:
        raise SignatureError("cannot sign an empty frame chain")
    priv = Ed25519PrivateKey.from_private_bytes(private_seed)
    return priv.sign(hash_frame_chain(frames))


def verify_chain(public_key: bytes, frames: list[Frame], signature: bytes) -> bool:
    """Verify a signature over a frame chain. Returns True or False (never raises)."""
    if len(public_key) != 32:
        return False
    if len(signature) != 64:
        return False
    if not frames:
        return False
    try:
        pub = Ed25519PublicKey.from_public_bytes(public_key)
        pub.verify(signature, hash_frame_chain(frames))
        return True
    except Exception:  # InvalidSignature, ValueError, etc.
        return False
