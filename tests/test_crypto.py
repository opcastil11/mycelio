"""Ed25519 sign/verify tests for the frame-chain signing model."""
from __future__ import annotations

import pytest

from mycelio.crypto import (
    SignatureError,
    generate_keypair,
    public_from_private,
    sign_chain,
    verify_chain,
)
from mycelio.frame import Frame
from mycelio.verbs import Verb


def _make_chain() -> list[Frame]:
    return [
        Frame(verb=Verb.DISCOVER, stream_id=3, payload=b"\x01\x05"),
        Frame(verb=Verb.DISCOVER, stream_id=3, payload=b"\xff\xff"),
    ]


def test_keypair_generation_returns_32_byte_seed_and_pubkey():
    seed, pub = generate_keypair()
    assert len(seed) == 32
    assert len(pub) == 32


def test_public_derives_consistently_from_seed():
    seed, pub = generate_keypair()
    assert public_from_private(seed) == pub


def test_sign_verify_round_trip():
    seed, pub = generate_keypair()
    chain = _make_chain()
    sig = sign_chain(seed, chain)
    assert len(sig) == 64
    assert verify_chain(pub, chain, sig)


def test_verify_rejects_tampered_payload():
    seed, pub = generate_keypair()
    chain = _make_chain()
    sig = sign_chain(seed, chain)
    # Mutate the last frame's payload — verification must fail.
    tampered = chain[:-1] + [Frame(verb=Verb.DISCOVER, stream_id=3, payload=b"\xff\x00")]
    assert verify_chain(pub, tampered, sig) is False


def test_verify_rejects_wrong_pubkey():
    seed, _ = generate_keypair()
    _, other_pub = generate_keypair()
    chain = _make_chain()
    sig = sign_chain(seed, chain)
    assert verify_chain(other_pub, chain, sig) is False


def test_verify_rejects_wrong_size_signature():
    _, pub = generate_keypair()
    assert verify_chain(pub, _make_chain(), b"x" * 63) is False
    assert verify_chain(pub, _make_chain(), b"x" * 65) is False


def test_verify_rejects_empty_chain():
    _, pub = generate_keypair()
    assert verify_chain(pub, [], b"x" * 64) is False


def test_sign_rejects_empty_chain():
    seed, _ = generate_keypair()
    with pytest.raises(SignatureError, match="empty"):
        sign_chain(seed, [])


def test_sign_rejects_bad_seed_length():
    with pytest.raises(SignatureError, match="32 bytes"):
        sign_chain(b"\x01" * 16, _make_chain())
