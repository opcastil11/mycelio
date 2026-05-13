"""Tests for the vendor manifest format + dual signing."""
from __future__ import annotations

import pytest

from mycelio.crypto import generate_keypair
from mycelio.manifest import (
    BackendKind,
    Manifest,
    ManifestError,
    OpDef,
    ParamDef,
    ParamLocation,
    decode_manifest,
    derive_service_id,
    encode_manifest,
    sign_directory,
    sign_vendor,
    verify_signatures,
)


def _stripe_manifest(vendor_pub: bytes) -> Manifest:
    return Manifest(
        service_id=b"\xab\xcd\xef\x01\x02\x03\x04\x05",
        slug="stripe",
        vendor_pubkey=vendor_pub,
        backend_url="https://api.stripe.com",
        backend_kind=BackendKind.HTTP,
        auth_header="Authorization",
        auth_prefix="Bearer",
        ops=[
            OpDef(
                slug="charge",
                method="POST",
                path="/v1/charges",
                params=[
                    ParamDef(key="amount", location=ParamLocation.BODY, required=True),
                    ParamDef(key="currency", location=ParamLocation.BODY, required=True),
                    ParamDef(key="customer", location=ParamLocation.BODY, required=True),
                ],
            ),
            OpDef(
                slug="list_charges",
                method="GET",
                path="/v1/charges",
                streams_response=True,
                params=[
                    ParamDef(key="limit", location=ParamLocation.QUERY, required=False),
                ],
            ),
        ],
    )


def test_round_trip_signed_manifest():
    vendor_seed, vendor_pub = generate_keypair()
    dir_seed, dir_pub = generate_keypair()

    m = _stripe_manifest(vendor_pub)
    sign_vendor(m, vendor_seed)
    sign_directory(m, dir_seed)

    encoded = encode_manifest(m)
    decoded = decode_manifest(encoded)

    assert decoded.slug == "stripe"
    assert decoded.vendor_pubkey == vendor_pub
    assert decoded.backend_url == "https://api.stripe.com"
    assert decoded.backend_kind == BackendKind.HTTP
    assert decoded.auth_header == "Authorization"
    assert len(decoded.ops) == 2
    assert decoded.ops[0].slug == "charge"
    assert decoded.ops[1].streams_response is True
    assert len(decoded.ops[0].params) == 3
    assert decoded.vendor_signature == m.vendor_signature
    assert decoded.directory_signature == m.directory_signature


def test_verify_signatures_passes_on_valid():
    vendor_seed, vendor_pub = generate_keypair()
    dir_seed, dir_pub = generate_keypair()
    m = _stripe_manifest(vendor_pub)
    sign_vendor(m, vendor_seed)
    sign_directory(m, dir_seed)
    verify_signatures(m, directory_pubkey=dir_pub)  # raises on failure


def test_verify_signatures_rejects_tampered_backend_url():
    vendor_seed, vendor_pub = generate_keypair()
    dir_seed, dir_pub = generate_keypair()
    m = _stripe_manifest(vendor_pub)
    sign_vendor(m, vendor_seed)
    sign_directory(m, dir_seed)

    encoded = encode_manifest(m)
    tampered = decode_manifest(encoded)
    tampered.backend_url = "https://attacker.example.com"

    with pytest.raises(ManifestError, match="vendor signature is invalid"):
        verify_signatures(tampered, directory_pubkey=dir_pub)


def test_verify_signatures_rejects_wrong_directory_key():
    vendor_seed, vendor_pub = generate_keypair()
    dir_seed, _ = generate_keypair()
    _, decoy_pub = generate_keypair()
    m = _stripe_manifest(vendor_pub)
    sign_vendor(m, vendor_seed)
    sign_directory(m, dir_seed)
    with pytest.raises(ManifestError, match="directory signature is invalid"):
        verify_signatures(m, directory_pubkey=decoy_pub)


def test_verify_signatures_rejects_directory_swap():
    """Directory signature is over the vendor's exact bytes — can't be
    reattached to a different vendor's manifest."""
    vendor_seed_a, vendor_pub_a = generate_keypair()
    vendor_seed_b, vendor_pub_b = generate_keypair()
    dir_seed, dir_pub = generate_keypair()

    # Sign manifest A with directory
    m_a = _stripe_manifest(vendor_pub_a)
    sign_vendor(m_a, vendor_seed_a)
    sign_directory(m_a, dir_seed)

    # Swap A's directory signature onto B's manifest
    m_b = _stripe_manifest(vendor_pub_b)
    sign_vendor(m_b, vendor_seed_b)
    m_b.directory_signature = m_a.directory_signature  # forge

    with pytest.raises(ManifestError, match="directory signature is invalid"):
        verify_signatures(m_b, directory_pubkey=dir_pub)


def test_get_op():
    vendor_seed, vendor_pub = generate_keypair()
    m = _stripe_manifest(vendor_pub)
    assert m.get_op("charge").method == "POST"
    with pytest.raises(ManifestError, match="not found"):
        m.get_op("doesnt_exist")


def test_derive_service_id_is_8_bytes_and_deterministic():
    _, pub = generate_keypair()
    a = derive_service_id("stripe", pub)
    b = derive_service_id("stripe", pub)
    assert a == b
    assert len(a) == 8
    # Different slug → different ID
    assert derive_service_id("paypal", pub) != a
    # Different directory key → different ID
    _, other_pub = generate_keypair()
    assert derive_service_id("stripe", other_pub) != a


def test_param_out_name_falls_back_to_key():
    p = ParamDef(key="customer", location=ParamLocation.BODY)
    assert p.out_name == "customer"
    p2 = ParamDef(key="customer", location=ParamLocation.BODY, backend_name="customer_id")
    assert p2.out_name == "customer_id"


def test_encode_manifest_is_compact():
    """A 2-op manifest with both 64-byte Ed25519 sigs should fit well under 500 bytes."""
    vendor_seed, vendor_pub = generate_keypair()
    dir_seed, _ = generate_keypair()
    m = _stripe_manifest(vendor_pub)
    sign_vendor(m, vendor_seed)
    sign_directory(m, dir_seed)
    encoded = encode_manifest(m)
    # Stripe's OpenAPI YAML is ~50-200 KB. Hitting ~400 bytes here is a >100x reduction.
    assert len(encoded) < 500, f"manifest is {len(encoded)} bytes"
