"""Round-trip + malformed tests for the field-prefixed payload codec."""
from __future__ import annotations

import pytest

from mycelio.payload import (
    PayloadError,
    TypeCode,
    decode_payload,
    decode_varint,
    encode_payload,
    encode_varint,
)


# ---------------------------------------------------------------------------
# Varint
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("n", [0, 1, 127, 128, 16383, 16384, 0xFFFFFFFF, 2**63 - 1])
def test_varint_round_trip(n):
    encoded = encode_varint(n)
    decoded, offset = decode_varint(encoded)
    assert decoded == n
    assert offset == len(encoded)


def test_varint_small_values_are_one_byte():
    assert len(encode_varint(0)) == 1
    assert len(encode_varint(127)) == 1
    assert len(encode_varint(128)) == 2


def test_varint_rejects_negative():
    with pytest.raises(PayloadError, match="non-negative"):
        encode_varint(-1)


def test_varint_truncated_decodes_to_error():
    with pytest.raises(PayloadError, match="truncated"):
        decode_varint(b"\x80\x80")  # never-terminating


# ---------------------------------------------------------------------------
# Map round-trip — covers every primitive type
# ---------------------------------------------------------------------------


def test_round_trip_primitives():
    payload = {
        1: (TypeCode.BOOL, True),
        2: (TypeCode.U8, 200),
        3: (TypeCode.U32, 123456),
        4: (TypeCode.U64, 2**40),
        5: (TypeCode.BYTES, b"\x00\xff\xab"),
        6: (TypeCode.STRING, "hello mycelio"),
        7: (TypeCode.HASH, b"\x01" * 8),
        8: (TypeCode.PUBKEY, b"\x02" * 32),
        9: (TypeCode.SIG, b"\x03" * 64),
    }
    encoded = encode_payload(payload)
    decoded = decode_payload(encoded)
    assert decoded == payload


def test_round_trip_with_unicode_string():
    payload = {1: (TypeCode.STRING, "café · 测试")}
    decoded = decode_payload(encode_payload(payload))
    assert decoded[1] == (TypeCode.STRING, "café · 测试")


def test_round_trip_nested_map():
    """DISCOVER response: results = [map, map, map]."""
    inner = {
        1: (TypeCode.HASH, b"\xaa" * 8),
        2: (TypeCode.U8, 87),
        5: (TypeCode.STRING, "stripe"),
    }
    payload = {
        1: (
            TypeCode.ARRAY,
            [(TypeCode.MAP, inner), (TypeCode.MAP, inner)],
        ),
        2: (TypeCode.U32, 2),
    }
    decoded = decode_payload(encode_payload(payload))
    assert decoded == payload


def test_round_trip_empty_payload():
    assert decode_payload(encode_payload({})) == {}


# ---------------------------------------------------------------------------
# Canonical (sorted) encoding — required for deterministic signing
# ---------------------------------------------------------------------------


def test_encode_is_deterministic_regardless_of_dict_order():
    """Field IDs are sorted, so two dicts with same content produce same bytes."""
    a = {3: (TypeCode.U8, 5), 1: (TypeCode.BOOL, True), 2: (TypeCode.STRING, "x")}
    b = {1: (TypeCode.BOOL, True), 2: (TypeCode.STRING, "x"), 3: (TypeCode.U8, 5)}
    assert encode_payload(a) == encode_payload(b)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_encode_rejects_u8_out_of_range():
    with pytest.raises(PayloadError, match="u8 out of range"):
        encode_payload({1: (TypeCode.U8, 256)})


def test_encode_rejects_wrong_hash_length():
    with pytest.raises(PayloadError, match="HASH expects exactly 8"):
        encode_payload({1: (TypeCode.HASH, b"\x01" * 7)})


def test_encode_rejects_wrong_pubkey_length():
    with pytest.raises(PayloadError, match="PUBKEY expects exactly 32"):
        encode_payload({1: (TypeCode.PUBKEY, b"\x01" * 31)})


def test_decode_rejects_trailing_bytes():
    buf = encode_payload({1: (TypeCode.U8, 1)})
    with pytest.raises(PayloadError, match="trailing bytes"):
        decode_payload(buf + b"\x00")


def test_decode_rejects_unknown_type_byte():
    """A type byte not in the TypeCode enum is rejected at decode time."""
    # 1 field, id=1, type=0xCC
    buf = b"\x01\x01\xcc\x00"
    with pytest.raises(PayloadError, match="unknown type byte"):
        decode_payload(buf)


def test_decode_rejects_truncated_string():
    """Length says 20 bytes but only 5 are present."""
    buf = b"\x01\x01\x05\x14hello"  # field_id=1, STRING, len=20, only 5 bytes
    with pytest.raises(PayloadError, match="truncated STRING"):
        decode_payload(buf)


# ---------------------------------------------------------------------------
# Discover response wire size — sanity check the token-savings claim
# ---------------------------------------------------------------------------


def test_discover_response_is_compact():
    """A 3-result DISCOVER response should be well under 200 bytes."""
    entry = lambda h, score, name: {  # noqa: E731
        1: (TypeCode.HASH, h),
        2: (TypeCode.U8, score),
        3: (TypeCode.U32, 0b1011),  # cat_flags
        4: (TypeCode.U32, 0b00101),  # proto_flags
        5: (TypeCode.STRING, name),
    }
    payload = {
        1: (
            TypeCode.ARRAY,
            [
                (TypeCode.MAP, entry(b"\x01" * 8, 87, "stripe")),
                (TypeCode.MAP, entry(b"\x02" * 8, 81, "openai")),
                (TypeCode.MAP, entry(b"\x03" * 8, 78, "resend")),
            ],
        ),
        2: (TypeCode.U32, 3),
    }
    encoded = encode_payload(payload)
    assert len(encoded) < 200, f"3-result DISCOVER took {len(encoded)} bytes"
