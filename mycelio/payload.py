"""Field-prefixed payload encoding for Mycelio v0.

Each field is:

    <field_id: varint> <type: u8> <length-or-value: varies>

Type codes (see spec/protocol-v0.md):

    0x00 bool         1 byte
    0x01 u8           1 byte
    0x02 u32          varint
    0x03 u64          varint
    0x04 bytes        varint length + raw bytes
    0x05 string       varint length + UTF-8 bytes
    0x06 array        varint count + repeated <type, value>
    0x07 map          varint count + repeated <field_id, type, value>
    0x08 hash         exactly 8 bytes
    0x09 sig          exactly 64 bytes
    0x0A pubkey       exactly 32 bytes

The encoder accepts Python types and a per-field type hint. The decoder
reads a stream and returns a dict mapping field_id → value.
"""
from __future__ import annotations

from enum import IntEnum
from typing import Any


class PayloadError(Exception):
    """Raised on malformed payloads."""


class TypeCode(IntEnum):
    BOOL = 0x00
    U8 = 0x01
    U32 = 0x02
    U64 = 0x03
    BYTES = 0x04
    STRING = 0x05
    ARRAY = 0x06
    MAP = 0x07
    HASH = 0x08  # 8 bytes
    SIG = 0x09  # 64 bytes
    PUBKEY = 0x0A  # 32 bytes


_FIXED_LEN = {TypeCode.HASH: 8, TypeCode.SIG: 64, TypeCode.PUBKEY: 32}


# ---------------------------------------------------------------------------
# Varint (unsigned, protobuf-style)
# ---------------------------------------------------------------------------


def encode_varint(n: int) -> bytes:
    if n < 0:
        raise PayloadError(f"varint must be non-negative, got {n}")
    out = bytearray()
    while n > 0x7F:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n & 0x7F)
    return bytes(out)


def decode_varint(buf: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode a varint at `offset`. Returns (value, new_offset)."""
    n = 0
    shift = 0
    while True:
        if offset >= len(buf):
            raise PayloadError("truncated varint")
        b = buf[offset]
        offset += 1
        n |= (b & 0x7F) << shift
        if not (b & 0x80):
            return n, offset
        shift += 7
        if shift >= 64:
            raise PayloadError("varint exceeds 64 bits")


# ---------------------------------------------------------------------------
# Scalar encode/decode (private — used by field codec)
# ---------------------------------------------------------------------------


def _encode_value(value: Any, type_code: TypeCode) -> bytes:
    if type_code == TypeCode.BOOL:
        if not isinstance(value, bool):
            raise PayloadError(f"bool expected, got {type(value).__name__}")
        return b"\x01" if value else b"\x00"
    if type_code == TypeCode.U8:
        if not isinstance(value, int) or not (0 <= value <= 0xFF):
            raise PayloadError(f"u8 out of range: {value}")
        return bytes([value])
    if type_code in (TypeCode.U32, TypeCode.U64):
        if not isinstance(value, int) or value < 0:
            raise PayloadError(f"unsigned int expected, got {value!r}")
        return encode_varint(value)
    if type_code == TypeCode.BYTES:
        if not isinstance(value, (bytes, bytearray)):
            raise PayloadError(f"bytes expected, got {type(value).__name__}")
        return encode_varint(len(value)) + bytes(value)
    if type_code == TypeCode.STRING:
        if not isinstance(value, str):
            raise PayloadError(f"str expected, got {type(value).__name__}")
        encoded = value.encode("utf-8")
        return encode_varint(len(encoded)) + encoded
    if type_code in _FIXED_LEN:
        expected = _FIXED_LEN[type_code]
        if not isinstance(value, (bytes, bytearray)) or len(value) != expected:
            raise PayloadError(
                f"{type_code.name} expects exactly {expected} bytes, got {len(value) if hasattr(value,'__len__') else '?'}"
            )
        return bytes(value)
    if type_code == TypeCode.ARRAY:
        # Array entries must each be (TypeCode, value).
        if not isinstance(value, list):
            raise PayloadError(f"array expected list, got {type(value).__name__}")
        parts = [encode_varint(len(value))]
        for entry in value:
            if not (isinstance(entry, tuple) and len(entry) == 2):
                raise PayloadError("array entries must be (TypeCode, value) tuples")
            sub_type, sub_val = entry
            parts.append(bytes([int(sub_type)]))
            parts.append(_encode_value(sub_val, TypeCode(sub_type)))
        return b"".join(parts)
    if type_code == TypeCode.MAP:
        if not isinstance(value, dict):
            raise PayloadError(f"map expected dict, got {type(value).__name__}")
        return encode_map(value)
    raise PayloadError(f"unknown type code: {type_code}")


def _decode_value(buf: bytes, offset: int, type_code: TypeCode) -> tuple[Any, int]:
    if type_code == TypeCode.BOOL:
        if offset >= len(buf):
            raise PayloadError("truncated bool")
        return bool(buf[offset]), offset + 1
    if type_code == TypeCode.U8:
        if offset >= len(buf):
            raise PayloadError("truncated u8")
        return buf[offset], offset + 1
    if type_code in (TypeCode.U32, TypeCode.U64):
        return decode_varint(buf, offset)
    if type_code in (TypeCode.BYTES, TypeCode.STRING):
        length, offset = decode_varint(buf, offset)
        if offset + length > len(buf):
            raise PayloadError(f"truncated {type_code.name}")
        chunk = buf[offset : offset + length]
        offset += length
        if type_code == TypeCode.STRING:
            try:
                return chunk.decode("utf-8"), offset
            except UnicodeDecodeError as exc:
                raise PayloadError(f"invalid utf-8: {exc}") from exc
        return bytes(chunk), offset
    if type_code in _FIXED_LEN:
        length = _FIXED_LEN[type_code]
        if offset + length > len(buf):
            raise PayloadError(f"truncated {type_code.name}")
        return bytes(buf[offset : offset + length]), offset + length
    if type_code == TypeCode.ARRAY:
        count, offset = decode_varint(buf, offset)
        result: list[tuple[TypeCode, Any]] = []
        for _ in range(count):
            if offset >= len(buf):
                raise PayloadError("truncated array entry type")
            try:
                sub_type = TypeCode(buf[offset])
            except ValueError as exc:
                raise PayloadError(f"unknown type in array: 0x{buf[offset]:02x}") from exc
            offset += 1
            sub_val, offset = _decode_value(buf, offset, sub_type)
            result.append((sub_type, sub_val))
        return result, offset
    if type_code == TypeCode.MAP:
        return decode_map(buf, offset)
    raise PayloadError(f"unknown type code: {type_code}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def encode_map(fields: dict[int, tuple[TypeCode, Any]]) -> bytes:
    """Encode a map (dict of field_id → (TypeCode, value)).

    Top-level payload encoding uses the same map format with a leading
    varint count (so it can be embedded as a sub-map). The encoder emits
    fields in numeric key order for canonical output (required for
    deterministic signing).
    """
    parts = [encode_varint(len(fields))]
    for fid in sorted(fields.keys()):
        type_code, value = fields[fid]
        parts.append(encode_varint(fid))
        parts.append(bytes([int(type_code)]))
        parts.append(_encode_value(value, TypeCode(type_code)))
    return b"".join(parts)


def decode_map(buf: bytes, offset: int = 0) -> tuple[dict[int, tuple[TypeCode, Any]], int]:
    """Decode a map. Returns (dict, new_offset)."""
    count, offset = decode_varint(buf, offset)
    out: dict[int, tuple[TypeCode, Any]] = {}
    for _ in range(count):
        fid, offset = decode_varint(buf, offset)
        if offset >= len(buf):
            raise PayloadError("truncated map field type")
        try:
            type_code = TypeCode(buf[offset])
        except ValueError as exc:
            raise PayloadError(f"unknown type byte: 0x{buf[offset]:02x}") from exc
        offset += 1
        value, offset = _decode_value(buf, offset, type_code)
        out[fid] = (type_code, value)
    return out, offset


def encode_payload(fields: dict[int, tuple[TypeCode, Any]]) -> bytes:
    """Encode a top-level frame payload."""
    return encode_map(fields)


def decode_payload(buf: bytes) -> dict[int, tuple[TypeCode, Any]]:
    """Decode a complete frame payload. Trailing bytes raise."""
    fields, offset = decode_map(buf)
    if offset != len(buf):
        raise PayloadError(
            f"trailing bytes in payload: parsed {offset}, total {len(buf)}"
        )
    return fields
