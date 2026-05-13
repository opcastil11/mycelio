"""Frame round-trip + malformed-input tests."""
from __future__ import annotations

import pytest

from mycelio import Frame, Verb, encode_frame, decode_frame
from mycelio.frame import HEADER_LEN, MAGIC, MAX_PAYLOAD, FrameError


def test_encode_empty_ping_is_14_bytes():
    """An empty-payload frame is exactly the header size on the wire."""
    f = Frame(verb=Verb.PING, stream_id=1)
    encoded = encode_frame(f)
    assert len(encoded) == HEADER_LEN
    assert encoded.startswith(MAGIC)


def test_round_trip_discover():
    payload = b"\x01\x05\x06payments"
    f = Frame(verb=Verb.DISCOVER, stream_id=3, payload=payload)
    decoded, consumed = decode_frame(encode_frame(f))
    assert consumed == HEADER_LEN + len(payload)
    assert decoded == f


def test_round_trip_preserves_stream_id():
    f = Frame(verb=Verb.ROUTE, stream_id=0x7FFFFFFF, payload=b"x" * 100)
    decoded, _ = decode_frame(encode_frame(f))
    assert decoded.stream_id == 0x7FFFFFFF


def test_decode_with_trailing_bytes_returns_consumed():
    """Two frames concatenated — decode_frame should consume only the first."""
    f1 = Frame(verb=Verb.PING, stream_id=1)
    f2 = Frame(verb=Verb.GOODBYE, stream_id=2, payload=b"bye")
    buf = encode_frame(f1) + encode_frame(f2)
    d1, n = decode_frame(buf)
    assert d1 == f1
    d2, _ = decode_frame(buf[n:])
    assert d2 == f2


def test_decode_rejects_bad_magic():
    with pytest.raises(FrameError, match="bad magic"):
        decode_frame(b"XXXX" + b"\x00" * 10)


def test_decode_rejects_short_header():
    with pytest.raises(FrameError, match="incomplete header"):
        decode_frame(b"MYCL\x00")


def test_decode_rejects_short_payload():
    """Header claims a 100-byte payload but buffer only has 5 bytes."""
    header = MAGIC + b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x64"
    with pytest.raises(FrameError, match="incomplete frame"):
        decode_frame(header + b"short")


def test_decode_rejects_unknown_verb():
    """A frame with verb byte not in the Verb enum is rejected."""
    header = MAGIC + b"\x00\x42\x00\x00\x00\x01\x00\x00\x00\x00"
    with pytest.raises(FrameError, match="unknown verb"):
        decode_frame(header)


def test_decode_rejects_oversized_payload_length():
    """A header claiming >16 MiB is rejected before allocating."""
    huge = MAX_PAYLOAD + 1
    header = MAGIC + bytes([0, 1, 0, 0, 0, 1]) + huge.to_bytes(4, "big")
    with pytest.raises(FrameError, match="exceeds MAX_PAYLOAD"):
        decode_frame(header)


def test_encode_rejects_oversized_payload():
    with pytest.raises(FrameError, match="exceeds"):
        Frame(verb=Verb.ROUTE, stream_id=1, payload=b"x" * (MAX_PAYLOAD + 1))


def test_encode_rejects_out_of_range_stream_id():
    with pytest.raises(FrameError, match="stream_id"):
        Frame(verb=Verb.PING, stream_id=2**32)
