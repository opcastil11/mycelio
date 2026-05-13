"""Binary frame encode/decode for Mycelio v0.

Frame format (14-byte header + payload):

    +--------+---------+--------+--------------+--------+----------+
    | MAGIC  | VERSION |  VERB  |  STREAM_ID   | LENGTH | PAYLOAD  |
    | 4 B    |  1 B    |  1 B   |     4 B      |  4 B   |  N B     |
    +--------+---------+--------+--------------+--------+----------+

This module only handles the frame envelope. Payload encoding (field-IDs,
varint, type codes) lives in `mycelio.payload` (not yet implemented).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from mycelio.verbs import Verb

MAGIC = b"MYCL"
VERSION_V0 = 0x00
HEADER_LEN = 14
MAX_PAYLOAD = 16 * 1024 * 1024  # 16 MiB


class FrameError(Exception):
    """Raised on malformed frames."""


@dataclass(frozen=True)
class Frame:
    """A single Mycelio frame.

    Parameters
    ----------
    verb : Verb
        The operation code (see Verb enum).
    stream_id : int
        Multiplex identifier. Odd = client-allocated, even = server-allocated.
    payload : bytes
        Field-encoded body. Empty for verbs like PING that carry no data.
    version : int
        Protocol version. Defaults to v0 (0x00).
    """

    verb: Verb
    stream_id: int
    payload: bytes = b""
    version: int = VERSION_V0

    def __post_init__(self) -> None:
        if not (0 <= self.stream_id <= 0xFFFFFFFF):
            raise FrameError(f"stream_id out of u32 range: {self.stream_id}")
        if len(self.payload) > MAX_PAYLOAD:
            raise FrameError(
                f"payload exceeds {MAX_PAYLOAD} bytes (got {len(self.payload)})"
            )


def encode_frame(frame: Frame) -> bytes:
    """Encode a Frame to its wire representation."""
    return (
        MAGIC
        + struct.pack(
            ">BBII",
            frame.version,
            int(frame.verb),
            frame.stream_id,
            len(frame.payload),
        )
        + frame.payload
    )


def decode_frame(buf: bytes) -> tuple[Frame, int]:
    """Decode one frame from the front of `buf`.

    Returns
    -------
    (Frame, bytes_consumed)
        The parsed frame and the number of bytes consumed from `buf`.

    Raises
    ------
    FrameError
        If the buffer doesn't contain a complete, well-formed frame.
    """
    if len(buf) < HEADER_LEN:
        raise FrameError(
            f"incomplete header: need {HEADER_LEN} bytes, have {len(buf)}"
        )
    if buf[:4] != MAGIC:
        raise FrameError(f"bad magic: {buf[:4]!r}")

    version, verb_byte, stream_id, length = struct.unpack(
        ">BBII", buf[4:HEADER_LEN]
    )

    if length > MAX_PAYLOAD:
        raise FrameError(f"payload length {length} exceeds MAX_PAYLOAD {MAX_PAYLOAD}")

    total = HEADER_LEN + length
    if len(buf) < total:
        raise FrameError(
            f"incomplete frame: header says {length}-byte payload, "
            f"buffer has {len(buf) - HEADER_LEN} bytes remaining"
        )

    try:
        verb = Verb(verb_byte)
    except ValueError as exc:
        raise FrameError(f"unknown verb byte: 0x{verb_byte:02x}") from exc

    payload = buf[HEADER_LEN:total]
    return Frame(verb=verb, stream_id=stream_id, payload=payload, version=version), total
