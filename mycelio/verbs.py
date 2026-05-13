"""Mycelio v0 verb codes.

The verb byte is the first instruction in every frame. See spec/protocol-v0.md
for full semantics.
"""
from __future__ import annotations

from enum import IntEnum


class Verb(IntEnum):
    """Verb codes for the Mycelio wire protocol."""

    PING = 0x01
    DISCOVER = 0x02
    INSPECT = 0x03
    ROUTE = 0x04
    BENCH = 0x05
    CLAIM = 0x06
    PAY = 0x07
    INDEX = 0x08

    SIG = 0xFE
    GOODBYE = 0xFF


# Reserved field IDs that mean the same thing across every verb.
RESERVED_FIELD_ERROR_CODE = 0xFF
RESERVED_FIELD_ERROR_MSG = 0xFE
