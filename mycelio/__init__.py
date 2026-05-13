"""Mycelio — binary, agent-native, peer-to-peer protocol for SaaS.

See README.md and spec/protocol-v0.md for the protocol definition.
"""

from mycelio.client import ClientError, DiscoverEntry, DiscoverResponse, MycelioClient, RouteResponse
from mycelio.crypto import (
    SignatureError,
    generate_keypair,
    public_from_private,
    sign_chain,
    verify_chain,
)
from mycelio.frame import Frame, FrameError, decode_frame, encode_frame
from mycelio.payload import (
    PayloadError,
    TypeCode,
    decode_payload,
    encode_payload,
)
from mycelio.verbs import Verb

__version__ = "0.0.1"
__protocol_version__ = 0  # v0 draft

__all__ = [
    "ClientError",
    "DiscoverEntry",
    "DiscoverResponse",
    "Frame",
    "FrameError",
    "MycelioClient",
    "PayloadError",
    "RouteResponse",
    "SignatureError",
    "TypeCode",
    "Verb",
    "decode_frame",
    "decode_payload",
    "encode_frame",
    "encode_payload",
    "generate_keypair",
    "public_from_private",
    "sign_chain",
    "verify_chain",
    "__version__",
    "__protocol_version__",
]
