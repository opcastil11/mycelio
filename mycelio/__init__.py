"""Mycelio — binary, agent-native, peer-to-peer protocol for SaaS.

See README.md and spec/protocol-v0.md for the protocol definition.
"""

from mycelio.frame import Frame, FrameError, encode_frame, decode_frame
from mycelio.verbs import Verb

__version__ = "0.0.1"
__protocol_version__ = 0  # v0 draft

__all__ = [
    "Frame",
    "FrameError",
    "Verb",
    "encode_frame",
    "decode_frame",
    "__version__",
    "__protocol_version__",
]
