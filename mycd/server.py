"""mycd — async TCP server speaking Mycelio v0.

Phase 0 scope:
- Accept TCP connections (no TLS yet — sandboxed env first)
- Parse incoming frames
- Handle PING (version negotiation, agent registration)
- Handle DISCOVER against an in-memory service registry
- Sign every server response with the root key (SIG frame)
- Handle GOODBYE gracefully

Future:
- TLS termination (Phase 0.5)
- ROUTE verb tunneling to vendor backends (Phase 1)
- BENCH / CLAIM / PAY / INDEX (Phase 1+)
- Mycelium peer gossip (Phase 2)
"""
from __future__ import annotations

import logging
import ssl
from dataclasses import dataclass

import anyio
from anyio.abc import SocketStream
from anyio.streams.tls import TLSListener

from mycelio.crypto import sign_chain
from mycelio.frame import HEADER_LEN, MAX_PAYLOAD, Frame, FrameError, decode_frame, encode_frame
from mycelio.payload import PayloadError, TypeCode, decode_payload, encode_payload
from mycelio.verbs import Verb

log = logging.getLogger("mycd.server")


@dataclass
class ServiceEntry:
    """A service in the in-memory registry. Phase 0 uses these directly
    instead of loading from a real directory."""

    service_id: bytes  # 8 bytes
    name: str
    score: int  # 0-100
    cat_flags: int  # u32 bitfield
    proto_flags: int  # u32 bitfield


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


class MycdServer:
    """Minimal Mycelio daemon. Holds the root signing key + service registry."""

    def __init__(
        self,
        *,
        root_seed: bytes,
        services: list[ServiceEntry] | None = None,
        protocol_version: int = 0,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.root_seed = root_seed
        self.services = services or []
        self.protocol_version = protocol_version
        self.ssl_context = ssl_context

    async def serve(self, host: str, port: int) -> None:
        """Run forever, accepting connections on (host, port).

        If `ssl_context` was provided at construction, the listener wraps
        incoming connections in TLS; otherwise it's plain TCP.
        """
        tcp = await anyio.create_tcp_listener(local_host=host, local_port=port)
        if self.ssl_context is not None:
            listener = TLSListener(tcp, ssl_context=self.ssl_context)
            log.info("mycd listening on %s:%s (TLS)", host, port)
        else:
            listener = tcp
            log.info("mycd listening on %s:%s (plain TCP)", host, port)
        await listener.serve(self._handle_connection)

    # ------------------------------------------------------------------
    # Connection handling
    # ------------------------------------------------------------------

    async def _handle_connection(self, stream: SocketStream) -> None:
        try:
            buf = bytearray()
            async for chunk in stream:
                buf.extend(chunk)
                while len(buf) >= HEADER_LEN:
                    try:
                        frame, consumed = decode_frame(bytes(buf))
                    except FrameError as exc:
                        # Incomplete frame — wait for more data unless the
                        # header is wrong (then disconnect).
                        if "incomplete" in str(exc):
                            break
                        log.warning("frame parse error: %s", exc)
                        await self._send_goodbye(stream, reason=str(exc), code=1)
                        return
                    del buf[:consumed]

                    closed = await self._dispatch(stream, frame)
                    if closed:
                        return
        except (anyio.EndOfStream, anyio.BrokenResourceError):
            pass  # client disconnected, normal
        finally:
            await stream.aclose()

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    async def _dispatch(self, stream: SocketStream, frame: Frame) -> bool:
        """Handle a single inbound frame. Returns True if the connection should close."""
        if frame.verb == Verb.PING:
            await self._handle_ping(stream, frame)
            return False
        if frame.verb == Verb.DISCOVER:
            await self._handle_discover(stream, frame)
            return False
        if frame.verb == Verb.GOODBYE:
            log.debug("client said goodbye on stream %d", frame.stream_id)
            return True

        # Unsupported verb — close per spec.
        await self._send_goodbye(
            stream,
            reason=f"verb 0x{int(frame.verb):02x} not implemented in Phase 0",
            code=1,
        )
        return True

    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------

    async def _handle_ping(self, stream: SocketStream, frame: Frame) -> None:
        """Respond to PING. v0: ignore agent_id and salt_id for now."""
        # Parse the request (may be empty — that's valid).
        client_version = self.protocol_version
        if frame.payload:
            try:
                fields = decode_payload(frame.payload)
                if 1 in fields:
                    client_version = fields[1][1]
            except PayloadError as exc:
                log.warning("malformed PING payload: %s", exc)

        # Negotiate down to the lowest common version (just ours for v0).
        negotiated = min(client_version, self.protocol_version)
        response = Frame(
            verb=Verb.PING,
            stream_id=frame.stream_id,
            payload=encode_payload({1: (TypeCode.U8, negotiated)}),
        )
        await self._send_signed(stream, [response])

    async def _handle_discover(self, stream: SocketStream, frame: Frame) -> None:
        try:
            req = decode_payload(frame.payload) if frame.payload else {}
        except PayloadError as exc:
            await self._send_error(stream, frame, code="bad_payload", msg=str(exc))
            return

        # Pull filters. Field IDs per spec: 1=query, 2=category, 3=min_score, 4=proto_flags, 5=limit
        query = req.get(1, (None, None))[1]
        min_score = req.get(3, (None, 0))[1]
        proto_flags = req.get(4, (None, 0))[1]
        limit = min(req.get(5, (None, 10))[1] or 10, 50)

        matches = [
            s for s in self.services
            if (not min_score or s.score >= min_score)
            and (not proto_flags or (s.proto_flags & proto_flags) == proto_flags)
            and (not query or query.lower() in s.name.lower())
        ]
        matches.sort(key=lambda s: s.score, reverse=True)
        total = len(matches)
        matches = matches[:limit]

        results = [
            (
                TypeCode.MAP,
                {
                    1: (TypeCode.HASH, s.service_id),
                    2: (TypeCode.U8, s.score),
                    3: (TypeCode.U32, s.cat_flags),
                    4: (TypeCode.U32, s.proto_flags),
                    5: (TypeCode.STRING, s.name),
                },
            )
            for s in matches
        ]
        payload = encode_payload(
            {
                1: (TypeCode.ARRAY, results),
                2: (TypeCode.U32, total),
            }
        )
        response = Frame(verb=Verb.DISCOVER, stream_id=frame.stream_id, payload=payload)
        await self._send_signed(stream, [response])

    # ------------------------------------------------------------------
    # Outbound helpers
    # ------------------------------------------------------------------

    async def _send_signed(self, stream: SocketStream, frames: list[Frame]) -> None:
        """Send a chain of response frames followed by a SIG frame.

        The signature covers exactly the frames in `frames` (not the SIG itself).
        """
        for f in frames:
            await stream.send(encode_frame(f))
        sig_bytes = sign_chain(self.root_seed, frames)
        sig_frame = Frame(verb=Verb.SIG, stream_id=frames[-1].stream_id, payload=sig_bytes)
        await stream.send(encode_frame(sig_frame))

    async def _send_error(
        self,
        stream: SocketStream,
        request_frame: Frame,
        *,
        code: str,
        msg: str,
    ) -> None:
        """Reply with an error in the same verb (per spec, reserved field IDs)."""
        payload = encode_payload(
            {
                0xFE: (TypeCode.STRING, msg),
                0xFF: (TypeCode.STRING, code),
            }
        )
        err_frame = Frame(verb=request_frame.verb, stream_id=request_frame.stream_id, payload=payload)
        await self._send_signed(stream, [err_frame])

    async def _send_goodbye(self, stream: SocketStream, *, reason: str, code: int) -> None:
        payload = encode_payload(
            {
                1: (TypeCode.STRING, reason),
                2: (TypeCode.U8, code),
            }
        )
        bye = Frame(verb=Verb.GOODBYE, stream_id=0, payload=payload)
        try:
            await stream.send(encode_frame(bye))
        except (anyio.BrokenResourceError, anyio.ClosedResourceError):
            pass
