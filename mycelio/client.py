"""Async client SDK for Mycelio v0.

Usage:

    async with MycelioClient.connect("127.0.0.1", 4242, root_pubkey=PUB) as cli:
        await cli.ping()
        results = await cli.discover(query="payment", min_score=80)
        for entry in results.results:
            print(entry.name, entry.score)

Every server response is signature-verified against `root_pubkey`. If
verification fails, the client raises `SignatureError`. This is the
trust mechanism that lets us safely talk to peer relay nodes later.
"""
from __future__ import annotations

import itertools
import ssl
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import AsyncIterator

import anyio
from anyio.abc import SocketStream
from anyio.streams.tls import TLSStream

from mycelio.crypto import SignatureError, verify_chain
from mycelio.frame import HEADER_LEN, Frame, FrameError, decode_frame, encode_frame
from mycelio.payload import PayloadError, TypeCode, decode_payload, encode_payload
from mycelio.verbs import Verb


class ClientError(Exception):
    """Raised on protocol-level client failures."""


@dataclass
class DiscoverEntry:
    service_id: bytes
    score: int
    cat_flags: int
    proto_flags: int
    name: str


@dataclass
class DiscoverResponse:
    results: list[DiscoverEntry] = field(default_factory=list)
    total: int = 0


class MycelioClient:
    """One persistent connection. Streams allocated lazily."""

    def __init__(self, stream: SocketStream, root_pubkey: bytes) -> None:
        self._stream = stream
        self._root_pubkey = root_pubkey
        # Client-allocated stream IDs are odd (cf. HTTP/2 §5.1.1).
        self._stream_counter = itertools.count(1, step=2)
        self._read_buf = bytearray()

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    @classmethod
    @asynccontextmanager
    async def connect(
        cls,
        host: str,
        port: int,
        *,
        root_pubkey: bytes,
        ssl_context: ssl.SSLContext | None = None,
    ) -> AsyncIterator["MycelioClient"]:
        """Open a Mycelio connection.

        Pass `ssl_context` to enable TLS. The TLS-level identity (cert
        chain) is independent from Mycelio's frame-chain signing — TLS
        protects the bytes in transit, the root_pubkey verifies that
        the directory authored what we receive.
        """
        stream = await anyio.connect_tcp(host, port)
        if ssl_context is not None:
            stream = await TLSStream.wrap(
                stream,
                hostname=host,
                ssl_context=ssl_context,
            )
        client = cls(stream, root_pubkey)
        try:
            yield client
        finally:
            await client.close()

    async def close(self) -> None:
        # Send GOODBYE then close.
        try:
            payload = encode_payload(
                {1: (TypeCode.STRING, "client closing"), 2: (TypeCode.U8, 0)}
            )
            bye = Frame(verb=Verb.GOODBYE, stream_id=0, payload=payload)
            await self._stream.send(encode_frame(bye))
        except (anyio.BrokenResourceError, anyio.ClosedResourceError):
            pass
        await self._stream.aclose()

    # ------------------------------------------------------------------
    # High-level verbs
    # ------------------------------------------------------------------

    async def ping(self, *, version: int = 0) -> int:
        """Negotiate version + check liveness. Returns negotiated version."""
        payload = encode_payload({1: (TypeCode.U8, version)})
        response = await self._request(Verb.PING, payload)
        fields = decode_payload(response.payload) if response.payload else {}
        return fields.get(1, (None, version))[1]

    async def discover(
        self,
        *,
        query: str | None = None,
        category: int = 0,
        min_score: int = 0,
        proto_flags: int = 0,
        limit: int = 10,
    ) -> DiscoverResponse:
        """Find services matching the filters."""
        req_fields: dict[int, tuple[TypeCode, object]] = {}
        if query is not None:
            req_fields[1] = (TypeCode.STRING, query)
        if category:
            req_fields[2] = (TypeCode.U8, category)
        if min_score:
            req_fields[3] = (TypeCode.U8, min_score)
        if proto_flags:
            req_fields[4] = (TypeCode.U32, proto_flags)
        req_fields[5] = (TypeCode.U8, limit)

        response = await self._request(Verb.DISCOVER, encode_payload(req_fields))
        return self._parse_discover(response.payload)

    # ------------------------------------------------------------------
    # Wire-level request/response
    # ------------------------------------------------------------------

    async def _request(self, verb: Verb, payload: bytes) -> Frame:
        """Send one request frame, await one response frame + SIG."""
        sid = next(self._stream_counter)
        req = Frame(verb=verb, stream_id=sid, payload=payload)
        await self._stream.send(encode_frame(req))

        response: Frame | None = None
        sig: bytes | None = None
        async for frame in self._frame_iter():
            if frame.stream_id != sid:
                continue
            if frame.verb == Verb.SIG:
                sig = frame.payload
                break
            response = frame  # may be overwritten by streaming responses
        if response is None:
            raise ClientError(f"connection closed before response to {verb.name}")
        if sig is None:
            raise ClientError(f"no SIG frame received for {verb.name}")

        # Check for error envelope (reserved field IDs).
        if response.payload:
            try:
                fields = decode_payload(response.payload)
                if 0xFF in fields:
                    code = fields[0xFF][1]
                    msg = fields.get(0xFE, (None, ""))[1]
                    raise ClientError(f"server error [{code}]: {msg}")
            except PayloadError:
                pass  # not a parseable error envelope, treat as data

        if not verify_chain(self._root_pubkey, [response], sig):
            raise SignatureError(f"signature verification failed for {verb.name}")

        return response

    async def _frame_iter(self) -> AsyncIterator[Frame]:
        """Yield frames from the stream as they arrive."""
        try:
            async for chunk in self._stream:
                self._read_buf.extend(chunk)
                while len(self._read_buf) >= HEADER_LEN:
                    try:
                        frame, consumed = decode_frame(bytes(self._read_buf))
                    except FrameError as exc:
                        if "incomplete" in str(exc):
                            break
                        raise ClientError(f"bad frame from server: {exc}") from exc
                    del self._read_buf[:consumed]
                    yield frame
        except (anyio.EndOfStream, anyio.BrokenResourceError):
            return

    # ------------------------------------------------------------------
    # Parsers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_discover(payload: bytes) -> DiscoverResponse:
        if not payload:
            return DiscoverResponse()
        fields = decode_payload(payload)
        results: list[DiscoverEntry] = []
        if 1 in fields:
            _, raw_array = fields[1]
            for sub_type, entry in raw_array:
                if sub_type != TypeCode.MAP:
                    continue
                results.append(
                    DiscoverEntry(
                        service_id=entry[1][1],
                        score=entry[2][1],
                        cat_flags=entry[3][1],
                        proto_flags=entry[4][1],
                        name=entry[5][1],
                    )
                )
        total = fields.get(2, (None, 0))[1]
        return DiscoverResponse(results=results, total=total)
