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
from mycelio.manifest import Manifest, ParamLocation, decode_manifest
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


@dataclass
class RouteResponse:
    """A response from a ROUTE call. Body is raw backend bytes (typically JSON)."""

    status_code: int
    content_type: str
    body: bytes

    def json(self) -> Any:
        """Parse the body as JSON. Raises if content-type isn't JSON."""
        import json as _json
        if "json" not in self.content_type.lower() and self.content_type:
            raise ValueError(f"backend returned {self.content_type}, not JSON")
        return _json.loads(self.body.decode("utf-8"))

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


@dataclass
class FetchResponse:
    """A response from a FETCH call.

    `source` is `"heuristic"` (daemon scraped + extracted) or `"manifest"`
    (host ships a signed Mycelio manifest, returned verbatim). `signed`
    is true only on the manifest path. The envelope is always SIG-framed.
    """

    source: str
    signed: bool
    content: str
    affordances: list[dict[str, Any]] = field(default_factory=list)
    fetched_at: int = 0
    ttl_seconds: int = 0
    outline: list[dict[str, Any]] = field(default_factory=list)


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

    async def inspect(self, service_id: bytes) -> Manifest:
        """Fetch the full manifest for a service. Verifies the directory's
        countersignature locally (the manifest itself carries its own sigs)."""
        if len(service_id) != 8:
            raise ValueError(f"service_id must be 8 bytes, got {len(service_id)}")
        payload = encode_payload({1: (TypeCode.HASH, service_id)})
        response = await self._request(Verb.INSPECT, payload)
        fields = decode_payload(response.payload) if response.payload else {}
        if 1 not in fields:
            raise ClientError("INSPECT response missing manifest bytes (field 1)")
        manifest_bytes = fields[1][1]
        return decode_manifest(manifest_bytes)

    async def route(
        self,
        manifest: Manifest,
        op: str,
        params: dict[str, Any] | None = None,
        *,
        payment_proof: bytes | None = None,
    ) -> RouteResponse:
        """Invoke an op on a service. `manifest` must be a freshly INSPECTed
        Manifest — its param order defines the on-wire field IDs.

        Example:
            m = await cli.inspect(svc_hash)
            r = await cli.route(m, "charge", {"amount": 500, "currency": "usd"})
            print(r.status_code, r.json())
        """
        params = params or {}
        op_def = manifest.get_op(op)

        # Encode params in manifest order — field id N = nth param in op.params.
        param_fields: dict[int, tuple[TypeCode, Any]] = {}
        for idx, p in enumerate(op_def.params, start=1):
            if p.key not in params:
                if p.required:
                    raise ValueError(f"missing required param: {p.key!r}")
                continue
            value = params[p.key]
            # Pick a wire type for the value.
            if isinstance(value, bool):
                param_fields[idx] = (TypeCode.BOOL, value)
            elif isinstance(value, int):
                param_fields[idx] = (TypeCode.U64, value)
            elif isinstance(value, str):
                param_fields[idx] = (TypeCode.STRING, value)
            elif isinstance(value, (bytes, bytearray)):
                param_fields[idx] = (TypeCode.BYTES, bytes(value))
            else:
                raise ValueError(
                    f"unsupported param type for {p.key!r}: {type(value).__name__}"
                )

        req_fields: dict[int, tuple[TypeCode, Any]] = {
            1: (TypeCode.HASH, manifest.service_id),
            2: (TypeCode.STRING, op),
        }
        if param_fields:
            req_fields[3] = (TypeCode.MAP, param_fields)
        if payment_proof is not None:
            req_fields[4] = (TypeCode.BYTES, payment_proof)

        response = await self._request(Verb.ROUTE, encode_payload(req_fields))
        fields = decode_payload(response.payload) if response.payload else {}
        return RouteResponse(
            status_code=fields.get(1, (None, 0))[1],
            body=fields.get(2, (None, b""))[1],
            content_type=fields.get(3, (None, ""))[1],
        )

    async def fetch(
        self,
        url: str,
        *,
        max_bytes: int | None = None,
        outline_only: bool = False,
        section_id: str | None = None,
        outline_mode: str = "structural",
    ) -> FetchResponse:
        """Get agent-friendly content for any URL.

        Modes:
            ``outline_only=True``: fast index of sections; ``content`` is empty,
                ``outline`` is populated.
            ``section_id="..."``: returns just that section's text in
                ``content``; ``outline`` is reduced to that one entry.
            default: full content + outline + affordances.

        ``outline_mode`` is ``"structural"`` (free, h1–h6) or ``"llm"`` (the
        daemon calls a configured LLM to generate a semantic outline; requires
        server-side env config or returns ``llm_unavailable``).
        """
        req_fields: dict[int, tuple[TypeCode, Any]] = {
            1: (TypeCode.STRING, url),
        }
        if max_bytes is not None:
            req_fields[2] = (TypeCode.U32, max_bytes)
        if outline_only:
            req_fields[7] = (TypeCode.BOOL, True)
        if section_id is not None:
            req_fields[8] = (TypeCode.STRING, section_id)
        if outline_mode and outline_mode != "structural":
            req_fields[9] = (TypeCode.STRING, outline_mode)

        response = await self._request(Verb.FETCH, encode_payload(req_fields))
        fields = decode_payload(response.payload) if response.payload else {}

        affordances = _parse_affordances_field(fields.get(4))
        outline = _parse_outline_field(fields.get(7))

        return FetchResponse(
            source=fields.get(1, (None, "heuristic"))[1],
            signed=fields.get(2, (None, False))[1],
            content=fields.get(3, (None, ""))[1],
            affordances=affordances,
            fetched_at=fields.get(5, (None, 0))[1],
            ttl_seconds=fields.get(6, (None, 0))[1],
            outline=outline,
        )

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
    def _parse_discover(payload: bytes) -> DiscoverResponse:  # noqa: D401
        return _parse_discover_impl(payload)


def _parse_affordances_field(field_cell) -> list[dict[str, Any]]:
    """Decode the FETCH affordances array (field 4) into named-key dicts.

    Wire shape per affordance:
        1: kind, 2: target, 3: label, 4: hints (map)
    Hints (form):  1: method, 2: fields[{1:name,2:type,3:required}]
    Hints (op):    1: method, 3: path
    """
    if field_cell is None:
        return []
    out: list[dict[str, Any]] = []
    for sub_type, entry in field_cell[1]:
        if sub_type != TypeCode.MAP:
            continue
        aff: dict[str, Any] = {}
        if 1 in entry:
            aff["kind"] = entry[1][1]
        if 2 in entry:
            aff["target"] = entry[2][1]
        if 3 in entry:
            aff["label"] = entry[3][1]
        if 4 in entry:
            hints_map = entry[4][1]
            hints: dict[str, Any] = {}
            if 1 in hints_map:
                hints["method"] = hints_map[1][1]
            if 2 in hints_map:
                f_list: list[dict[str, Any]] = []
                for st, fmap in hints_map[2][1]:
                    if st != TypeCode.MAP:
                        continue
                    f_list.append({
                        "name": fmap.get(1, (None, ""))[1],
                        "type": fmap.get(2, (None, "text"))[1],
                        "required": fmap.get(3, (None, False))[1],
                    })
                hints["fields"] = f_list
            if 3 in hints_map:
                hints["path"] = hints_map[3][1]
            if hints:
                aff["hints"] = hints
        out.append(aff)
    return out


def _parse_outline_field(field_cell) -> list[dict[str, Any]]:
    """Decode the FETCH outline array (field 7) into named-key dicts:
    each entry has keys ``id``, ``heading``, ``depth``, ``size_bytes``,
    ``preview``."""
    if field_cell is None:
        return []
    out: list[dict[str, Any]] = []
    for sub_type, entry in field_cell[1]:
        if sub_type != TypeCode.MAP:
            continue
        out.append({
            "id": entry.get(1, (None, ""))[1],
            "heading": entry.get(2, (None, ""))[1],
            "depth": entry.get(3, (None, 0))[1],
            "size_bytes": entry.get(4, (None, 0))[1],
            "preview": entry.get(5, (None, ""))[1],
        })
    return out


def _parse_discover_impl(payload: bytes) -> DiscoverResponse:
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
