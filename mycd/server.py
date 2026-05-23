"""mycd — async TCP server speaking Mycelio v0.

Phase 0 + 0.5 + 1 scope:
- TLS-wrapped TCP listener
- PING (version negotiation)
- DISCOVER (in-memory service registry)
- INSPECT (returns the manifest for a service_id)
- ROUTE (translates to outbound HTTP and streams response back)
- GOODBYE

The ROUTE handler is the "Rappi courier" — the agent sends one binary
frame, mycd reads the vendor's manifest, builds an HTTP request to the
vendor's existing backend, gets the response, and frames it back to
the agent with an Ed25519 signature. The vendor never knew Mycelio
existed.
"""
from __future__ import annotations

import logging
import ssl
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import anyio
import httpx
from anyio.abc import SocketStream
from anyio.streams.tls import TLSListener

from mycd.extractor import (
    DEFAULT_MAX_BYTES,
    ExtractedContent,
    ExtractorError,
    fetch_and_extract,
)
from mycd.outline import (
    LLMOutlineError,
    Section,
    bind_llm_content,
    find_section,
    llm_outline_enabled,
    llm_sections,
)
from mycelio.crypto import sign_chain
from mycelio.frame import HEADER_LEN, MAX_PAYLOAD, Frame, FrameError, decode_frame, encode_frame
from mycelio.manifest import (
    Manifest,
    ManifestError,
    ParamLocation,
    encode_manifest,
)
from mycelio.payload import PayloadError, TypeCode, decode_payload, encode_payload
from mycelio.verbs import Verb

FETCH_CACHE_MAX = 1024
DEFAULT_FETCH_TTL_SECONDS = 24 * 3600  # 24 h

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
        manifests: list[Manifest] | None = None,
        protocol_version: int = 0,
        ssl_context: ssl.SSLContext | None = None,
        http_client: httpx.AsyncClient | None = None,
        respect_robots: bool = True,
        fetch_ttl_seconds: int = DEFAULT_FETCH_TTL_SECONDS,
        jina_fallback: bool = True,
    ) -> None:
        self.root_seed = root_seed
        self.services = services or []
        self.manifests_by_id: dict[bytes, Manifest] = {
            m.service_id: m for m in (manifests or [])
        }
        # Host → Manifest, derived from each manifest's backend_url. Used by
        # FETCH for the manifest-graduation path (P3).
        self.manifests_by_host: dict[str, Manifest] = {}
        for m in (manifests or []):
            host = urlparse(m.backend_url).hostname
            if host:
                self.manifests_by_host[host.lower()] = m
        self.protocol_version = protocol_version
        self.ssl_context = ssl_context
        # Outbound HTTP client for ROUTE translation. Tests inject a mock transport.
        self._http_client = http_client or httpx.AsyncClient(timeout=30)
        # Track whether we own the httpx client (so we close it on shutdown).
        self._owns_http_client = http_client is None
        # FETCH state — shared in-memory cache + robots cache across calls.
        self._respect_robots = respect_robots
        self._fetch_ttl_seconds = fetch_ttl_seconds
        self._jina_fallback = jina_fallback
        self._fetch_cache: dict[str, tuple[ExtractedContent, int]] = {}
        self._robots_cache: dict[str, Any] = {}

    async def aclose(self) -> None:
        if self._owns_http_client:
            await self._http_client.aclose()

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
        if frame.verb == Verb.INSPECT:
            await self._handle_inspect(stream, frame)
            return False
        if frame.verb == Verb.ROUTE:
            await self._handle_route(stream, frame)
            return False
        if frame.verb == Verb.FETCH:
            await self._handle_fetch(stream, frame)
            return False
        if frame.verb == Verb.GOODBYE:
            log.debug("client said goodbye on stream %d", frame.stream_id)
            return True

        # Unsupported verb — close per spec.
        await self._send_goodbye(
            stream,
            reason=f"verb 0x{int(frame.verb):02x} not implemented",
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

    async def _handle_inspect(self, stream: SocketStream, frame: Frame) -> None:
        """Return the full manifest for a service_id.

        Request: {1: service_id (8B hash)}
        Response: {1: bytes (encoded manifest)} — the agent decodes locally.
        """
        try:
            req = decode_payload(frame.payload) if frame.payload else {}
        except PayloadError as exc:
            await self._send_error(stream, frame, code="bad_payload", msg=str(exc))
            return

        service_id = req.get(1, (None, None))[1]
        if not service_id:
            await self._send_error(stream, frame, code="missing_service_id", msg="field 1 required")
            return

        manifest = self.manifests_by_id.get(service_id)
        if manifest is None:
            await self._send_error(
                stream, frame, code="service_not_found",
                msg=f"no manifest for service {service_id.hex()}",
            )
            return

        try:
            encoded = encode_manifest(manifest)
        except ManifestError as exc:
            await self._send_error(stream, frame, code="manifest_encode_failed", msg=str(exc))
            return

        response = Frame(
            verb=Verb.INSPECT,
            stream_id=frame.stream_id,
            payload=encode_payload({1: (TypeCode.BYTES, encoded)}),
        )
        await self._send_signed(stream, [response])

    async def _handle_route(self, stream: SocketStream, frame: Frame) -> None:
        """Translate a Mycelio ROUTE into an outbound HTTP call.

        Request fields (per spec):
          1 service_id : hash
          2 op         : string (the op slug)
          3 params     : map of field-id -> value (sequential field IDs match
                         the order of params in the manifest's op definition,
                         starting at 1)
          4 payment_proof : bytes (when required by op)

        Response: {1: status_code, 2: body_bytes, 3: content_type}
        """
        try:
            req = decode_payload(frame.payload) if frame.payload else {}
        except PayloadError as exc:
            await self._send_error(stream, frame, code="bad_payload", msg=str(exc))
            return

        service_id = req.get(1, (None, None))[1]
        op_slug = req.get(2, (None, None))[1]
        params_map = req.get(3, (None, {}))[1]  # dict[int, (TypeCode, value)]
        payment_proof = req.get(4, (None, None))[1]

        if not service_id or not op_slug:
            await self._send_error(stream, frame, code="missing_fields", msg="service_id and op required")
            return

        manifest = self.manifests_by_id.get(service_id)
        if manifest is None:
            await self._send_error(
                stream, frame, code="service_not_found",
                msg=f"no manifest for service {service_id.hex()}",
            )
            return

        try:
            op = manifest.get_op(op_slug)
        except ManifestError as exc:
            await self._send_error(stream, frame, code="op_not_found", msg=str(exc))
            return

        if op.requires_payment and not payment_proof:
            await self._send_error(stream, frame, code="payment_required", msg="x402 proof required")
            return

        # Build the outbound HTTP request from the manifest + params.
        try:
            method, url, query, body, headers = _build_outbound_request(
                manifest, op, params_map,
            )
        except _BuildError as exc:
            await self._send_error(stream, frame, code="bad_params", msg=str(exc))
            return

        log.debug("route %s.%s → %s %s", manifest.slug, op_slug, method, url)

        try:
            backend_response = await self._http_client.request(
                method, url, params=query, json=body if body else None, headers=headers,
            )
        except httpx.HTTPError as exc:
            log.warning("route backend error %s: %s", url, exc)
            await self._send_error(stream, frame, code="backend_unreachable", msg=str(exc))
            return

        content_type = backend_response.headers.get("content-type", "")
        response_payload = encode_payload(
            {
                1: (TypeCode.U32, backend_response.status_code),
                2: (TypeCode.BYTES, backend_response.content),
                3: (TypeCode.STRING, content_type),
            }
        )
        response = Frame(verb=Verb.ROUTE, stream_id=frame.stream_id, payload=response_payload)
        await self._send_signed(stream, [response])

    async def _handle_fetch(self, stream: SocketStream, frame: Frame) -> None:
        """Heuristic content extraction for any URL.

        Request fields:
          1 url           : string (required)
          2 max_bytes     : u32 (optional, default 256 KiB)
          3 affordances   : bool (optional; reserved)
          7 outline_only  : bool (optional)
          8 section_id    : string (optional — return just that section)
          9 outline_mode  : string (optional — "structural" | "llm", default "structural")

        Response: {1: source, 2: signed, 3: content, 4: affordances,
                   5: fetched_at, 6: ttl_seconds, 7: outline}.
        """
        try:
            req = decode_payload(frame.payload) if frame.payload else {}
        except PayloadError as exc:
            await self._send_error(stream, frame, code="bad_payload", msg=str(exc))
            return

        url = req.get(1, (None, None))[1]
        if not url:
            await self._send_error(stream, frame, code="bad_url", msg="field 1 (url) required")
            return

        mb_field = req.get(2)
        max_bytes = mb_field[1] if mb_field and mb_field[1] > 0 else DEFAULT_MAX_BYTES
        outline_only = bool(req.get(7, (None, False))[1])
        section_id = req.get(8, (None, None))[1] or None
        outline_mode = (req.get(9, (None, "structural"))[1] or "structural").lower()
        if outline_mode not in ("structural", "llm"):
            await self._send_error(
                stream, frame, code="bad_payload",
                msg=f"unknown outline_mode {outline_mode!r}",
            )
            return

        # Resolve the underlying extraction (cache → manifest → fetch).
        now = int(time.time())
        source = "heuristic"
        signed = False
        ttl_remaining = self._fetch_ttl_seconds
        extracted: ExtractedContent | None = None

        cached = self._fetch_cache.get(url)
        if cached is not None:
            cached_extracted, expires_at = cached
            if expires_at > now:
                extracted = cached_extracted
                ttl_remaining = expires_at - now
            else:
                self._fetch_cache.pop(url, None)

        if extracted is None:
            target_host = (urlparse(url).hostname or "").lower()
            manifest = self.manifests_by_host.get(target_host)
            if manifest is not None:
                extracted = _build_manifest_extracted(manifest, url, now)
                source = "manifest"
                signed = True
            else:
                try:
                    extracted = await fetch_and_extract(
                        url,
                        http_client=self._http_client,
                        max_bytes=max_bytes,
                        respect_robots=self._respect_robots,
                        robots_cache=self._robots_cache,
                        jina_fallback=self._jina_fallback,
                    )
                except ExtractorError as exc:
                    await self._send_error(stream, frame, code=exc.code, msg=exc.message)
                    return
                expires_at = now + self._fetch_ttl_seconds
                if len(self._fetch_cache) >= FETCH_CACHE_MAX:
                    self._fetch_cache.pop(next(iter(self._fetch_cache)))
                self._fetch_cache[url] = (extracted, expires_at)
                log.debug("fetch %s via %s (%d chars)", url, extracted.engine, len(extracted.content))

        # Lazily compute LLM outline (cached on the extracted entry).
        if outline_mode == "llm" and extracted.llm_sections is None:
            if not llm_outline_enabled():
                await self._send_error(
                    stream, frame, code="llm_unavailable",
                    msg="MYCD_OUTLINE_LLM_PROVIDER / ANTHROPIC_API_KEY not configured",
                )
                return
            try:
                raw = await llm_sections(extracted.content, http_client=self._http_client)
                extracted.llm_sections = bind_llm_content(raw, extracted.content)
            except LLMOutlineError as exc:
                log.warning("llm outline failed for %s: %s", url, exc)
                await self._send_error(stream, frame, code="llm_failed", msg=str(exc))
                return

        sections = (
            extracted.llm_sections
            if outline_mode == "llm" and extracted.llm_sections is not None
            else extracted.sections
        )

        if section_id:
            picked = find_section(sections, section_id)
            if picked is None:
                await self._send_error(
                    stream, frame, code="section_not_found",
                    msg=f"no section with id {section_id!r}",
                )
                return
            content_out = picked.content
            affordances_out: list[dict] = []
            outline_out: list[Section] = [picked]
        elif outline_only:
            content_out = ""
            affordances_out = []
            outline_out = sections
        else:
            content_out = extracted.content
            affordances_out = extracted.affordances
            outline_out = sections

        await self._send_fetch_response(
            stream, frame, extracted,
            source=source, signed=signed, ttl_seconds=ttl_remaining,
            content_override=content_out,
            affordances_override=affordances_out,
            outline=outline_out,
        )

    async def _send_fetch_response(
        self,
        stream: SocketStream,
        request_frame: Frame,
        extracted: ExtractedContent,
        *,
        source: str,
        signed: bool,
        ttl_seconds: int,
        content_override: str | None = None,
        affordances_override: list[dict] | None = None,
        outline: list[Section] | None = None,
    ) -> None:
        content = content_override if content_override is not None else extracted.content
        affordances = (
            affordances_override if affordances_override is not None else extracted.affordances
        )
        affordances_array = [_encode_affordance(aff) for aff in affordances]
        outline_array = [_encode_section(s) for s in (outline or [])]

        payload = encode_payload(
            {
                1: (TypeCode.STRING, source),
                2: (TypeCode.BOOL, signed),
                3: (TypeCode.STRING, content),
                4: (TypeCode.ARRAY, affordances_array),
                5: (TypeCode.U64, extracted.fetched_at),
                6: (TypeCode.U32, ttl_seconds),
                7: (TypeCode.ARRAY, outline_array),
            }
        )
        response = Frame(
            verb=Verb.FETCH,
            stream_id=request_frame.stream_id,
            payload=payload,
        )
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


def _build_manifest_extracted(manifest: Manifest, url: str, now: int) -> ExtractedContent:
    """Render a signed manifest into the FETCH response shape.

    Content is a short Markdown summary; affordances are the manifest's
    ops as ``kind="op"`` entries the agent can hand to ROUTE.
    """
    op_lines = [
        f"- `{op.slug}` — {op.method.upper()} {op.path}"
        for op in manifest.ops
    ]
    content = (
        f"# {manifest.slug}\n\n"
        f"Signed Mycelio manifest. {len(manifest.ops)} operation(s):\n\n"
        + "\n".join(op_lines)
        + "\n\nInvoke any op by slug via ROUTE."
    )
    affordances = [
        {
            "kind": "op",
            "target": op.slug,
            "label": f"{op.method.upper()} {op.path}",
            "hints": {"method": op.method.upper(), "path": op.path},
        }
        for op in manifest.ops
    ]
    return ExtractedContent(
        content=content,
        fetched_at=now,
        final_url=url,
        engine="manifest",
        affordances=affordances,
    )


def _encode_section(s: Section) -> tuple[TypeCode, dict]:
    """Encode one outline entry. Wire fields:
        1: id, 2: heading, 3: depth, 4: size_bytes, 5: preview
    """
    return (
        TypeCode.MAP,
        {
            1: (TypeCode.STRING, s.id),
            2: (TypeCode.STRING, s.heading),
            3: (TypeCode.U8, s.depth),
            4: (TypeCode.U32, s.size_bytes),
            5: (TypeCode.STRING, s.preview),
        },
    )


def _encode_affordance(aff: dict[str, Any]) -> tuple[TypeCode, dict]:
    """Convert a parsed affordance dict to a (TypeCode.MAP, encoded) entry
    suitable for the FETCH response affordances array.

    Wire fields per affordance:
        1: kind (string)
        2: target (string)
        3: label (string)
        4: hints (map, optional) — for forms: {1: method, 2: fields[]};
           for ops: {1: method, 3: path}
    """
    out: dict[int, tuple[TypeCode, Any]] = {
        1: (TypeCode.STRING, aff["kind"]),
        2: (TypeCode.STRING, aff["target"]),
        3: (TypeCode.STRING, aff["label"]),
    }
    hints = aff.get("hints") or {}
    hint_map: dict[int, tuple[TypeCode, Any]] = {}
    if "method" in hints:
        hint_map[1] = (TypeCode.STRING, hints["method"])
    if "fields" in hints:
        entries: list[tuple[TypeCode, Any]] = []
        for f in hints["fields"]:
            entries.append(
                (TypeCode.MAP, {
                    1: (TypeCode.STRING, f.get("name", "")),
                    2: (TypeCode.STRING, f.get("type", "text")),
                    3: (TypeCode.BOOL, bool(f.get("required", False))),
                })
            )
        hint_map[2] = (TypeCode.ARRAY, entries)
    if "path" in hints:
        hint_map[3] = (TypeCode.STRING, hints["path"])
    if hint_map:
        out[4] = (TypeCode.MAP, hint_map)
    return (TypeCode.MAP, out)


class _BuildError(Exception):
    """Raised when an outbound request can't be built from a ROUTE payload."""


def _pyify(type_code: TypeCode, value: Any) -> Any:
    """Convert a (TypeCode, value) tuple from a decoded payload into a plain
    Python value usable in URL/JSON/header contexts."""
    if type_code == TypeCode.BYTES:
        # Best-effort: try utf-8, otherwise hex. Most params are strings.
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value.hex()
    return value


def _build_outbound_request(
    manifest: Manifest,
    op,
    params_map: dict,
) -> tuple[str, str, dict, dict, dict]:
    """Translate a ROUTE request into (method, url, query, body, headers).

    Param-passing convention (v0):
    - Field ID `n` in `params_map` corresponds to param at index `n-1` in
      `op.params`. So field 1 = first param, field 2 = second, etc.
    - This is what the agent gets back from INSPECT — the manifest's
      param order is the agent's wire-level field ordering.

    Params with `location = PATH` are substituted into `op.path` placeholders.
    Params with `location = QUERY` go into URL query string.
    Params with `location = BODY` go into the JSON body.
    Params with `location = HEADER` go into HTTP headers.

    Required-but-missing params raise _BuildError.
    """
    # Build a name -> python value map by walking the manifest's param order.
    values: dict[str, Any] = {}
    for idx, p in enumerate(op.params, start=1):
        cell = params_map.get(idx)
        if cell is None:
            if p.required:
                raise _BuildError(f"missing required param: {p.key!r}")
            continue
        type_code, raw = cell
        values[p.key] = _pyify(type_code, raw)

    # Substitute path templates.
    path = op.path
    for p in op.params:
        if p.location == ParamLocation.PATH and p.key in values:
            placeholder = "{" + p.out_name + "}"
            path = path.replace(placeholder, str(values[p.key]))

    url = manifest.backend_url.rstrip("/") + (path if path.startswith("/") else "/" + path)

    query: dict[str, Any] = {}
    body: dict[str, Any] = {}
    headers: dict[str, str] = {}
    for p in op.params:
        if p.key not in values:
            continue
        v = values[p.key]
        if p.location == ParamLocation.QUERY:
            query[p.out_name] = v
        elif p.location == ParamLocation.BODY:
            body[p.out_name] = v
        elif p.location == ParamLocation.HEADER:
            headers[p.out_name] = str(v)
        # PATH already substituted above.

    # Inject vendor auth credentials if the manifest declares them.
    if manifest.auth_header:
        # In production: mycd would resolve the vendor's secret from a vault.
        # For Phase 1: we pass through whatever's set in the manifest (the
        # vault integration comes from Prowl as part of the M-series gateway
        # work).
        token = "MYCD_VENDOR_TOKEN"
        prefix = manifest.auth_prefix
        headers[manifest.auth_header] = f"{prefix} {token}".strip() if prefix else token

    return op.method.upper(), url, query, body, headers
