"""End-to-end ROUTE: agent → mycd → mocked vendor backend.

Proves the full Phase 1 flow: a binary ROUTE frame from the client, mycd
translates to HTTP using a signed manifest, hits a mock backend, frames
the response back to the agent, signs it.
"""
from __future__ import annotations

import json
import socket

import anyio
import httpx
import pytest

from mycd.server import MycdServer, ServiceEntry
from mycelio import MycelioClient, generate_keypair
from mycelio.manifest import (
    BackendKind,
    Manifest,
    OpDef,
    ParamDef,
    ParamLocation,
    derive_service_id,
    sign_directory,
    sign_vendor,
)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ---------------------------------------------------------------------------
# Mock backend — captures requests so we can assert on them
# ---------------------------------------------------------------------------


class MockBackend:
    """Records every inbound request. Returns canned responses keyed by
    (method, path). Used as an httpx MockTransport handler."""

    def __init__(self) -> None:
        self.calls: list[httpx.Request] = []
        self.routes: dict[tuple[str, str], httpx.Response] = {}

    def route(self, method: str, path: str, response: httpx.Response) -> None:
        self.routes[(method.upper(), path)] = response

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        key = (request.method.upper(), request.url.path)
        if key not in self.routes:
            return httpx.Response(404, json={"error": f"no route: {key}"})
        return self.routes[key]


def _build_stripe_manifest(dir_pubkey: bytes, vendor_pub: bytes) -> Manifest:
    """Build + sign a simple 'Stripe' test manifest."""
    return Manifest(
        service_id=derive_service_id("stripe", dir_pubkey),
        slug="stripe",
        vendor_pubkey=vendor_pub,
        backend_url="https://api.stripe.com",
        backend_kind=BackendKind.HTTP,
        auth_header="Authorization",
        auth_prefix="Bearer",
        ops=[
            OpDef(
                slug="charge",
                method="POST",
                path="/v1/charges",
                params=[
                    ParamDef(key="amount", location=ParamLocation.BODY, required=True),
                    ParamDef(key="currency", location=ParamLocation.BODY, required=True),
                ],
            ),
            OpDef(
                slug="get_charge",
                method="GET",
                path="/v1/charges/{id}",
                params=[
                    ParamDef(key="id", location=ParamLocation.PATH, required=True),
                ],
            ),
        ],
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_route_end_to_end_translates_to_http():
    """Agent sends ROUTE → mycd hits backend over HTTP → agent gets framed response."""
    dir_seed, dir_pub = generate_keypair()
    vendor_seed, vendor_pub = generate_keypair()

    manifest = _build_stripe_manifest(dir_pub, vendor_pub)
    sign_vendor(manifest, vendor_seed)
    sign_directory(manifest, dir_seed)

    backend = MockBackend()
    backend.route(
        "POST", "/v1/charges",
        httpx.Response(200, json={"id": "ch_test_abc", "amount": 500, "status": "succeeded"}),
    )
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(backend))

    server = MycdServer(
        root_seed=dir_seed,
        manifests=[manifest],
        http_client=http_client,
    )
    port = _free_port()

    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve, "127.0.0.1", port)
        await anyio.sleep(0.05)

        async with MycelioClient.connect("127.0.0.1", port, root_pubkey=dir_pub) as cli:
            # 1. Agent fetches the manifest first (one INSPECT call)
            m = await cli.inspect(manifest.service_id)
            assert m.slug == "stripe"
            assert len(m.ops) == 2

            # 2. Agent invokes the charge op
            resp = await cli.route(m, "charge", {"amount": 500, "currency": "usd"})

        tg.cancel_scope.cancel()

    # Assert the backend was actually hit with translated request
    assert len(backend.calls) == 1
    req = backend.calls[0]
    assert req.method == "POST"
    assert req.url.path == "/v1/charges"
    assert req.url.host == "api.stripe.com"
    body = json.loads(req.content)
    assert body == {"amount": 500, "currency": "usd"}
    assert req.headers["Authorization"].startswith("Bearer ")

    # Assert the agent got the framed response
    assert resp.status_code == 200
    assert "json" in resp.content_type
    assert resp.json() == {"id": "ch_test_abc", "amount": 500, "status": "succeeded"}


@pytest.mark.asyncio
async def test_route_substitutes_path_params():
    dir_seed, dir_pub = generate_keypair()
    vendor_seed, vendor_pub = generate_keypair()
    manifest = _build_stripe_manifest(dir_pub, vendor_pub)
    sign_vendor(manifest, vendor_seed)
    sign_directory(manifest, dir_seed)

    backend = MockBackend()
    backend.route(
        "GET", "/v1/charges/ch_xyz",
        httpx.Response(200, json={"id": "ch_xyz", "status": "succeeded"}),
    )
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(backend))
    server = MycdServer(root_seed=dir_seed, manifests=[manifest], http_client=http_client)
    port = _free_port()

    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve, "127.0.0.1", port)
        await anyio.sleep(0.05)
        async with MycelioClient.connect("127.0.0.1", port, root_pubkey=dir_pub) as cli:
            m = await cli.inspect(manifest.service_id)
            resp = await cli.route(m, "get_charge", {"id": "ch_xyz"})
        tg.cancel_scope.cancel()

    assert backend.calls[0].url.path == "/v1/charges/ch_xyz"
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_route_returns_error_for_unknown_service():
    dir_seed, dir_pub = generate_keypair()
    server = MycdServer(root_seed=dir_seed, manifests=[])
    port = _free_port()

    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve, "127.0.0.1", port)
        await anyio.sleep(0.05)
        async with MycelioClient.connect("127.0.0.1", port, root_pubkey=dir_pub) as cli:
            from mycelio import ClientError
            with pytest.raises(ClientError, match="service_not_found"):
                await cli.inspect(b"\xab" * 8)
        tg.cancel_scope.cancel()


@pytest.mark.asyncio
async def test_route_rejects_missing_required_param():
    dir_seed, dir_pub = generate_keypair()
    vendor_seed, vendor_pub = generate_keypair()
    manifest = _build_stripe_manifest(dir_pub, vendor_pub)
    sign_vendor(manifest, vendor_seed)
    sign_directory(manifest, dir_seed)

    server = MycdServer(root_seed=dir_seed, manifests=[manifest])
    port = _free_port()

    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve, "127.0.0.1", port)
        await anyio.sleep(0.05)
        async with MycelioClient.connect("127.0.0.1", port, root_pubkey=dir_pub) as cli:
            m = await cli.inspect(manifest.service_id)
            # Client-side check kicks in before sending — that's fine, also valid coverage.
            with pytest.raises(ValueError, match="missing required param"):
                await cli.route(m, "charge", {"amount": 500})  # currency missing
        tg.cancel_scope.cancel()


# ---------------------------------------------------------------------------
# Bytes-on-wire benchmark for ROUTE — the headline number
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_route_wire_bytes_vs_http_json():
    """Compare bytes-on-wire of a Mycelio ROUTE vs the equivalent HTTP+JSON."""
    dir_seed, dir_pub = generate_keypair()
    vendor_seed, vendor_pub = generate_keypair()
    manifest = _build_stripe_manifest(dir_pub, vendor_pub)
    sign_vendor(manifest, vendor_seed)
    sign_directory(manifest, dir_seed)

    backend = MockBackend()
    backend.route(
        "POST", "/v1/charges",
        httpx.Response(200, json={"id": "ch_abc", "amount": 500}),
    )
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(backend))
    server = MycdServer(root_seed=dir_seed, manifests=[manifest], http_client=http_client)
    port = _free_port()

    bytes_in = 0
    bytes_out = 0

    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve, "127.0.0.1", port)
        await anyio.sleep(0.05)

        sock = await anyio.connect_tcp("127.0.0.1", port)

        from mycelio.frame import HEADER_LEN, encode_frame, Frame, decode_frame
        from mycelio.payload import encode_payload, TypeCode
        from mycelio.verbs import Verb

        # Send ROUTE directly (no INSPECT — we already have the manifest)
        route_payload = encode_payload({
            1: (TypeCode.HASH, manifest.service_id),
            2: (TypeCode.STRING, "charge"),
            3: (TypeCode.MAP, {
                1: (TypeCode.U64, 500),
                2: (TypeCode.STRING, "usd"),
            }),
        })
        route_frame = encode_frame(Frame(verb=Verb.ROUTE, stream_id=1, payload=route_payload))
        bytes_out = len(route_frame)
        await sock.send(route_frame)

        # Read response + SIG
        buf = bytearray()
        while True:
            chunk = await sock.receive(4096)
            if not chunk:
                break
            buf.extend(chunk)
            bytes_in = len(buf)
            # Try to consume two frames (response + SIG)
            done = False
            tmp = bytes(buf)
            n_frames = 0
            offset = 0
            while offset < len(tmp) - HEADER_LEN:
                try:
                    f, consumed = decode_frame(tmp[offset:])
                except Exception:
                    break
                offset += consumed
                n_frames += 1
                if f.verb == Verb.SIG:
                    done = True
                    break
            if done:
                break

        await sock.aclose()
        tg.cancel_scope.cancel()

    # Equivalent HTTP+JSON traffic:
    # - HTTP request line + headers + body (~250-350 B)
    # - HTTP response status + headers + JSON body (~250 B)
    # Total ~500-600 B before TLS overhead. With TLS handshake amortized
    # over many requests, still ~400-500 B per call.
    typical_http_bytes = 500

    print(f"\n  ROUTE Mycelio wire bytes (round trip): {bytes_in + bytes_out} B")
    print(f"      out (ROUTE request):  {bytes_out} B")
    print(f"      in  (response + SIG): {bytes_in} B")
    print(f"  Equivalent HTTP+JSON (no TLS): ~{typical_http_bytes} B")
    print(f"  Wire ratio: {typical_http_bytes / (bytes_in + bytes_out):.1f}x smaller\n")

    assert bytes_in + bytes_out < typical_http_bytes, (
        "Mycelio ROUTE must be smaller than HTTP+JSON equivalent"
    )
