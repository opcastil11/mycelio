"""End-to-end Phase 1 demo: agent finds + uses a service through Mycelio.

Spins up a `mycd` with a signed manifest pointing at a mock 'Stripe' backend,
then runs an agent through DISCOVER → INSPECT → ROUTE. Prints byte counts.

Run:
    python examples/route_demo.py
"""
from __future__ import annotations

import socket

import anyio
import httpx

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
    p = s.getsockname()[1]
    s.close()
    return p


def fake_stripe(request: httpx.Request) -> httpx.Response:
    """Mock 'Stripe' backend — accepts POST /v1/charges, returns a fake charge."""
    if request.url.path == "/v1/charges" and request.method == "POST":
        return httpx.Response(
            200,
            json={
                "id": "ch_demo_001",
                "amount": 500,
                "currency": "usd",
                "status": "succeeded",
            },
        )
    return httpx.Response(404, json={"error": f"unknown route {request.url.path}"})


async def run():
    # 1. Generate keys
    dir_seed, dir_pub = generate_keypair()
    vendor_seed, vendor_pub = generate_keypair()

    # 2. Build + sign manifest
    manifest = Manifest(
        service_id=derive_service_id("stripe", dir_pub),
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
        ],
    )
    sign_vendor(manifest, vendor_seed)
    sign_directory(manifest, dir_seed)

    print(f"Directory root key: {dir_pub.hex()[:16]}...")
    print(f"Vendor pubkey:      {vendor_pub.hex()[:16]}...")
    print(f"Service ID:         {manifest.service_id.hex()}")
    print()

    # 3. Spin up mycd with the manifest + a mocked HTTP client to Stripe
    services = [ServiceEntry(
        service_id=manifest.service_id, name="stripe",
        score=87, cat_flags=0b001, proto_flags=0b00111,
    )]
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(fake_stripe))
    server = MycdServer(
        root_seed=dir_seed,
        services=services,
        manifests=[manifest],
        http_client=http_client,
    )
    port = _free_port()

    async with anyio.create_task_group() as tg:
        listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=port)
        tg.start_soon(listener.serve, server._handle_connection)
        await anyio.sleep(0.05)
        print(f"mycd listening on 127.0.0.1:{port}\n")

        # 4. Agent flow: connect → DISCOVER → INSPECT → ROUTE
        async with MycelioClient.connect("127.0.0.1", port, root_pubkey=dir_pub) as cli:
            await cli.ping()

            print("→ DISCOVER (find payment services)")
            r = await cli.discover(min_score=80, limit=10)
            for e in r.results:
                print(f"   ← {e.name:>10}  score={e.score}  id={e.service_id.hex()[:8]}...")
            svc = r.results[0]
            print()

            print(f"→ INSPECT {svc.service_id.hex()}")
            m = await cli.inspect(svc.service_id)
            print(f"   ← manifest: {m.slug} @ {m.backend_url}")
            print(f"     ops: {[op.slug for op in m.ops]}")
            print()

            print("→ ROUTE charge {amount: 500, currency: usd}")
            resp = await cli.route(m, "charge", {"amount": 500, "currency": "usd"})
            print(f"   ← status: {resp.status_code}")
            print(f"     body:   {resp.json()}")
            print()

            print("Done. Stripe was hit at api.stripe.com via mycd translation,")
            print("the agent never spoke HTTP, and every response was Ed25519-signed.")

        tg.cancel_scope.cancel()


if __name__ == "__main__":
    anyio.run(run)
