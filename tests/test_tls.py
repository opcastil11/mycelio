"""End-to-end TLS: server wraps in TLSListener, client wraps in TLSStream."""
from __future__ import annotations

import socket

import anyio
import pytest

from mycd.server import MycdServer, ServiceEntry
from mycelio import MycelioClient, generate_keypair
from mycelio.tls_dev import make_client_context_trusting, make_server_context


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.mark.asyncio
async def test_tls_round_trip_ping_and_discover():
    """Same Phase 0 flow, but TLS-wrapped end to end."""
    seed, pub = generate_keypair()
    server_ctx, cert_pem = make_server_context("localhost")
    client_ctx = make_client_context_trusting(cert_pem)

    services = [
        ServiceEntry(service_id=b"\xab" * 8, name="testsvc", score=80, cat_flags=1, proto_flags=1),
    ]
    server = MycdServer(root_seed=seed, services=services, ssl_context=server_ctx)
    port = _free_port()

    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve, "127.0.0.1", port)
        await anyio.sleep(0.1)  # listener bind

        async with MycelioClient.connect(
            "127.0.0.1", port, root_pubkey=pub, ssl_context=client_ctx
        ) as cli:
            assert await cli.ping() == 0
            resp = await cli.discover(min_score=50)
            assert [e.name for e in resp.results] == ["testsvc"]

        tg.cancel_scope.cancel()
