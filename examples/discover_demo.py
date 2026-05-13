"""End-to-end Mycelio demo + wire-bytes comparison vs JSON/REST.

Runs an in-process mycd, opens a client connection, issues PING + DISCOVER,
and prints both the structured results and a byte-count comparison against
an equivalent JSON response.

Run:
    python examples/discover_demo.py
"""
from __future__ import annotations

import json
import socket

import anyio

from mycd.server import MycdServer, ServiceEntry
from mycelio import MycelioClient, generate_keypair


SERVICES = [
    ServiceEntry(service_id=b"\x01" * 8, name="stripe", score=87, cat_flags=0b001, proto_flags=0b00111),
    ServiceEntry(service_id=b"\x02" * 8, name="openai", score=92, cat_flags=0b010, proto_flags=0b00011),
    ServiceEntry(service_id=b"\x03" * 8, name="resend", score=78, cat_flags=0b100, proto_flags=0b00011),
    ServiceEntry(service_id=b"\x04" * 8, name="paypal", score=72, cat_flags=0b001, proto_flags=0b00001),
    ServiceEntry(service_id=b"\x05" * 8, name="anthropic", score=94, cat_flags=0b010, proto_flags=0b00011),
]


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


async def run():
    seed, pub = generate_keypair()
    server = MycdServer(root_seed=seed, services=SERVICES)
    port = _free_port()

    async with anyio.create_task_group() as tg:
        listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=port)
        tg.start_soon(listener.serve, server._handle_connection)
        await anyio.sleep(0.05)

        print(f"mycd listening on 127.0.0.1:{port}")
        print(f"root pubkey: {pub.hex()[:16]}...")
        print()

        async with MycelioClient.connect("127.0.0.1", port, root_pubkey=pub) as cli:
            print("→ PING")
            v = await cli.ping()
            print(f"← negotiated protocol version: {v}")
            print()

            print("→ DISCOVER min_score=80")
            resp = await cli.discover(min_score=80, limit=10)
            print(f"← {len(resp.results)} results (total {resp.total}):")
            for entry in resp.results:
                print(f"    {entry.name:>10}  score={entry.score:3d}  "
                      f"id={entry.service_id.hex()[:8]}...  "
                      f"proto=0b{entry.proto_flags:05b}")
            print()

            # Compare against equivalent REST/JSON
            json_equiv = {
                "results": [
                    {
                        "service_id": e.service_id.hex(),
                        "score": e.score,
                        "category_flags": e.cat_flags,
                        "protocol_flags": e.proto_flags,
                        "name": e.name,
                        "verified": True,
                        "claimed": True,
                    }
                    for e in resp.results
                ],
                "total": resp.total,
            }
            json_bytes = json.dumps(json_equiv).encode()
            print(f"Equivalent JSON: {len(json_bytes)} bytes")
            print(f"(Mycelio wire bytes measured in tests/test_e2e.py)")

        tg.cancel_scope.cancel()


if __name__ == "__main__":
    anyio.run(run)
