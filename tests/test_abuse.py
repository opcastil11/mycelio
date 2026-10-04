"""Daemon anti-abuse limits (mycd.abuse + MycdServer._handle_connection)."""
from __future__ import annotations

import socket
import struct

import anyio
import pytest

from mycd.abuse import AbuseGuard, AbuseLimits
from mycd.server import MycdServer
from mycelio import MycelioClient, generate_keypair
from mycelio.frame import MAGIC, Frame, decode_frame, encode_frame
from mycelio.payload import decode_payload
from mycelio.verbs import Verb


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _limits(**kw) -> AbuseLimits:
    base = dict(trusted=())  # loopback is NOT exempt in these tests
    base.update(kw)
    return AbuseLimits(**base)


async def _start(tg, server, port):
    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=port)
    tg.start_soon(listener.serve, server._handle_connection)
    await anyio.sleep(0.05)


async def _read_goodbye(stream) -> str:
    buf = bytearray()
    with anyio.fail_after(3):
        while True:
            try:
                buf.extend(await stream.receive())
            except (anyio.EndOfStream, anyio.BrokenResourceError):
                break
            try:
                frame, _ = decode_frame(bytes(buf))
                break
            except Exception:
                continue
    frame, _ = decode_frame(bytes(buf))
    assert frame.verb == Verb.GOODBYE
    return decode_payload(frame.payload)[1][1]


def test_guard_counts_connections_and_exempts_trusted():
    g = AbuseGuard(AbuseLimits(max_conns_per_ip=2, trusted=AbuseLimits.from_env().trusted))
    assert g.open("203.0.113.1") is None
    assert g.open("203.0.113.1") is None
    assert g.open("203.0.113.1") is not None
    g.close("203.0.113.1")
    assert g.open("203.0.113.1") is None
    for _ in range(10):
        assert g.open("172.18.0.4") is None  # docker-net shim: exempt


def test_guard_frame_bucket_and_fetch_window():
    g = AbuseGuard(_limits(frame_burst=3, frames_per_sec=1, fetch_per_min=2))
    assert [g.allow_frame("1.1.1.1", now=0) for _ in range(4)] == [True, True, True, False]
    assert g.allow_frame("1.1.1.1", now=1.1)
    assert g.allow_fetch("1.1.1.1", now=0) == 0
    assert g.allow_fetch("1.1.1.1", now=1) == 0
    assert g.allow_fetch("1.1.1.1", now=2) > 0
    assert g.allow_fetch("1.1.1.1", now=61) == 0


async def test_connection_cap_rejects_extra_connections():
    seed, pub = generate_keypair()
    server = MycdServer(root_seed=seed, abuse=AbuseGuard(_limits(max_conns_per_ip=2)))
    port = _free_port()
    async with anyio.create_task_group() as tg:
        await _start(tg, server, port)
        a = await anyio.connect_tcp("127.0.0.1", port)
        b = await anyio.connect_tcp("127.0.0.1", port)
        await anyio.sleep(0.05)
        c = await anyio.connect_tcp("127.0.0.1", port)
        assert "too many concurrent connections" in await _read_goodbye(c)
        await a.aclose()
        await anyio.sleep(0.05)
        async with MycelioClient.connect("127.0.0.1", port, root_pubkey=pub) as cli:
            assert await cli.ping() == 0
        await b.aclose()
        tg.cancel_scope.cancel()


async def test_oversized_frame_header_disconnects():
    seed, _ = generate_keypair()
    server = MycdServer(root_seed=seed, abuse=AbuseGuard(_limits(max_frame=1024)))
    port = _free_port()
    async with anyio.create_task_group() as tg:
        await _start(tg, server, port)
        s = await anyio.connect_tcp("127.0.0.1", port)
        await s.send(MAGIC + struct.pack(">BBII", 0, int(Verb.PING), 1, 10_000_000))
        assert "exceeds limit" in await _read_goodbye(s)
        tg.cancel_scope.cancel()


async def test_idle_timeout_disconnects():
    seed, _ = generate_keypair()
    server = MycdServer(root_seed=seed, abuse=AbuseGuard(_limits(idle_timeout=0.3)))
    port = _free_port()
    async with anyio.create_task_group() as tg:
        await _start(tg, server, port)
        s = await anyio.connect_tcp("127.0.0.1", port)
        assert "idle" in await _read_goodbye(s)
        tg.cancel_scope.cancel()


async def test_frame_flood_disconnects():
    seed, _ = generate_keypair()
    server = MycdServer(root_seed=seed, abuse=AbuseGuard(_limits(frame_burst=5, frames_per_sec=0.1)))
    port = _free_port()
    async with anyio.create_task_group() as tg:
        await _start(tg, server, port)
        s = await anyio.connect_tcp("127.0.0.1", port)
        ping = encode_frame(Frame(verb=Verb.PING, stream_id=1, payload=b""))
        await s.send(ping * 20)
        buf = bytearray()
        with anyio.fail_after(3):
            while True:
                try:
                    buf.extend(await s.receive())
                except (anyio.EndOfStream, anyio.BrokenResourceError):
                    break
        frames = []
        while buf:
            f, n = decode_frame(bytes(buf))
            frames.append(f)
            del buf[:n]
        assert frames[-1].verb == Verb.GOODBYE
        assert "frame rate" in decode_payload(frames[-1].payload)[1][1]
        tg.cancel_scope.cancel()


async def test_fetch_rate_limited_per_ip():
    import httpx

    seed, pub = generate_keypair()

    def handler(req):
        if req.url.path == "/robots.txt":
            return httpx.Response(404)
        return httpx.Response(200, text="<html><body><h1>Hi</h1><p>" + "x " * 200 + "</p></body></html>",
                              headers={"content-type": "text/html"})

    server = MycdServer(
        root_seed=seed,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        jina_fallback=False,
        abuse=AbuseGuard(_limits(fetch_per_min=2)),
    )
    port = _free_port()
    from mycelio import ClientError
    async with anyio.create_task_group() as tg:
        await _start(tg, server, port)
        async with MycelioClient.connect("127.0.0.1", port, root_pubkey=pub) as cli:
            await cli.fetch("https://a.example/1")
            await cli.fetch("https://a.example/2")
            with pytest.raises(ClientError, match="rate_limited"):
                await cli.fetch("https://a.example/3")
        tg.cancel_scope.cancel()
