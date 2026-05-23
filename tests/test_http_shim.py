"""HTTP shim: starts an in-process mycd, talks to it through MycelioClient.

The shim is just a translator (HTTP → Mycelio FETCH → HTTP response), so
these tests assert it preserves error codes, content type negotiation,
and the affordance payload.
"""
from __future__ import annotations

import os
import socket

import anyio
import httpx
import pytest

from mycd.server import MycdServer
from mycelio import generate_keypair


HTML = """<!DOCTYPE html><html><body>
<article>
<h1>Hello</h1>
<p>This is a real-ish paragraph with enough content for trafilatura to
keep it. Trafilatura needs a minimum amount of text to consider a region
the main content, and a single short sentence won't always cut it.</p>
<a href="/next">go next</a>
</article>
</body></html>"""


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class FakeUpstream:
    def __init__(self) -> None:
        self.calls: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        key = str(request.url)
        if key.endswith("/robots.txt"):
            return httpx.Response(404)
        if key == "https://example.test/":
            return httpx.Response(200, html=HTML)
        return httpx.Response(404, text=f"no mock for {key}")


@pytest.fixture(autouse=True)
def reset_shim_env():
    keys = ["MYCD_HOST", "MYCD_PORT", "MYCD_ROOT_PUBKEY"]
    saved = {k: os.environ.get(k) for k in keys}
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


@pytest.mark.asyncio
async def test_shim_returns_markdown_for_text_accept():
    dir_seed, dir_pub = generate_keypair()
    upstream = FakeUpstream()
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    server = MycdServer(
        root_seed=dir_seed,
        http_client=http_client,
        respect_robots=False,
        jina_fallback=False,
    )
    port = _free_port()

    os.environ["MYCD_HOST"] = "127.0.0.1"
    os.environ["MYCD_PORT"] = str(port)
    os.environ["MYCD_ROOT_PUBKEY"] = dir_pub.hex()
    # Import after env is set; module reads env lazily inside _config().
    from mycd.http_shim import app

    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve, "127.0.0.1", port)
        await anyio.sleep(0.05)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://shim") as cli:
            r = await cli.get("/r/https://example.test/")
            assert r.status_code == 200
            assert "text/markdown" in r.headers["content-type"]
            assert "Hello" in r.text
            assert r.headers["X-Mycelio-Source"] == "heuristic"
            assert r.headers["X-Mycelio-Signed"] == "false"
            assert int(r.headers["X-Mycelio-Affordances"]) >= 1

            # JSON form
            r = await cli.get("/r/https://example.test/", headers={"Accept": "application/json"})
            assert r.status_code == 200
            body = r.json()
            assert body["source"] == "heuristic"
            assert any(a["kind"] == "link" for a in body["affordances"])

        tg.cancel_scope.cancel()


@pytest.mark.asyncio
async def test_shim_query_param_form():
    dir_seed, dir_pub = generate_keypair()
    upstream = FakeUpstream()
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    server = MycdServer(
        root_seed=dir_seed, http_client=http_client,
        respect_robots=False, jina_fallback=False,
    )
    port = _free_port()
    os.environ.update({
        "MYCD_HOST": "127.0.0.1",
        "MYCD_PORT": str(port),
        "MYCD_ROOT_PUBKEY": dir_pub.hex(),
    })
    from mycd.http_shim import app

    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve, "127.0.0.1", port)
        await anyio.sleep(0.05)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://shim") as cli:
            r = await cli.get("/r", params={"url": "https://example.test/"})
            assert r.status_code == 200
            assert "Hello" in r.text
        tg.cancel_scope.cancel()


@pytest.mark.asyncio
async def test_shim_rejects_non_http_url():
    dir_seed, dir_pub = generate_keypair()
    server = MycdServer(root_seed=dir_seed, respect_robots=False, jina_fallback=False)
    port = _free_port()
    os.environ.update({
        "MYCD_HOST": "127.0.0.1",
        "MYCD_PORT": str(port),
        "MYCD_ROOT_PUBKEY": dir_pub.hex(),
    })
    from mycd.http_shim import app

    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve, "127.0.0.1", port)
        await anyio.sleep(0.05)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://shim") as cli:
            r = await cli.get("/r/ftp://example.test/")
            assert r.status_code == 400
            assert "bad_url" in r.text
        tg.cancel_scope.cancel()


@pytest.mark.asyncio
async def test_shim_surfaces_fetch_failed_code_and_status():
    dir_seed, dir_pub = generate_keypair()
    upstream = FakeUpstream()  # everything 404
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    server = MycdServer(
        root_seed=dir_seed, http_client=http_client,
        respect_robots=False, jina_fallback=False,
    )
    port = _free_port()
    os.environ.update({
        "MYCD_HOST": "127.0.0.1",
        "MYCD_PORT": str(port),
        "MYCD_ROOT_PUBKEY": dir_pub.hex(),
    })
    from mycd.http_shim import app

    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve, "127.0.0.1", port)
        await anyio.sleep(0.05)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://shim") as cli:
            r = await cli.get("/r/https://gone.test/", headers={"Accept": "application/json"})
            assert r.status_code == 502
            assert r.json()["error"] == "fetch_failed"
        tg.cancel_scope.cancel()


@pytest.mark.asyncio
async def test_shim_healthz():
    from mycd.http_shim import app
    os.environ["MYCD_ROOT_PUBKEY"] = "00" * 32  # not used for /healthz
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://shim") as cli:
        r = await cli.get("/healthz")
        assert r.status_code == 200
        assert r.text.strip() == "ok"
