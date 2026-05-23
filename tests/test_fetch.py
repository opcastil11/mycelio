"""End-to-end FETCH: agent → mycd → mocked external sources.

Covers the two-tier extraction (trafilatura local, Jina fallback) plus
the response envelope, the in-memory cache, error code surfacing, and
the robots.txt gate.
"""
from __future__ import annotations

import socket

import anyio
import httpx
import pytest

from mycd.server import MycdServer
from mycelio import ClientError, MycelioClient, generate_keypair

SAMPLE_HTML = """<!DOCTYPE html>
<html>
<head><title>Acme Pricing</title></head>
<body>
<header><nav>Home About</nav></header>
<main>
<article>
<h1>Pricing Plans</h1>
<p>Choose the plan that fits your team. We offer transparent, simple
pricing for projects of every size.</p>
<h2>Starter</h2>
<p>For solo developers and small projects. Nineteen dollars per month
with all core features included and email support.</p>
<h2>Team</h2>
<p>For growing teams. Ninety-nine dollars per month with priority
support and advanced analytics included.</p>
</article>
</main>
<footer>(c) Acme 2026</footer>
</body>
</html>"""

SPA_HTML = "<html><body><div id='root'></div></body></html>"
JINA_SAMPLE = "# Pricing Plans\n\nChoose the plan that fits your team."


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class MockWeb:
    """Routes responses by exact URL string. Treats unrouted /robots.txt
    as 404 (= no restrictions), and any other unrouted URL as 404."""

    def __init__(self) -> None:
        self.calls: list[httpx.Request] = []
        self.routes: dict[str, httpx.Response] = {}

    def route(self, url: str, response: httpx.Response) -> None:
        self.routes[url] = response

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        key = str(request.url)
        if key in self.routes:
            return self.routes[key]
        if key.endswith("/robots.txt"):
            return httpx.Response(404)
        return httpx.Response(404, text=f"no mock for {key}")


def _make_server(
    mock_web: MockWeb,
    *,
    respect_robots: bool = False,
    jina_fallback: bool = True,
) -> tuple[MycdServer, bytes, int]:
    dir_seed, dir_pub = generate_keypair()
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(mock_web))
    server = MycdServer(
        root_seed=dir_seed,
        http_client=http_client,
        respect_robots=respect_robots,
        jina_fallback=jina_fallback,
    )
    return server, dir_pub, _free_port()


@pytest.mark.asyncio
async def test_fetch_local_extraction_happy_path():
    """trafilatura extracts a normal HTML page — no Jina fallback needed."""
    web = MockWeb()
    web.route("https://acme.com/pricing", httpx.Response(200, html=SAMPLE_HTML))
    server, dir_pub, port = _make_server(web)

    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve, "127.0.0.1", port)
        await anyio.sleep(0.05)
        async with MycelioClient.connect("127.0.0.1", port, root_pubkey=dir_pub) as cli:
            page = await cli.fetch("https://acme.com/pricing")
            assert page.source == "heuristic"
            assert page.signed is False
            assert "Pricing Plans" in page.content
            assert "Starter" in page.content
            assert page.ttl_seconds > 0
            assert page.fetched_at > 0
            assert page.affordances == []  # P1 — empty
        tg.cancel_scope.cancel()

    # No Jina hit on the local-success path
    assert not any("r.jina.ai" in str(c.url) for c in web.calls)


@pytest.mark.asyncio
async def test_fetch_falls_back_to_jina_when_trafilatura_empty():
    """SPA-style page (trafilatura yields nothing) triggers Jina fallback."""
    web = MockWeb()
    web.route("https://spa.app/", httpx.Response(200, html=SPA_HTML))
    web.route(
        "https://r.jina.ai/https://spa.app/",
        httpx.Response(200, text=JINA_SAMPLE),
    )
    server, dir_pub, port = _make_server(web)

    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve, "127.0.0.1", port)
        await anyio.sleep(0.05)
        async with MycelioClient.connect("127.0.0.1", port, root_pubkey=dir_pub) as cli:
            page = await cli.fetch("https://spa.app/")
            assert "Pricing Plans" in page.content
            assert page.source == "heuristic"
        tg.cancel_scope.cancel()

    jina_hits = [c for c in web.calls if "r.jina.ai" in str(c.url)]
    assert len(jina_hits) == 1


@pytest.mark.asyncio
async def test_fetch_caches_responses():
    """Second call for the same URL is served from the daemon cache."""
    web = MockWeb()
    web.route("https://acme.com/", httpx.Response(200, html=SAMPLE_HTML))
    server, dir_pub, port = _make_server(web)

    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve, "127.0.0.1", port)
        await anyio.sleep(0.05)
        async with MycelioClient.connect("127.0.0.1", port, root_pubkey=dir_pub) as cli:
            p1 = await cli.fetch("https://acme.com/")
            p2 = await cli.fetch("https://acme.com/")
            assert p1.content == p2.content
            assert p2.ttl_seconds <= p1.ttl_seconds  # countdown
        tg.cancel_scope.cancel()

    upstream = [c for c in web.calls if str(c.url) == "https://acme.com/"]
    assert len(upstream) == 1  # cache prevented the second fetch


@pytest.mark.asyncio
async def test_fetch_rejects_bad_url():
    web = MockWeb()
    server, dir_pub, port = _make_server(web)
    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve, "127.0.0.1", port)
        await anyio.sleep(0.05)
        async with MycelioClient.connect("127.0.0.1", port, root_pubkey=dir_pub) as cli:
            with pytest.raises(ClientError, match="bad_url"):
                await cli.fetch("not-a-url")
        tg.cancel_scope.cancel()


@pytest.mark.asyncio
async def test_fetch_surfaces_fetch_failed_when_both_paths_fail():
    """Local fetch 404 → Jina fallback also 404 → fetch_failed."""
    web = MockWeb()  # default 404 for everything
    server, dir_pub, port = _make_server(web)
    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve, "127.0.0.1", port)
        await anyio.sleep(0.05)
        async with MycelioClient.connect("127.0.0.1", port, root_pubkey=dir_pub) as cli:
            with pytest.raises(ClientError, match="fetch_failed"):
                await cli.fetch("https://nowhere.example/")
        tg.cancel_scope.cancel()


@pytest.mark.asyncio
async def test_fetch_respects_robots_txt():
    web = MockWeb()
    web.route(
        "https://acme.com/robots.txt",
        httpx.Response(200, text="User-agent: *\nDisallow: /private"),
    )
    web.route("https://acme.com/private/secret", httpx.Response(200, html=SAMPLE_HTML))
    server, dir_pub, port = _make_server(web, respect_robots=True)

    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve, "127.0.0.1", port)
        await anyio.sleep(0.05)
        async with MycelioClient.connect("127.0.0.1", port, root_pubkey=dir_pub) as cli:
            with pytest.raises(ClientError, match="robots_blocked"):
                await cli.fetch("https://acme.com/private/secret")
            # Sibling allowed path under same host still works.
            web.route("https://acme.com/public", httpx.Response(200, html=SAMPLE_HTML))
            allowed = await cli.fetch("https://acme.com/public")
            assert "Pricing" in allowed.content
        tg.cancel_scope.cancel()


@pytest.mark.asyncio
async def test_fetch_disables_jina_when_flag_off():
    """When jina_fallback=False, trafilatura-empty raises extraction_empty."""
    web = MockWeb()
    web.route("https://spa.app/", httpx.Response(200, html=SPA_HTML))
    server, dir_pub, port = _make_server(web, jina_fallback=False)

    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve, "127.0.0.1", port)
        await anyio.sleep(0.05)
        async with MycelioClient.connect("127.0.0.1", port, root_pubkey=dir_pub) as cli:
            with pytest.raises(ClientError, match="extraction_empty"):
                await cli.fetch("https://spa.app/")
        tg.cancel_scope.cancel()

    assert not any("r.jina.ai" in str(c.url) for c in web.calls)
