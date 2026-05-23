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
<a href="/signup">Start free trial</a>
<a href="https://docs.acme.com">Docs</a>
<a href="javascript:void(0)">menu</a>
<a href="#top">back to top</a>
<form action="/subscribe" method="POST" aria-label="Newsletter signup">
  <input name="email" type="email" required />
  <input name="plan" type="text" />
</form>
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
    manifests: list[Manifest] | None = None,
) -> tuple[MycdServer, bytes, int]:
    dir_seed, dir_pub = generate_keypair()
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(mock_web))
    server = MycdServer(
        root_seed=dir_seed,
        http_client=http_client,
        respect_robots=respect_robots,
        jina_fallback=jina_fallback,
        manifests=manifests,
    )
    return server, dir_pub, _free_port()


def _build_signed_stripe_manifest() -> Manifest:
    """A minimal signed manifest pointing at api.stripe.com."""
    dir_seed, dir_pub = generate_keypair()
    vendor_seed, vendor_pub = generate_keypair()
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
                slug="charge", method="POST", path="/v1/charges",
                params=[
                    ParamDef(key="amount", location=ParamLocation.BODY, required=True),
                    ParamDef(key="currency", location=ParamLocation.BODY, required=True),
                ],
            ),
            OpDef(
                slug="get_charge", method="GET", path="/v1/charges/{id}",
                params=[ParamDef(key="id", location=ParamLocation.PATH, required=True)],
            ),
        ],
    )
    sign_vendor(manifest, vendor_seed)
    sign_directory(manifest, dir_seed)
    return manifest


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
            # SAMPLE_HTML carries links + a form → affordances populated (P2).
            assert any(a["kind"] == "link" for a in page.affordances)
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
async def test_fetch_extracts_affordances_from_html():
    """Links + forms surface as typed affordances; junk hrefs are dropped."""
    web = MockWeb()
    web.route("https://acme.com/pricing", httpx.Response(200, html=SAMPLE_HTML))
    server, dir_pub, port = _make_server(web)

    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve, "127.0.0.1", port)
        await anyio.sleep(0.05)
        async with MycelioClient.connect("127.0.0.1", port, root_pubkey=dir_pub) as cli:
            page = await cli.fetch("https://acme.com/pricing")

            kinds = {a["kind"] for a in page.affordances}
            assert "link" in kinds
            assert "form" in kinds

            targets = [a["target"] for a in page.affordances]
            # Relative href resolved against the page URL.
            assert "https://acme.com/signup" in targets
            # Absolute href preserved.
            assert "https://docs.acme.com" in targets
            # Junk schemes / fragment-only links dropped.
            assert not any("javascript:" in t for t in targets)
            assert not any(t.endswith("#top") for t in targets)

            form = next(a for a in page.affordances if a["kind"] == "form")
            assert form["target"] == "https://acme.com/subscribe"
            assert form["hints"]["method"] == "POST"
            field_names = [f["name"] for f in form["hints"]["fields"]]
            assert field_names == ["email", "plan"]
            assert form["hints"]["fields"][0]["required"] is True
            assert form["hints"]["fields"][1]["required"] is False
        tg.cancel_scope.cancel()


@pytest.mark.asyncio
async def test_fetch_no_affordances_on_jina_path():
    """Jina fallback returns content but no affordances (no raw HTML)."""
    web = MockWeb()
    web.route("https://spa.app/", httpx.Response(200, html=SPA_HTML))
    web.route("https://r.jina.ai/https://spa.app/", httpx.Response(200, text=JINA_SAMPLE))
    server, dir_pub, port = _make_server(web)

    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve, "127.0.0.1", port)
        await anyio.sleep(0.05)
        async with MycelioClient.connect("127.0.0.1", port, root_pubkey=dir_pub) as cli:
            page = await cli.fetch("https://spa.app/")
            assert page.affordances == []
        tg.cancel_scope.cancel()


@pytest.mark.asyncio
async def test_fetch_graduates_to_manifest_when_host_registered():
    """Host has a signed manifest → no scraping, return ops as affordances."""
    manifest = _build_signed_stripe_manifest()
    web = MockWeb()
    # Even if the host would serve content, FETCH should short-circuit.
    web.route("https://api.stripe.com/anything", httpx.Response(200, html=SAMPLE_HTML))
    server, dir_pub, port = _make_server(web, manifests=[manifest])

    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve, "127.0.0.1", port)
        await anyio.sleep(0.05)
        # The server's dir_pub differs from the manifest's signing key, so use
        # the server's root_pubkey to verify the envelope SIG.
        async with MycelioClient.connect("127.0.0.1", port, root_pubkey=dir_pub) as cli:
            page = await cli.fetch("https://api.stripe.com/anything")

            assert page.source == "manifest"
            assert page.signed is True
            assert "stripe" in page.content
            assert "/v1/charges" in page.content

            kinds = {a["kind"] for a in page.affordances}
            assert kinds == {"op"}
            slugs = {a["target"] for a in page.affordances}
            assert slugs == {"charge", "get_charge"}

            charge = next(a for a in page.affordances if a["target"] == "charge")
            assert charge["hints"]["method"] == "POST"
            assert charge["hints"]["path"] == "/v1/charges"
        tg.cancel_scope.cancel()

    # No upstream HTTP fetch happened (manifest path skips scraping).
    assert not any("api.stripe.com" in str(c.url) for c in web.calls)


@pytest.mark.asyncio
async def test_fetch_returns_structural_outline():
    """Heuristic page with h1/h2/h3 produces an outline."""
    web = MockWeb()
    sectioned = b"""<!DOCTYPE html><html><body><article>
<h1>Acme Docs</h1>
<p>This is a guide to using the Acme API for processing payments at scale.</p>
<h2>Auth</h2>
<p>Use a bearer token in the Authorization header for every request you make.</p>
<h2>Charges</h2>
<p>Create a charge with POST to the charges endpoint to bill a customer.</p>
</article></body></html>"""
    web.route("https://acme.com/docs", httpx.Response(200, content=sectioned, headers={"content-type": "text/html"}))
    server, dir_pub, port = _make_server(web)

    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve, "127.0.0.1", port)
        await anyio.sleep(0.05)
        async with MycelioClient.connect("127.0.0.1", port, root_pubkey=dir_pub) as cli:
            page = await cli.fetch("https://acme.com/docs")
            ids = [s["id"] for s in page.outline]
            assert ids == ["acme-docs", "auth", "charges"]
            assert all(s["size_bytes"] > 0 for s in page.outline[1:])
            assert page.outline[1]["heading"] == "Auth"
        tg.cancel_scope.cancel()


@pytest.mark.asyncio
async def test_fetch_outline_only_omits_content():
    web = MockWeb()
    sectioned = b"""<html><body>
<h1>Top</h1><p>intro paragraph long enough for trafilatura</p>
<h2>Sub</h2><p>second paragraph long enough for trafilatura</p>
</body></html>"""
    web.route("https://acme.com/", httpx.Response(200, content=sectioned, headers={"content-type": "text/html"}))
    server, dir_pub, port = _make_server(web)

    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve, "127.0.0.1", port)
        await anyio.sleep(0.05)
        async with MycelioClient.connect("127.0.0.1", port, root_pubkey=dir_pub) as cli:
            page = await cli.fetch("https://acme.com/", outline_only=True)
            assert page.content == ""
            assert page.affordances == []
            assert len(page.outline) >= 1
        tg.cancel_scope.cancel()


@pytest.mark.asyncio
async def test_fetch_section_id_narrows_to_one_section():
    web = MockWeb()
    sectioned = b"""<html><body><article>
<h1>Acme</h1>
<p>A long enough intro paragraph for trafilatura to keep around.</p>
<h2>Pricing</h2>
<p>Our pricing tiers start at nineteen dollars per month for solo developers.</p>
<h2>Support</h2>
<p>Email us at support@acme.example for help with your account or billing.</p>
</article></body></html>"""
    web.route("https://acme.com/", httpx.Response(200, content=sectioned, headers={"content-type": "text/html"}))
    server, dir_pub, port = _make_server(web)

    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve, "127.0.0.1", port)
        await anyio.sleep(0.05)
        async with MycelioClient.connect("127.0.0.1", port, root_pubkey=dir_pub) as cli:
            page = await cli.fetch("https://acme.com/", section_id="pricing")
            assert "pricing tiers" in page.content
            assert "support@acme" not in page.content
            assert len(page.outline) == 1
            assert page.outline[0]["id"] == "pricing"
        tg.cancel_scope.cancel()


@pytest.mark.asyncio
async def test_fetch_unknown_section_id_errors():
    web = MockWeb()
    web.route("https://acme.com/pricing", httpx.Response(200, html=SAMPLE_HTML))
    server, dir_pub, port = _make_server(web)

    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve, "127.0.0.1", port)
        await anyio.sleep(0.05)
        async with MycelioClient.connect("127.0.0.1", port, root_pubkey=dir_pub) as cli:
            with pytest.raises(ClientError, match="section_not_found"):
                await cli.fetch("https://acme.com/pricing", section_id="does-not-exist")
        tg.cancel_scope.cancel()


@pytest.mark.asyncio
async def test_fetch_llm_outline_unavailable_when_unconfigured():
    web = MockWeb()
    web.route("https://acme.com/pricing", httpx.Response(200, html=SAMPLE_HTML))
    server, dir_pub, port = _make_server(web)

    # Make sure env doesn't accidentally enable any LLM provider.
    import os
    saved = {k: os.environ.pop(k, None) for k in (
        "MYCD_OUTLINE_LLM_PROVIDER", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
    )}
    # Also block the claude-cli auto-discovery path.
    import shutil as _shutil
    _real_which = _shutil.which
    _shutil.which = lambda _name: None
    try:
        async with anyio.create_task_group() as tg:
            tg.start_soon(server.serve, "127.0.0.1", port)
            await anyio.sleep(0.05)
            async with MycelioClient.connect("127.0.0.1", port, root_pubkey=dir_pub) as cli:
                with pytest.raises(ClientError, match="llm_unavailable"):
                    await cli.fetch("https://acme.com/pricing", outline_mode="llm")
            tg.cancel_scope.cancel()
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v
        _shutil.which = _real_which


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
