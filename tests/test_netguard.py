"""SSRF guard (mycd.netguard) + shim rate limiting."""
from __future__ import annotations

import ipaddress

import httpx
import pytest
from starlette.testclient import TestClient

from mycd import netguard
from mycd.extractor import BadURLError, fetch_and_extract
from mycd.netguard import BlockedTarget, check_url, ip_is_public, resolve_public


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1", "10.128.0.5", "172.17.0.2", "192.168.1.1", "169.254.169.254",
        "100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "fc00::1", "fd12::1", "fe80::1",
        "::ffff:127.0.0.1", "::ffff:169.254.169.254", "2002:a00:1::", "64:ff9b::a9fe:a9fe",
    ],
)
def test_private_ips_rejected(ip):
    assert not ip_is_public(ipaddress.ip_address(ip))


@pytest.mark.parametrize("ip", ["93.184.215.14", "8.8.8.8", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"])
def test_public_ips_allowed(ip):
    assert ip_is_public(ipaddress.ip_address(ip))


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/computeMetadata/v1/",
        "http://metadata.google.internal/",
        "http://127.0.0.1/",
        "http://localhost/",
        "http://[::1]/",
        "http://2130706433/",
        "http://0x7f.1/",
        "http://10.128.0.5/",
        "https://example.com:4242/",
        "http://example.com:8080/",
        "https://host:transform/x",
        "ftp://example.com/",
        "file:///etc/passwd",
        "http://user:pw@example.com/",
    ],
)
def test_check_url_rejects(url):
    with pytest.raises(BlockedTarget):
        check_url(url)


def test_check_url_accepts_public():
    assert check_url("https://example.com/a?b=1") == ("https", "example.com", 443)
    assert check_url("http://example.com:80/") == ("http", "example.com", 80)


async def test_resolve_public_rejects_private_answers(monkeypatch):
    async def fake_getaddrinfo(host, port, type=0):
        return [(2, 1, 6, "", ("10.0.0.7", port))]

    import asyncio
    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(BlockedTarget):
        await resolve_public("evil.example", 443)


async def test_resolve_unresolvable_fails_closed():
    with pytest.raises(BlockedTarget):
        await resolve_public("does-not-exist.invalid", 443)


async def test_redirect_to_private_is_blocked_and_no_jina(monkeypatch):
    """A public host 302-ing to the metadata server must fail on that hop,
    with no Jina fallback, and the private hop must never be sent."""
    sent: list[str] = []

    async def fake_resolve(host, port):
        if host == "public.example":
            return "93.184.215.14"
        return await resolve_public(host, port)

    class Recorder(netguard.PinnedTransport):
        async def handle_async_request(self, request):
            # run the real guard first, then answer without the network
            netguard.check_url(str(request.url))
            await fake_resolve(request.url.host, request.url.port or 80)
            sent.append(str(request.url))
            if request.url.path == "/robots.txt":
                return httpx.Response(404, request=request)
            return httpx.Response(
                302, headers={"Location": "http://169.254.169.254/computeMetadata/v1/"},
                request=request,
            )

    client = httpx.AsyncClient(transport=Recorder())
    with pytest.raises(BadURLError):
        await fetch_and_extract("http://public.example/", http_client=client)
    assert all("169.254" not in u for u in sent)
    assert not any("jina" in u for u in sent)


async def test_body_cap_enforced_while_streaming():
    big = b"<html><body>" + b"a" * 400_000 + b"</body></html>"

    def handler(request):
        if request.url.path == "/robots.txt":
            return httpx.Response(404)
        return httpx.Response(200, content=big, headers={"content-type": "text/html"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    from mycd.extractor import TooLargeError
    with pytest.raises(TooLargeError):
        await fetch_and_extract("https://big.example/", http_client=client, jina_fallback=False)


# --------------------------------------------------------------------------
# Shim: rate limit + client IP + static URL check
# --------------------------------------------------------------------------


@pytest.fixture
def shim(monkeypatch):
    from mycd import http_shim

    monkeypatch.setattr(http_shim, "PER_IP", http_shim.SlidingWindow(5, 60))
    monkeypatch.setattr(http_shim, "GLOBAL", http_shim.SlidingWindow(1000, 60))

    async def fake_fetch(url, **kw):
        return http_shim.PlainTextResponse("ok")

    monkeypatch.setattr(http_shim, "_do_fetch", fake_fetch)
    return http_shim


def test_rate_limit_429_with_retry_after(shim):
    c = TestClient(shim.app)  # peer "testclient" → untrusted, XFF ignored
    codes = [c.get("/r/https://example.com/").status_code for _ in range(8)]
    assert codes[:5] == [200] * 5 and codes[5:] == [429] * 3
    r = c.get("/r/https://example.com/")
    assert int(r.headers["retry-after"]) >= 1
    assert c.get("/healthz").status_code == 200


def test_untrusted_peer_cannot_spoof_xff(shim):
    c = TestClient(shim.app)
    codes = [
        c.get("/r/https://example.com/", headers={"X-Forwarded-For": f"1.2.3.{i}"}).status_code
        for i in range(8)
    ]
    assert codes.count(429) == 3


def test_client_ip_trusts_xff_only_from_proxy(shim):
    class Req:
        def __init__(self, peer, xff):
            self.client = type("C", (), {"host": peer})()
            self.headers = {"x-forwarded-for": xff}

    assert shim.client_ip(Req("172.18.0.5", "203.0.113.9")) == "203.0.113.9"
    assert shim.client_ip(Req("172.18.0.5", "6.6.6.6, 203.0.113.9")) == "203.0.113.9"
    assert shim.client_ip(Req("198.51.100.1", "203.0.113.9")) == "198.51.100.1"


def test_shim_rejects_private_literal_before_daemon():
    from mycd import http_shim

    c = TestClient(http_shim.app)
    for u in ("http://169.254.169.254/x", "http://127.0.0.1:4242/", "http://10.128.0.5:8000/"):
        r = c.get(f"/r/{u}")
        assert r.status_code == 400, (u, r.text)
