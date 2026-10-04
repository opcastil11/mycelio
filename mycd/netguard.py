"""Outbound-request guard for FETCH (SSRF protection).

FETCH downloads whatever URL an anonymous caller hands it, so every request
the daemon makes on a caller's behalf goes through ``safe_fetch_client()``:

* only ``http``/``https``, only the ports in ``ALLOWED_PORTS`` (80/443 by
  default, ``MYCD_FETCH_ALLOWED_PORTS`` overrides);
* the host is resolved once and **every** answer must be a public address —
  loopback, RFC1918, link-local (cloud metadata 169.254.169.254), CGNAT,
  ULA/link-local IPv6, multicast, reserved, and IPv4 embedded in IPv6
  (mapped / 6to4 / NAT64 / Teredo) are refused;
* the connection is made to *that* validated IP (Host header + SNI keep the
  name), so a 0-TTL DNS answer cannot swap in an internal address between
  check and connect (DNS rebinding);
* the check lives in the transport, so it runs for every redirect hop too.

Unresolvable names fail closed: letting httpx resolve them a second time
would reopen the rebinding window.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
from urllib.parse import urlsplit

import httpx

DNS_TIMEOUT = 3.0
MAX_REDIRECTS = 5

BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata",
    "metadata.google.internal",
    "metadata.goog",
}
BLOCKED_SUFFIXES = (".localhost", ".internal", ".local", ".home.arpa")

_EXTRA_BLOCKED = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
]
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def _allowed_ports() -> frozenset[int]:
    raw = os.environ.get("MYCD_FETCH_ALLOWED_PORTS", "").strip()
    if not raw:
        return frozenset({80, 443})
    return frozenset(int(p) for p in raw.split(",") if p.strip())


ALLOWED_PORTS = _allowed_ports()


class BlockedTarget(ValueError):
    """The URL points somewhere FETCH must not go."""


def ip_is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = ip.ipv4_mapped or ip.sixtofour
        if ip.teredo:
            embedded = ip.teredo[1]
        if ip in _NAT64:
            embedded = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if embedded is not None and not ip_is_public(embedded):
            return False
    if any(ip in net for net in _EXTRA_BLOCKED):
        return False
    return ip.is_global and not ip.is_multicast


def check_url(url: str) -> tuple[str, str, int]:
    """Static checks (no DNS). Returns (scheme, host, port) or raises."""
    try:
        parts = urlsplit(url)
        port = parts.port  # raises ValueError on 'host:junk'
    except ValueError as exc:
        raise BlockedTarget(f"unparseable url: {exc}") from exc
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise BlockedTarget(f"url scheme must be http(s), got {scheme!r}")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise BlockedTarget("url has no host")
    if parts.username or parts.password:
        raise BlockedTarget("credentials in url are not allowed")
    if port is None:
        port = 443 if scheme == "https" else 80
    if port not in ALLOWED_PORTS:
        raise BlockedTarget(f"port {port} not allowed (allowed: {sorted(ALLOWED_PORTS)})")
    if host in BLOCKED_HOSTNAMES or host.endswith(BLOCKED_SUFFIXES):
        raise BlockedTarget(f"host {host!r} is internal")
    literal = _as_ip(host)
    if literal is not None and not ip_is_public(literal):
        raise BlockedTarget(f"address {literal} is private/reserved")
    return scheme, host, port


def _as_ip(host: str):
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    # inet_aton accepts the odd legacy forms (0x7f.1, 2130706433, 127.1)
    # that some resolvers/libcs still honour.
    try:
        return ipaddress.IPv4Address(socket.inet_aton(host))
    except OSError:
        return None


async def resolve_public(host: str, port: int) -> str:
    """Resolve ``host`` and return one address; raise unless all are public."""
    literal = _as_ip(host)
    if literal is not None:
        if not ip_is_public(literal):
            raise BlockedTarget(f"address {literal} is private/reserved")
        return str(literal)
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout=DNS_TIMEOUT
        )
    except (socket.gaierror, asyncio.TimeoutError, OSError, UnicodeError) as exc:
        raise BlockedTarget(f"could not resolve {host!r}") from exc
    if not infos:
        raise BlockedTarget(f"could not resolve {host!r}")
    chosen: str | None = None
    for _fam, _type, _proto, _canon, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0].split("%", 1)[0])
        if not ip_is_public(ip):
            raise BlockedTarget(f"{host!r} resolves to private/reserved address {ip}")
        if chosen is None:
            chosen = str(ip)
    assert chosen is not None
    return chosen


class PinnedTransport(httpx.AsyncHTTPTransport):
    """Validate + connect to the validated IP, on every request (incl. redirects)."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        _scheme, host, port = check_url(str(url))
        ip = await resolve_public(host, port)
        request.headers["Host"] = host if url.port is None else f"{host}:{url.port}"
        request.extensions = {**request.extensions, "sni_hostname": host}
        request.url = url.copy_with(host=ip)
        try:
            return await super().handle_async_request(request)
        finally:
            # httpx resolves a relative Location against request.url; keep the name.
            request.url = url


def safe_fetch_client(*, timeout: float = 15.0, **kwargs) -> httpx.AsyncClient:
    kwargs.setdefault("max_redirects", MAX_REDIRECTS)
    return httpx.AsyncClient(
        transport=PinnedTransport(retries=0),
        timeout=httpx.Timeout(timeout, connect=5.0),
        trust_env=False,
        **kwargs,
    )
