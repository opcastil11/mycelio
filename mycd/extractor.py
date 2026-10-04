"""HTML → Markdown extraction for the FETCH verb.

Two-tier strategy:

1. Local fetch + `trafilatura` extraction (fast, free, no external dep).
   Handles static HTML — docs, blogs, e-commerce. ~1 ms per page.
2. If local extraction is empty or the content isn't HTML (PDFs, JS-only
   SPAs, anti-bot), fall back to **Jina Reader** at `r.jina.ai/<url>`.
   Slower (~5–8 s) but handles JS rendering, PDFs, and image captioning.

Both engines are pluggable via constructor args — tests inject mocked
httpx transports for either path.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser

import httpx
import trafilatura

from mycd.affordances import parse_affordances
from mycd.netguard import BlockedTarget, check_url
from mycd.outline import Section, structural_sections

DEFAULT_MAX_BYTES = 256 * 1024
HARD_MAX_BYTES = 2 * 1024 * 1024  # ceiling for a caller-supplied max_bytes
ROBOTS_MAX_BYTES = 512 * 1024
DEFAULT_USER_AGENT = "MycelioFetch/0 (+https://mycelio.prowl.world)"
ROBOTS_TIMEOUT = 5.0
FETCH_TIMEOUT = 15.0
JINA_TIMEOUT = 30.0
JINA_READER_BASE = "https://r.jina.ai"


@dataclass
class ExtractedContent:
    """A successful extraction. `final_url` reflects any redirects.
    `engine` is which path succeeded — informational, not on the wire.
    `affordances` is empty on the Jina path (we don't have raw HTML).
    `sections` is the structural outline (also empty on Jina path).
    `llm_sections` is populated lazily by the daemon on demand."""

    content: str
    fetched_at: int
    final_url: str
    engine: str  # "trafilatura" | "jina"
    affordances: list[dict[str, Any]] = field(default_factory=list)
    sections: list[Section] = field(default_factory=list)
    llm_sections: list[Section] | None = None


# ---------------------------------------------------------------------------
# Errors — `code` matches the wire error code surfaced by mycd.
# ---------------------------------------------------------------------------


class ExtractorError(Exception):
    code = "fetch_failed"

    def __init__(self, message: str = "") -> None:
        super().__init__(message)
        self.message = message


class BadURLError(ExtractorError):
    code = "bad_url"


class RobotsBlockedError(ExtractorError):
    code = "robots_blocked"


class FetchFailedError(ExtractorError):
    code = "fetch_failed"


class ExtractionEmptyError(ExtractorError):
    code = "extraction_empty"


class TooLargeError(ExtractorError):
    code = "too_large"


# ---------------------------------------------------------------------------
# URL + robots helpers
# ---------------------------------------------------------------------------


def _validate_url(url: str) -> tuple[str, str]:
    """Return (scheme, netloc) or raise BadURLError.

    Static SSRF checks (scheme, port allow-list, internal names, private IP
    literals) run here; DNS-level checks run per request in the transport
    (see ``mycd.netguard``). A malformed port used to raise a bare
    ValueError deep inside httpx and take the whole daemon down.
    """
    try:
        check_url(url)
    except BlockedTarget as exc:
        raise BadURLError(str(exc)) from exc
    parsed = urlparse(url)
    return parsed.scheme, parsed.netloc


async def _read_capped(response: httpx.Response, cap: int) -> bytes:
    """Read a streamed body, aborting as soon as it exceeds ``cap`` bytes."""
    declared = response.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > cap:
        raise TooLargeError(f"response {declared} bytes exceeds cap {cap}")
    buf = bytearray()
    async for chunk in response.aiter_bytes():
        buf.extend(chunk)
        if len(buf) > cap:
            raise TooLargeError(f"response exceeds cap {cap} bytes")
    return bytes(buf)


async def _check_robots(
    url: str,
    *,
    http_client: httpx.AsyncClient,
    robots_cache: dict[str, RobotFileParser] | None,
    user_agent: str,
) -> None:
    scheme, host = _validate_url(url)
    cache_key = f"{scheme}://{host}"
    rp = robots_cache.get(cache_key) if robots_cache is not None else None
    if rp is None:
        rp = RobotFileParser()
        try:
            async with http_client.stream(
                "GET",
                f"{cache_key}/robots.txt",
                follow_redirects=True,
                timeout=ROBOTS_TIMEOUT,
            ) as r:
                if r.status_code == 200:
                    raw = await _read_capped(r, ROBOTS_MAX_BYTES)
                    rp.parse(raw.decode("utf-8", "replace").splitlines())
                else:
                    rp.parse([])  # no robots.txt → fully allowed
        except (httpx.HTTPError, TooLargeError):
            rp.parse([])  # be permissive on robots fetch errors
        if robots_cache is not None:
            robots_cache[cache_key] = rp
    if not rp.can_fetch(user_agent, url):
        raise RobotsBlockedError(f"robots.txt disallows {url}")


# ---------------------------------------------------------------------------
# Engines
# ---------------------------------------------------------------------------


async def _try_local(
    url: str,
    *,
    http_client: httpx.AsyncClient,
    max_bytes: int,
    user_agent: str,
) -> ExtractedContent | None:
    """Local path: httpx fetch + trafilatura. Returns None on empty
    extraction (caller may fall back to Jina). Raises on hard failures."""
    async with http_client.stream(
        "GET",
        url,
        headers={"User-Agent": user_agent},
        follow_redirects=True,
        timeout=FETCH_TIMEOUT,
    ) as response:
        if response.status_code >= 400:
            raise FetchFailedError(f"HTTP {response.status_code} for {url}")
        body = await _read_capped(response, max_bytes)

    content_type = response.headers.get("content-type", "").lower()
    is_htmlish = (not content_type) or "html" in content_type or "xml" in content_type
    if not is_htmlish:
        return None  # PDF, image, etc. — let Jina handle it

    extracted = trafilatura.extract(
        body,
        url=str(response.url),
        output_format="markdown",
        include_links=True,
    )
    if not extracted or not extracted.strip():
        return None

    return ExtractedContent(
        content=extracted,
        fetched_at=int(time.time()),
        final_url=str(response.url),
        engine="trafilatura",
        affordances=parse_affordances(body, str(response.url)),
        sections=structural_sections(body),
    )


async def _try_jina(
    url: str,
    *,
    http_client: httpx.AsyncClient,
    jina_base: str,
    user_agent: str,
) -> ExtractedContent:
    """Fallback: ask Jina Reader to render the URL. Returns plain-text
    Markdown directly (no JSON envelope when Accept: text/plain)."""
    target = f"{jina_base.rstrip('/')}/{url}"
    try:
        response = await http_client.get(
            target,
            headers={"User-Agent": user_agent, "Accept": "text/plain"},
            timeout=JINA_TIMEOUT,
        )
    except httpx.HTTPError as exc:
        raise FetchFailedError(f"jina fallback failed: {exc}") from exc
    if response.status_code >= 400:
        raise FetchFailedError(f"jina returned HTTP {response.status_code}")
    text = response.text.strip()
    if not text:
        raise ExtractionEmptyError(f"jina returned empty content for {url}")
    return ExtractedContent(
        content=text,
        fetched_at=int(time.time()),
        final_url=url,
        engine="jina",
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def fetch_and_extract(
    url: str,
    *,
    http_client: httpx.AsyncClient,
    max_bytes: int = DEFAULT_MAX_BYTES,
    respect_robots: bool = True,
    robots_cache: dict[str, RobotFileParser] | None = None,
    user_agent: str = DEFAULT_USER_AGENT,
    jina_fallback: bool = True,
    jina_base: str = JINA_READER_BASE,
) -> ExtractedContent:
    """Fetch a URL and return its main content as Markdown.

    Tries trafilatura locally first. Falls back to Jina Reader when the
    local path returns no content (SPA, PDF, anti-bot) or when the
    fetch itself fails. `TooLargeError` is a hard cap — no fallback.

    `http_client` is injected so tests can use httpx.MockTransport.
    `robots_cache` is shared across calls by the daemon (one
    RobotFileParser per host).
    """
    _validate_url(url)
    max_bytes = min(max_bytes, HARD_MAX_BYTES)
    try:
        return await _fetch_and_extract(
            url,
            http_client=http_client,
            max_bytes=max_bytes,
            respect_robots=respect_robots,
            robots_cache=robots_cache,
            user_agent=user_agent,
            jina_fallback=jina_fallback,
            jina_base=jina_base,
        )
    except BlockedTarget as exc:
        # SSRF guard tripped (DNS → private IP, redirect into the internal
        # network, bad port on a hop). Hard failure: no Jina fallback.
        raise BadURLError(str(exc)) from exc


async def _fetch_and_extract(
    url: str,
    *,
    http_client: httpx.AsyncClient,
    max_bytes: int,
    respect_robots: bool,
    robots_cache: dict[str, RobotFileParser] | None,
    user_agent: str,
    jina_fallback: bool,
    jina_base: str,
) -> ExtractedContent:
    if respect_robots:
        await _check_robots(
            url,
            http_client=http_client,
            robots_cache=robots_cache,
            user_agent=user_agent,
        )

    local_err: ExtractorError | None = None
    try:
        result = await _try_local(
            url,
            http_client=http_client,
            max_bytes=max_bytes,
            user_agent=user_agent,
        )
        if result is not None:
            return result
        local_err = ExtractionEmptyError(f"no main content found in {url}")
    except TooLargeError:
        raise  # hard cap, never fall back
    except ExtractorError as exc:
        local_err = exc
    except httpx.HTTPError as exc:
        local_err = FetchFailedError(f"http error: {exc}")

    if jina_fallback:
        try:
            return await _try_jina(
                url,
                http_client=http_client,
                jina_base=jina_base,
                user_agent=user_agent,
            )
        except ExtractorError:
            pass  # both failed → surface the local error

    raise local_err
