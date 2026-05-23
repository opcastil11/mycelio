"""HTTP shim for the FETCH verb.

A tiny Starlette app that speaks HTTP on the outside and Mycelio on the
inside. Lets anyone with ``curl`` exercise FETCH without installing the
Python SDK.

Routes:

  GET /r/<url>            → text/markdown by default, JSON with
                            ``Accept: application/json``
  GET /r?url=<url>        → same, query-param form
  GET /healthz            → liveness ping

Config via env:
  MYCD_HOST          (default ``mycd``)
  MYCD_PORT          (default ``4242``)
  MYCD_ROOT_PUBKEY   hex-encoded 32-byte Ed25519 pubkey (required)
  MYCD_SHIM_PORT     (default ``8080``)
"""
from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager

from mycelio import ClientError, MycelioClient

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

log = logging.getLogger("mycd.http_shim")

_ERROR_STATUS = {
    "bad_url": 400,
    "robots_blocked": 451,
    "fetch_failed": 502,
    "extraction_empty": 502,
    "too_large": 413,
    "bad_payload": 400,
}


def _config() -> tuple[str, int, bytes]:
    host = os.environ.get("MYCD_HOST", "mycd")
    port = int(os.environ.get("MYCD_PORT", "4242"))
    pubhex = os.environ.get("MYCD_ROOT_PUBKEY", "").strip()
    if len(pubhex) != 64:
        raise RuntimeError(
            "MYCD_ROOT_PUBKEY must be a 64-char hex string (32 raw bytes); "
            f"got {len(pubhex)} chars"
        )
    return host, port, bytes.fromhex(pubhex)


@asynccontextmanager
async def _client():
    """Open a one-shot Mycelio connection. For v0 we don't pool — connection
    setup is ~1 ms over localhost-in-docker and TLS isn't in the loop yet."""
    host, port, pub = _config()
    async with MycelioClient.connect(host, port, root_pubkey=pub) as cli:
        yield cli


def _error_response(code: str, message: str, *, want_json: bool) -> Response:
    status = _ERROR_STATUS.get(code, 500)
    body = {"error": code, "message": message}
    if want_json:
        return JSONResponse(body, status_code=status)
    return PlainTextResponse(
        f"[{code}] {message}\n",
        status_code=status,
        media_type="text/plain; charset=utf-8",
    )


def _parse_error(exc: ClientError) -> tuple[str, str]:
    """ClientError messages from the daemon look like
    'server error [bad_url]: field 1 (url) required'."""
    msg = str(exc)
    if "[" in msg and "]" in msg:
        code = msg[msg.index("[") + 1 : msg.index("]")]
        rest = msg[msg.index("]") + 1 :].lstrip(": ").strip()
        return code, rest or msg
    return "fetch_failed", msg


async def _do_fetch(url: str, want_json: bool) -> Response:
    if not url or not url.startswith(("http://", "https://")):
        return _error_response(
            "bad_url", "url must start with http:// or https://", want_json=want_json
        )
    try:
        async with _client() as cli:
            page = await cli.fetch(url)
    except ClientError as exc:
        code, msg = _parse_error(exc)
        return _error_response(code, msg, want_json=want_json)
    except Exception as exc:  # connection refused, signature error, etc.
        log.exception("shim fetch failed for %s", url)
        return _error_response("fetch_failed", str(exc), want_json=want_json)

    if want_json:
        return JSONResponse(
            {
                "source": page.source,
                "signed": page.signed,
                "content": page.content,
                "affordances": page.affordances,
                "fetched_at": page.fetched_at,
                "ttl_seconds": page.ttl_seconds,
            }
        )
    return PlainTextResponse(
        page.content,
        media_type="text/markdown; charset=utf-8",
        headers={
            "X-Mycelio-Source": page.source,
            "X-Mycelio-Signed": "true" if page.signed else "false",
            "X-Mycelio-TTL": str(page.ttl_seconds),
            "X-Mycelio-Affordances": str(len(page.affordances)),
            "Cache-Control": f"public, max-age={page.ttl_seconds}",
        },
    )


def _wants_json(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    fmt = request.query_params.get("format", "")
    return "application/json" in accept or fmt == "json"


async def reader_prepend(request: Request) -> Response:
    """``GET /r/https://example.com`` — Jina-style prepend."""
    url = request.path_params["url"]
    # Strip a leading slash and re-decode if Starlette already did it. We
    # intentionally keep ``://`` in the path; Starlette's path param matcher
    # uses ``path:`` to allow that.
    return await _do_fetch(url, _wants_json(request))


async def reader_query(request: Request) -> Response:
    """``GET /r?url=...`` — query-param form, easier to share."""
    url = request.query_params.get("url", "")
    return await _do_fetch(url, _wants_json(request))


async def healthz(_: Request) -> Response:
    return PlainTextResponse("ok\n")


app = Starlette(
    debug=False,
    routes=[
        Route("/r/{url:path}", reader_prepend, methods=["GET", "HEAD"]),
        Route("/r", reader_query, methods=["GET", "HEAD"]),
        Route("/healthz", healthz, methods=["GET"]),
    ],
)


def main() -> None:
    """Entrypoint: ``python -m mycd.http_shim``."""
    import uvicorn

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    port = int(os.environ.get("MYCD_SHIM_PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    main()
