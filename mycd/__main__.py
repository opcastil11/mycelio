"""`python -m mycd` — start the Mycelio reference daemon."""
from __future__ import annotations

import argparse
import logging
import ssl
import sys
from pathlib import Path

import anyio

from mycd import __version__
from mycd.server import MycdServer, ServiceEntry
from mycelio import __protocol_version__
from mycelio.crypto import generate_keypair


# Phase 0 demo registry. Real catalog comes from a directory backend later.
DEMO_SERVICES = [
    ServiceEntry(
        service_id=b"\x01" * 8,
        name="stripe",
        score=87,
        cat_flags=0b001,  # payments
        proto_flags=0b00111,  # rest, openapi, x402
    ),
    ServiceEntry(
        service_id=b"\x02" * 8,
        name="openai",
        score=92,
        cat_flags=0b010,  # llm
        proto_flags=0b00011,  # rest, openapi
    ),
    ServiceEntry(
        service_id=b"\x03" * 8,
        name="resend",
        score=78,
        cat_flags=0b100,  # email
        proto_flags=0b00011,
    ),
]


def load_or_generate_root_key(path: str | None) -> tuple[bytes, bytes]:
    if path:
        p = Path(path)
        seed = p.read_bytes()
        if len(seed) != 32:
            print(f"error: {path} is {len(seed)} bytes, expected 32", file=sys.stderr)
            sys.exit(2)
        from mycelio.crypto import public_from_private
        return seed, public_from_private(seed)
    # Ephemeral key — fine for dev / tests.
    seed, pub = generate_keypair()
    print(f"warning: generated ephemeral root key (pub: {pub.hex()[:16]}...)", file=sys.stderr)
    return seed, pub


def build_ssl_context(cert_path: str, key_path: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return ctx


def main() -> int:
    parser = argparse.ArgumentParser(prog="mycd", description="Mycelio reference daemon")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=4242)
    parser.add_argument(
        "--root-key",
        help="Path to 32-byte Ed25519 private seed. Generated ephemerally if omitted.",
    )
    parser.add_argument("--tls-cert", help="Path to TLS certificate (PEM)")
    parser.add_argument("--tls-key", help="Path to TLS private key (PEM)")
    parser.add_argument(
        "--self-signed",
        action="store_true",
        help="Generate a self-signed cert for the given --host. For dev only.",
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args()

    if args.version:
        print(f"mycd {__version__}  (protocol v{__protocol_version__})")
        return 0

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    seed, pub = load_or_generate_root_key(args.root_key)
    print(f"root pubkey: {pub.hex()}", file=sys.stderr)

    ssl_ctx: ssl.SSLContext | None = None
    if args.tls_cert and args.tls_key:
        ssl_ctx = build_ssl_context(args.tls_cert, args.tls_key)
        print(f"TLS enabled (cert: {args.tls_cert})", file=sys.stderr)
    elif args.self_signed:
        from mycelio.tls_dev import make_server_context
        ssl_ctx, _ = make_server_context(common_name=args.host)
        print("TLS enabled (self-signed — dev only)", file=sys.stderr)

    server = MycdServer(root_seed=seed, services=DEMO_SERVICES, ssl_context=ssl_ctx)

    try:
        anyio.run(server.serve, args.host, args.port)
    except KeyboardInterrupt:
        print()  # clean line after ^C
    return 0


if __name__ == "__main__":
    sys.exit(main())
