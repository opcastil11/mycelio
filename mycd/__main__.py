"""`python -m mycd` entry point.

Skeleton — full daemon to be implemented in Phase 0. For now this just
parses CLI args and prints the planned configuration so the package is
runnable end-to-end (pyproject scripts entry works).
"""
from __future__ import annotations

import argparse
import sys

from mycd import __version__
from mycelio import __protocol_version__


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="mycd",
        description="Mycelio reference daemon",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=4242, help="TCP port (default: 4242)")
    parser.add_argument("--tls-cert", help="Path to TLS certificate")
    parser.add_argument("--tls-key", help="Path to TLS private key")
    parser.add_argument(
        "--root-key",
        help="Path to Ed25519 private key used to sign directory responses",
    )
    parser.add_argument(
        "--version", action="store_true", help="Print version and exit"
    )

    args = parser.parse_args()

    if args.version:
        print(f"mycd {__version__}  (protocol v{__protocol_version__})")
        return 0

    # Phase 0 placeholder. Real daemon comes next.
    print(f"mycd {__version__} (protocol v{__protocol_version__}) — skeleton")
    print(f"  would listen on {args.host}:{args.port}")
    print("  TODO: TLS handshake, frame parser, verb dispatch, ROUTE tunneling")
    return 0


if __name__ == "__main__":
    sys.exit(main())
