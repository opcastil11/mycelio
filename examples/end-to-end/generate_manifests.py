#!/usr/bin/env python3
"""End-to-end demo: generate Mycelio manifests from real-world OpenAPI specs.

This script feeds public OpenAPI specs through ``mycelio.codegen.manifest_from_openapi``,
signs each one with an ephemeral vendor + directory keypair, and prints a
table summarizing what came out. It exists to prove the codegen function
works on production-grade specs — not on toy fixtures.

Run from the repo root::

    pip install -e '.[server]' pyyaml
    python examples/end-to-end/generate_manifests.py

Output binaries are written to ``examples/end-to-end/out/<slug>.myc``.
"""
from __future__ import annotations

import time
from pathlib import Path

from mycelio.codegen import CodegenError, manifest_from_openapi
from mycelio.crypto import generate_keypair
from mycelio.manifest import (
    decode_manifest,
    encode_manifest,
    sign_directory,
    sign_vendor,
    verify_signatures,
)


# Real-world OpenAPI specs that are publicly reachable + have absolute server URLs.
# Sourced from the canonical upstream repos so we're benchmarking the actual
# spec each vendor maintains, not a third-party mirror.
SPECS: list[tuple[str, str]] = [
    ("openai",  "https://raw.githubusercontent.com/openai/openai-openapi/master/openapi.yaml"),
    ("stripe",  "https://raw.githubusercontent.com/stripe/openapi/master/openapi/spec3.json"),
    ("github",  "https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json"),
]


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB"):
        if n < 1024:
            return f"{n:6.1f} {unit}"
        n /= 1024
    return f"{n:6.1f} GB"


def main() -> int:
    out_dir = Path(__file__).resolve().parent / "out"
    out_dir.mkdir(exist_ok=True)

    # Ephemeral keys — every run uses fresh ones. Real vendors use their
    # own offline-protected Ed25519 keys; the real directory is Prowl.
    vendor_seed, vendor_pub = generate_keypair()
    dir_seed, dir_pub = generate_keypair()

    print(f"\nvendor pubkey:    {vendor_pub.hex()}")
    print(f"directory pubkey: {dir_pub.hex()}")
    print()

    header = (
        f"{'service':10s}  {'time':>6s}  {'ops':>5s}  {'unsigned':>10s}  "
        f"{'signed':>10s}  auth-header               backend"
    )
    print(header)
    print("-" * len(header))

    fail = 0
    for slug, url in SPECS:
        t0 = time.monotonic()
        try:
            m = manifest_from_openapi(
                url,
                vendor_pubkey=vendor_pub,
                directory_pubkey=dir_pub,
                slug=slug,
            )
            sign_vendor(m, vendor_seed)
            sign_directory(m, dir_seed)
            signed = encode_manifest(m)
            unsigned_len = len(signed) - 64 - 64 - 4  # rough: drop the two SIG fields
            elapsed = time.monotonic() - t0

            # Round-trip + verify, prove the binary is valid Mycelio
            decoded = decode_manifest(signed)
            verify_signatures(decoded, directory_pubkey=dir_pub)

            out_path = out_dir / f"{slug}.myc"
            out_path.write_bytes(signed)

            print(
                f"{slug:10s}  {elapsed:5.1f}s  {len(m.ops):5d}  "
                f"{_fmt_bytes(unsigned_len):>10s}  {_fmt_bytes(len(signed)):>10s}  "
                f"{(m.auth_header or '(none)'):25s} {m.backend_url}"
            )
        except CodegenError as exc:
            print(f"{slug:10s}  FAIL: {exc}")
            fail += 1
        except Exception as exc:
            print(f"{slug:10s}  FAIL ({type(exc).__name__}): {exc}")
            fail += 1

    print()
    print(f"Output binaries: {out_dir}")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
