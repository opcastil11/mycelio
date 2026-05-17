<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
    <img src="assets/logo-light.svg" alt="Mycelio" width="260">
  </picture>
</p>

<p align="center">
  <strong>Binary, agent-native protocol for AI agents to discover and invoke SaaS services without speaking HTTP+JSON.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/License-Apache_2.0-blue.svg"></a>
  <a href="#status"><img alt="Status: experimental" src="https://img.shields.io/badge/status-experimental-orange.svg"></a>
  <a href="https://www.python.org/"><img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11+-blue.svg"></a>
  <a href="https://mycelio.prowl.world/"><img alt="Live daemon" src="https://img.shields.io/badge/daemon-live-success.svg"></a>
</p>

> HTTP+JSON is for browsers. Mycelio is for agents.

## Why

An AI agent finding and using a SaaS today:

```
GET /v1/discover?q=payments        →  8 KB JSON  (~2000 tokens)
GET /v1/metrics/{id}               →  4 KB JSON
GET /v1/services/by-slug/stripe    →  6 KB JSON
POST https://api.stripe.com/...    →  HTTP + TLS handshake + JSON
```

4 TCP connections, ~20 KB on wire, ~5000 tokens just to evaluate one
service and make one call. Agents pay per token, and the bytes on the
wire are control-plane plumbing the LLM has to read and write.

The same cycle over Mycelio:

```
one persistent binary session ─────▶
  DISCOVER {category: payments}      ← 12 bytes
  ← [3 service hashes, ranked]       ← 28 bytes
  ROUTE {hash, op: charge, ...}      ← 16 bytes    (tunneled to vendor)
  ← {ok: true, charge_id: ...}       ← 24 bytes
```

1 connection, ~80 bytes on the wire, ~20 tokens.

## The Rappi model

**Vendors do not implement Mycelio.** Like a food delivery service:

- The **agent** is the customer placing an order.
- The **vendor backend** (Stripe, Plaid, Resend, etc.) is the restaurant —
  keeps its existing HTTP API unchanged.
- **`mycd`** is the courier. It speaks Mycelio frames to the agent and
  HTTP to the vendor. The agent never sees HTTP; the vendor never sees
  Mycelio.

What the vendor publishes instead: a ~400-byte signed manifest describing
their endpoints. `mycd` (and any directory operator) reads the manifest
to know how to translate. The manifest is dual-signed — by the vendor and
by the directory's root key — so agents can verify both authenticity and
endorsement before invoking.

## Status

**v0 — experimental.** Reference daemon `mycd` is live on the public
internet at `myc://mycelio.prowl.world:4242` for poking at. 63 tests
cover frame codec, crypto, manifest signing, and end-to-end `ROUTE`
through a mocked HTTP backend.

Phase progress:

- [x] **Phase 0** — wire spec v0, frame codec, 10 verbs defined
- [x] **Phase 0.5** — TLS support, async daemon, signature-verifying SDK
- [x] **Phase 1** — vendor manifests, dual signing, `INSPECT`, `ROUTE` over real HTTP
- [ ] **Phase 2** — endpoint design bench: auto-generate manifests from OpenAPI
- [ ] **Phase 3** — streaming responses (SSE/chunked through `ROUTE`) + `PAY` (x402)
- [ ] **Phase 4** — peer-to-peer relay of signed directory shards
- [ ] **Phase 5** — public 1.0, multi-language reference implementations, conformance suite

Production directory implementation lives at [prowl.world](https://prowl.world).

## Install

```bash
pip install mycelio          # SDK only
pip install 'mycelio[server]' # SDK + mycd daemon
```

Requires Python 3.11+.

## Try it

The live demo daemon serves a small toy directory you can `DISCOVER` and
`INSPECT` against:

```python
import asyncio
from mycelio.client import MycelioClient

async def main():
    async with MycelioClient("mycelio.prowl.world", 4242) as c:
        services = await c.discover(category="payments")
        for s in services:
            print(s.name, s.hash.hex()[:16])

asyncio.run(main())
```

See [`examples/`](examples/) for `DISCOVER` and `ROUTE` end-to-end demos
including signature verification.

## Run your own daemon

```bash
mycd --host 0.0.0.0 --port 4242
```

This starts the reference server with an ephemeral Ed25519 root key
printed on stdout. Clients need that pubkey to verify signed responses.

For production use you'd pin a persistent key and feed it real vendor
manifests; see [`spec/manifest-v0.md`](spec/manifest-v0.md).

## Architecture

| Component | Role |
|---|---|
| **Wire protocol** | Binary frames over TCP (raw or TLS). 4-byte magic + varint length + 1-byte verb + payload. Field-ID encoded payload. No JSON, no HTTP. |
| **`mycd`** | Reference daemon. Serves Mycelio frames in; translates `ROUTE` to outbound HTTP for the vendor's existing backend. |
| **`mycelio` SDK** | Async Python client. One persistent connection, all verbs through it. Verifies signatures against pinned root key. |
| **Vendor manifest** | ~200–400 byte signed binary file describing a service's Mycelio surface. Auto-generated from OpenAPI (Phase 2). |
| **Directory** | The signer + indexer of manifests. Prowl is the canonical implementation; the spec doesn't require a single one. |

## Verbs (v0)

| Code | Verb | Purpose | Shipped |
|---|---|---|---|
| `0x01` | `PING` | Version negotiation, keepalive | ✅ |
| `0x02` | `DISCOVER` | Find services by category / query / filter | ✅ |
| `0x03` | `INSPECT` | Get full metadata for one service | ✅ |
| `0x04` | `ROUTE` | Invoke a service through the tunnel | ✅ |
| `0x05` | `BENCH` | Submit benchmark result | Phase 3 |
| `0x06` | `CLAIM` | Verify vendor ownership | Phase 3 |
| `0x07` | `PAY` | x402 payment proof | Phase 3 |
| `0x08` | `INDEX` | Request a directory shard (relay nodes) | Phase 4 |
| `0xFE` | `SIG` | Ed25519 signature over preceding frames | ✅ |
| `0xFF` | `GOODBYE` | Close connection | ✅ |

Full wire spec: [`spec/protocol-v0.md`](spec/protocol-v0.md).
Manifest format: [`spec/manifest-v0.md`](spec/manifest-v0.md).

## How vendors onboard (planned, Phase 2)

1. Claim service via the upstream directory (e.g. [prowl.world](https://prowl.world))
   using DNS TXT / well-known file / HTML meta tag.
2. Paste OpenAPI URL into the directory's design bench.
3. The directory auto-generates a Mycelio manifest, signs it, and serves
   it to any `mycd` instance that asks.
4. Agents discover the service through `DISCOVER` and invoke through
   `ROUTE`. Neither party speaks HTTP or JSON over the wire.

Until Phase 2 ships, manifests are handwritten — see
[`spec/manifest-v0.md`](spec/manifest-v0.md) for the format.

## Project layout

```
mycelio/        # SDK: client, frame codec, crypto, manifest, verbs
mycd/           # Reference daemon (server)
spec/           # Wire protocol + manifest format specs
tests/          # 63 tests (pytest + pytest-asyncio)
examples/       # discover_demo.py, route_demo.py
```

## Contributing

Mycelio is a protocol, not a product — the [spec](spec/) is authoritative,
not this Python implementation. Implementations in Go, Rust, JS, etc. are
welcome. Conformance tests will land in Phase 5.

For now: file an issue, open a PR, or chat at [prowl.world](https://prowl.world).

## License

Apache 2.0. See [LICENSE](LICENSE).
