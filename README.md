# Mycelio

Binary, agent-native, peer-to-peer protocol for discovering and invoking
SaaS services. Built for AI agents that pay per token. Bypasses HTTP and
JSON entirely for control-plane traffic.

> SEO is for humans. ASO is for agents.
> HTTP+JSON is for browsers. Mycelio is for agents.

## Status

**v0 — Private development.** Spec is being drafted; reference daemon is
a skeleton. Going public (Apache 2.0) once v0 is conformance-tested.

## The problem

An AI agent finding and using a SaaS today:

```
GET /v1/discover?q=payments        →  8 KB JSON  (~2000 tokens)
GET /v1/metrics/{id}               →  4 KB JSON
GET /v1/services/by-slug/stripe    →  6 KB JSON
POST https://api.stripe.com/...    →  HTTP+TLS+JSON
```

4 connections, ~20 KB on wire, ~5000 tokens just to evaluate one service.

Mycelio:

```
one persistent binary session ──>
  DISCOVER {category: payments}    ← 12 bytes
  ← [3 service hashes, ranked]     ← 28 bytes
  ROUTE {hash, op: charge, …}      ← 16 bytes  (tunnels to Stripe)
  ← {ok: true, charge_id: …}       ← 24 bytes
```

1 connection, ~80 bytes on wire, ~20 tokens.

## Architecture

| Component | Role |
|---|---|
| **Wire protocol** | Binary frames over TLS-TCP (raw, or WebSocket-binary fallback). Magic + varint-length + 1-byte verb + payload. Field-ID encoded. No JSON, no HTTP. |
| **`mycd`** | Reference daemon. Serves Mycelio frames in; translates to HTTP / MCP / SSE on the way to vendor backends. Caches signed directory shards. |
| **`mycelio`** (Python SDK) | `pip install mycelio`. Async client. One persistent connection, all verbs through it. |
| **Vendor manifest** | Signed binary file describing a service's Mycelio surface. Auto-generated from OpenAPI for typical REST APIs. |
| **Mycelium relay** | Peer-to-peer gossip of signed directory shards. Phase 2. Root key holder (initially Prowl) is the only authority; peers relay, never forge. |

## Verbs (v0)

| Code | Verb | Purpose |
|---|---|---|
| 0x01 | `PING` | Version negotiation, keepalive |
| 0x02 | `DISCOVER` | Find services by category / query / filter |
| 0x03 | `INSPECT` | Get full metadata for one service |
| 0x04 | `ROUTE` | Invoke a service through the tunnel |
| 0x05 | `BENCH` | Submit benchmark result |
| 0x06 | `CLAIM` | Verify vendor ownership |
| 0x07 | `PAY` | x402 payment proof |
| 0x08 | `INDEX` | Request a directory shard (for relay nodes) |
| 0xFE | `SIG` | Ed25519 signature over preceding frames in a stream |
| 0xFF | `GOODBYE` | Close connection |

See [`spec/protocol-v0.md`](spec/protocol-v0.md) for the full wire spec.

## How vendors onboard

1. Claim service via the upstream directory (e.g. prowl.world) using the
   existing DNS / well-known / meta-tag flow.
2. In the vendor console, paste OpenAPI URL or MCP manifest URL.
3. The directory auto-generates a Mycelio manifest (~200 bytes for a
   typical CRUD API), signs it with the root key, and gossips it.
4. Agents discover the service through `DISCOVER` and invoke it through
   `ROUTE` — neither party speaks HTTP or JSON over the wire.

## License

Apache 2.0 (planned, on public release).

## Reference implementation

`mycd` (Python) lives in this repo. Other implementations (Go, Rust, JS)
are welcome — the spec is authoritative, not the reference daemon.
