# Mycelio Protocol v0

Wire-format spec for the Mycelio agent network protocol. This document
is the source of truth — implementations conform to it, not to the
reference daemon.

> **Status:** Draft v0. Wire format may change without backwards
> compatibility until v1. Field IDs become permanent at v1.

## Goals

1. **Minimize bytes-on-wire.** Every encoded field is a varint field-ID
   + value. No JSON keys, no XML, no whitespace.
2. **Minimize round trips.** Multiplexed streams over one persistent
   connection. Discovery + invocation + payment in one session.
3. **Trust without TLS.** Every server response is Ed25519-signed by the
   root key. Peers can relay frames they didn't author.
4. **Binary friendly.** Designed to be parseable in <100 lines of code
   in any language with stdlib only.

## Transport

Mycelio is **transport-agnostic** but ships with two canonical bindings:

- **Raw TLS-TCP** on port 4242. Canonical.
- **WebSocket-binary** at `wss://{host}/myc`. Firewall-friendly fallback.

Both carry the same frames. Implementations MUST support raw TLS-TCP
and SHOULD support the WebSocket binding.

The protocol does not depend on TLS for trust (signatures handle that),
but TLS is REQUIRED on all bindings to protect agent keys and payment
proofs in transit.

## Frame format

```
+--------+---------+--------+--------------+--------+----------+
| MAGIC  | VERSION |  VERB  |  STREAM_ID   | LENGTH | PAYLOAD  |
| 4 B    |  1 B    |  1 B   |     4 B      |  4 B   |  N B     |
+--------+---------+--------+--------------+--------+----------+
```

| Field | Type | Description |
|---|---|---|
| `MAGIC` | `bytes[4]` | `0x4D 0x59 0x43 0x4C` ("MYCL"). Identifies a Mycelio frame. |
| `VERSION` | `u8` | Protocol version. v0 = `0x00`. |
| `VERB` | `u8` | See [Verbs](#verbs). |
| `STREAM_ID` | `u32` BE | Multiplex identifier. Client streams are odd, server streams are even (cf. HTTP/2 §5.1.1). |
| `LENGTH` | `u32` BE | Payload length in bytes. Max 16 MiB enforced. |
| `PAYLOAD` | `bytes[LENGTH]` | Field-encoded body. See [Payload encoding](#payload-encoding). |

Frame header is **14 bytes** total. Empty-payload frames (e.g. PING) are
exactly 14 bytes on the wire.

## Payload encoding

Each field in a payload is:

```
<field_id: varint> <type: u8> <length-or-value: varint+bytes>
```

`field_id` is a stable integer assigned per (verb, field) pair. Field
IDs are immutable after v1.

`type` codes:

| Code | Type | Encoding |
|---|---|---|
| `0x00` | `bool` | 1 byte: `0x00` false, `0x01` true |
| `0x01` | `u8` | 1 byte |
| `0x02` | `u32` | varint |
| `0x03` | `u64` | varint |
| `0x04` | `bytes` | varint length + bytes |
| `0x05` | `string` | varint length + UTF-8 bytes |
| `0x06` | `array` | varint count + repeated <type, value> entries |
| `0x07` | `map` | varint count + repeated <field_id, type, value> entries (nested) |
| `0x08` | `hash` | exactly 8 bytes (service-hash, vendor-hash, etc.) |
| `0x09` | `sig` | exactly 64 bytes (Ed25519 signature) |
| `0x0A` | `pubkey` | exactly 32 bytes (Ed25519 public key) |

Varint follows the [protobuf varint](https://protobuf.dev/programming-guides/encoding/#varints)
encoding: 7 data bits per byte, MSB set on continuation. A 64-bit value
fits in at most 10 bytes; most field IDs fit in 1.

## Connection lifecycle

1. Client opens TLS-TCP to `{host}:4242` (or WebSocket-binary).
2. Client sends `PING` on stream 1 with its highest supported version.
3. Server replies `PING` on stream 1 with negotiated version. Both
   sides MUST downgrade to the lowest common version. v0 servers MUST
   reject clients claiming v > 0 with `GOODBYE` (reason: incompatible).
4. Subsequent verbs interleave on independently-allocated stream IDs.
5. Either side closes by sending `GOODBYE` and then performing TLS close.

## Identity

- **Service ID:** 8-byte `hash`. Computed as
  `sha256(canonical_slug + "|" + root_pubkey)[0:8]`. Collision-resistant
  at the directory's expected scale (≤10^9 services).
- **Vendor ID:** 32-byte Ed25519 `pubkey`. The vendor signs their own
  manifest; the directory countersigns to admit it.
- **Agent ID:** 32-byte Ed25519 `pubkey`. Agents identify on each
  connection via a one-shot `PING` field; per-frame agent signatures
  are not required (the connection is authenticated by the TLS handshake).
- **Salt ID:** opaque 16-byte rolling identifier used by sampled-call
  audit. Inherited from Prowl's [M0 sampling protocol](https://prowl.world/llms.txt).

## Signing

Every response from the server in a request/response stream ends with
a `SIG` frame (verb `0xFE`). The signature covers:

```
H = sha256(
  frame_1_full_bytes ||
  frame_2_full_bytes ||
  ... ||
  frame_N_full_bytes
)
sig = Ed25519_sign(root_priv, H)
```

The signature is verifiable by anyone holding the directory's root
public key. **Relay nodes can replay signed frames but cannot forge
new ones.** This is what makes the mycelium safe.

The root public key is distributed out of band (DNS TXT record on the
directory's apex, or hardcoded in the client SDK).

## Verbs

### `PING` (0x01)

Version negotiation + keepalive. First frame on any new connection.

| Field ID | Name | Type | Notes |
|---|---|---|---|
| 1 | `version` | `u8` | Supported protocol version (sender's max). |
| 2 | `agent_id` | `pubkey` | (Optional) Agent's public key for this session. |
| 3 | `cap_flags` | `u32` | Bitfield of capability flags (streaming, ROUTE tunneling, etc.). |
| 4 | `salt_id` | `bytes` | (Optional) Sampling salt the agent will use. |

### `DISCOVER` (0x02)

Find services. Request fields:

| Field ID | Name | Type | Notes |
|---|---|---|---|
| 1 | `query` | `string` | Free-text query. Optional. |
| 2 | `category` | `u8` | Category enum (see appendix). 0 = any. |
| 3 | `min_score` | `u8` | 0–100. |
| 4 | `proto_flags` | `u32` | Required protocols bitfield (MCP, OpenAPI, x402, streaming, …). |
| 5 | `limit` | `u8` | Max results, default 10, cap 50. |

Response fields:

| Field ID | Name | Type | Notes |
|---|---|---|---|
| 1 | `results` | `array<map>` | Ranked service entries. |
| 2 | `total` | `u32` | Total matches (for pagination). |

Each result entry is a map with:

| Field ID | Name | Type |
|---|---|---|
| 1 | `service_id` | `hash` |
| 2 | `score` | `u8` |
| 3 | `cat_flags` | `u32` |
| 4 | `proto_flags` | `u32` |
| 5 | `name` | `string` |

A 10-result `DISCOVER` response is typically ~150 bytes total — about
**60× smaller** than the equivalent JSON.

### `INSPECT` (0x03)

Full metadata for one service. Request: `{service_id: hash}`.

Response: a map of all known fields (description, pricing, schema URL,
auth type, sample requests, etc.). Field IDs assigned in `spec/inspect-fields.md`
(to be drafted as v0 stabilizes).

### `ROUTE` (0x04)

Invoke a service. The daemon forwards the call to the vendor backend
(translating to HTTP / MCP / SSE as needed) and returns the response
frame-by-frame.

Request:

| Field ID | Name | Type |
|---|---|---|
| 1 | `service_id` | `hash` |
| 2 | `op` | `string` | Operation slug from the manifest (e.g. `"charge"`). |
| 3 | `params` | `map` | Arguments. Keys are field IDs from the manifest's op definition. |
| 4 | `payment_proof` | `bytes` | x402 proof, when required. |

Response: streamed back over the same stream. For non-streaming
backends, a single response map. For streaming (SSE) backends,
multiple `ROUTE` frames with `partial: true` flag, terminated by a
`done: true` frame and a `SIG` frame covering the chain.

### `BENCH` (0x05)

Submit a benchmark result. Mirrors `POST /v1/benchmark/protocol/submit`
in the JSON API. Requires an authenticated agent.

### `CLAIM` (0x06)

Initiate or complete a vendor claim. Mirrors `POST /v1/claim` and
`POST /v1/claim/verify`. Verification proof types: `dns_txt`,
`well_known_file`, `html_meta_tag`.

### `PAY` (0x07)

Submit an x402 payment proof. Mirrors `X-Payment-Proof` header but in-protocol.

### `INDEX` (0x08)

Used by peer relay nodes. Request a directory shard (compressed list
of signed service entries). Returns one shard per response frame.

### `FETCH` (0x09)

Get agent-friendly content for any URL. Two paths share the same
response shape:

- **Heuristic** — host has no manifest. The daemon fetches the URL,
  extracts the main content, and returns it. `source = "heuristic"`,
  `signed = false` (the *envelope* is still SIG-signed, but the daemon
  isn't vouching for the content's correctness).
- **Manifest** — host ships a signed Mycelio manifest. The daemon
  returns the manifest payload directly. `source = "manifest"`,
  `signed = true`.

Request:

| Field ID | Name | Type | Notes |
|---|---|---|---|
| 1 | `url` | `string` | Absolute URL. Required. |
| 2 | `max_bytes` | `u32` | Response cap. Default 262144 (256 KiB). |
| 3 | `affordances` | `bool` | Whether to include parsed affordances. Default `true`. P2+ only — ignored in P1. |

Response:

| Field ID | Name | Type | Notes |
|---|---|---|---|
| 1 | `source` | `string` | `"manifest"` \| `"heuristic"`. |
| 2 | `signed` | `bool` | True only when `source == "manifest"`. |
| 3 | `content` | `string` | Extracted Markdown. |
| 4 | `affordances` | `array<map>` | Inferred links / forms (heuristic) or manifest ops (manifest path). Each entry: `{1:kind, 2:target, 3:label, 4:hints?}`. Hint keys: `1:method, 2:fields[{1:name,2:type,3:required}], 3:path`. |
| 5 | `fetched_at` | `u64` | Unix seconds. |
| 6 | `ttl_seconds` | `u32` | How long the daemon's cache will keep this entry. |

Error codes (set on field `0xFF`):

| Code | Meaning |
|---|---|
| `bad_url` | URL is malformed or not absolute. |
| `robots_blocked` | Target's `robots.txt` disallows fetching. |
| `fetch_failed` | Network or HTTP-level failure reaching the URL. |
| `extraction_empty` | The URL responded but no main content could be extracted. |
| `too_large` | Response exceeded `max_bytes`. |

### `SIG` (0xFE)

Signature frame. Closes a server-side response stream. See [Signing](#signing).

### `GOODBYE` (0xFF)

Close the connection cleanly. May include a reason field:

| Field ID | Name | Type |
|---|---|---|
| 1 | `reason` | `string` | Human-readable. |
| 2 | `code` | `u8` | Machine-readable. 0 = normal, 1 = incompatible version, 2 = unauthenticated, 3 = rate-limited. |

## Errors

Errors are returned in the response frame of the originating verb, with
field ID `0xFF` (reserved) set to a string error code:

```
{ 0xFF: "service_not_found", 0xFE: "Service hash 0x... not in directory" }
```

The verb byte of the response is unchanged (i.e. an error reply to a
`DISCOVER` is still a `DISCOVER` frame).

## Backwards compatibility

- Wire format may change up to v1. v0 is a draft.
- After v1: field IDs are permanent. New fields get new IDs. Removed
  fields are reserved.
- Verbs are permanent after v1. New verbs get new codes.
- Clients SHOULD ignore unknown field IDs.
- Servers MUST reject unknown verbs with `GOODBYE`.

## Conformance

A reference test suite lives in [`tests/conformance/`](../tests/conformance/).
An implementation is v0-conformant if it passes the suite. The suite
exercises: frame parsing, signing/verification, all verbs, multiplex
streams, graceful shutdown, and the error envelope.

## Open questions

These are still being decided for v0 → v1:

1. **QUIC vs raw TCP** as the canonical transport. QUIC gives free
   multiplexing + congestion control but ~1 MB native lib. TCP is
   simple but needs manual stream management.
2. **Shard format** for `INDEX`. Likely roaring-bitmap-backed but TBD.
3. **Payment-in-protocol vs out-of-band**. Whether `PAY` should embed
   the proof or just reference an external transaction.
4. **Discovery query language**. Just keyword + category, or full
   pgvector-equivalent semantic search?
