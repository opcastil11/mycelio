# Vendor Manifest — v0

A vendor manifest tells `mycd` (and any other Mycelio daemon) how to
translate an inbound `ROUTE {service_id, op, params}` into an outbound
call to the vendor's backend.

A manifest is **signed twice**:
1. By the vendor (proves the vendor authored it)
2. By the directory's root key (proves the directory admitted it)

Both signatures are Ed25519 over the canonical-encoded payload.

## Wire format

A manifest is a single field-prefixed map (same encoding as a frame
payload, see `protocol-v0.md`). Top-level fields:

| Field ID | Name | Type | Description |
|---|---|---|---|
| 1 | `service_id` | `hash` (8B) | The directory-assigned service hash. |
| 2 | `slug` | `string` | Human-readable slug. Informational; service_id is the authoritative key. |
| 3 | `vendor_pubkey` | `pubkey` (32B) | The vendor's Ed25519 public key. |
| 4 | `backend_url` | `string` | Base URL of the vendor's backend (HTTPS in prod). |
| 5 | `backend_kind` | `u8` | 0=http, 1=mcp, 2=sse, 3=grpc (only 0=http implemented in v0). |
| 6 | `auth_header` | `string` | (Optional) Header name to inject vendor auth into (e.g. `Authorization`). |
| 7 | `auth_prefix` | `string` | (Optional) Prefix for auth header (e.g. `Bearer`). |
| 8 | `ops` | `array<map>` | Operation table. Each entry maps a Mycelio op slug to an HTTP method + path template + param mapping. See [Op entry](#op-entry). |
| 9 | `vendor_signature` | `sig` (64B) | Ed25519 signature by `vendor_pubkey` over the canonical-encoded map with fields 1-8 only (excluding 9 and 10). |
| 10 | `directory_signature` | `sig` (64B) | Ed25519 signature by the directory root key over the canonical-encoded map with fields 1-9 (excluding 10). |

### Op entry

Each entry in `ops` is itself a map:

| Field ID | Name | Type | Description |
|---|---|---|---|
| 1 | `slug` | `string` | The Mycelio op slug — what an agent specifies in `ROUTE.op`. |
| 2 | `method` | `string` | HTTP method (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`). |
| 3 | `path` | `string` | URL path template. May contain `{param_name}` placeholders. |
| 4 | `params` | `array<map>` | Param descriptors. Maps Mycelio param keys → location (path/query/body/header) + transform. |
| 5 | `requires_payment` | `bool` | If true, the request must include a valid `payment_proof` in the ROUTE frame. |
| 6 | `streams_response` | `bool` | If true, the backend returns a streaming response (SSE/chunked); mycd emits multiple ROUTE frames. |

### Param descriptor

| Field ID | Name | Type | Description |
|---|---|---|---|
| 1 | `key` | `string` | The Mycelio param key (as it appears in the agent's `ROUTE.params`). |
| 2 | `location` | `u8` | 0=path, 1=query, 2=body_json_field, 3=header. |
| 3 | `backend_name` | `string` | (Optional) The name to use on the backend (e.g. `customer_id` in the path while agents pass `customer`). Defaults to `key`. |
| 4 | `required` | `bool` | If true and missing, mycd returns an error frame. |

## Signing rules

To prevent confusion attacks:

- **`vendor_signature`** (field 9) signs the encoded map *with only fields 1-8* sorted by field ID. The vendor's signing input is deterministic regardless of how the directory later countersigns.
- **`directory_signature`** (field 10) signs the encoded map *with fields 1-9*. This means the directory commits to the vendor's exact bytes.

This nesting ensures:
- A malicious vendor can't reuse another vendor's manifest (vendor pubkey is in the signed range).
- The directory can't be impersonated (root pubkey is hardcoded in clients).
- Manifest bytes are tamper-evident in transit (any byte flip breaks one or both signatures).

## Distribution

Phase 1: manifests live in mycd's memory (or on disk), loaded at startup.
Phase 2: manifests are gossiped through the mycelium as signed shards via the `INDEX` verb. Peers cache shards; agents query the nearest peer.

## Example (decoded)

```
service_id:     ab cd ef 01 02 03 04 05
slug:           "stripe"
vendor_pubkey:  92 fe ... (32 bytes)
backend_url:    "https://api.stripe.com"
backend_kind:   0  (http)
auth_header:    "Authorization"
auth_prefix:    "Bearer"
ops:
  - slug:               "charge"
    method:             "POST"
    path:               "/v1/charges"
    streams_response:   false
    requires_payment:   false
    params:
      - { key: "amount",   location: 2, backend_name: "amount",   required: true }
      - { key: "currency", location: 2, backend_name: "currency", required: true }
      - { key: "customer", location: 2, backend_name: "customer", required: true }
  - slug:               "list_charges"
    method:             "GET"
    path:               "/v1/charges"
    streams_response:   true
    params:
      - { key: "limit",  location: 1, backend_name: "limit",  required: false }
vendor_signature:    ...  (64 bytes)
directory_signature: ...  (64 bytes)
```

Encoded size: ~280 bytes for a typical 3-op service. Compare to the
equivalent OpenAPI YAML (often 5-50 KB).

## Auto-generation from OpenAPI

The directory can auto-generate a manifest skeleton from a vendor's
OpenAPI spec:

1. Iterate `paths` × `methods` → `ops`
2. Map path parameters → `location: 0` (path)
3. Map query parameters → `location: 1`
4. Map body fields → `location: 2`
5. Map security schemes → `auth_header` + `auth_prefix`
6. Default `slug` = `operationId` (or `method_path_normalized`)
7. Skip ops the directory can't safely automate (multipart, file upload — handled in v1+)

The vendor reviews and signs. The directory countersigns. The manifest
goes live. This is the foundation of the **endpoint design bench** —
the same generator surfaces "this op would be 30% more token-efficient
if you renamed `customer_id_or_email` → `customer`."

## v0 limitations

- Only HTTP backends (`backend_kind = 0`). MCP/SSE/gRPC backends come in v1.
- No batching (one op call per ROUTE frame). Batch verb in v1.
- No retries; mycd returns whatever the backend returns.
- Auth is a single header injection; OAuth2 token refresh is out of scope.
