# FETCH verb — heuristic content + affordances for un-manifested hosts

**Status:** Plan / not yet specced.
**Phase:** Mycelio 1.5 (between manifest-enabled hosts and full action graph).
**Owner:** TBD.

## Why

Today an agent can only invoke Mycelio against a host that already ships a
signed manifest. That's the long-term goal, but day-1 adoption is zero —
no vendor has a manifest yet.

A second mode — *"give me whatever is at this URL, in agent-friendly
form"* — gives Mycelio a useful answer for any URL on the web from day
one, and a graduation path:

- **Today:** heuristic extraction. Zero work for the site owner.
- **Tomorrow:** same surface, but the response is signed because the
  owner shipped a manifest.

Adoption hook for unregistered sites, coherence with the manifest pitch
for registered ones — same verb, same response shape, only `source` and
`signed` change.

Prior art: Jina Reader (`r.jina.ai/<url>`) does this for Markdown over
HTTP. The differential here is binary wire + affordances + the
graduation surface.

## What

New verb `FETCH = 0x09`. Agent sends a URL; daemon answers with:

- **content** — extracted main text (Markdown)
- **affordances** — nav links + form actions inferred from HTML
- **source** — `"manifest"` if a signed manifest exists for the host,
  `"heuristic"` otherwise
- **signed** — `true` only when `source == "manifest"`

When `source == "manifest"`, mycd returns the manifest payload directly
(the daemon already knows how to resolve it). When heuristic, mycd
fetches the HTML, extracts content via trafilatura, parses forms/links
into affordance nodes, and signs the **envelope** — i.e. mycd vouches
for *"I fetched this URL at this time and extracted this"*, not for the
content itself.

## Wire format (sketch)

Request `FETCH`:

| field_id | type | name | required | notes |
|---|---|---|---|---|
| `0x01` | string | `url` | yes | absolute URL |
| `0x02` | u32 | `max_bytes` | no | response cap, default 256 KiB |
| `0x03` | bool | `affordances` | no | default `true` |

Response (same verb byte; errors via reserved fields):

| field_id | type | name |
|---|---|---|
| `0x01` | string | `source` (`"manifest"` \| `"heuristic"`) |
| `0x02` | bool   | `signed` |
| `0x03` | string | `content` (Markdown) |
| `0x04` | array<map> | `affordances` — each `{kind, target, label, hints?}` |
| `0x05` | u64    | `fetched_at` |
| `0x06` | u32    | `ttl_seconds` |

## Engine

**v0: trafilatura** — Python, MIT, no outbound API calls, ~1 ms per
page after warm-up. Self-hostable in mycd. Mature project, used by
research orgs.

**Not Jina Reader as primary:** the public endpoint is free but
rate-limited and external. Acceptable as a fallback if trafilatura
extraction is empty; not acceptable as the only path.

**Robots.txt:** respect by default. If disallowed, return
`error_code = ROBOTS_BLOCKED`. Agents that need to override get a
separate verb (out of scope here).

## Phases

| Phase | Scope | Estimate |
|---|---|---|
| **P1** | New verb, trafilatura extraction, 24h TTL cache (URL-hash keyed). No affordances yet. | ~1 week |
| **P2** | Parse `<a>`, `<form>`, `<input>` into typed affordance nodes. Cap 50/page. Detect pagination, login forms, search boxes. | ~1 week |
| **P3** | If mycd resolves a manifest for the host, return that instead. Same response shape; `source = "manifest"`, `signed = true`. | ~0.5 week |

**Deferred:** form → fully-typed action call (needs schema inference,
separate plan).

## What this is not

- **Not a scraper-as-a-service.** One-shot per agent request, cached
  short-term. No bulk crawling. No background workers.
- **Not a competitor to `llms.txt`.** `llms.txt` is owner-curated;
  FETCH is daemon-inferred. They coexist: if a host ships both,
  precedence is manifest > `llms.txt` > heuristic.
- **Not signed content.** The envelope is signed (mycd attestation). The
  extracted content carries no trust beyond *"mycd fetched this from
  this URL at this time"*.

## Open questions

- **Auth-gated pages** (cookies, bearer tokens): out of scope for P1.
  Needs a separate `FETCH_AUTH` verb with credential forwarding.
- **Quota / pricing:** how many fetches per agent per day before
  charging? Defer to the Prowl revenue layer — Mycelio just enforces a
  per-connection rate limit at the daemon.
- **PDFs / non-HTML:** out of scope for P1. trafilatura handles HTML
  only; PDFs need a separate extractor path.
- **JS-rendered pages:** P1 uses plain HTTP GET. SPAs that render
  client-side will return mostly empty content. Headless-browser
  rendering deferred (cost + complexity).

## Success criteria

- P1: any public URL returns clean Markdown content in <1s p50,
  cache-hit <50ms.
- P2: form fields and nav links surface as structured affordances on
  ≥80% of common e-commerce / docs pages (sampled across 30 sites).
- P3: manifest-shipping host (e.g. internal pilot vendor) returns
  `signed = true` end-to-end, agent verifies signature offline.

## Related

- `spec/protocol-v0.md` — base protocol (verbs, payload encoding).
- `spec/manifest-v0.md` — manifest format (what P3 returns directly).
