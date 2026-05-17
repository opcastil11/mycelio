# End-to-end codegen demo

Proof that `mycelio.codegen.manifest_from_openapi()` handles real
production-grade OpenAPI specs, not just hand-crafted fixtures.

## What it does

`generate_manifests.py` fetches three large public OpenAPI specs from
their canonical upstream repos, runs each through the codegen function,
signs the result with an ephemeral vendor + directory keypair, decodes
the binary back, and verifies both signatures.

If anything along that pipeline broke, the script exits non-zero. If
everything works, it prints a table of what it produced.

## How to run

```bash
pip install -e '.[server]'   # mycelio + cryptography + httpx
pip install pyyaml           # needed because the OpenAI spec is YAML
python examples/end-to-end/generate_manifests.py
```

Signed manifest binaries land in `examples/end-to-end/out/`.

## Representative output

(Numbers will vary slightly — vendors update their specs.)

```
service       time    ops    unsigned      signed  auth-header               backend
----------------------------------------------------------------------------------------------
openai         3.1s    242     33.7 KB     33.8 KB  Authorization             https://api.openai.com/v1
stripe         0.9s    587    121.8 KB    121.8 KB  Authorization             https://api.stripe.com
github         1.4s   1184    204.2 KB    204.3 KB  (none)                    https://api.github.com
```

## Things this tells us

- **Codegen scales.** It chews through a 7.7 MB Stripe spec (587 ops) in
  under a second and emits a single signed binary.
- **The "400 bytes" pitch is for SMALL APIs.** The marketing line on the
  landing page (`a 400-byte signed file`) is true for a typical 2–5 op
  service. Large surfaces like Stripe (587 ops) or GitHub (1,184 ops)
  produce manifests in the hundreds of KB. Still tiny compared to the
  original specs (50–200× smaller) but not 400 bytes.
- **Auth detection is conservative.** GitHub's `api.github.com.json`
  doesn't define `components.securitySchemes` at all, so the codegen
  emits `auth_header=None`. That's the correct behavior — better to
  emit an explicit "no auth detected" than to guess.
- **All three round-trip.** Encode → sign vendor → sign directory →
  decode → verify both signatures, every one. That's what proves the
  manifest is byte-compatible with the rest of the Mycelio stack.

## Things this demo doesn't do (yet)

- It does **not** actually serve the generated manifests through `mycd`
  for agent invocation. That would require extending `mycd` to load
  manifests from a directory at startup; out of scope for the codegen
  demo. The current `mycd/__main__.py` has a hardcoded mini-directory
  for the existing `DISCOVER` / `ROUTE` tests.
- It does **not** prove agents can call OpenAI/Stripe/GitHub through
  Mycelio end-to-end — that requires real API credentials and an
  upstream `mycd` instance configured to inject them. Future demo.

## Files

- `generate_manifests.py` — the demo script
- `out/` — gitignored output directory (regenerated on each run)
