"""Generate Mycelio Manifest objects from OpenAPI 3.x specs.

This is the foundation of the Prowl Design "manifest" sub-feature. Given
an OpenAPI 3.x spec (as a parsed dict, an https:// URL, or a local file
path), produce an *unsigned* Manifest that the vendor can then sign with
their Ed25519 key and submit to the directory for co-signing.

Scope is intentionally minimal for v0:

- OpenAPI 3.0+ only. Swagger 2.0 must be converted first.
- The first entry in ``servers[]`` is taken as the backend URL.
- Auth detection covers HTTP-bearer and apiKey-in-header. OAuth2 flows
  and other interactive schemes are not supported.
- ``$ref`` resolution is local-only (``#/components/...``); external file
  refs are not followed.
- Streaming detection is intentionally NOT done — ``streams_response``
  stays False. Vendors can edit the manifest if they need it.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import httpx

from mycelio.manifest import (
    BackendKind,
    Manifest,
    OpDef,
    ParamDef,
    ParamLocation,
    derive_service_id,
)


class CodegenError(Exception):
    """Raised when an OpenAPI spec cannot be converted to a Mycelio manifest."""


HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def manifest_from_openapi(
    source: dict | str | Path,
    *,
    vendor_pubkey: bytes,
    directory_pubkey: bytes,
    slug: str | None = None,
) -> Manifest:
    """Build an unsigned Manifest from an OpenAPI 3.x spec.

    Parameters
    ----------
    source : dict | str | pathlib.Path
        The OpenAPI spec, given as one of:

        - a dict (already parsed)
        - an ``https://`` or ``http://`` URL (fetched with httpx)
        - a local file path (str or Path); parsed as JSON, then YAML if
          PyYAML is installed.

    vendor_pubkey : bytes
        32-byte Ed25519 public key of the vendor publishing the manifest.
    directory_pubkey : bytes
        32-byte Ed25519 public key of the directory. Used only to derive
        the 8-byte ``service_id`` via :func:`mycelio.manifest.derive_service_id`;
        the directory's signing key is not needed here (the countersignature
        happens after the vendor signs).
    slug : str, optional
        Canonical slug for this service. If omitted, derived from
        ``info.title`` (lowercased, ascii-only, dashes for whitespace).

    Returns
    -------
    Manifest
        Unsigned Manifest (``vendor_signature`` and ``directory_signature``
        both None). Caller is expected to call
        :func:`mycelio.manifest.sign_vendor` then submit to the directory.

    Raises
    ------
    CodegenError
        If the spec is malformed, the OpenAPI version is unsupported,
        no server URL is present, or no operations are found.
    """
    if len(vendor_pubkey) != 32:
        raise CodegenError(
            f"vendor_pubkey must be 32 bytes, got {len(vendor_pubkey)}"
        )
    if len(directory_pubkey) != 32:
        raise CodegenError(
            f"directory_pubkey must be 32 bytes, got {len(directory_pubkey)}"
        )

    spec = _load_spec(source)
    _validate_openapi(spec)

    info = spec.get("info") or {}
    inferred_slug = slug or _slug_from_title(info.get("title") or "")
    if not inferred_slug:
        raise CodegenError(
            "could not derive slug; pass slug= or set info.title in the spec"
        )

    backend_url = _backend_url(spec)
    auth_header, auth_prefix = _extract_auth(spec)
    ops = _extract_ops(spec)

    if not ops:
        raise CodegenError("no operations found in spec paths")

    return Manifest(
        service_id=derive_service_id(inferred_slug, directory_pubkey),
        slug=inferred_slug,
        vendor_pubkey=vendor_pubkey,
        backend_url=backend_url,
        backend_kind=BackendKind.HTTP,
        auth_header=auth_header,
        auth_prefix=auth_prefix,
        ops=ops,
    )


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def _load_spec(source: dict | str | Path) -> dict:
    if isinstance(source, dict):
        return source
    if isinstance(source, Path):
        return _parse_json_or_yaml(source.read_text(encoding="utf-8"))
    if isinstance(source, str):
        if source.startswith(("http://", "https://")):
            with httpx.Client(timeout=10.0, follow_redirects=True) as client:
                resp = client.get(source)
                resp.raise_for_status()
                return _parse_json_or_yaml(resp.text)
        return _parse_json_or_yaml(Path(source).read_text(encoding="utf-8"))
    raise CodegenError(f"unsupported source type: {type(source).__name__}")


def _parse_json_or_yaml(text: str) -> dict:
    # JSON is always supported (no extra deps).
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # YAML is optional — only attempted if JSON failed AND PyYAML is around.
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError as exc:
        raise CodegenError(
            "spec is not valid JSON and PyYAML is not installed; "
            "install pyyaml or convert the spec to JSON"
        ) from exc
    try:
        result = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise CodegenError(f"failed to parse spec as JSON or YAML: {exc}") from exc
    if not isinstance(result, dict):
        raise CodegenError("spec must parse to a top-level object/mapping")
    return result


def _validate_openapi(spec: dict) -> None:
    version = spec.get("openapi", "")
    if not isinstance(version, str) or not version.startswith("3."):
        raise CodegenError(
            f"only OpenAPI 3.x is supported (got openapi={version!r}); "
            "Swagger 2.0 specs must be converted first"
        )


# ---------------------------------------------------------------------------
# Slug / backend / auth
# ---------------------------------------------------------------------------


_SLUG_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def _slug_from_title(title: str) -> str:
    """Lowercase + ascii-only + dashes for non-alnum runs."""
    if not title:
        return ""
    s = title.lower().strip()
    s = _SLUG_NON_ALNUM.sub("-", s)
    return s.strip("-")


def _backend_url(spec: dict) -> str:
    servers = spec.get("servers") or []
    if not servers:
        raise CodegenError("spec has no servers[]; cannot determine backend URL")
    url = (servers[0].get("url") or "").rstrip("/")
    if not url:
        raise CodegenError("servers[0].url is empty")
    return url


def _extract_auth(spec: dict) -> tuple[str | None, str | None]:
    """Find the first bearer or apiKey-in-header scheme.

    Returns ``(header, prefix)``, or ``(None, None)`` if no usable scheme.
    OAuth2 flows are not supported — they need user interaction the
    protocol doesn't model in v0.
    """
    schemes = (spec.get("components") or {}).get("securitySchemes") or {}
    # Iterate deterministically for stable manifest output.
    for _name in sorted(schemes):
        scheme = schemes[_name]
        if not isinstance(scheme, dict):
            continue
        stype = scheme.get("type")
        if stype == "http" and (scheme.get("scheme") or "").lower() == "bearer":
            return "Authorization", "Bearer"
        if stype == "apiKey" and scheme.get("in") == "header":
            header = scheme.get("name")
            if header:
                return header, None
    return None, None


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------


def _extract_ops(spec: dict) -> list[OpDef]:
    paths = spec.get("paths") or {}
    components = spec.get("components") or {}
    ops: list[OpDef] = []
    seen_slugs: set[str] = set()

    # Iterate paths in document order. Most spec authors order their
    # paths meaningfully, and a stable order makes the manifest
    # reproducible from the same input.
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        path_level_params = path_item.get("parameters") or []
        for method in HTTP_METHODS:
            op = path_item.get(method)
            if not isinstance(op, dict):
                continue

            base_slug = op.get("operationId") or _slug_from_method_path(method, path)
            slug = base_slug
            i = 2
            while slug in seen_slugs:
                slug = f"{base_slug}-{i}"
                i += 1
            seen_slugs.add(slug)

            params = _extract_params(op, path_level_params, components)

            ops.append(
                OpDef(
                    slug=slug,
                    method=method.upper(),
                    path=path,
                    params=params,
                )
            )
    return ops


def _slug_from_method_path(method: str, path: str) -> str:
    """Fallback when operationId is missing: ``<method>-<slugified path>``."""
    cleaned = re.sub(r"[{}]", "", path)
    parts = [p for p in re.split(r"[/_-]", cleaned) if p]
    if not parts:
        return method.lower()
    return f"{method.lower()}-{'-'.join(parts)}"


def _extract_params(
    op: dict,
    path_level_params: list,
    components: dict,
) -> list[ParamDef]:
    """Extract path/query/header params and (best-effort) request-body fields.

    Body extraction is a flat one-level walk over ``requestBody.content[*].schema.properties``.
    Nested objects, arrays, and discriminator unions are intentionally
    flattened to top-level keys — this preserves the agent-facing surface
    without trying to mirror full JSON Schema in the manifest.
    """
    params: list[ParamDef] = []
    seen: set[tuple[str, ParamLocation]] = set()

    # Path-level + op-level parameters (path-level comes first per OpenAPI spec).
    for raw in list(path_level_params) + list(op.get("parameters") or []):
        if not isinstance(raw, dict):
            continue
        resolved = _resolve_ref(raw, components)
        loc = _param_location(resolved.get("in"))
        if loc is None:
            continue
        name = resolved.get("name")
        if not name:
            continue
        key = (name, loc)
        if key in seen:
            continue
        seen.add(key)
        params.append(
            ParamDef(
                key=name,
                location=loc,
                required=bool(resolved.get("required", False)),
            )
        )

    # Request-body fields.
    request_body = op.get("requestBody")
    if isinstance(request_body, dict):
        resolved_body = _resolve_ref(request_body, components)
        body_required = bool(resolved_body.get("required", False))
        content = resolved_body.get("content") or {}
        schema = None
        for ct in (
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
        ):
            if ct in content:
                schema = (content[ct] or {}).get("schema")
                if schema is not None:
                    break
        if isinstance(schema, dict):
            schema = _resolve_ref(schema, components)
            if schema.get("type") == "object" or "properties" in schema:
                required_props = set(schema.get("required") or [])
                for prop_name in (schema.get("properties") or {}):
                    key = (prop_name, ParamLocation.BODY)
                    if key in seen:
                        continue
                    seen.add(key)
                    params.append(
                        ParamDef(
                            key=prop_name,
                            location=ParamLocation.BODY,
                            required=body_required and prop_name in required_props,
                        )
                    )

    return params


def _param_location(in_value: Any) -> ParamLocation | None:
    if not isinstance(in_value, str):
        return None
    return {
        "path": ParamLocation.PATH,
        "query": ParamLocation.QUERY,
        "header": ParamLocation.HEADER,
        # cookie is unsupported in v0; falls through to None.
    }.get(in_value)


def _resolve_ref(obj: dict, components: dict) -> dict:
    """Resolve a local ``#/components/...`` $ref to its target.

    Returns ``obj`` unchanged if there's no $ref or the ref isn't local.
    External refs (other files / URLs) are intentionally not followed.
    """
    ref = obj.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/components/"):
        return obj
    parts = ref[len("#/components/"):].split("/")
    cur: Any = components
    for part in parts:
        if not isinstance(cur, dict):
            return obj
        cur = cur.get(part)
        if cur is None:
            return obj
    return cur if isinstance(cur, dict) else obj
