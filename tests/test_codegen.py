"""Tests for mycelio.codegen — OpenAPI → Manifest conversion."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from mycelio.codegen import CodegenError, manifest_from_openapi
from mycelio.crypto import generate_keypair
from mycelio.manifest import (
    BackendKind,
    ParamLocation,
    decode_manifest,
    derive_service_id,
    encode_manifest,
    sign_directory,
    sign_vendor,
    verify_signatures,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _stripe_like_spec() -> dict:
    """A small Stripe-shaped OpenAPI 3.0 spec covering the cases that matter:

    - bearer auth in securitySchemes
    - $ref in request body schema
    - $ref in path parameter (via the components.parameters convention)
    - path + query + body params
    - operationId provided on most ops
    - one op missing operationId (to exercise the fallback slug)
    """
    return {
        "openapi": "3.0.3",
        "info": {"title": "Stripe Payments API", "version": "1.0.0"},
        "servers": [{"url": "https://api.stripe.com/v1"}],
        "components": {
            "securitySchemes": {
                "bearer": {"type": "http", "scheme": "bearer"},
            },
            "parameters": {
                "ChargeIdPath": {
                    "name": "charge_id",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"},
                },
            },
            "schemas": {
                "ChargeIn": {
                    "type": "object",
                    "required": ["amount", "currency"],
                    "properties": {
                        "amount": {"type": "integer"},
                        "currency": {"type": "string"},
                        "source": {"type": "string"},
                    },
                },
            },
        },
        "paths": {
            "/charges": {
                "post": {
                    "operationId": "createCharge",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ChargeIn"},
                            },
                        },
                    },
                },
                "get": {
                    "operationId": "listCharges",
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "integer"},
                        },
                    ],
                },
            },
            "/charges/{charge_id}": {
                "parameters": [
                    {"$ref": "#/components/parameters/ChargeIdPath"},
                ],
                "get": {"operationId": "getCharge"},
                # No operationId — exercise the fallback slug
                "delete": {},
            },
        },
    }


def _vendor_and_dir_keys() -> tuple[bytes, bytes, bytes, bytes]:
    """Returns (vendor_seed, vendor_pub, dir_seed, dir_pub)."""
    vs, vp = generate_keypair()
    ds, dp = generate_keypair()
    return vs, vp, ds, dp


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_generates_manifest_from_stripe_like_spec():
    _, vendor_pub, _, dir_pub = _vendor_and_dir_keys()
    m = manifest_from_openapi(
        _stripe_like_spec(),
        vendor_pubkey=vendor_pub,
        directory_pubkey=dir_pub,
    )

    assert m.slug == "stripe-payments-api"
    assert m.vendor_pubkey == vendor_pub
    assert m.backend_url == "https://api.stripe.com/v1"
    assert m.backend_kind == BackendKind.HTTP
    assert m.auth_header == "Authorization"
    assert m.auth_prefix == "Bearer"
    assert m.service_id == derive_service_id("stripe-payments-api", dir_pub)
    assert m.vendor_signature is None  # caller signs
    assert m.directory_signature is None


def test_slug_can_be_overridden_by_caller():
    _, vendor_pub, _, dir_pub = _vendor_and_dir_keys()
    m = manifest_from_openapi(
        _stripe_like_spec(),
        vendor_pubkey=vendor_pub,
        directory_pubkey=dir_pub,
        slug="stripe",
    )
    assert m.slug == "stripe"
    assert m.service_id == derive_service_id("stripe", dir_pub)


def test_uses_operationid_for_slugs():
    _, vendor_pub, _, dir_pub = _vendor_and_dir_keys()
    m = manifest_from_openapi(
        _stripe_like_spec(),
        vendor_pubkey=vendor_pub,
        directory_pubkey=dir_pub,
    )
    slugs = [op.slug for op in m.ops]
    assert "createCharge" in slugs
    assert "listCharges" in slugs
    assert "getCharge" in slugs


def test_falls_back_to_method_path_slug_when_no_operation_id():
    _, vendor_pub, _, dir_pub = _vendor_and_dir_keys()
    m = manifest_from_openapi(
        _stripe_like_spec(),
        vendor_pubkey=vendor_pub,
        directory_pubkey=dir_pub,
    )
    delete_op = next(op for op in m.ops if op.method == "DELETE")
    # Fallback slug is kebab-case: underscores in path segments are
    # normalized to dashes so the slug is consistent regardless of
    # spec author's naming style.
    assert delete_op.slug == "delete-charges-charge-id"


# ---------------------------------------------------------------------------
# Auth detection
# ---------------------------------------------------------------------------


def test_extracts_bearer_auth():
    _, vendor_pub, _, dir_pub = _vendor_and_dir_keys()
    m = manifest_from_openapi(
        _stripe_like_spec(),
        vendor_pubkey=vendor_pub,
        directory_pubkey=dir_pub,
    )
    assert m.auth_header == "Authorization"
    assert m.auth_prefix == "Bearer"


def test_extracts_apikey_header_auth():
    spec = _stripe_like_spec()
    spec["components"]["securitySchemes"] = {
        "key": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
    }
    _, vendor_pub, _, dir_pub = _vendor_and_dir_keys()
    m = manifest_from_openapi(spec, vendor_pubkey=vendor_pub, directory_pubkey=dir_pub)
    assert m.auth_header == "X-API-Key"
    assert m.auth_prefix is None


def test_no_auth_scheme_means_no_auth_header():
    spec = _stripe_like_spec()
    spec["components"].pop("securitySchemes", None)
    _, vendor_pub, _, dir_pub = _vendor_and_dir_keys()
    m = manifest_from_openapi(spec, vendor_pubkey=vendor_pub, directory_pubkey=dir_pub)
    assert m.auth_header is None
    assert m.auth_prefix is None


def test_apikey_in_query_or_cookie_is_ignored():
    """apiKey-in-header is the only apiKey location we support in v0."""
    spec = _stripe_like_spec()
    spec["components"]["securitySchemes"] = {
        "key": {"type": "apiKey", "in": "query", "name": "api_key"},
    }
    _, vendor_pub, _, dir_pub = _vendor_and_dir_keys()
    m = manifest_from_openapi(spec, vendor_pubkey=vendor_pub, directory_pubkey=dir_pub)
    assert m.auth_header is None
    assert m.auth_prefix is None


# ---------------------------------------------------------------------------
# Parameters
# ---------------------------------------------------------------------------


def test_extracts_path_query_body_params_with_correct_locations():
    _, vendor_pub, _, dir_pub = _vendor_and_dir_keys()
    m = manifest_from_openapi(
        _stripe_like_spec(),
        vendor_pubkey=vendor_pub,
        directory_pubkey=dir_pub,
    )
    create = m.get_op("createCharge")
    body_keys = {p.key for p in create.params if p.location == ParamLocation.BODY}
    assert body_keys == {"amount", "currency", "source"}

    list_op = m.get_op("listCharges")
    query_keys = [p for p in list_op.params if p.location == ParamLocation.QUERY]
    assert len(query_keys) == 1
    assert query_keys[0].key == "limit"
    assert query_keys[0].required is False

    get_op = m.get_op("getCharge")
    path_keys = [p for p in get_op.params if p.location == ParamLocation.PATH]
    assert len(path_keys) == 1
    assert path_keys[0].key == "charge_id"
    assert path_keys[0].required is True


def test_required_flag_propagates_from_body_required_list():
    _, vendor_pub, _, dir_pub = _vendor_and_dir_keys()
    m = manifest_from_openapi(
        _stripe_like_spec(),
        vendor_pubkey=vendor_pub,
        directory_pubkey=dir_pub,
    )
    create = m.get_op("createCharge")
    by_name = {p.key: p for p in create.params}
    assert by_name["amount"].required is True
    assert by_name["currency"].required is True
    # `source` is not in the required list → required=False even though
    # requestBody.required is True at the wrapper level.
    assert by_name["source"].required is False


def test_resolves_local_ref_in_path_parameter():
    """The /charges/{charge_id} GET uses a $ref to components.parameters.

    If $ref resolution is broken, the path parameter would silently drop.
    """
    _, vendor_pub, _, dir_pub = _vendor_and_dir_keys()
    m = manifest_from_openapi(
        _stripe_like_spec(),
        vendor_pubkey=vendor_pub,
        directory_pubkey=dir_pub,
    )
    get_op = m.get_op("getCharge")
    assert any(p.key == "charge_id" and p.location == ParamLocation.PATH for p in get_op.params)


def test_cookie_params_are_ignored():
    spec = _stripe_like_spec()
    spec["paths"]["/charges"]["get"]["parameters"].append(
        {"name": "session", "in": "cookie", "required": True, "schema": {"type": "string"}}
    )
    _, vendor_pub, _, dir_pub = _vendor_and_dir_keys()
    m = manifest_from_openapi(spec, vendor_pubkey=vendor_pub, directory_pubkey=dir_pub)
    list_op = m.get_op("listCharges")
    assert all(p.key != "session" for p in list_op.params)


def test_form_encoded_request_body_is_extracted_like_json():
    spec = _stripe_like_spec()
    spec["paths"]["/charges"]["post"]["requestBody"] = {
        "required": True,
        "content": {
            "application/x-www-form-urlencoded": {
                "schema": {"$ref": "#/components/schemas/ChargeIn"},
            }
        },
    }
    _, vendor_pub, _, dir_pub = _vendor_and_dir_keys()
    m = manifest_from_openapi(spec, vendor_pubkey=vendor_pub, directory_pubkey=dir_pub)
    create = m.get_op("createCharge")
    body_keys = {p.key for p in create.params if p.location == ParamLocation.BODY}
    assert body_keys == {"amount", "currency", "source"}


# ---------------------------------------------------------------------------
# Disambiguation
# ---------------------------------------------------------------------------


def test_disambiguates_duplicate_operation_slugs():
    """Two ops with the same operationId would otherwise collide silently."""
    spec = _stripe_like_spec()
    spec["paths"]["/dupes"] = {
        "get": {"operationId": "dupe"},
        "post": {"operationId": "dupe"},
    }
    _, vendor_pub, _, dir_pub = _vendor_and_dir_keys()
    m = manifest_from_openapi(spec, vendor_pubkey=vendor_pub, directory_pubkey=dir_pub)
    dupe_slugs = sorted(op.slug for op in m.ops if op.slug.startswith("dupe"))
    assert dupe_slugs == ["dupe", "dupe-2"]


# ---------------------------------------------------------------------------
# Input formats
# ---------------------------------------------------------------------------


def test_accepts_url_input(monkeypatch):
    """The URL path goes through httpx.Client.get — patch it to avoid network."""
    import httpx

    spec_json = json.dumps(_stripe_like_spec())

    class FakeResp:
        text = spec_json
        def raise_for_status(self):
            pass

    class FakeClient:
        def __init__(self, *a, **k):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def get(self, _url):
            return FakeResp()

    monkeypatch.setattr(httpx, "Client", FakeClient)

    _, vendor_pub, _, dir_pub = _vendor_and_dir_keys()
    m = manifest_from_openapi(
        "https://example.com/openapi.json",
        vendor_pubkey=vendor_pub,
        directory_pubkey=dir_pub,
    )
    assert m.slug == "stripe-payments-api"


def test_accepts_path_input(tmp_path):
    spec_file = tmp_path / "openapi.json"
    spec_file.write_text(json.dumps(_stripe_like_spec()), encoding="utf-8")

    _, vendor_pub, _, dir_pub = _vendor_and_dir_keys()
    m = manifest_from_openapi(
        spec_file,
        vendor_pubkey=vendor_pub,
        directory_pubkey=dir_pub,
    )
    assert m.slug == "stripe-payments-api"


def test_accepts_local_file_path_as_string(tmp_path):
    spec_file = tmp_path / "openapi.json"
    spec_file.write_text(json.dumps(_stripe_like_spec()), encoding="utf-8")

    _, vendor_pub, _, dir_pub = _vendor_and_dir_keys()
    m = manifest_from_openapi(
        str(spec_file),
        vendor_pubkey=vendor_pub,
        directory_pubkey=dir_pub,
    )
    assert m.slug == "stripe-payments-api"


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


def test_raises_on_openapi_2_0():
    _, vendor_pub, _, dir_pub = _vendor_and_dir_keys()
    with pytest.raises(CodegenError, match="OpenAPI 3.x"):
        manifest_from_openapi(
            {"swagger": "2.0", "info": {"title": "x"}, "paths": {}},
            vendor_pubkey=vendor_pub,
            directory_pubkey=dir_pub,
        )


def test_raises_on_missing_servers():
    spec = _stripe_like_spec()
    spec.pop("servers")
    _, vendor_pub, _, dir_pub = _vendor_and_dir_keys()
    with pytest.raises(CodegenError, match="no servers"):
        manifest_from_openapi(spec, vendor_pubkey=vendor_pub, directory_pubkey=dir_pub)


def test_raises_on_empty_servers_url():
    spec = _stripe_like_spec()
    spec["servers"] = [{"url": ""}]
    _, vendor_pub, _, dir_pub = _vendor_and_dir_keys()
    with pytest.raises(CodegenError, match="empty"):
        manifest_from_openapi(spec, vendor_pubkey=vendor_pub, directory_pubkey=dir_pub)


def test_raises_on_no_operations():
    spec = _stripe_like_spec()
    spec["paths"] = {}
    _, vendor_pub, _, dir_pub = _vendor_and_dir_keys()
    with pytest.raises(CodegenError, match="no operations"):
        manifest_from_openapi(spec, vendor_pubkey=vendor_pub, directory_pubkey=dir_pub)


def test_raises_on_wrong_vendor_pubkey_length():
    with pytest.raises(CodegenError, match="vendor_pubkey must be 32 bytes"):
        manifest_from_openapi(
            _stripe_like_spec(),
            vendor_pubkey=b"\x00" * 16,
            directory_pubkey=b"\x00" * 32,
        )


def test_raises_on_wrong_directory_pubkey_length():
    with pytest.raises(CodegenError, match="directory_pubkey must be 32 bytes"):
        manifest_from_openapi(
            _stripe_like_spec(),
            vendor_pubkey=b"\x00" * 32,
            directory_pubkey=b"\x00" * 16,
        )


def test_raises_when_slug_and_title_both_missing():
    spec = _stripe_like_spec()
    spec["info"]["title"] = ""
    _, vendor_pub, _, dir_pub = _vendor_and_dir_keys()
    with pytest.raises(CodegenError, match="could not derive slug"):
        manifest_from_openapi(spec, vendor_pubkey=vendor_pub, directory_pubkey=dir_pub)


# ---------------------------------------------------------------------------
# Integration: round-trip through signing + encoding
# ---------------------------------------------------------------------------


def test_generated_manifest_round_trips_through_sign_and_encode():
    """The codegen output must pass through the existing sign + encode +
    decode + verify pipeline unchanged. This is the most important test —
    if it passes, the codegen is producing a Manifest the rest of the
    Mycelio stack accepts as a peer.
    """
    vendor_seed, vendor_pub, dir_seed, dir_pub = _vendor_and_dir_keys()
    m = manifest_from_openapi(
        _stripe_like_spec(),
        vendor_pubkey=vendor_pub,
        directory_pubkey=dir_pub,
    )
    sign_vendor(m, vendor_seed)
    sign_directory(m, dir_seed)
    encoded = encode_manifest(m)
    decoded = decode_manifest(encoded)

    assert decoded.slug == m.slug
    assert decoded.backend_url == m.backend_url
    assert decoded.auth_header == m.auth_header
    assert decoded.auth_prefix == m.auth_prefix
    assert len(decoded.ops) == len(m.ops)
    verify_signatures(decoded, directory_pubkey=dir_pub)


def test_generated_manifest_is_compact():
    """A typical multi-op API should still hit a small signed manifest."""
    vendor_seed, vendor_pub, dir_seed, dir_pub = _vendor_and_dir_keys()
    m = manifest_from_openapi(
        _stripe_like_spec(),
        vendor_pubkey=vendor_pub,
        directory_pubkey=dir_pub,
    )
    sign_vendor(m, vendor_seed)
    sign_directory(m, dir_seed)
    encoded = encode_manifest(m)
    # 4 ops with mixed params — should still fit well under 1 KB.
    assert len(encoded) < 1024, f"manifest is {len(encoded)} bytes"
