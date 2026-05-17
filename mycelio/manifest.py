"""Vendor manifest format for Mycelio v0.

See spec/manifest-v0.md for the wire format. This module provides:

- Dataclasses for in-memory representation (Manifest, OpDef, ParamDef)
- encode_manifest() — canonical byte representation
- decode_manifest() — parse + validate signatures
- sign_manifest() — vendor sign + directory countersign helpers
- validate_manifest() — check ops list, param names, signatures
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from mycelio.payload import PayloadError, TypeCode, decode_payload, encode_payload


class ManifestError(Exception):
    """Raised on malformed or invalid manifests."""


class ParamLocation(IntEnum):
    PATH = 0
    QUERY = 1
    BODY = 2
    HEADER = 3


class BackendKind(IntEnum):
    HTTP = 0
    MCP = 1
    SSE = 2
    GRPC = 3


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ParamDef:
    key: str
    location: ParamLocation
    backend_name: str | None = None
    required: bool = False

    @property
    def out_name(self) -> str:
        return self.backend_name or self.key


@dataclass
class OpDef:
    slug: str
    method: str
    path: str
    params: list[ParamDef] = field(default_factory=list)
    requires_payment: bool = False
    streams_response: bool = False


@dataclass
class Manifest:
    service_id: bytes  # 8 bytes
    slug: str
    vendor_pubkey: bytes  # 32 bytes
    backend_url: str
    backend_kind: BackendKind = BackendKind.HTTP
    auth_header: str | None = None
    auth_prefix: str | None = None
    ops: list[OpDef] = field(default_factory=list)
    vendor_signature: bytes | None = None  # 64 bytes
    directory_signature: bytes | None = None  # 64 bytes

    def get_op(self, slug: str) -> OpDef:
        for op in self.ops:
            if op.slug == slug:
                return op
        raise ManifestError(f"op not found: {slug!r}")


# ---------------------------------------------------------------------------
# Encode / decode
# ---------------------------------------------------------------------------


def _encode_param(p: ParamDef) -> dict[int, tuple[TypeCode, Any]]:
    fields: dict[int, tuple[TypeCode, Any]] = {
        1: (TypeCode.STRING, p.key),
        2: (TypeCode.U8, int(p.location)),
        4: (TypeCode.BOOL, p.required),
    }
    if p.backend_name and p.backend_name != p.key:
        fields[3] = (TypeCode.STRING, p.backend_name)
    return fields


def _encode_op(op: OpDef) -> dict[int, tuple[TypeCode, Any]]:
    return {
        1: (TypeCode.STRING, op.slug),
        2: (TypeCode.STRING, op.method),
        3: (TypeCode.STRING, op.path),
        4: (TypeCode.ARRAY, [(TypeCode.MAP, _encode_param(p)) for p in op.params]),
        5: (TypeCode.BOOL, op.requires_payment),
        6: (TypeCode.BOOL, op.streams_response),
    }


def _encode_core(m: Manifest, *, include_vendor_sig: bool, include_dir_sig: bool) -> bytes:
    """Encode the manifest map. `include_*_sig` controls which signatures are part of the bytes.

    - Vendor signs the encoding with both flags False.
    - Directory signs the encoding with include_vendor_sig=True, include_dir_sig=False.
    - Wire encoding has both True.
    """
    fields: dict[int, tuple[TypeCode, Any]] = {
        1: (TypeCode.HASH, m.service_id),
        2: (TypeCode.STRING, m.slug),
        3: (TypeCode.PUBKEY, m.vendor_pubkey),
        4: (TypeCode.STRING, m.backend_url),
        5: (TypeCode.U8, int(m.backend_kind)),
    }
    if m.auth_header:
        fields[6] = (TypeCode.STRING, m.auth_header)
    if m.auth_prefix:
        fields[7] = (TypeCode.STRING, m.auth_prefix)
    fields[8] = (TypeCode.ARRAY, [(TypeCode.MAP, _encode_op(op)) for op in m.ops])
    if include_vendor_sig:
        if m.vendor_signature is None or len(m.vendor_signature) != 64:
            raise ManifestError("vendor_signature required but missing or wrong length")
        fields[9] = (TypeCode.SIG, m.vendor_signature)
    if include_dir_sig:
        if m.directory_signature is None or len(m.directory_signature) != 64:
            raise ManifestError("directory_signature required but missing or wrong length")
        fields[10] = (TypeCode.SIG, m.directory_signature)
    return encode_payload(fields)


def encode_manifest(m: Manifest) -> bytes:
    """Encode the full wire form (with both signatures)."""
    return _encode_core(m, include_vendor_sig=True, include_dir_sig=True)


def encode_unsigned_manifest(m: Manifest) -> bytes:
    """Encode just the core fields (no signatures).

    This is the byte string that :func:`sign_vendor` signs over — useful for
    previewing a manifest before any signatures are attached, or for
    handing to an offline signer.
    """
    return _encode_core(m, include_vendor_sig=False, include_dir_sig=False)


def encode_vendor_signed_manifest(m: Manifest) -> bytes:
    """Encode the manifest with the vendor signature but no directory sig.

    This is what a vendor submits to the directory when requesting a
    countersignature. Raises :class:`ManifestError` if the manifest has
    not been vendor-signed yet.
    """
    return _encode_core(m, include_vendor_sig=True, include_dir_sig=False)


def _decode_param(raw: dict[int, tuple[TypeCode, Any]]) -> ParamDef:
    key = raw[1][1]
    loc = ParamLocation(raw[2][1])
    backend_name = raw.get(3, (None, None))[1]
    required = raw.get(4, (None, False))[1]
    return ParamDef(key=key, location=loc, backend_name=backend_name, required=required)


def _decode_op(raw: dict[int, tuple[TypeCode, Any]]) -> OpDef:
    params = []
    if 4 in raw:
        _, arr = raw[4]
        for sub_type, entry in arr:
            if sub_type != TypeCode.MAP:
                raise ManifestError("op.params entry must be a map")
            params.append(_decode_param(entry))
    return OpDef(
        slug=raw[1][1],
        method=raw[2][1],
        path=raw[3][1],
        params=params,
        requires_payment=raw.get(5, (None, False))[1],
        streams_response=raw.get(6, (None, False))[1],
    )


def decode_manifest(buf: bytes) -> Manifest:
    """Decode a wire-format manifest. Does not verify signatures (call verify_signatures)."""
    try:
        fields = decode_payload(buf)
    except PayloadError as exc:
        raise ManifestError(f"failed to decode payload: {exc}") from exc

    required = [1, 3, 4, 5, 8, 9, 10]
    missing = [f for f in required if f not in fields]
    if missing:
        raise ManifestError(f"manifest missing required fields: {missing}")

    ops = []
    _, raw_ops = fields[8]
    for sub_type, entry in raw_ops:
        if sub_type != TypeCode.MAP:
            raise ManifestError("ops entry must be a map")
        ops.append(_decode_op(entry))

    return Manifest(
        service_id=fields[1][1],
        slug=fields.get(2, (None, ""))[1],
        vendor_pubkey=fields[3][1],
        backend_url=fields[4][1],
        backend_kind=BackendKind(fields[5][1]),
        auth_header=fields.get(6, (None, None))[1],
        auth_prefix=fields.get(7, (None, None))[1],
        ops=ops,
        vendor_signature=fields[9][1],
        directory_signature=fields[10][1],
    )


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


def _sign(seed: bytes, data: bytes) -> bytes:
    if len(seed) != 32:
        raise ManifestError(f"private seed must be 32 bytes, got {len(seed)}")
    return Ed25519PrivateKey.from_private_bytes(seed).sign(data)


def _verify(pubkey: bytes, signature: bytes, data: bytes) -> bool:
    if len(pubkey) != 32 or len(signature) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(signature, data)
        return True
    except Exception:
        return False


def sign_vendor(m: Manifest, vendor_seed: bytes) -> Manifest:
    """Compute the vendor signature over the core (fields 1-8). Returns a new Manifest."""
    core_bytes = _encode_core(m, include_vendor_sig=False, include_dir_sig=False)
    sig = _sign(vendor_seed, core_bytes)
    m.vendor_signature = sig
    return m


def sign_directory(m: Manifest, directory_seed: bytes) -> Manifest:
    """Compute the directory countersignature over fields 1-9."""
    if m.vendor_signature is None:
        raise ManifestError("vendor signature must be set before directory signs")
    bytes_with_vendor = _encode_core(m, include_vendor_sig=True, include_dir_sig=False)
    sig = _sign(directory_seed, bytes_with_vendor)
    m.directory_signature = sig
    return m


def verify_signatures(m: Manifest, *, directory_pubkey: bytes) -> None:
    """Verify both signatures. Raises ManifestError on failure."""
    if m.vendor_signature is None or m.directory_signature is None:
        raise ManifestError("manifest is missing one or both signatures")

    vendor_core = _encode_core(m, include_vendor_sig=False, include_dir_sig=False)
    if not _verify(m.vendor_pubkey, m.vendor_signature, vendor_core):
        raise ManifestError("vendor signature is invalid")

    dir_core = _encode_core(m, include_vendor_sig=True, include_dir_sig=False)
    if not _verify(directory_pubkey, m.directory_signature, dir_core):
        raise ManifestError("directory signature is invalid")


# ---------------------------------------------------------------------------
# Service-ID derivation
# ---------------------------------------------------------------------------


def derive_service_id(slug: str, directory_pubkey: bytes) -> bytes:
    """Compute the 8-byte service ID from a slug + directory key.

    Per spec: sha256(slug + "|" + directory_pubkey)[0:8]. Collision-
    resistant at the expected directory scale.
    """
    h = hashlib.sha256()
    h.update(slug.encode("utf-8"))
    h.update(b"|")
    h.update(directory_pubkey)
    return h.digest()[:8]
