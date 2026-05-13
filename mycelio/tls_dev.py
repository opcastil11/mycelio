"""Self-signed TLS cert generator for development + tests.

Production should use a real cert (Let's Encrypt etc.). This module
exists so tests + local demos can exercise the TLS path without
external infrastructure.
"""
from __future__ import annotations

import datetime
import ssl
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def make_self_signed_cert(common_name: str = "localhost") -> tuple[bytes, bytes]:
    """Generate a self-signed cert + key in PEM bytes.

    Returns (cert_pem, key_pem).
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name), x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def make_server_context(common_name: str = "localhost") -> tuple[ssl.SSLContext, bytes]:
    """Build a server SSLContext using a fresh self-signed cert.

    Returns (server_ctx, cert_pem) — the cert_pem can be added to a
    client context's trust store for the test/dev pair.
    """
    cert_pem, key_pem = make_self_signed_cert(common_name)
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as cf, \
         tempfile.NamedTemporaryFile(suffix=".key", delete=False) as kf:
        cf.write(cert_pem)
        kf.write(key_pem)
        cert_path = cf.name
        key_path = kf.name
    ctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return ctx, cert_pem


def make_client_context_trusting(cert_pem: bytes) -> ssl.SSLContext:
    """Build a client SSLContext that trusts the given PEM cert."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False  # self-signed cert; hostname check fails on localhost
    ctx.load_verify_locations(cadata=cert_pem.decode())
    return ctx


def write_cert_pair(out_dir: Path, common_name: str = "localhost") -> tuple[Path, Path]:
    """Write a fresh cert + key to `out_dir`. Returns (cert_path, key_path)."""
    cert_pem, key_pem = make_self_signed_cert(common_name)
    out_dir.mkdir(parents=True, exist_ok=True)
    cert_path = out_dir / "mycd.crt"
    key_path = out_dir / "mycd.key"
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)
    return cert_path, key_path
