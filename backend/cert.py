"""
cert.py — Exposes the server's own TLS certificate SPKI fingerprint so that
the browser client can perform certificate pinning checks.

Endpoint:  GET /api/cert/fingerprint
Response:  {
               "spki_sha256_hex": "<64 hex chars>",
               "spki_sha256_b64": "<base64url>",
               "algorithm":       "sha256/spki",
               "subject":         "<cert CN or subject string>"
           }

The SPKI (SubjectPublicKeyInfo) hash is the standard format used by
browsers' `Expect-CT` / `Public-Key-Pins` mechanisms and by `openssl`:

    openssl x509 -in server.crt -pubkey -noout \
      | openssl pkey -pubin -outform DER \
      | openssl dgst -sha256

The fingerprint is computed once at import time from the certificate file
specified by the TLS_CERT_FILE environment variable, or the dev cert generated
by Werkzeug at .tls/dev-cert.crt.  If no certificate can be found, the
endpoint returns a 503 with an informative error.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from flask import Blueprint, jsonify


bp = Blueprint("cert", __name__, url_prefix="/api/cert")

# ── Certificate loading ────────────────────────────────────────────────────────

def _locate_cert_file() -> Optional[Path]:
    """Return the path to the server's leaf TLS certificate, or None."""
    # 1. Explicit environment variable (production)
    env_path = os.environ.get("TLS_CERT_FILE")
    if env_path:
        p = Path(env_path)
        if p.exists():
            return p

    # 2. Werkzeug dev-cert default location (mirrors server.py logic)
    dev_base = os.environ.get("TLS_DEV_CERT_BASE", ".tls/dev-cert")
    dev_cert = Path(dev_base).with_suffix(".crt")
    if dev_cert.exists():
        return dev_cert

    return None


def _compute_spki_fingerprint(cert_path: Path) -> dict:
    """
    Load a PEM certificate and return its SPKI SHA-256 fingerprint in both
    hex and base64url forms, plus the certificate subject string.
    """
    pem_data = cert_path.read_bytes()
    cert = x509.load_pem_x509_certificate(pem_data)

    # Export the SubjectPublicKeyInfo (SPKI) in DER format — this is the
    # format that browsers and openssl use for pin comparison.
    spki_der = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    digest = hashlib.sha256(spki_der).digest()

    try:
        subject = cert.subject.rfc4514_string()
    except Exception:
        subject = str(cert.subject)

    return {
        "spki_sha256_hex": digest.hex(),
        "spki_sha256_b64": base64.urlsafe_b64encode(digest).decode(),
        "algorithm": "sha256/spki",
        "subject": subject,
    }


# Pre-compute once at import (module-level cache).
# If the cert file is not present yet (e.g. server hasn't generated the dev cert),
# the endpoint will return a 503.
_FINGERPRINT_CACHE: dict | None = None
_FINGERPRINT_ERROR: str | None = None

def _load_fingerprint() -> None:
    global _FINGERPRINT_CACHE, _FINGERPRINT_ERROR
    cert_path = _locate_cert_file()
    if cert_path is None:
        _FINGERPRINT_ERROR = (
            "No TLS certificate found. Set TLS_CERT_FILE or start the server "
            "with server.py so Werkzeug generates the dev cert."
        )
        return
    try:
        _FINGERPRINT_CACHE = _compute_spki_fingerprint(cert_path)
        _FINGERPRINT_CACHE["cert_file"] = str(cert_path)
    except Exception as exc:
        _FINGERPRINT_ERROR = f"Failed to compute SPKI fingerprint: {exc}"


_load_fingerprint()


# ── Route ──────────────────────────────────────────────────────────────────────

@bp.get("/fingerprint")
def fingerprint():
    """
    Return the server certificate's SPKI SHA-256 fingerprint.

    This endpoint is intentionally unauthenticated — the client needs to verify
    the cert *before* it can safely send credentials.  The value it returns is
    compared against hardcoded pins in the frontend cert_pin.js module, so a
    MITM cannot simply swap in a different fingerprint (they would first need to
    forge a certificate whose hash matches a pinned value, which is infeasible
    for SHA-256 over SPKI).
    """
    if _FINGERPRINT_CACHE is None:
        return jsonify({"error": _FINGERPRINT_ERROR or "Certificate not available"}), 503

    return jsonify(_FINGERPRINT_CACHE)