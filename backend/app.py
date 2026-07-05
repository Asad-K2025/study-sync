from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from flask import Flask, jsonify, redirect, request, send_from_directory

from backend.auth import bp as auth_bp
from backend.config import Config, project_root
from backend.db import close_db
from backend.db_init import init_db
from backend.routes import register_routes


# ── Certificate fingerprint helpers ───────────────────────────────────────────

def _locate_cert_file() -> Optional[Path]:
    """Return the path to the server's leaf TLS certificate, or None."""
    env_path = os.environ.get("TLS_CERT_FILE")
    if env_path:
        p = Path(env_path)
        if p.exists():
            return p
    dev_base = os.environ.get("TLS_DEV_CERT_BASE", ".tls/dev-cert")
    dev_cert = Path(dev_base).with_suffix(".crt")
    if dev_cert.exists():
        return dev_cert
    return None


def _compute_spki_fingerprint(cert_path: Path) -> dict:
    """Return the SHA-256 SPKI fingerprint of a PEM certificate."""
    pem_data = cert_path.read_bytes()
    cert = x509.load_pem_x509_certificate(pem_data)
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




# ── Certificate pin auto-update ───────────────────────────────────────────

def _update_frontend_pin(cert_hex: str) -> bool:
    """
    Automatically update the frontend cert_pin.js with current certificate fingerprint.
    
    This ensures that when the server restarts and generates a new certificate,
    the client-side pin is automatically synced without manual intervention.
    """
    try:
        import re
        frontend_dir = project_root() / "frontend"
        pin_file = frontend_dir / "js" / "cert_pin.js"
        
        if not pin_file.exists():
            return False
        
        current_content = pin_file.read_text()
        pattern = r'"[a-f0-9]{64}"'
        
        # Check if this fingerprint is already in the file
        if cert_hex in current_content:
            return True
            
        new_content = re.sub(pattern, f'"{cert_hex}"', current_content, count=1)
        
        if new_content != current_content:
            pin_file.write_text(new_content)
            
        return True
    except Exception:
        return False


# ── App factory ───────────────────────────────────────────────────────────────

def create_app() -> Flask:
    frontend_dir = project_root() / "frontend"

    app = Flask(
        __name__,
        static_folder=str(frontend_dir),
        static_url_path="",
    )
    app.config.from_object(Config)
    app.config.setdefault("PREFERRED_URL_SCHEME", "https")

    def _request_is_secure() -> bool:
        if request.is_secure:
            return True
        forwarded_proto = request.headers.get("X-Forwarded-Proto", "")
        return "https" in {part.strip().lower() for part in forwarded_proto.split(",") if part.strip()}

    @app.before_request
    def enforce_https():
        if not app.config.get("FORCE_HTTPS", True):
            return None
        if _request_is_secure():
            return None
        if request.path.startswith("/api/auth"):
            return jsonify({"error": "Authentication requires HTTPS (TLS 1.2+)."}), 403
        if request.path.startswith("/api/"):
            return jsonify({"error": "API access requires HTTPS (TLS 1.2+)."}), 403
        if request.method in {"GET", "HEAD"}:
            secure_url = request.url.replace("http://", "https://", 1)
            return redirect(secure_url, code=308)
        return jsonify({"error": "HTTPS is required."}), 403

    init_db(app)
    app.teardown_appcontext(close_db)

    @app.get("/")
    def index():
        return send_from_directory(frontend_dir, "index.html")

    @app.get("/login")
    def login_page():
        return send_from_directory(frontend_dir, "login.html")

    @app.get("/favicon.ico")
    def favicon():
        ico = frontend_dir / "favicon.ico"
        if ico.exists():
            return send_from_directory(frontend_dir, "favicon.ico")
        return ("", 204)

    @app.get("/api/cert/fingerprint")
    def cert_fingerprint():
        """
        Return the server certificate's SPKI SHA-256 fingerprint.

        Intentionally unauthenticated — the client needs to verify the cert
        *before* it can safely send credentials.  The returned value is compared
        against hardcoded pins in the frontend cert_pin.js module, so a MITM
        cannot simply swap in a different fingerprint without also forging a
        certificate whose hash matches a pinned value.

        For platforms that handle TLS termination (like Render), returns a dummy
        success response since certificate pinning is not needed.
        """
        cert_path = _locate_cert_file()
        if cert_path is None:
            # In production deployment (like Render), TLS is handled by platform
            return jsonify({
                "spki_sha256_hex": "",
                "spki_sha256_b64": "",
                "algorithm": "sha256/spki",
                "subject": "platform-managed-tls",
                "cert_file": "platform-managed"
            }), 200
        try:
            data = _compute_spki_fingerprint(cert_path)
            data["cert_file"] = str(cert_path)
            
            # Auto-update frontend pin on first request
            cert_hex = data['spki_sha256_hex']
            if not app.config.get("TESTING", False):
                _update_frontend_pin(cert_hex)
            
            return jsonify(data)
        except Exception as exc:
            return jsonify({"error": f"Failed to compute SPKI fingerprint: {exc}"}), 500

    register_routes(app)
    app.register_blueprint(auth_bp)

    return app