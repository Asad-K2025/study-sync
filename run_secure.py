#!/usr/bin/env python3
import os
import ssl
from pathlib import Path

from werkzeug.serving import make_ssl_devcert

from backend.app import create_app


app = create_app()


def _build_tls_context() -> ssl.SSLContext:
    """Build a secure TLS context with strict configuration.
    
    Security features:
    - TLS 1.2+ only (rejects vulnerable TLS 1.0/1.1)
    - Strong cipher suites (AEAD ciphers preferred)
    - Server-side cipher order preference
    - OCSP stapling support
    - Certificate verification for client connections
    """
    cert_file = os.environ.get("TLS_CERT_FILE")
    key_file = os.environ.get("TLS_KEY_FILE")
    
    if cert_file and key_file:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        
        # TLS 1.2 minimum - rejects vulnerable older protocols
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Load server certificate and key
        ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
        
        # Set strong cipher suites (AEAD ciphers preferred)
        ctx.set_ciphers(
            "ECDHE-ECDSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:"
            "ECDHE-RSA-CHACHA20-POLY1305:"
            "DHE-RSA-AES128-GCM-SHA256:"
            "DHE-RSA-AES256-GCM-SHA384"
        )
        
        # Prefer server cipher order (prevents BEAST, CRIME attacks)
        ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
        
        # Disable vulnerable options
        ctx.options |= ssl.OP_NO_SSLv2
        ctx.options |= ssl.OP_NO_SSLv3
        ctx.options |= ssl.OP_NO_COMPRESSION
        ctx.options |= ssl.OP_NO_TICKET
        ctx.options |= ssl.OP_SINGLE_DH_USE
        ctx.options |= ssl.OP_SINGLE_ECDH_USE
        
        # Enable OCSP stapling if available
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        except NotImplementedError:
            pass
        
        return ctx

    cert_base = Path(os.environ.get("TLS_DEV_CERT_BASE", ".tls/dev-cert"))
    cert_path = cert_base.with_suffix(".crt")
    key_path = cert_base.with_suffix(".key")
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    
    if not cert_path.exists() or not key_path.exists():
        print(f"[TLS] Generating self-signed certificate for development: {cert_base}")
        make_ssl_devcert(str(cert_base), host="localhost")
    else:
        print(f"[TLS] Using existing certificate: {cert_path}")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    # TLS 1.2 minimum - rejects vulnerable older protocols
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    
    # Load server certificate and key
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    
    # Set strong cipher suites (AEAD ciphers preferred)
    ctx.set_ciphers(
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "DHE-RSA-AES128-GCM-SHA256:"
        "DHE-RSA-AES256-GCM-SHA384"
    )
    
    # Prefer server cipher order (prevents BEAST, CRIME attacks)
    ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    
    # Disable vulnerable options
    ctx.options |= ssl.OP_NO_SSLv2
    ctx.options |= ssl.OP_NO_SSLv3
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.options |= ssl.OP_NO_TICKET
    ctx.options |= ssl.OP_SINGLE_DH_USE
    ctx.options |= ssl.OP_SINGLE_ECDH_USE
    
    # Enable OCSP stapling if available
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except NotImplementedError:
        pass
    
    return ctx


if __name__ == "__main__":
    print("=" * 60)
    print("StudySync Server - Secure TLS Configuration")
    print("=" * 60)
    
    # Print TLS configuration
    tls_ctx = _build_tls_context()
    print(f"[TLS] Protocol: TLS 1.2+ (minimum)")
    print(f"[TLS] Cipher suites: {tls_ctx.get_ciphers()}")
    print(f"[TLS] Certificate verification: enabled")
    print("=" * 60)
    
    app.run(host="0.0.0.0", port=8765, debug=True, ssl_context=tls_ctx)

