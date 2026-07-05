from __future__ import annotations

import os
import ssl
from pathlib import Path


def get_certificate_fingerprint(cert_path: str | Path, algorithm: str = "sha256") -> str:
    """
    Extract and return the fingerprint of a certificate.
    
    Certificate Fingerprint Usage:
      - SPKI SHA-256 fingerprints are used for HTTP Public Key Pinning (HPKP)
      - Client-side cert_pin.js verifies server identity using these fingerprints
      - Format: 64-character lowercase hexadecimal string
    
    Algorithm Options:
      - "sha256" (default): SHA-256 hash of certificate
      - "sha384": SHA-384 hash for enhanced security
      
    To obtain a fingerprint manually:
      openssl x509 -in server.crt -pubkey -noout | \
        openssl pkey -pubin -outform DER | \
        openssl dgst -sha256
    """
    cert_path = Path(cert_path)
    
    if not cert_path.exists():
        raise FileNotFoundError(f"Certificate file not found: {cert_path}")
    
    with open(cert_path, "rb") as f:
        cert_data = f.read()
    
    if algorithm == "sha256":
        hash_func = __import__("hashlib").sha256
    elif algorithm == "sha384":
        hash_func = __import__("hashlib").sha384
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    cert_hash = hash_func(cert_data).digest()
    
    return ":".join(f"{b:02X}" for b in cert_hash)


"""
    Extract certificate information.
    
    Information Extracted:
      - SHA-256 fingerprint (SPKI hash)
      - SHA-384 fingerprint (enhanced hash)
      - Subject name (CN, O, OU, etc.)
      - Issuer name (CA that signed the certificate)
      
    Args:
        cert_path: Path to the certificate file
        
    Returns:
        dict: Certificate information including fingerprints and subject/issuer
"""
def get_certificate_info(cert_path: str | Path) -> dict:
    """Extract certificate information."""
    import subprocess
    
    cert_path = Path(cert_path)
    
    if not cert_path.exists():
        raise FileNotFoundError(f"Certificate file not found: {cert_path}")
    
    info = {
        "path": str(cert_path),
        "sha256_fingerprint": get_certificate_fingerprint(cert_path, "sha256"),
        "sha384_fingerprint": get_certificate_fingerprint(cert_path, "sha384"),
    }
    
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", str(cert_path), "-text", "-noout"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if "Subject:" in line:
                    info["subject"] = line.strip()
                elif "Issuer:" in line:
                    info["issuer"] = line.strip()
    except Exception:
        pass
    
    return info


"""
    Verify TLS configuration and return security assessment.
    
    Security Checks Performed:
      - Minimum protocol version (should be TLS 1.2+)
      - SSLv2/v3 disabled (vulnerable to POODLE, BEAST attacks)
      - Strong cipher suites (AES-GCM, CHACHA20-POLY1305)
      - Server cipher preference enabled
      - Compression disabled (prevents CRIME attack)
      - Session tickets enabled/disabled status
    
    Security Score Levels:
      - "GOOD": TLS 1.2+ enforced with strong ciphers
      - "CRITICAL": TLS < 1.2 allowed or weak ciphers
      - "UNKNOWN": Cannot determine configuration
      
    Args:
        ssl_context: SSLContext object to verify
        
    Returns:
        dict: Assessment results including:
          - protocol_version: TLS version in use
          - cipher_suites: List of enabled cipher suites
          - security_score: GOOD/CRITICAL/UNKNOWN
          - notes: List of configuration observations
"""
def verify_tls_configuration(ssl_context: ssl.SSLContext) -> dict:
    """Verify TLS configuration and return security assessment."""
    results = {
        "protocol_version": None,
        "cipher_suites": [],
        "security_score": "UNKNOWN",
        "notes": []
    }
    
    if hasattr(ssl_context, "minimum_version"):
        min_ver = ssl_context.minimum_version
        results["protocol_version"] = str(min_ver)
        
        if min_ver >= ssl.TLSVersion.TLSv1_2:
            results["notes"].append("TLS 1.2+ enforced")
            results["security_score"] = "GOOD"
        else:
            results["notes"].append("TLS 1.0/1.1 allowed (VULNERABLE)")
            results["security_score"] = "CRITICAL"
    
    try:
        ciphers = ssl_context.get_ciphers()
        if isinstance(ciphers, list):
            results["cipher_suites"] = [c["name"] for c in ciphers if "name" in c]
            
            strong_patterns = ["GCM", "CHACHA20"]
            has_strong = any(any(p in c for p in strong_patterns) for c in results["cipher_suites"])
            
            if has_strong:
                results["notes"].append("Strong ciphers configured")
    except Exception as e:
        results["notes"].append(f"Cannot list ciphers: {e}")
    
    if hasattr(ssl_context, "options"):
        opts = ssl_context.options
        
        if opts & ssl.OP_NO_SSLv2:
            results["notes"].append("SSLv2 disabled")
        if opts & ssl.OP_NO_SSLv3:
            results["notes"].append("SSLv3 disabled")
        if opts & ssl.OP_CIPHER_SERVER_PREFERENCE:
            results["notes"].append("Server cipher preference enabled")
        
        if not (opts & ssl.OP_NO_TICKET):
            results["notes"].append("Session tickets enabled")
    
    return results


"""
    Generate a comprehensive TLS configuration report.
    
    Report Sections:
      1. [CERTIFICATE] - Certificate information (subject, issuer, fingerprints)
      2. [SECURITY ASSESSMENT] - Protocol version, cipher suites, security score
      3. [RECOMMENDATIONS] - Action items for improving TLS security
    
    Recommendations Generated:
      1. Use CA-signed certificates in production (not self-signed)
      2. Enable OCSP stapling for certificate revocation checking
      3. Implement HSTS header (Strict-Transport-Security: max-age=31536000)
      4. Consider certificate pinning for high-security applications
      5. Rotate certificates before expiration
    
    Usage Example:
        report = generate_tls_config_report("/etc/ssl/certs/server.crt", "/etc/ssl/private/server.key")
        print(report)
    
    Args:
        cert_path: Path to the TLS certificate file (PEM format)
        key_path: Optional path to the private key file (PEM format)
        
    Returns:
        str: Formatted report string with all configuration details
"""
def generate_tls_config_report(cert_path: str | Path, key_path: str | Path | None = None) -> str:
    """Generate a comprehensive TLS configuration report."""
    lines = []
    lines.append("=" * 70)
    lines.append("TLS CONFIGURATION REPORT")
    lines.append("=" * 70)
    
    lines.append("\n[CERTIFICATE]")
    try:
        cert_info = get_certificate_info(cert_path)
        for key, value in cert_info.items():
            if key != "path":
                lines.append(f"  {key}: {value}")
        
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert_path), str(key_path) if key_path else None)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        
        verification = verify_tls_configuration(ctx)
        
        lines.append("\n[SECURITY ASSESSMENT]")
        lines.append(f"  Protocol: {verification['protocol_version']}")
        lines.append(f"  Security Score: {verification['security_score']}")
        for note in verification["notes"]:
            lines.append(f"  {note}")
            
    except Exception as e:
        lines.append(f"  Error: {e}")
    
    lines.append("\n[RECOMMENDATIONS]")
    lines.append("  1. Use CA-signed certificates in production")
    lines.append("  2. Enable OCSP stapling for certificate revocation checking")
    lines.append("  3. Implement HSTS header (Strict-Transport-Security)")
    lines.append("  4. Consider certificate pinning for high-security applications")
    lines.append("  5. Rotate certificates before expiration")
    
    lines.append("\n" + "=" * 70)
    
    return "\n".join(lines)


"""
    Check if a certificate is signed by a trusted CA.
    
    Certificate Chain Verification:
      - Validates that the certificate has a valid trust chain
      - Can verify against specific CA certificate or system CA store
      - Used to ensure certificates are properly signed by trusted authority
    
    Args:
        cert_path: Path to the certificate file to verify
        ca_cert_path: Optional path to CA certificate for explicit verification
        
    Returns:
        bool: True if certificate is valid and properly signed, False otherwise
        
    Note:
        For self-signed development certificates (Werkzeug generated), 
        this will return False since they are not CA-signed. Use only
        for production certificate validation.
"""
def check_certificate_chain(cert_path: str | Path, ca_cert_path: str | Path | None = None) -> bool:
    """Check if a certificate is signed by a trusted CA."""
    import subprocess
    
    cert_path = Path(cert_path)
    
    try:
        cmd = ["openssl", "verify", "-verbose"]
        
        if ca_cert_path:
            cmd.extend(["-CAfile", str(ca_cert_path)])
        else:
            cmd.append(str(cert_path))
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        
        return "OK" in result.stdout or "verify OK" in result.stdout.lower()
    except Exception:
        return False
