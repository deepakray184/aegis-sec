"""
SSL / TLS Configuration, Certificate Analysis, and Transport Layer Auditor.
"""

from typing import List, Dict, Tuple, Any, Optional
import ssl
import socket
from datetime import datetime, timezone
import urllib.request
import urllib.error
from urllib.parse import urlparse
from aegis_core.models import Finding, Severity, Category


class TLSAuditor:
    def __init__(self, hostname: str, port: int = 443, timeout: float = 6.0):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout

    def audit(self) -> Tuple[List[Finding], Dict[str, Any]]:
        findings: List[Finding] = []
        details: Dict[str, Any] = {
            "certificate": {},
            "protocols": {},
            "http_redirect": {},
            "cipher": None,
        }

        # 1. Inspect SSL/TLS Certificate
        cert_info = self._get_certificate_details()
        details["certificate"] = cert_info

        if not cert_info.get("connected"):
            findings.append(
                Finding(
                    id="TLS-CONN-FAIL",
                    title="TLS/SSL Connection Failed or Not Supported",
                    severity=Severity.CRITICAL,
                    category=Category.TLS_SSL,
                    description=f"Could not establish a secure TLS/SSL handshake with {self.hostname}:{self.port}. Error: {cert_info.get('error', 'Unknown')}",
                    impact="Users cannot connect securely to this service. Data in transit is vulnerable to interception.",
                    remediation="Deploy a valid SSL/TLS certificate and configure HTTPS listener on port 443.",
                    evidence=f"Handshake error: {cert_info.get('error')}",
                    owasp_category="A02:2021-Cryptographic Failures",
                    cwe_id="CWE-319",
                    cvss_score=8.5,
                )
            )
            return findings, details

        # 2. Check Expiration & Validity
        days_left = cert_info.get("days_remaining")
        if days_left is not None:
            if days_left < 0:
                findings.append(
                    Finding(
                        id="TLS-CERT-EXPIRED",
                        title="SSL/TLS Certificate is Expired",
                        severity=Severity.CRITICAL,
                        category=Category.TLS_SSL,
                        description=f"The SSL/TLS certificate expired {abs(days_left)} days ago ({cert_info.get('not_after')}).",
                        impact="Browsers will block user access with severe security warnings, leading to total denial of service and loss of trust.",
                        remediation="Immediately renew and deploy a valid SSL/TLS certificate.",
                        evidence=f"Expires: {cert_info.get('not_after')} (Days remaining: {days_left})",
                        owasp_category="A02:2021-Cryptographic Failures",
                        cwe_id="CWE-298",
                        cvss_score=8.0,
                    )
                )
            elif days_left < 15:
                findings.append(
                    Finding(
                        id="TLS-CERT-EXPIRING-SOON",
                        title=f"SSL/TLS Certificate Expiring Soon ({days_left} Days Remaining)",
                        severity=Severity.HIGH,
                        category=Category.TLS_SSL,
                        description=f"The certificate will expire in {days_left} days on {cert_info.get('not_after')}.",
                        impact="If not renewed promptly, users will experience service outages and security warnings.",
                        remediation="Renew certificate immediately or ensure automated renewal (e.g. Certbot/ACME) is operating.",
                        evidence=f"Days until expiry: {days_left}",
                        owasp_category="A02:2021-Cryptographic Failures",
                        cwe_id="CWE-298",
                        cvss_score=6.5,
                    )
                )
            elif days_left < 30:
                findings.append(
                    Finding(
                        id="TLS-CERT-EXPIRING-30D",
                        title=f"SSL/TLS Certificate Renewal Recommended ({days_left} Days Remaining)",
                        severity=Severity.LOW,
                        category=Category.TLS_SSL,
                        description=f"The certificate has {days_left} days of validity remaining.",
                        impact="Approaching renewal window.",
                        remediation="Schedule certificate renewal.",
                        evidence=f"Days until expiry: {days_left}",
                        owasp_category="A02:2021-Cryptographic Failures",
                        cwe_id="CWE-298",
                        cvss_score=3.0,
                    )
                )

        # 3. Check Protocol Support (e.g. deprecated TLS 1.0, 1.1)
        protocol_findings = self._check_deprecated_protocols()
        findings.extend(protocol_findings)

        # 4. Check HTTP to HTTPS Redirection
        redirect_finding, redirect_info = self._check_http_to_https_redirect()
        details["http_redirect"] = redirect_info
        if redirect_finding:
            findings.append(redirect_finding)

        # 5. Check Cipher Suite & Negotiated Version
        cipher_tuple = cert_info.get("cipher")
        details["cipher"] = cipher_tuple
        if cipher_tuple:
            cipher_name, proto, bits = cipher_tuple
            if bits < 128:
                findings.append(
                    Finding(
                        id="TLS-WEAK-CIPHER",
                        title=f"Weak Negotiated Cipher Suite ({bits}-bit)",
                        severity=Severity.HIGH,
                        category=Category.TLS_SSL,
                        description=f"The negotiated cipher suite '{cipher_name}' uses weak {bits}-bit encryption.",
                        impact="Insufficient encryption strength allows potential eavesdropping or decryption of sensitive traffic.",
                        remediation="Disable weak ciphers and enforce modern AES-GCM or CHACHA20-POLY1305 ciphers with minimum 128-bit key length.",
                        evidence=f"Cipher: {cipher_name}, Protocol: {proto}, Bits: {bits}",
                        owasp_category="A02:2021-Cryptographic Failures",
                        cwe_id="CWE-326",
                        cvss_score=7.1,
                    )
                )

        return findings, details

    def _get_certificate_details(self) -> Dict[str, Any]:
        """Fetches and parses the target's peer certificate."""
        result: Dict[str, Any] = {"connected": False}
        context = ssl.create_default_context()

        try:
            connect_timeout = min(self.timeout, 3.0)
            with socket.create_connection((self.hostname, self.port), timeout=connect_timeout) as sock:
                sock.settimeout(connect_timeout)
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    result["connected"] = True
                    result["cipher"] = ssock.cipher()
                    result["tls_version"] = ssock.version()

                    # Parse Common Name & Subject
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    result["subject"] = subject
                    result["common_name"] = subject.get("commonName")
                    result["issuer"] = issuer
                    result["issuer_org"] = issuer.get("organizationName", issuer.get("commonName"))

                    # Subject Alternative Names (SANs)
                    sans = [item[1] for item in cert.get("subjectAltName", []) if item[0] == "DNS"]
                    result["sans"] = sans

                    # Validity
                    not_before_str = cert.get("notBefore")
                    not_after_str = cert.get("notAfter")
                    result["not_before"] = not_before_str
                    result["not_after"] = not_after_str

                    if not_after_str:
                        # Format example: 'Oct 24 12:00:00 2026 GMT'
                        expiry_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        now_dt = datetime.now(timezone.utc)
                        delta = (expiry_dt - now_dt).days
                        result["days_remaining"] = delta

        except ssl.SSLCertVerificationError as e:
            result["connected"] = True
            result["verification_error"] = str(e)
            result["error"] = f"SSL Certificate Verification Failed: {e.verify_message}"
        except Exception as e:
            result["error"] = str(e)

        return result

    def _check_deprecated_protocols(self) -> List[Finding]:
        """Tests if obsolete TLS 1.0 or TLS 1.1 are enabled."""
        findings = []
        protocols_to_test = []

        # Check if Python environment supports testing older protocols
        if hasattr(ssl, "PROTOCOL_TLSv1"):
            protocols_to_test.append(("TLSv1.0", ssl.PROTOCOL_TLSv1))
        if hasattr(ssl, "PROTOCOL_TLSv1_1"):
            protocols_to_test.append(("TLSv1.1", ssl.PROTOCOL_TLSv1_1))

        for proto_name, proto_const in protocols_to_test:
            try:
                ctx = ssl.SSLContext(proto_const)
                ctx.set_ciphers("ALL:@SECLEVEL=0")
                with socket.create_connection((self.hostname, self.port), timeout=2.0) as sock:
                    sock.settimeout(2.0)
                    with ctx.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                        findings.append(
                            Finding(
                                id=f"TLS-DEPRECATED-{proto_name.replace('.', '_')}",
                                title=f"Deprecated Protocol Supported: {proto_name}",
                                severity=Severity.HIGH,
                                category=Category.TLS_SSL,
                                description=f"The server successfully negotiated a handshake using {proto_name}, which is officially deprecated (RFC 8996).",
                                impact="Deprecated protocols suffer from known cryptographic vulnerabilities (POODLE, BEAST) and lack modern forward secrecy guarantees.",
                                remediation=f"Disable {proto_name} in your web server / load balancer configuration and enforce TLS 1.2 and TLS 1.3 only.",
                                evidence=f"Handshake succeeded with {proto_name}.",
                                owasp_category="A02:2021-Cryptographic Failures",
                                cwe_id="CWE-326",
                                cvss_score=7.4,
                                references=["https://datatracker.ietf.org/doc/rfc8996/"],
                            )
                        )
            except Exception:
                # Protocol failed to handshake, which is desirable
                pass

        return findings

    def _check_http_to_https_redirect(self) -> Tuple[Optional[Finding], Dict[str, Any]]:
        """Checks if port 80 (HTTP) automatically redirects to HTTPS."""
        info: Dict[str, Any] = {"redirects_to_https": False, "status_code": None, "redirect_location": None}
        http_url = f"http://{self.hostname}/"

        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            def http_error_301(self, req, fp, code, msg, headers):
                return fp
            def http_error_302(self, req, fp, code, msg, headers):
                return fp
            def http_error_307(self, req, fp, code, msg, headers):
                return fp
            def http_error_308(self, req, fp, code, msg, headers):
                return fp

        opener = urllib.request.build_opener(NoRedirectHandler)
        req = urllib.request.Request(http_url, headers={"User-Agent": "AegisSec-Auditor/2.0"})

        try:
            with opener.open(req, timeout=self.timeout) as resp:
                status = getattr(resp, "status", getattr(resp, "code", 200))
                location = resp.headers.get("Location", "")
                info["status_code"] = status
                info["redirect_location"] = location

                if status in (301, 302, 307, 308) and location.startswith("https://"):
                    info["redirects_to_https"] = True
                    return None, info
                else:
                    return (
                        Finding(
                            id="TLS-NO-HTTPS-REDIRECT",
                            title="Plain HTTP Does Not Redirect to HTTPS",
                            severity=Severity.HIGH,
                            category=Category.TLS_SSL,
                            description=f"Initial request to '{http_url}' returned HTTP {status} without redirecting directly to HTTPS.",
                            impact="Users entering the domain without 'https://' may transmit session tokens or credentials in cleartext over unencrypted HTTP.",
                            remediation="Configure a permanent HTTP 301 redirect from HTTP (port 80) to HTTPS (port 443).",
                            evidence=f"HTTP {status} -> Location: '{location or 'None'}'",
                            owasp_category="A02:2021-Cryptographic Failures",
                            cwe_id="CWE-319",
                            cvss_score=7.2,
                        ),
                        info,
                    )
        except urllib.error.URLError as e:
            info["error"] = str(e)
            # Port 80 might be closed or timed out, which is also an acceptable posture if only 443 is open
            return None, info
        except Exception as e:
            info["error"] = str(e)
            return None, info
