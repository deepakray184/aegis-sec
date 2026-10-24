"""
HTTP Security Headers and Server Information Disclosure Auditor.
"""

from typing import List, Dict, Tuple, Any
import re
from urllib.parse import urlparse
from aegis_core.models import Finding, Severity, Category
from aegis_core.config import SECURITY_HEADERS_SPEC
from aegis_core.remediation import get_headers_remediation_code


class HeadersAuditor:
    def __init__(self, headers: Dict[str, str], status_code: int, url: str):
        # Normalize header keys to lowercase for case-insensitive lookup
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.raw_headers = headers
        self.status_code = status_code
        self.url = url
        self.domain = urlparse(url).netloc

    def audit(self) -> Tuple[List[Finding], Dict[str, Any]]:
        findings: List[Finding] = []
        details: Dict[str, Any] = {
            "present_headers": {},
            "missing_headers": [],
            "information_leaks": [],
        }

        # 1. Audit missing or weak standard security headers
        for header_name, spec in SECURITY_HEADERS_SPEC.items():
            header_lower = header_name.lower()
            if header_lower not in self.headers:
                if spec["required"]:
                    findings.append(
                        Finding(
                            id=f"HDR-MISSING-{header_name.upper().replace('-', '_')}",
                            title=f"Missing Security Header: {header_name}",
                            severity=Severity(spec["severity_missing"]),
                            category=Category.HEADERS,
                            description=spec["description"],
                            impact=f"Without {header_name}, the browser lacks client-side security controls, increasing exposure to attacks.",
                            remediation=f"Configure your web server or reverse proxy to return the header: '{header_name}: {spec['recommended']}'.",
                            evidence=f"Header '{header_name}' was not returned in HTTP response (HTTP status {self.status_code}).",
                            owasp_category=spec["owasp"],
                            cwe_id=spec["cwe"],
                            cvss_score=5.3 if spec["severity_missing"] == "HIGH" else 3.7,
                            references=[
                                f"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{header_name}",
                                "https://owasp.org/www-project-secure-headers/",
                            ],
                            remediation_code=get_headers_remediation_code(),
                        )
                    )
                    details["missing_headers"].append(header_name)
                else:
                    details["missing_headers"].append(header_name)
            else:
                value = self.headers[header_lower]
                details["present_headers"][header_name] = value
                # Inspect specific header values for misconfigurations
                self._inspect_header_value(header_name, value, findings)

        # 2. Audit Server / Tech Banner Information Leaks
        leak_headers = ["server", "x-powered-by", "x-aspnet-version", "x-runtime", "x-version", "via"]
        for leak in leak_headers:
            if leak in self.headers:
                val = self.headers[leak]
                details["information_leaks"].append({leak: val})
                # Check if it exposes exact version numbers
                has_version = bool(re.search(r"\d+\.\d+", val))
                findings.append(
                    Finding(
                        id=f"HDR-LEAK-{leak.upper().replace('-', '_')}",
                        title=f"Server Technology Banner Disclosure: {leak.title()}",
                        severity=Severity.LOW if has_version else Severity.INFO,
                        category=Category.EXPOSURE,
                        description=(
                            f"The HTTP response contains the '{leak}' header with value '{val}'. "
                            "Exposing exact server software and version numbers assists attackers in profiling the target "
                            "and searching for known CVEs affecting that specific release."
                        ),
                        impact="Facilitates reconnaissance and targeting of known vulnerabilities in specific software versions.",
                        remediation=f"Suppress or mask the '{leak}' header in your web server / application configuration.",
                        evidence=f"{leak}: {val}",
                        owasp_category="A05:2021-Security Misconfiguration",
                        cwe_id="CWE-200",
                        cvss_score=3.1 if has_version else 2.0,
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
                        ],
                        remediation_code=get_headers_remediation_code(),
                    )
                )

        return findings, details

    def _inspect_header_value(self, name: str, value: str, findings: List[Finding]):
        """Inspects quality and strength of configured security headers."""
        val_lower = value.lower()

        if name == "Strict-Transport-Security":
            # Check max-age
            match = re.search(r"max-age=(\d+)", val_lower)
            if not match:
                findings.append(
                    Finding(
                        id="HDR-HSTS-INVALID",
                        title="Invalid HSTS Configuration (Missing max-age)",
                        severity=Severity.HIGH,
                        category=Category.HEADERS,
                        description="Strict-Transport-Security header is present but lacks a valid max-age directive.",
                        impact="Browsers will ignore the HSTS directive, leaving users unprotected from downgrade attacks.",
                        remediation="Set 'max-age=31536000; includeSubDomains; preload'.",
                        evidence=f"Strict-Transport-Security: {value}",
                        owasp_category="A05:2021-Security Misconfiguration",
                        cwe_id="CWE-319",
                        cvss_score=5.0,
                    )
                )
            else:
                max_age = int(match.group(1))
                if max_age < 15552000:  # less than ~180 days
                    findings.append(
                        Finding(
                            id="HDR-HSTS-SHORT-MAXAGE",
                            title="HSTS max-age Duration Too Short",
                            severity=Severity.MEDIUM,
                            category=Category.HEADERS,
                            description=f"HSTS max-age is set to {max_age} seconds (recommended is at least 31536000 seconds / 1 year).",
                            impact="Short HSTS duration reduces the window of protection against SSL stripping attacks.",
                            remediation="Increase max-age to 31536000 (1 year) or 63072000 (2 years).",
                            evidence=f"Strict-Transport-Security: {value}",
                            owasp_category="A05:2021-Security Misconfiguration",
                            cwe_id="CWE-319",
                            cvss_score=4.0,
                        )
                    )
                if "includesubdomains" not in val_lower:
                    findings.append(
                        Finding(
                            id="HDR-HSTS-NO-SUBDOMAINS",
                            title="HSTS Missing includeSubDomains Directive",
                            severity=Severity.LOW,
                            category=Category.HEADERS,
                            description="HSTS policy does not cover subdomains, leaving subdomains vulnerable to insecure HTTP.",
                            impact="Attackers can intercept HTTP traffic on subdomains to capture session cookies or hijack traffic.",
                            remediation="Add 'includeSubDomains' to the Strict-Transport-Security header.",
                            evidence=f"Strict-Transport-Security: {value}",
                            owasp_category="A05:2021-Security Misconfiguration",
                            cwe_id="CWE-319",
                            cvss_score=3.5,
                        )
                    )

        elif name == "Content-Security-Policy":
            # Check for unsafe-inline or unsafe-eval
            if "'unsafe-inline'" in val_lower and "nonce" not in val_lower and "sha256" not in val_lower:
                findings.append(
                    Finding(
                        id="HDR-CSP-UNSAFE-INLINE",
                        title="Content-Security-Policy Allows 'unsafe-inline'",
                        severity=Severity.MEDIUM,
                        category=Category.HEADERS,
                        description="CSP policy permits inline scripts ('unsafe-inline') without nonce or hash restrictions.",
                        impact="Significantly reduces protection against Cross-Site Scripting (XSS) attacks.",
                        remediation="Use cryptographic nonces (nonce-...) or SHA-256 hashes instead of 'unsafe-inline'.",
                        evidence=f"Content-Security-Policy: {value}",
                        owasp_category="A03:2021-Injection",
                        cwe_id="CWE-79",
                        cvss_score=6.1,
                    )
                )
            if "'unsafe-eval'" in val_lower:
                findings.append(
                    Finding(
                        id="HDR-CSP-UNSAFE-EVAL",
                        title="Content-Security-Policy Allows 'unsafe-eval'",
                        severity=Severity.LOW,
                        category=Category.HEADERS,
                        description="CSP policy permits execution of eval() and similar dynamic code execution mechanisms.",
                        impact="Allows string-to-code execution which can be leveraged during exploitation.",
                        remediation="Refactor code to avoid eval() and remove 'unsafe-eval' from script-src.",
                        evidence=f"Content-Security-Policy: {value}",
                        owasp_category="A03:2021-Injection",
                        cwe_id="CWE-95",
                        cvss_score=3.8,
                    )
                )
            if "default-src *" in val_lower or "script-src *" in val_lower:
                findings.append(
                    Finding(
                        id="HDR-CSP-WILDCARD",
                        title="Content-Security-Policy Uses Overly Permissive Wildcard (*)",
                        severity=Severity.HIGH,
                        category=Category.HEADERS,
                        description="CSP includes wildcard origins (*) in default-src or script-src, allowing scripts from any external domain.",
                        impact="Negates the primary defensive purpose of CSP against malicious third-party script injection.",
                        remediation="Explicitly specify trusted source domains or use 'self'.",
                        evidence=f"Content-Security-Policy: {value}",
                        owasp_category="A05:2021-Security Misconfiguration",
                        cwe_id="CWE-1021",
                        cvss_score=6.5,
                    )
                )

        elif name == "X-Frame-Options":
            if val_lower not in ["deny", "sameorigin"]:
                findings.append(
                    Finding(
                        id="HDR-XFO-INVALID",
                        title="Invalid or Obsolete X-Frame-Options Directive",
                        severity=Severity.LOW,
                        category=Category.HEADERS,
                        description=f"X-Frame-Options has non-standard value '{value}'. The obsolete 'ALLOW-FROM' is no longer supported in modern browsers.",
                        impact="May result in the browser ignoring clickjacking protection.",
                        remediation="Set X-Frame-Options to DENY or SAMEORIGIN, or migrate to CSP frame-ancestors directive.",
                        evidence=f"X-Frame-Options: {value}",
                        owasp_category="A05:2021-Security Misconfiguration",
                        cwe_id="CWE-1021",
                        cvss_score=3.5,
                    )
                )
