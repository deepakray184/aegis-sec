"""
Cookie Security Flags and Cross-Origin Resource Sharing (CORS) Auditor.
"""

from typing import List, Dict, Tuple, Any
import urllib.request
from urllib.parse import urlparse
from aegis_core.models import Finding, Severity, Category
from aegis_core.remediation import get_cors_remediation_code


class CookiesCORSAuditor:
    def __init__(self, url: str, response_headers: Dict[str, str], timeout: float = 6.0):
        self.url = url
        self.parsed = urlparse(url)
        self.response_headers = {k.lower(): v for k, v in response_headers.items()}
        self.timeout = timeout

    def audit(self) -> Tuple[List[Finding], Dict[str, Any]]:
        findings: List[Finding] = []
        details: Dict[str, Any] = {
            "cookies": [],
            "cors_tests": {},
        }

        # 1. Audit Set-Cookie headers
        cookie_findings, cookie_details = self._audit_cookies()
        findings.extend(cookie_findings)
        details["cookies"] = cookie_details

        # 2. Audit CORS configuration
        cors_findings, cors_details = self._audit_cors()
        findings.extend(cors_findings)
        details["cors_tests"] = cors_details

        return findings, details

    def _audit_cookies(self) -> Tuple[List[Finding], List[Dict[str, Any]]]:
        findings = []
        cookie_list = []

        # Find all Set-Cookie headers (or comma-separated if aggregated)
        set_cookie_raw = self.response_headers.get("set-cookie")
        if not set_cookie_raw:
            return findings, cookie_list

        # Split multiple cookies if necessary
        cookie_strings = [c.strip() for c in set_cookie_raw.split("\n") if c.strip()]
        if len(cookie_strings) == 1 and ", " in set_cookie_raw:
            # Check if multiple cookies were joined
            potential = set_cookie_raw.split(", ")
            cookie_strings = potential

        for cookie_str in cookie_strings:
            parts = [p.strip() for p in cookie_str.split(";")]
            if not parts or "=" not in parts[0]:
                continue

            cookie_name = parts[0].split("=")[0].strip()
            flags = {p.lower().split("=")[0].strip(): p.split("=")[1].strip() if "=" in p else True for p in parts[1:]}

            cookie_info = {
                "name": cookie_name,
                "has_secure": "secure" in flags,
                "has_httponly": "httponly" in flags,
                "samesite": flags.get("samesite", None),
            }
            cookie_list.append(cookie_info)

            # Check Secure flag
            if not cookie_info["has_secure"] and self.parsed.scheme == "https":
                findings.append(
                    Finding(
                        id=f"COOKIE-NO-SECURE-{cookie_name}",
                        title=f"Cookie Missing 'Secure' Attribute: {cookie_name}",
                        severity=Severity.MEDIUM,
                        category=Category.COOKIES_CORS,
                        description=f"Cookie '{cookie_name}' was set without the 'Secure' flag over HTTPS.",
                        impact="The browser will transmit this cookie over unencrypted HTTP connections if requested, risking credential eavesdropping.",
                        remediation="Append '; Secure' to the Set-Cookie directive.",
                        evidence=f"Set-Cookie: {cookie_str}",
                        owasp_category="A05:2021-Security Misconfiguration",
                        cwe_id="CWE-614",
                        cvss_score=5.3,
                        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#secure"],
                    )
                )

            # Check HttpOnly flag
            if not cookie_info["has_httponly"]:
                # High severity if it looks like a session/auth cookie, medium otherwise
                is_session = any(k in cookie_name.lower() for k in ["session", "token", "auth", "jwt", "id", "sid"])
                findings.append(
                    Finding(
                        id=f"COOKIE-NO-HTTPONLY-{cookie_name}",
                        title=f"Cookie Missing 'HttpOnly' Attribute: {cookie_name}",
                        severity=Severity.HIGH if is_session else Severity.LOW,
                        category=Category.COOKIES_CORS,
                        description=f"Cookie '{cookie_name}' does not include the 'HttpOnly' attribute.",
                        impact="Client-side scripts (JavaScript via document.cookie) can access this cookie. In the event of a Cross-Site Scripting (XSS) vulnerability, an attacker can steal session cookies directly.",
                        remediation="Append '; HttpOnly' to the Set-Cookie directive.",
                        evidence=f"Set-Cookie: {cookie_str}",
                        owasp_category="A07:2021-Identification and Authentication Failures",
                        cwe_id="CWE-1004",
                        cvss_score=6.5 if is_session else 3.5,
                        references=["https://owasp.org/www-community/HttpOnly"],
                    )
                )

            # Check SameSite attribute
            if not cookie_info["samesite"]:
                findings.append(
                    Finding(
                        id=f"COOKIE-NO-SAMESITE-{cookie_name}",
                        title=f"Cookie Missing 'SameSite' Attribute: {cookie_name}",
                        severity=Severity.LOW,
                        category=Category.COOKIES_CORS,
                        description=f"Cookie '{cookie_name}' lacks the 'SameSite' attribute.",
                        impact="Increases vulnerability to Cross-Site Request Forgery (CSRF) in legacy browsers.",
                        remediation="Add '; SameSite=Lax' or '; SameSite=Strict' to the Set-Cookie directive.",
                        evidence=f"Set-Cookie: {cookie_str}",
                        owasp_category="A01:2021-Broken Access Control",
                        cwe_id="CWE-1275",
                        cvss_score=3.7,
                    )
                )

        return findings, cookie_list

    def _audit_cors(self) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        cors_info = {}

        test_origins = [
            ("arbitrary_origin", "https://attacker-origin.example.com"),
            ("null_origin", "null"),
        ]

        for test_type, origin_val in test_origins:
            try:
                req = urllib.request.Request(
                    self.url,
                    headers={
                        "Origin": origin_val,
                        "User-Agent": "AegisSec-Auditor/2.0",
                    },
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    acao = headers.get("access-control-allow-origin")
                    acac = headers.get("access-control-allow-credentials", "").lower() == "true"

                    cors_info[test_type] = {"origin_sent": origin_val, "acao": acao, "acac": acac}

                    if acao == origin_val and acac:
                        findings.append(
                            Finding(
                                id=f"CORS-CRITICAL-REFLECTION-{test_type.upper()}",
                                title="Critical CORS Misconfiguration: Arbitrary Origin Reflection with Credentials",
                                severity=Severity.CRITICAL,
                                category=Category.COOKIES_CORS,
                                description=(
                                    f"The server reflected the untrusted origin '{origin_val}' in Access-Control-Allow-Origin "
                                    "AND responded with 'Access-Control-Allow-Credentials: true'."
                                ),
                                impact="Allows malicious websites to read authenticated user responses, hijack sessions, and steal sensitive account data cross-origin.",
                                remediation="Whitelist trusted origins strictly. Never dynamically reflect untrusted Origin headers with Allow-Credentials: true.",
                                evidence=f"Origin: {origin_val} -> Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: true",
                                owasp_category="A01:2021-Broken Access Control",
                                cwe_id="CWE-942",
                                cvss_score=8.8,
                                references=["https://portswigger.net/web-security/cors"],
                                remediation_code=get_cors_remediation_code(),
                            )
                        )
                    elif acao == "*" and acac:
                        findings.append(
                            Finding(
                                id="CORS-WILDCARD-CREDENTIALS",
                                title="Invalid CORS: Wildcard Origin with Credentials",
                                severity=Severity.HIGH,
                                category=Category.COOKIES_CORS,
                                description="The server specified Access-Control-Allow-Origin: * along with Access-Control-Allow-Credentials: true.",
                                impact="Standard browsers reject this combination, but it demonstrates misconfigured cross-origin policy.",
                                remediation="Specify a strictly trusted single origin when enabling credentials.",
                                evidence="Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
                                owasp_category="A01:2021-Broken Access Control",
                                cwe_id="CWE-942",
                                cvss_score=6.5,
                            )
                        )
                    elif acao == origin_val:
                        findings.append(
                            Finding(
                                id=f"CORS-PERMISSIVE-REFLECTION-{test_type.upper()}",
                                title=f"Permissive CORS: Arbitrary Origin Reflection ({test_type})",
                                severity=Severity.MEDIUM,
                                category=Category.COOKIES_CORS,
                                description=f"The server reflected untrusted origin '{origin_val}' in Access-Control-Allow-Origin without credentials.",
                                impact="Allows any website to read public API or page data cross-origin.",
                                remediation="Restrict Access-Control-Allow-Origin to authorized domains only.",
                                evidence=f"Origin: {origin_val} -> Access-Control-Allow-Origin: {acao}",
                                owasp_category="A01:2021-Broken Access Control",
                                cwe_id="CWE-942",
                                cvss_score=5.3,
                                remediation_code=get_cors_remediation_code(),
                            )
                        )
            except Exception:
                pass

        return findings, cors_info
