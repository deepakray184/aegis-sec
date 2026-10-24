"""
HTTP Methods, WebDAV, and Server Verb Tampering Auditor.
"""

from typing import List, Dict, Tuple, Any
import urllib.request
import urllib.error
from urllib.parse import urlparse
from aegis_core.models import Finding, Severity, Category
from aegis_core.config import DEFAULT_USER_AGENT


class MethodsAuditor:
    def __init__(self, url: str, timeout: float = 5.0):
        self.url = url
        self.timeout = timeout

    def audit(self) -> Tuple[List[Finding], Dict[str, Any]]:
        findings: List[Finding] = []
        details: Dict[str, Any] = {
            "allowed_methods": [],
            "trace_enabled": False,
        }

        # 1. Test OPTIONS method
        try:
            req = urllib.request.Request(self.url, headers={"User-Agent": DEFAULT_USER_AGENT}, method="OPTIONS")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                allow_header = resp.headers.get("Allow", "")
                if allow_header:
                    methods = [m.strip().upper() for m in allow_header.split(",") if m.strip()]
                    details["allowed_methods"] = methods
        except Exception:
            pass

        # 2. Specifically test TRACE method (XST vulnerability)
        try:
            req = urllib.request.Request(self.url, headers={"User-Agent": DEFAULT_USER_AGENT}, method="TRACE")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    details["trace_enabled"] = True
                    findings.append(
                        Finding(
                            id="METH-TRACE-ENABLED",
                            title="Dangerous HTTP Method Enabled: TRACE (Cross-Site Tracing)",
                            severity=Severity.MEDIUM,
                            category=Category.HTTP_METHODS,
                            description="The web server has HTTP TRACE method enabled. TRACE echoes back the incoming request headers.",
                            impact="Attackers can leverage TRACE via Cross-Site Tracing (XST) to bypass 'HttpOnly' cookie protections and steal sensitive session tokens.",
                            remediation="Disable HTTP TRACE/TRACK methods in the web server configuration (e.g. in Apache: 'TraceEnable Off').",
                            evidence=f"TRACE request to {self.url} returned HTTP 200 OK.",
                            owasp_category="A05:2021-Security Misconfiguration",
                            cwe_id="CWE-16",
                            cvss_score=5.3,
                            references=["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
                        )
                    )
        except urllib.error.HTTPError as e:
            # 405 Method Not Allowed or 403 Forbidden is the expected, secure behavior
            pass
        except Exception:
            pass

        return findings, details
