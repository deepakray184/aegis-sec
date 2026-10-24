"""
Audit Orchestrator and Scanner Core for AegisSec.
"""

from typing import Optional, Callable
import time
import socket
import urllib.request
import urllib.error
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from aegis_core.models import (
    AuditResult,
    TargetInfo,
    Severity,
    Finding,
)
from aegis_core.config import DEFAULT_USER_AGENT, DEFAULT_TIMEOUT
from aegis_core.scoring import calculate_audit_summary
from aegis_core.modules.headers_auditor import HeadersAuditor
from aegis_core.modules.tls_auditor import TLSAuditor
from aegis_core.modules.dns_auditor import DNSAuditor
from aegis_core.modules.cookies_cors import CookiesCORSAuditor
from aegis_core.modules.exposure import ExposureAuditor
from aegis_core.modules.methods import MethodsAuditor


class SecurityAuditor:
    def __init__(
        self,
        target_input: str,
        timeout: float = DEFAULT_TIMEOUT,
        progress_callback: Optional[Callable[[str, str], None]] = None,
    ):
        self.raw_target = target_input.strip()
        self.timeout = timeout
        self.progress_callback = progress_callback or (lambda step, msg: None)

    def run(self) -> AuditResult:
        start_time = time.time()

        # Step 1: Normalize target URL and domain
        self.progress_callback("INIT", f"Normalizing and resolving target: {self.raw_target}")
        normalized_url, domain, port, scheme = self._normalize_target(self.raw_target)

        # Step 2: Resolve IP addresses
        ip_addresses = self._resolve_ips(domain)
        target_info = TargetInfo(
            url=normalized_url,
            domain=domain,
            port=port,
            scheme=scheme,
            ip_addresses=ip_addresses,
        )

        # Step 3: Fetch initial HTTP response & headers
        self.progress_callback("FETCH", f"Connecting to {normalized_url}...")
        initial_headers, status_code, server_banner = self._fetch_initial_response(normalized_url)
        target_info.server_banner = server_banner

        findings: list[Finding] = []
        module_details: dict[str, any] = {}

        # Step 4: Run audit modules in parallel
        self.progress_callback("AUDIT", "Executing parallel audit modules...")

        with ThreadPoolExecutor(max_workers=6) as executor:
            future_headers = executor.submit(
                HeadersAuditor(initial_headers, status_code, normalized_url).audit
            )
            future_tls = executor.submit(
                TLSAuditor(domain, port, timeout=self.timeout).audit
            )
            future_dns = executor.submit(
                DNSAuditor(domain, timeout=self.timeout).audit
            )
            future_cookies_cors = executor.submit(
                CookiesCORSAuditor(normalized_url, initial_headers, timeout=self.timeout).audit
            )
            future_exposure = executor.submit(
                ExposureAuditor(normalized_url, timeout=self.timeout).audit
            )
            future_methods = executor.submit(
                MethodsAuditor(normalized_url, timeout=self.timeout).audit
            )

            module_futures = {
                "headers": (future_headers, "HTTP Security Headers"),
                "tls": (future_tls, "SSL/TLS & Cryptography"),
                "dns": (future_dns, "DNS & Email Security"),
                "cookies_cors": (future_cookies_cors, "Cookies & CORS Policy"),
                "exposure": (future_exposure, "Information Exposure & Files"),
                "methods": (future_methods, "HTTP Methods & WebDAV"),
            }

            for mod_key, (fut, label) in module_futures.items():
                try:
                    mod_findings, mod_info = fut.result()
                    findings.extend(mod_findings)
                    module_details[mod_key] = mod_info
                    self.progress_callback("MODULE_DONE", f"Completed: {label} ({len(mod_findings)} findings)")
                except Exception as e:
                    module_details[mod_key] = {"error": str(e)}
                    self.progress_callback("MODULE_ERROR", f"Error in {label}: {e}")

        # Step 5: Sort findings by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        findings.sort(key=lambda x: (severity_order.get(x.severity, 99), x.id))

        # Step 6: Compute score, grade, and statistical summary
        duration = time.time() - start_time
        summary = calculate_audit_summary(findings, duration)
        self.progress_callback("COMPLETE", f"Audit finished in {summary.duration_seconds}s with Grade {summary.grade} ({summary.score}/100)")

        return AuditResult(
            target=target_info,
            summary=summary,
            findings=findings,
            module_details=module_details,
        )

    def _normalize_target(self, target: str) -> tuple[str, str, int, str]:
        if "://" not in target:
            target = f"https://{target}"

        parsed = urlparse(target)
        scheme = parsed.scheme.lower() or "https"
        domain = parsed.hostname or parsed.netloc

        if not domain:
            raise ValueError(f"Invalid target URL or domain: '{target}'")

        port = parsed.port or (443 if scheme == "https" else 80)
        normalized = f"{scheme}://{domain}" if (port in (80, 443)) else f"{scheme}://{domain}:{port}"
        if parsed.path and parsed.path != "/":
            normalized += parsed.path

        return normalized, domain, port, scheme

    def _resolve_ips(self, domain: str) -> list[str]:
        ips = []
        try:
            info = socket.getaddrinfo(domain, None)
            for item in info:
                ip = item[4][0]
                if ip not in ips:
                    ips.append(ip)
        except Exception:
            pass
        return ips

    def _fetch_initial_response(self, url: str) -> tuple[dict[str, str], int, Optional[str]]:
        headers: dict[str, str] = {}
        status_code = 200
        server_banner = None

        req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status_code = resp.status
                headers = dict(resp.headers)
                server_banner = resp.headers.get("Server")
        except urllib.error.HTTPError as e:
            status_code = e.code
            headers = dict(e.headers)
            server_banner = e.headers.get("Server")
        except Exception as e:
            # If initial connection fails over https, attempt http fallback
            pass

        return headers, status_code, server_banner
