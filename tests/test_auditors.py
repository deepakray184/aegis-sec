"""
Unit and Functional Test Suite for AegisSec Security Auditor.
Tests all analysis logic, scoring calculations, and report generators without external network dependence.
"""

import unittest
import os
import sys

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aegis_core.models import Finding, Severity, Category, TargetInfo, AuditResult
from aegis_core.scoring import calculate_audit_summary
from aegis_core.modules.headers_auditor import HeadersAuditor
from aegis_core.modules.cookies_cors import CookiesCORSAuditor
from aegis_core.modules.shodan_auditor import ShodanAuditor
from aegis_core.modules.tech_auditor import TechAuditor
from aegis_core.reporters.html_reporter import HTMLReporter
from aegis_core.reporters.markdown_reporter import MarkdownReporter
from aegis_core.reporters.json_reporter import JSONReporter


class TestHeadersAuditor(unittest.TestCase):
    def test_missing_critical_headers(self):
        # Empty headers
        auditor = HeadersAuditor(headers={}, status_code=200, url="https://example.com")
        findings, details = auditor.audit()

        finding_ids = [f.id for f in findings]
        self.assertIn("HDR-MISSING-STRICT_TRANSPORT_SECURITY", finding_ids)
        self.assertIn("HDR-MISSING-CONTENT_SECURITY_POLICY", finding_ids)
        self.assertIn("HDR-MISSING-X_FRAME_OPTIONS", finding_ids)
        self.assertIn("HDR-MISSING-X_CONTENT_TYPE_OPTIONS", finding_ids)

    def test_server_leak_detection(self):
        headers = {
            "Server": "Apache/2.4.41 (Ubuntu)",
            "X-Powered-By": "PHP/7.4.3",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'self';",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }
        auditor = HeadersAuditor(headers=headers, status_code=200, url="https://example.com")
        findings, details = auditor.audit()

        finding_ids = [f.id for f in findings]
        self.assertIn("HDR-LEAK-SERVER", finding_ids)
        self.assertIn("HDR-LEAK-X_POWERED_BY", finding_ids)
        self.assertNotIn("HDR-MISSING-STRICT_TRANSPORT_SECURITY", finding_ids)

    def test_csp_unsafe_inline(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline';",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }
        auditor = HeadersAuditor(headers=headers, status_code=200, url="https://example.com")
        findings, details = auditor.audit()

        finding_ids = [f.id for f in findings]
        self.assertIn("HDR-CSP-UNSAFE-INLINE", finding_ids)


class TestCookiesAuditor(unittest.TestCase):
    def test_insecure_cookie_detection(self):
        headers = {
            "Set-Cookie": "session_id=xyz123456; Path=/",
        }
        auditor = CookiesCORSAuditor("https://example.com", headers)
        findings, details = auditor._audit_cookies()

        finding_ids = [f.id for f in findings]
        self.assertIn("COOKIE-NO-SECURE-session_id", finding_ids)
        self.assertIn("COOKIE-NO-HTTPONLY-session_id", finding_ids)
        self.assertIn("COOKIE-NO-SAMESITE-session_id", finding_ids)


class TestShodanAuditor(unittest.TestCase):
    def test_private_ip_handling(self):
        auditor = ShodanAuditor(["127.0.0.1", "192.168.1.1", "10.0.0.5"])
        findings, details = auditor.audit()
        self.assertEqual(len(findings), 0)
        self.assertIn("No public IP addresses", details.get("note", ""))

    def test_risky_port_and_cve_analysis(self):
        auditor = ShodanAuditor(["8.8.8.8"])
        # Mock responses
        auditor._query_shodan_internetdb = lambda ip: {
            "ports": [80, 443, 3306, 23],
            "vulns": ["CVE-2023-1234"],
            "tags": ["cloud"],
            "cpes": ["cpe:/a:mysql:mysql"],
        }
        auditor._query_ip_intelligence = lambda ip: {
            "country": "United States",
            "city": "Mountain View",
            "isp": "Google LLC",
            "org": "Google LLC",
            "as": "AS15169 Google LLC",
        }
        findings, details = auditor.audit()
        finding_ids = [f.id for f in findings]
        self.assertIn("SHODAN-PORT-EXPOSED-3306", finding_ids)
        self.assertIn("SHODAN-PORT-EXPOSED-23", finding_ids)
        self.assertIn("SHODAN-KNOWN-CVES", finding_ids)
        self.assertIn("NET-INFRA-PROFILE", finding_ids)


class TestTechAuditor(unittest.TestCase):
    def test_detect_wordpress_and_version_leak(self):
        headers = {"Server": "nginx/1.18.0", "X-Pingback": "https://example.com/xmlrpc.php"}
        html = '<meta name="generator" content="WordPress 6.4.2" /><link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">'
        auditor = TechAuditor(headers=headers, html_body=html)
        findings, details = auditor.audit()

        tech_names = [t["name"] for t in details["technologies"]]
        self.assertIn("WordPress", tech_names)
        self.assertIn("Nginx", tech_names)

        # Check WordPress version was captured
        wp_tech = next(t for t in details["technologies"] if t["name"] == "WordPress")
        self.assertEqual(wp_tech["version"], "6.4.2")

        # Check finding
        finding_ids = [f.id for f in findings]
        self.assertIn("TECH-WP-VERSION-LEAK", finding_ids)

    def test_detect_react_and_nextjs(self):
        headers = {"X-Powered-By": "Next.js", "Server": "cloudflare"}
        html = '<div id="__next"><div id="root">Hello</div></div><script src="/_next/static/chunks/main.js"></script>'
        auditor = TechAuditor(headers=headers, html_body=html)
        findings, details = auditor.audit()

        tech_names = [t["name"] for t in details["technologies"]]
        self.assertIn("Next.js", tech_names)
        self.assertIn("React", tech_names)
        self.assertIn("Cloudflare", tech_names)

    def test_detect_vulnerable_jquery_and_eol_php(self):
        headers = {"X-Powered-By": "PHP/7.4.3", "Server": "Apache/2.4.41"}
        html = '<script src="https://code.jquery.com/jquery-3.4.1.min.js"></script>'
        auditor = TechAuditor(headers=headers, html_body=html)
        findings, details = auditor.audit()

        tech_names = [t["name"] for t in details["technologies"]]
        self.assertIn("PHP", tech_names)
        self.assertIn("jQuery", tech_names)
        self.assertIn("Apache HTTP Server", tech_names)

        finding_ids = [f.id for f in findings]
        self.assertIn("TECH-EOL-PHP-7_4_3", finding_ids)
        self.assertIn("TECH-VULN-JQUERY-3_4_1", finding_ids)


class TestScoringEngine(unittest.TestCase):
    def test_perfect_score(self):
        summary = calculate_audit_summary([], duration_seconds=1.5)
        self.assertEqual(summary.score, 100)
        self.assertEqual(summary.grade, "A+")

    def test_penalty_deduction(self):
        findings = [
            Finding(
                id="TEST-CRIT",
                title="Critical Issue",
                severity=Severity.CRITICAL,
                category=Category.EXPOSURE,
                description="desc",
                impact="impact",
                remediation="rem",
            ),
            Finding(
                id="TEST-HIGH",
                title="High Issue",
                severity=Severity.HIGH,
                category=Category.HEADERS,
                description="desc",
                impact="impact",
                remediation="rem",
            ),
        ]
        # Critical = -25, High = -15 -> 100 - 40 = 60
        summary = calculate_audit_summary(findings, duration_seconds=2.0)
        self.assertEqual(summary.score, 60)
        self.assertEqual(summary.grade, "C")
        self.assertEqual(summary.critical_count, 1)
        self.assertEqual(summary.high_count, 1)


class TestReporters(unittest.TestCase):
    def setUp(self):
        target = TargetInfo(
            url="https://testsite.internal",
            domain="testsite.internal",
            port=443,
            scheme="https",
            ip_addresses=["192.168.1.100"],
            server_banner="nginx/1.18.0",
        )
        findings = [
            Finding(
                id="HDR-MISSING-CSP",
                title="Missing Security Header: Content-Security-Policy",
                severity=Severity.HIGH,
                category=Category.HEADERS,
                description="CSP is missing.",
                impact="High XSS risk.",
                remediation="Add CSP header.",
                evidence="No CSP found",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-1021",
                cvss_score=6.5,
                remediation_code={"Nginx": "add_header Content-Security-Policy \"default-src 'self';\";"},
            )
        ]
        summary = calculate_audit_summary(findings, duration_seconds=1.2)
        self.result = AuditResult(
            target=target,
            summary=summary,
            findings=findings,
            module_details={"headers": {"missing": ["Content-Security-Policy"]}},
        )

    def test_html_reporter(self):
        reporter = HTMLReporter(self.result)
        html_out = reporter.render()
        self.assertIn("AegisSec Security Report - testsite.internal", html_out)
        self.assertIn("Missing Security Header: Content-Security-Policy", html_out)
        self.assertIn("CWE-1021", html_out)

    def test_markdown_reporter(self):
        reporter = MarkdownReporter(self.result)
        md_out = reporter.render()
        self.assertIn("# 🛡️ Security Audit Report: testsite.internal", md_out)
        self.assertIn("Missing Security Header: Content-Security-Policy", md_out)

    def test_json_reporter(self):
        reporter = JSONReporter(self.result)
        json_out = reporter.render()
        self.assertIn('"domain": "testsite.internal"', json_out)
        self.assertIn('"id": "HDR-MISSING-CSP"', json_out)


if __name__ == "__main__":
    unittest.main()
