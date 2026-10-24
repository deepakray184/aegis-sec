"""
Information Disclosure, Robots.txt, Security.txt, and Sensitive File Exposure Auditor.
"""

from typing import List, Dict, Tuple, Any
import urllib.request
import urllib.error
from urllib.parse import urljoin, urlparse
from aegis_core.models import Finding, Severity, Category
from aegis_core.config import SENSITIVE_PATHS, DEFAULT_USER_AGENT
from aegis_core.remediation import get_git_block_remediation_code


class ExposureAuditor:
    def __init__(self, base_url: str, timeout: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.parsed = urlparse(base_url)
        self.timeout = timeout

    def audit(self) -> Tuple[List[Finding], Dict[str, Any]]:
        findings: List[Finding] = []
        details: Dict[str, Any] = {
            "robots_txt": None,
            "security_txt": None,
            "sensitive_paths_checked": len(SENSITIVE_PATHS),
            "exposed_files": [],
        }

        # 1. Audit robots.txt
        robots_finding, robots_info = self._audit_robots_txt()
        details["robots_txt"] = robots_info
        if robots_finding:
            findings.append(robots_finding)

        # 2. Audit security.txt (RFC 9116)
        security_txt_finding, sec_info = self._audit_security_txt()
        details["security_txt"] = sec_info
        if security_txt_finding:
            findings.append(security_txt_finding)

        # 3. Probe sensitive files safely (non-destructive)
        exposed_findings, exposed_list = self._probe_sensitive_files()
        findings.extend(exposed_findings)
        details["exposed_files"] = exposed_list

        return findings, details

    def _audit_robots_txt(self) -> Tuple[Any, Dict[str, Any]]:
        url = urljoin(self.base_url, "/robots.txt")
        info: Dict[str, Any] = {"present": False, "disallowed_sensitive": []}

        try:
            req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_USER_AGENT})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    content = resp.read(8192).decode("utf-8", errors="replace")
                    info["present"] = True

                    # Search for sensitive disallowed directories
                    sensitive_keywords = ["admin", "secret", "private", "backup", "db", "api/internal", "staging", "login", "auth"]
                    disallowed = []
                    for line in content.splitlines():
                        line_clean = line.strip()
                        if line_clean.lower().startswith("disallow:"):
                            path = line_clean.split(":", 1)[1].strip()
                            if any(k in path.lower() for k in sensitive_keywords):
                                disallowed.append(path)

                    info["disallowed_sensitive"] = disallowed

                    if disallowed:
                        return (
                            Finding(
                                id="EXP-ROBOTS-SENSITIVE-PATHS",
                                title="Sensitive Paths Disclosed in robots.txt",
                                severity=Severity.LOW,
                                category=Category.EXPOSURE,
                                description=f"The robots.txt file publicly lists sensitive directories: {', '.join(disallowed[:5])}.",
                                impact="Attackers frequently inspect robots.txt to discover hidden admin portals, staging directories, or API routes.",
                                remediation="Do not rely on robots.txt for security or concealment. Enforce robust authentication on all sensitive endpoints.",
                                evidence=f"robots.txt excerpt:\n" + "\n".join([f"Disallow: {p}" for p in disallowed[:5]]),
                                owasp_category="A01:2021-Broken Access Control",
                                cwe_id="CWE-200",
                                cvss_score=3.3,
                                references=["https://cheatsheetseries.owasp.org/cheatsheets/Information_Disclosure_Cheat_Sheet.html"],
                            ),
                            info,
                        )
        except Exception:
            pass

        return None, info

    def _audit_security_txt(self) -> Tuple[Any, Dict[str, Any]]:
        paths = ["/.well-known/security.txt", "/security.txt"]
        info: Dict[str, Any] = {"present": False, "path": None}

        for p in paths:
            url = urljoin(self.base_url, p)
            try:
                req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_USER_AGENT})
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    if resp.status == 200:
                        content = resp.read(2048).decode("utf-8", errors="replace")
                        if "contact:" in content.lower():
                            info["present"] = True
                            info["path"] = p
                            return None, info
            except Exception:
                continue

        # If not present, flag as INFO
        return (
            Finding(
                id="EXP-SECURITY-TXT-MISSING",
                title="Missing security.txt Vulnerability Disclosure Policy (RFC 9116)",
                severity=Severity.INFO,
                category=Category.EXPOSURE,
                description="The website does not publish a security.txt file at /.well-known/security.txt.",
                impact="Ethical security researchers who discover vulnerabilities may not know how or where to responsibly report them.",
                remediation="Deploy a security.txt file at /.well-known/security.txt containing Contact and Expires fields per RFC 9116.",
                evidence="Neither /.well-known/security.txt nor /security.txt returned a valid security policy.",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-200",
                cvss_score=1.5,
                references=["https://datatracker.ietf.org/doc/html/rfc9116"],
            ),
            info,
        )

    def _probe_sensitive_files(self) -> Tuple[List[Finding], List[str]]:
        findings = []
        exposed = []

        for item in SENSITIVE_PATHS:
            path = item["path"]
            url = urljoin(self.base_url, path)
            try:
                req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_USER_AGENT})
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    status = resp.status
                    if status == 200:
                        body_preview = resp.read(1024)
                        # Avoid false positives by validating content indicators
                        indicator = item.get("indicator")
                        valid = False

                        if indicator:
                            body_str = body_preview.decode("utf-8", errors="replace")
                            # Ensure it's not a customized HTML 404 page returning status 200
                            is_html = "<!doctype html" in body_str.lower() or "<html" in body_str.lower()
                            if indicator in body_str and not (is_html and "404" in body_str):
                                valid = True
                        else:
                            # Binary or general check (e.g., .DS_Store starts with \x00\x00\x00\x01Bud1)
                            if path == "/.DS_Store" and b"\x00\x00\x00\x01Bud1" in body_preview:
                                valid = True

                        if valid:
                            exposed.append(path)
                            findings.append(
                                Finding(
                                    id=f"EXP-FILE-{path.strip('/').replace('.', '_').replace('-', '_').upper()}",
                                    title=f"Critical Information Disclosure: Exposed {item['name']}",
                                    severity=Severity(item["severity"]),
                                    category=Category.EXPOSURE,
                                    description=f"{item['description']} Located at: {url}",
                                    impact="Direct compromise of system source code, credentials, architecture, or environment configurations.",
                                    remediation=f"Block public access to '{path}' immediately at the web server / reverse proxy layer.",
                                    evidence=f"URL {url} returned HTTP 200 with signature match: '{indicator}'.",
                                    owasp_category=item["owasp"],
                                    cwe_id=item["cwe"],
                                    cvss_score=9.0 if item["severity"] == "CRITICAL" else 7.5,
                                    references=["https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"],
                                    remediation_code=get_git_block_remediation_code(),
                                )
                            )
            except urllib.error.HTTPError:
                # 403, 404, 500 etc. mean path is not freely exposed
                pass
            except Exception:
                pass

        return findings, exposed
