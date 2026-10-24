"""
DNS Posture, Email Spoofing Defense (SPF / DMARC / MX), CAA, and DNSSEC Auditor.
"""

from typing import List, Dict, Tuple, Any, Optional
import subprocess
import shutil
import re
from aegis_core.models import Finding, Severity, Category


class DNSAuditor:
    def __init__(self, domain: str, timeout: float = 5.0):
        self.domain = domain
        self.timeout = timeout
        self.has_dig = shutil.which("dig") is not None
        self.has_nslookup = shutil.which("nslookup") is not None

    def audit(self) -> Tuple[List[Finding], Dict[str, Any]]:
        findings: List[Finding] = []
        details: Dict[str, Any] = {
            "spf_records": [],
            "dmarc_records": [],
            "mx_records": [],
            "caa_records": [],
            "dnssec_enabled": False,
        }

        # Check if domain is an IP address or localhost
        is_ip_or_local = self.domain in ("localhost", "127.0.0.1", "::1") or re.match(r"^\d+\.\d+\.\d+\.\d+$", self.domain)
        if is_ip_or_local:
            details["note"] = "Target is a direct IP address or localhost; domain-level DNS/email checks skipped."
            return findings, details
        mx_records = self._query_dns(self.domain, "MX")
        details["mx_records"] = mx_records
        has_mail = len(mx_records) > 0

        # 2. Query SPF Records
        txt_records = self._query_dns(self.domain, "TXT")
        spf_records = [r for r in txt_records if r.strip().startswith("v=spf1")]
        details["spf_records"] = spf_records

        if not spf_records:
            findings.append(
                Finding(
                    id="DNS-SPF-MISSING",
                    title="Missing SPF (Sender Policy Framework) Record",
                    severity=Severity.HIGH if has_mail else Severity.MEDIUM,
                    category=Category.DNS_EMAIL,
                    description=f"No SPF TXT record ('v=spf1') was found for {self.domain}.",
                    impact="Without SPF, external mail servers cannot verify whether outgoing emails originating from your domain are legitimate, making domain spoofing and phishing trivial.",
                    remediation="Publish a TXT record with your authorized mail sending servers, e.g. 'v=spf1 include:_spf.google.com ~all' or 'v=spf1 -all' if domain does not send mail.",
                    evidence="DNS TXT query returned no record beginning with 'v=spf1'.",
                    owasp_category="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-290",
                    cvss_score=6.5 if has_mail else 4.0,
                    references=["https://datatracker.ietf.org/doc/html/rfc7208"],
                )
            )
        elif len(spf_records) > 1:
            findings.append(
                Finding(
                    id="DNS-SPF-MULTIPLE",
                    title="Multiple SPF Records Found (RFC 7208 Violation)",
                    severity=Severity.HIGH,
                    category=Category.DNS_EMAIL,
                    description=f"Multiple SPF records found ({len(spf_records)}). Per RFC 7208, a domain must have at most one SPF TXT record.",
                    impact="Receiving mail servers may treat multiple SPF records as a permanent error (PermError) and discard SPF verification, leaving the domain vulnerable to spoofing.",
                    remediation="Merge all authorized sending sources into a single SPF TXT record.",
                    evidence="Records: " + " | ".join(spf_records),
                    owasp_category="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-290",
                    cvss_score=5.8,
                )
            )
        else:
            spf = spf_records[0].lower()
            if "+all" in spf:
                findings.append(
                    Finding(
                        id="DNS-SPF-PERMISSIVE-PLUS-ALL",
                        title="Critical SPF Misconfiguration: Insecure '+all' Directive",
                        severity=Severity.CRITICAL,
                        category=Category.DNS_EMAIL,
                        description="The SPF record specifies '+all', which explicitly authorizes ANY server on the Internet to send email as this domain.",
                        impact="Attackers can send forged emails directly from your domain that will pass SPF authentication worldwide.",
                        remediation="Replace '+all' with '~all' (softfail) or '-all' (hardfail).",
                        evidence=f"SPF record: {spf_records[0]}",
                        owasp_category="A05:2021-Security Misconfiguration",
                        cwe_id="CWE-290",
                        cvss_score=8.5,
                    )
                )
            elif "?all" in spf:
                findings.append(
                    Finding(
                        id="DNS-SPF-NEUTRAL-ALL",
                        title="Permissive SPF Record: '?all' (Neutral)",
                        severity=Severity.MEDIUM,
                        category=Category.DNS_EMAIL,
                        description="The SPF record uses '?all', signifying a neutral stance. Mail servers will not reject unauthorized senders.",
                        impact="Reduces defensive posture against email spoofing and phishing.",
                        remediation="Transition SPF policy to '~all' or '-all'.",
                        evidence=f"SPF record: {spf_records[0]}",
                        owasp_category="A05:2021-Security Misconfiguration",
                        cwe_id="CWE-290",
                        cvss_score=5.0,
                    )
                )

        # 3. Query DMARC Records (_dmarc.domain)
        dmarc_domain = f"_dmarc.{self.domain}"
        dmarc_txt = self._query_dns(dmarc_domain, "TXT")
        dmarc_records = [r for r in dmarc_txt if "v=dmarc1" in r.lower()]
        details["dmarc_records"] = dmarc_records

        if not dmarc_records:
            findings.append(
                Finding(
                    id="DNS-DMARC-MISSING",
                    title="Missing DMARC (Domain-based Message Authentication) Record",
                    severity=Severity.HIGH if has_mail else Severity.MEDIUM,
                    category=Category.DNS_EMAIL,
                    description=f"No DMARC record found at {dmarc_domain}.",
                    impact="Without DMARC, receiving email providers lack instructions on how to handle failed SPF/DKIM checks, allowing phishing campaigns to abuse your identity.",
                    remediation=f"Publish a TXT record at '{dmarc_domain}' with 'v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{self.domain}'.",
                    evidence=f"DNS query for TXT at {dmarc_domain} returned no DMARC record.",
                    owasp_category="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-290",
                    cvss_score=6.5 if has_mail else 4.0,
                    references=["https://datatracker.ietf.org/doc/html/rfc7489"],
                )
            )
        else:
            dmarc_val = dmarc_records[0].lower()
            if "p=none" in dmarc_val:
                findings.append(
                    Finding(
                        id="DNS-DMARC-POLICY-NONE",
                        title="Weak DMARC Policy: 'p=none' (Monitoring Only)",
                        severity=Severity.MEDIUM,
                        category=Category.DNS_EMAIL,
                        description="DMARC policy is set to 'p=none', which only collects reports and does not block spoofed emails from reaching inboxes.",
                        impact="Phishing and domain impersonation emails will continue to be delivered to recipient mailboxes.",
                        remediation="Once monitoring proves legitimate mail flows pass SPF/DKIM, upgrade policy to 'p=quarantine' or 'p=reject'.",
                        evidence=f"DMARC record: {dmarc_records[0]}",
                        owasp_category="A05:2021-Security Misconfiguration",
                        cwe_id="CWE-290",
                        cvss_score=4.5,
                    )
                )

        # 4. Check CAA (Certificate Authority Authorization)
        caa_records = self._query_dns(self.domain, "CAA")
        details["caa_records"] = caa_records
        if not caa_records:
            findings.append(
                Finding(
                    id="DNS-CAA-MISSING",
                    title="Missing DNS CAA (Certificate Authority Authorization) Record",
                    severity=Severity.LOW,
                    category=Category.DNS_EMAIL,
                    description="No CAA record is configured for this domain.",
                    impact="Any Certificate Authority can issue SSL/TLS certificates for this domain if validated, increasing rogue certificate risk.",
                    remediation="Add CAA DNS records explicitly listing authorized CAs (e.g., '0 issue \"letsencrypt.org\"').",
                    evidence="CAA DNS lookup returned empty.",
                    owasp_category="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-295",
                    cvss_score=3.0,
                    references=["https://datatracker.ietf.org/doc/html/rfc8659"],
                )
            )

        # 5. Check DNSSEC
        dnssec_records = self._query_dns(self.domain, "DS")
        if dnssec_records:
            details["dnssec_enabled"] = True
        else:
            details["dnssec_enabled"] = False
            findings.append(
                Finding(
                    id="DNS-DNSSEC-DISABLED",
                    title="DNSSEC (DNS Security Extensions) Not Enabled",
                    severity=Severity.INFO,
                    category=Category.DNS_EMAIL,
                    description="No DS (Delegation Signer) record found in the parent zone for this domain.",
                    impact="DNS responses can theoretically be spoofed or poisoned on insecure networks without cryptographic validation.",
                    remediation="Enable DNSSEC signing through your domain registrar and DNS provider.",
                    evidence="DS record query returned empty.",
                    owasp_category="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-345",
                    cvss_score=2.0,
                )
            )

        return findings, details

    def _query_dns(self, query_name: str, rr_type: str) -> List[str]:
        """Queries DNS records using system dig or nslookup utility."""
        records: List[str] = []

        if self.has_dig:
            try:
                cmd = ["dig", "+short", "+time=2", "+tries=1", query_name, rr_type]
                proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=self.timeout)
                if proc.returncode == 0:
                    for line in proc.stdout.strip().splitlines():
                        cleaned = line.strip().strip('"')
                        if cleaned:
                            records.append(cleaned)
                    return records
            except Exception:
                pass

        if self.has_nslookup:
            try:
                cmd = ["nslookup", f"-type={rr_type}", query_name]
                proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=self.timeout)
                if proc.returncode == 0:
                    # Parse nslookup output
                    for line in proc.stdout.splitlines():
                        line_s = line.strip()
                        if "text =" in line_s:
                            val = line_s.split("text =", 1)[1].strip().strip('"')
                            records.append(val)
                        elif "mail exchanger =" in line_s:
                            val = line_s.split("mail exchanger =", 1)[1].strip()
                            records.append(val)
                    return records
            except Exception:
                pass

        return records
