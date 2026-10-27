"""
Shodan InternetDB and Network/ASN Intelligence Auditor.
Uses Shodan's official free, keyless InternetDB API and IP intelligence endpoints.
"""

from typing import List, Dict, Tuple, Any, Optional
import json
import urllib.request
import urllib.error
from aegis_core.models import Finding, Severity, Category
from aegis_core.config import DEFAULT_USER_AGENT

# Port risk classifications
RISKY_PORTS = {
    21: {"name": "FTP", "severity": Severity.MEDIUM, "impact": "Cleartext file transfer protocol. Insecure transmission of credentials.", "cwe": "CWE-319"},
    22: {"name": "SSH", "severity": Severity.INFO, "impact": "Secure Shell service exposed to public internet. Ensure password authentication is disabled and brute-force protection (fail2ban) is enforced.", "cwe": "CWE-16"},
    23: {"name": "Telnet", "severity": Severity.CRITICAL, "impact": "Telnet transmits all sessions, credentials, and keystrokes in cleartext.", "cwe": "CWE-319"},
    25: {"name": "SMTP", "severity": Severity.LOW, "impact": "Direct mail transfer service exposed. Verify it is not an open mail relay.", "cwe": "CWE-16"},
    1433: {"name": "Microsoft SQL Server", "severity": Severity.HIGH, "impact": "Direct database exposure. Vulnerable to credential brute-forcing and TDS protocol exploits.", "cwe": "CWE-668"},
    3306: {"name": "MySQL / MariaDB", "severity": Severity.HIGH, "impact": "Database engine directly exposed to public internet. Attackers can brute-force credentials or exploit unpatched server flaws.", "cwe": "CWE-668"},
    3389: {"name": "RDP (Remote Desktop)", "severity": Severity.HIGH, "impact": "Remote Desktop protocol exposed. Frequent target for ransomware campaigns and brute-force attacks.", "cwe": "CWE-668"},
    5432: {"name": "PostgreSQL", "severity": Severity.HIGH, "impact": "PostgreSQL database port publicly reachable.", "cwe": "CWE-668"},
    5900: {"name": "VNC", "severity": Severity.HIGH, "impact": "Virtual Network Computing remote desktop exposed. Insecure authentication vectors.", "cwe": "CWE-668"},
    6379: {"name": "Redis", "severity": Severity.CRITICAL, "impact": "Redis often lacks authentication by default, allowing remote code execution and memory theft.", "cwe": "CWE-306"},
    9200: {"name": "Elasticsearch", "severity": Severity.HIGH, "impact": "Elasticsearch cluster port exposed. High risk of data leaks and unauthorized cluster index deletion.", "cwe": "CWE-306"},
    27017: {"name": "MongoDB", "severity": Severity.CRITICAL, "impact": "MongoDB port exposed. High risk of unauthenticated database exfiltration and ransomware wiping.", "cwe": "CWE-306"},
}


class ShodanAuditor:
    def __init__(self, ip_addresses: List[str], timeout: float = 6.0):
        # Filter for valid IPv4/IPv6, exclude localhost/private
        self.ip_addresses = [ip for ip in ip_addresses if not self._is_private_ip(ip)]
        self.timeout = timeout

    def audit(self) -> Tuple[List[Finding], Dict[str, Any]]:
        findings: List[Finding] = []
        details: Dict[str, Any] = {
            "queried_ips": self.ip_addresses,
            "shodan_data": {},
            "network_info": {},
            "detected_open_ports": [],
            "cves_found": [],
            "tags": [],
        }

        if not self.ip_addresses:
            details["note"] = "No public IP addresses available to query Shodan InternetDB."
            return findings, details

        # Query primary IP
        primary_ip = self.ip_addresses[0]

        # 1. Fetch Shodan InternetDB data (Ports, CVEs, Tags, CPEs)
        shodan_info = self._query_shodan_internetdb(primary_ip)
        details["shodan_data"] = shodan_info

        # 2. Fetch IP & ASN Intelligence
        net_info = self._query_ip_intelligence(primary_ip)
        details["network_info"] = net_info

        if not shodan_info and not net_info:
            return findings, details

        open_ports = shodan_info.get("ports", [])
        cves = shodan_info.get("vulns", [])
        tags = shodan_info.get("tags", [])
        details["detected_open_ports"] = open_ports
        details["cves_found"] = cves
        details["tags"] = tags

        # 3. Analyze Risky Exposed Ports
        for port in open_ports:
            if port in RISKY_PORTS:
                p_spec = RISKY_PORTS[port]
                findings.append(
                    Finding(
                        id=f"SHODAN-PORT-EXPOSED-{port}",
                        title=f"Publicly Exposed Risky Service: {p_spec['name']} (Port {port})",
                        severity=p_spec["severity"],
                        category=Category.NETWORK_INTEL,
                        description=f"Shodan InternetDB discovered port {port} ({p_spec['name']}) listening and publicly accessible on host {primary_ip}.",
                        impact=p_spec["impact"],
                        remediation=f"Block incoming traffic to port {port} at your firewall or cloud security group (AWS SG / Cloudflare / UFW). Ensure administration services are accessible only via a secure VPN or bastion host.",
                        evidence=f"Shodan InternetDB confirmed open port {port} on {primary_ip}. Tags: {', '.join(tags) or 'None'}",
                        owasp_category="A05:2021-Security Misconfiguration",
                        cwe_id=p_spec["cwe"],
                        cvss_score=8.5 if p_spec["severity"] == Severity.CRITICAL else 6.8 if p_spec["severity"] == Severity.HIGH else 4.0,
                        references=[
                            f"https://www.shodan.io/host/{primary_ip}",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
                        ],
                    )
                )

        # 4. Analyze Shodan Known CVE Vulnerabilities
        if cves:
            findings.append(
                Finding(
                    id="SHODAN-KNOWN-CVES",
                    title=f"Known CVE Vulnerabilities Flagged by Shodan ({len(cves)} Detected)",
                    severity=Severity.CRITICAL,
                    category=Category.NETWORK_INTEL,
                    description=f"Shodan scanner correlation identified {len(cves)} known Common Vulnerabilities and Exposures (CVEs) associated with services on {primary_ip}: {', '.join(cves[:8])}{'...' if len(cves) > 8 else ''}.",
                    impact="Publicly disclosed vulnerabilities with known exploit vectors leave infrastructure susceptible to automated botnets and targeted compromise.",
                    remediation="Audit listening services, update running software packages to their latest vendor-patched releases, and retire legacy software components.",
                    evidence=f"Shodan CVEs: {', '.join(cves)}\nCPEs: {', '.join(shodan_info.get('cpes', []))}",
                    owasp_category="A06:2021-Vulnerable and Outdated Components",
                    cwe_id="CWE-1395",
                    cvss_score=9.5,
                    references=[f"https://nvd.nist.gov/vuln/detail/{cve}" for cve in cves[:3]],
                )
            )

        # 5. Network Posture Information Notice
        asn_str = net_info.get("as", net_info.get("org", "Unknown"))
        loc_str = f"{net_info.get('city', '')}, {net_info.get('country', '')}".strip(", ")
        findings.append(
            Finding(
                id="NET-INFRA-PROFILE",
                title=f"Network Infrastructure & Hosting Profile: {asn_str}",
                severity=Severity.INFO,
                category=Category.NETWORK_INTEL,
                description=f"Host is routed under {asn_str} located in {loc_str or 'Global'}. Shodan reports {len(open_ports)} open port(s): {', '.join(map(str, open_ports)) if open_ports else 'None listed'}.",
                impact="Network reconnaissance mapping for threat surface awareness.",
                remediation="Ensure only essential web ports (80, 443) are publicly routable and enforce WAF/DDoS protection.",
                evidence=f"IP: {primary_ip} | ASN: {asn_str} | Open Ports: {open_ports} | Tags: {tags}",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-200",
                cvss_score=1.0,
            )
        )

        return findings, details

    def _query_shodan_internetdb(self, ip: str) -> Dict[str, Any]:
        """Queries Shodan's official free, keyless InternetDB API."""
        url = f"https://internetdb.shodan.io/{ip}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_USER_AGENT})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    return data
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # 404 indicates Shodan has not indexed any open services on this IP (clean/quiet host)
                return {"ports": [], "cves": [], "tags": [], "cpes": []}
        except Exception:
            pass
        return {}

    def _query_ip_intelligence(self, ip: str) -> Dict[str, Any]:
        """Queries ASN, ISP, and geographic intelligence."""
        # Try ipwho.is (CORS-friendly, free, reliable)
        urls = [
            f"https://ipwho.is/{ip}",
            f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as",
        ]
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_USER_AGENT})
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        if data.get("status") in ("success", True) or "connection" in data or "as" in data:
                            # Normalize fields
                            return {
                                "country": data.get("country", ""),
                                "city": data.get("city", ""),
                                "isp": str(data.get("isp", data.get("connection", {}).get("isp", "")) or ""),
                                "org": str(data.get("org", data.get("connection", {}).get("org", "")) or ""),
                                "as": str(data.get("as", data.get("connection", {}).get("asn", "")) or ""),
                            }
            except Exception:
                continue
        return {}

    def _is_private_ip(self, ip: str) -> bool:
        """Determines if an IP is localhost or a private RFC1918 address."""
        if ip in ("127.0.0.1", "localhost", "::1"):
            return True
        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16."):
            return True
        return False
