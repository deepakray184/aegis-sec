"""
Data models for the AegisSec Website Security Auditor.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def score_penalty(self) -> int:
        penalties = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }
        return penalties.get(self, 0)

    @property
    def color_hex(self) -> str:
        colors = {
            Severity.CRITICAL: "#ef4444",  # red
            Severity.HIGH: "#f97316",      # orange
            Severity.MEDIUM: "#eab308",    # yellow
            Severity.LOW: "#3b82f6",       # blue
            Severity.INFO: "#64748b",      # slate/gray
        }
        return colors.get(self, "#64748b")

    @property
    def ansi_color(self) -> str:
        ansi = {
            Severity.CRITICAL: "\033[91m\033[1m",  # Bold Red
            Severity.HIGH: "\033[31m",              # Red
            Severity.MEDIUM: "\033[33m",            # Yellow
            Severity.LOW: "\033[34m",               # Blue
            Severity.INFO: "\033[90m",              # Gray
        }
        return ansi.get(self, "\033[0m")


class Category(str, Enum):
    HEADERS = "HTTP Security Headers"
    TLS_SSL = "SSL / TLS & Encryption"
    DNS_EMAIL = "DNS & Email Authentication"
    COOKIES_CORS = "Cookies & CORS Security"
    EXPOSURE = "Information Disclosure"
    HTTP_METHODS = "HTTP Methods & Server Config"
    NETWORK_INTEL = "Network & Shodan Intelligence"
    TECH_STACK = "Technology Stack & Software Profile"


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    category: Category
    description: str
    impact: str
    remediation: str
    evidence: Optional[str] = None
    owasp_category: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    references: List[str] = field(default_factory=list)
    remediation_code: Optional[Dict[str, str]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["category"] = self.category.value
        return d


@dataclass
class TargetInfo:
    url: str
    domain: str
    port: int
    scheme: str
    ip_addresses: List[str] = field(default_factory=list)
    server_banner: Optional[str] = None
    canonical_url: Optional[str] = None
    scan_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    asn: Optional[str] = None
    isp: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    shodan_tags: List[str] = field(default_factory=list)
    shodan_vulns: List[str] = field(default_factory=list)
    technologies: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuditSummary:
    score: int = 100
    grade: str = "A+"
    grade_label: str = "Excellent"
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    duration_seconds: float = 0.0
    owasp_breakdown: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuditResult:
    target: TargetInfo
    summary: AuditSummary
    findings: List[Finding] = field(default_factory=list)
    module_details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target.to_dict(),
            "summary": self.summary.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "module_details": self.module_details,
        }
