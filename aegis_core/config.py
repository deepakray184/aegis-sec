"""
Configuration settings, audit catalogs, and probe lists for AegisSec.
"""

from typing import List, Dict, Any

# HTTP Client configuration
DEFAULT_USER_AGENT = "AegisSec-Auditor/2.0 (+https://github.com/security/aegis-sec; Authorized Security Audit)"
DEFAULT_TIMEOUT = 8.0  # seconds
MAX_REDIRECTS = 5
MAX_BODY_SAMPLE_BYTES = 4096

# Known security headers specifications
SECURITY_HEADERS_SPEC = {
    "Strict-Transport-Security": {
        "required": True,
        "severity_missing": "HIGH",
        "cwe": "CWE-319",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": "Enforces HTTPS connections and prevents SSL-stripping man-in-the-middle attacks.",
        "recommended": "max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "required": True,
        "severity_missing": "HIGH",
        "cwe": "CWE-1021",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": "Restricts resources (scripts, styles, images) that can be loaded to prevent XSS and data injection.",
        "recommended": "default-src 'self'; script-src 'self'; object-src 'none';",
    },
    "X-Frame-Options": {
        "required": True,
        "severity_missing": "MEDIUM",
        "cwe": "CWE-1021",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": "Protects against Clickjacking by forbidding the site from being rendered within an iframe.",
        "recommended": "DENY or SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "required": True,
        "severity_missing": "LOW",
        "cwe": "CWE-16",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": "Prevents MIME-type sniffing, ensuring browsers follow the declared Content-Type.",
        "recommended": "nosniff",
    },
    "Referrer-Policy": {
        "required": True,
        "severity_missing": "LOW",
        "cwe": "CWE-116",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": "Controls how much referrer information is included with requests.",
        "recommended": "strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "required": False,
        "severity_missing": "INFO",
        "cwe": "CWE-16",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": "Restricts browser features like camera, microphone, geolocation, and payment APIs.",
        "recommended": "camera=(), microphone=(), geolocation=()",
    },
    "Cross-Origin-Opener-Policy": {
        "required": False,
        "severity_missing": "INFO",
        "cwe": "CWE-16",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": "Isolates the browsing context to protect against Spectre-style cross-origin leaks.",
        "recommended": "same-origin",
    },
    "Cross-Origin-Resource-Policy": {
        "required": False,
        "severity_missing": "INFO",
        "cwe": "CWE-16",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": "Blocks others from loading your resources cross-origin.",
        "recommended": "same-site or same-origin",
    },
}

# Sensitive file exposure paths for non-destructive probing
SENSITIVE_PATHS: List[Dict[str, Any]] = [
    {
        "path": "/.git/HEAD",
        "name": "Git Repository Metadata",
        "severity": "CRITICAL",
        "cwe": "CWE-538",
        "owasp": "A05:2021-Security Misconfiguration",
        "indicator": "ref: refs/",
        "description": "Exposed Git repository allows attackers to download complete source code, commit history, and secrets.",
    },
    {
        "path": "/.git/config",
        "name": "Git Config File",
        "severity": "CRITICAL",
        "cwe": "CWE-538",
        "owasp": "A05:2021-Security Misconfiguration",
        "indicator": "[core]",
        "description": "Exposed Git config leaks internal repository URLs and upstream credentials.",
    },
    {
        "path": "/.env",
        "name": "Environment Variables File",
        "severity": "CRITICAL",
        "cwe": "CWE-540",
        "owasp": "A05:2021-Security Misconfiguration",
        "indicator": "=",
        "description": "Exposed .env configuration file typically contains database credentials, API keys, and secret tokens.",
    },
    {
        "path": "/.env.local",
        "name": "Local Environment Config",
        "severity": "CRITICAL",
        "cwe": "CWE-540",
        "owasp": "A05:2021-Security Misconfiguration",
        "indicator": "=",
        "description": "Exposed local environment variables file contains sensitive secrets and override credentials.",
    },
    {
        "path": "/docker-compose.yml",
        "name": "Docker Compose Manifest",
        "severity": "HIGH",
        "cwe": "CWE-538",
        "owasp": "A05:2021-Security Misconfiguration",
        "indicator": "services:",
        "description": "Docker Compose file reveals internal network architecture, database passwords, and container setup.",
    },
    {
        "path": "/web.config",
        "name": "IIS Web Config",
        "severity": "HIGH",
        "cwe": "CWE-538",
        "owasp": "A05:2021-Security Misconfiguration",
        "indicator": "<configuration>",
        "description": "IIS server configuration file leaks connection strings and application structure.",
    },
    {
        "path": "/phpinfo.php",
        "name": "PHP Info Diagnostic Page",
        "severity": "MEDIUM",
        "cwe": "CWE-200",
        "owasp": "A05:2021-Security Misconfiguration",
        "indicator": "PHP Version",
        "description": "Exposed phpinfo() discloses complete PHP modules, system environment variables, and file system paths.",
    },
    {
        "path": "/actuator/health",
        "name": "Spring Boot Actuator",
        "severity": "MEDIUM",
        "cwe": "CWE-200",
        "owasp": "A05:2021-Security Misconfiguration",
        "indicator": '"status":',
        "description": "Spring Boot actuator endpoint leaks application state and internal framework versions.",
    },
    {
        "path": "/.DS_Store",
        "name": "macOS Finder Metadata",
        "severity": "LOW",
        "cwe": "CWE-538",
        "owasp": "A05:2021-Security Misconfiguration",
        "indicator": None,  # Binary detection
        "description": ".DS_Store file leaks names of hidden and sensitive files within web directories.",
    },
    {
        "path": "/swagger.json",
        "name": "Swagger / OpenAPI Specification",
        "severity": "LOW",
        "cwe": "CWE-200",
        "owasp": "A05:2021-Security Misconfiguration",
        "indicator": '"swagger":',
        "description": "Publicly exposed API specifications disclose unannounced endpoints and parameter definitions.",
    },
]
