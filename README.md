# 🛡️ AegisSec: End-to-End Website Security Auditor & Report Agent

**AegisSec** is an enterprise-grade, defensive vulnerability assessment and security posture auditing agent. Give it any website URL or domain, and it executes a multi-module parallel security audit, computes a weighted risk score and letter grade (A+ to F), and generates professional executive and technical reports in **HTML (PDF-ready)**, **Markdown**, and **JSON**.

Designed strictly for authorized penetration testing, DevSecOps pipelines, and defensive security hardening. Zero external dependencies required—runs out of the box on Python 3.8+.

---

## 🚀 Key Features

* **Zero-Dependency Architecture**: Built entirely with the Python Standard Library (`ssl`, `socket`, `urllib`, `concurrent.futures`, `json`, `dataclasses`). Runs immediately without `pip install`.
* **High-Speed Parallel Auditing**: Executes concurrent audit modules via thread workers in milliseconds.
* **Comprehensive Defensive Security Audit**:
  * **HTTP Security Headers**: Audits 12+ headers including HSTS, CSP (script-src, unsafe-inline/eval), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, COEP, CORP.
  * **SSL/TLS & Cryptography**: Certificate validity, expiration alerts, SANs, weak ciphers, deprecated TLS 1.0/1.1 protocols, and plain HTTP-to-HTTPS redirect enforcement.
  * **DNS & Email Spoofing Defense**: SPF syntax & policy (`+all`, `~all`, `-all`), multiple SPF record detection (RFC 7208), DMARC policy enforcement (`_dmarc.<domain>`), CAA records, and DNSSEC.
  * **Cookie & CORS Hygiene**: Audits `Secure`, `HttpOnly`, `SameSite` flags, and tests for arbitrary origin reflection with credentials (`Access-Control-Allow-Credentials: true`).
  * **Information Exposure Probing**: Safe, non-destructive detection of exposed `.git`, `.env`, `docker-compose.yml`, `web.config`, `robots.txt` path disclosure, and RFC 9116 `security.txt`.
  * **HTTP Methods**: Tests verb tampering and dangerous methods like `TRACE` (Cross-Site Tracing).
* **CVSS & OWASP Top 10 Mapping**: Every finding is categorized by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), mapped to OWASP Top 10 (2021) and CWE IDs.
* **Copy-Paste Remediation Snippets**: Ready-to-use hardening configs for **Nginx**, **Apache**, **Caddy**, and **Node.js/Express**.
* **Dual Interface**:
  * Fast, ANSI-colored **CLI**.
  * Embedded **Interactive Web Dashboard & Report Viewer** (`--serve`).

---

## 📦 Project Structure

```
├── aegis.py                     # Main CLI executable entrypoint
├── server.py                    # Built-in Web UI & Report Dashboard
├── aegis_core/
│   ├── config.py                # Audit specifications & probe definitions
│   ├── models.py                # Finding, TargetInfo, AuditResult data models
│   ├── scanner.py               # Parallel audit orchestrator
│   ├── scoring.py               # Weighted score & letter grade calculation
│   ├── remediation.py           # Actionable config blueprints (Nginx, Apache, etc.)
│   ├── modules/
│   │   ├── headers_auditor.py   # HTTP Security Headers & Banner audit
│   │   ├── tls_auditor.py       # SSL/TLS & Certificate audit
│   │   ├── dns_auditor.py       # SPF, DMARC, CAA, DNSSEC audit
│   │   ├── cookies_cors.py      # Cookie flags & CORS exploitation audit
│   │   ├── exposure.py          # Sensitive file & metadata exposure audit
│   │   └── methods.py           # HTTP Methods & WebDAV audit
│   └── reporters/
│       ├── html_reporter.py     # Interactive, PDF-ready executive HTML dashboard
│       ├── markdown_reporter.py # GitHub / documentation Markdown report
│       └── json_reporter.py     # Machine-readable JSON for CI/CD pipelines
├── reports/                     # Output directory for generated audit reports
└── tests/
    ├── test_auditors.py         # Unit test suite (100% offline)
    └── mock_target.py           # Mock target server for end-to-end testing
```

---

## ⚡ Quick Start

### 1. Audit a Website via CLI
Run an audit by passing any domain or URL:
```bash
python3 aegis.py example.com
```
or with a full URL:
```bash
python3 aegis.py https://my-staging-site.com
```

### 2. Automatically Open the HTML Report in Browser
```bash
python3 aegis.py example.com --view
```

### 3. Launch the Interactive Web Dashboard
Run the web dashboard where you can audit websites interactively from your browser:
```bash
python3 aegis.py --serve
# or directly:
python3 server.py
```
Then navigate to: **`http://localhost:8080`**

---

## 🛠️ CLI Options

```text
usage: aegis.py [-h] [-o OUTPUT_DIR] [-f {all,html,md,json}] [-t TIMEOUT] [--view] [--serve] [--port PORT] [target]

AegisSec: End-to-End Website Security Auditor & Report Agent

positional arguments:
  target                Target domain or URL (e.g. example.com or https://example.com)

options:
  -h, --help            show this help message and exit
  -o, --output-dir      Directory where reports are saved (default: ./reports)
  -f, --format          Report output format: all, html, md, json (default: all)
  -t, --timeout         HTTP/TLS request timeout in seconds (default: 8.0)
  --view                Automatically open generated HTML report in default browser
  --serve               Launch the local interactive Web Dashboard & Report Viewer
  --port PORT           Web UI server port if using --serve (default: 8080)
```

---

## 🧪 Running Tests

The test suite runs completely offline without network requests:
```bash
python3 -m unittest tests/test_auditors.py -v
```

---

## ⚖️ Legal & Ethical Use
AegisSec performs non-destructive security posture and vulnerability auditing. Users must only scan domains and web applications they own or have explicit, documented authorization to assess.
