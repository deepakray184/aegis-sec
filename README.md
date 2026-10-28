# 🛡️ AegisSec: Website Security Auditor & Shodan Intelligence Agent

<p align="center">
  <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/Python-3.8%2B-brightgreen.svg" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/Dependencies-Zero%20(Standard%20Library)-success.svg" alt="Zero Dependencies">
  <img src="https://img.shields.io/badge/Recon-Shodan%20InternetDB-orange.svg" alt="Shodan InternetDB">
  <img src="https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-informational.svg" alt="Live Demo">
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white" alt="Docker Ready">
</p>

<p align="center">
  <b>AegisSec</b> is an enterprise-grade, defensive vulnerability assessment, threat surface intelligence, and security posture auditing agent. Give it any website URL or domain, and it executes a multi-module parallel security audit, computes a weighted risk score and letter grade (A+ to F), and generates professional executive and technical reports in <b>PDF (Print-Ready)</b>, <b>Interactive HTML</b>, <b>Markdown</b>, and <b>JSON</b>.
</p>

<p align="center">
  🌐 <b>Live Web Dashboard:</b> <a href="https://deepakray184.github.io/aegis-sec/">https://deepakray184.github.io/aegis-sec/</a>
</p>

---

## 📑 Table of Contents
- [Architecture & Workflow](#-architecture--workflow)
- [Key Features](#-key-features)
- [Audited Security Controls & OWASP Mapping](#-audited-security-controls--owasp-mapping)
- [Project Structure](#-project-structure)
- [Quick Start (CLI)](#-quick-start-cli)
- [Deploying to GitHub Pages](#-deploying-to-github-pages-2-steps)
- [Deploying the Free Cloud Backend API](#-deploying-the-free-cloud-backend-api)
- [REST API Reference](#-rest-api-reference)
- [Running Tests](#-running-tests)
- [Legal & Ethical Disclaimer](#-legal--ethical-disclaimer)

---

## 🏛️ Architecture & Workflow

```
                        ┌──────────────────────────────────────┐
                        │      Target Input (URL / Domain)     │
                        └──────────────────┬───────────────────┘
                                           │
                        ┌──────────────────▼───────────────────┐
                        │   Target Normalization & DNS IP      │
                        └──────────────────┬───────────────────┘
                                           │
         ┌─────────────────────────────────┴─────────────────────────────────┐
         │              Parallel Audit Engine (ThreadPoolExecutor)           │
         ├──────────────────┬───────────────────┬────────────────────────────┤
         │  Headers Auditor │   TLS/SSL Auditor │   DNS & Email (SPF/DMARC)  │
         ├──────────────────┼───────────────────┼────────────────────────────┤
         │  Cookies & CORS  │ Sensitive Exposure│   Shodan InternetDB Recon  │
         └──────────────────┴──────────────┬────┴────────────────────────────┘
                                           │
                        ┌──────────────────▼───────────────────┐
                        │    Scoring Engine & OWASP Mapping    │
                        │    (Score 0-100, Grade A+ to F, CVSS)│
                        └──────────────────┬───────────────────┘
                                           │
       ┌───────────────────┬───────────────┴───────────────┬───────────────────┐
       ▼                   ▼                               ▼                   ▼
┌──────────────┐    ┌──────────────┐                ┌──────────────┐    ┌──────────────┐
│Executive PDF │    │Interactive   │                │GitHub / Jira │    │CI/CD Machine │
│Report (Print)│    │HTML Dashboard│                │Markdown Doc  │    │JSON Telemetry│
└──────────────┘    └──────────────┘                └──────────────┘    └──────────────┘
```

---

## 🚀 Key Features

* **Zero Mandatory Dependencies**: Runs out of the box on Python 3.8+ using pure standard library (`ssl`, `socket`, `urllib`, `concurrent.futures`, `json`, `dataclasses`).
* **Shodan InternetDB & Network Intelligence**:
  * Free, keyless reconnaissance via **Shodan's InternetDB API**.
  * Identifies **open public ports** (e.g. 21, 22, 23, 80, 443, 3306, 3389, 8080).
  * Automatically cross-references and flags **known CVE vulnerabilities** and software CPEs.
  * Resolves **ASN**, **ISP**, **Hosting Organization**, **Country**, and **City**.
* **Comprehensive Defensive Security Audit**:
  * **HTTP Security Headers**: Evaluates HSTS, CSP (script-src, unsafe-inline/eval), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, COEP, CORP.
  * **SSL/TLS & Cryptography**: Certificate expiration countdown, SANs, weak ciphers, deprecated TLS 1.0/1.1 protocols, and plain HTTP-to-HTTPS redirect enforcement.
  * **DNS & Email Spoofing Defense**: SPF syntax & policy (`+all`, `~all`, `-all`), multiple SPF record detection (RFC 7208), DMARC policy enforcement (`_dmarc.<domain>`), CAA records, and DNSSEC.
  * **Cookie & CORS Hygiene**: Audits `Secure`, `HttpOnly`, `SameSite` flags, and tests for arbitrary origin reflection with credentials (`Access-Control-Allow-Credentials: true`).
  * **Information Exposure Probing**: Safe, non-destructive detection of exposed `.git`, `.env`, `docker-compose.yml`, `web.config`, `robots.txt` path disclosure, and RFC 9116 `security.txt`.
  * **HTTP Methods**: Tests verb tampering and dangerous methods like `TRACE` (Cross-Site Tracing).
* **Automated Executive PDF & HTML Generation**:
  * Built-in headless Chromium engine converts audit results into pixel-perfect executive PDF documents with print typography.
* **Dual Interface**:
  * Fast, ANSI-colored **CLI**.
  * Embedded **Interactive Web Dashboard & Report Viewer** (`--serve`).
  * **GitHub Pages Web App** (`docs/`) ready for instant web deployment!

---

## 🛡️ Audited Security Controls & OWASP Mapping

| Category | Security Control Audited | OWASP Top 10 | CWE ID | Default Severity |
| :--- | :--- | :--- | :--- | :--- |
| **Network & Shodan** | Known CVE Vulnerabilities | A06:2021-Vulnerable Components | CWE-1395 | 🔴 CRITICAL |
| **Network & Shodan** | Exposed Database / Admin Ports (RDP, DB, Telnet) | A05:2021-Security Misconfiguration | CWE-668 | 🔴 CRITICAL / 🟠 HIGH |
| **TLS / SSL** | Expired or Missing SSL/TLS Certificate | A02:2021-Cryptographic Failures | CWE-319 | 🔴 CRITICAL |
| **TLS / SSL** | Deprecated Protocols (TLS 1.0 / TLS 1.1) | A02:2021-Cryptographic Failures | CWE-326 | 🟠 HIGH |
| **TLS / SSL** | Certificate Expiring Soon (<15 Days) | A02:2021-Cryptographic Failures | CWE-298 | 🟠 HIGH |
| **Headers** | Missing Content-Security-Policy (CSP) | A05:2021-Security Misconfiguration | CWE-1021 | 🟠 HIGH |
| **Headers** | Missing Strict-Transport-Security (HSTS) | A05:2021-Security Misconfiguration | CWE-319 | 🟠 HIGH |
| **Headers** | Missing X-Frame-Options (Clickjacking) | A05:2021-Security Misconfiguration | CWE-1021 | 🟡 MEDIUM |
| **DNS & Email** | Permissive SPF Record (`+all` / `?all`) | A05:2021-Security Misconfiguration | CWE-290 | 🔴 CRITICAL / 🟡 MEDIUM |
| **DNS & Email** | Missing or Monitoring-Only DMARC Policy | A05:2021-Security Misconfiguration | CWE-290 | 🟠 HIGH / 🟡 MEDIUM |
| **Cookies & CORS** | Cookie Missing `HttpOnly` / `Secure` Flags | A07:2021-Auth Failures / A05 | CWE-1004 / CWE-614 | 🟠 HIGH / 🟡 MEDIUM |
| **Cookies & CORS** | Arbitrary Origin Reflection with Credentials | A01:2021-Broken Access Control | CWE-942 | 🔴 CRITICAL |
| **Exposure** | Exposed Git Metadata / Environment Files (`.git`, `.env`) | A05:2021-Security Misconfiguration | CWE-538 / CWE-540 | 🔴 CRITICAL |
| **Exposure** | Sensitive Paths Disclosed in `robots.txt` | A01:2021-Broken Access Control | CWE-200 | 🔵 LOW |
| **Exposure** | Missing `security.txt` RFC 9116 Policy | A05:2021-Security Misconfiguration | CWE-200 | ⚪ INFO |
| **HTTP Methods** | Dangerous HTTP Methods Enabled (`TRACE` / XST) | A05:2021-Security Misconfiguration | CWE-16 | 🟡 MEDIUM |

---

## 📦 Project Structure

```
├── aegis.py                     # Main CLI executable entrypoint
├── server.py                    # Production REST API & Web Dashboard
├── docs/                        # GitHub Pages static Web Application
│   ├── index.html               # Modern Tailwind CSS single-page app
│   └── app.js                   # Interactive client logic & API bridge
├── render.yaml                  # 1-Click deploy blueprint for Render.com
├── Procfile                     # Process file for Railway / Render
├── Dockerfile                   # Container manifest with Chromium
├── aegis_core/
│   ├── config.py                # Audit specifications & probe definitions
│   ├── models.py                # Finding, TargetInfo, AuditResult data models
│   ├── scanner.py               # Parallel audit orchestrator
│   ├── scoring.py               # Weighted score & letter grade calculation
│   ├── remediation.py           # Actionable config blueprints (Nginx, Apache, etc.)
│   ├── modules/
│   │   ├── shodan_auditor.py    # Shodan InternetDB, ASN, & CVE intelligence
│   │   ├── headers_auditor.py   # HTTP Security Headers & Banner audit
│   │   ├── tls_auditor.py       # SSL/TLS & Certificate audit
│   │   ├── dns_auditor.py       # SPF, DMARC, CAA, DNSSEC audit
│   │   ├── cookies_cors.py      # Cookie flags & CORS exploitation audit
│   │   ├── exposure.py          # Sensitive file & metadata exposure audit
│   │   └── methods.py           # HTTP Methods & WebDAV audit
│   └── reporters/
│       ├── pdf_reporter.py      # Executive PDF document generator
│       ├── html_reporter.py     # Interactive SVG executive HTML dashboard
│       ├── markdown_reporter.py # GitHub / documentation Markdown report
│       └── json_reporter.py     # Machine-readable JSON for CI/CD pipelines
├── reports/                     # Output directory for generated audit reports
└── tests/
    ├── test_auditors.py         # Unit test suite (100% offline)
    └── mock_target.py           # Mock target server for end-to-end testing
```

---

## ⚡ Quick Start (CLI)

### 1. Basic Audit
Pass any target domain or URL:
```bash
python3 aegis.py example.com
```

### 2. Generate PDF and Open in Browser
```bash
python3 aegis.py demo.testfire.net --format all --view
```

### 3. Specify Custom Output Directory and Timeout
```bash
python3 aegis.py https://my-site.com -o ./custom_reports -t 10.0
```

### 4. Launch Local Interactive Web Dashboard
```bash
python3 aegis.py --serve
# or directly:
python3 server.py
```
Open **`http://localhost:8080`** in your browser.

---

## 🌐 GitHub Pages Deployment (Zero Setup Needed!)

The web dashboard is located in the **`docs/`** folder and runs **100% autonomously on GitHub Pages with zero server backend required**:

1. In your GitHub repository:
   * Go to **Settings** → **Pages**.
   * Under **Build and deployment**:
     * **Source**: `Deploy from a branch`
     * **Branch**: `main` | Folder: `/docs`
   * Click **Save**.
2. Your live website security auditor is instantly live at:  
   👉 **`https://deepakray184.github.io/aegis-sec/`**

### How It Works Out-of-the-Box:
- **Browser Cloud Engine (Default)**: Automatically queries Cloudflare DoH, Google DoH, Shodan InternetDB, and IP intelligence directly from the visitor's browser.
- **Zero Server Cost**: Requires no servers, databases, or third-party paid keys to operate.
- **Instant Client-Side Exports**: Generates Executive PDF (Print-ready), Standalone Interactive HTML reports, and JSON telemetry with one click.

---

## ☁️ Optional: Custom Python Backend API (Advanced)

If you want deep raw TCP socket TLS cipher verification, raw HTTP response header inspection, and Chromium PDF rendering:

### Option A: Local Backend
```bash
python3 server.py
# Or:
python3 aegis.py --serve
```
In your GitHub Pages dashboard, click the top status badge, switch to **Custom Python Backend API**, and enter `http://localhost:8080`.

### Option B: 1-Click Deploy on Render.com (Free)
1. Sign up for free at [Render.com](https://render.com).
2. Click **New +** → **Blueprint** and select your `aegis-sec` GitHub repository.
3. Render will automatically detect `render.yaml` and deploy your API.
4. On your live GitHub Pages site, click the top status badge and paste your Render URL (`https://your-service.onrender.com`).

### Option C: Run with Docker
```bash
docker build -t aegis-sec .
docker run -p 8080:8080 aegis-sec
```

---

## 🔌 REST API Reference

The built-in backend provides a CORS-enabled JSON API for integration into CI/CD pipelines and web apps:

### Health Check
```http
GET /health
```
```json
{
  "status": "healthy",
  "service": "AegisSec API",
  "version": "2.0"
}
```

### Trigger Security Audit
```http
POST /api/scan
Content-Type: application/json

{
  "target": "example.com"
}
```
**Response (excerpt):**
```json
{
  "status": "success",
  "target": "example.com",
  "score": 8,
  "grade": "F",
  "total_findings": 11,
  "report_url": "/reports/audit_example_com_20261024_175154.html",
  "pdf_url": "/reports/audit_example_com_20261024_175154.pdf",
  "result": {
    "target": {
      "domain": "example.com",
      "ip_addresses": ["104.20.23.154"],
      "asn": "AS13335 Cloudflare, Inc.",
      "open_ports": [80, 443]
    },
    "summary": {
      "score": 8,
      "grade": "F",
      "critical_count": 0,
      "high_count": 5
    }
  }
}
```

---

## 🧪 Running Tests

The test suite runs completely offline without network requests:
```bash
python3 -m unittest tests/test_auditors.py -v
```

---

## ⚖️ Legal & Ethical Disclaimer
AegisSec performs non-destructive security posture and vulnerability auditing. Users must only scan domains and web applications they own or have explicit, documented authorization to assess.
