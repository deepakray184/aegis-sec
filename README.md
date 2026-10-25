# 🛡️ AegisSec: End-to-End Website Security Auditor & Shodan Intelligence Agent

**AegisSec** is an enterprise-grade, defensive vulnerability assessment, threat surface intelligence, and security posture auditing agent. Give it any website URL or domain, and it executes a multi-module parallel security audit, computes a weighted risk score and letter grade (A+ to F), and generates professional executive and technical reports in **PDF (Print-Ready)**, **Interactive HTML**, **Markdown**, and **JSON**.

Designed strictly for authorized penetration testing, DevSecOps pipelines, and defensive security hardening. Zero external dependencies required—runs out of the box on Python 3.8+.

---

## 🚀 Key Features

* **Zero-Dependency Architecture**: Built entirely with the Python Standard Library (`ssl`, `socket`, `urllib`, `concurrent.futures`, `json`, `dataclasses`). Runs immediately without `pip install`.
* **Shodan & Network Intelligence**:
  * Integrates **Shodan InternetDB** to discover **publicly open ports** (e.g. 21, 22, 23, 80, 443, 3306, 3389, 8080).
  * Automatically flags **known CVE vulnerabilities** and software CPEs indexed by Shodan.
  * Resolves **ASN**, **ISP**, **Hosting Provider**, and **Geographic Location**.
* **Comprehensive Defensive Security Audit**:
  * **HTTP Security Headers**: Audits 12+ headers including HSTS, CSP (script-src, unsafe-inline/eval), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, COEP, CORP.
  * **SSL/TLS & Cryptography**: Certificate validity, expiration alerts, SANs, weak ciphers, deprecated TLS 1.0/1.1 protocols, and plain HTTP-to-HTTPS redirect enforcement.
  * **DNS & Email Spoofing Defense**: SPF syntax & policy (`+all`, `~all`, `-all`), multiple SPF record detection (RFC 7208), DMARC policy enforcement (`_dmarc.<domain>`), CAA records, and DNSSEC.
  * **Cookie & CORS Hygiene**: Audits `Secure`, `HttpOnly`, `SameSite` flags, and tests for arbitrary origin reflection with credentials (`Access-Control-Allow-Credentials: true`).
  * **Information Exposure Probing**: Safe, non-destructive detection of exposed `.git`, `.env`, `docker-compose.yml`, `web.config`, `robots.txt` path disclosure, and RFC 9116 `security.txt`.
  * **HTTP Methods**: Tests verb tampering and dangerous methods like `TRACE` (Cross-Site Tracing).
* **Automated Executive PDF & HTML Generation**:
  * Built-in headless Chromium engine converts audit results into pixel-perfect executive PDF documents.
* **Dual Interface**:
  * Fast, ANSI-colored **CLI**.
  * Embedded **Interactive Web Dashboard & Report Viewer** (`--serve`).
  * **GitHub Pages Web App** (`docs/`) ready for instant web deployment!

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

### 1. Audit a Website via CLI
Run an audit by passing any domain or URL:
```bash
python3 aegis.py example.com
```

### 2. Generate PDF and Open in Browser
```bash
python3 aegis.py demo.testfire.net --format all --view
```

### 3. Launch Local Web Dashboard & API
```bash
python3 aegis.py --serve
# or:
python3 server.py
```
Open **`http://localhost:8080`** in your browser.

---

## 🌐 Deploying to GitHub Pages (2 Steps)

The web dashboard is located in the **`docs/`** folder and can be hosted for free on GitHub Pages:

1. In your GitHub repository:
   * Go to **Settings** → **Pages**.
   * Under **Build and deployment**:
     * **Source**: `Deploy from a branch`
     * **Branch**: `main` | Folder: `/docs`
   * Click **Save**.
2. Your live web tool will be available at:
   `https://deepakray184.github.io/aegis-sec/`

---

## ☁️ Deploying the Free Backend API

To allow your GitHub Pages site to run audits from anywhere on the web:

### Option A: 1-Click Deploy on Render.com (Free)
1. Sign up on [Render.com](https://render.com) (free).
2. Click **New** → **Blueprint** and connect your `aegis-sec` GitHub repository.
3. Render will automatically detect `render.yaml` and deploy your API.
4. On your GitHub Pages site, click the **Backend Status** badge and paste your Render URL (`https://your-service.onrender.com`).

### Option B: Run with Docker
```bash
docker build -t aegis-sec .
docker run -p 8080:8080 aegis-sec
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
