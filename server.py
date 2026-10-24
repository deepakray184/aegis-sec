"""
Lightweight Web Dashboard and Interactive Report Server for AegisSec.
Zero-dependency, pure standard library HTTP server.
"""

import os
import sys
import json
import urllib.parse
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from datetime import datetime, timezone

# Add root directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aegis_core.scanner import SecurityAuditor
from aegis_core.reporters.html_reporter import HTMLReporter
from aegis_core.reporters.markdown_reporter import MarkdownReporter
from aegis_core.reporters.json_reporter import JSONReporter

REPORTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "reports"))
os.makedirs(REPORTS_DIR, exist_ok=True)


class AegisWebHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            self._serve_dashboard()
        elif path.startswith("/reports/"):
            filename = os.path.basename(path)
            file_path = os.path.join(REPORTS_DIR, filename)
            if os.path.exists(file_path):
                self._serve_file(file_path)
            else:
                self.send_error(404, "Report file not found")
        elif path == "/api/list-reports":
            self._serve_list_reports()
        elif path == "/api/scan":
            target = query.get("target", [""])[0]
            if not target:
                self._send_json({"error": "Missing 'target' parameter"}, status=400)
                return
            self._handle_scan(target)
        else:
            self.send_error(404, "Page Not Found")

    def _serve_dashboard(self):
        html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AegisSec - Web Security Auditor Dashboard</title>
    <style>
        :root {
            --bg-primary: #0a0e17;
            --bg-secondary: #111827;
            --bg-card: #1f2937;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --border-color: #374151;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --accent-green: #10b981;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background: var(--bg-primary); color: var(--text-primary); line-height: 1.6; padding: 40px 20px; }
        .container { max-width: 900px; margin: 0 auto; }
        .hero { text-align: center; margin-bottom: 40px; }
        .hero-badge { display: inline-flex; align-items: center; gap: 8px; background: rgba(6, 182, 212, 0.15); color: var(--accent-cyan); padding: 6px 16px; border-radius: 20px; font-size: 0.85rem; font-weight: 600; margin-bottom: 16px; border: 1px solid rgba(6, 182, 212, 0.3); }
        .hero h1 { font-size: 2.5rem; font-weight: 800; letter-spacing: -0.5px; margin-bottom: 12px; }
        .hero p { color: var(--text-secondary); font-size: 1.1rem; }
        
        .scan-card { background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 16px; padding: 32px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); margin-bottom: 40px; }
        .input-group { display: flex; gap: 12px; margin-bottom: 16px; }
        .input-target { flex: 1; background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 10px; padding: 14px 20px; font-size: 1.05rem; color: #fff; outline: none; transition: border-color 0.2s; }
        .input-target:focus { border-color: var(--accent-cyan); box-shadow: 0 0 15px rgba(6, 182, 212, 0.2); }
        .btn-scan { background: linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%); color: #fff; border: none; border-radius: 10px; padding: 14px 28px; font-size: 1.05rem; font-weight: 700; cursor: pointer; transition: opacity 0.2s; display: flex; align-items: center; gap: 8px; }
        .btn-scan:hover { opacity: 0.9; }
        .btn-scan:disabled { opacity: 0.5; cursor: not-allowed; }

        .disclaimer { font-size: 0.8rem; color: var(--text-secondary); text-align: center; }

        .status-box { display: none; background: #131c2e; border: 1px solid #1e3a8a; border-radius: 10px; padding: 16px 20px; margin-top: 20px; }
        .spinner { display: inline-block; width: 18px; height: 18px; border: 3px solid rgba(255,255,255,0.3); border-radius: 50%; border-top-color: #fff; animation: spin 1s ease-in-out infinite; vertical-align: middle; margin-right: 8px; }
        @keyframes spin { to { transform: rotate(360deg); } }

        .history-card { background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 16px; padding: 24px; }
        .history-card h2 { font-size: 1.25rem; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center; }
        .report-item { background: var(--bg-card); border: 1px solid rgba(255,255,255,0.05); border-radius: 10px; padding: 14px 18px; margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center; text-decoration: none; color: inherit; transition: all 0.2s; }
        .report-item:hover { border-color: var(--accent-cyan); transform: translateX(4px); }
        .report-title { font-weight: 600; font-size: 0.95rem; }
        .report-date { font-size: 0.8rem; color: var(--text-secondary); }
        .view-pill { background: #2563eb; color: #fff; padding: 4px 12px; border-radius: 6px; font-size: 0.8rem; font-weight: 600; }
    </style>
</head>
<body>
<div class="container">
    <div class="hero">
        <div class="hero-badge">🛡️ AegisSec Automated Security Agent</div>
        <h1>Website Security Auditor</h1>
        <p>Comprehensive vulnerability assessment, SSL/TLS, HTTP headers, CORS, and executive reporting</p>
    </div>

    <div class="scan-card">
        <form id="scanForm" onsubmit="triggerScan(event)">
            <div class="input-group">
                <input type="text" id="targetInput" class="input-target" placeholder="Enter target domain or URL (e.g. example.com or https://mysite.com)" required autofocus>
                <button type="submit" id="scanBtn" class="btn-scan">
                    <span>Audit Website</span>
                </button>
            </div>
            <p class="disclaimer">⚠️ Please ensure you are authorized to audit and review the security posture of the target domain.</p>
        </form>

        <div id="statusBox" class="status-box">
            <span class="spinner"></span>
            <span id="statusText">Initiating parallel security audit modules...</span>
        </div>
    </div>

    <div class="history-card">
        <h2>
            <span>📁 Generated Reports History</span>
            <button onclick="loadReports()" style="background: none; border: none; color: var(--accent-cyan); cursor: pointer; font-size: 0.85rem;">Refresh</button>
        </h2>
        <div id="reportsList">
            <p style="color: var(--text-secondary); font-size: 0.9rem;">Loading historical audits...</p>
        </div>
    </div>
</div>

<script>
    async function loadReports() {
        const listDiv = document.getElementById('reportsList');
        try {
            const resp = await fetch('/api/list-reports');
            const data = await resp.json();
            if (!data.reports || data.reports.length === 0) {
                listDiv.innerHTML = '<p style="color: var(--text-secondary); font-size: 0.9rem;">No reports generated yet. Enter a target above to run your first audit!</p>';
                return;
            }
            listDiv.innerHTML = data.reports.map(r => `
                <a href="${r.url}" target="_blank" class="report-item">
                    <div>
                        <div class="report-title">${r.name}</div>
                        <div class="report-date">Generated: ${r.modified} &bull; Size: ${r.size}</div>
                    </div>
                    <div class="view-pill">View Report &rarr;</div>
                </a>
            `).join('');
        } catch (e) {
            listDiv.innerHTML = '<p style="color: #ef4444;">Failed to load report list.</p>';
        }
    }

    async function triggerScan(e) {
        e.preventDefault();
        const target = document.getElementById('targetInput').value.trim();
        if (!target) return;

        const scanBtn = document.getElementById('scanBtn');
        const statusBox = document.getElementById('statusBox');
        const statusText = document.getElementById('statusText');

        scanBtn.disabled = true;
        statusBox.style.display = 'block';
        statusText.innerText = `Auditing ${target} across TLS, Headers, DNS, CORS, and Exposure...`;

        try {
            const resp = await fetch(`/api/scan?target=${encodeURIComponent(target)}`);
            const data = await resp.json();
            if (data.error) {
                statusText.innerText = `Error: ${data.error}`;
                scanBtn.disabled = false;
            } else if (data.report_url) {
                statusText.innerText = `Audit complete! Opening report...`;
                window.location.href = data.report_url;
            }
        } catch (err) {
            statusText.innerText = `Connection failed: ${err.message}`;
            scanBtn.disabled = false;
        }
    }

    window.addEventListener('DOMContentLoaded', loadReports);
</script>
</body>
</html>
"""
        self._send_html(html_content)

    def _handle_scan(self, target: str):
        try:
            auditor = SecurityAuditor(target)
            result = auditor.run()

            timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            sanitized_domain = result.target.domain.replace(".", "_").replace(":", "_")
            base_filename = f"audit_{sanitized_domain}_{timestamp_slug}"

            # Save HTML, MD, JSON
            html_file = f"{base_filename}.html"
            html_path = os.path.join(REPORTS_DIR, html_file)
            HTMLReporter(result).save(html_path)

            md_path = os.path.join(REPORTS_DIR, f"{base_filename}.md")
            MarkdownReporter(result).save(md_path)

            json_path = os.path.join(REPORTS_DIR, f"{base_filename}.json")
            JSONReporter(result).save(json_path)

            self._send_json({
                "status": "success",
                "target": result.target.domain,
                "score": result.summary.score,
                "grade": result.summary.grade,
                "total_findings": result.summary.total_findings,
                "report_url": f"/reports/{html_file}",
            })
        except Exception as e:
            self._send_json({"error": str(e)}, status=500)

    def _serve_list_reports(self):
        reports = []
        if os.path.exists(REPORTS_DIR):
            for fname in sorted(os.listdir(REPORTS_DIR), reverse=True):
                if fname.endswith(".html"):
                    fpath = os.path.join(REPORTS_DIR, fname)
                    stat = os.stat(fpath)
                    mod_time = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                    size_kb = f"{round(stat.st_size / 1024, 1)} KB"
                    reports.append({
                        "name": fname.replace(".html", ""),
                        "url": f"/reports/{fname}",
                        "modified": mod_time,
                        "size": size_kb,
                    })
        self._send_json({"reports": reports})

    def _serve_file(self, filepath: str):
        content_type = "text/html"
        if filepath.endswith(".json"):
            content_type = "application/json"
        elif filepath.endswith(".md"):
            content_type = "text/markdown"

        try:
            with open(filepath, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", f"{content_type}; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_error(500, str(e))

    def _send_html(self, content: str, status: int = 200):
        encoded = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _send_json(self, data: dict, status: int = 200):
        encoded = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format, *args):
        # Clean logging
        sys.stderr.write(f"[AegisSec Web] {args[0]} - {args[1]}\n")


def start_dashboard(host: str = "127.0.0.1", port: int = 8080):
    server = ThreadingHTTPServer((host, port), AegisWebHandler)
    url = f"http://{host}:{port}"
    print(f"\n\033[32m\033[1m[+] AegisSec Web Dashboard live at:\033[0m \033[36m{url}\033[0m")
    print(f"\033[90mPress Ctrl+C to stop the dashboard server.\033[0m\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\033[33m[*] Stopping AegisSec Dashboard...\033[0m")
        server.shutdown()


if __name__ == "__main__":
    start_dashboard()
