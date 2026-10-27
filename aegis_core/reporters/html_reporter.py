"""
Professional HTML & PDF-Ready Executive Security Report Generator for AegisSec.
"""

import html
from typing import Dict
from aegis_core.models import AuditResult, Severity


class HTMLReporter:
    def __init__(self, result: AuditResult):
        self.result = result

    def render(self) -> str:
        r = self.result
        t = r.target
        s = r.summary

        # Color schemes based on score/grade
        if s.score >= 85:
            score_color = "#10b981"  # Emerald Green
            grade_bg = "rgba(16, 185, 129, 0.15)"
        elif s.score >= 70:
            score_color = "#3b82f6"  # Blue
            grade_bg = "rgba(59, 130, 246, 0.15)"
        elif s.score >= 55:
            score_color = "#f59e0b"  # Amber
            grade_bg = "rgba(245, 158, 11, 0.15)"
        else:
            score_color = "#ef4444"  # Red
            grade_bg = "rgba(239, 68, 68, 0.15)"

        # Calculate circular gauge stroke
        circumference = 2 * 3.14159 * 52
        stroke_offset = circumference - (s.score / 100.0) * circumference

        loc_parts = [p for p in [t.city, t.country] if p]
        location_display = f" &bull; {html.escape(', '.join(loc_parts))}" if loc_parts else ""
        open_ports_display = html.escape(", ".join(map(str, t.open_ports))) if t.open_ports else "None flagged"
        asn_display = html.escape(str(t.asn or t.isp or "N/A"))

        # Build Findings HTML
        findings_html = []
        for idx, f in enumerate(r.findings, 1):
            sev_class = f.severity.value.lower()
            sev_badge_color = {
                Severity.CRITICAL: "#ef4444",
                Severity.HIGH: "#f97316",
                Severity.MEDIUM: "#eab308",
                Severity.LOW: "#3b82f6",
                Severity.INFO: "#64748b",
            }.get(f.severity, "#64748b")

            code_snippets_html = ""
            if f.remediation_code:
                code_snippets_html = "<div class='snippets-container'>"
                for srv_name, code in f.remediation_code.items():
                    code_snippets_html += f"""
                    <div class="snippet-block">
                        <div class="snippet-header">
                            <span>{html.escape(srv_name)}</span>
                            <button class="copy-btn" onclick="copySnippet(this)">Copy</button>
                        </div>
                        <pre><code>{html.escape(code)}</code></pre>
                    </div>
                    """
                code_snippets_html += "</div>"

            evidence_html = ""
            if f.evidence:
                evidence_html = f"""
                <div class="finding-section">
                    <h4>Evidence / Detected Response</h4>
                    <pre class="evidence-box"><code>{html.escape(f.evidence)}</code></pre>
                </div>
                """

            findings_html.append(f"""
            <div class="finding-card severity-{sev_class}" data-severity="{sev_class}" data-keywords="{html.escape((f.title + ' ' + f.id + ' ' + (f.cwe_id or '') + ' ' + (f.owasp_category or '')).lower())}">
                <div class="finding-top">
                    <div class="finding-meta-badges">
                        <span class="badge badge-sev" style="background-color: {sev_badge_color};">{f.severity.value}</span>
                        <span class="badge badge-cat">{html.escape(f.category.value)}</span>
                        {f'<span class="badge badge-cwe">{html.escape(f.cwe_id)}</span>' if f.cwe_id else ''}
                        {f'<span class="badge badge-cvss">CVSS {f.cvss_score}</span>' if f.cvss_score else ''}
                    </div>
                    <span class="finding-id">#{idx} &bull; {f.id}</span>
                </div>
                <h3 class="finding-title">{html.escape(f.title)}</h3>
                <p class="finding-desc">{html.escape(f.description)}</p>
                
                <div class="finding-section">
                    <h4>Security Impact</h4>
                    <p class="finding-impact">{html.escape(f.impact)}</p>
                </div>

                {evidence_html}

                <div class="finding-section">
                    <h4>Actionable Remediation</h4>
                    <p class="finding-remediation">{html.escape(f.remediation)}</p>
                    {code_snippets_html}
                </div>
            </div>
            """)

        all_findings_str = "\n".join(findings_html) if findings_html else "<div class='empty-state'>🎉 No vulnerabilities or security issues detected!</div>"

        # OWASP items
        owasp_rows = []
        for cat, cnt in s.owasp_breakdown.items():
            pct = min(100, int((cnt / max(1, s.total_findings)) * 100))
            owasp_rows.append(f"""
            <div class="owasp-row">
                <div class="owasp-name"><span>{html.escape(cat)}</span> <strong>{cnt}</strong></div>
                <div class="owasp-bar-bg"><div class="owasp-bar-fill" style="width: {pct}%;"></div></div>
            </div>
            """)
        owasp_html = "\n".join(owasp_rows) if owasp_rows else "<p style='color:#94a3b8; font-size: 0.9rem;'>No OWASP Top 10 vulnerabilities detected.</p>"

        # Module status indicators
        mod_status_html = []
        for mod_name, label in [
            ("headers", "HTTP Security Headers"),
            ("tls", "SSL / TLS Encryption"),
            ("dns", "DNS & Email Posture"),
            ("cookies_cors", "Cookies & CORS"),
            ("exposure", "Information Exposure"),
            ("methods", "HTTP Methods"),
            ("shodan", "Network & Shodan Intel"),
            ("tech", "Software & Libraries"),
        ]:
            mod_findings_cnt = sum(1 for f in r.findings if f.category.value.lower().startswith(label.lower()[:5]))
            mod_status_html.append(f"""
            <div class="mod-pill">
                <span class="mod-dot"></span>
                <span class="mod-name">{label}</span>
                <span class="mod-cnt">{mod_findings_cnt} issues</span>
            </div>
            """)

        # Build Tech Stack Badges HTML
        tech_cards = []
        for tech in t.technologies:
            v_badge = f'<span class="tech-ver">v{html.escape(tech["version"])}</span>' if tech.get("version") else ""
            tech_cards.append(f"""
            <div class="tech-badge">
                <span class="tech-icon">{tech.get('icon', '💻')}</span>
                <div class="tech-info">
                    <span class="tech-name">{html.escape(tech['name'])}</span>
                    <span class="tech-cat">{html.escape(tech.get('category', 'Library'))}</span>
                </div>
                {v_badge}
            </div>
            """)
        tech_stack_html = "".join(tech_cards) if tech_cards else "<p style='color:#94a3b8; font-size: 0.85rem;'>No specific client/server libraries fingerprinted.</p>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AegisSec Security Report - {html.escape(t.domain)}</title>
    <style>
        :root {{
            --bg-primary: #0a0e17;
            --bg-secondary: #111827;
            --bg-card: #1f2937;
            --bg-card-hover: #263345;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --border-color: #374151;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --accent-orange: #f97316;
            --accent-yellow: #eab308;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
        }}

        body {{
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding-bottom: 80px;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 24px;
        }}

        /* Header Navigation */
        header {{
            background: linear-gradient(180deg, #131c2e 0%, var(--bg-primary) 100%);
            border-bottom: 1px solid var(--border-color);
            padding: 24px 0;
            margin-bottom: 32px;
        }}

        .nav-content {{
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .brand {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .brand-logo {{
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 22px;
            box-shadow: 0 0 20px rgba(6, 182, 212, 0.4);
        }}

        .brand-title h1 {{
            font-size: 1.4rem;
            font-weight: 700;
            letter-spacing: -0.5px;
        }}

        .brand-title p {{
            font-size: 0.8rem;
            color: var(--text-secondary);
        }}

        .header-actions {{
            display: flex;
            gap: 12px;
        }}

        .btn {{
            padding: 8px 16px;
            border-radius: 8px;
            font-size: 0.88rem;
            font-weight: 600;
            cursor: pointer;
            border: 1px solid transparent;
            transition: all 0.2s ease;
        }}

        .btn-print {{
            background: #2563eb;
            color: #ffffff;
        }}

        .btn-print:hover {{
            background: #1d4ed8;
            box-shadow: 0 0 15px rgba(37, 99, 235, 0.5);
        }}

        /* Executive Banner */
        .exec-banner {{
            display: grid;
            grid-template-columns: 280px 1fr 300px;
            gap: 24px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 28px;
            margin-bottom: 32px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
        }}

        /* Score Circle */
        .score-box {{
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            border-right: 1px solid var(--border-color);
            padding-right: 24px;
        }}

        .gauge-svg {{
            transform: rotate(-90deg);
        }}

        .gauge-bg {{
            fill: none;
            stroke: #2d3748;
            stroke-width: 10;
        }}

        .gauge-fill {{
            fill: none;
            stroke: {score_color};
            stroke-width: 10;
            stroke-linecap: round;
            stroke-dasharray: {circumference};
            stroke-dashoffset: {stroke_offset};
            transition: stroke-dashoffset 1s ease-in-out;
        }}

        .gauge-text {{
            position: absolute;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }}

        .score-num {{
            font-size: 2.2rem;
            font-weight: 800;
            color: {score_color};
        }}

        .grade-pill {{
            margin-top: 8px;
            background: {grade_bg};
            color: {score_color};
            padding: 4px 14px;
            border-radius: 20px;
            font-size: 0.9rem;
            font-weight: 700;
            border: 1px solid {score_color}40;
        }}

        /* Target Meta */
        .target-meta {{
            display: flex;
            flex-direction: column;
            justify-content: center;
        }}

        .target-meta h2 {{
            font-size: 1.5rem;
            margin-bottom: 8px;
            word-break: break-all;
        }}

        .meta-list {{
            list-style: none;
            margin-top: 12px;
        }}

        .meta-list li {{
            font-size: 0.88rem;
            color: var(--text-secondary);
            margin-bottom: 6px;
        }}

        .meta-list strong {{
            color: var(--text-primary);
        }}

        /* KPI Cards Grid */
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 12px;
        }}

        .kpi-card {{
            background: var(--bg-card);
            border-radius: 10px;
            padding: 12px 16px;
            display: flex;
            flex-direction: column;
            justify-content: center;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }}

        .kpi-val {{
            font-size: 1.5rem;
            font-weight: 700;
        }}

        .kpi-label {{
            font-size: 0.75rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .crit-color {{ color: var(--accent-red); }}
        .high-color {{ color: var(--accent-orange); }}
        .med-color {{ color: var(--accent-yellow); }}
        .low-color {{ color: var(--accent-blue); }}

        /* Two Column Analytics */
        .analytics-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
            margin-bottom: 32px;
        }}

        .panel-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 24px;
        }}

        .panel-card h3 {{
            font-size: 1.1rem;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .tech-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(210px, 1fr));
            gap: 12px;
            margin-top: 12px;
        }}

        .tech-badge {{
            background: var(--bg-card);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 10px;
            padding: 10px 14px;
            display: flex;
            align-items: center;
            gap: 12px;
            transition: border-color 0.15s;
        }}

        .tech-badge:hover {{
            border-color: var(--accent-cyan);
        }}

        .tech-icon {{ font-size: 1.3rem; }}
        .tech-info {{ display: flex; flex-direction: column; flex: 1; }}
        .tech-name {{ font-weight: 700; font-size: 0.88rem; color: #f8fafc; }}
        .tech-cat {{ font-size: 0.72rem; color: var(--text-secondary); }}
        .tech-ver {{
            background: rgba(6, 182, 212, 0.15);
            color: var(--accent-cyan);
            border: 1px solid rgba(6, 182, 212, 0.3);
            border-radius: 6px;
            font-size: 0.72rem;
            font-weight: 700;
            padding: 2px 8px;
        }}

        .owasp-row {{
            margin-bottom: 12px;
        }}

        .owasp-name {{
            display: flex;
            justify-content: space-between;
            font-size: 0.85rem;
            margin-bottom: 4px;
        }}

        .owasp-bar-bg {{
            height: 6px;
            background: var(--bg-card);
            border-radius: 3px;
            overflow: hidden;
        }}

        .owasp-bar-fill {{
            height: 100%;
            background: linear-gradient(90deg, #3b82f6, #06b6d4);
            border-radius: 3px;
        }}

        .mod-pills-wrap {{
            display: flex;
            flex-direction: column;
            gap: 10px;
        }}

        .mod-pill {{
            background: var(--bg-card);
            border-radius: 8px;
            padding: 10px 14px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 0.88rem;
        }}

        .mod-dot {{
            width: 8px;
            height: 8px;
            background: var(--accent-green);
            border-radius: 50%;
            display: inline-block;
            margin-right: 8px;
        }}

        .mod-cnt {{
            color: var(--accent-cyan);
            font-weight: 600;
        }}

        /* Filter Controls */
        .filter-bar {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 14px 20px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 16px;
            flex-wrap: wrap;
        }}

        .filter-buttons {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }}

        .filter-btn {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 6px 14px;
            border-radius: 6px;
            font-size: 0.82rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.15s;
        }}

        .filter-btn.active, .filter-btn:hover {{
            background: #2563eb;
            color: #ffffff;
            border-color: #2563eb;
        }}

        .search-input {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 8px 14px;
            border-radius: 6px;
            font-size: 0.85rem;
            width: 260px;
            outline: none;
        }}

        .search-input:focus {{
            border-color: var(--accent-cyan);
        }}

        /* Findings List */
        .finding-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 14px;
            padding: 24px;
            margin-bottom: 20px;
            transition: border-color 0.2s;
        }}

        .finding-card:hover {{
            border-color: #4b5563;
        }}

        .finding-top {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
            flex-wrap: wrap;
            gap: 8px;
        }}

        .finding-meta-badges {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }}

        .badge {{
            font-size: 0.72rem;
            font-weight: 700;
            padding: 3px 8px;
            border-radius: 4px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .badge-sev {{ color: #ffffff; }}
        .badge-cat {{ background: #374151; color: #cbd5e1; }}
        .badge-cwe {{ background: #1e293b; color: #94a3b8; border: 1px solid #334155; }}
        .badge-cvss {{ background: #0f172a; color: #38bdf8; border: 1px solid #0284c7; }}

        .finding-id {{
            font-family: monospace;
            font-size: 0.8rem;
            color: var(--text-secondary);
        }}

        .finding-title {{
            font-size: 1.2rem;
            margin-bottom: 8px;
        }}

        .finding-desc {{
            color: #cbd5e1;
            font-size: 0.95rem;
            margin-bottom: 16px;
        }}

        .finding-section {{
            margin-top: 16px;
            padding-top: 14px;
            border-top: 1px solid rgba(255, 255, 255, 0.05);
        }}

        .finding-section h4 {{
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-secondary);
            margin-bottom: 6px;
        }}

        .finding-impact {{
            color: #f87171;
            font-size: 0.9rem;
        }}

        .finding-remediation {{
            color: #34d399;
            font-size: 0.9rem;
            margin-bottom: 12px;
        }}

        .evidence-box {{
            background: #090d16;
            border: 1px solid #1e293b;
            border-radius: 8px;
            padding: 12px 16px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.85rem;
            color: #e2e8f0;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }}

        /* Code Snippets */
        .snippets-container {{
            margin-top: 12px;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }}

        .snippet-block {{
            background: #090d16;
            border: 1px solid #1e293b;
            border-radius: 8px;
            overflow: hidden;
        }}

        .snippet-header {{
            background: #111827;
            padding: 6px 14px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.78rem;
            font-weight: 600;
            color: var(--text-secondary);
            border-bottom: 1px solid #1e293b;
        }}

        .snippet-block pre {{
            padding: 12px 14px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.82rem;
            color: #a5f3fc;
            overflow-x: auto;
        }}

        .copy-btn {{
            background: #1f2937;
            border: 1px solid #374151;
            color: #e2e8f0;
            padding: 2px 8px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.72rem;
        }}

        .copy-btn:hover {{
            background: #374151;
        }}

        /* Print Specific Styling */
        @media print {{
            body {{
                background-color: #ffffff;
                color: #000000;
            }}
            .filter-bar, .btn-print, .header-actions {{
                display: none !important;
            }}
            .exec-banner, .panel-card, .finding-card {{
                background: #ffffff !important;
                border: 1px solid #cccccc !important;
                color: #000000 !important;
                break-inside: avoid;
                box-shadow: none !important;
            }}
            .finding-desc, .meta-list li, .finding-section h4 {{
                color: #333333 !important;
            }}
            .evidence-box, .snippet-block {{
                background: #f8fafc !important;
                border: 1px solid #e2e8f0 !important;
                color: #000000 !important;
            }}
        }}

        @media (max-width: 900px) {{
            .exec-banner {{
                grid-template-columns: 1fr;
            }}
            .score-box {{
                border-right: none;
                border-bottom: 1px solid var(--border-color);
                padding-bottom: 20px;
                padding-right: 0;
            }}
            .analytics-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>

<header>
    <div class="container nav-content">
        <div class="brand">
            <div class="brand-logo">🛡️</div>
            <div class="brand-title">
                <h1>AegisSec Auditor</h1>
                <p>Enterprise Website Vulnerability & Security Posture Report</p>
            </div>
        </div>
        <div class="header-actions">
            <button class="btn btn-print" onclick="window.print()">Print / Export PDF</button>
        </div>
    </div>
</header>

<main class="container">
    <!-- Executive Banner -->
    <section class="exec-banner">
        <div class="score-box">
            <div style="position: relative; width: 120px; height: 120px; display: flex; align-items: center; justify-content: center;">
                <svg width="120" height="120" class="gauge-svg">
                    <circle cx="60" cy="60" r="52" class="gauge-bg"></circle>
                    <circle cx="60" cy="60" r="52" class="gauge-fill"></circle>
                </svg>
                <div class="gauge-text">
                    <span class="score-num">{s.score}</span>
                    <span style="font-size: 0.75rem; color: #94a3b8;">/ 100</span>
                </div>
            </div>
            <div class="grade-pill">{s.grade} &bull; {s.grade_label}</div>
        </div>

        <div class="target-meta">
            <h2>{html.escape(t.domain)}</h2>
            <ul class="meta-list">
                <li><strong>Audited URL:</strong> <a href="{html.escape(t.url)}" target="_blank" style="color: #38bdf8;">{html.escape(t.url)}</a></li>
                <li><strong>Detected Server:</strong> {html.escape(t.server_banner or 'Masked / Hidden')}</li>
                <li><strong>IP Addresses:</strong> {html.escape(', '.join(t.ip_addresses) or 'N/A')}</li>
                <li><strong>Network / ASN:</strong> {asn_display}{location_display}</li>
                <li><strong>Open Ports (Shodan):</strong> {open_ports_display}</li>
                <li><strong>Scan Completed:</strong> {t.scan_timestamp} ({s.duration_seconds}s)</li>
            </ul>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card">
                <span class="kpi-val crit-color">{s.critical_count}</span>
                <span class="kpi-label">Critical</span>
            </div>
            <div class="kpi-card">
                <span class="kpi-val high-color">{s.high_count}</span>
                <span class="kpi-label">High</span>
            </div>
            <div class="kpi-card">
                <span class="kpi-val med-color">{s.medium_count}</span>
                <span class="kpi-label">Medium</span>
            </div>
            <div class="kpi-card">
                <span class="kpi-val low-color">{s.low_count + s.info_count}</span>
                <span class="kpi-label">Low / Info</span>
            </div>
        </div>
    </section>

    <!-- Analytics & Scope Grid -->
    <section class="analytics-grid">
        <div class="panel-card">
            <h3>📊 OWASP Top 10 Risk Mapping</h3>
            {owasp_html}
        </div>
        <div class="panel-card">
            <h3>🔍 Audited Security Controls</h3>
            <div class="mod-pills-wrap">
                {mod_status_html[0]}
                {mod_status_html[1]}
                {mod_status_html[2]}
                {mod_status_html[3]}
                {mod_status_html[4]}
                {mod_status_html[5]}
                {mod_status_html[6] if len(mod_status_html) > 6 else ''}
                {mod_status_html[7] if len(mod_status_html) > 7 else ''}
            </div>
        </div>
    </section>

    <!-- Technology Stack Profiler Section -->
    <section class="panel-card" style="margin-bottom: 24px;">
        <h3>💻 Detected Technologies & Software Libraries ({len(t.technologies)})</h3>
        <div class="tech-grid">
            {tech_stack_html}
        </div>
    </section>

    <!-- Filter Bar -->
    <section class="filter-bar">
        <div class="filter-buttons">
            <button class="filter-btn active" data-filter="all">All ({s.total_findings})</button>
            <button class="filter-btn" data-filter="critical">Critical ({s.critical_count})</button>
            <button class="filter-btn" data-filter="high">High ({s.high_count})</button>
            <button class="filter-btn" data-filter="medium">Medium ({s.medium_count})</button>
            <button class="filter-btn" data-filter="low">Low ({s.low_count})</button>
            <button class="filter-btn" data-filter="info">Info ({s.info_count})</button>
        </div>
        <input type="text" id="searchInput" class="search-input" placeholder="Search findings (e.g. CSP, CORS, SSL)..." oninput="filterFindings()">
    </section>

    <!-- Findings Section -->
    <section id="findingsList">
        {all_findings_str}
    </section>
</main>

<script>
    let currentFilter = 'all';

    document.querySelectorAll('.filter-btn').forEach(btn => {{
        btn.addEventListener('click', () => {{
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentFilter = btn.getAttribute('data-filter');
            filterFindings();
        }});
    }});

    function filterFindings() {{
        const searchVal = document.getElementById('searchInput').value.toLowerCase().trim();
        const cards = document.querySelectorAll('.finding-card');

        cards.forEach(card => {{
            const sev = card.getAttribute('data-severity');
            const keywords = card.getAttribute('data-keywords') || '';

            const matchesSeverity = (currentFilter === 'all' || sev === currentFilter);
            const matchesSearch = (!searchVal || keywords.includes(searchVal));

            if (matchesSeverity && matchesSearch) {{
                card.style.display = 'block';
            }} else {{
                card.style.display = 'none';
            }}
        }});
    }}

    function copySnippet(btn) {{
        const pre = btn.parentElement.nextElementSibling;
        navigator.clipboard.writeText(pre.innerText).then(() => {{
            const orig = btn.innerText;
            btn.innerText = 'Copied!';
            setTimeout(() => btn.innerText = orig, 2000);
        }});
    }}
</script>
</body>
</html>
"""

    def save(self, filepath: str) -> None:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self.render())
