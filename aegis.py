#!/usr/bin/env python3
"""
AegisSec - End-to-End Website Security Auditor & Executive Report Agent.
Author: Google Deepmind / Advanced Agentic Coding
"""

import sys
import os
import argparse
import subprocess
from datetime import datetime, timezone

# Add root directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aegis_core.models import Severity
from aegis_core.scanner import SecurityAuditor
from aegis_core.reporters.html_reporter import HTMLReporter
from aegis_core.reporters.markdown_reporter import MarkdownReporter
from aegis_core.reporters.json_reporter import JSONReporter
from aegis_core.reporters.pdf_reporter import PDFReporter


# ANSI formatting colors
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_CYAN = "\033[36m"
C_BLUE = "\033[34m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_RED = "\033[31m"
C_GRAY = "\033[90m"
C_MAGENTA = "\033[35m"


def print_banner():
    banner = f"""
{C_CYAN}{C_BOLD}
    █████╗ ███████╗ ██████╗ ██╗███████╗    ███████╗███████╗ ██████╗
   ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝    ██╔════╝██╔════╝██╔════╝
   ███████║█████╗  ██║  ███╗██║███████╗    ███████╗█████╗  ██║     
   ██╔══██║██╔══╝  ██║   ██║██║╚════██║    ╚════██║██╔══╝  ██║     
   ██║  ██║███████╗╚██████╔╝██║███████║    ███████║███████╗╚██████╗
   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝    ╚══════╝╚══════╝ ╚═════╝
{C_RESET}
   {C_BOLD}Automated Website Security Auditor & Professional Reporting Agent{C_RESET}
   {C_GRAY}Designed for Authorized Penetration Testing & Defensive Security Assessments{C_RESET}
   {C_GRAY}─────────────────────────────────────────────────────────────────────────{C_RESET}
"""
    print(banner)


def progress_callback(step: str, message: str):
    symbols = {
        "INIT": f"{C_BLUE}[*]{C_RESET}",
        "FETCH": f"{C_CYAN}[~]{C_RESET}",
        "AUDIT": f"{C_MAGENTA}[⚙]{C_RESET}",
        "MODULE_DONE": f"{C_GREEN}[+]{C_RESET}",
        "MODULE_ERROR": f"{C_RED}[!]{C_RESET}",
        "COMPLETE": f"{C_GREEN}[✔]{C_RESET}",
    }
    prefix = symbols.get(step, f"{C_BLUE}[*]{C_RESET}")
    print(f"  {prefix} {message}")


def main():
    parser = argparse.ArgumentParser(
        description="AegisSec: End-to-End Website Security Auditor & Report Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", nargs="?", help="Target domain or URL (e.g. example.com or https://example.com)")
    parser.add_argument("-o", "--output-dir", default="./reports", help="Directory where reports are saved (default: ./reports)")
    parser.add_argument("-f", "--format", choices=["all", "html", "md", "json", "pdf"], default="all", help="Report output format (default: all)")
    parser.add_argument("-t", "--timeout", type=float, default=8.0, help="HTTP/TLS request timeout in seconds (default: 8.0)")
    parser.add_argument("--view", action="store_true", help="Automatically open generated HTML report in default browser")
    parser.add_argument("--serve", action="store_true", help="Launch the local interactive Web Dashboard & Report Viewer")
    parser.add_argument("--port", type=int, default=8080, help="Web UI server port if using --serve (default: 8080)")

    args = parser.parse_args()

    print_banner()

    # If --serve is requested without a target, launch server directly
    if args.serve and not args.target:
        from server import start_dashboard
        start_dashboard(port=args.port)
        return

    if not args.target:
        parser.print_help()
        print(f"\n{C_RED}Error: Target URL or domain is required (or use --serve to open web dashboard).{C_RESET}\n")
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)

    print(f"{C_BOLD}Starting Security Audit for:{C_RESET} {C_CYAN}{args.target}{C_RESET}\n")

    try:
        auditor = SecurityAuditor(args.target, timeout=args.timeout, progress_callback=progress_callback)
        result = auditor.run()
    except Exception as e:
        print(f"\n{C_RED}{C_BOLD}[!] Audit Failed:{C_RESET} {e}")
        sys.exit(1)

    s = result.summary
    t = result.target

    # Terminal Summary Table
    grade_color = C_GREEN if s.score >= 85 else C_BLUE if s.score >= 70 else C_YELLOW if s.score >= 55 else C_RED

    print(f"\n{C_GRAY}{'=' * 72}{C_RESET}")
    print(f"{C_BOLD}                  AUDIT SUMMARY & EXECUTIVE SCORECARD{C_RESET}")
    print(f"{C_GRAY}{'=' * 72}{C_RESET}")
    print(f"  Target Domain       : {C_BOLD}{t.domain}{C_RESET}")
    print(f"  IP Addresses        : {', '.join(t.ip_addresses) or 'N/A'}")
    print(f"  Detected Server     : {t.server_banner or 'Hidden / Cloudflare'}")
    print(f"  Audit Duration      : {s.duration_seconds}s")
    print(f"  Security Score      : {grade_color}{C_BOLD}{s.score} / 100{C_RESET}")
    print(f"  Security Grade      : {grade_color}{C_BOLD}{s.grade} ({s.grade_label}){C_RESET}")
    print(f"{C_GRAY}{'─' * 72}{C_RESET}")
    print(f"  {C_RED}Critical Vulnerabilities :{C_RESET} {C_BOLD}{s.critical_count}{C_RESET}")
    print(f"  {C_YELLOW}High Severity Issues     :{C_RESET} {C_BOLD}{s.high_count}{C_RESET}")
    print(f"  {C_YELLOW}Medium Severity Issues   :{C_RESET} {C_BOLD}{s.medium_count}{C_RESET}")
    print(f"  {C_BLUE}Low / Informational      :{C_RESET} {C_BOLD}{s.low_count + s.info_count}{C_RESET}")
    print(f"  {C_BOLD}Total Findings Detected  :{C_RESET} {C_BOLD}{s.total_findings}{C_RESET}")
    print(f"{C_GRAY}{'=' * 72}{C_RESET}\n")

    # Generate Reports
    timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    sanitized_domain = t.domain.replace(".", "_").replace(":", "_")
    base_filename = os.path.join(args.output_dir, f"audit_{sanitized_domain}_{timestamp_slug}")

    created_reports = []

    if args.format in ("all", "html", "pdf"):
        html_path = f"{base_filename}.html"
        HTMLReporter(result).save(html_path)
        if args.format != "pdf":
            created_reports.append(("HTML Dashboard (Interactive)", html_path))

        # Generate PDF if requested or part of 'all'
        if args.format in ("all", "pdf"):
            pdf_path = f"{base_filename}.pdf"
            if PDFReporter(html_path).generate(pdf_path):
                created_reports.append(("Executive PDF Document", pdf_path))

    if args.format in ("all", "md"):
        md_path = f"{base_filename}.md"
        MarkdownReporter(result).save(md_path)
        created_reports.append(("Markdown Report", md_path))

    if args.format in ("all", "json"):
        json_path = f"{base_filename}.json"
        JSONReporter(result).save(json_path)
        created_reports.append(("JSON Machine-Readable", json_path))

    print(f"{C_GREEN}{C_BOLD}Reports Successfully Generated:{C_RESET}")
    for label, path in created_reports:
        print(f"  • {label:26}: {C_CYAN}{path}{C_RESET}")
    print()

    # Handle automatic viewing or server launch
    if args.view and created_reports:
        html_file = next((p for l, p in created_reports if p.endswith(".html")), None)
        if html_file:
            print(f"{C_BLUE}[*] Opening HTML Report in browser...{C_RESET}")
            if sys.platform == "darwin":
                subprocess.run(["open", html_file])
            elif sys.platform.startswith("linux"):
                subprocess.run(["xdg-open", html_file])

    if args.serve:
        from server import start_dashboard
        start_dashboard(port=args.port)


if __name__ == "__main__":
    main()
