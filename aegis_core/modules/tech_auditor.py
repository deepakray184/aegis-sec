"""
Wappalyzer-like Technology Stack, CMS, Framework, and Software Library Profiler.
Analyzes HTTP headers, HTML DOM, meta tags, script/link sources, and cookies to fingerprint software.
"""

from typing import List, Dict, Tuple, Any, Optional
import re
from urllib.parse import urlparse
from aegis_core.models import Finding, Severity, Category


# Definition of technology fingerprinting signatures
TECH_SIGNATURES: List[Dict[str, Any]] = [
    # --- Content Management Systems (CMS) ---
    {
        "name": "WordPress",
        "category": "CMS",
        "icon": "📝",
        "cpe": "cpe:/a:wordpress:wordpress",
        "meta": {"generator": r"WordPress(?: ([0-9.]+))?"},
        "html": [r"/wp-content/", r"/wp-includes/", r"wp-json"],
        "headers": {"x-pingback": r".*"},
        "cookies": [r"wordpress_", r"wp-settings-"],
    },
    {
        "name": "Drupal",
        "category": "CMS",
        "icon": "💧",
        "cpe": "cpe:/a:drupal:drupal",
        "meta": {"generator": r"Drupal(?: ([0-9.]+))?"},
        "headers": {"x-generator": r"Drupal(?: ([0-9.]+))?", "x-drupal-cache": r".*"},
        "html": [r"drupal\.js", r"/sites/default/files/", r"/sites/all/themes/"],
    },
    {
        "name": "Joomla!",
        "category": "CMS",
        "icon": "🇯",
        "cpe": "cpe:/a:joomla:joomla",
        "meta": {"generator": r"Joomla!(?: ([0-9.]+))?"},
        "html": [r"/media/jui/js/", r"/components/com_"],
    },
    {
        "name": "Shopify",
        "category": "E-Commerce",
        "icon": "🛍️",
        "headers": {"x-shopify-stage": r".*", "x-shopid": r".*"},
        "html": [r"cdn\.shopify\.com", r"Shopify\.theme"],
    },
    {
        "name": "Ghost",
        "category": "CMS",
        "icon": "👻",
        "meta": {"generator": r"Ghost(?: ([0-9.]+))?"},
        "headers": {"x-ghost-cache-status": r".*"},
        "html": [r"ghost-search", r"/assets/built/"],
    },
    {
        "name": "Magento",
        "category": "E-Commerce",
        "icon": "📦",
        "html": [r"Mage\.Cookies", r"/skin/frontend/", r"/static/frontend/"],
        "cookies": [r"frontend", r"adminhtml"],
    },
    {
        "name": "Webflow",
        "category": "CMS / Site Builder",
        "icon": "🌊",
        "meta": {"generator": r"Webflow"},
        "html": [r"d2jypt75y119px\.cloudfront\.net", r"webflow\.js"],
    },
    {
        "name": "Squarespace",
        "category": "CMS / Site Builder",
        "icon": "⬛",
        "headers": {"x-served-by": r"Squarespace"},
        "html": [r"static\.squarespace\.com", r"squarespace-headers"],
    },
    {
        "name": "Wix",
        "category": "CMS / Site Builder",
        "icon": "🌐",
        "headers": {"x-wix-request-id": r".*"},
        "html": [r"static\.wixstatic\.com"],
    },

    # --- JavaScript Frameworks & Libraries ---
    {
        "name": "React",
        "category": "JavaScript Framework",
        "icon": "⚛️",
        "scripts": [r"react(?:\.production|\.development)?(?:\.min)?\.js", r"react-dom"],
        "html": [r"_reactFiber", r"data-reactroot", r'<div[^>]+id=["\']root["\']'],
    },
    {
        "name": "Next.js",
        "category": "Web Framework (React)",
        "icon": "▲",
        "headers": {"x-powered-by": r"Next\.js(?: ([0-9.]+))?"},
        "html": [r"/_next/static/", r'<div[^>]+id=["\']__next["\']', r"__NEXT_DATA__"],
    },
    {
        "name": "Vue.js",
        "category": "JavaScript Framework",
        "icon": "💚",
        "scripts": [r"vue(?:\.runtime|\.global)?(?:\.min)?\.js"],
        "html": [r"data-v-[a-f0-9]+", r'<div[^>]+id=["\']app["\']'],
    },
    {
        "name": "Nuxt.js",
        "category": "Web Framework (Vue)",
        "icon": "⛰️",
        "headers": {"x-powered-by": r"Nuxt"},
        "html": [r"/_nuxt/", r'<div[^>]+id=["\']__nuxt["\']'],
    },
    {
        "name": "Angular",
        "category": "JavaScript Framework",
        "icon": "🅰️",
        "scripts": [r"angular(?:\.min)?\.js"],
        "html": [r'ng-version=["\']([0-9.]+)["\']', r"<app-root>", r"ng-app="],
    },
    {
        "name": "jQuery",
        "category": "JavaScript Library",
        "icon": "💲",
        "cpe": "cpe:/a:jquery:jquery",
        "scripts": [
            r"jquery[.-]([0-9.]+)(?:\.slim)?(?:\.min)?\.js",
            r"code\.jquery\.com/jquery-([0-9.]+)",
            r"/jquery(?:\.min)?\.js",
        ],
        "html": [r"jQuery v([0-9.]+)"],
    },
    {
        "name": "HTMX",
        "category": "JavaScript Library",
        "icon": "⚡",
        "scripts": [r"htmx(?:\.org)?@([0-9.]+)", r"htmx(?:\.min)?\.js"],
        "html": [r"hx-get=", r"hx-post=", r"hx-target="],
    },
    {
        "name": "Alpine.js",
        "category": "JavaScript Framework",
        "icon": "🏔️",
        "scripts": [r"alpine(?:js)?[.-]([0-9.]+)", r"alpine(?:\.min)?\.js"],
        "html": [r"x-data=", r"x-bind=", r"x-show="],
    },
    {
        "name": "Svelte",
        "category": "JavaScript Framework",
        "icon": "🔥",
        "html": [r"svelte-[a-z0-9]+", r"__svelte"],
    },

    # --- CSS & UI Frameworks ---
    {
        "name": "Tailwind CSS",
        "category": "CSS Framework",
        "icon": "🎨",
        "scripts": [r"cdn\.tailwindcss\.com"],
        "html": [r"tailwindcss", r'class=["\'][^"\']*\b(?:flex|grid|items-center|justify-between|bg-slate-|text-sm)\b'],
    },
    {
        "name": "Bootstrap",
        "category": "CSS Framework",
        "icon": "🅱️",
        "scripts": [r"bootstrap[.-]([0-9.]+)(?:\.bundle)?(?:\.min)?\.(?:js|css)"],
        "html": [r'class=["\'][^"\']*\b(?:col-md-|col-lg-|navbar-expand|btn-primary|btn-secondary)\b'],
    },
    {
        "name": "Font Awesome",
        "category": "Icon Font",
        "icon": "🚩",
        "scripts": [r"font-awesome[.-]([0-9.]+)?", r"fontawesome"],
        "html": [r'class=["\'][^"\']*\bfa[srldb]? fa-[a-z0-9-]+'],
    },

    # --- Web Servers & Proxies ---
    {
        "name": "Nginx",
        "category": "Web Server",
        "icon": "🟢",
        "cpe": "cpe:/a:f5:nginx",
        "headers": {"server": r"nginx(?:/([0-9.]+))?"},
    },
    {
        "name": "Apache HTTP Server",
        "category": "Web Server",
        "icon": "🪶",
        "cpe": "cpe:/a:apache:http_server",
        "headers": {"server": r"Apache(?:/([0-9.]+))?"},
    },
    {
        "name": "Microsoft IIS",
        "category": "Web Server",
        "icon": "🪟",
        "cpe": "cpe:/a:microsoft:internet_information_services",
        "headers": {"server": r"Microsoft-IIS(?:/([0-9.]+))?"},
    },
    {
        "name": "Cloudflare",
        "category": "CDN / Reverse Proxy",
        "icon": "☁️",
        "headers": {"server": r"cloudflare", "cf-ray": r".*", "cf-cache-status": r".*"},
    },
    {
        "name": "LiteSpeed",
        "category": "Web Server",
        "icon": "⚡",
        "headers": {"server": r"LiteSpeed"},
    },
    {
        "name": "Caddy",
        "category": "Web Server",
        "icon": "🔒",
        "headers": {"server": r"Caddy"},
    },
    {
        "name": "Amazon CloudFront",
        "category": "CDN",
        "icon": "📦",
        "headers": {"via": r".*CloudFront", "x-amz-cf-id": r".*"},
    },
    {
        "name": "Fastly",
        "category": "CDN",
        "icon": "🚀",
        "headers": {"x-served-by": r"cache-.*", "via": r".*varnish.*"},
    },

    # --- Programming Languages & Frameworks ---
    {
        "name": "PHP",
        "category": "Programming Language",
        "icon": "🐘",
        "cpe": "cpe:/a:php:php",
        "headers": {"x-powered-by": r"PHP(?:/([0-9.]+))?"},
        "cookies": [r"PHPSESSID"],
    },
    {
        "name": "ASP.NET",
        "category": "Web Framework",
        "icon": "🔷",
        "headers": {
            "x-powered-by": r"ASP\.NET",
            "x-aspnet-version": r"([0-9.]+)",
            "x-aspnetmvc-version": r"([0-9.]+)",
        },
        "cookies": [r"ASP\.NET_SessionId", r"\.AspNetCore\."],
    },
    {
        "name": "Express.js",
        "category": "Web Framework (Node.js)",
        "icon": "🚂",
        "headers": {"x-powered-by": r"Express"},
        "cookies": [r"connect\.sid"],
    },
    {
        "name": "Django",
        "category": "Web Framework (Python)",
        "icon": "🎸",
        "cookies": [r"csrftoken", r"django_language"],
    },
    {
        "name": "Laravel",
        "category": "Web Framework (PHP)",
        "icon": "🔴",
        "cookies": [r"laravel_session"],
        "headers": {"set-cookie": r"laravel_session"},
    },
    {
        "name": "Apache Tomcat / Java",
        "category": "Application Server",
        "icon": "☕",
        "headers": {"server": r"Apache-Coyote(?:/([0-9.]+))?"},
        "cookies": [r"JSESSIONID"],
    },
    {
        "name": "Ruby on Rails",
        "category": "Web Framework (Ruby)",
        "icon": "💎",
        "headers": {"x-powered-by": r"Phusion Passenger"},
        "cookies": [r"_rails_session"],
    },

    # --- Analytics & Monitoring ---
    {
        "name": "Google Analytics",
        "category": "Analytics",
        "icon": "📈",
        "html": [r"gtag\(", r"ga\('create'", r"google-analytics\.com/analytics\.js"],
        "scripts": [r"googletagmanager\.com/gtag/js"],
    },
    {
        "name": "Google Tag Manager",
        "category": "Tag Management",
        "icon": "🏷️",
        "scripts": [r"googletagmanager\.com/gtm\.js"],
        "html": [r"googletagmanager\.com/ns\.html"],
    },
    {
        "name": "Cloudflare Web Analytics",
        "category": "Analytics",
        "icon": "📊",
        "scripts": [r"static\.cloudflareinsights\.com/beacon(?:\.min)?\.js"],
    },
    {
        "name": "Sentry",
        "category": "Error Tracking",
        "icon": "🛡️",
        "scripts": [r"browser\.sentry-cdn\.com"],
    },
]


class TechAuditor:
    def __init__(self, headers: Dict[str, str], html_body: str = "", cookies_raw: str = ""):
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.html_body = html_body or ""
        self.cookies_raw = cookies_raw or self.headers.get("set-cookie", "")

    def audit(self) -> Tuple[List[Finding], Dict[str, Any]]:
        detected_techs: List[Dict[str, Any]] = []
        findings: List[Finding] = []

        # Parse scripts and meta tags from HTML
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', self.html_body, re.IGNORECASE)
        meta_dict = {}
        for m in re.finditer(r'<meta\s+([^>]+)>', self.html_body, re.IGNORECASE):
            attrs = m.group(1)
            name_m = re.search(r'name=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
            content_m = re.search(r'content=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
            if name_m and content_m:
                meta_dict[name_m.group(1).lower()] = content_m.group(1)

        # Evaluate each technology signature
        for sig in TECH_SIGNATURES:
            name = sig["name"]
            matched = False
            version: Optional[str] = None
            evidence_matched: List[str] = []

            # 1. Check HTTP Headers
            if "headers" in sig:
                for h_key, h_pattern in sig["headers"].items():
                    if h_key in self.headers:
                        val = self.headers[h_key]
                        m = re.search(h_pattern, val, re.IGNORECASE)
                        if m:
                            matched = True
                            evidence_matched.append(f"Header '{h_key}: {val}'")
                            if m.groups() and m.group(1):
                                version = m.group(1)

            # 2. Check Meta Tags
            if "meta" in sig and (not matched or not version):
                for m_name, m_pattern in sig["meta"].items():
                    if m_name in meta_dict:
                        val = meta_dict[m_name]
                        m = re.search(m_pattern, val, re.IGNORECASE)
                        if m:
                            matched = True
                            evidence_matched.append(f"Meta tag '{m_name}=\"{val}\"'")
                            if m.groups() and m.group(1):
                                version = m.group(1)

            # 3. Check Scripts
            if "scripts" in sig and (not matched or not version):
                for s_src in scripts:
                    for s_pattern in sig["scripts"]:
                        m = re.search(s_pattern, s_src, re.IGNORECASE)
                        if m:
                            matched = True
                            evidence_matched.append(f"Script: {s_src}")
                            if m.groups() and m.group(1) and not version:
                                version = m.group(1)
                            break

            # 4. Check HTML Body patterns
            if "html" in sig and (not matched or not version):
                for h_pattern in sig["html"]:
                    m = re.search(h_pattern, self.html_body, re.IGNORECASE)
                    if m:
                        matched = True
                        evidence_matched.append(f"HTML Pattern: {h_pattern}")
                        if m.groups() and m.group(1) and not version:
                            version = m.group(1)
                        break

            # 5. Check Cookies
            if "cookies" in sig and not matched:
                for c_pattern in sig["cookies"]:
                    if re.search(c_pattern, self.cookies_raw, re.IGNORECASE):
                        matched = True
                        evidence_matched.append(f"Cookie matched pattern: {c_pattern}")
                        break

            if matched:
                tech_entry = {
                    "name": name,
                    "category": sig.get("category", "Other"),
                    "version": version,
                    "icon": sig.get("icon", "💻"),
                    "cpe": sig.get("cpe"),
                    "evidence": evidence_matched[0] if evidence_matched else "Signature match",
                }
                detected_techs.append(tech_entry)

        # Post-analysis: Check for outdated / vulnerable components
        vuln_findings = self._check_software_vulnerabilities(detected_techs)
        findings.extend(vuln_findings)

        # Informational tech stack summary finding
        if detected_techs:
            tech_summary_list = [f"{t['name']}" + (f" (v{t['version']})" if t['version'] else "") for t in detected_techs]
            findings.append(
                Finding(
                    id="TECH-STACK-DISCOVERED",
                    title=f"Technology Stack Fingerprinted ({len(detected_techs)} Components)",
                    severity=Severity.INFO,
                    category=Category.TECH_STACK,
                    description=f"Wappalyzer-style software fingerprinting identified {len(detected_techs)} technologies, frameworks, and libraries: {', '.join(tech_summary_list)}.",
                    impact="Reveals client-side and server-side software stack to auditors and potential adversaries for threat surface profiling.",
                    remediation="Ensure all identified frameworks and libraries are updated to supported, vendor-patched releases. Hide server version numbers where feasible.",
                    evidence="Identified Components:\n" + "\n".join([f"• {t['category']}: {t['name']}" + (f" v{t['version']}" if t['version'] else "") for t in detected_techs]),
                    owasp_category="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-200",
                    cvss_score=1.0,
                )
            )

        details = {
            "technologies": detected_techs,
            "count": len(detected_techs),
        }

        return findings, details

    def _check_software_vulnerabilities(self, techs: List[Dict[str, Any]]) -> List[Finding]:
        """Correlates detected versions with known EOL/Vulnerable software patterns."""
        findings: List[Finding] = []

        for t in techs:
            name = t["name"]
            ver = t.get("version")
            if not ver:
                continue

            # Check PHP version
            if name == "PHP":
                # EOL PHP check (PHP 5.x and 7.x are completely EOL)
                if ver.startswith("5.") or ver.startswith("7."):
                    findings.append(
                        Finding(
                            id=f"TECH-EOL-PHP-{ver.replace('.', '_')}",
                            title=f"End-Of-Life (EOL) Software: PHP {ver}",
                            severity=Severity.HIGH,
                            category=Category.TECH_STACK,
                            description=f"The server is running PHP version {ver}, which is officially End-Of-Life and no longer receives security patches from the PHP Foundation.",
                            impact="Known unpatched vulnerabilities in obsolete PHP releases can be exploited for remote code execution (RCE) or denial of service.",
                            remediation="Upgrade PHP to an actively supported release (PHP 8.2 or 8.3+).",
                            evidence=f"X-Powered-By: PHP/{ver}",
                            owasp_category="A06:2021-Vulnerable and Outdated Components",
                            cwe_id="CWE-1104",
                            cvss_score=7.8,
                            references=["https://www.php.net/supported-versions.php"],
                        )
                    )

            # Check jQuery version
            if name == "jQuery":
                # jQuery < 3.5.0 has known XSS CVEs (CVE-2020-11022, CVE-2020-11023, CVE-2015-9251)
                try:
                    parts = [int(p) for p in re.findall(r"\d+", ver)[:3]]
                    if parts and (parts[0] < 3 or (parts[0] == 3 and len(parts) > 1 and parts[1] < 5)):
                        findings.append(
                            Finding(
                                id=f"TECH-VULN-JQUERY-{ver.replace('.', '_')}",
                                title=f"Vulnerable JavaScript Library: jQuery {ver} (Known XSS)",
                                severity=Severity.MEDIUM,
                                category=Category.TECH_STACK,
                                description=f"The website includes jQuery version {ver}. jQuery versions prior to 3.5.0 contain known Cross-Site Scripting (XSS) vulnerabilities (CVE-2020-11022, CVE-2020-11023).",
                                impact="Attackers can pass untrusted HTML to jQuery manipulation methods (e.g. $.htmlPrefilter, $.html()), triggering script execution in the user's browser.",
                                remediation="Upgrade jQuery to version 3.7.1 or later.",
                                evidence=f"Detected jQuery version: {ver}",
                                owasp_category="A06:2021-Vulnerable and Outdated Components",
                                cwe_id="CWE-79",
                                cvss_score=6.1,
                                references=["https://nvd.nist.gov/vuln/detail/CVE-2020-11022"],
                            )
                        )
                except Exception:
                    pass

            # Check Apache version
            if name == "Apache HTTP Server":
                # Apache 2.4.49 and 2.4.50 had severe CVE-2021-41773 / CVE-2021-42013 (RCE / Path Traversal)
                if ver in ("2.4.49", "2.4.50"):
                    findings.append(
                        Finding(
                            id="TECH-VULN-APACHE-RCE",
                            title=f"Critical Known Vulnerability: Apache {ver} (CVE-2021-41773 Path Traversal / RCE)",
                            severity=Severity.CRITICAL,
                            category=Category.TECH_STACK,
                            description=f"Server banner identifies Apache {ver}, which suffers from a critical path traversal vulnerability actively exploited in the wild.",
                            impact="Allows remote unauthenticated attackers to read arbitrary files and achieve remote code execution.",
                            remediation="Immediately upgrade Apache to version 2.4.58 or higher.",
                            evidence=f"Server: Apache/{ver}",
                            owasp_category="A06:2021-Vulnerable and Outdated Components",
                            cwe_id="CWE-22",
                            cvss_score=9.8,
                            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
                        )
                    )

            # Check WordPress version leak
            if name == "WordPress":
                findings.append(
                    Finding(
                        id="TECH-WP-VERSION-LEAK",
                        title=f"WordPress Version Disclosed: {ver}",
                        severity=Severity.LOW,
                        category=Category.EXPOSURE,
                        description=f"The website explicitly leaks its WordPress version ({ver}) via HTML meta generator tags.",
                        impact="Assists attackers in targeting version-specific WordPress core exploits.",
                        remediation="Remove the generator meta tag in WordPress by adding 'remove_action(\"wp_head\", \"wp_generator\");' to your theme's functions.php.",
                        evidence=f'<meta name="generator" content="WordPress {ver}">',
                        owasp_category="A05:2021-Security Misconfiguration",
                        cwe_id="CWE-200",
                        cvss_score=3.5,
                    )
                )

        return findings
