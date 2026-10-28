// AegisSec Web Application - Client-Side Engine & Hybrid API Controller

let currentEngineMode = localStorage.getItem('aegis_engine_mode') || 'browser';
let currentBackendUrl = localStorage.getItem('aegis_backend_url') || (
    window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
        ? window.location.origin
        : 'http://localhost:8080'
);

let lastAuditData = null;
let currentFindings = [];
let activeSeverityFilter = 'all';

document.addEventListener('DOMContentLoaded', () => {
    initEngineSettings();
    updateEngineBadge();
});

// Engine configuration UI
function initEngineSettings() {
    const radioBrowser = document.getElementById('radioModeBrowser');
    const radioBackend = document.getElementById('radioModeBackend');
    const backendGroup = document.getElementById('backendConfigGroup');
    const backendInput = document.getElementById('backendUrlInput');

    if (backendInput) backendInput.value = currentBackendUrl;

    if (currentEngineMode === 'backend') {
        if (radioBackend) radioBackend.checked = true;
        if (backendGroup) backendGroup.classList.remove('hidden');
    } else {
        if (radioBrowser) radioBrowser.checked = true;
        if (backendGroup) backendGroup.classList.add('hidden');
    }
}

function onEngineModeChange() {
    const radioBackend = document.getElementById('radioModeBackend');
    const backendGroup = document.getElementById('backendConfigGroup');
    if (radioBackend && radioBackend.checked) {
        if (backendGroup) backendGroup.classList.remove('hidden');
    } else {
        if (backendGroup) backendGroup.classList.add('hidden');
    }
}

function saveEngineSettings() {
    const radioBackend = document.getElementById('radioModeBackend');
    const backendInput = document.getElementById('backendUrlInput');

    if (radioBackend && radioBackend.checked) {
        currentEngineMode = 'backend';
        if (backendInput && backendInput.value.trim()) {
            currentBackendUrl = backendInput.value.trim().replace(/\/$/, '');
            localStorage.setItem('aegis_backend_url', currentBackendUrl);
        }
    } else {
        currentEngineMode = 'browser';
    }

    localStorage.setItem('aegis_engine_mode', currentEngineMode);
    toggleConfigModal(false);
    updateEngineBadge();
}

function toggleConfigModal(show) {
    const modal = document.getElementById('configModal');
    if (modal) {
        modal.style.display = show ? 'flex' : 'none';
        if (show) initEngineSettings();
    }
}

function updateEngineBadge() {
    const badge = document.getElementById('engineStatusBadge');
    const text = document.getElementById('badgeEngineText');
    if (!badge || !text) return;

    if (currentEngineMode === 'browser') {
        badge.className = 'px-3 py-1 text-xs font-semibold rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:border-emerald-400 transition flex items-center gap-2 cursor-pointer shadow-sm';
        text.innerText = '⚡ Browser Cloud Engine';
    } else {
        badge.className = 'px-3 py-1 text-xs font-semibold rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 hover:border-cyan-400 transition flex items-center gap-2 cursor-pointer shadow-sm';
        text.innerText = '🐍 Python Backend API';
        checkBackendHealth();
    }
}

async function checkBackendHealth() {
    const text = document.getElementById('badgeEngineText');
    const badge = document.getElementById('engineStatusBadge');
    if (!text || !badge || currentEngineMode !== 'backend') return;

    try {
        const resp = await fetch(`${currentBackendUrl}/health`, { method: 'GET', signal: AbortSignal.timeout(3000) });
        if (resp.ok) {
            badge.className = 'px-3 py-1 text-xs font-semibold rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:border-emerald-400 transition flex items-center gap-2 cursor-pointer';
            text.innerText = '🐍 Backend Online';
        } else {
            throw new Error('Not OK');
        }
    } catch (e) {
        badge.className = 'px-3 py-1 text-xs font-semibold rounded-full bg-red-500/10 text-red-400 border border-red-500/20 hover:border-red-400 transition flex items-center gap-2 cursor-pointer';
        text.innerText = '⚠️ Backend Offline';
    }
}

function setTarget(url) {
    const input = document.getElementById('targetInput');
    if (input) {
        input.value = url;
    }
}

// Main Audit Dispatcher
async function runAudit(e) {
    e.preventDefault();
    const targetInput = document.getElementById('targetInput');
    const target = targetInput.value.trim();
    if (!target) return;

    const scanBtn = document.getElementById('scanBtn');
    const statusBox = document.getElementById('statusBox');
    const statusText = document.getElementById('statusText');
    const resultsContainer = document.getElementById('resultsContainer');

    scanBtn.disabled = true;
    statusBox.classList.remove('hidden');
    resultsContainer.classList.add('hidden');

    if (currentEngineMode === 'backend') {
        try {
            await runBackendAudit(target, statusText);
        } catch (err) {
            console.warn("Backend failed, falling back to Browser Cloud Engine:", err);
            statusText.innerHTML = `<span class="text-amber-400 font-semibold">Backend offline (${err.message}).</span> Running Browser Cloud Engine...`;
            await new Promise(r => setTimeout(r, 600));
            await runBrowserEngineAudit(target, statusText);
        }
    } else {
        await runBrowserEngineAudit(target, statusText);
    }

    scanBtn.disabled = false;
    statusBox.classList.add('hidden');
}

// Backend API Mode
async function runBackendAudit(target, statusText) {
    const steps = [
        "Connecting to Python AegisSec Backend...",
        "Querying raw TCP socket TLS certificates & ciphers...",
        "Auditing HTTP headers, cookies & CORS policies...",
        "Checking DNS SPF/DMARC & Shodan intelligence...",
        "Compiling executive audit report..."
    ];
    let idx = 0;
    const interval = setInterval(() => {
        if (idx < steps.length) {
            statusText.innerText = steps[idx++];
        }
    }, 1000);

    try {
        const response = await fetch(`${currentBackendUrl}/api/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: target })
        });
        clearInterval(interval);

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.error || `HTTP ${response.status}`);
        }

        const data = await response.json();
        lastAuditData = data;
        renderResults(data, 'Python Backend Engine');
    } catch (err) {
        clearInterval(interval);
        throw err;
    }
}

// ==========================================
// Browser Cloud Engine (100% Client-Side)
// ==========================================

async function queryDoH(name, type) {
    try {
        const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`;
        const res = await fetch(url, { headers: { 'Accept': 'application/dns-json' }, signal: AbortSignal.timeout(6000) });
        if (res.ok) {
            const data = await res.json();
            if (data && data.Status === 0) return data;
        }
    } catch (e) {
        // Fallback to Google DoH
    }

    try {
        const url2 = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`;
        const res2 = await fetch(url2, { signal: AbortSignal.timeout(6000) });
        if (res2.ok) return await res2.json();
    } catch (e2) {}

    return { Status: 2, Answer: [] };
}

function parseCpe(cpeStr) {
    const parts = cpeStr.split(':');
    if (parts.length < 4) return null;
    const type = parts[1].replace(/^\//, '');
    const vendor = parts[2];
    const product = parts[3];
    const version = (parts.length > 4 && parts[4] !== '-' && parts[4] !== '*') ? parts[4] : '';

    const nameMap = {
        'tomcat': 'Apache Tomcat',
        'http_server': 'Apache HTTP Server',
        'nginx': 'Nginx',
        'jre': 'Java / Oracle JRE',
        'jdk': 'Java / Oracle JDK',
        'cloudflare': 'Cloudflare CDN',
        'php': 'PHP Runtime',
        'wordpress': 'WordPress CMS',
        'openssh': 'OpenSSH',
        'iis': 'Microsoft IIS',
        'web_server': 'Google Web Server',
        'varnish': 'Varnish Cache',
        'lighttpd': 'Lighttpd',
        'caddy': 'Caddy Server'
    };

    const iconMap = {
        'tomcat': '🐱',
        'http_server': '🪶',
        'nginx': '🟢',
        'jre': '☕',
        'jdk': '☕',
        'cloudflare': '☁️',
        'php': '🐘',
        'wordpress': '📝',
        'openssh': '🔑',
        'iis': '🪟',
        'web_server': '🌐'
    };

    const catMap = {
        'tomcat': 'Web Server / Servlet Container',
        'http_server': 'Web Server',
        'nginx': 'Web Server / Reverse Proxy',
        'jre': 'Runtime Environment',
        'jdk': 'Runtime Environment',
        'cloudflare': 'CDN & Reverse Proxy',
        'php': 'Programming Language / Runtime',
        'wordpress': 'Content Management System',
        'openssh': 'Remote Administration',
        'iis': 'Web Server',
        'web_server': 'Web Server'
    };

    const formattedName = nameMap[product.toLowerCase()] || `${vendor} ${product}`.replace(/_/g, ' ');
    const icon = iconMap[product.toLowerCase()] || (type === 'a' ? '💻' : (type === 'o' ? '🖥️' : '📦'));
    const category = catMap[product.toLowerCase()] || (type === 'a' ? 'Software' : (type === 'o' ? 'Operating System' : 'Infrastructure'));

    return {
        name: formattedName,
        version: version,
        category: category,
        icon: icon,
        cpe: cpeStr
    };
}

async function runBrowserEngineAudit(rawTarget, statusText) {
    statusText.innerText = "Parsing target domain & normalizing URL...";
    let clean = rawTarget.trim();
    let hasExplicitHttp = clean.startsWith('http://');
    if (!clean.startsWith('http://') && !clean.startsWith('https://')) {
        clean = 'https://' + clean;
    }
    let parsed;
    try {
        parsed = new URL(clean);
    } catch (e) {
        parsed = new URL('https://' + clean);
    }
    const domain = parsed.hostname;
    const url = clean;

    const parts = domain.split('.');
    const rootDomain = parts.length > 2 ? parts.slice(-2).join('.') : domain;

    const startTime = Date.now();
    const findings = [];
    let findingIdx = 1;

    function addFinding(sev, title, desc, impact, rem, cat, cwe, cvss, owasp, evidence) {
        findings.push({
            id: `AEGIS-${String(findingIdx++).padStart(3, '0')}`,
            severity: sev,
            title: title,
            description: desc,
            impact: impact,
            remediation: rem,
            category: cat,
            cwe_id: cwe,
            cvss_score: cvss,
            owasp_category: owasp,
            evidence: evidence || ''
        });
    }

    // Step 1: DNS Resolution via DoH
    statusText.innerText = `Resolving DNS records for ${domain} via Cloudflare DoH...`;
    const [dohA, dohAAAA, dohTXT, dohDmarc, dohCAA, dohDS] = await Promise.all([
        queryDoH(domain, 'A'),
        queryDoH(domain, 'AAAA'),
        queryDoH(domain, 'TXT'),
        queryDoH(`_dmarc.${domain}`, 'TXT'),
        queryDoH(domain, 'CAA'),
        queryDoH(domain, 'DS')
    ]);

    const ipList = [];
    if (dohA.Answer) {
        dohA.Answer.filter(a => a.type === 1).forEach(a => ipList.push(a.data));
    }
    if (dohAAAA.Answer) {
        dohAAAA.Answer.filter(a => a.type === 28).forEach(a => ipList.push(a.data));
    }

    const primaryIp = ipList[0] || null;

    // Step 2: Shodan & Geo Intelligence
    statusText.innerText = "Querying Shodan InternetDB OSINT & IP geolocation...";
    let shodanData = { ports: [], cpes: [], tags: [], vulns: [], hostnames: [] };
    let geoData = {};

    if (primaryIp) {
        const [shodanRes, geoRes] = await Promise.allSettled([
            fetch(`https://internetdb.shodan.io/${primaryIp}`, { signal: AbortSignal.timeout(6000) }).then(r => r.json()),
            fetch(`https://ipwho.is/${primaryIp}`, { signal: AbortSignal.timeout(6000) }).then(r => r.json())
        ]);
        if (shodanRes.status === 'fulfilled' && shodanRes.value && !shodanRes.value.detail) {
            shodanData = shodanRes.value;
        }
        if (geoRes.status === 'fulfilled' && geoRes.value && geoRes.value.success) {
            geoData = geoRes.value;
        }
    }

    // Step 3: DNS Security Audits
    statusText.innerText = "Analyzing SPF, DMARC, CAA, and DNSSEC security records...";
    let spfRecord = null;
    if (dohTXT.Answer) {
        for (const ans of dohTXT.Answer) {
            const txt = (ans.data || '').replace(/^"|"$/g, '').trim();
            if (txt.startsWith('v=spf1')) {
                spfRecord = txt;
                break;
            }
        }
    }

    if (!spfRecord) {
        addFinding(
            'HIGH',
            'Missing SPF (Sender Policy Framework) Record',
            `Domain ${domain} does not publish an SPF record in DNS. Attackers can forge emails appearing from this domain.`,
            'High risk of spoofed email phishing campaigns, BEC attacks, and brand reputation damage.',
            'Publish a valid SPF TXT record in your DNS zone (e.g. "v=spf1 include:_spf.google.com ~all").',
            'DNS Security',
            'CWE-358',
            7.5,
            'A05:2021 - Security Misconfiguration',
            `Checked TXT records for ${domain}`
        );
    } else {
        if (spfRecord.includes('+all')) {
            addFinding(
                'HIGH',
                'Permissive SPF Policy (+all)',
                `The SPF record "${spfRecord}" specifies "+all", allowing ANY server worldwide to send email as ${domain}.`,
                'Completely negates SPF protections against domain impersonation.',
                'Replace "+all" with softfail "~all" or strict hardfail "-all".',
                'DNS Security',
                'CWE-358',
                7.2,
                'A05:2021 - Security Misconfiguration',
                `SPF Record: ${spfRecord}`
            );
        } else if (spfRecord.includes('?all')) {
            addFinding(
                'MEDIUM',
                'Weak SPF Neutral Policy (?all)',
                `The SPF record "${spfRecord}" specifies neutral policy (?all), meaning unauthorized senders are not flagged as failures.`,
                'Mail gateways treat unauthorized emails neutrally rather than rejecting or quarantining them.',
                'Enforce softfail "~all" or strict hardfail "-all".',
                'DNS Security',
                'CWE-358',
                5.3,
                'A05:2021 - Security Misconfiguration',
                `SPF Record: ${spfRecord}`
            );
        }
    }

    // DMARC Check
    let dmarcRecord = null;
    let dmarcAnswers = dohDmarc.Answer || [];
    if (!dmarcAnswers.length && rootDomain !== domain) {
        const rootDmarc = await queryDoH(`_dmarc.${rootDomain}`, 'TXT');
        dmarcAnswers = rootDmarc.Answer || [];
    }
    for (const ans of dmarcAnswers) {
        const txt = (ans.data || '').replace(/^"|"$/g, '').trim();
        if (txt.startsWith('v=DMARC1')) {
            dmarcRecord = txt;
            break;
        }
    }

    if (!dmarcRecord) {
        addFinding(
            'HIGH',
            'Missing DMARC Email Anti-Spoofing Policy',
            `Domain ${domain} lacks a DMARC policy record at _dmarc.${domain}.`,
            'Receivers cannot authenticate whether incoming mail genuinely originates from your domain, enabling spear-phishing.',
            'Publish a DMARC record at _dmarc.${domain} (e.g., "v=DMARC1; p=reject; rua=mailto:dmarc-reports@${domain}").',
            'DNS Security',
            'CWE-358',
            7.5,
            'A05:2021 - Security Misconfiguration',
            `Checked _dmarc.${domain} and _dmarc.${rootDomain}`
        );
    } else if (dmarcRecord.includes('p=none')) {
        addFinding(
            'MEDIUM',
            'Ineffective DMARC Policy (p=none Monitoring Only)',
            `The DMARC policy is set to "p=none", which provides reporting but does NOT instruct mail servers to block spoofed email.`,
            'Spoofed phishing messages impersonating this domain are still delivered to end-user inboxes.',
            'Upgrade DMARC policy to "p=quarantine" or "p=reject".',
            'DNS Security',
            'CWE-358',
            5.3,
            'A05:2021 - Security Misconfiguration',
            `DMARC Record: ${dmarcRecord}`
        );
    }

    // CAA Check
    const caaRecords = (dohCAA.Answer || []).filter(a => a.type === 257);
    if (caaRecords.length === 0) {
        addFinding(
            'LOW',
            'Missing CAA (Certificate Authority Authorization) Record',
            `No CAA DNS records found for ${domain}. Any public CA can issue SSL/TLS certificates for this domain.`,
            'Increased exposure to rogue certificate issuance if a public CA suffers a breach.',
            'Publish CAA records restricting issuance to authorized CAs (e.g. "0 issue letsencrypt.org").',
            'DNS Security',
            'CWE-295',
            3.7,
            'A05:2021 - Security Misconfiguration',
            `CAA query returned 0 records`
        );
    }

    // DNSSEC Check
    const dsRecords = (dohDS.Answer || []).filter(a => a.type === 43);
    if (dsRecords.length === 0 && !dohA.AD) {
        addFinding(
            'LOW',
            'DNSSEC (DNS Security Extensions) Not Configured',
            `Domain does not publish DNSSEC DS delegation records in the parent zone.`,
            'Vulnerable to DNS cache poisoning and man-in-the-middle query redirection.',
            'Sign your DNS zone with DNSSEC via your DNS registrar.',
            'DNS Security',
            'CWE-345',
            3.3,
            'A05:2021 - Security Misconfiguration',
            `DS records absent; Authenticated Data flag AD=${dohA.AD}`
        );
    }

    // Step 4: Shodan Ports & Vulnerabilities
    statusText.innerText = "Analyzing open ports and Shodan CVE intelligence...";
    const openPorts = shodanData.ports || [];
    const vulns = shodanData.vulns || [];

    const riskyPortRules = {
        23: { sev: 'CRITICAL', name: 'Telnet Unencrypted Remote Administration', cwe: 'CWE-319', cvss: 9.8, rem: 'Disable Telnet immediately and enforce SSH on port 22.' },
        3389: { sev: 'HIGH', name: 'Exposed Microsoft Remote Desktop (RDP)', cwe: 'CWE-284', cvss: 8.5, rem: 'Place RDP behind a VPN, bastion host, or IP whitelist.' },
        6379: { sev: 'HIGH', name: 'Exposed Redis In-Memory Database', cwe: 'CWE-306', cvss: 8.8, rem: 'Bind Redis to 127.0.0.1 and enable password authentication.' },
        27017: { sev: 'HIGH', name: 'Exposed MongoDB NoSQL Database', cwe: 'CWE-306', cvss: 8.8, rem: 'Restrict MongoDB access to trusted application servers.' },
        3306: { sev: 'HIGH', name: 'Exposed MySQL Relational Database', cwe: 'CWE-306', cvss: 8.5, rem: 'Close public access to port 3306 and use SSH tunnels.' },
        5432: { sev: 'HIGH', name: 'Exposed PostgreSQL Relational Database', cwe: 'CWE-306', cvss: 8.5, rem: 'Bind PostgreSQL to localhost or private network.' },
        9200: { sev: 'HIGH', name: 'Exposed Elasticsearch REST API', cwe: 'CWE-306', cvss: 8.5, rem: 'Enable Elastic Security authentication and isolate port 9200.' },
        21: { sev: 'MEDIUM', name: 'Unencrypted FTP Service', cwe: 'CWE-319', cvss: 6.5, rem: 'Migrate from plain FTP to SFTP (port 22) or FTPS with TLS.' },
        8080: { sev: 'LOW', name: 'Exposed Alternative HTTP Web Port (8080)', cwe: 'CWE-200', cvss: 4.3, rem: 'Verify if port 8080 exposes administrative consoles or staging APIs.' }
    };

    for (const p of openPorts) {
        if (riskyPortRules[p]) {
            const rule = riskyPortRules[p];
            addFinding(
                rule.sev,
                `Exposed Risky Service: Port ${p} (${rule.name})`,
                `Shodan InternetDB detected port ${p} open to the public internet on ${primaryIp || domain}.`,
                `Direct internet exposure increases attack surface and risk of unauthorized access or brute-force attacks.`,
                rule.rem,
                'Network Security',
                rule.cwe,
                rule.cvss,
                'A05:2021 - Security Misconfiguration',
                `Shodan open ports: ${openPorts.join(', ')}`
            );
        }
    }

    // CVEs from Shodan
    for (const cve of vulns) {
        addFinding(
            'CRITICAL',
            `Known Public Vulnerability: ${cve}`,
            `Shodan detected public vulnerability ${cve} associated with services running on ${primaryIp}.`,
            'Publicly disclosed CVEs often have active exploits available for remote attackers.',
            `Update the affected software package immediately. Reference: https://nvd.nist.gov/vuln/detail/${cve}`,
            'Vulnerability',
            'CWE-1035',
            9.8,
            'A06:2021 - Vulnerable and Outdated Components',
            `Detected by Shodan InternetDB on IP ${primaryIp}: ${cve}`
        );
    }

    // Self-signed certificate tag
    if ((shodanData.tags || []).includes('self-signed')) {
        addFinding(
            'HIGH',
            'Self-Signed SSL/TLS Certificate Flagged',
            `Shodan intelligence identified a self-signed SSL/TLS certificate deployed on ${primaryIp}.`,
            'Browsers display prominent security warnings, and traffic is vulnerable to man-in-the-middle attacks.',
            'Replace self-signed certificates with a trusted CA-signed certificate (e.g. free via Let\'s Encrypt).',
            'TLS/SSL Encryption',
            'CWE-295',
            7.4,
            'A02:2021 - Cryptographic Failures',
            `Shodan tags: ${shodanData.tags.join(', ')}`
        );
    }

    // Plaintext HTTP check
    if (hasExplicitHttp && !openPorts.includes(443)) {
        addFinding(
            'HIGH',
            'Unencrypted HTTP Protocol (Missing HTTPS)',
            `Target was specified over unencrypted HTTP (http://${domain}) and port 443 was not detected open.`,
            'All transmitted passwords, cookies, and session data can be intercepted by network eavesdroppers.',
            'Deploy an SSL/TLS certificate and enforce automatic HTTPS redirection (301 redirect).',
            'TLS/SSL Encryption',
            'CWE-319',
            7.5,
            'A02:2021 - Cryptographic Failures',
            `URL requested: ${url}`
        );
    }

    // Step 5: Technology Stack & Library Profiling (Wappalyzer-like)
    statusText.innerText = "Profiling detected technology stack and libraries...";
    const techStack = [];
    const seenTech = new Set();

    (shodanData.cpes || []).forEach(cpe => {
        const parsedTech = parseCpe(cpe);
        if (parsedTech && !seenTech.has(parsedTech.name)) {
            seenTech.add(parsedTech.name);
            techStack.push(parsedTech);
        }
    });

    // Detect cloud/CDN from Geo / ISP
    const ispOrg = `${geoData.connection?.isp || ''} ${geoData.connection?.org || ''}`.toLowerCase();
    if (ispOrg.includes('cloudflare')) {
        if (!seenTech.has('Cloudflare')) {
            techStack.push({ name: 'Cloudflare', category: 'CDN & WAF', icon: '☁️', version: '' });
            seenTech.add('Cloudflare');
        }
    } else if (ispOrg.includes('amazon') || ispOrg.includes('aws')) {
        if (!seenTech.has('Amazon Web Services')) {
            techStack.push({ name: 'Amazon Web Services (AWS)', category: 'Cloud Infrastructure', icon: '🟧', version: '' });
            seenTech.add('Amazon Web Services');
        }
    } else if (ispOrg.includes('google')) {
        if (!seenTech.has('Google Cloud')) {
            techStack.push({ name: 'Google Cloud Platform', category: 'Cloud Infrastructure', icon: '🌐', version: '' });
            seenTech.add('Google Cloud');
        }
    } else if (ispOrg.includes('rackspace')) {
        if (!seenTech.has('Rackspace Cloud')) {
            techStack.push({ name: 'Rackspace Cloud', category: 'Cloud Infrastructure', icon: '🏢', version: '' });
            seenTech.add('Rackspace Cloud');
        }
    } else if (ispOrg.includes('digitalocean')) {
        if (!seenTech.has('DigitalOcean')) {
            techStack.push({ name: 'DigitalOcean', category: 'Cloud Infrastructure', icon: '🌊', version: '' });
            seenTech.add('DigitalOcean');
        }
    }

    // Step 6: Score & OWASP Aggregation
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    const owaspMap = {};

    findings.forEach(f => {
        counts[f.severity] = (counts[f.severity] || 0) + 1;
        if (f.owasp_category) {
            owaspMap[f.owasp_category] = (owaspMap[f.owasp_category] || 0) + 1;
        }
    });

    const deductions = (counts.CRITICAL * 25) + (counts.HIGH * 15) + (counts.MEDIUM * 8) + (counts.LOW * 3);
    const score = Math.max(0, 100 - deductions);

    let grade = 'F';
    let gradeLabel = 'CRITICAL RISK';
    if (score >= 95) { grade = 'A+'; gradeLabel = 'EXCELLENT'; }
    else if (score >= 85) { grade = 'A'; gradeLabel = 'GOOD'; }
    else if (score >= 70) { grade = 'B'; gradeLabel = 'FAIR'; }
    else if (score >= 55) { grade = 'C'; gradeLabel = 'POOR'; }
    else if (score >= 40) { grade = 'D'; gradeLabel = 'HIGH RISK'; }

    const duration = ((Date.now() - startTime) / 1000).toFixed(2);

    const auditData = {
        result: {
            target: {
                url: url,
                domain: domain,
                ip_addresses: ipList,
                server_banner: techStack.length ? techStack[0].name : (geoData.connection?.isp || 'Cloud / Protected Origin'),
                asn: geoData.connection ? `AS${geoData.connection.asn} ${geoData.connection.org || ''}` : '',
                isp: geoData.connection?.isp || '',
                country: geoData.country || '',
                city: geoData.city || '',
                open_ports: openPorts,
                shodan_vulns: vulns,
                technologies: techStack,
                scan_timestamp: new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC'
            },
            summary: {
                score: score,
                grade: grade,
                grade_label: gradeLabel,
                total_findings: findings.length,
                critical_count: counts.CRITICAL,
                high_count: counts.HIGH,
                medium_count: counts.MEDIUM,
                low_count: counts.LOW,
                info_count: counts.INFO,
                owasp_breakdown: owaspMap,
                duration_seconds: parseFloat(duration)
            },
            findings: findings
        }
    };

    lastAuditData = auditData;
    renderResults(auditData, 'Browser Cloud Engine (100% Client-Side)');
}

// ==========================================
// Results Rendering
// ==========================================

function renderResults(data, engineLabel) {
    const container = document.getElementById('resultsContainer');
    const res = data.result || {};
    const target = res.target || {};
    const summary = res.summary || {};
    currentFindings = res.findings || [];

    // Engine Label
    const engineIndicator = document.getElementById('scanEngineIndicator');
    if (engineIndicator) {
        engineIndicator.innerText = engineLabel || 'AegisSec Security Engine';
    }

    // Score & Grade Styling
    let scoreColor = '#ef4444';
    let gradeBadgeColor = 'bg-red-500/10 text-red-400 border-red-500/20';
    if (summary.score >= 85) {
        scoreColor = '#10b981';
        gradeBadgeColor = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
    } else if (summary.score >= 70) {
        scoreColor = '#3b82f6';
        gradeBadgeColor = 'bg-blue-500/10 text-blue-400 border-blue-500/20';
    } else if (summary.score >= 55) {
        scoreColor = '#f59e0b';
        gradeBadgeColor = 'bg-amber-500/10 text-amber-400 border-amber-500/20';
    }

    // Circular gauge animation
    const circumference = 2 * Math.PI * 52;
    const offset = circumference - (summary.score / 100.0) * circumference;

    const gaugeSvg = document.getElementById('gaugeFill');
    if (gaugeSvg) {
        gaugeSvg.style.stroke = scoreColor;
        gaugeSvg.style.strokeDashoffset = offset;
    }

    document.getElementById('scoreText').innerText = summary.score;
    document.getElementById('scoreText').style.color = scoreColor;
    
    const gradeBadge = document.getElementById('gradeBadge');
    gradeBadge.className = `mt-4 px-3 py-1 rounded-full text-xs font-bold border ${gradeBadgeColor}`;
    gradeBadge.innerText = `${summary.grade} • ${summary.grade_label}`;

    // Target Info
    document.getElementById('targetDomain').innerText = target.domain || 'N/A';
    document.getElementById('targetUrl').innerText = target.url || 'N/A';
    document.getElementById('targetUrl').href = target.url || '#';
    document.getElementById('targetServer').innerText = target.server_banner || 'Protected Origin';
    document.getElementById('targetIps').innerText = (target.ip_addresses || []).join(', ') || 'N/A';
    document.getElementById('targetAsn').innerText = (target.asn || target.isp || 'N/A') + (target.country ? ` (${target.city || ''}, ${target.country})` : '');
    document.getElementById('scanDuration').innerText = `${summary.duration_seconds}s (${target.scan_timestamp})`;

    // Shodan Open Ports
    const portsList = document.getElementById('shodanPorts');
    const openPorts = target.open_ports || [];
    if (openPorts.length > 0) {
        portsList.innerHTML = openPorts.map(p => `
            <span class="px-2.5 py-1 bg-slate-800 border border-slate-700 text-cyan-400 rounded-md text-xs font-mono font-semibold">
                Port ${p}
            </span>
        `).join('');
    } else {
        portsList.innerHTML = '<span class="text-xs text-slate-500 italic">No listening services flagged by Shodan</span>';
    }

    // Shodan Tags & CVEs
    const shodanVulnsBox = document.getElementById('shodanVulns');
    const vulns = target.shodan_vulns || [];
    if (vulns.length > 0) {
        shodanVulnsBox.innerHTML = `
            <div class="p-3 bg-red-500/10 border border-red-500/30 rounded-xl space-y-2 mt-2">
                <span class="text-xs font-bold text-red-400">⚠️ Known CVE Vulnerabilities Detected (${vulns.length}):</span>
                <div class="flex flex-wrap gap-1.5">
                    ${vulns.map(v => `<a href="https://nvd.nist.gov/vuln/detail/${v}" target="_blank" class="px-2 py-0.5 bg-red-950 text-red-300 border border-red-800 rounded text-xs font-mono hover:bg-red-900">${v}</a>`).join('')}
                </div>
            </div>
        `;
    } else {
        shodanVulnsBox.innerHTML = '';
    }

    // KPI Counters
    document.getElementById('kpiCritical').innerText = summary.critical_count || 0;
    document.getElementById('kpiHigh').innerText = summary.high_count || 0;
    document.getElementById('kpiMedium').innerText = summary.medium_count || 0;
    document.getElementById('kpiLow').innerText = (summary.low_count || 0) + (summary.info_count || 0);

    // OWASP Bars
    renderOwaspBreakdown(summary.owasp_breakdown || {}, summary.total_findings || 1);

    // Render Technology Stack
    renderTechStack(target.technologies || []);

    // Render Findings List
    filterFindings('all');

    container.classList.remove('hidden');
    container.scrollIntoView({ behavior: 'smooth' });
}

function renderOwaspBreakdown(breakdown, total) {
    const list = document.getElementById('owaspList');
    const entries = Object.entries(breakdown);
    if (entries.length === 0) {
        list.innerHTML = '<p class="text-xs text-slate-500">No OWASP Top 10 vulnerabilities flagged.</p>';
        return;
    }

    list.innerHTML = entries.map(([cat, cnt]) => {
        const pct = Math.min(100, Math.round((cnt / total) * 100));
        return `
            <div class="space-y-1">
                <div class="flex justify-between text-xs">
                    <span class="text-slate-300 font-medium">${escapeHtml(cat)}</span>
                    <strong class="text-cyan-400">${cnt}</strong>
                </div>
                <div class="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div class="h-full bg-gradient-to-r from-blue-500 to-cyan-400" style="width: ${pct}%;"></div>
                </div>
            </div>
        `;
    }).join('');
}

function renderTechStack(techs) {
    const grid = document.getElementById('techStackGrid');
    const badge = document.getElementById('techCountBadge');
    if (!grid) return;

    if (badge) {
        badge.innerText = `${techs.length} Detected`;
    }

    if (techs.length === 0) {
        grid.innerHTML = '<div class="col-span-full p-4 text-center text-xs text-slate-500 italic bg-slate-950/60 rounded-xl border border-slate-800/60">No client or server technology signatures matched.</div>';
        return;
    }

    grid.innerHTML = techs.map(t => `
        <div class="bg-slate-950 border border-slate-800/80 rounded-xl p-3.5 flex items-center justify-between gap-3 hover:border-slate-700 transition">
            <div class="flex items-center gap-3 min-w-0">
                <span class="text-xl shrink-0">${t.icon || '💻'}</span>
                <div class="truncate">
                    <div class="font-semibold text-xs text-white truncate">${escapeHtml(t.name)}</div>
                    <div class="text-[11px] text-slate-400 truncate">${escapeHtml(t.category || 'Software')}</div>
                </div>
            </div>
            ${t.version ? `<span class="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-cyan-950 border border-cyan-800 text-cyan-300 shrink-0">v${escapeHtml(t.version)}</span>` : ''}
        </div>
    `).join('');
}

function filterFindings(sev) {
    activeSeverityFilter = sev;
    document.querySelectorAll('.filter-pill').forEach(btn => {
        if (btn.getAttribute('data-sev') === sev) {
            btn.className = 'filter-pill px-3 py-1 rounded-lg text-xs font-semibold bg-cyan-600 text-white cursor-pointer';
        } else {
            btn.className = 'filter-pill px-3 py-1 rounded-lg text-xs font-semibold bg-slate-800 text-slate-400 hover:text-white cursor-pointer';
        }
    });

    const searchVal = (document.getElementById('findingSearchInput').value || '').toLowerCase().trim();
    const container = document.getElementById('findingsCards');

    const filtered = currentFindings.filter(f => {
        const matchesSev = (sev === 'all' || f.severity.toLowerCase() === sev.toLowerCase());
        const keyword = `${f.title} ${f.id} ${f.cwe_id || ''} ${f.owasp_category || ''} ${f.description}`.toLowerCase();
        const matchesSearch = !searchVal || keyword.includes(searchVal);
        return matchesSev && matchesSearch;
    });

    if (filtered.length === 0) {
        container.innerHTML = '<div class="p-8 text-center text-slate-500 text-sm">No findings match the selected filter.</div>';
        return;
    }

    const sevColors = {
        'CRITICAL': 'bg-red-500 text-white',
        'HIGH': 'bg-orange-500 text-white',
        'MEDIUM': 'bg-amber-500 text-slate-900',
        'LOW': 'bg-blue-500 text-white',
        'INFO': 'bg-slate-600 text-white'
    };

    container.innerHTML = filtered.map((f, i) => `
        <div class="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4 hover:border-slate-700 transition">
            <div class="flex flex-wrap items-center justify-between gap-2">
                <div class="flex flex-wrap items-center gap-2">
                    <span class="px-2 py-0.5 rounded text-xs font-bold ${sevColors[f.severity] || 'bg-slate-600'}">${f.severity}</span>
                    <span class="px-2 py-0.5 rounded text-xs bg-slate-800 text-slate-300 font-medium">${escapeHtml(f.category)}</span>
                    ${f.cwe_id ? `<span class="px-2 py-0.5 rounded text-xs bg-slate-800/80 border border-slate-700 text-slate-400 font-mono">${escapeHtml(f.cwe_id)}</span>` : ''}
                    ${f.cvss_score ? `<span class="px-2 py-0.5 rounded text-xs bg-cyan-950 border border-cyan-800 text-cyan-300 font-mono">CVSS ${f.cvss_score}</span>` : ''}
                </div>
                <span class="text-xs font-mono text-slate-500">#${i + 1} • ${f.id}</span>
            </div>

            <div>
                <h4 class="text-base font-bold text-white mb-1">${escapeHtml(f.title)}</h4>
                <p class="text-xs text-slate-300 leading-relaxed">${escapeHtml(f.description)}</p>
            </div>

            <div class="p-3 bg-red-950/20 border border-red-900/30 rounded-lg">
                <div class="text-xs font-semibold uppercase text-red-400 mb-1">Impact</div>
                <p class="text-xs text-red-300">${escapeHtml(f.impact)}</p>
            </div>

            ${f.evidence ? `
            <div>
                <div class="text-xs font-semibold uppercase text-slate-400 mb-1">Detected Evidence</div>
                <pre class="bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap">${escapeHtml(f.evidence)}</pre>
            </div>
            ` : ''}

            <div class="p-3 bg-emerald-950/20 border border-emerald-900/30 rounded-lg">
                <div class="text-xs font-semibold uppercase text-emerald-400 mb-1">Actionable Remediation</div>
                <p class="text-xs text-emerald-300">${escapeHtml(f.remediation)}</p>
            </div>
        </div>
    `).join('');
}

// ==========================================
// Client-Side Report Export (HTML, JSON, PDF)
// ==========================================

function downloadPdfReport() {
    if (lastAuditData && lastAuditData.pdf_url) {
        window.open(`${currentBackendUrl}${lastAuditData.pdf_url}`, '_blank');
    } else {
        window.print();
    }
}

function downloadJsonReport() {
    if (!lastAuditData) return;
    const domain = (lastAuditData.result?.target?.domain || 'report').replace(/[^a-zA-Z0-9.-]/g, '_');
    const jsonStr = JSON.stringify(lastAuditData, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegis-security-report-${domain}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function downloadHtmlReport() {
    if (!lastAuditData) return;
    const r = lastAuditData.result || {};
    const t = r.target || {};
    const s = r.summary || {};
    const findings = r.findings || [];
    const domain = (t.domain || 'report').replace(/[^a-zA-Z0-9.-]/g, '_');

    let scoreColor = '#ef4444';
    if (s.score >= 85) scoreColor = '#10b981';
    else if (s.score >= 70) scoreColor = '#3b82f6';
    else if (s.score >= 55) scoreColor = '#f59e0b';

    const findingsHtml = findings.map((f, i) => `
        <div style="background:#0f172a; border:1px solid #1e293b; border-radius:12px; padding:20px; margin-bottom:16px;">
            <div style="display:flex; justify-content:space-between; margin-bottom:12px; flex-wrap:wrap; gap:8px;">
                <div>
                    <span style="background:${f.severity === 'CRITICAL' ? '#ef4444' : f.severity === 'HIGH' ? '#f97316' : f.severity === 'MEDIUM' ? '#eab308' : '#3b82f6'}; color:#fff; font-size:11px; font-weight:700; padding:3px 8px; border-radius:6px;">${f.severity}</span>
                    <span style="background:#1e293b; color:#cbd5e1; font-size:11px; padding:3px 8px; border-radius:6px; margin-left:6px;">${escapeHtml(f.category)}</span>
                    ${f.cwe_id ? `<span style="background:#1e293b; color:#94a3b8; font-family:monospace; font-size:11px; padding:3px 8px; border-radius:6px; margin-left:6px;">${escapeHtml(f.cwe_id)}</span>` : ''}
                </div>
                <span style="color:#64748b; font-size:12px; font-family:monospace;">#${i + 1} • ${f.id}</span>
            </div>
            <h3 style="color:#fff; font-size:16px; margin:0 0 8px 0;">${escapeHtml(f.title)}</h3>
            <p style="color:#cbd5e1; font-size:13px; line-height:1.6; margin:0 0 12px 0;">${escapeHtml(f.description)}</p>
            <div style="background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.25); border-radius:8px; padding:12px; margin-bottom:12px;">
                <strong style="color:#f87171; font-size:11px; text-transform:uppercase; display:block; margin-bottom:4px;">Security Impact:</strong>
                <span style="color:#fca5a5; font-size:12px;">${escapeHtml(f.impact)}</span>
            </div>
            ${f.evidence ? `
            <div style="margin-bottom:12px;">
                <strong style="color:#94a3b8; font-size:11px; text-transform:uppercase; display:block; margin-bottom:4px;">Evidence / Detected Response:</strong>
                <pre style="background:#020617; border:1px solid #1e293b; color:#e2e8f0; font-size:12px; padding:10px; border-radius:8px; overflow-x:auto; white-space:pre-wrap;">${escapeHtml(f.evidence)}</pre>
            </div>` : ''}
            <div style="background:rgba(16,185,129,0.1); border:1px solid rgba(16,185,129,0.25); border-radius:8px; padding:12px;">
                <strong style="color:#34d399; font-size:11px; text-transform:uppercase; display:block; margin-bottom:4px;">Remediation:</strong>
                <span style="color:#6ee7b7; font-size:12px;">${escapeHtml(f.remediation)}</span>
            </div>
        </div>
    `).join('');

    const standaloneHtml = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AegisSec Security Report - ${escapeHtml(t.domain)}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #020617; color: #f8fafc; margin: 0; padding: 24px; }
        .container { max-width: 900px; margin: 0 auto; }
        .card { background: #0b1329; border: 1px solid #1e293b; border-radius: 16px; padding: 24px; margin-bottom: 24px; }
        .score-circle { width: 100px; height: 100px; border-radius: 50%; border: 6px solid ${scoreColor}; display: flex; align-items: center; justify-content: center; flex-direction: column; margin: 0 auto; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; }
        .pill { background: #1e293b; color: #38bdf8; font-family: monospace; font-size: 11px; padding: 4px 8px; border-radius: 6px; }
    </style>
</head>
<body>
    <div class="container">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px; border-bottom:1px solid #1e293b; padding-bottom:16px;">
            <div style="display:flex; align-items:center; gap:10px;">
                <span style="font-size:28px;">🛡️</span>
                <div>
                    <h1 style="margin:0; font-size:20px;">AegisSec Executive Report</h1>
                    <span style="color:#64748b; font-size:12px;">Audited on ${escapeHtml(t.scan_timestamp)}</span>
                </div>
            </div>
            <button onclick="window.print()" style="background:#2563eb; color:#fff; border:none; padding:8px 16px; border-radius:8px; cursor:pointer; font-weight:bold; font-size:12px;">Print / Save PDF</button>
        </div>

        <div class="card" style="display:flex; align-items:center; gap:32px; flex-wrap:wrap;">
            <div style="text-align:center; min-width:140px;">
                <div class="score-circle">
                    <span style="font-size:32px; font-weight:800; color:${scoreColor};">${s.score}</span>
                    <span style="font-size:10px; color:#64748b;">/ 100</span>
                </div>
                <div style="margin-top:10px; font-weight:bold; font-size:13px; color:${scoreColor};">${s.grade} • ${s.grade_label}</div>
            </div>
            <div style="flex:1; min-width:260px;">
                <h2 style="margin:0 0 4px 0; font-size:22px;">${escapeHtml(t.domain)}</h2>
                <a href="${escapeHtml(t.url)}" target="_blank" style="color:#38bdf8; font-size:12px;">${escapeHtml(t.url)}</a>
                <div class="grid" style="margin-top:16px;">
                    <div><span style="color:#64748b; font-size:11px; display:block;">IP Addresses</span><strong>${(t.ip_addresses || []).join(', ') || 'N/A'}</strong></div>
                    <div><span style="color:#64748b; font-size:11px; display:block;">Network / ASN</span><strong>${escapeHtml(t.asn || 'N/A')}</strong></div>
                    <div><span style="color:#64748b; font-size:11px; display:block;">Server Platform</span><strong>${escapeHtml(t.server_banner || 'N/A')}</strong></div>
                    <div><span style="color:#64748b; font-size:11px; display:block;">Location</span><strong>${escapeHtml(t.city ? t.city + ', ' + t.country : (t.country || 'N/A'))}</strong></div>
                </div>
            </div>
        </div>

        <div class="card">
            <h3 style="margin:0 0 12px 0; font-size:14px; text-transform:uppercase; color:#94a3b8;">🔍 Shodan Open Ports & Infrastructure</h3>
            <div style="display:flex; flex-wrap:wrap; gap:8px;">
                ${(t.open_ports && t.open_ports.length > 0) ? t.open_ports.map(p => `<span class="pill">Port ${p}</span>`).join('') : '<span style="color:#64748b; font-size:12px;">No open ports flagged by Shodan</span>'}
            </div>
        </div>

        <div class="card">
            <h3 style="margin:0 0 16px 0; font-size:14px; text-transform:uppercase; color:#94a3b8;">Audit Findings (${findings.length})</h3>
            ${findingsHtml}
        </div>
    </div>
</body>
</html>`;

    const blob = new Blob([standaloneHtml], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegis-security-report-${domain}.html`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' })[m]);
}
