// AegisSec GitHub Pages Client Application

const DEFAULT_BACKEND = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' 
    ? window.location.origin 
    : (localStorage.getItem('aegis_backend_url') || 'https://aegis-sec.onrender.com');

let currentBackendUrl = DEFAULT_BACKEND;
let currentFindings = [];
let activeSeverityFilter = 'all';

document.addEventListener('DOMContentLoaded', () => {
    initBackendConfig();
    checkBackendHealth();
});

function initBackendConfig() {
    const input = document.getElementById('backendUrlInput');
    const badge = document.getElementById('backendStatusBadge');
    if (input) {
        input.value = currentBackendUrl;
    }
}

function saveBackendUrl() {
    const input = document.getElementById('backendUrlInput');
    if (input && input.value.trim()) {
        currentBackendUrl = input.value.trim().replace(/\/$/, '');
        localStorage.setItem('aegis_backend_url', currentBackendUrl);
        toggleConfigModal(false);
        checkBackendHealth();
    }
}

async function checkBackendHealth() {
    const badge = document.getElementById('backendStatusBadge');
    if (!badge) return;
    
    badge.className = 'px-2.5 py-1 text-xs font-semibold rounded-full bg-yellow-500/10 text-yellow-400 border border-yellow-500/20';
    badge.innerText = 'Connecting...';

    try {
        const resp = await fetch(`${currentBackendUrl}/health`, { method: 'GET', signal: AbortSignal.timeout(4000) });
        if (resp.ok) {
            badge.className = 'px-2.5 py-1 text-xs font-semibold rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20';
            badge.innerText = 'Backend Online';
        } else {
            throw new Error('Not 200');
        }
    } catch (e) {
        badge.className = 'px-2.5 py-1 text-xs font-semibold rounded-full bg-red-500/10 text-red-400 border border-red-500/20 cursor-pointer';
        badge.innerText = 'Backend Offline (Click to configure)';
        badge.onclick = () => toggleConfigModal(true);
    }
}

function toggleConfigModal(show) {
    const modal = document.getElementById('configModal');
    if (modal) {
        modal.style.display = show ? 'flex' : 'none';
    }
}

function setTarget(url) {
    const input = document.getElementById('targetInput');
    if (input) {
        input.value = url;
    }
}

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

    const steps = [
        "Resolving domain and IP addresses...",
        "Querying Shodan InternetDB & Network ASN intelligence...",
        "Auditing HTTP Security Headers (HSTS, CSP, X-Frame-Options)...",
        "Inspecting SSL/TLS certificate validity & cipher suites...",
        "Checking DNS & Email spoofing policies (SPF / DMARC)...",
        "Probing sensitive files and compiling executive PDF report..."
    ];

    let stepIdx = 0;
    const interval = setInterval(() => {
        if (stepIdx < steps.length) {
            statusText.innerText = steps[stepIdx];
            stepIdx++;
        }
    }, 1200);

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
        statusBox.classList.add('hidden');
        scanBtn.disabled = false;
        renderResults(data);

    } catch (err) {
        clearInterval(interval);
        statusText.innerHTML = `<span class="text-red-400 font-semibold">Audit failed:</span> ${err.message}. <br/><span class="text-xs text-slate-400">Ensure the backend API is running and reachable. Click the status badge to configure the backend URL.</span>`;
        scanBtn.disabled = false;
    }
}

function renderResults(data) {
    const container = document.getElementById('resultsContainer');
    const res = data.result || {};
    const target = res.target || {};
    const summary = res.summary || {};
    currentFindings = res.findings || [];

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

    // Gauge circle calculation
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
    gradeBadge.className = `px-3 py-1 rounded-full text-xs font-bold border ${gradeBadgeColor}`;
    gradeBadge.innerText = `${summary.grade} • ${summary.grade_label}`;

    // Target Info
    document.getElementById('targetDomain').innerText = target.domain || 'N/A';
    document.getElementById('targetUrl').innerText = target.url || 'N/A';
    document.getElementById('targetUrl').href = target.url || '#';
    document.getElementById('targetServer').innerText = target.server_banner || 'Hidden / Cloudflare';
    document.getElementById('targetIps').innerText = (target.ip_addresses || []).join(', ') || 'N/A';
    document.getElementById('targetAsn').innerText = (target.asn || target.isp || 'N/A') + (target.country ? ` (${target.city || ''}, ${target.country})` : '');
    document.getElementById('scanDuration').innerText = `${summary.duration_seconds}s (${target.scan_timestamp})`;

    // Shodan Intelligence Section
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
            <div class="p-3 bg-red-500/10 border border-red-500/30 rounded-xl space-y-2">
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

    // Download Links
    const pdfBtn = document.getElementById('btnDownloadPdf');
    if (data.pdf_url) {
        pdfBtn.href = `${currentBackendUrl}${data.pdf_url}`;
        pdfBtn.classList.remove('hidden');
    } else {
        pdfBtn.classList.add('hidden');
    }

    const htmlBtn = document.getElementById('btnDownloadHtml');
    if (data.html_url) {
        htmlBtn.href = `${currentBackendUrl}${data.html_url}`;
    }

    const jsonBtn = document.getElementById('btnDownloadJson');
    if (data.json_url) {
        jsonBtn.href = `${currentBackendUrl}${data.json_url}`;
    }

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
                    <span class="text-slate-300 font-medium">${cat}</span>
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
            btn.className = 'filter-pill px-3 py-1 rounded-lg text-xs font-semibold bg-cyan-600 text-white';
        } else {
            btn.className = 'filter-pill px-3 py-1 rounded-lg text-xs font-semibold bg-slate-800 text-slate-400 hover:text-white';
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
                    <span class="px-2 py-0.5 rounded text-xs bg-slate-800 text-slate-300 font-medium">${f.category}</span>
                    ${f.cwe_id ? `<span class="px-2 py-0.5 rounded text-xs bg-slate-800/80 border border-slate-700 text-slate-400 font-mono">${f.cwe_id}</span>` : ''}
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

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' })[m]);
}
