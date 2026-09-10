/**
 * CyberProbe - Client Application Logic
 * Real-time Defensive Security Scanner & Pen-Testing Suite
 */

let currentScanData = null;
let activeEventSource = null;
let scanTimerInterval = null;
let scanStartEpoch = null;

// Tab Management
const navItems = document.querySelectorAll('.sidebar-menu .nav-item');
const tabViews = document.querySelectorAll('.tab-view');

function switchTab(tabId) {
  navItems.forEach(item => {
    if (item.dataset.tab === tabId) {
      item.classList.add('active');
    } else {
      item.classList.remove('active');
    }
  });

  tabViews.forEach(view => {
    if (view.id === `view-${tabId}`) {
      view.classList.add('active');
    } else {
      view.classList.remove('active');
    }
  });

  // Render view-specific content if available
  if (currentScanData) {
    if (tabId === 'target-scan') renderTargetScanDetails();
    if (tabId === 'pentest') renderPentestChecks();
    if (tabId === 'vulnerabilities') renderAllVulnerabilities('all');
    if (tabId === 'owasp') renderOwaspGrid();
    if (tabId === 'tls') renderTlsDetails();
    if (tabId === 'headers') renderHeadersInspector();
  }
}

navItems.forEach(btn => {
  btn.addEventListener('click', () => {
    const tabId = btn.dataset.tab;
    switchTab(tabId);
  });
});

// UI Elements
const targetUrlInput = document.getElementById('targetUrlInput');
const scanProfileSelect = document.getElementById('scanProfileSelect');
const startScanBtn = document.getElementById('startScanBtn');
const btnSpinner = document.getElementById('btnSpinner');
const btnPlayIcon = document.getElementById('btnPlayIcon');
const btnScanText = document.getElementById('btnScanText');

const engineStatusText = document.getElementById('engineStatusText');
const engineDot = document.getElementById('engineDot');
const progressStatusText = document.getElementById('progressStatusText');
const progressStatusDot = document.getElementById('progressStatusDot');
const progressPercentText = document.getElementById('progressPercentText');
const progressBarFill = document.getElementById('progressBarFill');
const activeScanningTarget = document.getElementById('activeScanningTarget');
const scanTimerText = document.getElementById('scanTimerText');

const terminalConsole = document.getElementById('terminalConsole');
const expandedTerminalConsole = document.getElementById('expandedTerminalConsole');

// Metrics
const metricTotal = document.getElementById('metricTotal');
const metricCritical = document.getElementById('metricCritical');
const metricHigh = document.getElementById('metricHigh');
const metricMedium = document.getElementById('metricMedium');
const metricLow = document.getElementById('metricLow');
const metricPages = document.getElementById('metricPages');

// Target Info
const targetInfoUrl = document.getElementById('targetInfoUrl');
const targetInfoScanType = document.getElementById('targetInfoScanType');
const targetInfoStartTime = document.getElementById('targetInfoStartTime');
const targetInfoDuration = document.getElementById('targetInfoDuration');
const targetInfoUrls = document.getElementById('targetInfoUrls');
const targetInfoTech = document.getElementById('targetInfoTech');
const targetInfoRiskScore = document.getElementById('targetInfoRiskScore');
const riskScoreBarFill = document.getElementById('riskScoreBarFill');
const targetStatusText = document.getElementById('targetStatusText');
const targetStatusBadge = document.getElementById('targetStatusBadge');

// Donut & Legend
const donutSlicesGroup = document.getElementById('donutSlicesGroup');
const donutTotalIssues = document.getElementById('donutTotalIssues');
const legendCritCount = document.getElementById('legendCritCount');
const legendCritPct = document.getElementById('legendCritPct');
const legendHighCount = document.getElementById('legendHighCount');
const legendHighPct = document.getElementById('legendHighPct');
const legendMedCount = document.getElementById('legendMedCount');
const legendMedPct = document.getElementById('legendMedPct');
const legendLowCount = document.getElementById('legendLowCount');
const legendLowPct = document.getElementById('legendLowPct');

// Table
const vulnTableBody = document.getElementById('vulnTableBody');
const checkHeadersNowBtn = document.getElementById('checkHeadersNowBtn');

// Helper to append log lines
function appendLog(time, level, message) {
  const line = document.createElement('div');
  line.className = 'terminal-line';

  let tagClass = 'tag-info';
  if (level === 'WARN') tagClass = 'tag-warn';
  if (level === 'CRIT') tagClass = 'tag-crit';
  if (level === 'PASS') tagClass = 'tag-pass';

  line.innerHTML = `<span class="log-time">${time}</span> <span class="log-tag ${tagClass}">[${level}]</span> <span>${escapeHtml(message)}</span>`;

  terminalConsole.appendChild(line);
  terminalConsole.scrollTop = terminalConsole.scrollHeight;

  if (expandedTerminalConsole) {
    const clone = line.cloneNode(true);
    expandedTerminalConsole.appendChild(clone);
    expandedTerminalConsole.scrollTop = expandedTerminalConsole.scrollHeight;
  }
}

function clearTerminal() {
  if (expandedTerminalConsole) {
    expandedTerminalConsole.innerHTML = '';
  }
  terminalConsole.innerHTML = '';
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Timer helper
function formatDuration(sec) {
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = Math.floor(sec % 60);
  const pad = (n) => String(n).padStart(2, '0');
  return `${pad(h)}:${pad(m)}:${pad(s)}`;
}

// Start Real Scan
async function startScan(customUrl = null) {
  const target = (customUrl || targetUrlInput.value || '').trim();
  if (!target) {
    alert('Please enter a target URL (e.g. https://example.com)');
    return;
  }

  const profile = scanProfileSelect.value;

  // Reset UI for scanning state
  startScanBtn.disabled = true;
  btnSpinner.style.display = 'inline-block';
  btnPlayIcon.style.display = 'none';
  btnScanText.textContent = 'Scanning...';

  engineStatusText.textContent = 'Engine: Running';
  engineDot.className = 'pulse-dot running';
  progressStatusText.textContent = 'Running';
  progressStatusDot.className = 'status-indicator-dot active';
  progressPercentText.textContent = '10%';
  progressBarFill.style.width = '10%';

  activeScanningTarget.textContent = target;
  targetInfoUrl.textContent = target;
  targetInfoScanType.textContent = profile;
  targetInfoStartTime.textContent = new Date().toLocaleString();
  targetInfoDuration.textContent = '00:00:01 (in progress)';
  targetStatusText.textContent = 'Scanning';

  // Clear previous terminal logs
  terminalConsole.innerHTML = '';
  if (expandedTerminalConsole) expandedTerminalConsole.innerHTML = '';

  scanStartEpoch = Date.now();
  if (scanTimerInterval) clearInterval(scanTimerInterval);

  let currentPercent = 10;
  scanTimerInterval = setInterval(() => {
    const elapsedSec = (Date.now() - scanStartEpoch) / 1000;
    scanTimerText.textContent = `Elapsed: ${formatDuration(elapsedSec)} | ETA: 00:00:03`;
    targetInfoDuration.textContent = `${formatDuration(elapsedSec)} (in progress)`;

    if (currentPercent < 90) {
      currentPercent += 8;
      progressPercentText.textContent = `${currentPercent}%`;
      progressBarFill.style.width = `${currentPercent}%`;
    }
  }, 400);

  // Close any existing SSE stream
  if (activeEventSource) {
    activeEventSource.close();
  }

  // Connect to SSE stream
  const sseUrl = `/api/scan-stream?url=${encodeURIComponent(target)}&profile=${encodeURIComponent(profile)}`;
  const evtSource = new EventSource(sseUrl);
  activeEventSource = evtSource;

  evtSource.addEventListener('log', (e) => {
    try {
      const data = JSON.parse(e.data);
      appendLog(data.time, data.level, data.message);
    } catch (err) {
      console.error(err);
    }
  });

  let scanCompleted = false;

  evtSource.addEventListener('complete', (e) => {
    scanCompleted = true;
    clearInterval(scanTimerInterval);
    progressPercentText.textContent = '100%';
    progressBarFill.style.width = '100%';

    try {
      const result = JSON.parse(e.data);
      currentScanData = result;
      populateScanResults(result);
    } catch (err) {
      console.error('Failed to parse scan completion payload:', err);
    } finally {
      evtSource.close();
      activeEventSource = null;
      finishScanUI();
    }
  });

  evtSource.addEventListener('error', async (e) => {
    if (scanCompleted) return;
    evtSource.close();
    activeEventSource = null;
    appendLog(getLogTimeStr(), 'WARN', 'Live stream paused, synchronizing via direct API...');

    try {
      const resp = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetUrl: target, scanProfile: profile })
      });
      const data = await resp.json();
      if (data.success) {
        clearInterval(scanTimerInterval);
        progressPercentText.textContent = '100%';
        progressBarFill.style.width = '100%';
        currentScanData = data;
        populateScanResults(data);
        if (data.logs) {
          data.logs.forEach(l => appendLog(l.time, l.level, l.message));
        }
      } else {
        throw new Error(data.error || 'Scan error');
      }
    } catch (postErr) {
      clearInterval(scanTimerInterval);
      appendLog(getLogTimeStr(), 'CRIT', `Scan error: ${postErr.message}`);
    } finally {
      finishScanUI();
    }
  });
}

function getLogTimeStr() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function finishScanUI() {
  startScanBtn.disabled = false;
  btnSpinner.style.display = 'none';
  btnPlayIcon.style.display = 'inline-block';
  btnScanText.textContent = 'Start Scan';

  engineStatusText.textContent = 'Engine: Standby';
  engineDot.className = 'pulse-dot green';
  progressStatusText.textContent = 'Completed';
  progressStatusDot.className = 'status-indicator-dot';
  targetStatusText.textContent = 'Completed';
}

// Populate Results into UI
function populateScanResults(result) {
  const { targetInfo, counts, securityHeaders, vulnerabilities, logs } = result;

  // Metrics
  metricTotal.textContent = counts.Total || 0;
  metricCritical.textContent = counts.Critical || 0;
  metricHigh.textContent = counts.High || 0;
  metricMedium.textContent = counts.Medium || 0;
  metricLow.textContent = counts.Low || 0;
  metricPages.textContent = targetInfo.discoveredUrls || 1;

  // Target Info
  targetInfoUrl.textContent = targetInfo.targetUrl;
  targetInfoScanType.textContent = targetInfo.scanType;
  targetInfoStartTime.textContent = targetInfo.startTime;
  targetInfoDuration.textContent = targetInfo.duration;
  targetInfoUrls.textContent = targetInfo.discoveredUrls;
  targetInfoTech.textContent = targetInfo.technologies.join(', ') || 'Custom';
  targetInfoRiskScore.textContent = `${targetInfo.riskScore} / 10`;

  const riskPct = Math.min(100, Math.max(0, targetInfo.riskScore * 10));
  riskScoreBarFill.style.width = `${riskPct}%`;

  // Update Donut Chart
  renderDonutChart(counts);

  // Update Security Headers Checklist
  renderHeadersChecklist(securityHeaders);

  // Update Top Vulnerabilities Table
  renderVulnTable(vulnerabilities);
}

// Donut Chart Drawing
function renderDonutChart(counts) {
  donutTotalIssues.textContent = counts.Total || 0;
  const total = counts.Total || 1;

  const critPct = Math.round(((counts.Critical || 0) / total) * 100);
  const highPct = Math.round(((counts.High || 0) / total) * 100);
  const medPct = Math.round(((counts.Medium || 0) / total) * 100);
  const lowPct = Math.max(0, 100 - (critPct + highPct + medPct));

  legendCritCount.textContent = counts.Critical || 0;
  legendCritPct.textContent = `${critPct}%`;
  legendHighCount.textContent = counts.High || 0;
  legendHighPct.textContent = `${highPct}%`;
  legendMedCount.textContent = counts.Medium || 0;
  legendMedPct.textContent = `${medPct}%`;
  legendLowCount.textContent = counts.Low || 0;
  legendLowPct.textContent = `${lowPct}%`;

  // Draw SVG Segments
  const radius = 70;
  const circumference = 2 * Math.PI * radius; // ~439.82
  donutSlicesGroup.innerHTML = '';

  const slices = [
    { name: 'crit', val: counts.Critical || 0, color: '#ff4757' },
    { name: 'high', val: counts.High || 0, color: '#ffa502' },
    { name: 'med', val: counts.Medium || 0, color: '#00e1ff' },
    { name: 'low', val: counts.Low || 0, color: '#a55eea' }
  ];

  let accumulatedPercent = 0;

  slices.forEach(slice => {
    if (slice.val <= 0) return;
    const slicePercent = slice.val / (counts.Total || 1);
    const strokeDash = slicePercent * circumference;
    const strokeOffset = -accumulatedPercent * circumference;

    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', '100');
    circle.setAttribute('cy', '100');
    circle.setAttribute('r', String(radius));
    circle.setAttribute('fill', 'transparent');
    circle.setAttribute('stroke', slice.color);
    circle.setAttribute('stroke-width', '24');
    circle.setAttribute('stroke-dasharray', `${strokeDash} ${circumference - strokeDash}`);
    circle.setAttribute('stroke-dashoffset', String(strokeOffset));
    circle.style.transition = 'stroke-dasharray 0.5s ease';

    donutSlicesGroup.appendChild(circle);
    accumulatedPercent += slicePercent;
  });
}

// Render Security Headers Checklist
function renderHeadersChecklist(secHeaders) {
  const map = {
    'Content-Security-Policy': 'CSP',
    'Strict-Transport-Security': 'HSTS',
    'X-Frame-Options': 'XFO',
    'X-Content-Type-Options': 'XCTO',
    'Referrer-Policy': 'REFPOL',
    'Permissions-Policy': 'PERMPOL'
  };

  for (const [key, idSuffix] of Object.entries(map)) {
    const item = secHeaders[key];
    const badge = document.getElementById(`badge-${idSuffix}`);
    if (!badge || !item) continue;

    if (item.status === 'Present') {
      badge.className = 'header-badge present';
      badge.innerHTML = `
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
          <polyline points="20 6 9 17 4 12"/>
        </svg>
        <span>Present</span>
      `;
    } else if (item.status === 'Not Set') {
      badge.className = 'header-badge warn';
      badge.innerHTML = `
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
        </svg>
        <span>Not Set</span>
      `;
    } else {
      badge.className = 'header-badge missing';
      badge.innerHTML = `
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
          <line x1="18" y1="6" x2="6" y2="18"/>
          <line x1="6" y1="6" x2="18" y2="18"/>
        </svg>
        <span>Missing</span>
      `;
    }
  }
}

// Render Top Vulnerabilities Table
function renderVulnTable(vulns) {
  vulnTableBody.innerHTML = '';

  if (!vulns || vulns.length === 0) {
    vulnTableBody.innerHTML = `<tr><td colspan="6" class="empty-table-cell">No vulnerabilities detected! Target passed all defensive checks.</td></tr>`;
    return;
  }

  vulns.forEach((v, idx) => {
    const tr = document.createElement('tr');

    const sevClass = v.severity.toLowerCase();
    tr.innerHTML = `
      <td class="th-num">${idx + 1}</td>
      <td class="th-vuln"><strong>${escapeHtml(v.name)}</strong></td>
      <td class="th-sev"><span class="sev-pill ${sevClass}">${v.severity}</span></td>
      <td class="th-end"><span class="code-endpoint">${escapeHtml(v.endpoint)}</span></td>
      <td class="th-stat"><span class="status-${v.status.toLowerCase()}-tag">${v.status}</span></td>
      <td class="th-act">
        <button class="inspect-btn" onclick="openInspectModal(${idx})">Inspect & Fix</button>
      </td>
    `;

    vulnTableBody.appendChild(tr);
  });
}

// Render Full Vulnerabilities Tab
function renderAllVulnerabilities(filter = 'all') {
  const container = document.getElementById('vulnCardsContainer');
  if (!container || !currentScanData) return;

  const vulns = currentScanData.vulnerabilities || [];

  document.getElementById('count-all').textContent = vulns.length;
  document.getElementById('count-crit').textContent = vulns.filter(v => v.severity === 'Critical').length;
  document.getElementById('count-high').textContent = vulns.filter(v => v.severity === 'High').length;
  document.getElementById('count-med').textContent = vulns.filter(v => v.severity === 'Medium').length;
  document.getElementById('count-low').textContent = vulns.filter(v => v.severity === 'Low').length;

  const filtered = filter === 'all' ? vulns : vulns.filter(v => v.severity === filter);

  if (filtered.length === 0) {
    container.innerHTML = `<div class="empty-state">No vulnerabilities match the selected filter.</div>`;
    return;
  }

  container.innerHTML = '';
  filtered.forEach((v, idx) => {
    const card = document.createElement('div');
    card.className = 'vuln-card-item';
    const sevClass = v.severity.toLowerCase();

    card.innerHTML = `
      <div class="vuln-card-head">
        <div class="vuln-card-title-group">
          <span class="sev-pill ${sevClass}">${v.severity}</span>
          <span class="vuln-card-title">${escapeHtml(v.name)}</span>
        </div>
        <button class="inspect-btn" onclick="openInspectModal(${idx})">Inspect & Fix &rarr;</button>
      </div>
      <div class="vuln-meta-pills">
        <span>Endpoint: <code>${escapeHtml(v.endpoint)}</code></span>
        <span>CWE: <strong>${v.cwe}</strong></span>
        <span>OWASP: <strong>${v.category}</strong></span>
      </div>
      <p class="vuln-desc-snippet">${escapeHtml(v.description)}</p>
    `;

    container.appendChild(card);
  });
}

document.querySelectorAll('.filter-pill').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    renderAllVulnerabilities(btn.dataset.filter);
  });
});

// Render OWASP Top 10 View
function renderOwaspGrid() {
  const container = document.getElementById('owaspGridContainer');
  if (!container) return;

  const owaspCategories = [
    { code: 'A01:2021', name: 'Broken Access Control', desc: 'Restrictions on what authenticated users can do are not properly enforced.' },
    { code: 'A02:2021', name: 'Cryptographic Failures', desc: 'Failures related to cryptography (such as cleartext transmission or weak TLS).' },
    { code: 'A03:2021', name: 'Injection', desc: 'User-supplied data is not validated, filtered, or sanitized by the application.' },
    { code: 'A04:2021', name: 'Insecure Design', desc: 'Risks related to design flaws and missing threat modeling principles.' },
    { code: 'A05:2021', name: 'Security Misconfiguration', desc: 'Missing security hardening, default configurations, or unhandled HTTP headers.' },
    { code: 'A06:2021', name: 'Vulnerable and Outdated Components', desc: 'Running out-of-date runtime versions, libraries, or server daemons.' },
    { code: 'A07:2021', name: 'Identification & Authentication Failures', desc: 'Weak cookie session attributes, brute-force vulnerabilities, credential stuffing.' },
    { code: 'A08:2021', name: 'Software & Data Integrity Failures', desc: 'Insecure deserialization, unverified CI/CD pipelines, untrusted CDN scripts.' },
    { code: 'A09:2021', name: 'Security Logging & Monitoring Failures', desc: 'Insufficient security auditing, missing alert telemetry, untracked API access.' },
    { code: 'A10:2021', name: 'Server-Side Request Forgery (SSRF)', desc: 'Web applications fetching remote resources without validating user-supplied URLs.' }
  ];

  const vulns = currentScanData?.vulnerabilities || [];

  container.innerHTML = '';
  owaspCategories.forEach(cat => {
    const card = document.createElement('div');
    card.className = 'owasp-card';

    const matchedVulns = vulns.filter(v => v.category && v.category.includes(cat.code));
    const isFlagged = matchedVulns.length > 0;

    card.innerHTML = `
      <div class="owasp-card-header">
        <span class="owasp-code">${cat.code}</span>
        <span class="owasp-status-tag ${isFlagged ? 'flagged' : 'clean'}">
          ${isFlagged ? `${matchedVulns.length} Defect(s) Found` : 'Clean / Compliant'}
        </span>
      </div>
      <h3 class="owasp-title">${cat.name}</h3>
      <p class="owasp-desc">${cat.desc}</p>
      ${isFlagged ? `<div style="margin-top:10px; font-size:11px; color:#f87171;">Flagged Issues: ${matchedVulns.map(m => m.name).join(', ')}</div>` : ''}
    `;

    container.appendChild(card);
  });
}

// Render TLS Details View
function renderTlsDetails() {
  const container = document.getElementById('tlsDetailsContainer');
  if (!container || !currentScanData) return;

  const tls = currentScanData.targetInfo.tlsInfo;
  if (!tls) {
    container.innerHTML = `<div class="empty-state">Target did not use HTTPS or TLS handshake was not performed.</div>`;
    return;
  }

  container.innerHTML = `
    <div class="tls-grid">
      <div class="tls-box">
        <div class="tls-box-title">Negotiated Protocol</div>
        <div class="tls-box-value" style="color: #00ff88; font-weight:700;">${tls.protocol || 'Unknown'}</div>
      </div>
      <div class="tls-box">
        <div class="tls-box-title">Cipher Suite</div>
        <div class="tls-box-value">${tls.cipherName || 'Unknown'}</div>
      </div>
      <div class="tls-box">
        <div class="tls-box-title">Certificate Issuer</div>
        <div class="tls-box-value">${tls.issuer?.O || tls.issuer?.CN || 'Unknown CA'}</div>
      </div>
      <div class="tls-box">
        <div class="tls-box-title">Validity Days Remaining</div>
        <div class="tls-box-value" style="color: ${tls.daysRemaining <= 15 ? '#ff4757' : '#34d399'}; font-weight:700;">
          ${tls.daysRemaining !== null ? `${tls.daysRemaining} days (Valid until: ${tls.validTo})` : 'N/A'}
        </div>
      </div>
      <div class="tls-box" style="grid-column: span 2;">
        <div class="tls-box-title">Subject Alternative Names (SAN)</div>
        <div class="tls-box-value">${tls.san || 'None'}</div>
      </div>
      <div class="tls-box" style="grid-column: span 2;">
        <div class="tls-box-title">CA Trust Status</div>
        <div class="tls-box-value" style="color: ${tls.authorized ? '#10b981' : '#ef4444'};">
          ${tls.authorized ? 'Verified Trusted Public Certificate Authority' : `Untrusted Certificate: ${tls.authError}`}
        </div>
      </div>
    </div>
  `;
}

// Render Headers Inspector
function renderHeadersInspector() {
  const container = document.getElementById('headersAuditContainer');
  if (!container || !currentScanData) return;

  const rawHeaders = currentScanData.rawHeaders || {};
  const keys = Object.keys(rawHeaders);

  if (keys.length === 0) {
    container.innerHTML = `<div class="empty-state">No headers captured.</div>`;
    return;
  }

  container.innerHTML = keys.map(k => `
    <div class="raw-header-row">
      <div class="raw-header-key">${escapeHtml(k)}</div>
      <div class="raw-header-val">${escapeHtml(rawHeaders[k])}</div>
    </div>
  `).join('');
}

// Render Target Surface Recon Tab
function renderTargetScanDetails() {
  const container = document.getElementById('targetScanDetailsContainer');
  if (!container || !currentScanData) return;

  const info = currentScanData.targetInfo;
  const dns = info.dnsInfo || {};
  const scripts = info.scripts || [];

  container.innerHTML = `
    <div class="recon-box">
      <div class="recon-box-title">Network & DNS Routing</div>
      <div class="recon-list">
        <div><strong>Resolved IPv4/IPv6 Addresses:</strong></div>
        <div class="recon-pill-row">
          ${(dns.ipAddresses && dns.ipAddresses.length > 0) ? dns.ipAddresses.map(ip => `<span class="recon-tag">${ip}</span>`).join('') : '<span style="color:#64748b;">No direct A records resolved</span>'}
          ${(dns.ipv6 && dns.ipv6.length > 0) ? dns.ipv6.map(ip6 => `<span class="recon-tag">${ip6}</span>`).join('') : ''}
        </div>
        ${(dns.cname && dns.cname.length > 0) ? `
          <div style="margin-top:8px;"><strong>CNAME Aliases:</strong></div>
          <div class="recon-pill-row">${dns.cname.map(cn => `<span class="recon-tag">${cn}</span>`).join('')}</div>
        ` : ''}
      </div>
    </div>

    <div class="recon-box">
      <div class="recon-box-title">Domain Email Security (SPF & DMARC)</div>
      <div class="recon-list">
        <div>SPF Record: <strong style="color: ${dns.hasSpf ? '#10b981' : '#f59e0b'};">${dns.hasSpf ? 'Configured (v=spf1)' : 'Missing SPF Policy'}</strong></div>
        <div>DMARC Enforcement: <strong style="color: ${dns.hasDmarc ? '#10b981' : '#ef4444'};">${dns.hasDmarc ? 'Active & Validated' : 'Missing DMARC Record'}</strong></div>
        <div style="margin-top:8px;"><strong>Mail Exchangers (MX):</strong></div>
        <div class="recon-pill-row">
          ${(dns.mxRecords && dns.mxRecords.length > 0) ? dns.mxRecords.map(mx => `<span class="recon-tag">${mx}</span>`).join('') : '<span style="color:#64748b;">No public MX records</span>'}
        </div>
      </div>
    </div>

    <div class="recon-box">
      <div class="recon-box-title">Detected Server & Edge Stack</div>
      <div class="recon-list">
        <div class="recon-pill-row">
          ${info.technologies.map(t => `<span class="recon-tag" style="color:#00ff88; border-color:rgba(0,255,136,0.3);">${t}</span>`).join('')}
        </div>
        <div style="margin-top:10px;">HTTP Response Code: <strong style="color:#38bdf8;">${info.statusCode || '200 OK'}</strong></div>
        <div>Target Scheme & Port: <strong>${info.targetUrl.startsWith('https') ? 'HTTPS / 443' : 'HTTP / 80'}</strong></div>
      </div>
    </div>

    <div class="recon-box">
      <div class="recon-box-title">Discovered Client Scripts & Dependencies (${scripts.length})</div>
      <div class="recon-list">
        ${scripts.length > 0 ? scripts.map(s => `<div class="recon-tag" style="color:#cbd5e1; font-size:10px;">${escapeHtml(s)}</div>`).join('') : '<div style="color:#64748b;">No external script references discovered</div>'}
      </div>
    </div>
  `;
}

// Render Full Pen-Test Tab
function renderPentestChecks() {
  const container = document.getElementById('pentestChecksContainer');
  if (!container || !currentScanData) return;

  const checks = currentScanData.pentestChecks || [];
  if (checks.length === 0) {
    container.innerHTML = `<div class="empty-state">No pen-test checks available. Run a scan first.</div>`;
    return;
  }

  container.innerHTML = checks.map(c => `
    <div class="pentest-row">
      <div class="pentest-left">
        <span class="pentest-id">${c.id}</span>
        <div class="pentest-info">
          <div class="pentest-name">${escapeHtml(c.name)}</div>
          <div class="pentest-details">${escapeHtml(c.details)}</div>
        </div>
      </div>
      <span class="pentest-status ${c.status.toLowerCase()}">${c.status}</span>
    </div>
  `).join('');
}

// Inspect & Fix Modal
let currentInspectIndex = null;
const inspectModal = document.getElementById('inspectModal');
const modalSevBadge = document.getElementById('modalSevBadge');
const modalVulnTitle = document.getElementById('modalVulnTitle');
const modalCwe = document.getElementById('modalCwe');
const modalOwasp = document.getElementById('modalOwasp');
const modalEndpoint = document.getElementById('modalEndpoint');
const modalStatus = document.getElementById('modalStatus');
const modalDescription = document.getElementById('modalDescription');
const modalImpact = document.getElementById('modalImpact');
const modalEvidence = document.getElementById('modalEvidence');
const modalRemediationSummary = document.getElementById('modalRemediationSummary');
const modalCodeSnippet = document.getElementById('modalCodeSnippet');

function openInspectModal(index) {
  if (!currentScanData || !currentScanData.vulnerabilities[index]) return;
  const vuln = currentScanData.vulnerabilities[index];
  currentInspectIndex = index;

  modalSevBadge.className = `modal-sev-badge ${vuln.severity.toLowerCase()}`;
  modalSevBadge.textContent = vuln.severity;
  modalVulnTitle.textContent = vuln.name;
  modalCwe.textContent = vuln.cwe || 'CWE-Unknown';
  modalOwasp.textContent = vuln.category || 'OWASP Top 10';
  modalEndpoint.textContent = vuln.endpoint || '/';
  modalStatus.textContent = `${vuln.status} (${vuln.status === 'Patched' ? 'Resolved' : 'Requires Attention'})`;
  modalStatus.className = `meta-value ${vuln.status === 'Patched' ? 'status-patched' : 'status-open'}`;

  modalDescription.textContent = vuln.description || '';
  modalImpact.textContent = vuln.impact || '';
  modalEvidence.textContent = vuln.evidence || 'No raw evidence captured.';
  modalRemediationSummary.textContent = vuln.remediation?.summary || 'Apply the recommended configuration.';
  modalCodeSnippet.textContent = vuln.remediation?.codeSnippet || '// Configuration snippet not provided.';

  inspectModal.style.display = 'flex';
}

function closeInspectModal() {
  inspectModal.style.display = 'none';
  currentInspectIndex = null;
}

function copySnippet() {
  const code = modalCodeSnippet.textContent;
  navigator.clipboard.writeText(code).then(() => {
    alert('Remediation code snippet copied to clipboard!');
  }).catch(() => {
    alert('Copied snippet.');
  });
}

function markAsResolved() {
  if (currentInspectIndex !== null && currentScanData?.vulnerabilities[currentInspectIndex]) {
    currentScanData.vulnerabilities[currentInspectIndex].status = 'Patched';
    renderVulnTable(currentScanData.vulnerabilities);
    closeInspectModal();
  }
}

// Export Reports
function printReport() {
  if (!currentScanData) {
    alert('Please execute a scan first before generating a report.');
    return;
  }
  window.print();
}

function downloadJsonReport() {
  if (!currentScanData) {
    alert('Please execute a scan first before exporting JSON.');
    return;
  }
  const blob = new Blob([JSON.stringify(currentScanData, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `cyberprobe-report-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// Quick Header Check
checkHeadersNowBtn?.addEventListener('click', () => {
  const target = targetUrlInput.value.trim();
  if (target) {
    startScan(target);
  }
});

startScanBtn?.addEventListener('click', () => {
  startScan();
});

// Auto-run or load default target on page load for immediate working experience
window.addEventListener('DOMContentLoaded', () => {
  // Pre-load default target
  const defaultTarget = 'https://example.com';
  targetUrlInput.value = defaultTarget;
  activeScanningTarget.textContent = defaultTarget;

  // Run initial real scan in background
  startScan(defaultTarget);
});
