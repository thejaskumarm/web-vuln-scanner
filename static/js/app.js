/* ════════════════════════════════════════════════
   Web Vulnerability Scanner — Frontend Logic
   Handles form submission, SSE streaming, and
   real-time UI updates.
   ════════════════════════════════════════════════ */

'use strict';

// ── DOM references ────────────────────────────────
const form        = document.getElementById('scan-form');
const urlInput    = document.getElementById('url-input');
const scanBtn     = document.getElementById('scan-btn');
const formError   = document.getElementById('form-error');
const scanPanel   = document.getElementById('scan-panel');
const targetUrl   = document.getElementById('target-url');
const targetStatus = document.getElementById('target-status');
const targetDot   = document.getElementById('target-dot');
const progressFill   = document.getElementById('progress-fill');
const progressLabel  = document.getElementById('progress-label');
const progressPct    = document.getElementById('progress-pct');
const progressTrack  = document.getElementById('progress-track');
const checkSteps  = document.getElementById('check-steps');
const resultsGrid = document.getElementById('results-grid');
const summaryCard = document.getElementById('summary-card');
const summaryIcon  = document.getElementById('summary-icon');
const summaryTitle = document.getElementById('summary-title');
const summaryDesc  = document.getElementById('summary-desc');
const resetBtn    = document.getElementById('reset-btn');
const downloadBtn = document.getElementById('download-btn');

// ── State ─────────────────────────────────────────
let eventSource = null;
let totalChecks = 10;
let completedChecks = 0;
let scanResults = [];    // accumulates result objects for report download
let scanUrl = '';        // target URL for the report
let scanElapsed = 0;     // scan duration in seconds

const CHECK_LABELS = [
  '', // 0-indexed padding
  'Headers',
  'HTTPS',
  'Files',
  'Cookies',
  'CSRF',
  'Disclosure',
  'XSS',
  'SQLi',
  'Redirect',
  'Dir List',
];

// ── Helpers ───────────────────────────────────────
function setProgress(pct, label) {
  progressFill.style.width = pct + '%';
  progressTrack.setAttribute('aria-valuenow', pct);
  progressLabel.textContent = label;
  progressPct.textContent   = Math.round(pct) + '%';
}

function showError(msg) {
  formError.textContent = msg;
  formError.hidden = false;
}
function clearError() {
  formError.textContent = '';
  formError.hidden = true;
}

function setBtnLoading(loading) {
  if (loading) {
    scanBtn.disabled = true;
    scanBtn.innerHTML = `<span class="spinner" aria-hidden="true"></span><span class="scan-form__btn-text">Scanning…</span>`;
  } else {
    scanBtn.disabled = false;
    scanBtn.innerHTML = `<span class="scan-form__btn-text">Scan Now</span><span class="scan-form__btn-icon" aria-hidden="true">→</span>`;
  }
}

function buildCheckSteps(total) {
  checkSteps.innerHTML = '';
  for (let i = 1; i <= total; i++) {
    const span = document.createElement('span');
    span.className = 'check-step';
    span.id = `step-${i}`;
    span.textContent = `${i}. ${CHECK_LABELS[i] || 'Check ' + i}`;
    checkSteps.appendChild(span);
  }
}

function setStepActive(num) {
  // Reset previous active
  document.querySelectorAll('.check-step.active').forEach(el => el.classList.remove('active'));
  const el = document.getElementById(`step-${num}`);
  if (el) el.classList.add('active');
}

function setStepDone(num, hasIssues) {
  const el = document.getElementById(`step-${num}`);
  if (!el) return;
  el.classList.remove('active');
  el.classList.add(hasIssues ? 'done-vuln' : 'done-ok');
  el.textContent = (hasIssues ? '✘ ' : '✔ ') + `${num}. ${CHECK_LABELS[num] || 'Check ' + num}`;
}

function renderResultCard(data) {
  const hasIssues = data.issues && data.issues.length > 0;
  const card = document.createElement('div');
  card.className = `result-card ${hasIssues ? 'result-card--vuln' : 'result-card--ok'}`;
  card.id = `result-card-${data.check}`;
  card.style.animationDelay = `${(data.check - 1) * 0.04}s`;

  const issuesHTML = hasIssues
    ? `<ul class="result-card__issues" aria-label="Issues found">
        ${data.issues.map(issue => `
          <li class="result-card__issue">
            <span class="result-card__issue-text">${escHtml(String(issue))}</span>
            <button class="copy-btn" title="Copy to clipboard" aria-label="Copy finding">📋</button>
          </li>`).join('')}
      </ul>`
    : `<p class="result-card__ok-msg">✔ No issues found</p>`;

  card.innerHTML = `
    <div class="result-card__header">
      <div class="result-card__title-wrap">
        <span class="result-card__num" aria-hidden="true">${data.check}</span>
        <span class="result-card__title">${escHtml(data.title)}</span>
      </div>
      <div class="result-card__badges">
        <span class="badge-owasp" aria-label="OWASP category">${escHtml(data.owasp)}</span>
        <span class="badge-status ${hasIssues ? 'badge-status--vuln' : 'badge-status--ok'}">
          ${hasIssues ? `${data.issues.length} issue${data.issues.length > 1 ? 's' : ''}` : 'Secure'}
        </span>
      </div>
    </div>
    <div class="result-card__body">${issuesHTML}</div>
  `;

  // Wire up copy buttons
  card.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const text = btn.previousElementSibling.textContent.trim();
      navigator.clipboard.writeText(text).then(() => {
        btn.classList.add('copied');
        btn.textContent = '✔';
        setTimeout(() => { btn.classList.remove('copied'); btn.textContent = '📋'; }, 1500);
      }).catch(() => { btn.textContent = '!'; });
    });
  });

  resultsGrid.appendChild(card);
}

function showSummary(totalIssues, elapsed) {
  summaryCard.hidden = false;
  let level, icon, title, desc;

  if (totalIssues === 0) {
    level = 'low'; icon = '🎉';
    title = 'Looking good! No major issues found.';
    desc  = 'Your website passed all checks. Keep monitoring regularly and stay up-to-date with security best practices.';
  } else if (totalIssues <= 3) {
    level = 'medium'; icon = '⚠️';
    title = `${totalIssues} issue${totalIssues > 1 ? 's' : ''} found — review recommended.`;
    desc  = 'A few improvements are needed. Review the flagged items above and apply fixes to strengthen your security posture.';
  } else {
    level = 'high'; icon = '🚨';
    title = `${totalIssues} issues found — action required.`;
    desc  = 'Significant vulnerabilities were detected. Address these findings as soon as possible to protect your users and data.';
  }

  if (elapsed) desc += ` Scan completed in ${elapsed}s.`;

  summaryCard.className = `summary-card summary-card--${level}`;
  summaryIcon.textContent  = icon;
  summaryTitle.textContent = title;
  summaryDesc.textContent  = desc;
}

function escHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function resetUI() {
  // Close any active stream
  if (eventSource) { eventSource.close(); eventSource = null; }

  // Reset state
  scanResults = []; scanUrl = ''; scanElapsed = 0;

  // Reset form
  urlInput.value = '';
  clearError();
  setBtnLoading(false);

  // Hide scan panel
  scanPanel.hidden = true;
  summaryCard.hidden = true;
  resultsGrid.innerHTML = '';
  checkSteps.innerHTML  = '';
  setProgress(0, 'Initializing…');
  completedChecks = 0;

  // Scroll to top
  window.scrollTo({ top: 0, behavior: 'smooth' });
  urlInput.focus();
}

// ── Form submit ───────────────────────────────────
form.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearError();

  const rawUrl = urlInput.value.trim();
  if (!rawUrl) {
    showError('Please enter a URL to scan.');
    urlInput.focus();
    return;
  }

  // Normalise URL
  let url = rawUrl;
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

  // Basic validation
  try { new URL(url); } catch {
    showError('That doesn\'t look like a valid URL. Example: https://example.com');
    return;
  }

  startScan(url);
});

// ── Reset button ──────────────────────────────────
resetBtn.addEventListener('click', resetUI);

// ── Start scan via SSE ────────────────────────────
function startScan(url) {
  setBtnLoading(true);
  completedChecks = 0;

  // Show panel
  scanPanel.hidden = false;
  summaryCard.hidden = true;
  resultsGrid.innerHTML = '';
  checkSteps.innerHTML  = '';
  scanResults = [];
  scanUrl = url;
  setProgress(0, 'Connecting…');
  targetUrl.textContent = url;
  targetStatus.textContent = '';
  targetDot.className = 'target-bar__dot';
  buildCheckSteps(10);

  // Scroll to panel
  setTimeout(() => {
    scanPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 100);

  // Open SSE connection
  if (eventSource) eventSource.close();
  eventSource = new EventSource(`/scan?url=${encodeURIComponent(url)}`);

  eventSource.onmessage = (e) => {
    let msg;
    try { msg = JSON.parse(e.data); } catch { return; }

    const { type, data } = msg;

    switch (type) {

      case 'start':
        totalChecks = data.total_checks || 10;
        setProgress(2, 'Starting scan…');
        break;

      case 'connected':
        targetStatus.textContent = `HTTP ${data.status}`;
        targetStatus.style.display = 'inline';
        break;

      case 'progress':
        setStepActive(data.check);
        const pct = (data.check / (totalChecks + 1)) * 100;
        setProgress(pct, data.label);
        break;

      case 'result':
        completedChecks++;
        scanResults.push(data);   // store for report download
        const hasIssues = data.issues && data.issues.length > 0;
        setStepDone(data.check, hasIssues);
        renderResultCard(data);
        const donePct = (completedChecks / totalChecks) * 100;
        setProgress(donePct, `Completed check ${data.check} of ${totalChecks}`);
        break;

      case 'done':
        // All done
        scanElapsed = data.elapsed || 0;
        setProgress(100, 'Scan complete ✔');
        targetDot.className = 'target-bar__dot done';
        setBtnLoading(false);
        showSummary(data.total_issues, data.elapsed);
        eventSource.close();
        eventSource = null;
        break;

      case 'error':
        setProgress(0, 'Scan failed');
        targetDot.className = 'target-bar__dot error';
        showError(data.message || 'Scan failed. Check the URL and try again.');
        setBtnLoading(false);
        eventSource.close();
        eventSource = null;
        break;
    }
  };

  eventSource.onerror = () => {
    if (eventSource && eventSource.readyState === EventSource.CLOSED) return; // normal close after done
    showError('Connection lost. The scan may have timed out.');
    setBtnLoading(false);
    targetDot.className = 'target-bar__dot error';
    if (eventSource) { eventSource.close(); eventSource = null; }
  };
}

// ── Keyboard shortcut: Enter in input ─────────────
urlInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') form.requestSubmit();
});

// ── Download Report ───────────────────────────────
downloadBtn.addEventListener('click', () => {
  const html = generateReport();
  const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  const host = (() => { try { return new URL(scanUrl).hostname.replace(/\W/g, '_'); } catch { return 'report'; } })();
  a.download = `vuln_report_${host}.html`;
  a.click();
  URL.revokeObjectURL(a.href);
});

function generateReport() {
  const ts = new Date().toLocaleString();
  const total = scanResults.reduce((s, r) => s + (r.issues ? r.issues.length : 0), 0);
  const riskLabel = total === 0 ? 'LOW RISK' : total <= 3 ? 'MEDIUM RISK' : 'HIGH RISK';
  const riskColor = total === 0 ? '#10b981' : total <= 3 ? '#f59e0b' : '#ef4444';

  const cards = scanResults.map(r => {
    const body = r.issues && r.issues.length
      ? `<ul>${r.issues.map(i => `<li>${escHtml(String(i))}</li>`).join('')}</ul>`
      : `<p class="ok">✔ No issues found</p>`;
    return `
      <div class="card">
        <h2>${escHtml(r.title)} <span class="owasp">${escHtml(r.owasp)}</span></h2>
        ${body}
      </div>`;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Scan Report – ${escHtml(scanUrl)}</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:'Segoe UI',system-ui,sans-serif;background:#080b14;color:#e2e8f0;padding:2rem}
    h1{font-size:2rem;color:#4f8ef7;margin-bottom:.25rem}
    .sub{color:#64748b;margin-bottom:2rem;font-size:.9rem}
    .meta{background:#0e1321;border:1px solid #1e2d4a;border-radius:12px;padding:1.5rem;margin-bottom:2rem}
    .meta p{margin:.4rem 0}.meta strong{color:#4f8ef7}
    .badge{display:inline-block;padding:.4rem 1.2rem;border-radius:999px;font-weight:700;font-size:.85rem;
      background:${riskColor}22;color:${riskColor};border:1px solid ${riskColor};margin-top:.5rem}
    .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(400px,1fr));gap:1.5rem}
    .card{background:#0e1321;border:1px solid #1e2d4a;border-radius:12px;padding:1.5rem}
    .card h2{font-size:1rem;color:#93c5fd;margin-bottom:1rem;display:flex;align-items:center;gap:.5rem}
    .owasp{font-size:.65rem;background:#7c3aed20;border:1px solid #7c3aed55;color:#a78bfa;
      padding:.15rem .45rem;border-radius:999px;font-weight:700}
    ul{list-style:none}
    li{padding:.4rem .75rem;margin:.3rem 0;background:#ef444415;color:#fca5a5;
      border-radius:0 6px 6px 0;font-size:.88rem;border-left:3px solid #ef4444}
    .ok{color:#10b981;font-size:.9rem;padding:.4rem 0}
    .footer{text-align:center;margin-top:3rem;color:#334155;font-size:.85rem}
    a{color:#4f8ef7}
  </style>
</head>
<body>
  <h1>🔍 Web Vulnerability Report</h1>
  <p class="sub">Generated by VulnScan · OWASP Top 10</p>
  <div class="meta">
    <p><strong>Target:</strong> <a href="${escHtml(scanUrl)}" target="_blank">${escHtml(scanUrl)}</a></p>
    <p><strong>Scanned At:</strong> ${ts}</p>
    <p><strong>Total Issues Found:</strong> ${total}</p>
    ${scanElapsed ? `<p><strong>Scan Duration:</strong> ${scanElapsed}s</p>` : ''}
    <div class="badge">${riskLabel} — ${total} issue(s)</div>
  </div>
  <div class="grid">${cards}</div>
  <div class="footer">
    <p>🔗 <a href="https://owasp.org/www-project-top-ten/" target="_blank">OWASP Top 10</a></p>
    <p style="margin-top:.5rem">⚠ For educational purposes only. Only scan sites you own or have permission to test.</p>
  </div>
</body>
</html>`;
}

