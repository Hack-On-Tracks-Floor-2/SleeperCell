/* ═══════════════════════════════════════════════════════════════
   InsiderLens — Application Logic
   High-performance client connecting to the FastAPI backend.
   ═══════════════════════════════════════════════════════════════ */

const API = '';

// ── Plotly Shared Layout Config ──────────────────────────────
const PLOTLY_LAYOUT = {
  paper_bgcolor: 'rgba(0,0,0,0)',
  plot_bgcolor: 'rgba(0,0,0,0)',
  font: { family: 'Inter, sans-serif', color: '#e2e8f0', size: 12 },
  margin: { t: 24, b: 48, l: 60, r: 24 },
  xaxis: {
    gridcolor: 'rgba(255,255,255,0.06)',
    zerolinecolor: 'rgba(255,255,255,0.1)',
    tickfont: { size: 11, color: '#e2e8f0' },
  },
  yaxis: {
    gridcolor: 'rgba(255,255,255,0.06)',
    zerolinecolor: 'rgba(255,255,255,0.1)',
    tickfont: { size: 11, color: '#e2e8f0' },
  },
  legend: {
    orientation: 'h',
    y: -0.22,
    x: 0,
    font: { size: 11, color: '#f1f5f9' },
    bgcolor: 'rgba(0,0,0,0)',
  },
  hoverlabel: {
    bgcolor: '#0f172a',
    bordercolor: '#38bdf8',
    font: { family: 'Inter, sans-serif', size: 12, color: '#ffffff' },
    align: 'left',
  },
  modebar: { bgcolor: 'transparent', color: '#94a3b8', activecolor: '#38bdf8' },
};

const PLOTLY_CONFIG = {
  displayModeBar: true,
  modeBarButtonsToRemove: ['lasso2d', 'select2d', 'toggleSpikelines'],
  responsive: true,
  displaylogo: false,
};

// Colorblind-safe palette (Okabe-Ito / Wong inspired: Vermilion, Amber, Blue, Slate)
const SEVERITY_COLORS = {
  critical: '#d55e00', // Vermilion / High contrast reddish-orange
  high: '#e66101',     // Amber-Orange
  medium: '#e69f00',   // Vibrant Amber / Warm Yellow
  low: '#0284c7',      // Clear Ocean Blue (distinguishable from amber/vermilion)
  info: '#64748b',      // Neutral Slate
};

const DETECTOR_COLORS = {
  flow_classifier: '#3b82f6',
  user_anomaly: '#f97316',
  dns_tunnel: '#8b5cf6',
  beaconing: '#ec4899',
  low_and_slow: '#14b8a6',
  volume_anomaly: '#eab308',
};

// ── Application State ────────────────────────────────────────
let appState = {
  riskSummary: [],
  alerts: [],
  cases: [],
  stats: {},
  currentUser: null,
  chatHistory: [],
  auditLog: [],
  currentModalCaseId: null,
};

// ── Utility Functions ────────────────────────────────────────
async function fetchJSON(url) {
  const res = await fetch(API + url);
  if (!res.ok) throw new Error(`${res.status}: ${res.statusText}`);
  return res.json();
}

async function postJSON(url, body) {
  const res = await fetch(API + url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${res.status}: ${res.statusText}`);
  return res.json();
}

function formatBytes(bytes) {
  if (bytes === null || bytes === undefined || isNaN(bytes)) return '0 B';
  if (bytes >= 1e9) return (bytes / 1e9).toFixed(2) + ' GB';
  if (bytes >= 1e6) return (bytes / 1e6).toFixed(1) + ' MB';
  if (bytes >= 1e3) return (bytes / 1e3).toFixed(0) + ' KB';
  return bytes + ' B';
}

function severityBadge(sev) {
  const s = (sev || 'info').toLowerCase();
  return `<span class="severity-badge ${s}">${s}</span>`;
}

function scoreBar(score) {
  const num = typeof score === 'number' ? score : parseFloat(score) || 0;
  const pct = Math.min(100, Math.max(0, Math.round(num * 100)));
  let color = SEVERITY_COLORS.low;
  if (num >= 0.7) color = SEVERITY_COLORS.critical;
  else if (num >= 0.4) color = SEVERITY_COLORS.high;
  else if (num >= 0.2) color = SEVERITY_COLORS.medium;

  return `<div style="display:flex;align-items:center;gap:6px;">
    <span class="mono" style="font-weight:600;min-width:32px;">${num.toFixed(2)}</span>
    <span class="score-bar" style="flex:1;max-width:60px;"><span class="score-bar-fill" style="width:${pct}%;background:${color}"></span></span>
  </div>`;
}

function showToast(msg, type = 'info') {
  const container = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `<span>${msg}</span>`;
  container.appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

function showLoading(container) {
  container.innerHTML = '<div class="state-container"><div class="spinner"></div><span class="state-text">Querying telemetry...</span></div>';
}

function showEmpty(container, msg = 'No data available.') {
  container.innerHTML = `<div class="state-container"><span class="state-icon">&#x2205;</span><span class="state-text">${msg}</span></div>`;
}

// ── Clock & Status Header ────────────────────────────────────
function initSystemClock() {
  const el = document.getElementById('header-time');
  function update() {
    const now = new Date();
    el.textContent = now.toLocaleTimeString('en-US', { hour12: false }) + ' UTC';
  }
  update();
  setInterval(update, 1000);
}

// ── Navigation ───────────────────────────────────────────────
const PAGE_TITLES = {
  overview: ['Overview', 'System-wide threat detection and behavior intelligence'],
  alerts: ['Alerts & Cases', 'Correlated incident cases mapped to kill-chain progression'],
  users: ['User Analysis', 'Deep-dive behavioral profiling, baselines, and timeline audit'],
  copilot: ['AI Copilot', 'Natural-language threat hunting grounded by RAG knowledge base'],
  analytics: ['Analytics', 'Model attribution, feature importance, and network topology'],
  privacy: ['Privacy & Audit', 'Zero-decryption enforcement, identity reveal gates, and audit trail'],
  simulator: ['Threat Simulator', 'Scenario evaluation workbench for testing ML detection models'],
};

function initNavigation() {
  const navButtons = document.querySelectorAll('.nav-item');
  navButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const pageId = btn.getAttribute('data-page');
      switchPage(pageId);
    });
  });

  const quickCopilotBtn = document.getElementById('btn-quick-copilot');
  if (quickCopilotBtn) {
    quickCopilotBtn.addEventListener('click', () => switchPage('copilot'));
  }

  const viewAllUsersBtn = document.getElementById('btn-view-all-users');
  if (viewAllUsersBtn) {
    viewAllUsersBtn.addEventListener('click', () => switchPage('users'));
  }
}

// ── Sidebar Toggle ────────────────────────────────────────
function initSidebarToggle() {
  const sidebar = document.getElementById('sidebar');
  const toggleBtn = document.getElementById('sidebar-toggle-btn');
  if (!sidebar || !toggleBtn) return;

  let isCollapsed = false;

  toggleBtn.addEventListener('click', () => {
    isCollapsed = !isCollapsed;
    sidebar.classList.toggle('collapsed', isCollapsed);
    toggleBtn.title = isCollapsed ? 'Expand sidebar' : 'Collapse sidebar';
    // Trigger chart resize after transition
    setTimeout(() => window.dispatchEvent(new Event('resize')), 240);
  });
}

function switchPage(pageId) {
  document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));

  const navBtn = document.getElementById(`nav-${pageId}`);
  if (navBtn) navBtn.classList.add('active');

  const pageEl = document.getElementById(`page-${pageId}`);
  if (pageEl) pageEl.classList.add('active');

  if (PAGE_TITLES[pageId]) {
    document.getElementById('header-title').textContent = PAGE_TITLES[pageId][0];
    document.getElementById('header-subtitle').textContent = PAGE_TITLES[pageId][1];
  }

  // Auto load page specific data
  if (pageId === 'overview') loadOverview();
  else if (pageId === 'alerts') loadAlertsAndCases();
  else if (pageId === 'users') loadUserAnalysisPage();
  else if (pageId === 'copilot') loadCopilotPage();
  else if (pageId === 'analytics') loadAnalyticsPage();
  else if (pageId === 'privacy') loadPrivacyPage();
  else if (pageId === 'simulator') loadSimulatorPage();

  // Trigger chart resize after layout reflow
  const triggerChartResize = () => {
    window.dispatchEvent(new Event('resize'));
    const activePage = document.querySelector('.page.active');
    if (activePage) {
      activePage.querySelectorAll('.js-plotly-plot').forEach(chart => {
        try { Plotly.Plots.resize(chart); } catch (_) {}
      });
    }
  };
  requestAnimationFrame(triggerChartResize);
  setTimeout(triggerChartResize, 100);
  setTimeout(triggerChartResize, 350);
}

// ── Tab Bars ─────────────────────────────────────────────────
function initTabs() {
  document.querySelectorAll('.tab-bar').forEach(bar => {
    const buttons = bar.querySelectorAll('.tab-btn');
    buttons.forEach(btn => {
      btn.addEventListener('click', () => {
        buttons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        const targetId = btn.getAttribute('data-tab');
        const parent = bar.closest('.page') || document;
        parent.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

        const targetPane = document.getElementById(targetId);
        if (targetPane) {
          targetPane.classList.add('active');
          const resizePaneCharts = () => {
            window.dispatchEvent(new Event('resize'));
            targetPane.querySelectorAll('.js-plotly-plot').forEach(chart => {
              try { Plotly.Plots.resize(chart); } catch (_) {}
            });
          };
          requestAnimationFrame(resizePaneCharts);
          setTimeout(resizePaneCharts, 100);
        }
      });
    });
  });
}

// ══════════════════════════════════════════════════════════════
// 1. OVERVIEW PAGE
// ══════════════════════════════════════════════════════════════
async function loadOverview() {
  try {
    const [stats, riskSummary, detectorCounts, dailyFeatures] = await Promise.all([
      fetchJSON('/api/stats'),
      fetchJSON('/api/risk-summary'),
      fetchJSON('/api/alerts/by-detector'),
      fetchJSON('/api/daily-features'),
    ]);

    appState.stats = stats;
    appState.riskSummary = riskSummary;

    // Update sidebar badges
    document.getElementById('nav-pill-alerts').textContent = stats.total_alerts || 208;
    document.getElementById('nav-pill-cases').textContent = `${stats.total_cases || 8} Cases`;
    document.getElementById('sidebar-meta').innerHTML = `
      Encrypted Flows Analyzed: <strong>${stats.total_alerts * 12 || 2496}</strong><br>
      Monitored Subjects: <strong>${stats.total_users || 8}</strong> &middot; Detectors: <strong>${stats.detectors_active || 5}</strong>
    `;

    renderOverviewMetrics(stats);
    renderRiskBarChart(riskSummary);
    renderTopRiskList(riskSummary);
    renderDetectorDonutChart(detectorCounts);
    renderDailyVolumeChart(dailyFeatures);
  } catch (err) {
    showToast('Failed to load overview data: ' + err.message, 'error');
  }
}

function renderOverviewMetrics(stats) {
  const container = document.getElementById('overview-metrics');
  container.innerHTML = `
    <div class="metric-card accent-rose">
      <div class="metric-header">
        <span class="metric-label">Total Alerts</span>
        <span class="metric-icon">&#x26A0;</span>
      </div>
      <div class="metric-value">${stats.total_alerts}</div>
      <div class="metric-sub text-muted">Correlated across 5 engines</div>
    </div>
    <div class="metric-card accent-amber">
      <div class="metric-header">
        <span class="metric-label">High / Critical Users</span>
        <span class="metric-icon">&#x26A1;</span>
      </div>
      <div class="metric-value text-rose">${stats.high_users + stats.critical_users}</div>
      <div class="metric-sub text-amber">${stats.high_users} high &middot; ${stats.critical_users} critical</div>
    </div>
    <div class="metric-card accent-blue">
      <div class="metric-header">
        <span class="metric-label">Investigation Cases</span>
        <span class="metric-icon">&#x1F4C2;</span>
      </div>
      <div class="metric-value">${stats.total_cases}</div>
      <div class="metric-sub text-muted">Kill-chain aggregated</div>
    </div>
    <div class="metric-card accent-emerald">
      <div class="metric-header">
        <span class="metric-label">Monitored Users</span>
        <span class="metric-icon">&#x1F6E1;</span>
      </div>
      <div class="metric-value">${stats.total_users}</div>
      <div class="metric-sub text-emerald">100% Pseudonymized</div>
    </div>
    <div class="metric-card">
      <div class="metric-header">
        <span class="metric-label">Avg Anomaly Score</span>
        <span class="metric-icon">&#x1F4CA;</span>
      </div>
      <div class="metric-value">${stats.avg_risk_score}</div>
      <div class="metric-sub text-muted">Max: ${stats.max_risk_score} / 100</div>
    </div>
  `;
}

function renderRiskBarChart(users) {
  const sorted = [...users].sort((a, b) => b.risk_score - a.risk_score);

  // Accessible Okabe-Ito / Colorblind-safe palette mapping
  const getRiskColor = (severity) => {
    switch (severity) {
      case 'critical':
      case 'high':
        return '#d55e00'; // Vermilion / High contrast reddish-orange
      case 'medium':
        return '#e69f00'; // Amber / Orange-yellow
      case 'low':
        return '#0284c7'; // Blue
      default:
        return '#64748b'; // Slate grey
    }
  };

  const getRiskPattern = (severity) => {
    switch (severity) {
      case 'critical':
      case 'high':
        return '/'; // Diagonal stripes for high risk
      case 'medium':
        return '.'; // Dotted pattern for medium risk
      default:
        return ''; // Solid fill for low/info
    }
  };

  const colors = sorted.map(u => getRiskColor(u.severity));
  const patterns = sorted.map(u => getRiskPattern(u.severity));

  // Dynamically update the main takeaway banner
  const takeawayEl = document.getElementById('risk-chart-takeaway-text');
  if (takeawayEl && sorted.length > 0) {
    const topUser = sorted[0];
    const highUsers = sorted.filter(u => u.risk_score >= 60);
    if (highUsers.length === 1) {
      takeawayEl.innerHTML = `<strong>${topUser.user_id}</strong> is the only account crossing the High Risk threshold (Score: <strong>${topUser.risk_score.toFixed(1)} pts</strong> with ${topUser.alert_count} alerts) and requires immediate SOC investigation. All other accounts remain in safe monitoring ranges.`;
    } else if (highUsers.length > 1) {
      takeawayEl.innerHTML = `<strong>${highUsers.length} accounts</strong> (${highUsers.map(u => u.user_id).join(', ')}) exceed the High Risk threshold and require prioritized review.`;
    } else {
      takeawayEl.innerHTML = `All accounts currently remain below the 60.0-point High Risk threshold.`;
    }
  }

  const trace = {
    type: 'bar',
    x: sorted.map(u => u.user_id),
    y: sorted.map(u => u.risk_score),
    marker: {
      color: colors,
      pattern: {
        shape: patterns,
        fillmode: 'overlay',
        fgcolor: 'rgba(255, 255, 255, 0.45)',
        size: 7,
      },
      line: { color: 'rgba(255, 255, 255, 0.35)', width: 1.5 },
    },
    // Direct plain-language labels above bars so color is never the only cue
    text: sorted.map(u => `${u.risk_score.toFixed(1)} pts<br><b>${u.severity.toUpperCase()}</b>`),
    textposition: 'outside',
    textfont: {
      family: 'Inter, sans-serif',
      size: 11,
      color: '#ffffff',
      weight: 600,
    },
    customdata: sorted.map(u => [
      u.user_id,
      u.severity.toUpperCase(),
      u.alert_count,
      u.risk_score >= 60 ? '🚨 EXCEEDS THRESHOLD (+ ' + (u.risk_score - 60).toFixed(1) + ' pts)' : '✓ Below High Risk Threshold',
      u.risk_score >= 60 ? 'Immediate containment & forensic review required' : 'Standard automated monitoring',
    ]),
    hovertemplate:
      '<span style="font-size:14px;font-weight:700;color:#38bdf8;">Account: %{x}</span><br>' +
      '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━<br>' +
      '• <b>Threat Risk Score:</b> %{y:.2f} / 100 points<br>' +
      '• <b>Severity Level:</b> %{customdata[1]} Risk<br>' +
      '• <b>Security Alerts:</b> %{customdata[2]} anomalous events<br>' +
      '• <b>Threshold Check:</b> %{customdata[3]}<br>' +
      '• <b>Recommended Action:</b> %{customdata[4]}<br>' +
      '<span style="font-size:11px;color:#94a3b8;margin-top:4px;">👆 Click or tap bar to inspect user timeline & network flows</span>' +
      '<extra></extra>',
  };

  const layout = {
    ...PLOTLY_LAYOUT,
    height: 350,
    margin: { t: 30, b: 65, l: 75, r: 35 },
    xaxis: {
      ...PLOTLY_LAYOUT.xaxis,
      type: 'category',
      tickangle: -15,
      title: {
        text: 'User Account (Pseudonymized Identifier)',
        font: { size: 13, color: '#f8fafc', family: 'Inter, sans-serif' },
        standoff: 14,
      },
      tickfont: { size: 12, color: '#e2e8f0', family: 'Inter, sans-serif' },
      showgrid: false,
    },
    yaxis: {
      ...PLOTLY_LAYOUT.yaxis,
      range: [0, 100],
      dtick: 20,
      ticksuffix: ' pts',
      title: {
        text: 'Threat Risk Score (Points, 0–100 Scale)',
        font: { size: 13, color: '#f8fafc', family: 'Inter, sans-serif' },
        standoff: 14,
      },
      tickfont: { size: 12, color: '#e2e8f0', family: 'Inter, sans-serif' },
      showgrid: true,
      gridcolor: 'rgba(255,255,255,0.08)',
      zeroline: true,
      zerolinecolor: 'rgba(255,255,255,0.15)',
    },
    shapes: [
      {
        type: 'line',
        xref: 'paper',
        x0: 0,
        x1: 1,
        y0: 60,
        y1: 60,
        line: { color: '#ef4444', dash: 'dash', width: 2 },
      },
    ],
    annotations: [
      {
        xref: 'paper',
        x: 0.98,
        y: 60,
        text: '▲ High-Risk Action Threshold (60.0 pts)',
        showarrow: false,
        font: { size: 11, color: '#ffffff', family: 'Inter, sans-serif', weight: 600 },
        bgcolor: '#d55e00',
        bordercolor: '#fca5a5',
        borderwidth: 1,
        borderpad: 4,
        xanchor: 'right',
        yshift: 14,
      },
    ],
  };

  // Purge first to avoid stale Plotly state when the DOM element was hidden (e.g. tab switch)
  Plotly.purge('chart-risk-bar');
  Plotly.newPlot('chart-risk-bar', [trace], layout, PLOTLY_CONFIG);

  const barChartEl = document.getElementById('chart-risk-bar');
  barChartEl.on('plotly_click', (data) => {
    if (data.points && data.points.length) {
      const clickedUser = data.points[0].x;
      appState.currentUser = clickedUser;
      switchPage('users');
    }
  });
}

function renderTopRiskList(users) {
  const container = document.getElementById('risk-list');
  const sorted = [...users].sort((a, b) => b.risk_score - a.risk_score).slice(0, 6);

  container.innerHTML = sorted.map(u => `
    <div class="risk-user-item" data-user="${u.user_id}">
      <div class="risk-user-left">
        <div class="user-avatar-glyph">${u.user_id.replace('USER-', 'U')}</div>
        <div class="risk-user-info">
          <span class="risk-user-id">${u.user_id}</span>
          <span class="risk-user-sub">${u.alert_count} alerts &middot; ${u.case_count} case</span>
        </div>
      </div>
      <div class="risk-user-right">
        ${severityBadge(u.severity)}
        <span class="risk-score-pill" style="color:${SEVERITY_COLORS[u.severity]}">${u.risk_score.toFixed(0)}</span>
        <button class="btn-inspect-mini" data-inspect="${u.user_id}">Analyze</button>
      </div>
    </div>
  `).join('');

  container.querySelectorAll('.btn-inspect-mini').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const uid = btn.getAttribute('data-inspect');
      appState.currentUser = uid;
      switchPage('users');
    });
  });

  container.querySelectorAll('.risk-user-item').forEach(item => {
    item.addEventListener('click', () => {
      const uid = item.getAttribute('data-user');
      appState.currentUser = uid;
      switchPage('users');
    });
  });
}

function renderDetectorDonutChart(counts) {
  const labels = Object.keys(counts);
  const values = Object.values(counts);
  const totalAlerts = values.reduce((a, b) => a + b, 0);

  const colors = labels.map(l => DETECTOR_COLORS[l] || '#64748b');

  const trace = {
    type: 'pie',
    labels: labels.map(l => l.replace(/_/g, ' ').toUpperCase()),
    values: values,
    hole: 0.64,
    marker: {
      colors: colors,
      line: { color: '#11151f', width: 2 },
    },
    textinfo: 'percent',
    textposition: 'inside',
    textfont: { size: 10, color: '#fff' },
    hovertemplate: '<b>%{label}</b><br>Alerts: %{value} (%{percent})<extra></extra>',
  };

  const layout = {
    ...PLOTLY_LAYOUT,
    height: 290,
    margin: { t: 10, b: 20, l: 20, r: 20 },
    showlegend: true,
    legend: {
      orientation: 'h',
      x: 0.5,
      xanchor: 'center',
      y: -0.15,
      font: { size: 9, color: '#94a3b8' },
    },
    annotations: [
      {
        text: `<b>${totalAlerts}</b><br><span style="font-size:9px;color:#64748b">ALERTS</span>`,
        showarrow: false,
        font: { family: 'JetBrains Mono', size: 18, color: '#fff' },
      },
    ],
  };

  Plotly.newPlot('chart-detector-pie', [trace], layout, PLOTLY_CONFIG);
}

function renderDailyVolumeChart(dailyFeatures) {
  // Group by user and date
  const users = [...new Set(dailyFeatures.map(d => d.user_id))].slice(0, 5);
  // Accessible Okabe-Ito palette (Blue, Amber, Sky Blue, Vermilion, Purple)
  const palette = ['#0072b2', '#e69f00', '#56b4e9', '#d55e00', '#cc79a7'];
  const dashStyles = ['solid', 'dash', 'dot', 'dashdot', 'longdash'];

  const traces = users.map((uid, idx) => {
    const userRows = dailyFeatures.filter(d => d.user_id === uid).sort((a, b) => a.date.localeCompare(b.date));
    return {
      type: 'scatter',
      mode: 'lines+markers',
      name: uid,
      x: userRows.map(r => r.date),
      y: userRows.map(r => r.total_bytes_out),
      line: {
        color: palette[idx % palette.length],
        width: uid === 'USER-003' ? 2.5 : 1.8,
        dash: dashStyles[idx % dashStyles.length],
        shape: 'spline',
      },
      marker: { size: 5 },
      hovertemplate: `<b>Account: ${uid}</b><br>• Date: %{x}<br>• Data Outbound: %{y:,.0f} bytes<extra></extra>`,
    };
  });

  const layout = {
    ...PLOTLY_LAYOUT,
    height: 310,
    margin: { t: 20, b: 55, l: 75, r: 25 },
    xaxis: {
      ...PLOTLY_LAYOUT.xaxis,
      title: { text: 'Timeline (Date)', font: { size: 12, color: '#f8fafc' } },
      tickfont: { size: 11, color: '#e2e8f0' },
      showgrid: false,
    },
    yaxis: {
      ...PLOTLY_LAYOUT.yaxis,
      title: { text: 'Data Transmitted (Bytes Outbound)', font: { size: 12, color: '#f8fafc' } },
      tickfont: { size: 11, color: '#e2e8f0' },
      tickformat: '~s',
      showgrid: true,
      gridcolor: 'rgba(255,255,255,0.06)',
    },
  };

  Plotly.newPlot('chart-daily-volume', traces, layout, PLOTLY_CONFIG);
}

// ══════════════════════════════════════════════════════════════
// 2. ALERTS & CASES PAGE
// ══════════════════════════════════════════════════════════════
async function loadAlertsAndCases() {
  try {
    const [cases, alerts] = await Promise.all([
      fetchJSON('/api/cases'),
      fetchJSON('/api/alerts?limit=500'),
    ]);

    appState.cases = cases;
    appState.alerts = alerts;

    document.getElementById('tab-counter-cases').textContent = cases.length;
    document.getElementById('tab-counter-alerts').textContent = alerts.length;

    renderCasesGrid(cases);
    initAlertFilters(alerts);
    renderAlertsTable(alerts);
  } catch (err) {
    showToast('Failed to load cases: ' + err.message, 'error');
  }
}

// ── Cases: New split-panel rendering ──────────────────────────────
let activeCaseId = null;

function renderCasesGrid(cases) {
  const listContainer = document.getElementById('cases-list-items');
  const countBadge = document.getElementById('cases-list-count');

  if (!cases.length) {
    listContainer.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text-muted);font-size:0.8rem;">No investigation cases recorded.</div>';
    return;
  }

  if (countBadge) countBadge.textContent = cases.length;

  listContainer.innerHTML = cases.map(c => {
    const sev = (c.severity || 'medium').toLowerCase();
    const scoreDisplay = (c.max_score || 0).toFixed(2);
    return `
      <div class="case-list-item" data-case-id="${c.case_id}" id="case-item-${c.case_id}">
        <div class="case-list-sev-dot ${sev}"></div>
        <div class="case-list-info">
          <div class="case-list-id">${c.case_id}</div>
          <div class="case-list-meta">${c.user_id} &middot; Score: ${scoreDisplay}</div>
        </div>
        <div class="case-list-badge">
          <span class="severity-badge ${sev}">${sev}</span>
        </div>
      </div>
    `;
  }).join('');

  // Attach click handlers
  listContainer.querySelectorAll('.case-list-item').forEach(item => {
    item.addEventListener('click', () => {
      const caseId = item.getAttribute('data-case-id');
      if (activeCaseId === caseId) {
        // Second click: open full case modal dossier
        openCaseModal(caseId);
      } else {
        // First click: show overview in center panel
        activeCaseId = caseId;
        listContainer.querySelectorAll('.case-list-item').forEach(i => i.classList.remove('active'));
        item.classList.add('active');
        const caseData = cases.find(c => c.case_id === caseId);
        renderCaseOverview(caseData);
      }
    });
  });
}

function renderCaseOverview(c) {
  const centerPanel = document.getElementById('cases-center-panel');
  if (!c) return;

  const sev = (c.severity || 'medium').toLowerCase();
  const stage = c.max_kill_chain || 3;
  const sevColor = { critical: '#f43f5e', high: '#f97316', medium: '#eab308', low: '#10b981' }[sev] || '#64748b';

  centerPanel.innerHTML = `
    <div class="case-overview-panel">
      <div class="case-overview-header">
        <div class="case-overview-id">
          <span class="case-overview-label">Investigation Case</span>
          <span class="case-overview-title">${c.case_id}</span>
        </div>
        <div class="case-overview-actions">
          ${severityBadge(sev)}
          <button class="btn btn-outline btn-sm" onclick="openIncidentReport('${c.case_id}')">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
            Report
          </button>
          <button class="btn btn-primary btn-sm" onclick="openCaseModal('${c.case_id}')">
            Full Dossier &rarr;
          </button>
        </div>
      </div>

      <!-- Stats grid -->
      <div class="case-detail-section">
        <div class="case-detail-section-title">Case Metrics</div>
        <div class="case-detail-grid">
          <div class="case-detail-stat">
            <span class="case-detail-stat-label">Subject</span>
            <span class="case-detail-stat-value">${c.user_id}</span>
          </div>
          <div class="case-detail-stat">
            <span class="case-detail-stat-label">Alert Count</span>
            <span class="case-detail-stat-value">${c.alert_count}</span>
          </div>
          <div class="case-detail-stat">
            <span class="case-detail-stat-label">Max Score</span>
            <span class="case-detail-stat-value" style="color:${sevColor}">${(c.max_score || 0).toFixed(2)}</span>
          </div>
          <div class="case-detail-stat">
            <span class="case-detail-stat-label">First Seen</span>
            <span class="case-detail-stat-value">${(c.first_seen || '').slice(0, 10)}</span>
          </div>
          <div class="case-detail-stat">
            <span class="case-detail-stat-label">Last Seen</span>
            <span class="case-detail-stat-value">${(c.last_seen || '').slice(0, 10)}</span>
          </div>
          <div class="case-detail-stat">
            <span class="case-detail-stat-label">Kill Chain</span>
            <span class="case-detail-stat-value">Stage ${stage}</span>
          </div>
        </div>
      </div>

      <!-- Kill chain visual -->
      <div class="case-detail-section">
        <div class="case-detail-section-title">Kill-Chain Progression</div>
        <div class="kill-chain-visual">
          <div class="kc-step ${stage >= 1 ? 'active' : ''}">
            <span class="kc-dot"></span>
            <span>1: Initial Access</span>
          </div>
          <span class="kc-arrow">&rarr;</span>
          <div class="kc-step ${stage >= 2 ? 'active' : ''}">
            <span class="kc-dot"></span>
            <span>2: Data Staging</span>
          </div>
          <span class="kc-arrow">&rarr;</span>
          <div class="kc-step ${stage >= 3 ? 'active' : ''}">
            <span class="kc-dot"></span>
            <span>3: Exfiltration</span>
          </div>
        </div>
      </div>

      <!-- AI explanation loading section -->
      <div class="case-detail-section" id="case-ai-summary-${c.case_id}">
        <div class="case-detail-section-title">AI Threat Summary</div>
        <div class="loading-inline"><div class="spinner"></div><span>Loading AI analysis...</span></div>
      </div>

      <div style="text-align:center;padding-top:8px;">
        <small style="color:var(--text-muted);font-size:0.72rem;">&#x2139; Click this case again in the left panel to open the full investigation dossier</small>
      </div>
    </div>
  `;

  // Async load AI explanation
  fetchJSON(`/api/explanations/${c.case_id}`).then(exp => {
    const aiSection = document.getElementById(`case-ai-summary-${c.case_id}`);
    if (!aiSection) return;
    aiSection.innerHTML = `
      <div class="case-detail-section-title">AI Threat Summary</div>
      <p style="font-size:0.875rem;color:#fff;line-height:1.55;margin-bottom:10px;">${exp.summary || 'Correlated behavioral anomaly detected.'}</p>
      ${(exp.why_flagged || []).length ? `<ul style="padding-left:18px;font-size:0.8rem;color:var(--text-secondary);">${(exp.why_flagged || []).map(w => `<li style="margin-bottom:4px;">${w}</li>`).join('')}</ul>` : ''}
    `;
  }).catch(() => {
    const aiSection = document.getElementById(`case-ai-summary-${c.case_id}`);
    if (aiSection) aiSection.innerHTML = '<div class="case-detail-section-title">AI Threat Summary</div><p style="color:var(--text-muted);font-size:0.8rem;">AI analysis not available for this case.</p>';
  });
}

function initAlertFilters(alerts) {
  const detectorSelect = document.getElementById('filter-detector');
  const userSelect = document.getElementById('filter-user');
  const searchInput = document.getElementById('alert-search-input');
  const scoreSlider = document.getElementById('filter-score');
  const scoreVal = document.getElementById('filter-score-val');

  const detectors = [...new Set(alerts.map(a => a.detector))];
  detectorSelect.innerHTML = '<option value="">All Detectors</option>' +
    detectors.map(d => `<option value="${d}">${d.replace(/_/g, ' ').toUpperCase()}</option>`).join('');

  const users = [...new Set(alerts.map(a => a.user_id))];
  userSelect.innerHTML = '<option value="">All Users</option>' +
    users.map(u => `<option value="${u}">${u}</option>`).join('');

  function applyFilters() {
    const q = searchInput.value.toLowerCase().trim();
    const det = detectorSelect.value;
    const usr = userSelect.value;
    const minScore = parseFloat(scoreSlider.value) || 0;
    scoreVal.textContent = minScore.toFixed(2);

    const filtered = alerts.filter(a => {
      if (det && a.detector !== det) return false;
      if (usr && a.user_id !== usr) return false;
      if (a.score < minScore) return false;
      if (q) {
        const text = `${a.alert_id} ${a.evidence_tags} ${a.detector} ${a.case_id}`.toLowerCase();
        if (!text.includes(q)) return false;
      }
      return true;
    });

    renderAlertsTable(filtered);
  }

  searchInput.oninput = applyFilters;
  detectorSelect.onchange = applyFilters;
  userSelect.onchange = applyFilters;
  scoreSlider.oninput = applyFilters;

  const exportBtn = document.getElementById('btn-export-alerts');
  if (exportBtn) {
    exportBtn.onclick = () => exportAlertsCSV(alerts);
  }
}

function renderAlertsTable(alerts) {
  const container = document.getElementById('alerts-table-wrapper');
  document.getElementById('alerts-count-badge').textContent = `Showing ${alerts.length} alerts`;

  if (!alerts.length) {
    showEmpty(container, 'No alerts match current filter criteria.');
    return;
  }

  container.innerHTML = `
    <table class="data-table">
      <thead>
        <tr>
          <th>Alert ID</th>
          <th>Timestamp</th>
          <th>User</th>
          <th>Detector</th>
          <th style="min-width:110px;">Score</th>
          <th>Kill Chain</th>
          <th>Evidence Tags</th>
          <th>Case</th>
        </tr>
      </thead>
      <tbody>
        ${alerts.slice(0, 150).map(a => `
          <tr>
            <td class="mono font-semibold" style="color:var(--accent-hover);">${a.alert_id}</td>
            <td class="mono text-xs text-muted">${(a.timestamp || '—').replace('T', ' ').slice(0, 16)}</td>
            <td><span class="mono" style="font-weight:600;">${a.user_id}</span></td>
            <td><span class="badge-subtle">${a.detector}</span></td>
            <td>${scoreBar(a.score)}</td>
            <td><span class="tag-pill">Stage ${a.kill_chain_stage || 1}</span></td>
            <td>
              ${(a.evidence_tags || '').split(/[,;]/).filter(Boolean).map(t => `<span class="tag-pill">${t.trim()}</span>`).join('')}
            </td>
            <td>
              <a href="javascript:void(0)" onclick="openCaseModal('${a.case_id}')" class="mono text-xs" style="color:#60a5fa;text-decoration:none;">${a.case_id || '—'}</a>
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

function exportAlertsCSV(alerts) {
  const headers = ['alert_id', 'timestamp', 'user_id', 'detector', 'score', 'kill_chain_stage', 'evidence_tags', 'case_id'];
  const rows = alerts.map(a => headers.map(h => `"${(a[h] || '').toString().replace(/"/g, '""')}"`).join(','));
  const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows].join('\n');
  const encodedUri = encodeURI(csvContent);
  const link = document.createElement('a');
  link.setAttribute('href', encodedUri);
  link.setAttribute('download', `insiderlens_alerts_${Date.now()}.csv`);
  document.body.appendChild(link);
  link.click();
  link.remove();
  showToast('Alerts CSV export generated successfully', 'success');
}

// ══════════════════════════════════════════════════════════════
// 3. USER ANALYSIS PAGE
// ══════════════════════════════════════════════════════════════
async function loadUserAnalysisPage() {
  try {
    const risk = await fetchJSON('/api/risk-summary');
    appState.riskSummary = risk;

    const select = document.getElementById('user-select');
    select.innerHTML = risk.map(u => `
      <option value="${u.user_id}">
        ${u.user_id} — Score: ${u.risk_score.toFixed(0)} (${u.severity.toUpperCase()})
      </option>
    `).join('');

    if (appState.currentUser) {
      select.value = appState.currentUser;
    } else {
      appState.currentUser = risk[0]?.user_id || 'USER-003';
      select.value = appState.currentUser;
    }

    select.onchange = (e) => {
      appState.currentUser = e.target.value;
      loadUserDetail(appState.currentUser);
    };

    await loadUserDetail(appState.currentUser);
  } catch (err) {
    showToast('Failed to load user analysis: ' + err.message, 'error');
  }
}

async function loadUserDetail(userId) {
  if (!userId) return;
  appState.currentUser = userId;
  try {
    const [detail, hourly] = await Promise.all([
      fetchJSON(`/api/user/${userId}`),
      fetchJSON(`/api/flows/hourly/${userId}`),
    ]);

    renderUserHeaderMeta(detail);
    renderUserMetrics(detail.risk);
    renderUserVolume(detail.daily_features, userId);
    renderUserHourly(hourly);
    renderUserZscore(detail.daily_features);
    renderUserTimeline(detail.timeline);

    // Refresh admin identity panel if session is still active
    if (isAdminSessionActive()) {
      const identityPanel = document.getElementById('admin-identity-panel');
      if (identityPanel && identityPanel.style.display !== 'none') {
        showIdentityPanel(identityPanel);
      }
    }
  } catch (err) {
    showToast(`Failed loading detail for ${userId}: ` + err.message, 'error');
  }
}

function renderUserHeaderMeta(detail) {
  const metaContainer = document.getElementById('user-context-meta');
  const firstRow = detail.daily_features[0] || {};
  const dept = firstRow.department || 'Enterprise';
  const role = firstRow.role || 'Staff Member';
  const hr = firstRow.hr_status || 'Active';

  metaContainer.innerHTML = `
    <span class="user-meta-chip">Department: <strong class="text-white">${dept}</strong></span>
    <span class="user-meta-chip">Role: <strong class="text-white">${role}</strong></span>
    <span class="user-meta-chip">Status: <strong class="${hr === 'Notice Period' ? 'text-rose' : 'text-emerald'}">${hr}</strong></span>
  `;
}

function renderUserMetrics(risk) {
  const container = document.getElementById('user-metrics');
  container.innerHTML = `
    <div class="metric-card ${risk.severity === 'critical' ? 'accent-rose' : risk.severity === 'high' ? 'accent-amber' : 'accent-blue'}">
      <div class="metric-header"><span class="metric-label">Assigned Risk Score</span></div>
      <div class="metric-value" style="color:${SEVERITY_COLORS[risk.severity]}">${risk.risk_score.toFixed(1)}</div>
      <div class="metric-sub">${severityBadge(risk.severity)}</div>
    </div>
    <div class="metric-card">
      <div class="metric-header"><span class="metric-label">Total Correlated Alerts</span></div>
      <div class="metric-value">${risk.alert_count}</div>
      <div class="metric-sub text-muted">Exfiltration & Anomaly</div>
    </div>
    <div class="metric-card">
      <div class="metric-header"><span class="metric-label">Investigation Cases</span></div>
      <div class="metric-value">${risk.case_count}</div>
      <div class="metric-sub text-muted">Correlated clusters</div>
    </div>
    <div class="metric-card accent-emerald">
      <div class="metric-header"><span class="metric-label">Privacy State</span></div>
      <div class="metric-value text-emerald">Gated</div>
      <div class="metric-sub text-muted">Pseudonymized Key ID</div>
    </div>
  `;
}

function renderUserVolume(dailyFeatures, userId) {
  const container = document.getElementById('chart-user-volume');
  if (!container || !dailyFeatures || !dailyFeatures.length) {
    if (container) showEmpty(container, 'No daily outbound volume data recorded for this user.');
    return;
  }

  const sorted = [...dailyFeatures].sort((a, b) => a.date.localeCompare(b.date));
  const dates = sorted.map(d => d.date);

  // Convert raw bytes to MB (Megabytes)
  const mbValues = sorted.map(d => {
    if (typeof d.total_bytes_out_mb === 'number' && !isNaN(d.total_bytes_out_mb)) {
      return d.total_bytes_out_mb;
    }
    return (d.total_bytes_out || 0) / (1024 * 1024);
  });

  // Calculate user's typical baseline range (exclude extreme outliers with z-score > 2)
  const nonSpikeValues = mbValues.filter((val, i) => {
    const z = sorted[i].total_bytes_out_z_self;
    return z === undefined || z === null || z === '' || Number(z) <= 2.0;
  });
  const baselineValues = nonSpikeValues.length >= 3 ? nonSpikeValues : mbValues;
  const baselineMean = baselineValues.reduce((a, b) => a + b, 0) / baselineValues.length;
  const variance = baselineValues.reduce((a, b) => a + Math.pow(b - baselineMean, 2), 0) / baselineValues.length;
  const baselineStd = Math.sqrt(variance);

  // Normal baseline corridor bounds
  const baselineUpper = Math.max(0.25, Number((baselineMean + 1.5 * (baselineStd || 0.05)).toFixed(2)));
  const baselineLower = Math.max(0, Number((Math.max(0, baselineMean - 1.0 * (baselineStd || 0.05))).toFixed(2)));

  // Identify spikes outside the corridor
  const spikeIndices = [];
  const spikeLabels = [];
  sorted.forEach((d, i) => {
    const mb = mbValues[i];
    if (mb > baselineUpper) {
      spikeIndices.push(i);
      const ratio = (mb / Math.max(baselineMean, 0.01)).toFixed(1);
      const dateParts = d.date.split('-');
      const monthNames = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
      const monthStr = monthNames[parseInt(dateParts[1], 10) - 1] || dateParts[1];
      const dayStr = parseInt(dateParts[2], 10);
      spikeLabels.push(`${monthStr} ${dayStr}: ${ratio}x normal`);
    }
  });

  // Dynamic Takeaway generation
  const takeawayEl = document.getElementById('takeaway-text-user-volume');
  const srEl = document.getElementById('sr-user-volume');
  if (spikeIndices.length > 0) {
    let maxSpikeIdx = spikeIndices[0];
    spikeIndices.forEach(idx => {
      if (mbValues[idx] > mbValues[maxSpikeIdx]) maxSpikeIdx = idx;
    });
    const maxMb = mbValues[maxSpikeIdx];
    const maxRatio = (maxMb / Math.max(baselineMean, 0.01)).toFixed(1);
    const dateParts = sorted[maxSpikeIdx].date.split('-');
    const monthNames = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    const monthStr = monthNames[parseInt(dateParts[1], 10) - 1] || dateParts[1];
    const dayStr = parseInt(dateParts[2], 10);

    const takeawayText = `<strong>${monthStr} ${dayStr}</strong> outbound volume was <strong>${maxRatio}x</strong> this user's normal baseline (<strong>${maxMb.toFixed(2)} MB</strong> vs ~${baselineMean.toFixed(2)} MB typical).`;
    if (takeawayEl) takeawayEl.innerHTML = takeawayText;
    if (srEl) srEl.textContent = `Daily Outbound Volume: ${monthStr} ${dayStr} was ${maxRatio} times normal baseline volume, transferring ${maxMb.toFixed(2)} MB.`;
  } else {
    const takeawayText = `Daily outbound volume remained within the normal baseline corridor (${baselineLower.toFixed(2)}–${baselineUpper.toFixed(2)} MB) with no anomalous spikes.`;
    if (takeawayEl) takeawayEl.innerHTML = takeawayText;
    if (srEl) srEl.textContent = `Daily Outbound Volume remained within normal corridor between ${baselineLower.toFixed(2)} MB and ${baselineUpper.toFixed(2)} MB.`;
  }

  // Trace 1: Lower bound of corridor (invisible baseline)
  const traceLower = {
    type: 'scatter',
    mode: 'lines',
    x: dates,
    y: dates.map(() => baselineLower),
    line: { width: 0, color: 'transparent' },
    showlegend: false,
    hoverinfo: 'none',
  };

  // Trace 2: Upper bound of corridor + Shaded fill
  const traceCorridor = {
    type: 'scatter',
    mode: 'lines',
    name: 'Normal baseline corridor',
    x: dates,
    y: dates.map(() => baselineUpper),
    fill: 'tonexty',
    fillcolor: 'rgba(56, 189, 248, 0.12)',
    line: { color: 'rgba(56, 189, 248, 0.5)', width: 1.5, dash: 'dot' },
    hovertemplate: `<b>Normal Baseline Corridor</b><br>• Range: ${baselineLower.toFixed(2)} – ${baselineUpper.toFixed(2)} MB<br>• Typical daily mean: ~${baselineMean.toFixed(2)} MB<extra></extra>`,
  };

  // Trace 3: Observed Outbound Volume
  const traceObserved = {
    type: 'scatter',
    mode: 'lines+markers',
    name: 'Observed data sent',
    x: dates,
    y: mbValues,
    line: { color: '#0072b2', width: 2.2 },
    marker: { size: 6, color: '#38bdf8', symbol: 'circle', line: { color: '#ffffff', width: 1 } },
    customdata: sorted.map((d, i) => {
      const mb = mbValues[i];
      const bytes = d.total_bytes_out || 0;
      const isSpike = mb > baselineUpper;
      const mult = (mb / Math.max(baselineMean, 0.01)).toFixed(1);
      return [
        bytes.toLocaleString(),
        isSpike ? `🚨 Spike (${mult}x normal)` : '✓ Inside normal range',
        baselineMean.toFixed(2),
      ];
    }),
    hovertemplate:
      '<b>Date: %{x}</b><br>' +
      '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━<br>' +
      '• <b>Data sent out:</b> %{y:.2f} MB (%{customdata[0]} bytes)<br>' +
      '• <b>Assessment:</b> %{customdata[1]}<br>' +
      '• <b>Typical baseline:</b> ~%{customdata[2]} MB<br>' +
      '<extra></extra>',
  };

  const traces = [traceLower, traceCorridor, traceObserved];

  // Trace 4: Marked Spikes Above Baseline (if any)
  if (spikeIndices.length > 0) {
    traces.push({
      type: 'scatter',
      mode: 'markers+text',
      name: 'Spike above baseline',
      x: spikeIndices.map(i => dates[i]),
      y: spikeIndices.map(i => mbValues[i]),
      marker: {
        size: 10,
        color: '#d55e00',
        symbol: 'diamond',
        line: { color: '#ffffff', width: 1.5 },
      },
      text: spikeLabels,
      textposition: 'top center',
      textfont: { size: 11, color: '#fca5a5', family: 'Inter, sans-serif', weight: 700 },
      hoverinfo: 'skip',
    });
  }

  const maxY = Math.max(...mbValues, baselineUpper * 1.3);

  const layout = {
    ...PLOTLY_LAYOUT,
    height: 310,
    margin: { t: 25, b: 60, l: 80, r: 25 },
    legend: {
      orientation: 'h',
      x: 0,
      y: -0.28,
      font: { size: 11, color: '#f1f5f9' },
    },
    xaxis: {
      ...PLOTLY_LAYOUT.xaxis,
      title: { text: 'Date', font: { size: 12, color: '#f8fafc', weight: 600 } },
      tickfont: { size: 11, color: '#e2e8f0' },
      showgrid: false,
    },
    yaxis: {
      ...PLOTLY_LAYOUT.yaxis,
      range: [0, maxY * 1.15],
      ticksuffix: ' MB',
      title: { text: 'Data sent out (MB)', font: { size: 12, color: '#f8fafc', weight: 600 }, standoff: 15 },
      tickfont: { size: 11, color: '#e2e8f0' },
      showgrid: true,
      gridcolor: 'rgba(255,255,255,0.06)',
    },
  };

  Plotly.purge('chart-user-volume');
  Plotly.newPlot('chart-user-volume', traces, layout, PLOTLY_CONFIG);
}

function renderUserHourly(hourly) {
  const el = document.getElementById('chart-user-hourly');
  if (!hourly || !hourly.length) {
    Plotly.purge(el);
    showEmpty(el, 'No hourly flow data available for this user.');
    return;
  }

  const hourIndices = Array.from({ length: 24 }, (_, i) => i);
  const hour12Labels = [
    '12 AM', '1 AM', '2 AM', '3 AM', '4 AM', '5 AM',
    '6 AM', '7 AM', '8 AM', '9 AM', '10 AM', '11 AM',
    '12 PM', '1 PM', '2 PM', '3 PM', '4 PM', '5 PM',
    '6 PM', '7 PM', '8 PM', '9 PM', '10 PM', '11 PM'
  ];

  const counts = Array.from({ length: 24 }, (_, i) => {
    const found = hourly.find(h => h.hour === i);
    return found ? found.count : 0;
  });

  const totalFlows = counts.reduce((a, b) => a + b, 0);
  const afterHoursFlows = counts.reduce((acc, c, i) => (i >= 19 || i < 7) ? acc + c : acc, 0);
  const maxCount = Math.max(...counts, 1);
  const peakHourIdx = counts.indexOf(maxCount);
  const peakHour12 = hour12Labels[peakHourIdx];

  // Dynamic Takeaway generation
  const takeawayEl = document.getElementById('takeaway-text-user-hourly');
  const srEl = document.getElementById('sr-user-hourly');
  if (afterHoursFlows > 0) {
    const pct = Math.round((afterHoursFlows / Math.max(totalFlows, 1)) * 100);
    const takeawayText = `<strong>${afterHoursFlows} connections (${pct}%)</strong> occurred during after-hours (7 PM – 7 AM UTC), peaking at <strong>${peakHour12} UTC</strong>.`;
    if (takeawayEl) takeawayEl.innerHTML = takeawayText;
    if (srEl) srEl.textContent = `Activity by Hour: ${afterHoursFlows} connections occurred during after-hours (7 PM to 7 AM UTC), with peak activity at ${peakHour12} UTC.`;
  } else {
    const takeawayText = `All <strong>${totalFlows} connections</strong> occurred during standard daytime business hours (7 AM – 7 PM UTC), peaking at ${peakHour12} UTC.`;
    if (takeawayEl) takeawayEl.innerHTML = takeawayText;
    if (srEl) srEl.textContent = `Activity by Hour: All ${totalFlows} connections occurred during standard daytime business hours, peaking at ${peakHour12} UTC.`;
  }

  // Split into daytime and after-hours bars for clear dual-coded legend
  const daytimeCounts = counts.map((c, i) => (i >= 7 && i < 19) ? c : 0);
  const afterHoursCounts = counts.map((c, i) => (i >= 19 || i < 7) ? c : 0);

  const traceDaytime = {
    type: 'bar',
    name: 'Daytime (7 AM – 7 PM)',
    x: hourIndices,
    y: daytimeCounts,
    marker: {
      color: '#0284c7', // Ocean Blue
      line: { color: 'rgba(255,255,255,0.2)', width: 1 },
    },
    customdata: hourIndices.map(i => [
      hour12Labels[i],
      `${String(i).padStart(2, '0')}:00 UTC`,
      'Daytime Business Hours (Normal)',
      totalFlows > 0 ? `${Math.round((counts[i] / totalFlows) * 100)}%` : '0%',
    ]),
    hovertemplate:
      '<b>%{customdata[0]} (%{customdata[1]})</b><br>' +
      '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━<br>' +
      '• <b>Connections:</b> %{y} network flows (%{customdata[3]} of daily activity)<br>' +
      '• <b>Window:</b> %{customdata[2]}<br>' +
      '<extra></extra>',
  };

  const traceAfterHours = {
    type: 'bar',
    name: 'After-hours (7 PM – 7 AM)',
    x: hourIndices,
    y: afterHoursCounts,
    marker: {
      color: '#d55e00', // Vermilion / Red-Orange
      pattern: {
        shape: '/',
        fillmode: 'overlay',
        fgcolor: 'rgba(255,255,255,0.45)',
        size: 6,
      },
      line: { color: 'rgba(255,255,255,0.35)', width: 1.2 },
    },
    customdata: hourIndices.map(i => [
      hour12Labels[i],
      `${String(i).padStart(2, '0')}:00 UTC`,
      '🚨 After-Hours Window (Closed Office)',
      totalFlows > 0 ? `${Math.round((counts[i] / totalFlows) * 100)}%` : '0%',
    ]),
    hovertemplate:
      '<b>%{customdata[0]} (%{customdata[1]})</b><br>' +
      '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━<br>' +
      '• <b>Connections:</b> %{y} network flows (%{customdata[3]} of daily activity)<br>' +
      '• <b>Window:</b> %{customdata[2]}<br>' +
      '<extra></extra>',
  };

  const layout = {
    ...PLOTLY_LAYOUT,
    height: 310,
    barmode: 'stack',
    margin: { t: 25, b: 60, l: 65, r: 25 },
    legend: {
      orientation: 'h',
      x: 0,
      y: -0.28,
      font: { size: 11, color: '#f1f5f9' },
    },
    xaxis: {
      ...PLOTLY_LAYOUT.xaxis,
      type: 'category',
      tickmode: 'array',
      tickvals: [0, 3, 6, 9, 12, 15, 18, 21],
      ticktext: ['12 AM', '3 AM', '6 AM', '9 AM', '12 PM', '3 PM', '6 PM', '9 PM'],
      tickangle: 0, // Strictly horizontal labels
      title: { text: 'Time of Day (UTC, 12-Hour AM/PM Format)', font: { size: 12, color: '#f8fafc', weight: 600 } },
      tickfont: { size: 11, color: '#e2e8f0' },
      showgrid: false,
    },
    yaxis: {
      ...PLOTLY_LAYOUT.yaxis,
      title: { text: 'Connections (Flows)', font: { size: 12, color: '#f8fafc', weight: 600 } },
      tickfont: { size: 11, color: '#e2e8f0' },
      ticksuffix: ' flows',
      showgrid: true,
      gridcolor: 'rgba(255,255,255,0.06)',
    },
    shapes: [
      // Evening after-hours shade: 19:00 - 24:00 (indices 18.5 - 23.5)
      {
        type: 'rect',
        xref: 'x',
        x0: 18.5,
        x1: 23.5,
        y0: 0,
        y1: 1,
        yref: 'paper',
        fillcolor: 'rgba(213, 94, 0, 0.10)',
        line: { width: 0 },
      },
      // Morning after-hours shade: 00:00 - 07:00 (indices -0.5 - 6.5)
      {
        type: 'rect',
        xref: 'x',
        x0: -0.5,
        x1: 6.5,
        y0: 0,
        y1: 1,
        yref: 'paper',
        fillcolor: 'rgba(213, 94, 0, 0.10)',
        line: { width: 0 },
      },
    ],
    annotations: [
      {
        xref: 'paper',
        x: 0.98,
        y: 1,
        yref: 'paper',
        text: 'After hours (7 PM - 7 AM)',
        showarrow: false,
        font: { size: 10, color: '#ffffff', weight: 600, family: 'Inter, sans-serif' },
        bgcolor: '#d55e00',
        bordercolor: '#fca5a5',
        borderpad: 4,
        xanchor: 'right',
        yshift: 12,
      },
    ],
  };

  Plotly.purge(el);
  Plotly.newPlot(el, [traceDaytime, traceAfterHours], layout, PLOTLY_CONFIG);
}

function renderUserZscore(dailyFeatures) {
  const container = document.getElementById('chart-user-zscore');
  if (!container || !dailyFeatures || !dailyFeatures.length) {
    if (container) showEmpty(container, 'No baseline deviation data available for this user.');
    return;
  }

  const sorted = [...dailyFeatures].sort((a, b) => a.date.localeCompare(b.date));
  const dates = sorted.map(d => d.date);

  // Four metrics with plain-language names, distinct colorblind-safe colors, and unique dash styles/markers
  const metricConfigs = [
    {
      col: 'total_bytes_out_z_self',
      name: 'Data sent',
      color: '#0072b2', // Dark Blue
      dash: 'solid',
      symbol: 'circle',
    },
    {
      col: 'total_flows_z_self',
      name: 'Number of connections',
      color: '#e69f00', // Amber
      dash: 'dash',
      symbol: 'square',
    },
    {
      col: 'unique_destinations_z_self',
      name: 'New destinations',
      color: '#882255', // Deep Maroon / Purple
      dash: 'dot',
      symbol: 'diamond',
    },
    {
      col: 'after_hours_ratio_z_self',
      name: 'After-hours activity',
      color: '#06b6d4', // Vibrant Cyan (distinct from red critical line!)
      dash: 'dashdot',
      symbol: 'triangle-up',
    },
  ];

  // Turn OFF spline smoothing: use 'linear' mode to connect real data points only
  const traces = metricConfigs.map(m => ({
    type: 'scatter',
    mode: 'lines+markers',
    name: m.name,
    x: dates,
    y: sorted.map(d => {
      const val = d[m.col];
      return (val !== undefined && val !== null && val !== '') ? Number(val) : 0;
    }),
    line: {
      width: 2.2,
      color: m.color,
      dash: m.dash,
      shape: 'linear', // REAL POINTS CONNECTED DIRECTLY (NO SPLINE)
    },
    marker: { size: 6, symbol: m.symbol, color: m.color, line: { color: '#ffffff', width: 1 } },
    customdata: sorted.map(d => {
      const val = Number(d[m.col] || 0);
      let assessment = 'Normal baseline range';
      if (val >= 3.0) assessment = '🚨 Very unusual (critical alert threshold breached)';
      else if (val >= 2.0) assessment = '⚠️ Unusual (warning threshold breached)';
      else if (val <= -2.0) assessment = 'Significantly below normal';
      return [m.name, assessment];
    }),
    hovertemplate:
      '<b>%{customdata[0]}</b><br>' +
      '• Date: <b>%{x}</b><br>' +
      '• Departure from normal: <b>+%{y:.2f} points</b><br>' +
      '• Assessment: %{customdata[1]}<br>' +
      '<extra></extra>',
  }));

  // Dynamic Takeaway generation
  let maxDev = -Infinity;
  let maxDate = '';
  let maxMetric = '';
  metricConfigs.forEach(m => {
    sorted.forEach(d => {
      const val = Number(d[m.col] || 0);
      if (val > maxDev) {
        maxDev = val;
        maxDate = d.date;
        maxMetric = m.name;
      }
    });
  });

  const takeawayEl = document.getElementById('takeaway-text-user-zscore');
  const srEl = document.getElementById('sr-user-zscore');
  if (maxDev >= 2.0 && maxDate) {
    const dateParts = maxDate.split('-');
    const monthNames = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    const monthStr = monthNames[parseInt(dateParts[1], 10) - 1] || dateParts[1];
    const dayStr = parseInt(dateParts[2], 10);
    const zoneName = maxDev >= 3.0 ? 'Very Unusual' : 'Unusual';

    const takeawayText = `<strong>${monthStr} ${dayStr}</strong> <strong>${maxMetric}</strong> surged to <strong>+${maxDev.toFixed(1)}</strong> points above normal, entering the <strong>${zoneName}</strong> zone.`;
    if (takeawayEl) takeawayEl.innerHTML = takeawayText;
    if (srEl) srEl.textContent = `Baseline Deviation Z-Scores: On ${monthStr} ${dayStr}, ${maxMetric} deviated by ${maxDev.toFixed(1)} points above normal baseline (${zoneName} level).`;
  } else {
    const takeawayText = `All behavioral metrics remained within expected statistical ranges (< 2.0 departures from normal baseline).`;
    if (takeawayEl) takeawayEl.innerHTML = takeawayText;
    if (srEl) srEl.textContent = `Baseline Deviation Z-Scores: All metrics remained within normal expected range.`;
  }

  // Calculate y bounds (accommodate extreme spikes e.g. 66+ or at least 4.5)
  const allY = traces.flatMap(t => t.y);
  const highestY = Math.max(...allY, 3.5);
  const lowestY = Math.min(...allY, 0);
  const yUpper = Math.max(4.5, highestY * 1.1);
  const yLower = Math.min(-1, lowestY - 0.5);

  const layout = {
    ...PLOTLY_LAYOUT,
    height: 320,
    margin: { t: 25, b: 60, l: 75, r: 25 },
    legend: {
      orientation: 'h',
      x: 0,
      y: -0.28,
      font: { size: 11, color: '#f1f5f9' },
    },
    xaxis: {
      ...PLOTLY_LAYOUT.xaxis,
      title: { text: 'Timeline (Date)', font: { size: 12, color: '#f8fafc', weight: 600 } },
      tickfont: { size: 11, color: '#e2e8f0' },
      showgrid: false,
    },
    yaxis: {
      ...PLOTLY_LAYOUT.yaxis,
      range: [yLower, yUpper],
      title: {
        text: 'Deviation from Normal (0 = normal, +2 = unusual)',
        font: { size: 12, color: '#f8fafc', weight: 600 },
        standoff: 15,
      },
      tickfont: { size: 11, color: '#e2e8f0' },
      showgrid: true,
      gridcolor: 'rgba(255,255,255,0.06)',
    },
    shapes: [
      // Shaded Area between +2 and +3 (Yellow / Warning: Unusual)
      {
        type: 'rect',
        xref: 'paper',
        x0: 0,
        x1: 1,
        y0: 2,
        y1: 3,
        fillcolor: 'rgba(245, 158, 11, 0.08)',
        line: { width: 0 },
      },
      // Shaded Area above +3 (Red / Critical: Very Unusual)
      {
        type: 'rect',
        xref: 'paper',
        x0: 0,
        x1: 1,
        y0: 3,
        y1: yUpper,
        fillcolor: 'rgba(220, 38, 38, 0.12)',
        line: { width: 0 },
      },
      // Warning line (+2)
      {
        type: 'line',
        xref: 'paper',
        x0: 0,
        x1: 1,
        y0: 2,
        y1: 2,
        line: { color: '#f59e0b', dash: 'dash', width: 1.8 },
      },
      // Critical line (+3)
      {
        type: 'line',
        xref: 'paper',
        x0: 0,
        x1: 1,
        y0: 3,
        y1: 3,
        line: { color: '#dc2626', dash: 'longdash', width: 2.2 },
      },
    ],
    annotations: [
      {
        xref: 'paper',
        x: 0.98,
        y: 2,
        text: 'Warning: unusual for this user (+2)',
        showarrow: false,
        font: { size: 10, color: '#ffffff', weight: 600, family: 'Inter, sans-serif' },
        bgcolor: '#d97706',
        bordercolor: '#fde68a',
        borderpad: 4,
        xanchor: 'right',
        yshift: 11,
      },
      {
        xref: 'paper',
        x: 0.98,
        y: 3,
        text: 'Critical: very unusual for this user (+3)',
        showarrow: false,
        font: { size: 10, color: '#ffffff', weight: 600, family: 'Inter, sans-serif' },
        bgcolor: '#dc2626',
        bordercolor: '#fca5a5',
        borderpad: 4,
        xanchor: 'right',
        yshift: 11,
      },
    ],
  };

  Plotly.purge('chart-user-zscore');
  Plotly.newPlot('chart-user-zscore', traces, layout, PLOTLY_CONFIG);
}

function renderUserTimeline(timeline) {
  const container = document.getElementById('user-timeline-table');
  if (!timeline || !timeline.length) {
    showEmpty(container, 'No alerts generated for this user.');
    return;
  }

  container.innerHTML = `
    <table class="data-table">
      <thead>
        <tr>
          <th>Alert ID</th>
          <th>Timestamp</th>
          <th>Detector</th>
          <th>Anomaly Score</th>
          <th>Evidence Tags</th>
          <th>Kill Chain</th>
        </tr>
      </thead>
      <tbody>
        ${timeline.map(t => `
          <tr>
            <td class="mono font-semibold" style="color:var(--accent-hover);">${t.alert_id}</td>
            <td class="mono text-xs text-muted">${(t.timestamp || '—').replace('T', ' ').slice(0, 16)}</td>
            <td><span class="badge-subtle">${t.detector}</span></td>
            <td>${scoreBar(t.score)}</td>
            <td>${(t.evidence || []).map(e => `<span class="tag-pill">${e}</span>`).join('')}</td>
            <td><span class="tag-pill">Stage ${t.kill_chain_stage || 1}</span></td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

// ══════════════════════════════════════════════════════════════
// 4. AI COPILOT PAGE
// ══════════════════════════════════════════════════════════════
function loadCopilotPage() {
  const chatInput = document.getElementById('chat-input');
  const chatSend = document.getElementById('chat-send');
  const clearChatBtn = document.getElementById('btn-clear-chat');

  // Bind click handlers for prompt chips
  document.querySelectorAll('.prompt-chip').forEach(chip => {
    chip.onclick = () => {
      const query = chip.getAttribute('data-query');
      chatInput.value = query;
      submitCopilotQuery(query);
    };
  });

  chatSend.onclick = () => {
    const q = chatInput.value.trim();
    if (q) submitCopilotQuery(q);
  };

  chatInput.onkeydown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      const q = chatInput.value.trim();
      if (q) submitCopilotQuery(q);
    }
  };

  if (clearChatBtn) {
    clearChatBtn.onclick = () => {
      appState.chatHistory = [];
      renderChatMessages();
      showToast('Conversation cleared', 'info');
    };
  }

  if (!appState.chatHistory.length) {
    // Initial welcome message
    appState.chatHistory.push({
      role: 'assistant',
      content: `Hello! I am the **InsiderLens Analyst Copilot**, your threat hunting and policy verification assistant. 
      
I can assist you with:
- **Investigating specific subjects** (e.g., *USER-003 exfiltration analysis*)
- **Explaining ML detection scores** (XGBoost, CUSUM drift, DNS tunneling)
- **Checking corporate security policies** and acceptable use playbooks
- **Guidance on incident containment** and gated reveal protocols

Select any suggested question from the left panel or type your inquiry below.`,
      sources: [],
    });
  }

  renderChatMessages();
}

async function submitCopilotQuery(query) {
  const chatInput = document.getElementById('chat-input');
  const chatSend = document.getElementById('chat-send');

  appState.chatHistory.push({ role: 'user', content: query });
  chatInput.value = '';
  renderChatMessages();

  chatSend.disabled = true;
  appState.chatHistory.push({ role: 'assistant', content: '', loading: true });
  renderChatMessages();

  try {
    const res = await postJSON('/api/copilot', { question: query });
    appState.chatHistory.pop(); // remove loading message
    appState.chatHistory.push({
      role: 'assistant',
      content: res.answer,
      sources: res.sources || [],
    });
  } catch (err) {
    appState.chatHistory.pop();
    appState.chatHistory.push({
      role: 'assistant',
      content: `⚠️ Error fetching response: ${err.message}. Please check if the local Ollama instance is active.`,
      sources: [],
    });
  } finally {
    chatSend.disabled = false;
    renderChatMessages();
  }
}

function renderChatMessages() {
  const container = document.getElementById('chat-messages');
  container.innerHTML = appState.chatHistory.map(msg => {
    if (msg.loading) {
      return `
        <div class="chat-msg assistant">
          <div class="chat-msg-avatar">&#x2728;</div>
          <div class="chat-msg-body">
            <div class="loading-inline">
              <div class="spinner"></div>
              <span>Searching ChromaDB &amp; synthesizing threat intelligence...</span>
            </div>
          </div>
        </div>
      `;
    }

    const isUser = msg.role === 'user';
    const avatar = isUser ? 'YOU' : '&#x2728;';

    // Parse Markdown safely
    let parsedText = '';
    if (window.marked && typeof window.marked.parse === 'function') {
      parsedText = window.marked.parse(msg.content);
    } else {
      parsedText = msg.content.replace(/\n/g, '<br>');
    }

    let sourcesHtml = '';
    if (msg.sources && msg.sources.length) {
      sourcesHtml = `
        <div class="chat-msg-sources">
          <strong>Referenced Sources:</strong><br>
          ${msg.sources.slice(0, 4).map((s, i) => `
            <span class="source-badge">[${i + 1}] ${s.source || ''} &gt; ${s.section || ''} ${s.relevance ? `(${(s.relevance * 100).toFixed(0)}%)` : ''}</span>
          `).join('')}
        </div>
      `;
    }

    return `
      <div class="chat-msg ${msg.role}">
        <div class="chat-msg-avatar">${avatar}</div>
        <div class="chat-msg-body">
          <div class="markdown-rendered">${parsedText}</div>
          ${sourcesHtml}
        </div>
      </div>
    `;
  }).join('');

  container.scrollTop = container.scrollHeight;
}

// ══════════════════════════════════════════════════════════════
// 5. ANALYTICS PAGE
// ══════════════════════════════════════════════════════════════
async function loadAnalyticsPage() {
  try {
    const [dailyAlerts, alerts, deptStats, shap, network] = await Promise.all([
      fetchJSON('/api/alerts/daily'),
      fetchJSON('/api/alerts?limit=500'),
      fetchJSON('/api/department-stats'),
      fetchJSON('/api/shap'),
      fetchJSON('/api/flows/network-graph'),
    ]);

    renderDailyAlertsChart(dailyAlerts);
    renderScoreDistChart(alerts);
    renderDeptStatsChart(deptStats);
    renderShapChart(shap);
    renderNetworkTopology(network);
  } catch (err) {
    showToast('Failed to load analytics: ' + err.message, 'error');
  }
}

function renderDailyAlertsChart(daily) {
  if (!daily || !daily.length) return;
  const detectors = [...new Set(daily.map(d => d.detector))];

  const traces = detectors.map(det => {
    const subset = daily.filter(d => d.detector === det);
    return {
      type: 'bar',
      name: det.replace(/_/g, ' '),
      x: subset.map(d => d.date),
      y: subset.map(d => d.count),
      marker: { color: DETECTOR_COLORS[det] || '#64748b' },
    };
  });

  const layout = {
    ...PLOTLY_LAYOUT,
    height: 320,
    barmode: 'stack',
    yaxis: {
      ...PLOTLY_LAYOUT.yaxis,
      title: { text: 'Alert Count', font: { size: 10, color: '#64748b' } },
    },
  };

  Plotly.newPlot('chart-daily-alerts', traces, layout, PLOTLY_CONFIG);
}

function renderScoreDistChart(alerts) {
  const detectors = [...new Set(alerts.map(a => a.detector))];
  const traces = detectors.map(det => ({
    type: 'histogram',
    name: det.replace(/_/g, ' '),
    x: alerts.filter(a => a.detector === det).map(a => a.score),
    opacity: 0.75,
    nbinsx: 20,
    marker: { color: DETECTOR_COLORS[det] || '#64748b' },
  }));

  const layout = {
    ...PLOTLY_LAYOUT,
    height: 320,
    barmode: 'overlay',
    xaxis: {
      ...PLOTLY_LAYOUT.xaxis,
      title: { text: 'Anomaly Score (0 - 1.0)', font: { size: 10, color: '#64748b' } },
    },
    yaxis: {
      ...PLOTLY_LAYOUT.yaxis,
      title: { text: 'Frequency', font: { size: 10, color: '#64748b' } },
    },
  };

  Plotly.newPlot('chart-score-dist', traces, layout, PLOTLY_CONFIG);
}

function renderDeptStatsChart(stats) {
  const container = document.getElementById('chart-dept-stats');
  if (!stats || !stats.length) {
    showEmpty(container, 'No department statistics available.');
    return;
  }

  // Filter out any rows with empty department names to avoid blank category axis entries
  const filtered = stats.filter(s => s.department && s.department.trim());
  if (!filtered.length) {
    showEmpty(container, 'No department statistics available.');
    return;
  }

  const deptNames = filtered.map(s => s.department);

  const traceAvg = {
    type: 'bar',
    name: 'Mean Outbound (Bytes)',
    x: deptNames,
    y: filtered.map(s => s.avg_bytes_out || 0),
    marker: { color: '#3b82f6' },
    hovertemplate: '<b>%{x}</b><br>Mean: %{y:,.0f} bytes<extra></extra>',
  };

  const traceMax = {
    type: 'bar',
    name: 'Max Observed Peak (Bytes)',
    x: deptNames,
    y: filtered.map(s => s.max_bytes_out || 0),
    marker: { color: '#f97316' },
    hovertemplate: '<b>%{x}</b><br>Peak: %{y:,.0f} bytes<extra></extra>',
  };

  const layout = {
    ...PLOTLY_LAYOUT,
    height: 380,
    barmode: 'group',
    margin: { t: 24, b: 80, l: 64, r: 24 },
    xaxis: {
      ...PLOTLY_LAYOUT.xaxis,
      // Force category type so department name strings are NEVER parsed as dates
      type: 'category',
      tickangle: -30,
      tickfont: { size: 10, color: '#94a3b8' },
    },
    yaxis: {
      ...PLOTLY_LAYOUT.yaxis,
      title: { text: 'Bytes Transmitted', font: { size: 10, color: '#64748b' } },
      tickformat: '~s',
    },
  };

  Plotly.purge(container);
  Plotly.newPlot(container, [traceAvg, traceMax], layout, PLOTLY_CONFIG);
}

function renderShapChart(shap) {
  const container = document.getElementById('chart-shap');
  if (!shap || !shap.available) {
    showEmpty(container, 'SHAP feature attribution values not generated yet.');
    return;
  }

  const features = shap.features.slice(0, 15);

  const trace = {
    type: 'bar',
    orientation: 'h',
    y: features.map(f => f.feature),
    x: features.map(f => f.importance),
    marker: {
      color: features.map(f => f.importance),
      colorscale: [
        [0, '#10b981'],
        [0.4, '#eab308'],
        [1, '#f43f5e'],
      ],
      line: { color: 'rgba(255,255,255,0.1)', width: 1 },
    },
    hovertemplate: '<b>%{y}</b><br>SHAP Contribution: %{x:.4f}<extra></extra>',
  };

  const layout = {
    ...PLOTLY_LAYOUT,
    height: 460,
    margin: { t: 20, b: 40, l: 180, r: 24 },
    yaxis: {
      ...PLOTLY_LAYOUT.yaxis,
      autorange: 'reversed',
      tickfont: { family: 'JetBrains Mono, monospace', size: 11, color: '#e2e8f0' },
    },
    xaxis: {
      ...PLOTLY_LAYOUT.xaxis,
      title: { text: 'Mean Absolute SHAP Value (XGBoost)', font: { size: 10, color: '#64748b' } },
    },
  };

  Plotly.newPlot('chart-shap', [trace], layout, PLOTLY_CONFIG);
}

function renderNetworkTopology(data) {
  const container = document.getElementById('chart-network');
  if (!data || !data.length) {
    showEmpty(container, 'No network flow topology data available.');
    return;
  }

  const users = [...new Set(data.map(d => d.user_id))];
  const dsts = [...new Set(data.map(d => d.dst_ip))];

  // Radial concentric positioning: Users on inner ring (radius 0.4), Dst on outer ring (radius 0.85)
  const nodeCoords = {};

  users.forEach((u, i) => {
    const angle = (2 * Math.PI * i) / users.length;
    nodeCoords[u] = {
      x: 0.38 * Math.cos(angle),
      y: 0.38 * Math.sin(angle),
      type: 'user',
      label: u,
    };
  });

  dsts.forEach((d, i) => {
    const angle = (2 * Math.PI * i) / dsts.length;
    nodeCoords[d] = {
      x: 0.88 * Math.cos(angle),
      y: 0.88 * Math.sin(angle),
      type: 'dst',
      label: d,
    };
  });

  // Edge traces
  const edgeTraces = data.map(d => {
    const uPos = nodeCoords[d.user_id];
    const dPos = nodeCoords[d.dst_ip];
    if (!uPos || !dPos) return null;

    const isSusp = d.is_suspicious || d.dst_category === 'cloud_storage';
    const edgeColor = isSusp ? 'rgba(244, 63, 94, 0.45)' : 'rgba(59, 130, 246, 0.15)';
    const edgeWidth = isSusp ? 2 : 0.8;

    return {
      type: 'scatter',
      mode: 'lines',
      x: [uPos.x, dPos.x],
      y: [uPos.y, dPos.y],
      line: { color: edgeColor, width: edgeWidth },
      hoverinfo: 'skip',
      showlegend: false,
    };
  }).filter(Boolean);

  // User nodes
  const userTrace = {
    type: 'scatter',
    mode: 'markers+text',
    name: 'Monitored Users',
    x: users.map(u => nodeCoords[u].x),
    y: users.map(u => nodeCoords[u].y),
    marker: {
      size: 14,
      color: '#3b82f6',
      line: { color: '#fff', width: 1.5 },
    },
    text: users,
    textposition: 'top center',
    textfont: { size: 10, color: '#93c5fd', family: 'JetBrains Mono' },
    hovertemplate: '<b>Internal User: %{text}</b><extra></extra>',
  };

  // Destination nodes
  const dstTrace = {
    type: 'scatter',
    mode: 'markers',
    name: 'External Endpoints',
    x: dsts.map(d => nodeCoords[d].x),
    y: dsts.map(d => nodeCoords[d].y),
    marker: {
      size: dsts.map(d => {
        const item = data.find(x => x.dst_ip === d);
        return item && (item.is_suspicious || item.dst_category === 'cloud_storage') ? 12 : 7;
      }),
      color: dsts.map(d => {
        const item = data.find(x => x.dst_ip === d);
        return item && (item.is_suspicious || item.dst_category === 'cloud_storage') ? '#f43f5e' : '#10b981';
      }),
      line: { color: 'rgba(255,255,255,0.2)', width: 1 },
    },
    text: dsts,
    hovertemplate: '<b>Endpoint: %{text}</b><extra></extra>',
  };

  const layout = {
    ...PLOTLY_LAYOUT,
    height: 520,
    xaxis: { visible: false, range: [-1.2, 1.2] },
    yaxis: { visible: false, range: [-1.2, 1.2] },
    showlegend: false,
    margin: { t: 20, b: 20, l: 20, r: 20 },
  };

  Plotly.newPlot('chart-network', [...edgeTraces, userTrace, dstTrace], layout, PLOTLY_CONFIG);
}

// ══════════════════════════════════════════════════════════════
// 6. PRIVACY & AUDIT PAGE
// ══════════════════════════════════════════════════════════════
async function loadPrivacyPage() {
  renderPrivacyControls();
  renderRevealForm();
  await loadAuditLog();
}

function renderPrivacyControls() {
  const controls = [
    { name: 'Zero-Payload Decryption', desc: 'Flow duration, packet inter-arrival timing, entropy, and volume analyzed. No TLS payload interception.' },
    { name: 'Pseudonymized User Identifiers', desc: 'Real identities replaced with cryptographically isolated surrogate keys (e.g. USER-003).' },
    { name: 'Dual-Key Gated De-Anonymization', desc: 'Identity reveal requires minimum HIGH severity (risk score >= 60.0) plus SOC Lead sign-off.' },
    { name: 'Role-Based Access Control (RBAC)', desc: 'Strict segregation between Triage Analyst, Lead Investigator, and Compliance Auditor roles.' },
    { name: 'Immutable Audit Trail', desc: 'Cryptographically hashed operational log recording every query, simulation, and de-anonymization.' },
    { name: 'Human-in-the-Loop Decisions', desc: 'AI engines suggest containment procedures; human analysts retain sole authority over user actions.' },
    { name: 'Departmental Bias Monitoring', desc: 'Alert ratios normalized by role to prevent unfair targeting of technical departments.' },
    { name: 'Data Minimization & Auto-Purge', desc: 'No sensitive URLs or file contents retained; 90-day automated telemetry expiration policy.' },
  ];

  document.getElementById('privacy-controls').innerHTML = controls.map(c => `
    <div class="control-item">
      <div class="control-icon">&#x2714;</div>
      <div class="control-text">
        <h4>${c.name}</h4>
        <p>${c.desc}</p>
      </div>
    </div>
  `).join('');
}

function renderRevealForm() {
  const container = document.getElementById('reveal-form-container');
  const users = appState.riskSummary.length ? appState.riskSummary : [{ user_id: 'USER-003', risk_score: 65, severity: 'high' }];

  container.innerHTML = `
    <form id="form-reveal" onsubmit="handleRevealSubmit(event)">
      <div class="sim-param-group">
        <label class="sim-param-label">Target Pseudonym:</label>
        <select id="reveal-pseudo" class="form-select">
          ${users.map(u => `<option value="${u.user_id}">${u.user_id} (Risk: ${u.risk_score.toFixed(0)} - ${u.severity.toUpperCase()})</option>`).join('')}
        </select>
      </div>
      <div class="sim-param-group">
        <label class="sim-param-label">Requester Role:</label>
        <select id="reveal-requester" class="form-select">
          <option value="lead_investigator">Lead SOC Investigator (Level 3)</option>
          <option value="data_privacy_officer">Data Privacy Officer (DPO)</option>
          <option value="analyst_tier2">Security Analyst (Tier 2)</option>
        </select>
      </div>
      <div class="sim-param-group">
        <label class="sim-param-label">Investigation Justification:</label>
        <textarea id="reveal-reason" class="search-input-wrapper form-select" rows="3" placeholder="Provide formal business justification, linked incident case ID, and regulatory scope..." required></textarea>
      </div>
      <button type="submit" class="btn btn-primary" style="width:100%;">
        Submit Gated Reveal Request
      </button>
    </form>
  `;
}

async function handleRevealSubmit(e) {
  e.preventDefault();
  const pseudoId = document.getElementById('reveal-pseudo').value;
  const requester = document.getElementById('reveal-requester').value;
  const justification = document.getElementById('reveal-reason').value.trim();

  try {
    const res = await postJSON('/api/reveal', {
      pseudo_id: pseudoId,
      requester: requester,
      justification: justification,
    });

    if (res.status === 'denied') {
      showToast(`Reveal Denied: ${res.message}`, 'error');
    } else {
      showToast(`Reveal Request Logged: ${res.message}`, 'success');
      document.getElementById('reveal-reason').value = '';
    }
    await loadAuditLog();
  } catch (err) {
    showToast('Failed to submit reveal request: ' + err.message, 'error');
  }
}

async function loadAuditLog() {
  try {
    const logs = await fetchJSON('/api/audit-log');
    const container = document.getElementById('audit-table');
    if (!logs.length) {
      showEmpty(container, 'No audit actions recorded in this session.');
      return;
    }

    container.innerHTML = `
      <table class="data-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Target</th>
            <th>Result</th>
          </tr>
        </thead>
        <tbody>
          ${[...logs].reverse().slice(0, 15).map(l => `
            <tr>
              <td class="mono text-xs text-muted">${(l.ts || '').replace('T', ' ').slice(11, 19)}</td>
              <td><span class="badge-subtle">${l.actor}</span></td>
              <td>${l.action}</td>
              <td class="mono text-xs">${l.target}</td>
              <td><span class="severity-badge ${l.result.includes('Success') || l.result.includes('Pending') ? 'low' : 'critical'}">${l.result}</span></td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  } catch (err) {
    console.error('Audit log fetch error:', err);
  }
}

// ══════════════════════════════════════════════════════════════
// 7. THREAT SIMULATOR PAGE
// ══════════════════════════════════════════════════════════════
async function loadSimulatorPage() {
  try {
    const scenarios = await fetchJSON('/api/scenarios');
    renderScenarioCatalog(scenarios);
    renderSimForm();
  } catch (err) {
    showToast('Failed to load scenarios: ' + err.message, 'error');
  }
}

function renderScenarioCatalog(scenarios) {
  const container = document.getElementById('scenario-table');
  if (!scenarios || !scenarios.length) {
    showEmpty(container, 'No scenarios found in catalog.');
    return;
  }

  window._simScenarios = scenarios;

  container.innerHTML = `
    <table class="data-table">
      <thead>
        <tr>
          <th>Scenario</th>
          <th>Description</th>
          <th>Target User</th>
          <th>Exfil Target</th>
          <th>Expected Detectors</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody>
        ${scenarios.map((s, i) => `
          <tr>
            <td><strong class="text-white">${s.name || s.scenario}</strong></td>
            <td class="text-xs text-muted" style="max-width:280px;line-height:1.4;">${s.description || 'Simulated anomalous behavior pattern'}</td>
            <td class="mono font-semibold">${s.user_id || 'USER-003'}</td>
            <td class="mono text-xs">${s.destination || 'mega.nz'}</td>
            <td><span class="tag-pill" style="font-size:0.75rem;">${s.expected_detectors || 'Ensemble'}</span></td>
            <td>
              <button class="btn btn-outline btn-sm" onclick="loadSimPresetByIndex(${i})">
                Load Preset
              </button>
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

function renderSimForm() {
  const container = document.getElementById('sim-form-container');
  container.innerHTML = `
    <form id="form-simulate" onsubmit="handleSimulateSubmit(event)">
      <div class="sim-param-group">
        <label class="sim-param-label">Scenario Name:</label>
        <input type="text" id="sim-scenario" class="form-select" value="Cloud Storage Exfiltration (High Volume)" required>
      </div>
      <div class="sim-param-group">
        <label class="sim-param-label">Simulated User Subject:</label>
        <select id="sim-user" class="form-select">
          <option value="USER-003">USER-003 (Finance / Active Resignation Notice)</option>
          <option value="USER-001">USER-001 (DevOps / Baseline Engineer)</option>
          <option value="USER-002">USER-002 (HR / Normal Profile)</option>
          <option value="USER-004">USER-004 (Database Engineering)</option>
          <option value="USER-007">USER-007 (IT Helpdesk Specialist)</option>
          <option value="USER-009">USER-009 (Systems Engineering / Flagged Ingress)</option>
          <option value="USER-010">USER-010 (External Contractor)</option>
        </select>
      </div>
      <div class="sim-param-group">
        <div class="sim-param-label">
          <span>Transfer Volume:</span>
          <span class="sim-param-val" id="sim-vol-val">1250 MB</span>
        </div>
        <input type="range" id="sim-volume" min="10" max="3000" step="25" value="1250" oninput="document.getElementById('sim-vol-val').textContent = this.value + ' MB'">
      </div>
      <div class="sim-param-group">
        <label class="sim-param-label">Destination IP / Domain:</label>
        <input type="text" id="sim-dest" class="form-select" value="mega.nz" required>
      </div>
      <div class="sim-param-group">
        <label class="sim-param-label">DNS Query (Optional Tunneling Probe):</label>
        <input type="text" id="sim-dns" class="form-select" placeholder="e.g. 783abdf1890cdfe991204857bca.tunnel.darkops-c2.net" value="">
      </div>
      <div class="sim-param-group" style="flex-direction:row;align-items:center;gap:10px;">
        <input type="checkbox" id="sim-after-hours" checked style="width:16px;height:16px;cursor:pointer;">
        <label for="sim-after-hours" style="font-size:0.8rem;color:#fff;cursor:pointer;">Simulate During After-Hours Window (22:45 UTC)</label>
      </div>
      <button type="submit" class="btn btn-primary" id="btn-run-sim" style="width:100%;margin-top:10px;">
        <span>Run Threat Simulation</span> &rarr;
      </button>
    </form>
  `;
}

window.loadSimPresetByIndex = function (idx) {
  if (!window._simScenarios || !window._simScenarios[idx]) return;
  const s = window._simScenarios[idx];
  window.loadSimPreset(
    s.name || s.scenario,
    s.user_id || 'USER-003',
    s.volume_mb || 500,
    s.destination || 'mega.nz',
    s.after_hours !== undefined ? s.after_hours : true,
    s.dns_query || ''
  );
};

window.loadSimPreset = function (name, user, vol, dest, afterHours, dns) {
  const scenInput = document.getElementById('sim-scenario');
  const userInput = document.getElementById('sim-user');
  const volInput = document.getElementById('sim-volume');
  const volVal = document.getElementById('sim-vol-val');
  const destInput = document.getElementById('sim-dest');
  const afterInput = document.getElementById('sim-after-hours');
  const dnsInput = document.getElementById('sim-dns');

  if (scenInput) scenInput.value = name;
  if (userInput) {
    let found = false;
    for (let opt of userInput.options) {
      if (opt.value === user) {
        userInput.value = user;
        found = true;
        break;
      }
    }
    if (!found) {
      const newOpt = document.createElement('option');
      newOpt.value = user;
      newOpt.textContent = `${user} (Target)`;
      userInput.appendChild(newOpt);
      userInput.value = user;
    }
  }
  if (volInput) {
    volInput.value = vol;
    if (volVal) volVal.textContent = vol + ' MB';
  }
  if (destInput) destInput.value = dest;
  if (afterInput) afterInput.checked = Boolean(afterHours);
  if (dnsInput) dnsInput.value = dns || '';
  showToast(`Loaded preset "${name}"`, 'info');
};

async function handleSimulateSubmit(e) {
  e.preventDefault();
  const resultsContainer = document.getElementById('sim-results');
  showLoading(resultsContainer);

  const payload = {
    scenario: document.getElementById('sim-scenario').value,
    user_id: document.getElementById('sim-user').value,
    volume_mb: parseInt(document.getElementById('sim-volume').value, 10),
    destination: document.getElementById('sim-dest').value,
    after_hours: document.getElementById('sim-after-hours').checked,
    dns_query: (document.getElementById('sim-dns').value || '').trim(),
  };

  try {
    const res = await postJSON('/api/simulate', payload);
    const isCritical = res.max_score >= 0.7;
    const isHigh = res.max_score >= 0.4;
    const statusClass = isCritical ? 'critical' : isHigh ? 'high' : 'normal';
    const kcClass = isCritical ? 'critical' : isHigh ? 'high' : 'normal';

    resultsContainer.innerHTML = `
      <div class="sim-result-card">
        <div class="sim-verdict-banner ${statusClass}">
          <div>
            <div style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.8px;font-weight:600;">Engine Evaluation Verdict</div>
            <div style="font-size:1.25rem;font-weight:700;">${res.status}</div>
          </div>
          <div class="mono" style="font-size:1.85rem;font-weight:700;">${(res.max_score * 100).toFixed(0)}%</div>
        </div>

        <div>
          <div style="font-size:0.75rem;font-weight:600;color:var(--text-tertiary);text-transform:uppercase;margin-bottom:8px;">Triggered Detection Models</div>
          ${(res.triggered_detectors && res.triggered_detectors.length) ? (res.triggered_detectors.map(d => `
            <div style="display:flex;align-items:center;justify-content:space-between;background:var(--bg-surface);padding:8px 12px;border-radius:6px;margin-bottom:6px;border:1px solid var(--border-subtle);">
              <span style="font-weight:600;font-size:0.85rem;color:#fff;">${d.name}</span>
              <span class="mono" style="color:var(--accent-hover);font-weight:700;">${(d.score * 100).toFixed(0)}% Confidence</span>
            </div>
          `).join('')) : `
            <div style="padding:10px 14px;background:var(--bg-surface);border-radius:6px;border:1px dashed var(--border-subtle);font-size:0.8rem;color:var(--text-muted);">
              &#x2714; No anomaly detectors triggered. Evaluated activity conforms to established benign baselines.
            </div>
          `}
        </div>

        ${(res.tags && res.tags.length) ? `
          <div>
            <div style="font-size:0.75rem;font-weight:600;color:var(--text-tertiary);text-transform:uppercase;margin-bottom:6px;">Behavioral Evidence Tags</div>
            <div style="display:flex;flex-wrap:wrap;gap:6px;">
              ${res.tags.map(t => `<span class="tag-pill" style="background:rgba(99,102,241,0.15);border:1px solid rgba(99,102,241,0.3);color:#a5b4fc;font-size:0.72rem;padding:3px 8px;border-radius:4px;">${t}</span>`).join('')}
            </div>
          </div>
        ` : ''}

        <div>
          <div style="font-size:0.75rem;font-weight:600;color:var(--text-tertiary);text-transform:uppercase;margin-bottom:6px;">Kill Chain Stage</div>
          <span class="severity-badge ${kcClass}">${res.kill_chain_stage}</span>
        </div>

        <div>
          <div style="font-size:0.75rem;font-weight:600;color:var(--text-tertiary);text-transform:uppercase;margin-bottom:6px;">GenAI Analysis &amp; Remediation Guidance</div>
          <p style="font-size:0.825rem;line-height:1.55;color:var(--text-primary);margin-bottom:8px;">${res.narrative}</p>
          <ul style="padding-left:18px;font-size:0.78rem;color:var(--text-secondary);line-height:1.45;">
            ${(res.recommended_actions || []).map(a => `<li style="margin-bottom:4px;">${a}</li>`).join('')}
          </ul>
        </div>
      </div>
    `;
    showToast('Simulation evaluated successfully', 'success');
  } catch (err) {
    showToast('Simulation error: ' + err.message, 'error');
    resultsContainer.innerHTML = `<div class="state-container"><span class="state-icon">&#x26A0;</span><span class="state-text">${err.message}</span></div>`;
  }
}

// ══════════════════════════════════════════════════════════════
// 8. MODALS & CASE DOSSIER
// ══════════════════════════════════════════════════════════════
window.openCaseModal = async function (caseId) {
  appState.currentModalCaseId = caseId;
  const modal = document.getElementById('case-modal');
  const title = document.getElementById('case-modal-title');
  const body = document.getElementById('case-modal-body');

  title.textContent = caseId;
  showLoading(body);
  modal.classList.add('open');

  try {
    const exp = await fetchJSON(`/api/explanations/${caseId}`);
    body.innerHTML = `
      <div style="margin-bottom:16px;">
        <h4 style="font-size:0.85rem;color:var(--text-tertiary);text-transform:uppercase;margin-bottom:4px;">Executive Incident Summary</h4>
        <p style="font-size:0.95rem;color:#fff;line-height:1.5;">${exp.summary || 'Correlated behavioral anomaly.'}</p>
      </div>

      <div style="margin-bottom:16px;">
        <h4 style="font-size:0.85rem;color:var(--text-tertiary);text-transform:uppercase;margin-bottom:6px;">Contributing Factors</h4>
        <ul style="padding-left:18px;">
          ${(exp.why_flagged || []).map(w => `<li style="margin-bottom:4px;">${w}</li>`).join('')}
        </ul>
      </div>

      <div style="margin-bottom:16px;">
        <h4 style="font-size:0.85rem;color:var(--text-tertiary);text-transform:uppercase;margin-bottom:6px;">Recommended Triage &amp; Containment</h4>
        <ul style="padding-left:18px;">
          ${(exp.recommended_actions || []).map(r => `<li style="margin-bottom:4px;">${r}</li>`).join('')}
        </ul>
      </div>

      <div>
        <h4 style="font-size:0.85rem;color:var(--text-tertiary);text-transform:uppercase;margin-bottom:4px;">Kill-Chain Progression Assessment</h4>
        <span class="severity-badge high">${exp.kill_chain_assessment || 'Stage 3: Data Exfiltration'}</span>
      </div>
    `;
  } catch (err) {
    body.innerHTML = `<div class="state-container"><span class="state-text">No detailed AI explanation found for ${caseId}.</span></div>`;
  }
};

window.openIncidentReport = async function (caseId) {
  const modal = document.getElementById('report-modal');
  const title = document.getElementById('report-modal-title');
  const body = document.getElementById('report-modal-body');

  title.textContent = `Incident Report — ${caseId}`;
  showLoading(body);
  modal.classList.add('open');

  try {
    const data = await fetchJSON(`/api/report/${caseId}`);
    if (window.marked && typeof window.marked.parse === 'function') {
      body.innerHTML = window.marked.parse(data.report);
    } else {
      body.innerHTML = `<pre><code>${data.report}</code></pre>`;
    }

    const copyBtn = document.getElementById('btn-copy-report');
    if (copyBtn) {
      copyBtn.onclick = () => {
        navigator.clipboard.writeText(data.report);
        showToast('Incident Report copied to clipboard', 'success');
      };
    }
  } catch (err) {
    body.innerHTML = `<div class="state-container"><span class="state-text">Report file not generated yet for ${caseId}.</span></div>`;
  }
};

function initModalHandlers() {
  document.getElementById('case-modal-close').onclick = () => {
    document.getElementById('case-modal').classList.remove('open');
  };
  document.getElementById('report-modal-close').onclick = () => {
    document.getElementById('report-modal').classList.remove('open');
  };

  // View full report from inside case modal
  document.getElementById('btn-modal-view-report').onclick = () => {
    if (appState.currentModalCaseId) {
      document.getElementById('case-modal').classList.remove('open');
      openIncidentReport(appState.currentModalCaseId);
    }
  };

  // Investigate user from case modal
  document.getElementById('btn-modal-investigate-user').onclick = () => {
    if (appState.currentModalCaseId) {
      const c = appState.cases.find(x => x.case_id === appState.currentModalCaseId);
      document.getElementById('case-modal').classList.remove('open');
      if (c && c.user_id) {
        appState.currentUser = c.user_id;
        switchPage('users');
      }
    }
  };
}

// ══════════════════════════════════════════════════════════════
// ADMIN IDENTITY REVEAL  —  Session-Token Architecture
// ══════════════════════════════════════════════════════════════
//
// Security model:
//   1. Admin enters password ONCE → POST /api/admin/session → server
//      validates and returns a short-lived opaque token (no PII returned).
//   2. Each identity reveal is a separate POST /api/admin/reveal with:
//        { session_token, pseudo_id }  — no password re-transmission.
//   3. Server returns ONLY the requested user's data per call.
//   4. Token stored only in JS heap (never localStorage / sessionStorage).
//   5. revealedIdentities cache lives in JS memory only — cleared on reload.
//
let adminSessionToken = null;          // opaque token from /api/admin/session
let adminSessionExpiry = null;         // client-side expiry mirror (ms epoch)
const revealedIdentities = new Map();  // pseudo_id → identity (lazy, per-user)
let chartNamesRevealed = false;        // track chart label toggle state

// ── Core token helpers ────────────────────────────────────────────────
function isAdminSessionActive() {
  if (!adminSessionToken) return false;
  if (adminSessionExpiry && Date.now() > adminSessionExpiry) {
    adminSessionToken = null;
    adminSessionExpiry = null;
    return false;
  }
  return true;
}

async function fetchIdentity(pseudoId) {
  /** Reveal a single user's identity on demand. Caches result in memory. */
  if (!isAdminSessionActive()) throw new Error('Session expired');
  if (revealedIdentities.has(pseudoId)) return revealedIdentities.get(pseudoId);

  const res = await postJSON('/api/admin/reveal', {
    pseudo_id: pseudoId,
    session_token: adminSessionToken,
    justification: 'On-demand admin reveal via SOC dashboard',
    requester: 'SOC Admin',
  });

  if (res.status === 'success') {
    revealedIdentities.set(pseudoId, res.identity);
    return res.identity;
  }
  throw new Error('Reveal failed: ' + (res.detail || 'Unknown error'));
}

// ── Admin password modal & session creation ────────────────────────────
function initAdminReveal() {
  const revealBtn  = document.getElementById('admin-reveal-btn');
  const modal      = document.getElementById('admin-pw-modal');
  const submitBtn  = document.getElementById('admin-pw-submit');
  const cancelBtn  = document.getElementById('admin-pw-cancel');
  const pwInput    = document.getElementById('admin-pw-input');
  const errorMsg   = document.getElementById('admin-pw-error');
  const identPanel = document.getElementById('admin-identity-panel');

  if (!revealBtn || !modal) return;

  // Click "Admin: Reveal Identity" button
  revealBtn.addEventListener('click', () => {
    if (isAdminSessionActive()) {
      // Session already live — toggle the identity panel for current user
      toggleIdentityPanel(identPanel);
    } else {
      openAdminModal();
    }
  });

  cancelBtn.addEventListener('click', closeAdminModal);
  modal.addEventListener('click', (e) => { if (e.target === modal) closeAdminModal(); });

  function openAdminModal() {
    pwInput.value = '';
    pwInput.classList.remove('error');
    errorMsg.classList.remove('visible');
    modal.classList.add('open');
    setTimeout(() => pwInput.focus(), 200);
  }

  function closeAdminModal() {
    modal.classList.remove('open');
  }

  // Step 1: Authenticate and get session token — no PII returned here
  async function attemptAuthenticate() {
    const password = pwInput.value.trim();
    if (!password) return;

    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span>Authenticating...</span>';

    try {
      const res = await postJSON('/api/admin/session', {
        password,
        requester: 'SOC Admin',
      });

      if (res.status === 'authorized' && res.session_token) {
        adminSessionToken = res.session_token;
        // Mirror the server-side expiry client-side (with a 30s buffer)
        adminSessionExpiry = Date.now() + (res.expires_in_seconds - 30) * 1000;

        closeAdminModal();

        revealBtn.classList.add('unlocked');
        revealBtn.innerHTML = `
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
            <path d="M7 11V7a5 5 0 0 1 5-5"></path>
          </svg>
          Session Active
        `;
        showToast('Admin session created. Reveals are gated per-user on demand.', 'success');

        // Show "Reveal Names" button on risk chart
        const chartRevealBtn = document.getElementById('chart-reveal-names-btn');
        if (chartRevealBtn) chartRevealBtn.style.display = 'inline-flex';

        // Step 2: Reveal identity for whichever user is currently selected
        await showIdentityPanel(identPanel);
      }
    } catch (err) {
      pwInput.classList.add('error');
      errorMsg.classList.add('visible');
      setTimeout(() => pwInput.classList.remove('error'), 500);
      showToast('Authentication failed — check your admin password.', 'error');
    } finally {
      submitBtn.disabled = false;
      submitBtn.innerHTML = `
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
        </svg>
        Unlock Identity
      `;
    }
  }

  submitBtn.addEventListener('click', attemptAuthenticate);
  pwInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') attemptAuthenticate(); });

  // Auto-refresh identity panel when the user dropdown changes
  document.getElementById('user-select')?.addEventListener('change', async () => {
    if (isAdminSessionActive() && identPanel && identPanel.style.display !== 'none') {
      await showIdentityPanel(identPanel);
    }
  });

  // Wire up the "Reveal Names" chart toggle
  const chartRevealBtn = document.getElementById('chart-reveal-names-btn');
  if (chartRevealBtn) {
    chartRevealBtn.addEventListener('click', () => toggleChartNames());
  }
}

// ── Identity panel (User Analysis page) ──────────────────────────────
async function showIdentityPanel(panel) {
  if (!panel) return;
  const userId = appState.currentUser || document.getElementById('user-select')?.value;
  if (!userId || !isAdminSessionActive()) return;

  // Show loading state
  panel.style.display = 'block';
  panel.innerHTML = `
    <div class="identity-card">
      <div class="loading-inline" style="padding:8px 0;">
        <div class="spinner"></div>
        <span>Fetching identity for <strong>${userId}</strong> — single-user reveal…</span>
      </div>
    </div>
  `;

  try {
    const identity = await fetchIdentity(userId);
    renderIdentityCard(panel, userId, identity);
  } catch (err) {
    panel.innerHTML = `
      <div class="identity-card">
        <p style="color:var(--severity-critical);font-size:0.8rem;">
          ⚠ Reveal failed: ${err.message}. Your session may have expired — please re-authenticate.
        </p>
      </div>
    `;
    if (err.message.includes('expired') || err.message.includes('401')) {
      adminSessionToken = null;
      adminSessionExpiry = null;
    }
  }
}

function renderIdentityCard(panel, userId, identity) {
  const initials   = identity.name.split(' ').map(n => n[0]).join('');
  const isHighRisk = identity.hr_status && (
    identity.hr_status.toLowerCase().includes('resign') ||
    identity.hr_status.toLowerCase().includes('leave')  ||
    identity.hr_status.toLowerCase().includes('flag')
  );

  panel.style.display = 'block';
  panel.innerHTML = `
    <div class="identity-card">
      ${isHighRisk
        ? `<div class="identity-warning-badge">&#x26A0; ${identity.hr_status}</div>`
        : ''}
      <div class="identity-card-header">
        <div class="identity-avatar">${initials}</div>
        <div class="identity-name-group">
          <div class="identity-real-name">${identity.name}</div>
          <div class="identity-emp-id">${identity.employee_id} &middot; ${identity.email}</div>
        </div>
        <div style="display:flex;flex-direction:column;align-items:flex-end;gap:6px;">
          ${severityBadge('critical')}
          <span style="font-size:0.68rem;color:var(--text-muted);font-family:'JetBrains Mono',monospace;">
            &#x1F512; ${userId}
          </span>
        </div>
      </div>
      <div class="identity-fields">
        <div class="identity-field">
          <span class="identity-field-label">Department</span>
          <span class="identity-field-value">${identity.department}</span>
        </div>
        <div class="identity-field">
          <span class="identity-field-label">Role</span>
          <span class="identity-field-value">${identity.role}</span>
        </div>
        <div class="identity-field">
          <span class="identity-field-label">IP Address</span>
          <span class="identity-field-value">${identity.ip}</span>
        </div>
        <div class="identity-field">
          <span class="identity-field-label">Device</span>
          <span class="identity-field-value">${identity.device}</span>
        </div>
        <div class="identity-field">
          <span class="identity-field-label">Clearance</span>
          <span class="identity-field-value">${identity.clearance}</span>
        </div>
        <div class="identity-field">
          <span class="identity-field-label">HR Status</span>
          <span class="identity-field-value"
            style="${isHighRisk ? 'color:var(--severity-critical)' : 'color:var(--severity-low)'}">
            ${identity.hr_status}
          </span>
        </div>
      </div>
      <p style="font-size:0.65rem;color:var(--text-muted);margin-top:10px;text-align:right;">
        &#x1F4CB; This reveal is logged in the audit trail. Session expires in ~1h.
      </p>
    </div>
  `;
}

function toggleIdentityPanel(panel) {
  if (!panel) return;
  if (panel.style.display === 'none' || !panel.style.display) {
    showIdentityPanel(panel);
  } else {
    panel.style.display = 'none';
  }
}

// ── Risk chart: "Reveal Names" toggle ────────────────────────────────
async function toggleChartNames() {
  if (!isAdminSessionActive()) {
    showToast('Start an admin session first to reveal real names on the chart.', 'error');
    return;
  }

  const btn = document.getElementById('chart-reveal-names-btn');
  chartNamesRevealed = !chartNamesRevealed;

  if (!chartNamesRevealed) {
    // Restore pseudonym labels — just re-render the original chart
    if (btn) {
      btn.classList.remove('unlocked');
      btn.innerHTML = `
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
        </svg>
        Reveal Names
      `;
    }
    // Re-render chart with original pseudonym labels
    if (appState.users) renderRiskBarChart(appState.users);
    return;
  }

  // Reveal mode ON — fetch real names for all visible bars
  if (btn) {
    btn.innerHTML = '<div class="spinner" style="width:12px;height:12px;border-width:1.5px;"></div> Fetching…';
    btn.disabled = true;
  }

  const users = appState.users || [];
  const sorted = [...users].sort((a, b) => b.risk_score - a.risk_score);

  // Fetch identities in parallel — each is an individual gated API call
  const results = await Promise.allSettled(
    sorted.map(u => fetchIdentity(u.user_id))
  );

  // Build a label map: pseudo_id → "First L. (USER-003)"
  const labelMap = {};
  sorted.forEach((u, i) => {
    const result = results[i];
    if (result.status === 'fulfilled') {
      const name = result.value.name;
      // Show abbreviated name to keep bar readable, append pseudonym
      const parts = name.split(' ');
      const abbrev = parts.length > 1
        ? `${parts[0]} ${parts[parts.length - 1][0]}.`
        : parts[0];
      labelMap[u.user_id] = `${abbrev}\n(${u.user_id})`;
    } else {
      labelMap[u.user_id] = u.user_id;  // fallback to pseudonym
    }
  });

  // Re-render with real name labels
  renderRiskBarChartWithLabels(sorted, labelMap);

  if (btn) {
    btn.disabled = false;
    btn.classList.add('unlocked');
    btn.innerHTML = `
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
        <path d="M7 11V7a5 5 0 0 1 5-5"></path>
      </svg>
      Hide Names
    `;
  }
  showToast(`${results.filter(r => r.status === 'fulfilled').length} identities revealed on chart.`, 'success');
}

function renderRiskBarChartWithLabels(sorted, labelMap) {
  /** Variant of renderRiskBarChart that uses real-name labels on the x-axis. */
  const getRiskColor = (severity) => {
    switch (severity) {
      case 'critical':
      case 'high':
        return '#d55e00'; // Vermilion
      case 'medium':
        return '#e69f00'; // Amber
      case 'low':
        return '#0284c7'; // Blue
      default:
        return '#64748b'; // Slate
    }
  };

  const getRiskPattern = (severity) => {
    switch (severity) {
      case 'critical':
      case 'high':
        return '/';
      case 'medium':
        return '.';
      default:
        return '';
    }
  };

  const colors = sorted.map(u => getRiskColor(u.severity));
  const patterns = sorted.map(u => getRiskPattern(u.severity));

  // Update takeaway text with revealed real names
  const takeawayEl = document.getElementById('risk-chart-takeaway-text');
  if (takeawayEl && sorted.length > 0) {
    const topUser = sorted[0];
    const realLabel = (labelMap[topUser.user_id] || topUser.user_id).replace('\n', ' ');
    takeawayEl.innerHTML = `<strong>${realLabel}</strong> is the only account crossing the High Risk threshold (Score: <strong>${topUser.risk_score.toFixed(1)} pts</strong> with ${topUser.alert_count} alerts) and requires immediate SOC investigation. All other accounts remain in safe monitoring ranges.`;
  }

  const trace = {
    type: 'bar',
    x: sorted.map(u => labelMap[u.user_id] || u.user_id),
    y: sorted.map(u => u.risk_score),
    marker: {
      color: colors,
      pattern: {
        shape: patterns,
        fillmode: 'overlay',
        fgcolor: 'rgba(255, 255, 255, 0.45)',
        size: 7,
      },
      line: { color: 'rgba(255, 255, 255, 0.35)', width: 1.5 },
    },
    text: sorted.map(u => `${u.risk_score.toFixed(1)} pts<br><b>${u.severity.toUpperCase()}</b>`),
    textposition: 'outside',
    textfont: { family: 'Inter, sans-serif', size: 11, color: '#ffffff', weight: 600 },
    customdata: sorted.map(u => [
      u.user_id,
      u.severity.toUpperCase(),
      u.alert_count,
      (labelMap[u.user_id] || u.user_id).split('\n')[0],
      u.risk_score >= 60 ? '🚨 EXCEEDS THRESHOLD (+ ' + (u.risk_score - 60).toFixed(1) + ' pts)' : '✓ Below High Risk Threshold',
      u.risk_score >= 60 ? 'Immediate containment & forensic review required' : 'Standard automated monitoring',
    ]),
    hovertemplate:
      '<span style="font-size:14px;font-weight:700;color:#38bdf8;">Employee: %{customdata[3]}</span> <span style="opacity:0.8;font-size:12px;">(%{customdata[0]})</span><br>' +
      '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━<br>' +
      '• <b>Threat Risk Score:</b> %{y:.2f} / 100 points<br>' +
      '• <b>Severity Level:</b> %{customdata[1]} Risk<br>' +
      '• <b>Security Alerts:</b> %{customdata[2]} anomalous events<br>' +
      '• <b>Threshold Check:</b> %{customdata[4]}<br>' +
      '• <b>Recommended Action:</b> %{customdata[5]}<br>' +
      '<span style="font-size:11px;color:#94a3b8;margin-top:4px;">👆 Click or tap bar to inspect user timeline & network flows</span>' +
      '<extra></extra>',
  };

  const layout = {
    ...PLOTLY_LAYOUT,
    height: 350,
    margin: { t: 30, b: 75, l: 75, r: 35 },
    xaxis: {
      ...PLOTLY_LAYOUT.xaxis,
      type: 'category',
      tickangle: -20,
      title: {
        text: 'Employee Identity (Real Name & Pseudonym)',
        font: { size: 13, color: '#f8fafc', family: 'Inter, sans-serif' },
        standoff: 14,
      },
      tickfont: { size: 11, color: '#e2e8f0', family: 'Inter, sans-serif' },
      showgrid: false,
    },
    yaxis: {
      ...PLOTLY_LAYOUT.yaxis,
      range: [0, 100],
      dtick: 20,
      ticksuffix: ' pts',
      title: {
        text: 'Threat Risk Score (Points, 0–100 Scale)',
        font: { size: 13, color: '#f8fafc', family: 'Inter, sans-serif' },
        standoff: 14,
      },
      tickfont: { size: 12, color: '#e2e8f0', family: 'Inter, sans-serif' },
      showgrid: true,
      gridcolor: 'rgba(255,255,255,0.08)',
      zeroline: true,
      zerolinecolor: 'rgba(255,255,255,0.15)',
    },
    shapes: [{
      type: 'line', xref: 'paper', x0: 0, x1: 1, y0: 60, y1: 60,
      line: { color: '#ef4444', dash: 'dash', width: 2 },
    }],
    annotations: [{
      xref: 'paper', x: 0.98, y: 60, text: '▲ High-Risk Action Threshold (60.0 pts)',
      showarrow: false,
      font: { size: 11, color: '#ffffff', family: 'Inter, sans-serif', weight: 600 },
      bgcolor: '#d55e00', bordercolor: '#fca5a5', borderwidth: 1, borderpad: 4,
      xanchor: 'right', yshift: 14,
    }],
  };

  Plotly.purge('chart-risk-bar');
  Plotly.newPlot('chart-risk-bar', [trace], layout, PLOTLY_CONFIG);

  // Re-attach click handler (navigate to user detail)
  document.getElementById('chart-risk-bar').on('plotly_click', (data) => {
    if (data.points?.length) {
      // Recover the pseudo_id from customdata since x is now the real name
      const pseudoId = data.points[0].customdata?.[0];
      if (pseudoId) {
        appState.currentUser = pseudoId;
        switchPage('users');
      }
    }
  });
}

// ── Application Bootstrap ────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  initSystemClock();
  initNavigation();
  initSidebarToggle();
  initTabs();
  initModalHandlers();
  initAdminReveal();

  // Load initial view
  loadOverview();
});
