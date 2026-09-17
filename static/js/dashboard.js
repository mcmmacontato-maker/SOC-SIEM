/* ══════════════════════════════════════════════════════════
   dashboard.js — SOC-SIEM Professional Dashboard Logic
═══════════════════════════════════════════════════════════ */

// ─── State ──────────────────────────────────────────────
let chartTimeline = null;
let chartAttacks = null;
let lastEventId = 0;
let isSimulating = false;
let currentPanel = 'dashboard';

// Chart.js global defaults
Chart.defaults.color = '#3d5a80';
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.font.size = 11;

const PALETTE = ['#1a7edb', '#28d99e', '#f27c39', '#e63950', '#9a6ef5', '#f0b429', '#3eb8d6', '#ff6b9d'];

// ─── Clock ──────────────────────────────────────────────
function tick() {
    const el = document.getElementById('clock');
    if (!el) return;
    const d = new Date();
    el.textContent = d.toLocaleTimeString('pt-BR', { hour12: false });
}
setInterval(tick, 1000);
tick();

// ─── Panel navigation ───────────────────────────────────
document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', e => {
        e.preventDefault();
        const target = item.dataset.panel;
        if (!target) return;
        switchPanel(target);
    });
});

function switchPanel(id) {
    currentPanel = id;
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    const panel = document.getElementById(`panel-${id}`);
    const navEl = document.querySelector(`[data-panel="${id}"]`);
    if (panel) panel.classList.add('active');
    if (navEl) navEl.classList.add('active');

    const titles = { dashboard: 'Overview', alerts: 'Alertas', incidents: 'Incidentes', feed: 'Event Log' };
    const crumbs = { dashboard: 'Dashboard', alerts: 'Alertas', incidents: 'Incidentes', feed: 'Live Log' };
    document.getElementById('page-title').textContent = titles[id] || id;
    document.getElementById('breadcrumb-current').textContent = crumbs[id] || id;
}

// ─── Toast ──────────────────────────────────────────────
function showToast(msg, isError = false) {
    const t = document.getElementById('toast');
    t.textContent = msg;
    t.className = 'toast show' + (isError ? ' error' : '');
    setTimeout(() => { t.classList.remove('show'); }, 3200);
}

// ─── Modals ─────────────────────────────────────────────
function openModal() { document.getElementById('modal').classList.add('open'); }
function closeModal(e) {
    if (!e || e.target.id === 'modal') document.getElementById('modal').classList.remove('open');
}
function closeIncidentModal(e) {
    if (!e || e.target.id === 'incident-modal')
        document.getElementById('incident-modal').classList.remove('open');
}
async function viewReport(incidentId) {
    try {
        const text = await (await fetch(`/api/report/${incidentId}`)).text();
        document.getElementById('incident-title').textContent = `Relatório IR-${String(incidentId).padStart(4, '0')}`;
        document.getElementById('incident-report').textContent = text;
        document.getElementById('incident-modal').classList.add('open');
    } catch {
        showToast('Erro ao carregar relatório', true);
    }
}

// ─── Simulate ───────────────────────────────────────────
async function simulate(scenario) {
    if (isSimulating) return;
    isSimulating = true;
    closeModal();
    try {
        const res = await fetch('/api/simulate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scenario })
        });
        const data = await res.json();
        showToast(`✅ "${scenario}" simulado · ${data.new_alerts} novo(s) alerta(s) gerado(s)`);
        await refreshAll();
    } catch {
        showToast('Erro ao simular ataque', true);
    } finally {
        isSimulating = false;
    }
}

// ─── Reset ──────────────────────────────────────────────
async function resetDemo() {
    if (!confirm('Limpar todos os dados do SIEM?')) return;
    await fetch('/api/reset', { method: 'POST' });
    lastEventId = 0;
    chartTimeline = null;
    chartAttacks = null;
    document.getElementById('chart-timeline').getContext('2d').clearRect(0, 0, 9999, 9999);
    document.getElementById('chart-attacks').getContext('2d').clearRect(0, 0, 9999, 9999);
    showToast('🔄 SIEM reiniciado — dados limpos.');
    await refreshAll();
}

// ─── Fetch helpers ───────────────────────────────────────
const fetchJSON = url => fetch(url).then(r => r.json());

// ─── KPI Cards ──────────────────────────────────────────
function updateKPIs(stats, alerts) {
    setVal('stat-events', stats.total_events);
    setVal('stat-alerts', stats.active_alerts);
    setVal('stat-incidents', stats.open_incidents);
    setVal('stat-eps', stats.events_last_min);

    const topIp = stats.top_ips?.[0];
    document.getElementById('stat-top-ip').textContent = topIp ? topIp.source_ip : '—';

    // Critical alert count tag
    const critCount = (alerts || []).filter(a => a.severity === 'CRITICAL').length;
    const tag = document.getElementById('kpi-crit-tag');
    if (tag) {
        tag.textContent = critCount ? `${critCount} CRÍTICO(S)` : '';
        tag.style.display = critCount ? '' : 'none';
    }

    // Nav badge
    const nb = document.getElementById('nav-alert-count');
    if (nb) {
        nb.textContent = stats.active_alerts;
        nb.classList.toggle('visible', stats.active_alerts > 0);
    }
}

function setVal(id, val) {
    const el = document.getElementById(id);
    if (!el) return;
    if (el.textContent === '—' || el.textContent === String(val)) { el.textContent = val ?? '—'; return; }
    const from = parseInt(el.textContent) || 0;
    const to = val ?? 0;
    const diff = to - from;
    let step = 0;
    const T = 16;
    const timer = setInterval(() => {
        step++;
        el.textContent = Math.round(from + diff * (step / T));
        if (step >= T) { el.textContent = to; clearInterval(timer); }
    }, 18);
}

// ─── Timeline Chart (FIXED) ─────────────────────────────
function renderTimeline(data) {
    // Pad to always have at least 10 minutes of ticks
    const labels = data.length ? data.map(d => d.minute) : ['—'];
    const values = data.length ? data.map(d => d.cnt) : [0];

    if (chartTimeline) {
        chartTimeline.data.labels = labels;
        chartTimeline.data.datasets[0].data = values;
        chartTimeline.update('none');
        return;
    }

    const ctx = document.getElementById('chart-timeline').getContext('2d');
    chartTimeline = new Chart(ctx, {
        type: 'bar',
        data: {
            labels,
            datasets: [{
                label: 'Eventos',
                data: values,
                backgroundColor: 'rgba(26,126,219,0.15)',
                borderColor: '#1a7edb',
                borderWidth: 1.5,
                borderRadius: 3,
                borderSkipped: false,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 350 },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#f5f8fc',
                    borderColor: '#bcd2eb',
                    borderWidth: 1,
                    titleColor: '#0d1b30',
                    bodyColor: '#3d5a80',
                    padding: 10,
                    callbacks: {
                        label: ctx => ` ${ctx.parsed.y} evento(s)`
                    }
                }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(40,70,120,0.2)', drawBorder: false },
                    ticks: { color: '#8aa3c0', font: { family: 'JetBrains Mono', size: 10 }, maxRotation: 0 }
                },
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(40,70,120,0.2)', drawBorder: false },
                    ticks: { color: '#8aa3c0', precision: 0 }
                }
            }
        }
    });
}

// ─── Attack Doughnut ────────────────────────────────────
function renderAttackChart(data) {
    const filtered = data.filter(d => d.event_type !== 'HTTP_REQUEST');
    const labels = filtered.map(d => d.event_type.replace(/_/g, ' '));
    const values = filtered.map(d => d.cnt);

    if (!values.length) { labels.push('SEM DADOS'); values.push(1); }

    if (chartAttacks) {
        chartAttacks.data.labels = labels;
        chartAttacks.data.datasets[0].data = values;
        chartAttacks.update('none');
        return;
    }

    const ctx = document.getElementById('chart-attacks').getContext('2d');
    chartAttacks = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels,
            datasets: [{
                data: values,
                backgroundColor: PALETTE,
                borderColor: '#111c2e',
                borderWidth: 2,
                hoverOffset: 4,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '68%',
            animation: { duration: 350 },
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#688aae',
                        boxWidth: 10, boxHeight: 10,
                        padding: 10,
                        font: { size: 10 }
                    }
                },
                tooltip: {
                    backgroundColor: '#f5f8fc',
                    borderColor: '#bcd2eb',
                    borderWidth: 1,
                    titleColor: '#0d1b30',
                    bodyColor: '#3d5a80',
                    padding: 10,
                }
            }
        }
    });
}

// ─── Top IPs ────────────────────────────────────────────
function renderTopIps(ips) {
    const el = document.getElementById('top-ips');
    if (!ips?.length) { el.innerHTML = '<p class="empty-msg">Sem dados</p>'; return; }
    const max = ips[0].cnt;
    el.innerHTML = ips.map((ip, i) => `
    <div class="ip-row">
      <div class="ip-meta">
        <span class="ip-addr">${esc(ip.source_ip)}</span>
        <span class="ip-cnt">${ip.cnt} eventos</span>
      </div>
      <div class="ip-bar-track">
        <div class="ip-bar-fill" style="width:${Math.round(ip.cnt / max * 100)}%;background:${PALETTE[i % PALETTE.length]}"></div>
      </div>
    </div>
  `).join('');
}

// ─── Alerts table (shared) ──────────────────────────────
function buildAlertRows(alerts, columns = 6) {
    if (!alerts.length) return `<tr><td colspan="${columns}" class="empty-row">Nenhum alerta encontrado</td></tr>`;
    return alerts.map(a => {
        const irBtn = a.incident_id
            ? `<button class="btn-ir" onclick="viewReport(${a.incident_id})">IR-${String(a.incident_id).padStart(4, '0')}</button>`
            : '—';
        const base = `
      <td><span class="sev-pill sev-${a.severity}">${a.severity}</span></td>
      <td style="font-weight:500">${esc(a.rule_name)}</td>
      <td class="font-mono" style="color:#f27c39;font-size:11px">${esc(a.source_ip || '—')}</td>
      <td style="color:#556b8a;font-size:11px">${esc(a.mitre_tactic || '—')}</td>`;
        if (columns === 8) {
            return `<tr>${base}
        <td style="color:#374e6f;font-size:10.5px">${esc(a.mitre_technique || '—')}</td>
        <td class="font-mono" style="color:#374e6f;font-size:10px">${fmtTs(a.timestamp)}</td>
        <td><span class="status-label status-${a.status || 'OPEN'}">${a.status || 'OPEN'}</span></td>
        <td>${irBtn}</td></tr>`;
        }
        return `<tr>${base}
      <td><span class="status-label status-${a.status || 'OPEN'}">${a.status || 'OPEN'}</span></td>
      <td>${irBtn}</td></tr>`;
    }).join('');
}

function renderAlerts(alerts) {
    const body = document.getElementById('alerts-body');
    const count = document.getElementById('alerts-count');
    const open = alerts.filter(a => a.status !== 'CLOSED');
    if (count) count.textContent = open.length;
    if (body) body.innerHTML = buildAlertRows(alerts.slice(0, 20), 6);
}

function renderAllAlerts(alerts) {
    const body = document.getElementById('all-alerts-body');
    const count = document.getElementById('all-alerts-count');
    if (count) count.textContent = alerts.length;
    if (body) body.innerHTML = buildAlertRows(alerts, 8);
}

// ─── Incidents ──────────────────────────────────────────
function renderIncidents(incidents) {
    const grid = document.getElementById('incidents-grid');
    if (!incidents.length) {
        grid.innerHTML = '<p class="empty-msg">Nenhum incidente registrado.</p>';
        return;
    }
    grid.innerHTML = incidents.map(inc => `
    <div class="incident-card sev-${inc.severity}">
      <div class="incident-card-top">
        <div>
          <div class="incident-id">IR-${String(inc.id).padStart(4, '0')} · ${inc.severity}</div>
          <div class="incident-name">${esc(inc.title)}</div>
          <div class="incident-ts">${fmtTs(inc.created_at, true)}</div>
        </div>
        <span class="sev-pill sev-${inc.severity}">${inc.severity}</span>
      </div>
      <div class="incident-card-foot">
        <span class="status-label status-${inc.status || 'OPEN'}">${inc.status || 'OPEN'}</span>
        <button class="btn-ir" onclick="viewReport(${inc.id})">Ver Relatório IR</button>
      </div>
    </div>
  `).join('');
}

// ─── Live Feed ──────────────────────────────────────────
function renderFeed(events) {
    const feed = document.getElementById('event-feed');
    const newEvs = events.filter(e => e.id > lastEventId);
    if (!newEvs.length) return;
    if (lastEventId === 0) feed.innerHTML = '';
    lastEventId = events[0]?.id || 0;

    newEvs.reverse().forEach(ev => {
        const line = document.createElement('div');
        line.className = 'feed-line';
        line.innerHTML = `
      <span class="feed-ts">${fmtShort(ev.timestamp)}</span>
      <span class="feed-sev ${ev.severity}">[${ev.severity.slice(0, 4)}]</span>
      <span class="feed-src">${esc(ev.source_ip || 'internal')}</span>
      <span class="feed-type">${esc(ev.event_type)}</span>`;
        feed.prepend(line);
    });
    while (feed.children.length > 80) feed.removeChild(feed.lastChild);
}

// ─── Main refresh ────────────────────────────────────────
async function refreshAll() {
    try {
        const [stats, alerts, incidents, events] = await Promise.all([
            fetchJSON('/api/stats'),
            fetchJSON('/api/alerts?limit=50'),
            fetchJSON('/api/incidents'),
            fetchJSON('/api/events?limit=40')
        ]);
        updateKPIs(stats, alerts);
        renderTimeline(stats.events_timeline || []);
        renderAttackChart(stats.top_attack_types || []);
        renderTopIps(stats.top_ips || []);
        renderAlerts(alerts);
        renderAllAlerts(alerts);
        renderIncidents(incidents);
        renderFeed(events);
    } catch (err) {
        console.warn('[SIEM] Refresh error:', err);
    }
}

// ─── Helpers ────────────────────────────────────────────
function esc(s) {
    return s == null ? '' : String(s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function fmtTs(ts, long = false) {
    if (!ts) return '—';
    try {
        const d = new Date(ts);
        if (long) return d.toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
        return d.toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
    } catch { return ts; }
}
function fmtShort(ts) {
    if (!ts) return '—';
    try { return new Date(ts).toLocaleTimeString('pt-BR', { hour12: false }); }
    catch { return ts; }
}

// ─── Boot ───────────────────────────────────────────────
refreshAll();
setInterval(refreshAll, 5000);
