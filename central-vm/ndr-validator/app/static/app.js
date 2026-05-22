let latest = null;
let refreshTimer = null;

const $ = (id) => document.getElementById(id);
const statusOrder = { ok: 0, unknown: 1, warn: 2, crit: 3 };

function esc(value) {
  return String(value ?? '').replace(/[&<>'"]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
}

function statusPill(status) {
  const s = status || 'unknown';
  return `<span class="status-pill ${esc(s)}">${esc(s)}</span>`;
}

function pretty(obj) {
  return JSON.stringify(obj || {}, null, 2);
}

async function fetchJson(url, options = {}) {
  const res = await fetch(url, options);
  if (!res.ok) throw new Error(`${url} returned ${res.status}`);
  return await res.json();
}

async function loadSummary(run = false) {
  $('subtitle').textContent = run ? 'Running validation…' : 'Loading latest scan…';
  const data = await fetchJson(run ? '/api/run' : '/api/summary', { method: run ? 'POST' : 'GET' });
  latest = data;
  renderSummary(data);
  await Promise.all([loadHistory(), loadConfig()]);
}

function renderSummary(data) {
  const score = Number(data.score || 0);
  $('scoreValue').textContent = score;
  $('scoreRing').style.setProperty('--angle', `${Math.round(score * 3.6)}deg`);
  $('globalStatus').className = `status-pill ${data.status || 'unknown'}`;
  $('globalStatus').textContent = data.status || 'unknown';
  $('generatedAt').textContent = `Scan ${data.scan_id?.slice(0, 8) || ''} • ${data.generated_at || ''} • ${Math.round(data.duration_ms || 0)} ms`;
  $('subtitle').textContent = 'Silent-error validation across Vector, Data Prepper, OpenSearch, Dashboards, correlation, ML, alerts, and Docker runtime.';

  $('highlights').innerHTML = (data.highlights || []).map(h => `<li>${esc(h)}</li>`).join('') || '<li>No highlights yet.</li>';
  renderComponents(data.components || []);
  renderPipeline(data.pipeline || []);
  renderChecks(data.checks || []);
  renderSensors(data.sensors || []);
  renderData(data.data || {});
}

function renderComponents(components) {
  $('componentsGrid').innerHTML = components.map(c => `
    <article class="component-card">
      <div class="component-top">
        <div>
          <div class="component-title">${esc(c.label)}</div>
          <div class="muted">${esc(c.name)}</div>
        </div>
        ${statusPill(c.status)}
      </div>
      <div class="component-score">${Number(c.score || 0)}</div>
      <div class="meter"><div style="width:${Number(c.score || 0)}%"></div></div>
      <div class="stats">
        <span>OK ${c.ok || 0}</span><span>Warn ${c.warn || 0}</span><span>Crit ${c.crit || 0}</span><span>Unknown ${c.unknown || 0}</span>
      </div>
    </article>
  `).join('');

  const componentNames = [...new Set((latest?.checks || []).map(c => c.component))].sort();
  $('componentFilter').innerHTML = '<option value="all">All components</option>' + componentNames.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join('');
}

function renderPipeline(stages) {
  const order = ['raw', 'sessions', 'behaviors', 'ml'];
  stages.sort((a,b) => order.indexOf(a.stage) - order.indexOf(b.stage));
  $('pipelineTimeline').innerHTML = stages.map(s => `
    <article class="pipeline-stage ${esc(s.status || 'unknown')}">
      <div class="pipeline-title">${esc(s.label || s.stage)}</div>
      ${statusPill(s.status)}
      <div class="muted" style="margin-top:12px">Latest: ${esc(s.latest || 'not found')}</div>
      <div class="stats" style="margin-top:10px">
        ${Object.entries(s).filter(([k]) => !['stage','label','status','latest'].includes(k)).map(([k,v]) => `<span>${esc(k)}: ${esc(v)}</span>`).join('')}
      </div>
    </article>
  `).join('') || '<div class="panel">No pipeline data yet.</div>';
}

function renderData(data) {
  $('rawData').textContent = pretty(data.raw || {});
  $('sessionData').textContent = pretty(data.sessions || {});
  $('behaviorData').textContent = pretty({ behaviors: data.behaviors || {}, ml: data.ml || {}, dataprepper: data.dataprepper || {}, opensearch: data.opensearch || {} });
}

function checkMatches(c) {
  const q = $('searchChecks').value.toLowerCase().trim();
  const status = $('statusFilter').value;
  const component = $('componentFilter').value;
  const text = `${c.id} ${c.name} ${c.component} ${c.summary} ${c.details} ${c.remediation}`.toLowerCase();
  if (status !== 'all' && c.status !== status) return false;
  if (component !== 'all' && c.component !== component) return false;
  if (q && !text.includes(q)) return false;
  return true;
}

function renderChecks(checks) {
  const sorted = [...checks].sort((a,b) => (statusOrder[b.status] ?? 1) - (statusOrder[a.status] ?? 1));
  const filtered = sorted.filter(checkMatches);
  $('checksList').innerHTML = filtered.map(c => `
    <article class="check-card">
      <div class="check-head" onclick="this.parentElement.classList.toggle('open')">
        ${statusPill(c.status)}
        <div>
          <div class="check-name">${esc(c.name)}</div>
          <div class="check-summary">${esc(c.summary)}</div>
        </div>
        <span class="component-chip">${esc(c.component)}</span>
      </div>
      <div class="check-body">
        ${c.details ? `<p><strong>Details:</strong> ${esc(c.details)}</p>` : ''}
        ${c.remediation ? `<p><strong>Fix / next step:</strong> ${esc(c.remediation)}</p>` : ''}
        <div class="data-grid">
          <div><div class="tiny-label">Metrics</div><pre class="code">${esc(pretty(c.metrics || {}))}</pre></div>
          <div><div class="tiny-label">Evidence</div><pre class="code">${esc(pretty(c.evidence || {}))}</pre></div>
        </div>
      </div>
    </article>
  `).join('') || '<div class="panel">No checks match your filter.</div>';
}

function renderSensors(sensors) {
  if (!sensors || sensors.length === 0) {
    $('sensorsGrid').innerHTML = '<div class="panel">No sensors found yet. Configure EXPECTED_SENSORS and VECTOR_TARGETS for richer validation.</div>';
    return;
  }
  const merged = new Map();
  sensors.forEach(s => {
    const key = s.name || s.url || 'unknown';
    merged.set(key, { ...(merged.get(key) || {}), ...s });
  });
  $('sensorsGrid').innerHTML = [...merged.entries()].map(([name, s]) => `
    <article class="component-card">
      <div class="component-top"><div><div class="component-title">${esc(name)}</div><div class="muted">${esc(s.url || 'OpenSearch observed sensor')}</div></div>${statusPill(s.status || 'unknown')}</div>
      <div class="stats">
        ${Object.entries(s).filter(([k]) => !['name','status','url'].includes(k)).map(([k,v]) => `<span>${esc(k)}: ${esc(v)}</span>`).join('')}
      </div>
    </article>
  `).join('');
}

async function loadHistory() {
  const data = await fetchJson('/api/history?limit=100');
  $('historyTable').querySelector('tbody').innerHTML = (data.history || []).map(r => `
    <tr><td>${esc(r.generated_at)}</td><td>${statusPill(r.status)}</td><td>${esc(r.score)}</td><td>${Math.round(r.duration_ms || 0)} ms</td><td>${esc(r.id)}</td></tr>
  `).join('');
}

async function loadConfig() {
  const data = await fetchJson('/api/config');
  $('configBlock').textContent = pretty(data);
}

function setupTabs() {
  document.querySelectorAll('.nav-item').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      btn.classList.add('active');
      $(btn.dataset.tab).classList.add('active');
    });
  });
}

function setupRefresh() {
  function reschedule() {
    if (refreshTimer) clearInterval(refreshTimer);
    const ms = Number($('refreshInterval').value || 0);
    if (ms > 0) refreshTimer = setInterval(() => loadSummary(false).catch(console.error), ms);
  }
  $('refreshInterval').addEventListener('change', reschedule);
  reschedule();
}

['searchChecks','statusFilter','componentFilter'].forEach(id => {
  document.addEventListener('input', (e) => {
    if (e.target && e.target.id === id && latest) renderChecks(latest.checks || []);
  });
  document.addEventListener('change', (e) => {
    if (e.target && e.target.id === id && latest) renderChecks(latest.checks || []);
  });
});

$('runScan').addEventListener('click', () => loadSummary(true).catch(err => alert(err.message)));
$('reload').addEventListener('click', () => loadSummary(false).catch(err => alert(err.message)));
setupTabs();
setupRefresh();
loadSummary(false).catch(err => {
  $('subtitle').textContent = err.message;
  console.error(err);
});
