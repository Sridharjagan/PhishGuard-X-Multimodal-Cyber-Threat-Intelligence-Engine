/* PhishGuard-X — Frontend v2.0 */
const API = '';

// ── Init ──────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  checkStatus();
  loadMetrics();
  loadGraphStats();
  setupLayerToggles();
  setupBatchCounter();
  document.getElementById('urlInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') scanURL();
  });
});

// ── Status ────────────────────────────────────────────────────
async function checkStatus() {
  try {
    const d = await (await fetch(`${API}/api/v2/status`)).json();
    const dot = document.getElementById('sdot');
    const txt = document.getElementById('stxt');
    const ver = document.getElementById('tVer');
    if (d.status === 'running') {
      dot.classList.add('on');
      txt.textContent = d.model_loaded ? 'ML Online' : 'Heuristic';
      ver.textContent = `SYS:ONLINE · ${d.features}F`;
    }
  } catch {
    document.getElementById('stxt').textContent = 'Offline';
  }
}

// ── Layer selector ────────────────────────────────────────────
function setupLayerToggles() {
  document.querySelectorAll('.layer-toggle').forEach(el => {
    el.addEventListener('click', () => {
      const cb = el.querySelector('input');
      cb.checked = !cb.checked;
      el.classList.toggle('active', cb.checked);
    });
  });
}

function getSelectedLayers() {
  const layers = [];
  document.querySelectorAll('.layer-toggle.active').forEach(el => {
    layers.push(el.dataset.layer);
  });
  return layers.length > 0 ? layers : ['url','xai'];
}

// ── Quick test ────────────────────────────────────────────────
function testURL(url) {
  document.getElementById('urlInput').value = url;
  scanURL();
}

// ── Main scanner ──────────────────────────────────────────────
async function scanURL() {
  const raw = document.getElementById('urlInput').value.trim();
  if (!raw) return;
  const url = raw.startsWith('http') ? raw : `https://${raw}`;
  const layers = getSelectedLayers();
  const btn = document.getElementById('scanBtn');

  btn.innerHTML = '<span class="spinner"></span> SCANNING';
  btn.classList.add('loading');
  btn.disabled = true;

  // Show loading overlay
  const sec = document.getElementById('resultsSection');
  sec.style.display = 'block';
  sec.scrollIntoView({ behavior: 'smooth', block: 'start' });

  const overlay = document.getElementById('loadingOverlay');
  overlay.style.display = 'block';
  document.getElementById('loadingLayers').innerHTML =
    layers.map(l => `⟳ Running ${l.toUpperCase()} intelligence layer...`).join('<br/>');

  try {
    const res = await fetch(`${API}/api/v2/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, layers })
    });
    const data = await res.json();
    overlay.style.display = 'none';
    if (data.error) { showError(data.error); return; }
    renderResults(data);
    // Update graph stats after analysis
    loadGraphStats();
  } catch (e) {
    overlay.style.display = 'none';
    showError('Cannot reach server. Run: python app.py');
  } finally {
    btn.innerHTML = 'SCAN <span>›</span>';
    btn.classList.remove('loading');
    btn.disabled = false;
  }
}

// ── Render results ────────────────────────────────────────────
function renderResults(data) {
  const phish = data.prediction === 'phishing';
  const cls   = phish ? 'phishing' : 'legitimate';
  const conf  = data.confidence || 0;
  const pct   = Math.round(conf * 100);

  // Verdict card
  const card = document.getElementById('verdictCard');
  card.className = `verdict-card ${cls}`;

  const icon = document.getElementById('vIcon');
  icon.className = `v-icon ${cls}`;
  icon.innerHTML = phish
    ? `<svg viewBox="0 0 60 60" fill="none"><circle cx="30" cy="30" r="28" stroke="currentColor" stroke-width="1.5"/>
       <path d="M18 18l24 24M42 18L18 42" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"/></svg>`
    : `<svg viewBox="0 0 60 60" fill="none"><circle cx="30" cy="30" r="28" stroke="currentColor" stroke-width="1.5"/>
       <path d="M17 30l10 10 16-16" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

  const lbl = document.getElementById('vLabel');
  lbl.textContent  = phish ? '⚠ PHISHING DETECTED' : '✓ LEGITIMATE URL';
  lbl.className    = `v-label ${cls}`;

  document.getElementById('vURL').textContent = data.url;

  // Confidence bar
  const fill = document.getElementById('confFill');
  fill.className = `conf-fill ${cls}`;
  setTimeout(() => { fill.style.width = pct + '%'; }, 60);
  document.getElementById('confPct').textContent = pct + '%';

  // Meta
  const rb = document.getElementById('riskBadge');
  rb.textContent = (data.risk_level || '—').toUpperCase();
  rb.className   = `risk-badge ${data.risk_level || 'low'}`;
  document.getElementById('aTime').textContent    = `${data.analysis_time_ms || '—'}ms`;
  document.getElementById('layersRun').textContent = (data.layers_run || []).join(' · ').toUpperCase();
  document.getElementById('modelVer').textContent  = data.model_version || '2.0.0';

  // Layer scores
  renderLayerScores(data.layer_scores || {}, data.layer_contributions || {});

  // Risk indicators (from XAI)
  const inds = (data.explanation?.risk_indicators) || [];
  renderIndicators(inds);

  // XAI
  if (data.explanation) renderXAI(data.explanation);

  // Domain panel
  if (data.domain_analysis) renderDomainPanel(data.domain_analysis);

  // Content panel
  if (data.content_analysis) renderContentPanel(data.content_analysis);

  // Attack vector
  renderAttackVectors(data.url_analysis || {}, data.all_features || {});
}

function renderLayerScores(scores, contributions) {
  const grid = document.getElementById('layerScores');
  document.getElementById('layerCount').textContent =
    `${Object.keys(scores).length} layers`;

  const layerInfo = {
    url:     { label: 'URL Intelligence',    icon: '🔗' },
    domain:  { label: 'Domain Intel',        icon: '🌐' },
    content: { label: 'Content Intel',       icon: '📄' },
    threat:  { label: 'Threat Feeds',        icon: '⚠' },
    graph:   { label: 'Attack Graph',        icon: '🕸' },
    llm:     { label: 'LLM Reasoning',       icon: '🧠' },
  };

  grid.innerHTML = Object.entries(scores).map(([layer, score]) => {
    const info  = layerInfo[layer] || { label: layer.toUpperCase(), icon: '◆' };
    const pct   = Math.round(score * 100);
    const cls   = pct > 65 ? 'danger' : pct > 35 ? 'warn' : 'safe';
    const cont  = contributions[layer];
    const mult  = cont ? ` ×${cont.multiplier}` : '';
    return `<div class="ls-item">
      <div class="ls-name">${info.icon} ${info.label}${mult}</div>
      <div class="ls-bar-track"><div class="ls-bar-fill" style="width:${pct}%"></div></div>
      <div class="ls-score ${cls}">${pct}%</div>
    </div>`;
  }).join('');
}

function renderIndicators(inds) {
  const list  = document.getElementById('indList');
  const count = document.getElementById('indCount');
  count.textContent = `${inds.length} detected`;
  if (!inds.length) {
    list.innerHTML = '<div class="no-ind">✓ No risk indicators detected</div>';
    return;
  }
  list.innerHTML = inds.map((d, i) => `
    <div class="ind-item" style="animation-delay:${i * 0.045}s">
      <span class="idot ${d.severity}"></span>
      <span class="iname">${d.name}</span>
      <span class="itag ${d.severity}">${d.severity}</span>
    </div>`).join('');
}

function renderXAI(xai) {
  // Analyst summary
  document.getElementById('analystSummary').textContent =
    xai.analyst_summary || 'Analysis complete.';
  document.getElementById('xaiMethod').textContent =
    (xai.method || 'rule-based').toUpperCase();

  // Top features
  const tf = document.getElementById('topFeatures');
  if (xai.top_features && xai.top_features.length) {
    tf.innerHTML = xai.top_features.map(f => {
      const isPos = f.shap_value > 0;
      const cls   = isPos ? 'pos' : 'neg';
      const arrow = isPos ? '↑' : '↓';
      return `<div class="tf-item">
        <span class="tf-name">${f.feature.replace(/_/g,' ')}</span>
        <span class="tf-shap ${cls}">${arrow} ${Math.abs(f.shap_value).toFixed(3)}</span>
      </div>`;
    }).join('');
  } else {
    tf.innerHTML = '';
  }

  // Counterfactuals
  const cf = document.getElementById('counterfactual');
  if (xai.counterfactual && xai.counterfactual.length) {
    cf.innerHTML = '<div style="font-family:var(--fm);font-size:.58rem;color:var(--t3);margin-bottom:6px;letter-spacing:.1em">COUNTERFACTUAL HINTS</div>' +
      xai.counterfactual.map(c => `<div class="cf-item">${c}</div>`).join('');
  } else {
    cf.innerHTML = '';
  }
}

function renderDomainPanel(dom) {
  const card = document.getElementById('domainCard');
  card.style.display = 'block';
  const grid = document.getElementById('domainGrid');
  const items = [
    ['Domain Age',    dom.age_days >= 0 ? `${dom.age_days} days` : 'Unknown',
                      dom.very_new ? 'bad' : dom.age_days < 30 ? 'warn' : 'ok'],
    ['Very New',      dom.very_new ? 'YES ⚠' : 'NO',       dom.very_new ? 'bad' : 'ok'],
    ['High-Risk Reg', dom.high_risk_reg ? 'YES ⚠' : 'NO',  dom.high_risk_reg ? 'bad' : 'ok'],
    ['Has SPF',       dom.has_spf ? 'YES' : 'NO',           dom.has_spf ? 'ok' : 'warn'],
    ['Has DMARC',     dom.has_dmarc ? 'YES' : 'NO',         dom.has_dmarc ? 'ok' : 'warn'],
    ['Fast Flux',     dom.fast_flux ? 'YES ⚠' : 'NO',       dom.fast_flux ? 'bad' : 'ok'],
    ['SSL Issuer Risk',dom.ssl_issuer_risk ? 'HIGH ⚠' : 'OK', dom.ssl_issuer_risk ? 'warn' : 'ok'],
    ['Domain Score',  `${Math.round((dom.domain_score || 0) * 100)}%`,
                      (dom.domain_score||0) > 0.6 ? 'bad' : (dom.domain_score||0) > 0.3 ? 'warn' : 'ok'],
  ];
  grid.innerHTML = items.map(([n,v,c]) =>
    `<div class="dg-item"><span class="dg-name">${n}</span><span class="dg-val ${c}">${v}</span></div>`
  ).join('');
}

function renderContentPanel(cont) {
  const card = document.getElementById('contentCard');
  card.style.display = 'block';
  const grid = document.getElementById('contentGrid');
  const items = [
    ['Fetch Success',    cont.fetch_success ? 'YES' : 'NO',         cont.fetch_success ? 'ok' : 'warn'],
    ['Password Input',   cont.password_input ? 'YES ⚠' : 'NO',      cont.password_input ? 'bad' : 'ok'],
    ['External Form',    cont.external_form ? 'YES ⚠' : 'NO',        cont.external_form ? 'bad' : 'ok'],
    ['JS Obfuscation',   `${cont.js_obfuscation || 0}/8`,            cont.js_obfuscation > 3 ? 'bad' : cont.js_obfuscation > 1 ? 'warn' : 'ok'],
    ['Social Eng Score', `${cont.se_total || 0}/20`,                 cont.se_total > 8 ? 'bad' : cont.se_total > 3 ? 'warn' : 'ok'],
    ['Title Mismatch',   cont.title_mismatch ? 'YES ⚠' : 'NO',      cont.title_mismatch ? 'bad' : 'ok'],
    ['Content Score',    `${Math.round((cont.content_score || 0) * 100)}%`, (cont.content_score||0) > 0.6 ? 'bad' : 'ok'],
  ];
  grid.innerHTML = items.map(([n,v,c]) =>
    `<div class="dg-item"><span class="dg-name">${n}</span><span class="dg-val ${c}">${v}</span></div>`
  ).join('');
}

function renderAttackVectors(urlAnalysis, allFeats) {
  const grid = document.getElementById('attackGrid');
  const items = [
    ['Homograph Attack',  urlAnalysis.homograph_detected ? 'DETECTED ⚠' : 'None', urlAnalysis.homograph_detected ? 'bad' : 'ok'],
    ['Leetspeak Spoof',   urlAnalysis.leet_spoof ? 'DETECTED ⚠' : 'None',         urlAnalysis.leet_spoof ? 'bad' : 'ok'],
    ['Mixed Unicode',     urlAnalysis.mixed_script ? 'DETECTED ⚠' : 'None',        urlAnalysis.mixed_script ? 'bad' : 'ok'],
    ['IP-Based URL',      allFeats.has_ip ? 'YES ⚠' : 'No',                        allFeats.has_ip ? 'bad' : 'ok'],
    ['@ Symbol Attack',   allFeats.has_at_sign ? 'YES ⚠' : 'No',                   allFeats.has_at_sign ? 'bad' : 'ok'],
    ['Double Encoded',    allFeats.double_encoded ? 'YES ⚠' : 'No',                allFeats.double_encoded ? 'bad' : 'ok'],
    ['URL Shortener',     allFeats.has_url_shortener ? 'YES ⚠' : 'No',             allFeats.has_url_shortener ? 'bad' : 'ok'],
    ['Base64 Redirect',   allFeats.has_base64_redirect ? 'YES ⚠' : 'No',           allFeats.has_base64_redirect ? 'bad' : 'ok'],
    ['Data URI',          allFeats.has_data_uri ? 'YES ⚠' : 'No',                  allFeats.has_data_uri ? 'bad' : 'ok'],
    ['Suspicious TLD',    allFeats.is_suspicious_tld ? 'YES ⚠' : 'No',             allFeats.is_suspicious_tld ? 'bad' : 'ok'],
    ['Brand in Subdomain',allFeats.brand_name_in_subdomain ? 'YES ⚠' : 'No',       allFeats.brand_name_in_subdomain ? 'bad' : 'ok'],
    ['Brand in Domain',   allFeats.brand_name_in_domain ? 'YES ⚠' : 'No',         allFeats.brand_name_in_domain ? 'bad' : 'ok'],
    ['ML Probability',    urlAnalysis.ml_probability != null ? `${Math.round(urlAnalysis.ml_probability*100)}%` : 'N/A', ''],
    ['Heuristic Score',   urlAnalysis.heuristic_score != null ? `${Math.round(urlAnalysis.heuristic_score*100)}%` : 'N/A', ''],
  ];
  grid.innerHTML = items.map(([n,v,c]) =>
    `<div class="dg-item"><span class="dg-name">${n}</span><span class="dg-val ${c}">${v}</span></div>`
  ).join('');
}

// ── Batch ─────────────────────────────────────────────────────
function setupBatchCounter() {
  document.getElementById('batchIn').addEventListener('input', () => {
    const n = document.getElementById('batchIn').value
      .split('\n').filter(l => l.trim()).length;
    document.getElementById('bCnt').textContent = `${n} URL${n !== 1 ? 's' : ''}`;
  });
}

async function batchScan() {
  const urls = document.getElementById('batchIn').value
    .split('\n').map(l => l.trim()).filter(Boolean);
  if (!urls.length) return;
  if (urls.length > 50) { alert('Max 50 URLs per batch.'); return; }

  const container = document.getElementById('batchResults');
  container.innerHTML =
    `<div style="text-align:center;padding:1.5rem"><span class="spinner"></span></div>`;

  try {
    const res  = await fetch(`${API}/api/v2/batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ urls, layers: ['url','xai'] })
    });
    const data = await res.json();
    const results   = data.results || [];
    const phishCnt  = results.filter(r => r.prediction === 'phishing').length;

    container.innerHTML = `
      <div style="font-family:var(--fm);font-size:.66rem;color:var(--t3);
        margin-bottom:10px;padding-bottom:10px;border-bottom:1px solid var(--brd)">
        ${results.length} scanned —
        <span style="color:var(--red)">${phishCnt} threats</span> ·
        <span style="color:var(--grn)">${results.length - phishCnt} safe</span>
      </div>
      ${results.map((r, i) => batchRowHTML(r, i)).join('')}`;
  } catch (e) {
    container.innerHTML = `<div style="color:var(--red);font-family:var(--fm);font-size:.75rem">
      Error: ${e.message}</div>`;
  }
}

function batchRowHTML(r, i) {
  if (r.error) return `<div class="br-item"><span style="color:var(--t3)">${r.url}: ${r.error}</span></div>`;
  const phish = r.prediction === 'phishing';
  const pct   = Math.round((r.confidence || 0) * 100);
  const inds  = r.explanation?.risk_indicators?.length || 0;
  return `<div class="br-item" style="animation-delay:${i * 0.03}s">
    <span class="br-dot ${r.prediction}"></span>
    <span class="br-url" title="${r.url}">${r.url}</span>
    <span style="font-family:var(--fm);font-size:.58rem;color:var(--t3)">${inds > 0 ? inds + ' signals' : ''}</span>
    <span style="font-family:var(--fm);font-size:.6rem;color:var(--t3)">${(r.risk_level||'').toUpperCase()}</span>
    <span class="br-pct ${phish ? 'd' : 's'}">${pct}%</span>
  </div>`;
}

// ── Metrics ───────────────────────────────────────────────────
async function loadMetrics() {
  try {
    const data = await (await fetch(`${API}/api/v2/metrics`)).json();
    const m    = data.model_metrics || {};
    const fmt  = v => (v * 100).toFixed(1) + '%';
    [['mAcc','bAcc',m.accuracy],['mPre','bPre',m.precision],
     ['mRec','bRec',m.recall],  ['mF1', 'bF1', m.f1_score],
     ['mAUC','bAUC',m.roc_auc]].forEach(([vi, bi, val]) => {
      const el = document.getElementById(vi);
      const bar= document.getElementById(bi);
      if (el && val != null) {
        el.textContent = fmt(val);
        setTimeout(() => { if (bar) bar.style.width = (val * 100) + '%'; }, 300);
      }
    });
    if (m.feature_importances) {
      const list    = document.getElementById('impList');
      const entries = Object.entries(m.feature_importances).slice(0, 12);
      const maxV    = entries[0]?.[1] || 1;
      list.innerHTML = entries.map(([n, v]) => `
        <div class="imp-row">
          <span class="imp-name">${n.replace(/_/g, ' ')}</span>
          <div class="imp-trk"><div class="imp-fill" style="width:0%" data-t="${(v/maxV*100).toFixed(1)}%"></div></div>
          <span class="imp-pct">${(v * 100).toFixed(1)}%</span>
        </div>`).join('');
      setTimeout(() => {
        document.querySelectorAll('.imp-fill').forEach(el => { el.style.width = el.dataset.t; });
      }, 500);
    }
  } catch {}
}

// ── Graph stats ───────────────────────────────────────────────
async function loadGraphStats() {
  try {
    const d = await (await fetch(`${API}/api/v2/graph/stats`)).json();
    document.getElementById('gsNodes').textContent   = d.nodes    || 0;
    document.getElementById('gsEdges').textContent   = d.edges    || 0;
    document.getElementById('gsDomains').textContent = d.domains  || 0;
    document.getElementById('gsClusters').textContent= d.clusters || 0;
  } catch {}
}

// ── Error ─────────────────────────────────────────────────────
function showError(msg) {
  const sec = document.getElementById('resultsSection');
  sec.style.display = 'block';
  const overlay = document.getElementById('loadingOverlay');
  if (overlay) overlay.style.display = 'none';
  document.getElementById('resultsSection').innerHTML = `
    <div class="loading-overlay" style="display:block">
      <div style="font-family:var(--fm);color:var(--red);font-size:.82rem;text-align:center">
        ⚠ ${msg}<br/><br/>
        <span style="color:var(--t3);font-size:.68rem">
          Start server: <code style="color:var(--cyan)">python app.py</code>
        </span>
      </div>
    </div>`;
  sec.scrollIntoView({ behavior: 'smooth' });
}
