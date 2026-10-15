const $ = id => document.getElementById(id);
let meta, lastResult, lastInput, busy = false;
const node = (tag, value, className) => { const element = document.createElement(tag); if (value !== undefined) element.textContent = String(value); if (className) element.className = className; return element; };
function notice(message = '', good = false) { $('notice').textContent = message; $('notice').className = good ? 'success' : ''; }
async function api(path, data) {
  const response = await fetch(path, data === undefined ? {} : { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Lab-Token': meta.token }, body: JSON.stringify(data) });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || `HTTP ${response.status}`);
  return result;
}
function setBusy(value) { busy = value; $('run').disabled = value; $('save').disabled = value || !lastResult; $('minimize').disabled = value || !lastResult; $('run').textContent = value ? 'Running…' : 'Run experiment ↗'; }
function selectPreset() {
  const item = meta.presets.find(p => p.id === $('preset').value);
  $('input').value = JSON.stringify(item.input, null, 2);
  $('presetDescription').textContent = item.summary;
  notice('Scenario loaded. Run it to update the observations.', true);
}
function isFinding(event) { return event.mismatch === true || event.stale_grant === true || ['added', 'removed', 'modified', 'mode_changed', 'behavior_changed'].includes(event.change); }
function renderLedger() {
  const events = lastResult?.events || [];
  const filtered = $('failOnly').checked ? events.filter(isFinding) : events;
  const keys = [...new Set(filtered.slice(0, 10).flatMap(Object.keys))].filter(k => !['content', 'payload'].includes(k)).slice(0, 10);
  const head = node('tr'); keys.forEach(k => head.append(node('th', k.replaceAll('_', ' '))));
  $('ledger').tHead.replaceChildren(head);
  $('ledger').tBodies[0].replaceChildren(...filtered.slice(0, 250).map(event => {
    const row = node('tr', undefined, isFinding(event) ? 'bad' : '');
    keys.forEach(k => row.append(node('td', typeof event[k] === 'object' ? JSON.stringify(event[k]) : (event[k] ?? '—'))));
    return row;
  }));
  $('ledgerHint').textContent = `${filtered.length.toLocaleString()} matching events · showing up to 250. Save a case for the complete ledger.`;
}
function renderVisual(result) {
  const policies = result.details?.policies;
  const changes = result.details?.change_counts;
  const rows = policies ? policies.map(p => [p.policy, p.stale_grants, `${p.stale_grants} stale`]) : changes ? Object.entries(changes).map(([k,v]) => [k,v,`${v} files`]) : [];
  $('visualPanel').hidden = !rows.length;
  $('visualTitle').textContent = policies ? 'Revoked requests still accepted' : 'Artifact differences';
  const max = Math.max(1, ...rows.map(r => r[1]));
  $('visual').replaceChildren(...rows.map(([label, value, caption]) => {
    const row = node('div', undefined, 'bar-row'), track = node('div', undefined, 'bar-track'), bar = node('div', undefined, 'bar');
    bar.style.width = `${100 * value / max}%`; track.append(bar); row.append(node('span', label), track, node('small', caption)); return row;
  }));
}
function render(result, input) {
  lastResult = result; lastInput = structuredClone(input);
  $('metrics').replaceChildren(...Object.entries(result.summary).slice(0, 8).map(([key, value]) => {
    const card = node('div', undefined, 'metric'); card.append(node('small', key.replaceAll('_', ' ')), node('strong', value)); return card;
  }));
  $('findings').className = '';
  $('findings').replaceChildren(...result.findings.map(f => {
    const card = node('article', undefined, `finding ${['critical','high','medium','low','info'].includes(f.severity) ? f.severity : 'info'}`);
    card.append(node('span', f.severity, 'severity'), node('h3', f.title), node('p', f.detail)); return card;
  }));
  if (!result.findings.length) $('findings').append(node('p', 'No findings for the supplied inputs. This is not a general security guarantee.'));
  $('raw').textContent = JSON.stringify(result, null, 2);
  $('runState').textContent = 'RUN COMPLETE'; $('saved').replaceChildren(); $('download').disabled = false;
  renderVisual(result); renderLedger();
}
async function run() {
  if (busy) return;
  notice(); setBusy(true);
  try { const input = JSON.parse($('input').value); render(await api('/api/run', input), input); notice('Run completed. All displayed measurements come from this result.', true); }
  catch (error) { notice(error.message); $('runState').textContent = 'RUN FAILED'; }
  finally { setBusy(false); }
}
$('run').addEventListener('click', run);
$('preset').addEventListener('change', selectPreset);
$('format').addEventListener('click', () => { try { $('input').value = JSON.stringify(JSON.parse($('input').value), null, 2); notice(); } catch(e) { notice(e.message); } });
$('failOnly').addEventListener('change', renderLedger);
$('save').addEventListener('click', async () => {
  if (!lastInput || busy) return; setBusy(true); notice();
  try {
    const saved = await api('/api/save', lastInput);
    const report = node('a', 'Open report'), bundle = node('a', 'Download verified ZIP');
    report.href = saved.report_url; report.target = '_blank'; report.rel = 'noopener'; bundle.href = saved.bundle_url;
    $('saved').replaceChildren(node('p', `Case ${saved.id}`), report, document.createTextNode(' · '), bundle);
    notice('Saved the last completed experiment and its replay manifest.', true);
  } catch(e) { notice(e.message); } finally { setBusy(false); }
});
$('minimize').addEventListener('click', async () => {
  if (!lastInput || busy) return; setBusy(true); notice();
  try { const result = await api('/api/minimize', lastInput); $('input').value = JSON.stringify(result.input, null, 2); render(result.result, result.input); notice(`Witness reduced from ${result.original_steps} to ${result.reduced_steps} steps in ${result.evaluations} evaluations.`, true); }
  catch(e) { notice(e.message); } finally { setBusy(false); }
});
$('download').addEventListener('click', () => {
  const allEvents = lastResult?.events || []; const events = $('failOnly').checked ? allEvents.filter(isFinding) : allEvents; const keys = [...new Set(allEvents.flatMap(Object.keys))];
  const cell = value => { let s = typeof value === 'object' ? JSON.stringify(value) : String(value ?? ''); if (/^[\s]*[=+\-@]/.test(s)) s = "'" + s; return '"' + s.replaceAll('"', '""') + '"'; };
  const body = [keys.map(cell).join(','), ...events.map(e => keys.map(k => cell(e[k])).join(','))].join('\r\n');
  const url = URL.createObjectURL(new Blob([body], { type: 'text/csv;charset=utf-8' })); const a = node('a'); a.href = url; a.download = `${meta.name}-ledger.csv`; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});
async function loadCases() {
  try {
    const { cases } = await api('/api/cases');
    $('caseList').replaceChildren(...cases.map(id => {
      const row = node('div', undefined, 'case-row'), links = node('div');
      const report = node('a', 'Report'), bundle = node('a', 'ZIP'), verify = node('button', 'Verify & replay');
      report.href = `/api/cases/${id}/report`; report.target = '_blank'; report.rel = 'noopener'; bundle.href = `/api/cases/${id}/bundle`;
      verify.addEventListener('click', async () => { try { const result = await api(`/api/cases/${id}/verify`); notice(result.ok ? `Case ${id}: hashes and replay verified.` : result.problems.join('\n'), result.ok); } catch(e) { notice(e.message); } });
      links.append(report, bundle, document.createTextNode(' '), verify); row.append(node('code', id), links); return row;
    }));
    if (!cases.length) $('caseList').append(node('p', 'No saved evidence yet. Run an experiment and save it from the workbench.'));
  } catch(e) { notice(e.message); }
}
$('refreshCases').addEventListener('click', loadCases);
document.querySelectorAll('[data-page]').forEach(button => button.addEventListener('click', () => {
  ['workbench','cases','method'].forEach(id => $(id).hidden = id !== button.dataset.page);
  document.querySelectorAll('[data-page]').forEach(b => b.classList.toggle('active', b === button));
  notice(); if (button.dataset.page === 'cases') loadCases();
}));
async function loadFile(event, key) {
  const file = event.target.files[0]; if (!file) return;
  if (file.size > 4 * 1024 * 1024) return notice('Archive limit: 4 MiB per ZIP in both the browser and CLI.');
  try { const bytes = new Uint8Array(await file.arrayBuffer()); let binary = ''; for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192)); const input = JSON.parse($('input').value); input[key] = btoa(binary); $('input').value = JSON.stringify(input, null, 2); notice('Archive loaded. Review the provenance policy and run the comparison.', true); } catch(e) { notice(e.message); }
}
$('baselineFile').addEventListener('change', event => loadFile(event, 'baseline_zip'));
$('candidateFile').addEventListener('change', event => loadFile(event, 'candidate_zip'));
try {
  meta = await api('/api/meta'); document.title = `${meta.name} · Workbench`;
  $('brand').textContent = meta.name; $('heading').textContent = meta.name; $('tagline').textContent = meta.tagline; $('version').textContent = `VERSION ${meta.version}`;
  const accents = { RevokeRace: '#b8ed71', TenantScope: '#9bc3ff', ReleaseTwin: '#ffc18a' }; document.documentElement.style.setProperty('--accent', accents[meta.name] || '#b8ed71');
  $('preset').replaceChildren(...meta.presets.map(p => { const option = node('option', p.title); option.value = p.id; return option; }));
  $('capabilities').replaceChildren(...meta.capabilities.map(s => node('li', s))); $('methodTitle').textContent = `${meta.name}: what the result means`;
  $('minimize').hidden = meta.name !== 'TenantScope'; $('releaseFiles').hidden = meta.name !== 'ReleaseTwin';
  selectPreset(); notice();
} catch(e) { notice(`Workbench could not initialize: ${e.message}`); $('heading').textContent = 'Connection unavailable'; $('run').disabled = true; }
