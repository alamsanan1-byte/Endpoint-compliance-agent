'use strict';
let apiKey = '';
let fleet = [];
const $ = (id) => document.getElementById(id);
const label = (value) => value.replaceAll('_', ' ');
function node(tag, text, className) {
  const el = document.createElement(tag);
  if (text !== undefined) el.textContent = text;
  if (className) el.className = className;
  return el;
}
async function api(path) {
  const response = await fetch(path, {headers: {Authorization: `Bearer ${apiKey}`}, cache: 'no-store'});
  if (!response.ok) throw new Error(response.status === 401 ? 'The API key was not accepted.' : `Request failed (${response.status}).`);
  return response.json();
}
function render() {
  const query = $('search').value.toLowerCase();
  const wanted = $('filter').value;
  const rows = fleet.filter(d => (d.hostname + d.device_id).toLowerCase().includes(query) &&
    (wanted === 'all' || (d.stale ? 'stale' : d.state) === wanted));
  $('devices').replaceChildren();
  if (!rows.length) {
    const row = node('tr'); const cell = node('td', 'No matching endpoints.'); cell.colSpan = 6; row.append(cell); $('devices').append(row);
  }
  for (const d of rows) {
    const row = node('tr'); const identity = node('td');
    identity.append(node('strong', d.hostname), node('small', d.device_id));
    const score = node('td'); score.append(node('strong', `${d.score.toFixed(1)}%`));
    const state = node('td'); state.append(node('span', label(d.stale ? 'stale' : d.state), `badge ${d.stale ? 'stale' : d.state}`));
    const action = node('td'); const button = node('button', 'View checks', 'text-button');
    button.addEventListener('click', () => showDevice(d)); action.append(button);
    row.append(identity, node('td', d.os === 'windows' ? 'Windows' : 'Linux'), score, state,
      node('td', new Date(d.collected_at).toLocaleString()), action);
    $('devices').append(row);
  }
}
async function showDevice(d) {
  $('detail').hidden = false;
  $('detail-title').textContent = `${d.hostname} / control evidence`;
  $('detail-note').textContent = d.policy_changed ? 'Current policy differs from the stored report evaluation. Scores below use the current policy.' : 'Current baseline evaluation. History preserves the original score and policy hash.';
  $('checks').replaceChildren();
  for (const check of d.checks) {
    const box = node('div', undefined, 'check');
    box.append(node('strong', label(check.id)), node('span', label(check.status), `badge ${check.status}`), node('p', check.detail));
    $('checks').append(box);
  }
  $('history').replaceChildren(node('p', 'Loading history…'));
  try {
    const data = await api(`/devices/${encodeURIComponent(d.device_id)}/history?limit=10`);
    if ($('detail-title').textContent !== `${d.hostname} / control evidence`) return;
    $('history').replaceChildren(...data.reports.map(r => node('p', `${new Date(r.report.collected_at).toLocaleString()} · ${r.evaluation.score}% · ${label(r.evaluation.state)} · policy ${r.evaluation.policy_hash.slice(0, 10)}`)));
  } catch (error) { $('history').replaceChildren(node('p', error.message)); }
  $('detail').scrollIntoView({behavior: 'smooth', block: 'start'});
}
async function refresh() {
  if (!apiKey) return;
  $('message').textContent = 'Loading fleet…';
  try {
    const data = await api('/fleet'); fleet = data.devices;
    $('metrics').replaceChildren();
    for (const [name, count] of [['Endpoints', data.total], ['Compliant', data.summary.compliant], ['Needs attention', data.summary.non_compliant + data.summary.warning], ['Unknown / stale', data.summary.unknown + data.summary.stale]]) {
      const metric = node('div', undefined, 'metric'); metric.append(node('span', name), node('strong', String(count))); $('metrics').append(metric);
    }
    $('updated').textContent = `Updated ${new Date(data.generated_at).toLocaleTimeString()} · ${data.total} endpoints`;
    $('message').textContent = 'Connected. Select an endpoint to inspect its controls and history.'; render();
  } catch (error) { $('message').textContent = error.message; }
}
$('login').addEventListener('submit', event => {event.preventDefault(); apiKey = $('key').value; $('key').value = ''; refresh();});
$('disconnect').addEventListener('click', () => {apiKey = ''; fleet = []; $('key').value = ''; $('metrics').replaceChildren(); $('detail').hidden = true; $('checks').replaceChildren(); $('history').replaceChildren(); $('updated').textContent = 'Disconnected'; $('message').textContent = 'Disconnected. Reload to start a fresh session.'; render();});
$('refresh').addEventListener('click', refresh);
$('search').addEventListener('input', render);
$('filter').addEventListener('change', render);
