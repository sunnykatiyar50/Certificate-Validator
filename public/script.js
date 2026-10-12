const $ = id => document.getElementById(id);

// ---------- helpers ----------

const state = { user: null };

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function showError(out, message) {
  out.innerHTML = `<div class="panel error"><span class="badge bad">Error</span> ${escapeHtml(message)}</div>`;
}

function formatDate(iso) {
  const d = new Date(iso);
  return isNaN(d) ? '' : d.toLocaleString();
}

function slug(text) {
  return String(text || 'keypair').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 50) || 'keypair';
}

// A unique id for one result on the page, e.g. to find a binary download again when its button is clicked.
function newId() {
  return window.crypto && crypto.randomUUID ? crypto.randomUUID() : `${Date.now().toString(36)}${Math.random().toString(36).slice(2)}`;
}

// All API calls go through here: the X-Requested-With header is required for writes (CSRF defence),
// and an expired session sends the user back to the login page.
async function api(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: { 'X-Requested-With': 'fetch', ...(options.headers || {}) },
    credentials: 'same-origin'
  });
  if (response.status === 401) {
    location.href = '/login.html';
    throw new Error('Your session has ended. Please sign in again.');
  }
  return response;
}

function jsonRequest(method, body) {
  return { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) };
}

// ---------- navigation ----------

const navItems = document.querySelectorAll('.nav-item[data-view]');
const views = document.querySelectorAll('.view');

function showView(name) {
  if (!$(`view-${name}`)) name = 'file';
  navItems.forEach(b => b.classList.toggle('active', b.dataset.view === name));
  views.forEach(v => v.classList.toggle('active', v.id === `view-${name}`));
  if (name === 'history') refreshHistory();
  if (name === 'cas') refreshCas();
  try { history.replaceState(null, '', `#${name}`); } catch (e) { /* hash is a convenience only */ }
}
navItems.forEach(b => b.addEventListener('click', () => showView(b.dataset.view)));

// ---------- validation forms ----------

async function submitAndRender(url, options, out) {
  out.textContent = 'Working...';
  try {
    const response = await api(url, options);
    renderCertResults(await response.json(), out);
  } catch (err) {
    showError(out, err.message === 'Failed to fetch' ? 'Request failed. Is the server running?' : err.message);
  }
}

$('fileForm').addEventListener('submit', e => {
  e.preventDefault();
  const out = $('result-file');
  const fileInput = $('certificate');
  if (!fileInput.files.length) return showError(out, 'Please select a certificate file.');
  const formData = new FormData();
  formData.append('certificate', fileInput.files[0]);
  const password = $('filePassword').value;
  const hostname = $('fileHostname').value.trim();
  if (password) formData.append('password', password);
  if (hostname) formData.append('hostname', hostname);
  submitAndRender('/api/validate-certificate', { method: 'POST', body: formData }, out);
});

$('textForm').addEventListener('submit', e => {
  e.preventDefault();
  const out = $('result-text');
  const certText = $('certText').value.trim();
  if (!certText) return showError(out, 'Please paste certificate text.');
  const formData = new FormData();
  formData.append('certText', certText);
  const password = $('textPassword').value;
  const hostname = $('textHostname').value.trim();
  if (password) formData.append('password', password);
  if (hostname) formData.append('hostname', hostname);
  submitAndRender('/api/validate-certificate', { method: 'POST', body: formData }, out);
});

$('liveForm').addEventListener('submit', e => {
  e.preventDefault();
  const out = $('result-live');
  let host = $('liveHost').value.trim();
  let port = $('livePort').value.trim();
  if (!host) return showError(out, 'Please enter a hostname.');
  // Accept pasted URLs and host:port.
  host = host.replace(/^[a-z]+:\/\//i, '').replace(/[/?#].*$/, '');
  const hostPort = /^([^:\[\]]+):(\d+)$/.exec(host);
  if (hostPort) {
    host = hostPort[1];
    port = port || hostPort[2];
  }
  submitAndRender('/api/check-host', jsonRequest('POST', { host, port: port || undefined }), out);
});

function clearForm(ids, outId) {
  ids.forEach(id => { $(id).value = ''; });
  if (outId) $(outId).innerHTML = '';
}
$('clearFileBtn').addEventListener('click', () => clearForm(['certificate', 'filePassword', 'fileHostname'], 'result-file'));
$('clearTextBtn').addEventListener('click', () => clearForm(['certText', 'textPassword', 'textHostname'], 'result-text'));
$('clearLiveBtn').addEventListener('click', () => clearForm(['liveHost', 'livePort'], 'result-live'));

// ---------- validation result rendering ----------

function certLabel(cert, idx) {
  const attrs = cert.subject || [];
  const cn = attrs.find(a => a.shortName === 'CN') || attrs[0];
  return cn ? `#${idx + 1} ${cn.value}` : `#${idx + 1}`;
}

function badge(kind, text) {
  return `<span class="badge ${kind}">${escapeHtml(text)}</span>`;
}

function renderDaysRemaining(cert) {
  if (typeof cert.daysRemaining !== 'number') return '';
  const d = cert.daysRemaining;
  if (d < 0) return badge('bad', `Expired ${-d} day${d === -1 ? '' : 's'} ago`);
  if (d <= 30) return badge('warn', `${d} day${d === 1 ? '' : 's'} left`);
  return badge('good', `${d} days left`);
}

function renderIssuedBy(cert, certs) {
  const by = cert.issuedBy;
  if (!by) return '';
  if (by.source === 'chain') return `Signed by certificate ${escapeHtml(certLabel(certs[by.index], by.index))}`;
  if (by.source === 'trust-store') return `Signed by trusted root: ${escapeHtml(by.name)}`;
  if (by.source === 'self') return 'Self-signed';
  return 'Issuer not provided';
}

function renderChain(data) {
  const chain = data.chain;
  if (!chain) return '';
  const kinds = { trusted: 'good', expired: 'bad', broken: 'bad', 'untrusted-root': 'warn', incomplete: 'warn' };
  const titles = {
    trusted: 'Trusted chain', expired: 'Chain expired', broken: 'Broken chain',
    'untrusted-root': 'Untrusted root', incomplete: 'Incomplete chain'
  };
  const path = chain.path.map(i => escapeHtml(certLabel(data.certs[i], i))).join(' &rarr; ');
  return `<div class="panel">
    <div class="panel-title">Chain verification ${badge(kinds[chain.status] || 'warn', titles[chain.status] || chain.status)}</div>
    <div>${escapeHtml(chain.message)}</div>
    <div class="muted">${path}</div>
    ${chain.unusedCerts.length ? `<div class="muted">Not part of the chain: ${chain.unusedCerts.map(i => escapeHtml(certLabel(data.certs[i], i))).join(', ')}</div>` : ''}
    <div class="muted">Trust store: ${escapeHtml(chain.trustStore)}</div>
    ${renderPlatforms(chain.platformTrust)}
  </div>`;
}

function renderPlatforms(trust) {
  if (!trust) return '';
  const kinds = { trusted: 'good', 'not-trusted': 'bad', expired: 'bad', unknown: 'warn' };
  const labels = { trusted: 'trusted', 'not-trusted': 'not trusted', expired: 'expired chain', unknown: 'unknown' };
  const asOf = trust.asOf ? ` Apple, Chrome and Microsoft use CCADB root-store data from ${escapeHtml(trust.asOf)}.` : '';
  return `<div class="platforms">${trust.platforms.map(p => badge(kinds[p.status] || 'warn', `${p.name}: ${labels[p.status] || p.status}`)).join(' ')}</div>
    <div class="muted">Whether the chain's root is in each root program.${asOf}</div>`;
}

function renderScts(scts) {
  if (!scts || !scts.length) return '';
  const rows = scts.map((s, i) => row(`SCT ${i + 1}`,
    `<b>${escapeHtml(s.logName || 'Unknown log')}</b>${s.logOperator ? ` (${escapeHtml(s.logOperator)})` : ''}${s.logState && s.logState !== 'usable' ? ' ' + badge('warn', s.logState) : ''}
     <div class="muted">Logged ${escapeHtml(formatDate(s.timestamp))}${s.signatureAlgorithm ? ' &middot; ' + escapeHtml(s.signatureAlgorithm) : ''}</div>
     ${s.logName ? '' : `<div class="muted mono">Log ID ${escapeHtml(s.logId)}</div>`}`));
  return section('Certificate Transparency', [row('Embedded SCTs', escapeHtml(String(scts.length))), ...rows]);
}

function renderHostname(check) {
  if (!check) return '';
  const body = check.matches
    ? `${badge('good', 'Match')} Certificate covers <b>${escapeHtml(check.hostname)}</b> (via ${escapeHtml(check.matchedName)})`
    : `${badge('bad', 'No match')} Certificate does not cover <b>${escapeHtml(check.hostname)}</b>`;
  return `<div class="panel"><div class="panel-title">Hostname check</div><div>${body}</div></div>`;
}

function renderLive(live) {
  if (!live) return '';
  return `<div class="panel">
    <div class="panel-title">Connection to ${escapeHtml(live.host)}:${escapeHtml(live.port)}</div>
    <div>Protocol: ${escapeHtml(live.protocol)} &middot; Cipher: ${escapeHtml(live.cipher)}</div>
    <div>Resolved address: ${escapeHtml(live.address)}</div>
    <div>${live.authorized
      ? badge('good', 'Accepted by the server\'s trust store')
      : badge('warn', 'Not accepted')} ${escapeHtml(live.authorizationError || '')}</div>
  </div>`;
}

function renderWarnings(warnings) {
  if (!warnings || !warnings.length) return '';
  const kinds = { danger: 'bad', warning: 'warn', info: 'info' };
  return `<ul class="warnings">${warnings.map(w => `<li>${badge(kinds[w.level] || 'info', w.level)} ${escapeHtml(w.message)}</li>`).join('')}</ul>`;
}

function renderName(attrs) {
  if (!attrs || attrs.length === 0) return '<span class="muted">None</span>';
  return attrs.map(a => `<span class="rdn"><b>${escapeHtml(a.shortName)}</b> ${escapeHtml(a.value)}</span>`).join('');
}

function chips(items) {
  return items.map(i => `<span class="chip">${escapeHtml(i)}</span>`).join('');
}

// One label/value row; skipped when there is no value.
function row(label, valueHtml, { mono = false } = {}) {
  if (!valueHtml) return '';
  return `<dt>${escapeHtml(label)}</dt><dd${mono ? ' class="mono"' : ''}>${valueHtml}</dd>`;
}

function section(title, rows) {
  const body = rows.join('');
  return body ? `<div class="section"><div class="section-title">${escapeHtml(title)}</div><dl class="details">${body}</dl></div>` : '';
}

function renderCert(cert, idx, certs) {
  const role = cert.isCA === true ? 'CA' : cert.isCA === false ? 'End-entity' : '';
  const issuerCheck = cert.issuedBy
    ? renderIssuedBy(cert, certs) + (cert.signatureCheck === 'invalid' ? ' ' + badge('bad', 'signature does not verify') : '')
    : '';
  const sans = (cert.sans || []).map(s => `${s.type}: ${s.value}`);
  const unknown = '<span class="muted">Unknown</span>';
  return `<div class="cert">
    <div class="cert-header">
      <div class="cert-title">${certs.length > 1 ? `Certificate ${idx + 1}` : 'Certificate'} ${role ? badge('info', role) : ''} ${renderDaysRemaining(cert)}</div>
      <div class="cert-status ${cert.valid ? 'ok' : 'bad'}">${cert.valid ? '&#10003; Valid' : '&#10007; Invalid'}</div>
    </div>
    ${cert.error ? `<div class="problem">${escapeHtml(cert.error)}</div>` : ''}
    ${renderWarnings(cert.warnings)}
    <div class="sections">
    ${section('Validity', [
      row('Valid from', escapeHtml(cert.validFrom)),
      row('Valid to', escapeHtml(cert.validTo))
    ])}
    ${section('Identity', [
      row('Subject', renderName(cert.subject)),
      row('Issuer', renderName(cert.issuer)),
      row('Issuer check', issuerCheck),
      row('Serial number', escapeHtml(cert.serialNumber) || unknown, { mono: true }),
      row('Version', escapeHtml(cert.version) || unknown)
    ])}
    ${section('Key and signature', [
      row('Public key', escapeHtml(cert.publicKeyInfo) || unknown),
      row('Signature algorithm', escapeHtml(cert.signatureAlgorithm) || unknown)
    ])}
    ${section('Fingerprints', [
      row('SHA-256', escapeHtml(cert.fingerprintSha256) || unknown, { mono: true }),
      row('SHA-1', escapeHtml(cert.fingerprintSha1) || unknown, { mono: true })
    ])}
    ${section('Extensions', [
      row('Subject alt names', chips(sans)),
      row('Key usage', chips(cert.keyUsage || [])),
      row('Extended key usage', chips(cert.extKeyUsage || []))
    ])}
    ${renderScts(cert.scts)}
    </div>
  </div>`;
}

function renderCertResults(data, out) {
  if (data.error) return showError(out, data.error);
  let html = '';
  if (data.hasPrivateKey) {
    html += '<div class="note-warn"><b>Note:</b> A private key was detected in the input. Private keys are ignored for validation.</div>';
  }
  if (data.certs && data.certs.length > 0) {
    html += renderLive(data.live) + renderHostname(data.hostnameCheck) + renderChain(data);
    html += data.certs.map((cert, idx) => renderCert(cert, idx, data.certs)).join('');
  } else {
    html += '<div class="panel error">No certificates found.</div>';
  }
  out.innerHTML = html;
}

// ---------- key pair generation ----------

const algorithmSelect = $('genAlgorithm');

function groupLabel(id) {
  if (id.startsWith('RSA')) return 'RSA';
  if (id.startsWith('ECDSA')) return 'ECDSA (elliptic curve)';
  return 'EdDSA';
}

async function loadAlgorithms() {
  try {
    const { algorithms } = await (await api('/api/algorithms')).json();
    const groups = new Map();
    algorithms.forEach(a => {
      const g = groupLabel(a.id);
      if (!groups.has(g)) groups.set(g, []);
      groups.get(g).push(a);
    });
    algorithmSelect.innerHTML = [...groups].map(([label, items]) =>
      `<optgroup label="${escapeHtml(label)}">${items.map(a => `<option value="${escapeHtml(a.id)}" data-hashed="${a.hashed}">${escapeHtml(a.label)}</option>`).join('')}</optgroup>`
    ).join('');
    algorithmSelect.value = 'RSA-2048';
    syncGenerateForm();
  } catch (err) {
    algorithmSelect.innerHTML = '<option value="">Could not load algorithms</option>';
  }
}

// Ed25519 has no separate hash; "keys only" needs no subject.
function syncGenerateForm() {
  const selected = algorithmSelect.selectedOptions[0];
  $('genHash').disabled = !!selected && selected.dataset.hashed === 'false';
  $('genSubject').hidden = $('genOutput').value === 'keys';
}
algorithmSelect.addEventListener('change', syncGenerateForm);
$('genOutput').addEventListener('change', syncGenerateForm);

function pemBlock(title, pem, filename, { secret = false, kind } = {}) {
  return `<div class="pem-block${secret ? ' secret' : ''}" data-kind="${escapeHtml(kind)}">
    <div class="pem-head">
      <span><b>${escapeHtml(title)}</b>${secret ? ' ' + badge('bad', 'keep secret') : ''}</span>
      <span class="pem-actions">
        <button type="button" class="btn small" data-action="copy">Copy</button>
        <button type="button" class="btn small" data-action="download" data-filename="${escapeHtml(filename)}">Download</button>
      </span>
    </div>
    <pre>${escapeHtml(pem)}</pre>
  </div>`;
}

// Shared by the Generate result and the History detail.
function renderKeyPair(entry, { notice = '', historyId = null, missingKeyMessage = '' } = {}) {
  const base = slug(entry.name);
  const kind = entry.certificatePem ? 'Self-signed certificate' : entry.csrPem ? 'Certificate signing request' : 'Key pair only';
  const hash = entry.hash ? ` with ${entry.hash}` : '';
  const actions = [];
  if (entry.certificatePem) actions.push('<button type="button" class="btn primary small" data-action="validate">Validate this certificate</button>');
  if (historyId) {
    actions.push(`<button type="button" class="btn small" data-action="rename" data-id="${escapeHtml(historyId)}">Rename</button>`);
    actions.push(`<button type="button" class="btn small danger" data-action="delete" data-id="${escapeHtml(historyId)}">Delete</button>`);
  }
  return `<div class="cert">
    <div class="cert-header">
      <div class="cert-title">${escapeHtml(entry.name)} ${badge('info', entry.algorithmLabel)}</div>
      <div class="pem-actions">${actions.join('')}</div>
    </div>
    ${notice ? `<div class="notice">${notice}</div>` : ''}
    ${section('Details', [
      row('Type', escapeHtml(kind + hash)),
      row('Owner', entry.owner ? escapeHtml(entry.owner) : ''),
      row('Subject', entry.subject ? `<span class="rdn"><b>CN</b> ${escapeHtml(entry.subject)}</span>` : ''),
      row('Subject alt names', chips(entry.sans || [])),
      row('Role', entry.certificatePem ? escapeHtml(entry.isCA ? 'CA certificate' : 'End-entity (TLS server and client)') : ''),
      row('Valid from', escapeHtml(formatDate(entry.notBefore))),
      row('Valid to', escapeHtml(formatDate(entry.notAfter))),
      row('SHA-256', escapeHtml(entry.fingerprintSha256), { mono: true }),
      row('Created', escapeHtml(formatDate(entry.createdAt)))
    ])}
    <div class="pem-list">
      ${entry.certificatePem ? pemBlock('Certificate', entry.certificatePem, `${base}-cert.pem`, { kind: 'certificate' }) : ''}
      ${entry.csrPem ? pemBlock('Certificate signing request', entry.csrPem, `${base}-csr.pem`, { kind: 'csr' }) : ''}
      ${entry.privateKeyPem
        ? pemBlock('Private key (PKCS#8)', entry.privateKeyPem, `${base}-key.pem`, { secret: true, kind: 'private' })
        : `<div class="panel muted">${escapeHtml(missingKeyMessage || 'The private key was not saved.')}</div>`}
      ${entry.publicKeyPem ? pemBlock('Public key (SPKI)', entry.publicKeyPem, `${base}-pub.pem`, { kind: 'public' }) : ''}
    </div>
  </div>`;
}

// What the server stores: everything except the private key.
function historyPayload(entry) {
  return {
    name: entry.name, algorithm: entry.algorithm, algorithmLabel: entry.algorithmLabel, hash: entry.hash,
    subject: entry.subject, sans: entry.sans || [], isCA: !!entry.isCA, notBefore: entry.notBefore, notAfter: entry.notAfter,
    fingerprintSha256: entry.fingerprintSha256, certificatePem: entry.certificatePem, csrPem: entry.csrPem, publicKeyPem: entry.publicKeyPem
  };
}

// Save a generated key pair to history, and keep its private key where the user chose: 'with' = this browser,
// 'server' = encrypted on the server, 'without' = nowhere, 'none' = nothing is saved. Returns the notice to show.
async function saveToHistory(entry, privateKeyPem, mode) {
  if (mode === 'none') return 'Not saved. Copy or download the private key now, it cannot be recovered later.';
  const saved = await api('/api/history', jsonRequest('POST', historyPayload(entry)));
  const result = await saved.json();
  if (!saved.ok) return `Could not save to history: ${escapeHtml(result.error || 'unknown error')}. Copy or download the private key now.`;
  let notice = `Saved to history as <b>${escapeHtml(entry.name)}</b>. `;
  if (mode === 'with') {
    notice += saveLocalKey(result.entry.id, privateKeyPem)
      ? 'The private key is kept in this browser only, never on the server.'
      : 'The private key could not be kept (browser storage is unavailable), so copy or download it now.';
  } else if (mode === 'server') {
    const put = await api(`/api/history/${encodeURIComponent(result.entry.id)}/key`, jsonRequest('PUT', { privateKeyPem }));
    const body = await put.json().catch(() => ({}));
    notice += put.ok
      ? 'The private key is kept on the server, encrypted, and only you can read it.'
      : `The private key could not be kept on the server (${escapeHtml(body.error || 'unknown error')}), so copy or download it now.`;
  } else {
    notice += 'The private key was not kept, so copy or download it now.';
  }
  updateHistoryCount();
  return notice;
}

$('generateForm').addEventListener('submit', async e => {
  e.preventDefault();
  const out = $('result-generate');
  const submit = e.submitter || e.target.querySelector('[type="submit"]');
  const algorithm = algorithmSelect.value;
  const output = $('genOutput').value;
  const commonName = $('genCommonName').value.trim();
  if (!algorithm) return showError(out, 'Choose an algorithm.');
  if (output !== 'keys' && !commonName) return showError(out, 'Common name is required.');

  const body = {
    algorithm, output, commonName,
    hash: $('genHash').value,
    sans: $('genSans').value,
    validityDays: $('genValidity').value,
    isCA: $('genIsCA').checked,
    organization: $('genOrg').value,
    organizationalUnit: $('genOu').value,
    country: $('genCountry').value,
    state: $('genState').value,
    locality: $('genLocality').value
  };

  submit.disabled = true;
  out.textContent = 'Generating...';
  try {
    const response = await api('/api/generate-keypair', jsonRequest('POST', body));
    const data = await response.json();
    if (!response.ok || data.error) return showError(out, data.error || 'Key generation failed.');

    const entry = {
      ...data,
      name: $('genName').value.trim() || `${commonName || 'keypair'} (${data.algorithmLabel})`,
      createdAt: new Date().toISOString()
    };
    const notice = await saveToHistory(entry, data.privateKeyPem, $('genHistory').value);
    out.innerHTML = renderKeyPair(entry, { notice });
  } catch (err) {
    showError(out, err.message === 'Failed to fetch' ? 'Request failed. Is the server running?' : err.message);
  } finally {
    submit.disabled = false;
  }
});

// ---------- history (stored on the server; private keys only in this browser) ----------

// Private keys never go to the server. If the user chooses to keep one, it lives in this browser's
// storage under the signed-in username, keyed by the history item's id.
const keyStoreName = () => `certvalidator.keys.v1:${state.user.username}`;
const LEGACY_HISTORY_KEY = 'certvalidator.history.v1';

function loadLocalKeys() {
  try {
    const keys = JSON.parse(localStorage.getItem(keyStoreName()) || '{}');
    return keys && typeof keys === 'object' ? keys : {};
  } catch (e) {
    return {};
  }
}

function saveLocalKeys(keys) {
  try {
    localStorage.setItem(keyStoreName(), JSON.stringify(keys));
    return true;
  } catch (e) {
    return false;
  }
}

function saveLocalKey(id, privateKeyPem) {
  const keys = loadLocalKeys();
  keys[id] = privateKeyPem;
  return saveLocalKeys(keys);
}

function removeLocalKeys(ids) {
  const keys = loadLocalKeys();
  ids.forEach(id => delete keys[id]);
  saveLocalKeys(keys);
}

function loadLegacyHistory() {
  try {
    const list = JSON.parse(localStorage.getItem(LEGACY_HISTORY_KEY) || '[]');
    return Array.isArray(list) ? list.filter(e => e && e.name && e.algorithm) : [];
  } catch (e) {
    return [];
  }
}

let historyEntries = [];
let selectedHistoryId = null;
let historyOwnerFilter = '';

function isAdmin() {
  return state.user && state.user.role === 'admin';
}

function updateHistoryCount() {
  api('/api/history').then(r => r.json()).then(data => {
    historyEntries = data.history || [];
    $('historyCount').textContent = historyEntries.length;
    $('historyCount').hidden = historyEntries.length === 0;
  }).catch(() => {});
}

async function refreshHistory() {
  try {
    const response = await api('/api/history');
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Could not load history.');
    historyEntries = data.history;
  } catch (err) {
    $('historyList').innerHTML = `<p class="muted">${escapeHtml(err.message)}</p>`;
    return;
  }
  $('historyCount').textContent = historyEntries.length;
  $('historyCount').hidden = historyEntries.length === 0;
  drawHistory();
}

function drawHistory() {
  const me = state.user.username;
  let list = historyEntries;

  // Admins can narrow the list to one user.
  $('historyAdminBar').hidden = !isAdmin();
  if (isAdmin()) {
    const counts = new Map();
    historyEntries.forEach(e => counts.set(e.owner, (counts.get(e.owner) || 0) + 1));
    if (historyOwnerFilter && !counts.has(historyOwnerFilter)) historyOwnerFilter = '';
    $('historyOwner').innerHTML = `<option value="">All users (${historyEntries.length})</option>` +
      [...counts].sort((a, b) => a[0].localeCompare(b[0])).map(([owner, n]) =>
        `<option value="${escapeHtml(owner)}">${escapeHtml(owner)}${owner === me ? ' (you)' : ''} (${n})</option>`).join('');
    $('historyOwner').value = historyOwnerFilter;
    if (historyOwnerFilter) list = list.filter(e => e.owner === historyOwnerFilter);
  }

  // Items saved in this browser before accounts existed can be imported once.
  const legacy = loadLegacyHistory();
  $('legacyBanner').hidden = legacy.length === 0;
  if (legacy.length) {
    $('legacyBanner').innerHTML = `${legacy.length} item${legacy.length === 1 ? '' : 's'} saved in this browser before sign-in was added.
      <button type="button" class="btn small" data-action="import-legacy">Import to my history</button>`;
  }

  $('clearHistoryBtn').hidden = !historyEntries.some(e => e.owner === me);
  if (!list.some(e => e.id === selectedHistoryId)) selectedHistoryId = list.length ? list[0].id : null;

  $('historyList').innerHTML = list.length
    ? list.map(e => `<button type="button" class="history-item${e.id === selectedHistoryId ? ' selected' : ''}" data-action="select" data-id="${escapeHtml(e.id)}">
        <span class="history-name">${escapeHtml(e.name)}</span>
        <span class="history-meta">${escapeHtml(e.algorithmLabel)} &middot; ${escapeHtml(formatDate(e.createdAt))}${isAdmin() ? ` &middot; ${escapeHtml(e.owner)}` : ''}</span>
        <span class="history-tags">${e.certificatePem ? badge('info', 'cert') : ''}${e.csrPem ? badge('info', 'csr') : ''}${e.owner === me && loadLocalKeys()[e.id] ? badge('warn', 'private key here') : ''}${e.keyOnServer ? badge('warn', 'key on server') : ''}</span>
      </button>`).join('')
    : `<p class="muted">${historyEntries.length ? 'No items for this user.' : 'Nothing here yet. Generated key pairs you choose to save will be listed here.'}</p>`;

  const selected = list.find(e => e.id === selectedHistoryId);
  if (!selected) {
    $('result-history').innerHTML = '';
    return;
  }
  const mine = selected.owner === me;
  const privateKeyPem = mine ? loadLocalKeys()[selected.id] : undefined;
  const card = (pem, message) => renderKeyPair({ ...selected, privateKeyPem: pem }, { historyId: selected.id, missingKeyMessage: message });
  if (!privateKeyPem && mine && selected.keyOnServer) {
    $('result-history').innerHTML = card(undefined, 'Loading the private key from the server...');
    api(`/api/history/${encodeURIComponent(selected.id)}/key`).then(r => r.json()).then(d => {
      if (selectedHistoryId === selected.id) $('result-history').innerHTML = card(d.privateKeyPem, d.error || 'The private key could not be loaded.');
    }).catch(() => {});
    return;
  }
  $('result-history').innerHTML = card(privateKeyPem, mine
    ? 'The private key was not kept: it is not on the server and not in this browser.'
    : 'Private keys are only ever visible to the person who generated them.');
}

$('historyOwner').addEventListener('change', e => {
  historyOwnerFilter = e.target.value;
  drawHistory();
});

async function importLegacyHistory(button) {
  const legacy = loadLegacyHistory();
  button.disabled = true;
  let imported = 0;
  const failures = [];
  for (const item of legacy) {
    try {
      const response = await api('/api/history', jsonRequest('POST', historyPayload(item)));
      const data = await response.json();
      if (!response.ok) {
        failures.push(`${item.name}: ${data.error}`);
        continue;
      }
      if (item.privateKeyPem) saveLocalKey(data.entry.id, item.privateKeyPem);
      imported++;
    } catch (err) {
      failures.push(`${item.name}: ${err.message}`);
    }
  }
  if (!failures.length) {
    try { localStorage.removeItem(LEGACY_HISTORY_KEY); } catch (e) { /* ignore */ }
  }
  await refreshHistory();
  if (failures.length) {
    $('legacyBanner').hidden = false;
    $('legacyBanner').textContent = `Imported ${imported} of ${legacy.length}. Not imported: ${failures.join('; ')}`;
  }
}

// ---------- click actions (copy, download, history, ...) ----------

function flash(btn, text) {
  const original = btn.textContent;
  btn.textContent = text;
  setTimeout(() => { btn.textContent = original; }, 1200);
}

async function historyRequest(method, url, body) {
  const response = await api(url, jsonRequest(method, body));
  const data = await response.json().catch(() => ({}));
  if (!response.ok) window.alert(data.error || 'That did not work.');
  return response.ok ? data : null;
}

document.addEventListener('click', async e => {
  const btn = e.target.closest('[data-action]');
  if (!btn) return;
  const action = btn.dataset.action;
  const id = btn.dataset.id;

  if (action === 'copy') {
    const text = btn.closest('.pem-block').querySelector('pre').textContent;
    try {
      await navigator.clipboard.writeText(text);
      flash(btn, 'Copied');
    } catch (err) {
      flash(btn, 'Copy failed');
    }
  } else if (action === 'download') {
    const text = btn.closest('.pem-block').querySelector('pre').textContent;
    const link = document.createElement('a');
    const url = URL.createObjectURL(new Blob([text], { type: 'application/x-pem-file' }));
    link.href = url;
    link.download = btn.dataset.filename || 'download.pem';
    link.click();
    URL.revokeObjectURL(url);
  } else if (action === 'validate') {
    const card = btn.closest('.cert');
    const block = card.querySelector('[data-kind="fullchain"] pre') || card.querySelector('[data-kind="certificate"] pre');
    $('certText').value = block.textContent;
    $('textHostname').value = '';
    showView('text');
    $('textForm').requestSubmit();
  } else if (action === 'clear') {
    clearForm(btn.dataset.ids.split(','), btn.dataset.out);
  } else if (action === 'copy-b64') {
    try {
      await navigator.clipboard.writeText(binaryDownloads.get(id).content);
      flash(btn, 'Copied');
    } catch (err) {
      flash(btn, 'Copy failed');
    }
  } else if (action === 'download-b64') {
    const f = binaryDownloads.get(id);
    if (f) saveBlob(base64ToBlob(f.content, f.mime), f.name);
  } else if (action === 'decode-csr') {
    $('decodeText').value = btn.closest('.cert').querySelector('[data-kind="csr"] pre').textContent;
    showView('decode');
    $('decodeForm').requestSubmit();
  } else if (action === 'sign-csr') {
    $('signCsrText').value = btn.closest('.cert').querySelector('[data-kind="csr"] pre').textContent;
    showView('ca-sign');
  } else if (action === 'use-ca' || action === 'intermediate-from-ca') {
    const card = btn.closest('.cert');
    const pair = card.querySelector('[data-kind="certificate"] pre').textContent + card.querySelector('[data-kind="private"] pre').textContent;
    if (action === 'use-ca') {
      $('signCaText').value = pair;
      showView('ca-sign');
    } else {
      $('caKind').value = 'intermediate';
      $('caKind').dispatchEvent(new Event('change'));
      $('caParentText').value = pair;
      $('caCommonName').value = '';
      showView('ca-create');
    }
  } else if (action === 'select') {
    selectedHistoryId = id;
    drawHistory();
  } else if (action === 'rename') {
    const entry = historyEntries.find(x => x.id === id);
    const name = entry && window.prompt('Rename', entry.name);
    if (name && name.trim() && await historyRequest('PATCH', `/api/history/${encodeURIComponent(id)}`, { name: name.trim() })) {
      refreshHistory();
    }
  } else if (action === 'delete') {
    const entry = historyEntries.find(x => x.id === id);
    const whose = entry && entry.owner !== state.user.username ? ` (saved by ${entry.owner})` : '';
    if (entry && window.confirm(`Delete "${entry.name}"${whose} from history? This cannot be undone.`)) {
      if (await historyRequest('DELETE', `/api/history/${encodeURIComponent(id)}`)) {
        removeLocalKeys([id]);
        refreshHistory();
      }
    }
  } else if (action === 'clear-history') {
    if (window.confirm('Delete all of your saved key pairs? This cannot be undone.')) {
      const mine = historyEntries.filter(x => x.owner === state.user.username).map(x => x.id);
      if (await historyRequest('DELETE', '/api/history')) {
        removeLocalKeys(mine);
        selectedHistoryId = null;
        refreshHistory();
      }
    }
  } else if (action === 'import-legacy') {
    importLegacyHistory(btn);
  } else if (action === 'ca-issue' || action === 'ca-sign-with' || action === 'ca-crl-with') {
    useSavedCa(btn.dataset.pick, action === 'ca-issue' ? 'issue' : action === 'ca-sign-with' ? 'sign' : 'crl');
  } else if (action === 'ca-download-cert') {
    const ca = findSavedCa(btn.dataset.pick);
    if (ca) saveBlob(new Blob([ca.certificatePem + (ca.chainPem || '')], { type: 'application/x-pem-file' }), `${slug(ca.name)}-ca.pem`);
  } else if (action === 'ca-download-key') {
    downloadCaKey(btn.dataset.pick);
  } else if (action === 'ca-rename') {
    renameSavedCa(btn.dataset.pick);
  } else if (action === 'ca-delete') {
    deleteSavedCa(btn.dataset.pick);
  }
});

// ---------- tools: shared helpers ----------

// Add the files chosen in `fileInputId` and any pasted text to a FormData under the given field names.
function appendInputs(fd, fileInputId, fileField, textId, textField) {
  for (const file of $(fileInputId).files) fd.append(fileField, file);
  const text = $(textId).value.trim();
  if (text) fd.append(textField, text);
}

function appendIf(fd, name, value) {
  const v = typeof value === 'string' ? value.trim() : value;
  if (v !== undefined && v !== null && v !== '') fd.append(name, v);
}

function hasInput(fileInputId, textId) {
  return $(fileInputId).files.length > 0 || $(textId).value.trim() !== '';
}

async function postTool(url, formData, out, render, submit) {
  out.textContent = 'Working...';
  if (submit) submit.disabled = true;
  try {
    const response = await api(url, { method: 'POST', body: formData });
    const data = await response.json();
    if (!response.ok || data.error) return showError(out, data.error || 'The request failed.');
    out.innerHTML = render(data);
  } catch (err) {
    showError(out, err.message === 'Failed to fetch' ? 'Request failed. Is the server running?' : err.message);
  } finally {
    if (submit) submit.disabled = false;
  }
}

const toolWarnings = list => (list && list.length)
  ? renderWarnings(list.map(message => ({ level: 'warning', message })))
  : '';

// Binary results (PFX, JKS, DER) are kept here so a download button can find them by id.
const binaryDownloads = new Map();

function base64ToBlob(b64, mime) {
  const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  return new Blob([bytes], { type: mime || 'application/octet-stream' });
}

function saveBlob(blob, filename) {
  const link = document.createElement('a');
  const url = URL.createObjectURL(blob);
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function humanSize(bytes) {
  return bytes < 1024 ? `${bytes} bytes` : `${(bytes / 1024).toFixed(1)} KB`;
}

function renderFiles(files) {
  return `<div class="pem-list">${files.map(f => {
    const note = f.note ? `<div class="muted file-note">${escapeHtml(f.note)}</div>` : '';
    if (f.encoding === 'text') {
      const secret = f.secret || /private-key/.test(f.name);
      return note + pemBlock(f.name, f.content, f.name, { secret, kind: f.name.replace(/\.[^.]+$/, '') });
    }
    const id = newId();
    binaryDownloads.set(id, f);
    const size = humanSize(Math.floor(f.content.length * 3 / 4));
    return `<div class="pem-block${f.secret || /keystore|\.pfx|private-key/.test(f.name) ? ' secret' : ''}">
      <div class="pem-head">
        <span><b>${escapeHtml(f.name)}</b> ${badge('info', size)}</span>
        <span class="pem-actions">
          <button type="button" class="btn small" data-action="copy-b64" data-id="${id}">Copy base64</button>
          <button type="button" class="btn small primary" data-action="download-b64" data-id="${id}">Download</button>
        </span>
      </div>
      <div class="file-note muted">${escapeHtml(f.note || 'Binary file.')}</div>
    </div>`;
  }).join('')}</div>`;
}

// ---------- decode (CSR / CRL / bundles) ----------

function renderCsrDecoded(c) {
  const unknown = '<span class="muted">Unknown</span>';
  const basic = c.basicConstraints ? `CA: ${c.basicConstraints.ca ? 'yes' : 'no'}${c.basicConstraints.pathLength !== null ? `, path length ${c.basicConstraints.pathLength}` : ''}` : '';
  return `<div class="cert">
    <div class="cert-header">
      <div class="cert-title">Certificate signing request ${badge('info', c.publicKey)}</div>
      <div class="cert-status ${c.signatureValid ? 'ok' : 'bad'}">${c.signatureValid ? '&#10003; Signature valid' : '&#10007; Signature invalid'}</div>
    </div>
    ${renderWarnings(c.warnings)}
    <div class="sections">
    ${section('Identity', [
      row('Subject', renderName(c.subject))
    ])}
    ${section('Key and signature', [
      row('Public key', escapeHtml(c.publicKey)),
      row('Signature algorithm', escapeHtml(c.signatureAlgorithm) || unknown),
      row('Key ID (SHA-256)', escapeHtml(c.keyId), { mono: true })
    ])}
    ${section('Requested', [
      row('Subject alt names', chips((c.sans || []).map(s => `${s.type}: ${s.value}`))),
      row('Key usage', chips(c.keyUsage || [])),
      row('Extended key usage', chips(c.extKeyUsage || [])),
      row('Basic constraints', escapeHtml(basic)),
      row('All extensions', chips((c.requestedExtensions || []).map(e => e.name || e.oid)))
    ])}
    ${section('Fingerprint', [row('SHA-256', escapeHtml(c.fingerprintSha256), { mono: true })])}
    </div>
  </div>`;
}

function renderCrlDecoded(c) {
  const sigBadge = { valid: badge('good', 'Signature valid'), invalid: badge('bad', 'Signature invalid'), unchecked: badge('info', 'Signature not checked') }[c.signature];
  const status = c.expired === null ? '' : c.expired ? badge('warn', 'Past next update') : badge('good', 'Current');
  const entries = (c.entries || []).map(e => `<tr><td class="mono">${escapeHtml(e.serialNumber)}</td><td>${escapeHtml(formatDate(e.revocationDate))}</td><td>${escapeHtml(e.reason || '')}</td></tr>`).join('');
  const certStatus = (c.certificateStatus || []).map(s => `<li>${s.revoked ? badge('bad', 'Revoked') : badge('good', 'Not on this CRL')} ${escapeHtml(s.subject)}${s.revoked ? ` <span class="muted">(${escapeHtml(formatDate(s.revocationDate))}${s.reason ? ', ' + escapeHtml(s.reason) : ''})</span>` : ''}</li>`).join('');
  return `<div class="cert">
    <div class="cert-header">
      <div class="cert-title">Certificate revocation list ${c.delta ? badge('info', 'Delta CRL') : ''} ${status}</div>
      <div class="cert-status">${sigBadge}</div>
    </div>
    ${renderWarnings(c.warnings)}
    <div class="sections">
    ${section('Issuer and dates', [
      row('Issuer', renderName(c.issuer)),
      row('This update', escapeHtml(formatDate(c.thisUpdate))),
      row('Next update', escapeHtml(formatDate(c.nextUpdate)) || '<span class="muted">Not set</span>'),
      row('CRL number', escapeHtml(c.crlNumber)),
      row('Signature algorithm', escapeHtml(c.signatureAlgorithm))
    ])}
    ${section('Contents', [
      row('Revoked certificates', escapeHtml(String(c.revokedCount))),
      row('SHA-256', escapeHtml(c.fingerprintSha256), { mono: true })
    ])}
    </div>
    ${certStatus ? `<div class="panel"><div class="panel-title">Certificates you supplied</div><ul class="warnings">${certStatus}</ul></div>` : ''}
    ${entries ? `<div class="section"><div class="section-title">Revoked serial numbers${c.entriesTruncated ? ` (first ${c.entries.length} of ${c.revokedCount})` : ''}</div>
      <div class="table-wrap"><table class="grid"><thead><tr><th>Serial</th><th>Revoked</th><th>Reason</th></tr></thead><tbody>${entries}</tbody></table></div></div>` : ''}
  </div>`;
}

function renderDecode(data) {
  let html = '';
  if (data.notes && data.notes.length) html += `<div class="note-warn">${data.notes.map(escapeHtml).join(' ')}</div>`;
  if (data.keystoreAliases && data.keystoreAliases.length) html += `<div class="panel muted">Keystore entries: ${escapeHtml(data.keystoreAliases.join(', '))}</div>`;
  (data.privateKeys || []).forEach(k => {
    html += `<div class="panel">${badge('warn', 'Private key')} A ${escapeHtml(k.description)} private key was found. It is not displayed.</div>`;
  });
  if (data.publicKeys) html += `<div class="panel muted">${data.publicKeys} public key${data.publicKeys === 1 ? '' : 's'} found.</div>`;
  html += data.csrs.map(renderCsrDecoded).join('');
  html += data.crls.map(renderCrlDecoded).join('');
  if (data.certificates && data.certificates.certs.length) {
    html += renderChain(data.certificates);
    html += data.certificates.certs.map((cert, idx) => renderCert(cert, idx, data.certificates.certs)).join('');
  }
  return html || '<div class="panel error">Nothing recognisable was found.</div>';
}

$('decodeForm').addEventListener('submit', e => {
  e.preventDefault();
  const out = $('result-decode');
  if (!hasInput('decodeFiles', 'decodeText')) return showError(out, 'Choose a file or paste some text.');
  const fd = new FormData();
  appendInputs(fd, 'decodeFiles', 'files', 'decodeText', 'text');
  appendIf(fd, 'password', $('decodePassword').value);
  postTool('/api/decode', fd, out, renderDecode, e.submitter);
});

// ---------- match key pair ----------

const KIND_LABELS = { 'private-key': 'Private key', certificate: 'Certificate', csr: 'CSR', 'public-key': 'Public key' };

function renderMatch(data) {
  const byId = new Map(data.items.map(i => [i.id, i]));
  let html = '';
  if (data.verdicts.length) {
    html += `<div class="panel"><div class="panel-title">Result</div><ul class="warnings">${data.verdicts.map(v => v.matches
      ? `<li>${badge('good', 'Match')} ${escapeHtml(v.subject)} belongs with ${v.partners.map(p => `<b>${escapeHtml(p)}</b>`).join(', ')}</li>`
      : `<li>${badge('bad', 'No match')} ${escapeHtml(v.subject)} does not match any certificate or CSR you supplied</li>`).join('')}</ul></div>`;
  }
  html += data.groups.map(g => `<div class="panel">
    <div class="panel-title">Public key ${g.number} &middot; ${escapeHtml(g.algorithm)} ${g.matched ? badge('good', `shared by ${g.members.length} items`) : badge('info', 'only one item')}</div>
    <ul class="warnings">${g.members.map(id => { const i = byId.get(id); return `<li>${badge(i.kind === 'private-key' ? 'warn' : 'info', KIND_LABELS[i.kind])} ${escapeHtml(i.label)}</li>`; }).join('')}</ul>
    <div class="muted mono">Key ID ${escapeHtml(g.keyId)}</div>
  </div>`).join('');
  if (data.notes && data.notes.length) html += `<div class="note-warn">${data.notes.map(escapeHtml).join(' ')}</div>`;
  return html;
}

$('matchForm').addEventListener('submit', e => {
  e.preventDefault();
  const out = $('result-match');
  if (!hasInput('matchFiles', 'matchText')) return showError(out, 'Choose files or paste a key, certificate or CSR.');
  const fd = new FormData();
  appendInputs(fd, 'matchFiles', 'files', 'matchText', 'text');
  appendIf(fd, 'password', $('matchPassword').value);
  postTool('/api/match', fd, out, renderMatch, e.submitter);
});

// ---------- CSR from an existing key ----------

function renderCsrCreated(data) {
  return `<div class="cert">
    <div class="cert-header">
      <div class="cert-title">Certificate signing request ${badge('info', data.algorithmLabel)}</div>
      <div class="pem-actions">
        <button type="button" class="btn small" data-action="decode-csr">Decode this CSR</button>
        <button type="button" class="btn small primary" data-action="sign-csr">Sign with my CA</button>
      </div>
    </div>
    ${section('Details', [
      row('Subject', escapeHtml(data.subject)),
      row('Subject alt names', chips(data.sans || []))
    ])}
    <div class="pem-list">${pemBlock('Certificate signing request', data.csrPem, 'request.csr', { kind: 'csr' })}</div>
  </div>`;
}

$('csrForm').addEventListener('submit', e => {
  e.preventDefault();
  const out = $('result-csr');
  if (!hasInput('csrKeyFiles', 'csrKeyText')) return showError(out, 'Provide the private key.');
  const fd = new FormData();
  appendInputs(fd, 'csrKeyFiles', 'key', 'csrKeyText', 'keyText');
  appendInputs(fd, 'csrCertFiles', 'cert', 'csrCertText', 'certText');
  appendIf(fd, 'keyPassword', $('csrKeyPassword').value);
  appendIf(fd, 'commonName', $('csrCommonName').value);
  appendIf(fd, 'sans', $('csrSans').value);
  appendIf(fd, 'hash', $('csrHash').value);
  appendIf(fd, 'organization', $('csrOrg').value);
  appendIf(fd, 'organizationalUnit', $('csrOu').value);
  appendIf(fd, 'country', $('csrCountry').value);
  appendIf(fd, 'state', $('csrState').value);
  appendIf(fd, 'locality', $('csrLocality').value);
  postTool('/api/csr/create', fd, out, renderCsrCreated, e.submitter);
});

// ---------- local CA ----------

function renderIssued(data, { title, usage, notice = '' }) {
  const actions = [];
  if (usage === 'ca') {
    actions.push('<button type="button" class="btn small primary" data-action="use-ca">Use to sign a CSR</button>');
    actions.push('<button type="button" class="btn small" data-action="intermediate-from-ca">Create an intermediate</button>');
  } else {
    actions.push('<button type="button" class="btn small primary" data-action="validate">Validate this certificate</button>');
  }
  const base = slug(data.subject);
  return `<div class="cert">
    <div class="cert-header">
      <div class="cert-title">${escapeHtml(title)} ${data.algorithmLabel ? badge('info', data.algorithmLabel) : ''}</div>
      <div class="pem-actions">${actions.join('')}</div>
    </div>
    ${notice ? `<div class="notice">${notice}</div>` : ''}
    ${toolWarnings(data.warnings)}
    ${section('Details', [
      row('Subject', `<span class="rdn"><b>CN</b> ${escapeHtml(data.subject)}</span>`),
      row('Issuer', escapeHtml(data.issuer) || '<span class="muted">Self-signed</span>'),
      row('Subject alt names', chips(data.sans || [])),
      row('Serial number', escapeHtml(data.serialNumber), { mono: true }),
      row('Valid from', escapeHtml(formatDate(data.notBefore))),
      row('Valid to', escapeHtml(formatDate(data.notAfter))),
      row('Path length', data.pathLength === null || data.pathLength === undefined ? '' : escapeHtml(String(data.pathLength))),
      row('Limited to', data.nameConstraints && data.nameConstraints.length ? chips(data.nameConstraints) : ''),
      row('SHA-256', escapeHtml(data.fingerprintSha256), { mono: true })
    ])}
    <div class="pem-list">
      ${pemBlock('Certificate', data.certificatePem, `${base}-cert.pem`, { kind: 'certificate' })}
      ${data.privateKeyPem ? pemBlock('Private key (PKCS#8)', data.privateKeyPem, `${base}-key.pem`, { secret: true, kind: 'private' }) : ''}
      ${data.chainPem ? pemBlock(data.fullchainPem ? 'CA chain' : 'Chain (this certificate + parent CAs)', data.chainPem, `${base}-chain.pem`, { kind: 'chain' }) : ''}
      ${data.fullchainPem ? pemBlock('Full chain (certificate + CA chain)', data.fullchainPem, `${base}-fullchain.pem`, { kind: 'fullchain' }) : ''}
    </div>
  </div>`;
}

$('caKind').addEventListener('change', () => {
  const intermediate = $('caKind').value === 'intermediate';
  $('caParent').hidden = !intermediate;
  $('caValidity').value = intermediate ? 1825 : 3650;
});

$('caCreateForm').addEventListener('submit', e => {
  e.preventDefault();
  const out = $('result-ca-create');
  const intermediate = $('caKind').value === 'intermediate';
  if (!$('caCommonName').value.trim()) return showError(out, 'Common name is required.');
  if (intermediate && !hasCa(CA_PICKERS.caParent)) return showError(out, 'Choose the parent CA, or provide its certificate and private key.');
  const fd = new FormData();
  if (intermediate) appendCa(fd, CA_PICKERS.caParent);
  appendIf(fd, 'commonName', $('caCommonName').value);
  appendIf(fd, 'algorithm', $('caAlgorithm').value);
  appendIf(fd, 'hash', $('caHash').value);
  appendIf(fd, 'validityDays', $('caValidity').value);
  appendIf(fd, 'pathLength', $('caPathLength').value);
  appendIf(fd, 'nameConstraints', $('caConstraints').value);
  appendIf(fd, 'organization', $('caOrg').value);
  appendIf(fd, 'organizationalUnit', $('caOu').value);
  appendIf(fd, 'country', $('caCountry').value);
  appendIf(fd, 'state', $('caState').value);
  appendIf(fd, 'locality', $('caLocality').value);
  const keep = $('caSave').value;
  postTool('/api/ca/create', fd, out, d => {
    if (keep !== 'none') keepNewCa(keep, d, out);
    return renderIssued(d, {
      title: d.kind === 'root' ? 'Root CA' : 'Intermediate CA', usage: 'ca',
      notice: keep === 'none' ? 'Not kept. Copy or download the private key now, it cannot be recovered later.' : '<span id="caKeepNotice">Saving...</span>'
    });
  }, e.submitter);
});

$('caSignForm').addEventListener('submit', e => {
  e.preventDefault();
  const out = $('result-ca-sign');
  if (!hasInput('signCsrFiles', 'signCsrText')) return showError(out, 'Provide the certificate signing request.');
  if (!hasCa(CA_PICKERS.sign)) return showError(out, 'Choose a CA, or provide the CA certificate and private key.');
  const fd = new FormData();
  appendInputs(fd, 'signCsrFiles', 'csr', 'signCsrText', 'csrText');
  appendCa(fd, CA_PICKERS.sign);
  appendIf(fd, 'usage', $('signUsage').value);
  appendIf(fd, 'validityDays', $('signValidity').value);
  appendIf(fd, 'sans', $('signSans').value);
  appendIf(fd, 'hash', $('signHash').value);
  appendIf(fd, 'crlUrl', $('signCrlUrl').value);
  fd.append('copySans', $('signCopySans').checked ? 'true' : 'false');
  postTool('/api/ca/sign', fd, out, d => renderIssued(d, { title: d.kind === 'intermediate' ? 'Signed intermediate CA' : 'Signed certificate', usage: d.kind === 'intermediate' ? 'ca' : 'leaf' }), e.submitter);
});

// ---------- convert ----------

const CONVERT_HINTS = {
  pem: 'Splits the input into certificate, chain and private key files. Set a password to encrypt the private key.',
  der: 'Writes each certificate (and the key, CSR or CRL) as a binary DER file.',
  p7b: 'Bundles the certificates into one PKCS#7 file. Private keys cannot be stored in P7B.',
  pfx: 'Add the private key and the certificate chain to the input. The PFX is encrypted with the password you choose.',
  jks: 'Add the private key and certificate chain to make a key entry, or just certificates for a trust store. The key password equals the keystore password.'
};

function syncConvertForm() {
  const format = $('convertFormat').value;
  const needsPassword = format === 'pfx' || format === 'jks';
  $('convertOutOptions').hidden = !(needsPassword || format === 'pem');
  $('convertOutPassword').placeholder = format === 'pem' ? 'Password to encrypt the private key (optional)' : 'Password for the output (required)';
  $('convertAlias').hidden = format === 'pem';
  $('convertLegacyRow').hidden = format !== 'pfx';
  $('convertHint').textContent = CONVERT_HINTS[format];
}
$('convertFormat').addEventListener('change', syncConvertForm);

function renderConverted(data) {
  const s = data.summary;
  const found = [];
  if (s.certificates) found.push(`${s.certificates} certificate${s.certificates === 1 ? '' : 's'}`);
  if (s.privateKey) found.push('a private key');
  if (s.csrs) found.push(`${s.csrs} CSR${s.csrs === 1 ? '' : 's'}`);
  if (s.crls) found.push(`${s.crls} CRL${s.crls === 1 ? '' : 's'}`);
  const match = s.keyMatchesLeaf === null ? '' : s.keyMatchesLeaf ? ` ${badge('good', 'Key matches the first certificate')}` : ` ${badge('bad', 'Key does not match the first certificate')}`;
  return `<div class="panel">
    <div class="panel-title">Found ${escapeHtml(found.join(', '))}${match}</div>
    ${s.chain.length ? `<div class="muted">Order: ${s.chain.map(escapeHtml).join(' &rarr; ')}</div>` : ''}
    ${s.keystoreAliases && s.keystoreAliases.length ? `<div class="muted">Keystore entries: ${escapeHtml(s.keystoreAliases.join(', '))}</div>` : ''}
  </div>${toolWarnings(data.warnings)}${renderFiles(data.files)}`;
}

$('convertForm').addEventListener('submit', e => {
  e.preventDefault();
  const out = $('result-convert');
  if (!hasInput('convertFiles', 'convertText')) return showError(out, 'Choose files or paste some text to convert.');
  const format = $('convertFormat').value;
  if ((format === 'pfx' || format === 'jks') && !$('convertOutPassword').value) return showError(out, 'Choose a password for the output file.');
  const fd = new FormData();
  appendInputs(fd, 'convertFiles', 'files', 'convertText', 'text');
  fd.append('format', format);
  appendIf(fd, 'password', $('convertPassword').value);
  appendIf(fd, 'outputPassword', $('convertOutPassword').value);
  appendIf(fd, 'alias', $('convertAlias').value);
  if (format === 'pfx' && $('convertLegacy').checked) fd.append('legacy', 'true');
  postTool('/api/convert', fd, out, renderConverted, e.submitter);
});
syncConvertForm();


// ---------- local development tools ----------

// A copyable block of text (commands or config). Reuses the key block look and its Copy button.
function codeBlock(title, code) {
  return `<div class="pem-block" data-kind="snippet">
    <div class="pem-head">
      <span><b>${escapeHtml(title)}</b></span>
      <span class="pem-actions"><button type="button" class="btn small" data-action="copy">Copy</button></span>
    </div>
    <pre>${escapeHtml(code)}</pre>
  </div>`;
}

// Names and networks a development CA is limited to when "Use local names" is pressed.
// Keep in sync with LOCAL_DNS and LOCAL_NETWORKS in lib/nameConstraints.js.
const LOCAL_CONSTRAINTS = 'localhost test example invalid local localdomain internal home.arpa lan 127.0.0.0/8 ::1/128 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 fc00::/7 fe80::/10';
$('caConstraintsLocal').addEventListener('click', () => { $('caConstraints').value = LOCAL_CONSTRAINTS; });

// ----- dev certificate -----

const DEV_SCOPE_HINTS = {
  local: 'The CA can only issue for reserved and private names (localhost, *.test, *.local, private IP ranges) plus the names above. If its key ever leaks, it cannot be used to impersonate real websites.',
  names: 'The CA can only issue for exactly the names above. The safest choice, but you cannot reuse the CA for other projects.',
  none: 'The CA has no restrictions. Anyone who gets its key could issue a certificate for any website that your devices would trust. Only use this if you will delete the CA afterwards.'
};

function syncDevCertForm() {
  const existing = $('devCaMode').value === 'existing';
  $('devCaNew').hidden = existing;
  $('devCaExisting').hidden = !existing;
  $('devScopeHint').textContent = DEV_SCOPE_HINTS[$('devScope').value] || '';
}
$('devCaMode').addEventListener('change', syncDevCertForm);
$('devScope').addEventListener('change', syncDevCertForm);
syncDevCertForm();

function trustGuide(password) {
  const steps = [
    ['macOS', 'sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt'],
    ['Windows (run as administrator)', 'certutil -addstore -f Root ca.cer'],
    ['Debian and Ubuntu', 'sudo cp ca.crt /usr/local/share/ca-certificates/dev-ca.crt\nsudo update-ca-certificates'],
    ['Fedora and RHEL', 'sudo cp ca.crt /etc/pki/ca-trust/source/anchors/\nsudo update-ca-trust'],
    ['Node.js', 'NODE_EXTRA_CA_CERTS=/path/to/ca.crt node app.js'],
    ['curl, git and Python', 'curl --cacert ca.crt https://localhost:8443/\ngit config --global http.sslCAInfo /path/to/ca.crt\nexport REQUESTS_CA_BUNDLE=/path/to/ca.crt'],
    ['Java', `java -Djavax.net.ssl.trustStore=truststore.jks -Djavax.net.ssl.trustStorePassword=${password} -jar app.jar`]
  ];
  return `<details class="guide" open>
    <summary>Trust the CA (once per machine)</summary>
    <p class="muted">Browsers and tools only accept the certificate once they trust the CA that signed it. Install <b>ca.crt</b> (or <b>ca.cer</b> on Windows).</p>
    ${steps.map(([title, code]) => codeBlock(title, code)).join('')}
    <p class="muted">Firefox keeps its own list: Settings, Privacy and Security, Certificates, View Certificates, Authorities, Import.</p>
  </details>`;
}

function serverGuide(base, password) {
  const key = `${base}-key.pem`;
  const chain = `${base}-fullchain.pem`;
  const snippets = [
    ['Node.js', ["const https = require('https');", "const fs = require('fs');", '', 'https.createServer({', `  key: fs.readFileSync('${key}'),`, `  cert: fs.readFileSync('${chain}')`, "}, (req, res) => res.end('ok')).listen(8443);"].join('\n')],
    ['Vite (vite.config.js)', ["import fs from 'fs';", '', 'export default {', '  server: {', '    https: {', `      key: fs.readFileSync('${key}'),`, `      cert: fs.readFileSync('${chain}')`, '    }', '  }', '};'].join('\n')],
    ['nginx', ['server {', '  listen 443 ssl;', `  ssl_certificate     ${chain};`, `  ssl_certificate_key ${key};`, '}'].join('\n')],
    ['Caddy', [`localhost:8443 {`, `  tls ${chain} ${key}`, '}'].join('\n')],
    ['Spring Boot (application.properties)', ['server.port=8443', `server.ssl.key-store=${base}.pfx`, 'server.ssl.key-store-type=PKCS12', `server.ssl.key-store-password=${password}`].join('\n')],
    ['Python (uvicorn)', `uvicorn app:app --port 8443 --ssl-keyfile ${key} --ssl-certfile ${chain}`],
    ['Go', `http.ListenAndServeTLS(":8443", "${chain}", "${key}", handler)`]
  ];
  return `<details class="guide">
    <summary>Use it in your server</summary>
    ${snippets.map(([title, code]) => codeBlock(title, code)).join('')}
  </details>`;
}

function renderDevCert(data) {
  const s = data.summary;
  const zip = data.files.find(f => f.name.endsWith('.zip'));
  const zipId = newId();
  binaryDownloads.set(zipId, zip);
  const ca = s.ca;
  const scopeText = ca.created
    ? (ca.nameConstraints ? '' : badge('warn', 'No name restrictions'))
    : '';
  return `<div class="cert">
    <div class="cert-header">
      <div class="cert-title">Dev certificate ${badge('info', s.algorithmLabel)}</div>
      <div class="pem-actions"><button type="button" class="btn primary" data-action="download-b64" data-id="${zipId}">Download everything (.zip)</button></div>
    </div>
    ${toolWarnings(data.warnings)}
    ${ca.created ? `<div class="notice">A new CA was created for this certificate. Its private key is in <b>ca-key.pem</b> and in the ZIP, and it is not kept anywhere else. Keep it if you want to issue more certificates from this CA.</div>` : ''}
    <div class="sections">
    ${section('Certificate', [
      row('Names', chips(s.names)),
      row('Valid from', escapeHtml(formatDate(s.notBefore))),
      row('Valid to', escapeHtml(formatDate(s.notAfter))),
      row('Used for', escapeHtml(s.clientAuth ? 'TLS server and TLS client' : 'TLS server')),
      row('Serial number', escapeHtml(s.serialNumber), { mono: true }),
      row('SHA-256', escapeHtml(s.fingerprintSha256), { mono: true }),
      row('CRL URL', s.crlUrl ? escapeHtml(s.crlUrl) : '')
    ])}
    ${section('Certificate authority', [
      row('CA', `${escapeHtml(ca.subject)} ${ca.created ? badge('good', 'New') : badge('info', 'Yours')} ${scopeText}`),
      row('Valid to', escapeHtml(formatDate(ca.notAfter))),
      row('Limited to', ca.nameConstraints ? chips(ca.nameConstraints) : ''),
      row('SHA-256', escapeHtml(ca.fingerprintSha256), { mono: true }),
      row('PFX / JKS password', `<span class="mono">${escapeHtml(s.bundlePassword)}</span>`)
    ])}
    </div>
  </div>
  <div class="cert">
    <div class="cert-title">How to use it</div>
    ${trustGuide(s.bundlePassword)}
    ${serverGuide(data.base, s.bundlePassword)}
  </div>
  <div class="section-title">Files</div>
  ${renderFiles(data.files.filter(f => f !== zip))}`;
}

$('devCertForm').addEventListener('submit', e => {
  e.preventDefault();
  const out = $('result-dev-cert');
  const existing = $('devCaMode').value === 'existing';
  if (existing && !hasCa(CA_PICKERS.devEx)) return showError(out, 'Choose a CA, or provide the CA certificate and private key.');
  const fd = new FormData();
  appendIf(fd, 'names', $('devNames').value);
  appendIf(fd, 'algorithm', $('devAlgorithm').value);
  appendIf(fd, 'validityDays', $('devValidity').value);
  appendIf(fd, 'bundlePassword', $('devBundlePassword').value);
  appendIf(fd, 'crlUrl', $('devCrlUrl').value);
  fd.append('clientAuth', $('devClientAuth').checked ? 'true' : 'false');
  if (existing) {
    appendCa(fd, CA_PICKERS.devEx);
  } else {
    appendIf(fd, 'caName', $('devCaName').value);
    appendIf(fd, 'scope', $('devScope').value);
  }
  postTool('/api/dev-cert', fd, out, renderDevCert, e.submitter);
});

// ----- revocation list -----

function crlGuide() {
  const blocks = [
    ['Look inside the list', 'openssl crl -in ca.crl -noout -text'],
    ['Check a certificate against it (OpenSSL)', 'cat ca.crt ca.crl > check.pem\nopenssl verify -crl_check -CAfile check.pem your-certificate.pem'],
    ['curl', 'curl --cacert ca.crt --crlfile ca.crl https://localhost:8443/'],
    ['Java', 'java -Dcom.sun.net.ssl.checkRevocation=true -Dcom.sun.security.enableCRLDP=true -jar app.jar']
  ];
  return `<div class="cert">
    <div class="cert-title">Try it</div>
    <p class="muted">Publish <b>ca.crl.der</b> at the CRL URL named in your certificates (see Dev Certificate, More options). Clients re-fetch it after the next update time, so make a new list before then.</p>
    ${blocks.map(([title, code]) => codeBlock(title, code)).join('')}
  </div>`;
}

function renderCrl(data) {
  const s = data.summary;
  const rows = s.entries.map(e => `<tr><td class="mono">${escapeHtml(e.serialNumber)}</td><td>${escapeHtml(formatDate(e.revocationDate))}</td><td>${escapeHtml(e.reason)}</td><td>${e.carried ? '<span class="muted">Kept</span>' : badge('good', 'Added')}</td></tr>`).join('');
  return `<div class="cert">
    <div class="cert-header">
      <div class="cert-title">Certificate revocation list ${badge('info', `CRL #${s.crlNumber}`)}</div>
      <div class="cert-status ok">&#10003; Signed</div>
    </div>
    ${toolWarnings(data.warnings)}
    <div class="sections">
    ${section('List', [
      row('Issuer', escapeHtml(s.issuer)),
      row('This update', escapeHtml(formatDate(s.thisUpdate))),
      row('Next update', `${escapeHtml(formatDate(s.nextUpdate))} <span class="muted">(in ${escapeHtml(String(s.nextUpdateDays))} days)</span>`)
    ])}
    ${section('Contents', [
      row('Revoked certificates', escapeHtml(String(s.entries.length))),
      row('Added now', escapeHtml(String(s.added))),
      row('Kept from the previous CRL', s.carriedOver ? escapeHtml(String(s.carriedOver)) : ''),
      row('Certificates revoked by file', s.revokedCertificates.length ? chips(s.revokedCertificates) : '')
    ])}
    </div>
    ${rows ? `<div class="section"><div class="section-title">Revoked serial numbers</div>
      <div class="table-wrap"><table class="grid"><thead><tr><th>Serial</th><th>Revoked</th><th>Reason</th><th></th></tr></thead><tbody>${rows}</tbody></table></div></div>` : ''}
  </div>
  ${renderFiles(data.files)}
  ${crlGuide()}`;
}

$('crlForm').addEventListener('submit', e => {
  e.preventDefault();
  const out = $('result-crl');
  if (!hasCa(CA_PICKERS.crl)) return showError(out, 'Choose a CA, or provide the CA certificate and private key.');
  if (!hasInput('crlCertFiles', 'crlCertText') && !$('crlSerials').value.trim() && !hasInput('crlPrevFiles', 'crlPrevText')) {
    if (!window.confirm('Nothing is selected for revocation, so the list will be empty. Create it anyway?')) return;
  }
  const fd = new FormData();
  appendCa(fd, CA_PICKERS.crl);
  appendInputs(fd, 'crlCertFiles', 'cert', 'crlCertText', 'certText');
  appendIf(fd, 'serials', $('crlSerials').value);
  appendIf(fd, 'reason', $('crlReason').value);
  appendIf(fd, 'nextUpdateDays', $('crlNextDays').value);
  appendInputs(fd, 'crlPrevFiles', 'previous', 'crlPrevText', 'previousText');
  postTool('/api/crl/create', fd, out, renderCrl, e.submitter);
});

// ----- key tools -----

const KEY_ACTIONS_WITH_PASSWORD = ['pkcs8', 'pkcs1', 'sec1'];

function syncKeyTools() {
  $('keyNewPasswordRow').hidden = !KEY_ACTIONS_WITH_PASSWORD.includes($('keyAction').value);
}
$('keyAction').addEventListener('change', syncKeyTools);
syncKeyTools();

function renderKeyTools(data) {
  const s = data.summary;
  const protection = s.result && s.result !== 'Public key'
    ? `${s.wasEncrypted ? 'Was protected' : 'Was not protected'}, result: ${s.resultEncrypted ? 'protected' : 'not protected'}`
    : (s.wasEncrypted ? 'Protected with a password' : 'Not protected');
  return `<div class="cert">
    <div class="cert-header">
      <div class="cert-title">Private key ${badge('info', s.keyDescription)} ${s.result ? badge('good', s.result) : ''}</div>
    </div>
    ${toolWarnings(data.warnings)}
    ${section('Key', [
      row('Type', escapeHtml(s.keyDescription)),
      row('Stored as', escapeHtml(s.sourceFormat)),
      row('Password', escapeHtml(protection)),
      row('Public key SHA-256', escapeHtml(s.fingerprintSha256), { mono: true }),
      row('SPKI pin (base64 SHA-256)', escapeHtml(s.spkiPinSha256), { mono: true })
    ])}
    <p class="muted">The fingerprint is of the public key, so it is the same whichever format or password the key is stored with, and it matches the certificate made for this key.</p>
  </div>
  ${renderFiles(data.files)}`;
}

$('keyToolsForm').addEventListener('submit', e => {
  e.preventDefault();
  const out = $('result-key-tools');
  if (!hasInput('keyFiles', 'keyText')) return showError(out, 'Provide a private key: choose a file or paste it.');
  const fd = new FormData();
  appendInputs(fd, 'keyFiles', 'files', 'keyText', 'text');
  appendIf(fd, 'password', $('keyPassword').value);
  appendIf(fd, 'action', $('keyAction').value);
  if (KEY_ACTIONS_WITH_PASSWORD.includes($('keyAction').value)) appendIf(fd, 'newPassword', $('keyNewPassword').value);
  postTool('/api/key-tools', fd, out, renderKeyTools, e.submitter);
});

// ---------- saved CAs (in this browser or on the server) ----------

// A CA can be kept in this browser (certificate and key in local storage, unencrypted) or on the server (the key is
// encrypted there and only its owner can use it). Either way it shows up in every CA picker.
const caStoreName = () => `certvalidator.cas.v1:${state.user.username}`;

function loadBrowserCas() {
  try {
    const cas = JSON.parse(localStorage.getItem(caStoreName()) || '{}');
    return cas && typeof cas === 'object' ? cas : {};
  } catch (e) {
    return {};
  }
}

function saveBrowserCas(cas) {
  try {
    localStorage.setItem(caStoreName(), JSON.stringify(cas));
    return true;
  } catch (e) {
    return false;
  }
}

let serverCas = [];
let casNotice = '';

const allCas = () => [
  ...serverCas.map(c => ({ ...c, where: 'server' })),
  ...Object.entries(loadBrowserCas()).map(([id, c]) => ({ ...c, id, where: 'browser' }))
].sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));

const findSavedCa = pick => allCas().find(c => `${c.where}:${c.id}` === pick);

// Every form that takes a CA: the picker, the manual upload fields it hides, and the field names the server expects.
const CA_PICKERS = {
  sign: { source: 'signCaSource', manual: 'signCaManual', hint: 'signCaHint', files: 'signCaFiles', text: 'signCaText', password: 'signCaPassword', fileField: 'ca', textField: 'caText', idField: 'caId', passwordField: 'caPassword' },
  crl: { source: 'crlCaSource', manual: 'crlCaManual', hint: 'crlCaHint', files: 'crlCaFiles', text: 'crlCaText', password: 'crlCaPassword', fileField: 'ca', textField: 'caText', idField: 'caId', passwordField: 'caPassword' },
  devEx: { source: 'devExCaSource', manual: 'devExCaManual', hint: 'devExCaHint', files: 'devCaFiles', text: 'devCaText', password: 'devCaPassword', fileField: 'ca', textField: 'caText', idField: 'caId', passwordField: 'caPassword' },
  caParent: { source: 'caParentCaSource', manual: 'caParentCaManual', hint: 'caParentCaHint', files: 'caParentFiles', text: 'caParentText', password: 'caParentPassword', fileField: 'issuer', textField: 'issuerText', idField: 'issuerId', passwordField: 'issuerPassword' },
  issue: { source: 'issueCaSource', manual: 'issueCaManual', hint: 'issueCaHint', files: 'issueCaFiles', text: 'issueCaText', password: 'issueCaPassword', fileField: 'ca', textField: 'caText', idField: 'caId', passwordField: 'caPassword' }
};

const CA_HINTS = {
  server: 'Saved on the server. Its key stays there, encrypted, and is only used to sign.',
  browser: 'Saved in this browser. Its key is sent to the server for this request only, held in memory and never stored.'
};

function syncCaPicker(p) {
  const value = $(p.source).value || '';
  $(p.manual).hidden = value !== '';
  $(p.hint).textContent = CA_HINTS[value.split(':')[0]] || '';
  $(p.hint).hidden = value === '';
}

function fillCaPickers() {
  const cas = allCas();
  const option = c => `<option value="${escapeHtml(`${c.where}:${c.id}`)}">${escapeHtml(c.name)}${new Date(c.notAfter) < new Date() ? ' (expired)' : ''}</option>`;
  const group = (label, where) => {
    const list = cas.filter(c => c.where === where);
    return list.length ? `<optgroup label="${label}">${list.map(option).join('')}</optgroup>` : '';
  };
  for (const p of Object.values(CA_PICKERS)) {
    const select = $(p.source);
    const previous = select.value;
    select.innerHTML = `<option value="">Upload or paste a CA...</option>${group('Saved on the server', 'server')}${group('Saved in this browser', 'browser')}`;
    const stillThere = cas.some(c => `${c.where}:${c.id}` === previous);
    // Pick the newest saved CA the first time, then leave the choice alone.
    select.value = stillThere ? previous : (p.touched || !cas.length ? '' : `${cas[0].where}:${cas[0].id}`);
    syncCaPicker(p);
  }
}

for (const p of Object.values(CA_PICKERS)) {
  $(p.source).addEventListener('change', () => {
    p.touched = true;
    syncCaPicker(p);
  });
}

// Has the user chosen a CA (saved, or uploaded / pasted)?
const hasCa = p => ($(p.source).value ? true : hasInput(p.files, p.text));

// Add the chosen CA to a request: its id for a server CA, its PEM for a browser CA, else the uploaded inputs.
function appendCa(fd, p) {
  const value = $(p.source).value || '';
  if (value.startsWith('server:')) {
    fd.append(p.idField, value.slice('server:'.length));
  } else if (value.startsWith('browser:')) {
    const ca = loadBrowserCas()[value.slice('browser:'.length)];
    if (ca) fd.append(p.textField, ca.certificatePem + (ca.chainPem || '') + ca.privateKeyPem);
  } else {
    appendInputs(fd, p.files, p.fileField, p.text, p.textField);
    appendIf(fd, p.passwordField, $(p.password).value);
  }
}

function updateCaCount() {
  const n = allCas().length;
  $('casCount').textContent = n;
  $('casCount').hidden = n === 0;
}

async function refreshCas() {
  try {
    const response = await api('/api/cas');
    const data = await response.json();
    if (response.ok) serverCas = data.cas || [];
  } catch (err) { /* keep what we have */ }
  updateCaCount();
  fillCaPickers();
  drawCas();
}

// Keep a CA. `fd` holds the CA inputs (files or text, and a password if needed). Resolves to the saved CA's name.
async function keepCa(where, fd, name) {
  if (where === 'server') {
    appendIf(fd, 'name', name);
    const response = await api('/api/cas', { method: 'POST', body: fd });
    const data = await response.json();
    if (!response.ok || data.error) throw new Error(data.error || 'The CA could not be saved.');
    await refreshCas();
    return data.ca.name;
  }
  const response = await api('/api/cas/check', { method: 'POST', body: fd });
  const ca = await response.json();
  if (!response.ok || ca.error) throw new Error(ca.error || 'The CA could not be read.');
  const cas = loadBrowserCas();
  const displayName = (name || '').trim() || ca.subject;
  cas[newId()] = { ...ca, name: displayName, createdAt: new Date().toISOString() };
  if (!saveBrowserCas(cas)) throw new Error('This browser would not store the CA (storage is unavailable or full).');
  await refreshCas();
  return displayName;
}

// After Create CA: keep the new CA where the user asked and say so next to the result.
function keepNewCa(where, data, out) {
  const fd = new FormData();
  fd.append('caText', data.certificatePem + (data.chainPem || '') + data.privateKeyPem);
  keepCa(where, fd, data.subject).then(name => {
    out.querySelector('#caKeepNotice').innerHTML = where === 'server'
      ? `Saved to <b>My CAs</b> as <b>${escapeHtml(name)}</b>. The key is kept on the server, encrypted, and only you can use it.`
      : `Saved to <b>My CAs</b> as <b>${escapeHtml(name)}</b>. The key is kept in this browser only, never on the server.`;
  }).catch(err => {
    out.querySelector('#caKeepNotice').textContent = `Could not keep this CA: ${err.message} Copy or download the private key now.`;
  });
}

function renderSavedCa(c) {
  const expired = new Date(c.notAfter) < new Date();
  const where = c.where === 'server' ? badge('info', 'On the server') : badge('warn', 'This browser');
  const pick = escapeHtml(`${c.where}:${c.id}`);
  const button = (action, label, extra = '') => `<button type="button" class="btn small${extra}" data-action="${action}" data-pick="${pick}">${label}</button>`;
  return `<div class="cert">
    <div class="cert-header">
      <div class="cert-title">${escapeHtml(c.name)} ${where} ${c.keyDescription ? badge('info', c.keyDescription) : ''} ${expired ? badge('bad', 'Expired') : ''}</div>
    </div>
    ${section('Details', [
      row('Subject', `<span class="rdn"><b>CN</b> ${escapeHtml(c.subject)}</span>`),
      row('Issuer', c.selfSigned ? '<span class="muted">Self-signed root</span>' : escapeHtml(c.issuer)),
      row('Valid from', escapeHtml(formatDate(c.notBefore))),
      row('Valid to', escapeHtml(formatDate(c.notAfter))),
      row('Path length', c.pathLength === null || c.pathLength === undefined ? '' : escapeHtml(String(c.pathLength))),
      row('Name restrictions', c.limited ? 'Yes, it can only issue for the names it is limited to' : ''),
      row('Key kept', c.where === 'server' ? 'On the server, encrypted (only you can use it)' : 'In this browser only (unencrypted)'),
      row('SHA-256', escapeHtml(c.fingerprintSha256), { mono: true })
    ])}
    <div class="pem-actions ca-actions">
      ${expired ? '' : button('ca-issue', 'Issue certificate', ' primary')}
      ${expired ? '' : button('ca-sign-with', 'Sign a CSR')}
      ${expired ? '' : button('ca-crl-with', 'Revoke / CRL')}
      ${button('ca-download-cert', 'Download certificate')}
      ${button('ca-download-key', 'Download key')}
      ${button('ca-rename', 'Rename')}
      ${button('ca-delete', 'Delete', ' danger')}
    </div>
  </div>`;
}

function drawCas() {
  const list = allCas();
  $('result-cas').innerHTML = (casNotice ? `<div class="notice">${casNotice}</div>` : '') +
    (list.length ? list.map(renderSavedCa).join('') : '<p class="muted">No saved CAs yet. Add one on the left, or tick "Keep this CA" when you create one.</p>');
}

function useSavedCa(pick, target) {
  const p = CA_PICKERS[target];
  fillCaPickers();
  p.touched = true;
  $(p.source).value = pick;
  syncCaPicker(p);
  showView(target === 'issue' ? 'issue' : target === 'sign' ? 'ca-sign' : 'crl');
}

async function downloadCaKey(pick) {
  const ca = findSavedCa(pick);
  if (!ca) return;
  let key = ca.privateKeyPem;
  if (ca.where === 'server') {
    try {
      const response = await api(`/api/cas/${encodeURIComponent(ca.id)}/key`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not load the key.');
      key = data.privateKeyPem;
    } catch (err) {
      casNotice = escapeHtml(err.message);
      return drawCas();
    }
  }
  saveBlob(new Blob([key], { type: 'application/x-pem-file' }), `${slug(ca.name)}-ca-key.pem`);
}

async function renameSavedCa(pick) {
  const ca = findSavedCa(pick);
  const name = ca && window.prompt('Rename', ca.name);
  if (!name || !name.trim()) return;
  if (ca.where === 'server') {
    if (await historyRequest('PATCH', `/api/cas/${encodeURIComponent(ca.id)}`, { name: name.trim() })) refreshCas();
  } else {
    const cas = loadBrowserCas();
    if (cas[ca.id]) cas[ca.id].name = name.trim().slice(0, 80);
    saveBrowserCas(cas);
    refreshCas();
  }
}

async function deleteSavedCa(pick) {
  const ca = findSavedCa(pick);
  if (!ca || !window.confirm(`Delete "${ca.name}"? Its private key is removed too and cannot be recovered unless you downloaded it.`)) return;
  if (ca.where === 'server') {
    if (!(await historyRequest('DELETE', `/api/cas/${encodeURIComponent(ca.id)}`))) return;
  } else {
    const cas = loadBrowserCas();
    delete cas[ca.id];
    saveBrowserCas(cas);
  }
  casNotice = '';
  refreshCas();
}

const WHERE_HINTS = {
  server: 'The key is stored encrypted on the server and only you can use it. It can sign for you from any browser. Anyone with access to the server and its VAULT_KEY or data folder could still decrypt it, so keep production CAs offline.',
  browser: 'The key stays in this browser only (unencrypted local storage) and is sent to the server just while it signs. It is lost if you clear site data, so download a copy.'
};
$('casWhere').addEventListener('change', () => { $('casWhereHint').textContent = WHERE_HINTS[$('casWhere').value] || ''; });
$('casWhereHint').textContent = WHERE_HINTS[$('casWhere').value] || '';
$('caSave').addEventListener('change', () => { $('caSaveHint').textContent = WHERE_HINTS[$('caSave').value] || 'Nothing is kept: the key is shown once and never stored.'; });
$('caSaveHint').textContent = WHERE_HINTS[$('caSave').value] || '';

$('casAddForm').addEventListener('submit', async e => {
  e.preventDefault();
  if (!hasInput('casFiles', 'casText')) {
    casNotice = 'Provide the CA certificate and its private key.';
    return drawCas();
  }
  const fd = new FormData();
  appendInputs(fd, 'casFiles', 'ca', 'casText', 'caText');
  appendIf(fd, 'caPassword', $('casPassword').value);
  const where = $('casWhere').value;
  const submit = e.submitter;
  if (submit) submit.disabled = true;
  try {
    const name = await keepCa(where, fd, $('casName').value);
    casNotice = `Saved <b>${escapeHtml(name)}</b> ${where === 'server' ? 'on the server' : 'in this browser'}. It is now available in the CA pickers.`;
    ['casFiles', 'casText', 'casPassword', 'casName'].forEach(id => { $(id).value = ''; });
  } catch (err) {
    casNotice = escapeHtml(err.message === 'Failed to fetch' ? 'Request failed. Is the server running?' : err.message);
  } finally {
    if (submit) submit.disabled = false;
  }
  drawCas();
});

// ---------- issue a certificate and key from a CA ----------

$('issueForm').addEventListener('submit', async e => {
  e.preventDefault();
  const out = $('result-issue');
  if (!hasCa(CA_PICKERS.issue)) return showError(out, 'Choose a CA, or provide the CA certificate and private key.');
  if (!$('issueCommonName').value.trim()) return showError(out, 'Common name is required.');
  const fd = new FormData();
  appendCa(fd, CA_PICKERS.issue);
  appendIf(fd, 'commonName', $('issueCommonName').value);
  appendIf(fd, 'sans', $('issueSans').value);
  appendIf(fd, 'algorithm', $('issueAlgorithm').value);
  appendIf(fd, 'validityDays', $('issueValidity').value);
  appendIf(fd, 'usage', $('issueUsage').value);
  appendIf(fd, 'hash', $('issueHash').value);
  appendIf(fd, 'crlUrl', $('issueCrlUrl').value);
  appendIf(fd, 'organization', $('issueOrg').value);
  appendIf(fd, 'organizationalUnit', $('issueOu').value);
  appendIf(fd, 'country', $('issueCountry').value);
  appendIf(fd, 'state', $('issueState').value);
  appendIf(fd, 'locality', $('issueLocality').value);

  const submit = e.submitter;
  if (submit) submit.disabled = true;
  out.textContent = 'Working...';
  try {
    const response = await api('/api/ca/issue', { method: 'POST', body: fd });
    const data = await response.json();
    if (!response.ok || data.error) return showError(out, data.error || 'The request failed.');
    const entry = { ...data, name: `${data.subject} (issued)`, isCA: false, createdAt: new Date().toISOString() };
    const notice = await saveToHistory(entry, data.privateKeyPem, $('issueSave').value);
    out.innerHTML = renderIssued(data, { title: 'Issued certificate', usage: 'leaf', notice });
  } catch (err) {
    showError(out, err.message === 'Failed to fetch' ? 'Request failed. Is the server running?' : err.message);
  } finally {
    if (submit) submit.disabled = false;
  }
});

// ---------- session ----------

$('signOutBtn').addEventListener('click', async () => {
  try {
    await fetch('/auth/logout', { method: 'POST', headers: { 'X-Requested-With': 'fetch' }, credentials: 'same-origin' });
  } finally {
    location.href = '/login.html';
  }
});

function showUser(user) {
  $('userChip').hidden = false;
  $('userAvatar').textContent = user.authDisabled ? 'L' : user.username.charAt(0);
  $('userName').textContent = user.authDisabled ? 'Local mode' : user.username;
  $('userRole').textContent = user.authDisabled ? 'No sign-in' : (user.role === 'admin' ? 'Admin' : 'User');
  $('signOutBtn').hidden = !!user.authDisabled;
}

// ---------- release notes ("What's new") ----------

const popover = $('releasePopover');
const versionBtn = $('versionBtn');
let notesHtml = null;
let closeTimer = null;
let pinned = false;   // opened by a click (or tap): stays open until dismissed

// Bullets may use **bold** and `code`. The text is escaped first, so notes can never inject HTML.
function inlineMarkup(text) {
  return escapeHtml(text)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>');
}

function sectionClass(title) {
  const key = String(title).toLowerCase().replace(/[^a-z]/g, '');
  return ['added', 'changed', 'fixed', 'removed', 'breaking', 'security'].includes(key) ? key : '';
}

function releaseSections(release) {
  return release.sections.map(s => `<div class="rn-section">
    <div class="rn-section-title ${sectionClass(s.title)}">${escapeHtml(s.title)}</div>
    <ul class="rn-list">${s.items.map(item => `<li>${inlineMarkup(item)}</li>`).join('')}</ul>
  </div>`).join('');
}

function renderReleaseNotes(data) {
  const releases = data.releases || [];
  if (!releases.length) return '<div class="rn-empty">No release notes yet.</div>';
  const current = releases.find(r => r.version === data.version) || releases[0];
  const older = releases.filter(r => r !== current);
  const title = current.version === data.version ? `What's new in v${current.version}` : `Latest release notes: v${current.version}`;
  return `<div class="rn-head"><div class="rn-title">${escapeHtml(title)}</div><div class="rn-date">${escapeHtml(current.date || '')}</div></div>
    <div class="rn-body">
      ${releaseSections(current)}
      ${older.length ? `<details class="rn-older"><summary>Earlier releases (${older.length})</summary>
        ${older.map(r => `<h4><span>v${escapeHtml(r.version)}</span><span class="rn-date">${escapeHtml(r.date || '')}</span></h4>${releaseSections(r)}`).join('')}
      </details>` : ''}
    </div>
    <div class="rn-foot">Files, pasted text and any keys you supply are processed in memory and discarded after each request. Private keys are never stored on the server.</div>`;
}

async function loadReleaseNotes() {
  if (notesHtml) return notesHtml;
  try {
    const response = await api('/api/release-notes');
    if (!response.ok) throw new Error('unavailable');
    notesHtml = renderReleaseNotes(await response.json());
    return notesHtml;
  } catch (err) {
    return '<div class="rn-empty">Release notes could not be loaded.</div>';
  }
}

async function openNotes() {
  clearTimeout(closeTimer);
  if (!popover.hidden) return;
  popover.hidden = false;
  versionBtn.setAttribute('aria-expanded', 'true');
  popover.innerHTML = '<div class="rn-empty">Loading...</div>';
  const html = await loadReleaseNotes();
  if (!popover.hidden) popover.innerHTML = html;
}

function closeNotes() {
  pinned = false;
  clearTimeout(closeTimer);
  popover.hidden = true;
  versionBtn.setAttribute('aria-expanded', 'false');
}

// A short delay lets the pointer travel from the version button to the popover.
function closeSoon() {
  if (pinned) return;
  clearTimeout(closeTimer);
  closeTimer = setTimeout(closeNotes, 250);
}

versionBtn.addEventListener('mouseenter', openNotes);
versionBtn.addEventListener('mouseleave', closeSoon);
popover.addEventListener('mouseenter', () => clearTimeout(closeTimer));
popover.addEventListener('mouseleave', closeSoon);
versionBtn.addEventListener('focus', openNotes);
versionBtn.addEventListener('blur', () => { if (!popover.matches(':hover')) closeSoon(); });
versionBtn.addEventListener('click', () => {
  if (pinned) return closeNotes();
  pinned = true;
  openNotes();
});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && !popover.hidden) closeNotes();
});
document.addEventListener('click', e => {
  if (!popover.hidden && !popover.contains(e.target) && !versionBtn.contains(e.target)) closeNotes();
});

// ---------- init ----------

fetch('/api/version')
  .then(r => r.json())
  .then(d => { $('version').textContent = `v${d.version}`; })
  .catch(() => {});

(async function init() {
  let status;
  try {
    status = await (await fetch('/auth/status', { credentials: 'same-origin' })).json();
  } catch (err) {
    return showError($('result-file'), 'Could not reach the server.');
  }
  if (!status.authenticated) {
    location.href = '/login.html';
    return;
  }
  state.user = status;
  showUser(status);
  loadAlgorithms();
  updateHistoryCount();
  refreshCas();
  showView(location.hash.slice(1) || 'file');
})();
