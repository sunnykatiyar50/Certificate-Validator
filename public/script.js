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
  $(outId).innerHTML = '';
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
  </div>`;
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
  return `<div class="pem-block${secret ? ' secret' : ''}" data-kind="${kind}">
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
    let notice;
    const saveMode = $('genHistory').value;
    if (saveMode === 'none') {
      notice = 'Not saved. Copy or download the private key now, it cannot be recovered later.';
    } else {
      const saved = await api('/api/history', jsonRequest('POST', historyPayload(entry)));
      const result = await saved.json();
      if (!saved.ok) {
        notice = `Could not save to history: ${escapeHtml(result.error || 'unknown error')}. Copy or download the private key now.`;
      } else {
        notice = `Saved to history as <b>${escapeHtml(entry.name)}</b>. `;
        if (saveMode === 'with') {
          notice += saveLocalKey(result.entry.id, data.privateKeyPem)
            ? 'The private key is kept in this browser only, never on the server.'
            : 'The private key could not be kept (browser storage is unavailable), so copy or download it now.';
        } else {
          notice += 'The private key was not kept, so copy or download it now.';
        }
        updateHistoryCount();
      }
    }
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
        <span class="history-tags">${e.certificatePem ? badge('info', 'cert') : ''}${e.csrPem ? badge('info', 'csr') : ''}${e.owner === me && loadLocalKeys()[e.id] ? badge('warn', 'private key here') : ''}</span>
      </button>`).join('')
    : `<p class="muted">${historyEntries.length ? 'No items for this user.' : 'Nothing here yet. Generated key pairs you choose to save will be listed here.'}</p>`;

  const selected = list.find(e => e.id === selectedHistoryId);
  if (!selected) {
    $('result-history').innerHTML = '';
    return;
  }
  const mine = selected.owner === me;
  const privateKeyPem = mine ? loadLocalKeys()[selected.id] : undefined;
  $('result-history').innerHTML = renderKeyPair({ ...selected, privateKeyPem }, {
    historyId: selected.id,
    missingKeyMessage: mine
      ? 'The private key is not stored on the server, and it was not kept in this browser.'
      : 'Private keys are never stored on the server, so only the person who generated this can have it.'
  });
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
    const pem = btn.closest('.cert').querySelector('[data-kind="certificate"] pre').textContent;
    $('certText').value = pem;
    $('textHostname').value = '';
    showView('text');
    $('textForm').requestSubmit();
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
  showView(location.hash.slice(1) || 'file');
})();
