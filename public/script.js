const $ = id => document.getElementById(id);

// ---------- helpers ----------

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

// ---------- navigation ----------

const navItems = document.querySelectorAll('.nav-item');
const views = document.querySelectorAll('.view');

function showView(name) {
  if (!$(`view-${name}`)) name = 'file';
  navItems.forEach(b => b.classList.toggle('active', b.dataset.view === name));
  views.forEach(v => v.classList.toggle('active', v.id === `view-${name}`));
  if (name === 'history') renderHistory();
  try { history.replaceState(null, '', `#${name}`); } catch (e) { /* hash is a convenience only */ }
}
navItems.forEach(b => b.addEventListener('click', () => showView(b.dataset.view)));

// ---------- validation forms ----------

async function submitAndRender(url, options, out) {
  out.textContent = 'Working...';
  try {
    const response = await fetch(url, options);
    renderCertResults(await response.json(), out);
  } catch (err) {
    showError(out, 'Request failed. Is the server running?');
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
  submitAndRender('/api/check-host', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ host, port: port || undefined })
  }, out);
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
    const { algorithms } = await (await fetch('/api/algorithms')).json();
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
function renderKeyPair(entry, { notice = '', historyId = null } = {}) {
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
        : '<div class="panel muted">The private key was not saved to history.</div>'}
      ${entry.publicKeyPem ? pemBlock('Public key (SPKI)', entry.publicKeyPem, `${base}-pub.pem`, { kind: 'public' }) : ''}
    </div>
  </div>`;
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
    const response = await fetch('/api/generate-keypair', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
    });
    const data = await response.json();
    if (!response.ok || data.error) return showError(out, data.error || 'Key generation failed.');

    const entry = {
      ...data,
      id: newId(),
      name: $('genName').value.trim() || `${commonName || 'keypair'} (${data.algorithmLabel})`,
      createdAt: new Date().toISOString()
    };
    let notice;
    const saveMode = $('genHistory').value;
    if (saveMode !== 'none') {
      const stored = { ...entry, privateKeyPem: saveMode === 'with' ? entry.privateKeyPem : null };
      notice = addToHistory(stored)
        ? `Saved to history as <b>${escapeHtml(entry.name)}</b>${saveMode === 'with' ? ' (including the private key)' : ' (without the private key)'}.`
        : 'Could not save to history: browser storage is unavailable or full.';
    } else {
      notice = 'Not saved. Copy or download the private key now, it cannot be recovered later.';
    }
    out.innerHTML = renderKeyPair(entry, { notice });
  } catch (err) {
    showError(out, 'Request failed. Is the server running?');
  } finally {
    submit.disabled = false;
  }
});

// ---------- history (browser localStorage) ----------

const HISTORY_KEY = 'certvalidator.history.v1';
let selectedHistoryId = null;

function newId() {
  return window.crypto && crypto.randomUUID ? crypto.randomUUID() : `${Date.now().toString(36)}${Math.random().toString(36).slice(2)}`;
}

function loadHistory() {
  try {
    const list = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
    return Array.isArray(list) ? list : [];
  } catch (e) {
    return [];
  }
}

function saveHistory(list) {
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(list));
    return true;
  } catch (e) {
    return false;
  }
}

function addToHistory(entry) {
  const list = loadHistory();
  list.unshift(entry);
  const ok = saveHistory(list);
  updateHistoryCount();
  return ok;
}

function updateHistoryCount() {
  const n = loadHistory().length;
  $('historyCount').textContent = n;
  $('historyCount').hidden = n === 0;
}

function renderHistory() {
  const list = loadHistory();
  $('clearHistoryBtn').hidden = list.length === 0;
  if (!list.some(e => e.id === selectedHistoryId)) selectedHistoryId = list.length ? list[0].id : null;

  $('historyList').innerHTML = list.length
    ? list.map(e => `<button type="button" class="history-item${e.id === selectedHistoryId ? ' selected' : ''}" data-action="select" data-id="${escapeHtml(e.id)}">
        <span class="history-name">${escapeHtml(e.name)}</span>
        <span class="history-meta">${escapeHtml(e.algorithmLabel)} &middot; ${escapeHtml(formatDate(e.createdAt))}</span>
        <span class="history-tags">${e.certificatePem ? badge('info', 'cert') : ''}${e.csrPem ? badge('info', 'csr') : ''}${e.privateKeyPem ? badge('warn', 'private key') : ''}</span>
      </button>`).join('')
    : '<p class="muted">Nothing here yet. Generated key pairs you choose to save will be listed here.</p>';

  const selected = list.find(e => e.id === selectedHistoryId);
  $('result-history').innerHTML = selected ? renderKeyPair(selected, { historyId: selected.id }) : '';
}

// ---------- click actions (copy, download, history, ...) ----------

function flash(btn, text) {
  const original = btn.textContent;
  btn.textContent = text;
  setTimeout(() => { btn.textContent = original; }, 1200);
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
    renderHistory();
  } else if (action === 'rename') {
    const list = loadHistory();
    const entry = list.find(x => x.id === id);
    const name = entry && window.prompt('Rename', entry.name);
    if (name && name.trim()) {
      entry.name = name.trim().slice(0, 80);
      saveHistory(list);
      renderHistory();
    }
  } else if (action === 'delete') {
    const list = loadHistory();
    const entry = list.find(x => x.id === id);
    if (entry && window.confirm(`Delete "${entry.name}" from history? This cannot be undone.`)) {
      saveHistory(list.filter(x => x.id !== id));
      updateHistoryCount();
      renderHistory();
    }
  } else if (action === 'clear-history') {
    if (window.confirm('Delete all saved key pairs from this browser? This cannot be undone.')) {
      saveHistory([]);
      selectedHistoryId = null;
      updateHistoryCount();
      renderHistory();
    }
  }
});

// ---------- init ----------

fetch('/api/version')
  .then(r => r.json())
  .then(d => { $('version').textContent = `v${d.version}`; })
  .catch(() => {});

loadAlgorithms();
updateHistoryCount();
showView(location.hash.slice(1) || 'file');
