const resultDiv = document.getElementById('result');

// Tab switching
const tabs = [
  { btn: 'fileTabBtn', panel: 'fileTab' },
  { btn: 'textTabBtn', panel: 'textTab' },
  { btn: 'liveTabBtn', panel: 'liveTab' }
].map(t => ({ btn: document.getElementById(t.btn), panel: document.getElementById(t.panel) }));

tabs.forEach(active => {
  active.btn.addEventListener('click', () => {
    tabs.forEach(t => {
      t.btn.classList.toggle('active', t === active);
      t.panel.classList.toggle('active', t === active);
    });
  });
});

function showError(message) {
  resultDiv.innerHTML = `<span class="icon red">&#10060;</span> ${escapeHtml(message)}`;
}

// POST to the API and render whatever comes back (errors included).
async function submitAndRender(url, options) {
  resultDiv.textContent = 'Validating...';
  try {
    const response = await fetch(url, options);
    renderCertResults(await response.json());
  } catch (err) {
    showError('Error validating certificate.');
  }
}

// File form
document.getElementById('fileForm').addEventListener('submit', e => {
  e.preventDefault();
  const fileInput = document.getElementById('certificate');
  if (!fileInput.files.length) return showError('Please select a certificate file.');
  const formData = new FormData();
  formData.append('certificate', fileInput.files[0]);
  const password = document.getElementById('filePassword').value;
  const hostname = document.getElementById('fileHostname').value.trim();
  if (password) formData.append('password', password);
  if (hostname) formData.append('hostname', hostname);
  submitAndRender('/api/validate-certificate', { method: 'POST', body: formData });
});

// Text form
document.getElementById('textForm').addEventListener('submit', e => {
  e.preventDefault();
  const certText = document.getElementById('certText').value.trim();
  if (!certText) return showError('Please paste certificate text.');
  const formData = new FormData();
  formData.append('certText', certText);
  const password = document.getElementById('textPassword').value;
  const hostname = document.getElementById('textHostname').value.trim();
  if (password) formData.append('password', password);
  if (hostname) formData.append('hostname', hostname);
  submitAndRender('/api/validate-certificate', { method: 'POST', body: formData });
});

// Live site form
document.getElementById('liveForm').addEventListener('submit', e => {
  e.preventDefault();
  let host = document.getElementById('liveHost').value.trim();
  let port = document.getElementById('livePort').value.trim();
  if (!host) return showError('Please enter a hostname.');
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
  });
});

// Clear buttons
function clearForm(ids) {
  ids.forEach(id => { document.getElementById(id).value = ''; });
  resultDiv.innerHTML = '';
}
document.getElementById('clearFileBtn').addEventListener('click', () => clearForm(['certificate', 'filePassword', 'fileHostname']));
document.getElementById('clearTextBtn').addEventListener('click', () => clearForm(['certText', 'textPassword', 'textHostname']));
document.getElementById('clearLiveBtn').addEventListener('click', () => clearForm(['liveHost', 'livePort']));

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatName(attrs) {
  if (!attrs || attrs.length === 0) return '';
  return attrs.map(a => `${escapeHtml(a.shortName)}=${escapeHtml(a.value)}`).join(', ');
}

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
  return body ? `<div class="section-title">${escapeHtml(title)}</div><dl class="details">${body}</dl>` : '';
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
  </div>`;
}

function renderCertResults(data) {
  if (data.error) {
    showError(`Error: ${data.error}`);
    return;
  }
  let html = '';
  if (data.hasPrivateKey) {
    html += '<div class="note-warn"><b>Note:</b> A private key was detected in the input. Private keys are ignored for validation.</div>';
  }
  if (data.certs && data.certs.length > 0) {
    html += renderLive(data.live) + renderHostname(data.hostnameCheck) + renderChain(data);
    html += data.certs.map((cert, idx) => renderCert(cert, idx, data.certs)).join('');
  } else {
    html += '<span class="icon red">&#10060;</span> No certificates found.';
  }
  resultDiv.innerHTML = html;
}

// Show the running version in the footer.
fetch('/api/version')
  .then(r => r.json())
  .then(d => { document.getElementById('version').textContent = `v${d.version}`; })
  .catch(() => {});
