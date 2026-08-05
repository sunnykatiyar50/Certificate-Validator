// Tab switching logic
const fileTabBtn = document.getElementById('fileTabBtn');
const textTabBtn = document.getElementById('textTabBtn');
const fileTab = document.getElementById('fileTab');
const textTab = document.getElementById('textTab');

fileTabBtn.addEventListener('click', () => {
  fileTabBtn.classList.add('active');
  textTabBtn.classList.remove('active');
  fileTab.classList.add('active');
  textTab.classList.remove('active');
});
textTabBtn.addEventListener('click', () => {
  textTabBtn.classList.add('active');
  fileTabBtn.classList.remove('active');
  textTab.classList.add('active');
  fileTab.classList.remove('active');
});

// File form submission
const fileForm = document.getElementById('fileForm');
fileForm.addEventListener('submit', async function(e) {
  e.preventDefault();
  const resultDiv = document.getElementById('result');
  resultDiv.innerHTML = 'Validating...';
  const fileInput = document.getElementById('certificate');
  const password = document.getElementById('filePassword').value;
  if (!fileInput.files.length) {
    resultDiv.innerHTML = '<span class="icon red">&#10060;</span> Please select a certificate file.';
    return;
  }
  const formData = new FormData();
  formData.append('certificate', fileInput.files[0]);
  if (password) {
    formData.append('password', password);
  }
  try {
    const response = await fetch('/api/validate-certificate', {
      method: 'POST',
      body: formData
    });
    const data = await response.json();
    renderCertResults(data);
  } catch (err) {
    resultDiv.innerHTML = `<span class="icon red">&#10060;</span> Error validating certificate.`;
  }
});

// Text form submission
const textForm = document.getElementById('textForm');
textForm.addEventListener('submit', async function(e) {
  e.preventDefault();
  const resultDiv = document.getElementById('result');
  resultDiv.innerHTML = 'Validating...';
  const certText = document.getElementById('certText').value.trim();
  const password = document.getElementById('textPassword').value;
  if (!certText) {
    resultDiv.innerHTML = '<span class="icon red">&#10060;</span> Please paste certificate text.';
    return;
  }
  const formData = new FormData();
  formData.append('certText', certText);
  if (password) {
    formData.append('password', password);
  }
  try {
    const response = await fetch('/api/validate-certificate', {
      method: 'POST',
      body: formData
    });
    const data = await response.json();
    renderCertResults(data);
  } catch (err) {
    resultDiv.innerHTML = `<span class="icon red">&#10060;</span> Error validating certificate.`;
  }
});

// Clear buttons logic
const clearFileBtn = document.getElementById('clearFileBtn');
clearFileBtn.addEventListener('click', function() {
  document.getElementById('certificate').value = '';
  document.getElementById('filePassword').value = '';
  document.getElementById('result').innerHTML = '';
});
const clearTextBtn = document.getElementById('clearTextBtn');
clearTextBtn.addEventListener('click', function() {
  document.getElementById('certText').value = '';
  document.getElementById('textPassword').value = '';
  document.getElementById('result').innerHTML = '';
});

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

function renderCertResults(data) {
  const resultDiv = document.getElementById('result');
  if (data.error) {
    resultDiv.innerHTML = `<span class="icon red">&#10060;</span> <b>Error:</b> ${escapeHtml(data.error)}`;
    return;
  }
  let html = '';
  if (data.hasPrivateKey) {
    html += `<div style="color:#b26b00;margin-bottom:8px"><b>Note:</b> A private key was detected in the input. Private keys are ignored for validation.</div>`;
  }
  if (data.certs && data.certs.length > 0) {
    data.certs.forEach((cert, idx) => {
      const sans = (cert.sans || []).map(s => `${escapeHtml(s.type)}: ${escapeHtml(s.value)}`).join(', ');
      const keyUsage = (cert.keyUsage || []).map(escapeHtml).join(', ');
      const extKeyUsage = (cert.extKeyUsage || []).map(escapeHtml).join(', ');
      html += `<div style="margin-bottom:18px;padding-bottom:10px;border-bottom:1px solid #e0e4ea;">
        <div style="font-weight:600;margin-bottom:4px;">Certificate ${data.certs.length > 1 ? idx+1 : ''}</div>
        <div><span class="icon ${cert.valid ? 'green' : 'red'}">${cert.valid ? '&#9989;' : '&#10060;'}</span> <b>${cert.valid ? 'Valid' : 'Invalid'} Certificate</b></div>
        <div>Valid from: ${escapeHtml(cert.validFrom)}</div>
        <div>Valid to: ${escapeHtml(cert.validTo)}</div>
        <div>Subject: ${formatName(cert.subject)}</div>
        <div>Issuer: ${formatName(cert.issuer)}</div>
        <div>Version: ${escapeHtml(cert.version || 'Unknown')}</div>
        <div>Serial Number: ${escapeHtml(cert.serialNumber || 'Unknown')}</div>
        <div>Signature Algorithm: ${escapeHtml(cert.signatureAlgorithm || 'Unknown')}</div>
        <div>Public Key: ${escapeHtml(cert.publicKeyInfo || 'Unknown')}</div>
        <div>SHA-1 Fingerprint: ${escapeHtml(cert.fingerprintSha1 || 'Unknown')}</div>
        <div>SHA-256 Fingerprint: ${escapeHtml(cert.fingerprintSha256 || 'Unknown')}</div>
        ${sans ? `<div>Subject Alternative Names: ${sans}</div>` : ''}
        ${keyUsage ? `<div>Key Usage: ${keyUsage}</div>` : ''}
        ${extKeyUsage ? `<div>Extended Key Usage: ${extKeyUsage}</div>` : ''}
        ${cert.error ? `<div style='color:#ff4136'><b>Problem:</b> ${escapeHtml(cert.error)}</div>` : ''}
      </div>`;
    });
  } else {
    html += '<span class="icon red">&#10060;</span> No certificates found.';
  }
  resultDiv.innerHTML = html;
} 