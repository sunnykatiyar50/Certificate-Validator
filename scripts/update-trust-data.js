#!/usr/bin/env node
// Refresh trust-data/root-stores.json and trust-data/ct-logs.json.
//
// root-stores.json: SHA-256 fingerprints of the root certificates that the Apple, Chrome and
// Microsoft root programs currently include, taken from the CCADB (https://www.ccadb.org/).
// Mozilla is not listed here: it is read at runtime from the store bundled with Node.js.
// ct-logs.json: names of the Certificate Transparency logs in Google's public log list, keyed by log ID.
//
//   node scripts/update-trust-data.js
const fs = require('fs');
const path = require('path');

const ALL_RECORDS_URL = 'https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv4';
const MICROSOFT_URL = 'https://ccadb.my.salesforce-sites.com/microsoft/IncludedCACertificateReportForMSFTCSV';
const CT_LOG_LIST_URL = 'https://www.gstatic.com/ct/log_list/v3/log_list.json';
const DATA_DIR = path.join(__dirname, '..', 'trust-data');

// Minimal RFC 4180 parser (quoted fields, doubled quotes, newlines inside quotes).
function parseCsv(text) {
  const rows = [];
  let row = [], field = '', quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; } else quoted = false;
      } else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; }
    else if (c !== '\r') field += c;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  const [header, ...body] = rows;
  return body.filter(r => r.length === header.length).map(r => Object.fromEntries(header.map((h, i) => [h, r[i]])));
}

async function download(url) {
  const res = await fetch(url, { signal: AbortSignal.timeout(120000) });
  if (!res.ok) throw new Error(`${url} returned HTTP ${res.status}`);
  return parseCsv(await res.text());
}

const normalize = fp => String(fp || '').replace(/[^0-9a-f]/gi, '').toUpperCase();
const sorted = set => [...set].filter(fp => fp.length === 64).sort();

async function updateRootStores() {
  const [records, microsoft] = await Promise.all([download(ALL_RECORDS_URL), download(MICROSOFT_URL)]);
  const roots = records.filter(r => r['Certificate Record Type'] === 'Root Certificate');
  const included = column => new Set(roots.filter(r => r[column] === 'Included').map(r => normalize(r['SHA-256 Fingerprint'])));

  const stores = {
    apple: sorted(included('Apple Status')),
    // The Chrome Root Store is used for TLS server authentication only.
    chrome: sorted(included('Chrome Status')),
    // Microsoft trusts many roots for purposes other than TLS, so keep those with the Server Authentication EKU.
    microsoft: sorted(new Set(microsoft
      .filter(r => r['Microsoft Status'] === 'Included' && /Server Authentication/.test(r['Microsoft EKUs']))
      .map(r => normalize(r['SHA-256 Fingerprint']))))
  };
  for (const [name, list] of Object.entries(stores)) {
    if (list.length < 50) throw new Error(`Only ${list.length} ${name} roots found; the CCADB format may have changed. Not writing.`);
  }
  write('root-stores.json', {
    generatedAt: new Date().toISOString().slice(0, 10),
    source: 'CCADB (ccadb.org) root store membership',
    stores
  });
  console.log('Root stores: ' + Object.entries(stores).map(([k, v]) => `${k} ${v.length}`).join(', '));
}

async function updateCtLogs() {
  const res = await fetch(CT_LOG_LIST_URL, { signal: AbortSignal.timeout(60000) });
  if (!res.ok) throw new Error(`${CT_LOG_LIST_URL} returned HTTP ${res.status}`);
  const list = await res.json();
  const logs = {};
  for (const operator of list.operators || []) {
    for (const log of [...(operator.logs || []), ...(operator.tiled_logs || [])]) {
      if (!log.log_id) continue;
      logs[log.log_id] = { name: log.description, operator: operator.name, state: Object.keys(log.state || {})[0] || 'unknown' };
    }
  }
  if (Object.keys(logs).length < 20) throw new Error('Too few CT logs found; the log list format may have changed. Not writing.');
  write('ct-logs.json', { generatedAt: new Date().toISOString().slice(0, 10), source: CT_LOG_LIST_URL, logs });
  console.log(`CT logs: ${Object.keys(logs).length}`);
}

function write(name, data) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(path.join(DATA_DIR, name), JSON.stringify(data, null, 1) + '\n');
}

Promise.all([updateRootStores(), updateCtLogs()]).catch(err => {
  console.error(err.message);
  process.exit(1);
});
