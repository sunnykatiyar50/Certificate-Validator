const fs = require('fs');
const path = require('path');

const DATA_FILE = path.join(__dirname, '..', 'trust-data', 'root-stores.json');

// Apple, Chrome and Microsoft membership comes from trust-data/root-stores.json (see scripts/update-trust-data.js).
// Mozilla is handled by analysis.js through the root store bundled with Node.js.
let cache;

function load() {
  if (cache === undefined) {
    try {
      const data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      const stores = Object.fromEntries(Object.entries(data.stores).map(([id, list]) => [id, new Set(list)]));
      cache = { asOf: data.generatedAt, stores };
    } catch (e) {
      cache = null; // the data file is optional; the other platforms are simply not reported
    }
  }
  return cache;
}

const normalize = fp => String(fp || '').replace(/[^0-9a-f]/gi, '').toUpperCase();

const LABELS = { apple: 'Apple', chrome: 'Chrome', microsoft: 'Microsoft' };

// Which of the extra root programs include the root with this SHA-256 fingerprint.
// Returns null when no data is available, otherwise { asOf, members: [{ id, name, included }] }.
function lookupRoot(fingerprint256) {
  const data = load();
  if (!data) return null;
  const fp = normalize(fingerprint256);
  return {
    asOf: data.asOf,
    members: Object.keys(LABELS).filter(id => data.stores[id]).map(id => ({ id, name: LABELS[id], included: data.stores[id].has(fp) }))
  };
}

function platformData() {
  const data = load();
  return data ? { asOf: data.asOf, ids: Object.keys(LABELS).filter(id => data.stores[id]) } : null;
}

module.exports = { lookupRoot, platformData, normalize, LABELS };
