const fs = require('fs');
const path = require('path');
const { X509Certificate } = require('@peculiar/x509');

const SCT_LIST_OID = '1.3.6.1.4.1.11129.2.4.2'; // RFC 6962 embedded SignedCertificateTimestampList
const HASH_ALGORITHMS = { 1: 'MD5', 2: 'SHA-1', 3: 'SHA-224', 4: 'SHA-256', 5: 'SHA-384', 6: 'SHA-512' };
const SIGNATURE_ALGORITHMS = { 1: 'RSA', 2: 'DSA', 3: 'ECDSA', 7: 'Ed25519' };

let logNames;
function knownLogs() {
  if (logNames === undefined) {
    try {
      logNames = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'trust-data', 'ct-logs.json'), 'utf8'));
    } catch (e) {
      logNames = null; // optional data file; logs are then shown by ID only
    }
  }
  return logNames;
}

// The extension value is a DER OCTET STRING that wraps the TLS-encoded list. Returns the inner bytes.
function unwrapOctetString(buf) {
  if (buf.length < 2 || buf[0] !== 0x04) return null;
  let len = buf[1];
  let offset = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 3 || buf.length < 2 + n) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[2 + i];
    offset = 2 + n;
  }
  return offset + len <= buf.length ? buf.subarray(offset, offset + len) : null;
}

// Parse the TLS-encoded SignedCertificateTimestampList (RFC 6962, section 3.3).
function parseSctList(buf) {
  if (buf.length < 2) return [];
  const total = buf.readUInt16BE(0);
  const scts = [];
  let pos = 2;
  const end = Math.min(buf.length, 2 + total);
  while (pos + 2 <= end) {
    const size = buf.readUInt16BE(pos);
    pos += 2;
    const sct = buf.subarray(pos, pos + size);
    pos += size;
    if (sct.length < 43 || pos > end) break; // version(1) + log id(32) + timestamp(8) + extensions length(2)
    const version = sct[0];
    const logId = sct.subarray(1, 33).toString('base64');
    const timestamp = new Date(Number(sct.readBigUInt64BE(33)));
    const extLen = sct.readUInt16BE(41);
    const sigAt = 43 + extLen;
    const hash = sct.length > sigAt + 1 ? HASH_ALGORITHMS[sct[sigAt]] : null;
    const signature = sct.length > sigAt + 1 ? SIGNATURE_ALGORITHMS[sct[sigAt + 1]] : null;
    const known = (knownLogs() || { logs: {} }).logs[logId];
    scts.push({
      version: version + 1,
      logId,
      logName: known ? known.name : null,
      logOperator: known ? known.operator : null,
      logState: known ? known.state : null,
      timestamp: isNaN(timestamp) ? null : timestamp.toISOString(),
      signatureAlgorithm: hash && signature ? `${hash} with ${signature}` : null
    });
  }
  return scts;
}

/**
 * Certificate Transparency SCTs embedded in a certificate (DER). Returns [] when there are none or the
 * certificate cannot be parsed. SCTs delivered through a TLS extension or OCSP stapling are not covered.
 */
function parseEmbeddedScts(der) {
  try {
    const cert = new X509Certificate(der);
    const ext = cert.extensions.find(e => e.type === SCT_LIST_OID);
    if (!ext) return [];
    const inner = unwrapOctetString(Buffer.from(ext.value));
    return inner ? parseSctList(inner) : [];
  } catch (e) {
    return [];
  }
}

module.exports = { parseEmbeddedScts, parseSctList, unwrapOctetString };
