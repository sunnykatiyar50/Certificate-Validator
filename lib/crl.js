// Create a certificate revocation list (CRL) from a local CA, to test how clients handle revoked certificates.
// Stateless: to add more revocations later, supply the previous CRL and its entries are carried over.
const crypto = require('crypto');
const forge = require('node-forge');
const x509 = require('@peculiar/x509');
const { extractBundle } = require('./bundle');
const { pem } = require('./keys');
const { verifyCrlSignature } = require('./crlVerify');
const { CaError, loadIssuer, hashOption, days, fingerprint, DAY_MS } = require('./ca');

x509.cryptoProvider.set(crypto.webcrypto);
const { asn1 } = forge;

const CRL_NUMBER_OID = '2.5.29.20';
const MAX_ENTRIES = 5000;
const MAX_NEXT_UPDATE_DAYS = 365;

class CrlError extends CaError {}

const REASONS = {
  unspecified: 0, keycompromise: 1, cacompromise: 2, affiliationchanged: 3, superseded: 4,
  cessationofoperation: 5, certificatehold: 6, privilegewithdrawn: 9, aacompromise: 10
};
const REASON_LABELS = {
  0: 'Unspecified', 1: 'Key compromise', 2: 'CA compromise', 3: 'Affiliation changed', 4: 'Superseded',
  5: 'Cessation of operation', 6: 'Certificate hold', 8: 'Remove from CRL', 9: 'Privilege withdrawn', 10: 'AA compromise'
};

const textFile = (name, content, note) => ({ name, mime: 'application/pkix-crl', note: note || null, encoding: 'text', content });
const binaryFile = (name, mime, content, note) => ({ name, mime, note: note || null, encoding: 'base64', content: Buffer.from(content).toString('base64') });

// "0x0A:0B" and "0a0b" are the same serial. Returns upper-case hex without leading zeros, or null if invalid.
function normalizeSerial(text) {
  const hex = String(text).trim().replace(/^0x/i, '').replace(/[:\s-]/g, '').toLowerCase();
  if (!/^[0-9a-f]+$/.test(hex) || hex.length > 80) return null;
  return hex.replace(/^0+(?=.)/, '').toUpperCase();
}

// A serial number is a positive ASN.1 INTEGER. When its first byte is 0x80 or more it needs a leading 00 byte,
// otherwise it would be read as a negative number and would not match the certificate's serial.
function derSerialHex(serial) {
  const hex = serial.length % 2 ? `0${serial}` : serial;
  return (parseInt(hex.slice(0, 2), 16) & 0x80 ? `00${hex}` : hex).toLowerCase();
}

function parseReason(token, fallback) {
  if (token === undefined || token === '') return fallback;
  if (/^\d+$/.test(token)) {
    const n = Number(token);
    if (REASON_LABELS[n] === undefined || n === 8) throw new CrlError(`Unknown revocation reason: ${token}`);
    return n;
  }
  const n = REASONS[String(token).toLowerCase().replace(/[^a-z]/g, '')];
  if (n === undefined) throw new CrlError(`Unknown revocation reason "${String(token).slice(0, 40)}". Use one of: ${Object.keys(REASONS).join(', ')}.`);
  return n;
}

/**
 * Parse lines such as "0A1B2C", "0A1B2C keyCompromise" or "0A1B2C, superseded, 2026-03-01". Separators are
 * whitespace, commas or semicolons; blank lines and lines starting with # are ignored.
 */
function parseSerialList(text, defaultReason, now) {
  const entries = [];
  for (const rawLine of String(text || '').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    // A single line may hold several serials separated by commas only when no reason or date follows; keep it simple:
    // each line is one entry: serial [reason] [date].
    const [serialToken, reasonToken, dateToken] = line.split(/[\s,;]+/);
    const serial = normalizeSerial(serialToken);
    if (!serial) throw new CrlError(`Not a valid serial number: ${serialToken.slice(0, 60)}`);
    let date = now;
    if (dateToken) {
      date = new Date(dateToken);
      if (Number.isNaN(date.getTime())) throw new CrlError(`Not a valid revocation date: ${dateToken.slice(0, 40)}`);
      if (date.getTime() > now.getTime() + 60 * 1000) throw new CrlError(`The revocation date ${dateToken} is in the future.`);
    }
    entries.push({ serial, reason: parseReason(reasonToken, defaultReason), date });
    if (entries.length > MAX_ENTRIES) throw new CrlError(`Too many entries (max ${MAX_ENTRIES}).`);
  }
  return entries;
}

function readCrlNumber(crl) {
  const ext = crl.extensions.find(e => e.type === CRL_NUMBER_OID);
  if (!ext) return null;
  try {
    const value = asn1.fromDer(Buffer.from(ext.value).toString('binary')).value;
    return BigInt('0x' + (Buffer.from(value, 'binary').toString('hex') || '0'));
  } catch (err) {
    return null;
  }
}

function crlNumberExtension(number) {
  const hex = number.toString(16);
  const bytes = Buffer.from(hex.length % 2 ? '0' + hex : hex, 'hex');
  const der = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, (bytes[0] & 0x80 ? Buffer.concat([Buffer.from([0]), bytes]) : bytes).toString('binary'));
  return new x509.Extension(CRL_NUMBER_OID, false, Buffer.from(asn1.toDer(der).getBytes(), 'binary'));
}

// The certificates being revoked must have been issued by this CA.
async function entriesFromCertificates(certInputs, issuer, defaultReason, now) {
  let bundle;
  try {
    bundle = extractBundle(certInputs);
  } catch (err) {
    throw new CrlError(`Certificates to revoke: ${err.message}`);
  }
  if (!bundle.certificates.length) throw new CrlError('No certificate was found in the certificates to revoke.');
  const issuerPublicKey = crypto.createPublicKey({ key: Buffer.from(issuer.cert.publicKey.rawData), format: 'der', type: 'spki' });
  const entries = [];
  const subjects = [];
  for (const der of bundle.certificates) {
    const cert = new x509.X509Certificate(der);
    const nodeCert = new crypto.X509Certificate(der);
    if (!nodeCert.verify(issuerPublicKey)) {
      throw new CrlError(`The certificate "${cert.subject}" was not issued by this CA, so it cannot be revoked here.`);
    }
    entries.push({ serial: normalizeSerial(cert.serialNumber), reason: defaultReason, date: now });
    subjects.push(cert.subject);
  }
  return { entries, subjects };
}

async function entriesFromPreviousCrl(crlInputs, issuer) {
  let bundle;
  try {
    bundle = extractBundle(crlInputs);
  } catch (err) {
    throw new CrlError(`Previous CRL: ${err.message}`);
  }
  if (!bundle.crls.length) throw new CrlError('No CRL was found in the previous CRL input.');
  const crl = new x509.X509Crl(bundle.crls[0]);
  let valid = false;
  try {
    const direct = verifyCrlSignature(Buffer.from(bundle.crls[0]), Buffer.from(issuer.cert.rawData));
    valid = direct === null ? await crl.verify({ publicKey: issuer.cert }) : direct;
  } catch (err) {
    valid = false;
  }
  if (!valid) throw new CrlError('The previous CRL was not signed by this CA, so its entries cannot be carried over.');
  return {
    number: readCrlNumber(crl),
    entries: crl.entries.map(e => ({
      serial: normalizeSerial(e.serialNumber),
      reason: typeof e.reason === 'number' ? e.reason : 0,
      date: e.revocationDate
    }))
  };
}

/**
 * Build a CRL signed by the CA found in `caInputs` (certificate + private key).
 * options: caPassword, serials (text), reason (default for new entries), certificateInputs (certs to revoke),
 *          previousCrlInputs, nextUpdateDays (default 30), hash.
 */
async function createCrl(caInputs, options = {}) {
  const hash = hashOption(options.hash);
  const issuer = await loadIssuer(caInputs, options.caPassword, hash);
  const usage = issuer.cert.getExtension(x509.KeyUsagesExtension);
  if (usage && !(usage.usages & x509.KeyUsageFlags.cRLSign)) throw new CrlError('The CA certificate\'s key usage does not allow signing CRLs (cRLSign is missing).');

  const now = new Date();
  const defaultReason = parseReason(options.reason, 0);
  const nextUpdateDays = days(options.nextUpdateDays, 30, MAX_NEXT_UPDATE_DAYS, 'Next update');
  const warnings = [];

  const previous = options.previousCrlInputs && options.previousCrlInputs.length ? await entriesFromPreviousCrl(options.previousCrlInputs, issuer) : null;
  const added = [];
  const fromText = parseSerialList(options.serials, defaultReason, now);
  added.push(...fromText);
  let revokedSubjects = [];
  if (options.certificateInputs && options.certificateInputs.length) {
    const fromCerts = await entriesFromCertificates(options.certificateInputs, issuer, defaultReason, now);
    added.push(...fromCerts.entries);
    revokedSubjects = fromCerts.subjects;
  }

  // Carried-over entries keep their original date and reason; a serial is listed once.
  const bySerial = new Map();
  for (const e of previous ? previous.entries : []) bySerial.set(e.serial, { ...e, carried: true });
  let duplicates = 0;
  for (const e of added) {
    if (bySerial.has(e.serial)) duplicates++;
    else bySerial.set(e.serial, { ...e, carried: false });
  }
  if (duplicates) warnings.push(`${duplicates} serial number${duplicates === 1 ? ' was' : 's were'} already revoked and ${duplicates === 1 ? 'was' : 'were'} not added again.`);
  const entries = [...bySerial.values()];
  if (entries.length > MAX_ENTRIES) throw new CrlError(`Too many entries (max ${MAX_ENTRIES}).`);
  if (!entries.length) warnings.push('This CRL lists no revoked certificates. That is valid: it tells clients that nothing from this CA is revoked.');

  const number = (previous && previous.number !== null ? previous.number : 0n) + 1n;
  const thisUpdate = new Date(now.getTime() - 60 * 1000);
  const nextUpdate = new Date(now.getTime() + nextUpdateDays * DAY_MS);

  const crl = await x509.X509CrlGenerator.create({
    issuer: issuer.cert.subjectName,
    thisUpdate,
    nextUpdate,
    entries: entries.map(e => ({
      serialNumber: derSerialHex(e.serial),
      revocationDate: e.date,
      reason: e.reason === 0 ? undefined : e.reason
    })),
    extensions: [await x509.AuthorityKeyIdentifierExtension.create(issuer.cert), crlNumberExtension(number)],
    signingKey: issuer.signingKey,
    signingAlgorithm: issuer.signingAlgorithm
  });

  const der = Buffer.from(crl.rawData);
  return {
    files: [
      textFile('ca.crl', pem('X509 CRL', der), 'The revocation list in PEM form.'),
      binaryFile('ca.crl.der', 'application/pkix-crl', der, 'The same list in binary DER form. This is what web servers usually publish at the CRL URL.')
    ],
    summary: {
      issuer: issuer.cert.subjectName.toString(),
      issuerFingerprintSha256: fingerprint(issuer.cert),
      crlNumber: number.toString(),
      thisUpdate: thisUpdate.toISOString(),
      nextUpdate: nextUpdate.toISOString(),
      nextUpdateDays,
      carriedOver: previous ? previous.entries.length : 0,
      added: entries.filter(e => !e.carried).length,
      revokedCertificates: revokedSubjects,
      entries: entries.map(e => ({
        serialNumber: e.serial,
        revocationDate: e.date.toISOString(),
        reason: REASON_LABELS[e.reason] || 'Unspecified',
        carried: e.carried
      }))
    },
    warnings
  };
}

module.exports = { createCrl, parseSerialList, normalizeSerial, CrlError, REASONS, REASON_LABELS };
