const crypto = require('crypto');
const net = require('net');
const x509 = require('@peculiar/x509');

const { webcrypto } = crypto;
x509.cryptoProvider.set(webcrypto);

const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_VALIDITY_DAYS = 3650;
const HASHES = ['SHA-256', 'SHA-384', 'SHA-512'];
const MAX_SANS = 50;
const HOSTNAME_RE = /^(\*\.)?(?=.{1,253}$)[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$/i;

// Algorithms offered to users. `hashed: false` means the signature algorithm has its own hash (Ed25519).
const ALGORITHMS = {
  'RSA-2048': { label: 'RSA 2048', keyGen: { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) }, sign: 'RSASSA-PKCS1-v1_5', rsa: true, hashed: true },
  'RSA-3072': { label: 'RSA 3072', keyGen: { name: 'RSASSA-PKCS1-v1_5', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]) }, sign: 'RSASSA-PKCS1-v1_5', rsa: true, hashed: true },
  'RSA-4096': { label: 'RSA 4096', keyGen: { name: 'RSASSA-PKCS1-v1_5', modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]) }, sign: 'RSASSA-PKCS1-v1_5', rsa: true, hashed: true },
  'ECDSA-P256': { label: 'ECDSA P-256', keyGen: { name: 'ECDSA', namedCurve: 'P-256' }, sign: 'ECDSA', hashed: true },
  'ECDSA-P384': { label: 'ECDSA P-384', keyGen: { name: 'ECDSA', namedCurve: 'P-384' }, sign: 'ECDSA', hashed: true },
  'ECDSA-P521': { label: 'ECDSA P-521', keyGen: { name: 'ECDSA', namedCurve: 'P-521' }, sign: 'ECDSA', hashed: true },
  'Ed25519': { label: 'Ed25519', keyGen: { name: 'Ed25519' }, sign: 'Ed25519', hashed: false }
};

class KeygenError extends Error {}

function pem(label, derBuffer) {
  const b64 = Buffer.from(derBuffer).toString('base64').match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`;
}

function clean(value, max, field) {
  const v = String(value === undefined || value === null ? '' : value).trim();
  if (v.length > max) throw new KeygenError(`${field} is too long (max ${max} characters).`);
  if (/[\u0000-\u001f]/.test(v)) throw new KeygenError(`${field} contains invalid characters.`);
  return v;
}

function parseSans(input) {
  const list = Array.isArray(input) ? input : String(input || '').split(/[\s,]+/);
  const sans = [];
  for (const raw of list) {
    const v = String(raw).trim();
    if (!v) continue;
    if (net.isIP(v)) sans.push({ type: 'ip', value: v });
    else if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) sans.push({ type: 'email', value: v });
    else if (/^https?:\/\/[^\s]+$/i.test(v)) sans.push({ type: 'url', value: v });
    else if (HOSTNAME_RE.test(v)) sans.push({ type: 'dns', value: v.toLowerCase() });
    else throw new KeygenError(`Invalid subject alternative name: ${v.slice(0, 60)}`);
  }
  if (sans.length > MAX_SANS) throw new KeygenError(`Too many subject alternative names (max ${MAX_SANS}).`);
  return sans;
}

function validate(options) {
  const algorithm = ALGORITHMS[options.algorithm];
  if (!algorithm) throw new KeygenError(`Unsupported algorithm. Choose one of: ${Object.keys(ALGORITHMS).join(', ')}.`);

  const hash = options.hash || 'SHA-256';
  if (!HASHES.includes(hash)) throw new KeygenError(`Unsupported hash. Choose one of: ${HASHES.join(', ')}.`);

  const output = options.output || 'certificate';
  if (!['certificate', 'csr', 'keys'].includes(output)) throw new KeygenError('Output must be "certificate", "csr" or "keys".');

  const commonName = clean(options.commonName, 64, 'Common name');
  if (output !== 'keys' && !commonName) throw new KeygenError('Common name is required.');

  const validityDays = options.validityDays === undefined || options.validityDays === '' ? 365 : Number(options.validityDays);
  if (!Number.isInteger(validityDays) || validityDays < 1 || validityDays > MAX_VALIDITY_DAYS) {
    throw new KeygenError(`Validity must be between 1 and ${MAX_VALIDITY_DAYS} days.`);
  }

  const country = clean(options.country, 2, 'Country').toUpperCase();
  if (country && !/^[A-Z]{2}$/.test(country)) throw new KeygenError('Country must be a two-letter code, e.g. US.');

  const sans = parseSans(options.sans);
  // Browsers ignore the CN, so mirror a hostname-like CN into the SANs when none were given.
  if (!sans.length && commonName && (HOSTNAME_RE.test(commonName) || net.isIP(commonName))) {
    sans.push(net.isIP(commonName) ? { type: 'ip', value: commonName } : { type: 'dns', value: commonName.toLowerCase() });
  }

  return {
    algorithm, algorithmId: options.algorithm, hash, output, commonName, validityDays, sans,
    organization: clean(options.organization, 64, 'Organization'),
    organizationalUnit: clean(options.organizationalUnit, 64, 'Organizational unit'),
    locality: clean(options.locality, 64, 'Locality'),
    state: clean(options.state, 64, 'State'),
    country,
    isCA: options.isCA === true || options.isCA === 'true'
  };
}

function buildName(p) {
  const parts = [];
  if (p.country) parts.push({ C: [p.country] });
  if (p.state) parts.push({ ST: [p.state] });
  if (p.locality) parts.push({ L: [p.locality] });
  if (p.organization) parts.push({ O: [p.organization] });
  if (p.organizationalUnit) parts.push({ OU: [p.organizationalUnit] });
  if (p.commonName) parts.push({ CN: [p.commonName] });
  return new x509.Name(parts);
}

async function buildExtensions(p, publicKey) {
  const extensions = [new x509.BasicConstraintsExtension(p.isCA, undefined, true)];
  if (p.isCA) {
    extensions.push(new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign | x509.KeyUsageFlags.digitalSignature, true));
  } else {
    let usages = x509.KeyUsageFlags.digitalSignature;
    if (p.algorithm.rsa) usages |= x509.KeyUsageFlags.keyEncipherment;
    extensions.push(new x509.KeyUsagesExtension(usages, true));
    extensions.push(new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth, x509.ExtendedKeyUsage.clientAuth]));
  }
  extensions.push(await x509.SubjectKeyIdentifierExtension.create(publicKey));
  if (p.sans.length) extensions.push(new x509.SubjectAlternativeNameExtension(p.sans));
  return extensions;
}

/**
 * Generate a key pair plus (depending on `output`) a self-signed certificate, a CSR, or just the keys.
 * Nothing is persisted; the caller receives everything in the return value.
 */
async function generateKeyPair(options) {
  const p = validate(options || {});
  // RSASSA keys are bound to a hash at generation time; ECDSA and Ed25519 keys are not.
  const keyGen = p.algorithm.rsa ? { ...p.algorithm.keyGen, hash: p.hash } : p.algorithm.keyGen;
  const keys = await webcrypto.subtle.generateKey(keyGen, true, ['sign', 'verify']);
  const signingAlgorithm = p.algorithm.hashed ? { name: p.algorithm.sign, hash: p.hash } : { name: p.algorithm.sign };

  const privateKeyPem = pem('PRIVATE KEY', await webcrypto.subtle.exportKey('pkcs8', keys.privateKey));
  const publicKeyPem = pem('PUBLIC KEY', await webcrypto.subtle.exportKey('spki', keys.publicKey));

  const result = {
    algorithm: p.algorithmId,
    algorithmLabel: p.algorithm.label,
    hash: p.algorithm.hashed ? p.hash : null,
    privateKeyPem,
    publicKeyPem,
    certificatePem: null,
    csrPem: null,
    fingerprintSha256: null,
    subject: p.commonName ? p.commonName : null,
    sans: p.sans.map(s => `${s.type.toUpperCase()}: ${s.value}`),
    notBefore: null,
    notAfter: null,
    isCA: p.isCA
  };

  if (p.output === 'certificate') {
    const notBefore = new Date(Date.now() - 60 * 1000); // small allowance for clock skew
    const notAfter = new Date(notBefore.getTime() + p.validityDays * DAY_MS);
    const cert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: crypto.randomBytes(16).toString('hex').replace(/^([89a-f])/i, '7'), // positive, non-zero
      name: buildName(p),
      notBefore,
      notAfter,
      signingAlgorithm,
      keys: keys,
      extensions: await buildExtensions(p, keys.publicKey)
    });
    result.certificatePem = pem('CERTIFICATE', cert.rawData);
    result.fingerprintSha256 = crypto.createHash('sha256').update(Buffer.from(cert.rawData)).digest('hex').toUpperCase().match(/.{2}/g).join(':');
    result.notBefore = notBefore.toISOString();
    result.notAfter = notAfter.toISOString();
  } else if (p.output === 'csr') {
    const extensions = p.sans.length ? [new x509.SubjectAlternativeNameExtension(p.sans)] : [];
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
      name: buildName(p), keys: keys, signingAlgorithm, extensions
    });
    result.csrPem = pem('CERTIFICATE REQUEST', csr.rawData);
  }
  return result;
}

function listAlgorithms() {
  return Object.entries(ALGORITHMS).map(([id, a]) => ({ id, label: a.label, hashed: a.hashed }));
}

module.exports = { generateKeyPair, listAlgorithms, KeygenError, MAX_VALIDITY_DAYS, HASHES, ALGORITHMS, HOSTNAME_RE, helpers: { pem, clean, parseSans, buildName } };
