// A small local certificate authority: create root and intermediate CAs, and sign CSRs with them.
// Also creates CSRs from an existing private key. Nothing is stored; keys exist only for the request.
const crypto = require('crypto');
const x509 = require('@peculiar/x509');
const { extractBundle } = require('./bundle');
const { ALGORITHMS, HASHES, HOSTNAME_RE, helpers } = require('./keygen');
const { KeyError, spkiOf, toSigningKeys, describeKey, pem, sha256Hex, colonHex } = require('./keys');

x509.cryptoProvider.set(crypto.webcrypto);
const { webcrypto } = crypto;
const { clean, parseSans, buildName } = helpers;

const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_CA_DAYS = 7300;
const MAX_LEAF_DAYS = 3650;
const TLS_MAX_DAYS = 398;
const USAGES = ['server', 'client', 'both', 'ca'];

class CaError extends Error {}

const randomSerial = () => crypto.randomBytes(16).toString('hex').replace(/^([89a-f])/i, '7'); // positive, non-zero

function toCaError(err) {
  return err instanceof KeyError ? new CaError(err.message) : err;
}

function fields(options) {
  const country = clean(options.country, 2, 'Country').toUpperCase();
  if (country && !/^[A-Z]{2}$/.test(country)) throw new CaError('Country must be a two-letter code, e.g. US.');
  return {
    commonName: clean(options.commonName, 64, 'Common name'),
    organization: clean(options.organization, 64, 'Organization'),
    organizationalUnit: clean(options.organizationalUnit, 64, 'Organizational unit'),
    locality: clean(options.locality, 64, 'Locality'),
    state: clean(options.state, 64, 'State'),
    country
  };
}

function hashOption(value) {
  const hash = value || 'SHA-256';
  if (!HASHES.includes(hash)) throw new CaError(`Unsupported hash. Choose one of: ${HASHES.join(', ')}.`);
  return hash;
}

function days(value, fallback, max, label) {
  const n = value === undefined || value === '' || value === null ? fallback : Number(value);
  if (!Number.isInteger(n) || n < 1 || n > max) throw new CaError(`${label} must be between 1 and ${max} days.`);
  return n;
}

function pathLengthOption(value) {
  if (value === undefined || value === null || value === '') return undefined;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0 || n > 10) throw new CaError('Path length must be a whole number from 0 to 10.');
  return n;
}

function certPem(cert) {
  return pem('CERTIFICATE', cert.rawData);
}

const fingerprint = cert => colonHex(sha256Hex(Buffer.from(cert.rawData)));

// Find the CA certificate and private key in the supplied inputs and check that they can issue certificates.
async function loadIssuer(inputs, password, hash) {
  let bundle;
  try {
    bundle = extractBundle(inputs, { password });
  } catch (err) {
    throw new CaError(`CA input: ${err.message}`);
  }
  if (!bundle.privateKeys.length) throw new CaError('The CA private key was not found. Paste it together with the CA certificate, or upload a PFX/JKS file.');
  if (!bundle.certificates.length) throw new CaError('The CA certificate was not found.');

  const keyObject = bundle.privateKeys[0].keyObject;
  const keySpki = spkiOf(keyObject);
  const certs = bundle.certificates.map(der => new x509.X509Certificate(der));
  const index = certs.findIndex(c => Buffer.from(c.publicKey.rawData).equals(keySpki));
  if (index < 0) throw new CaError('The CA private key does not match any certificate you supplied.');

  const cert = certs[index];
  const constraints = cert.getExtension(x509.BasicConstraintsExtension);
  if (!constraints || !constraints.ca) throw new CaError('That certificate is not a CA (it has no basic constraint CA:TRUE), so it cannot sign certificates.');
  const usage = cert.getExtension(x509.KeyUsagesExtension);
  if (usage && !(usage.usages & x509.KeyUsageFlags.keyCertSign)) throw new CaError('The CA certificate\'s key usage does not allow signing certificates (keyCertSign is missing).');
  const now = new Date();
  if (now < cert.notBefore) throw new CaError('The CA certificate is not yet valid.');
  if (now > cert.notAfter) throw new CaError('The CA certificate has expired.');

  let signing;
  try {
    signing = await toSigningKeys(keyObject, hash);
  } catch (err) {
    throw toCaError(err);
  }
  return {
    cert,
    signingKey: signing.keys.privateKey,
    signingAlgorithm: signing.signingAlgorithm,
    pathLength: constraints.pathLength,
    chain: certs.filter((_, i) => i !== index)
  };
}

/**
 * Create a root CA (no issuer) or an intermediate CA signed by `issuerInputs` ({ name, buffer } list holding the
 * parent certificate and private key). Returns the new certificate and private key.
 */
async function createCa(options, { issuerInputs, issuerPassword } = {}) {
  const p = fields(options);
  if (!p.commonName) throw new CaError('Common name is required.');
  const algorithm = ALGORITHMS[options.algorithm || 'ECDSA-P256'];
  if (!algorithm) throw new CaError(`Unsupported algorithm. Choose one of: ${Object.keys(ALGORITHMS).join(', ')}.`);
  const hash = hashOption(options.hash);
  const issuer = issuerInputs && issuerInputs.length ? await loadIssuer(issuerInputs, issuerPassword, hash) : null;
  const warnings = [];

  let validityDays = days(options.validityDays, issuer ? 1825 : 3650, MAX_CA_DAYS, 'Validity');
  const notBefore = new Date(Date.now() - 60 * 1000);
  let notAfter = new Date(notBefore.getTime() + validityDays * DAY_MS);
  let pathLength = pathLengthOption(options.pathLength);

  if (issuer) {
    if (issuer.pathLength === 0) throw new CaError('The parent CA has a path length of 0, so it cannot issue another CA.');
    if (issuer.pathLength !== undefined && (pathLength === undefined || pathLength >= issuer.pathLength)) {
      pathLength = issuer.pathLength - 1;
      warnings.push(`Path length set to ${pathLength} to stay below the parent's limit of ${issuer.pathLength}.`);
    }
    if (notAfter > issuer.cert.notAfter) {
      notAfter = issuer.cert.notAfter;
      validityDays = Math.floor((notAfter - notBefore) / DAY_MS);
      warnings.push(`Validity shortened to ${validityDays} days so it does not outlive the parent CA.`);
    }
  }

  const keyGen = algorithm.rsa ? { ...algorithm.keyGen, hash } : algorithm.keyGen;
  const keys = await webcrypto.subtle.generateKey(keyGen, true, ['sign', 'verify']);
  const signingAlgorithm = issuer
    ? issuer.signingAlgorithm
    : algorithm.hashed ? { name: algorithm.sign, hash } : { name: algorithm.sign };

  const extensions = [
    new x509.BasicConstraintsExtension(true, pathLength, true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    await x509.SubjectKeyIdentifierExtension.create(keys.publicKey)
  ];
  if (issuer) extensions.push(await x509.AuthorityKeyIdentifierExtension.create(issuer.cert));

  const params = { serialNumber: randomSerial(), notBefore, notAfter, signingAlgorithm, extensions };
  const name = buildName(p);
  const cert = issuer
    ? await x509.X509CertificateGenerator.create({ ...params, subject: name, issuer: issuer.cert.subjectName, signingKey: issuer.signingKey, publicKey: keys.publicKey })
    : await x509.X509CertificateGenerator.createSelfSigned({ ...params, name, keys });

  const privateKeyPem = pem('PRIVATE KEY', await webcrypto.subtle.exportKey('pkcs8', keys.privateKey));
  const certificatePem = certPem(cert);
  const parentChain = issuer ? [issuer.cert, ...issuer.chain].map(certPem).join('') : '';
  return {
    kind: issuer ? 'intermediate' : 'root',
    algorithmLabel: algorithm.label,
    subject: p.commonName,
    issuer: issuer ? issuer.cert.subjectName.toString() : null,
    serialNumber: cert.serialNumber.toUpperCase(),
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    pathLength: pathLength === undefined ? null : pathLength,
    fingerprintSha256: fingerprint(cert),
    certificatePem,
    privateKeyPem,
    chainPem: issuer ? certificatePem + parentChain : null,
    warnings
  };
}

/**
 * Sign the first CSR found in `csrInputs` with the CA found in `caInputs` (certificate plus private key).
 * options: validityDays, hash, usage (server | client | both | ca), copySans (default true), sans, pathLength.
 */
async function signCsr(csrInputs, caInputs, { caPassword, ...options } = {}) {
  const usage = options.usage || 'server';
  if (!USAGES.includes(usage)) throw new CaError(`Usage must be one of: ${USAGES.join(', ')}.`);
  const hash = hashOption(options.hash);

  let csrBundle;
  try {
    csrBundle = extractBundle(csrInputs);
  } catch (err) {
    throw new CaError(`CSR: ${err.message}`);
  }
  if (!csrBundle.csrs.length) throw new CaError('No certificate signing request found. Paste a PEM "CERTIFICATE REQUEST" or upload a .csr file.');
  const csr = new x509.Pkcs10CertificateRequest(csrBundle.csrs[0]);
  if (!(await csr.verify())) throw new CaError('The CSR signature does not verify, so it was not signed.');

  const issuer = await loadIssuer(caInputs, caPassword, hash);
  const warnings = [];
  const isCa = usage === 'ca';

  const validityDays = days(options.validityDays, isCa ? 1825 : 90, isCa ? MAX_CA_DAYS : MAX_LEAF_DAYS, 'Validity');
  const notBefore = new Date(Date.now() - 60 * 1000);
  let notAfter = new Date(notBefore.getTime() + validityDays * DAY_MS);
  if (notAfter > issuer.cert.notAfter) {
    notAfter = issuer.cert.notAfter;
    warnings.push(`Validity shortened to ${Math.floor((notAfter - notBefore) / DAY_MS)} days so it does not outlive the CA certificate.`);
  }
  if (!isCa && (notAfter - notBefore) / DAY_MS > TLS_MAX_DAYS) {
    warnings.push(`Validity is over ${TLS_MAX_DAYS} days. Browsers reject publicly trusted TLS certificates that long; this is fine for a private CA but some clients may complain.`);
  }

  const keyObject = crypto.createPublicKey({ key: Buffer.from(csr.publicKey.rawData), format: 'der', type: 'spki' });
  const extensions = [];
  let pathLength;
  if (isCa) {
    pathLength = pathLengthOption(options.pathLength);
    if (issuer.pathLength === 0) throw new CaError('The signing CA has a path length of 0, so it cannot issue another CA.');
    if (issuer.pathLength !== undefined && (pathLength === undefined || pathLength >= issuer.pathLength)) {
      pathLength = issuer.pathLength - 1;
      warnings.push(`Path length set to ${pathLength} to stay below the signing CA's limit of ${issuer.pathLength}.`);
    }
    extensions.push(new x509.BasicConstraintsExtension(true, pathLength, true));
    extensions.push(new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true));
  } else {
    extensions.push(new x509.BasicConstraintsExtension(false, undefined, true));
    let keyUsage = x509.KeyUsageFlags.digitalSignature;
    if (keyObject.asymmetricKeyType === 'rsa') keyUsage |= x509.KeyUsageFlags.keyEncipherment;
    extensions.push(new x509.KeyUsagesExtension(keyUsage, true));
    const eku = [];
    if (usage === 'server' || usage === 'both') eku.push(x509.ExtendedKeyUsage.serverAuth);
    if (usage === 'client' || usage === 'both') eku.push(x509.ExtendedKeyUsage.clientAuth);
    extensions.push(new x509.ExtendedKeyUsageExtension(eku));
  }

  // Subject alternative names: those requested in the CSR (unless switched off) plus any added here.
  const sans = [];
  const addSan = s => { if (!sans.some(x => x.type === s.type && x.value === s.value)) sans.push(s); };
  const copySans = options.copySans === undefined ? true : options.copySans === true || options.copySans === 'true';
  const requested = csr.extensions.find(e => e instanceof x509.SubjectAlternativeNameExtension);
  if (copySans && requested) requested.names.items.forEach(n => addSan({ type: n.type, value: n.value }));
  parseSans(options.sans).forEach(addSan);
  const cn = (csr.subjectName.getField('CN') || [])[0];
  if (!isCa && !sans.length && cn && HOSTNAME_RE.test(cn)) {
    addSan({ type: 'dns', value: cn.toLowerCase() });
    warnings.push(`The CSR had no subject alternative names, so the common name ${cn} was added as one.`);
  }
  if (sans.length) extensions.push(new x509.SubjectAlternativeNameExtension(sans));
  else if (!isCa && usage !== 'client') warnings.push('This certificate has no subject alternative names; browsers and modern TLS clients will not accept it for a hostname.');

  extensions.push(await x509.SubjectKeyIdentifierExtension.create(csr.publicKey));
  extensions.push(await x509.AuthorityKeyIdentifierExtension.create(issuer.cert));

  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: randomSerial(),
    subject: csr.subjectName,
    issuer: issuer.cert.subjectName,
    notBefore,
    notAfter,
    signingAlgorithm: issuer.signingAlgorithm,
    signingKey: issuer.signingKey,
    publicKey: csr.publicKey,
    extensions
  });

  const certificatePem = certPem(cert);
  const caChainPem = [issuer.cert, ...issuer.chain].map(certPem).join('');
  return {
    kind: isCa ? 'intermediate' : usage,
    subject: cn || csr.subject,
    issuer: issuer.cert.subjectName.toString(),
    keyDescription: describeKey(keyObject),
    sans: sans.map(s => `${s.type.toUpperCase()}: ${s.value}`),
    serialNumber: cert.serialNumber.toUpperCase(),
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    pathLength: pathLength === undefined ? null : pathLength,
    fingerprintSha256: fingerprint(cert),
    certificatePem,
    chainPem: caChainPem,
    fullchainPem: certificatePem + caChainPem,
    warnings
  };
}

/**
 * Create a CSR for an existing private key (from `keyInputs`). Subject and SANs come from `options`; when
 * `certificateInputs` holds an existing certificate they are copied from it for any field left empty (handy for renewals).
 */
async function createCsr(keyInputs, { keyPassword, certificateInputs, ...options } = {}) {
  let bundle;
  try {
    bundle = extractBundle(keyInputs, { password: keyPassword });
  } catch (err) {
    throw new CaError(`Private key: ${err.message}`);
  }
  if (!bundle.privateKeys.length) throw new CaError('No private key found. Paste a PEM private key or upload a key, PFX or JKS file.');
  const hash = hashOption(options.hash);
  let signing;
  try {
    signing = await toSigningKeys(bundle.privateKeys[0].keyObject, hash);
  } catch (err) {
    throw toCaError(err);
  }

  const p = fields(options);
  let sans = parseSans(options.sans);
  let name = null;
  if (certificateInputs && certificateInputs.length) {
    let certs;
    try {
      certs = extractBundle(certificateInputs).certificates;
    } catch (err) {
      throw new CaError(`Certificate: ${err.message}`);
    }
    if (!certs.length) throw new CaError('No certificate found to copy the subject from.');
    const existing = new x509.X509Certificate(certs[0]);
    const hasSubjectInput = p.commonName || p.organization || p.organizationalUnit || p.locality || p.state || p.country;
    if (!hasSubjectInput) name = existing.subjectName;
    const ext = existing.getExtension(x509.SubjectAlternativeNameExtension);
    if (!sans.length && ext) sans = ext.names.items.map(n => ({ type: n.type, value: n.value }));
  }
  if (!name) {
    if (!p.commonName) throw new CaError('Common name is required (or supply a certificate to copy the subject from).');
    name = buildName(p);
    // Browsers ignore the CN, so mirror a hostname-like one into the SANs when none were given.
    if (!sans.length && HOSTNAME_RE.test(p.commonName)) sans = [{ type: 'dns', value: p.commonName.toLowerCase() }];
  }

  const extensions = sans.length ? [new x509.SubjectAlternativeNameExtension(sans)] : [];
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name, keys: signing.keys, signingAlgorithm: signing.signingAlgorithm, extensions
  });
  return {
    algorithmLabel: signing.description,
    subject: name.toString(),
    sans: sans.map(s => `${s.type.toUpperCase()}: ${s.value}`),
    csrPem: pem('CERTIFICATE REQUEST', csr.rawData)
  };
}

module.exports = { createCa, signCsr, createCsr, CaError };
