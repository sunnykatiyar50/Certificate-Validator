// Decoders for certificate signing requests (CSRs), certificate revocation lists (CRLs) and certificate bundles
// (PKCS#7 / P7B, PFX, JKS, PEM bundles).
const crypto = require('crypto');
const x509 = require('@peculiar/x509');
const { extractBundle } = require('./bundle');
const { buildReport, wrapDer } = require('./certificate');
const { describeKey, sha256Hex, colonHex } = require('./keys');

x509.cryptoProvider.set(crypto.webcrypto);

const MAX_CRL_ENTRIES = 500;
const CRL_NUMBER_OID = '2.5.29.20';
const DELTA_CRL_OID = '2.5.29.27';

const REVOCATION_REASONS = {
  0: 'Unspecified', 1: 'Key compromise', 2: 'CA compromise', 3: 'Affiliation changed', 4: 'Superseded',
  5: 'Cessation of operation', 6: 'Certificate hold', 8: 'Remove from CRL', 9: 'Privilege withdrawn', 10: 'AA compromise'
};

const EXTENSION_NAMES = {
  '2.5.29.17': 'Subject Alternative Name', '2.5.29.15': 'Key Usage', '2.5.29.37': 'Extended Key Usage',
  '2.5.29.19': 'Basic Constraints', '2.5.29.14': 'Subject Key Identifier', '2.5.29.35': 'Authority Key Identifier',
  '1.3.6.1.5.5.7.1.1': 'Authority Information Access', '2.5.29.31': 'CRL Distribution Points',
  '2.5.29.32': 'Certificate Policies', '1.3.6.1.4.1.311.2.1.14': 'Microsoft CSR attributes',
  '1.3.6.1.4.1.311.20.2': 'Microsoft certificate template name', '1.3.6.1.5.5.7.1.24': 'TLS Feature (OCSP must-staple)'
};
const EKU_NAMES = {
  '1.3.6.1.5.5.7.3.1': 'TLS Web Server Authentication', '1.3.6.1.5.5.7.3.2': 'TLS Web Client Authentication',
  '1.3.6.1.5.5.7.3.3': 'Code Signing', '1.3.6.1.5.5.7.3.4': 'Email Protection', '1.3.6.1.5.5.7.3.8': 'Time Stamping',
  '1.3.6.1.5.5.7.3.9': 'OCSP Signing'
};
const KEY_USAGE_FLAGS = ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly'];
const WEAK_HASHES = /^(sha-?1|md[245])$/i;

// Name as [{ shortName, value }], the same shape the certificate report uses.
function nameParts(name) {
  return name.toJSON().flatMap(rdn => Object.entries(rdn).map(([shortName, value]) => ({
    shortName,
    value: Array.isArray(value) ? value.join(', ') : value
  })));
}

const isoOrNull = date => (date instanceof Date && !isNaN(date) ? date.toISOString() : null);

function signatureName(alg) {
  return alg && alg.hash ? `${alg.hash.name} with ${alg.name}` : (alg && alg.name) || null;
}

// Hex serials without leading zeros, so CRL entries and certificate serials compare equal.
const normalizeSerial = hex => (String(hex).toLowerCase().replace(/^0+(?=.)/, '') || '0');

// ---- CSR ----

async function decodeCsr(der) {
  const csr = new x509.Pkcs10CertificateRequest(der);
  const spki = Buffer.from(csr.publicKey.rawData);
  const keyObject = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
  const keyDescription = describeKey(keyObject);

  let signatureValid = false;
  try {
    signatureValid = await csr.verify();
  } catch (e) {
    signatureValid = false;
  }

  const requested = [];
  let sans = [];
  let keyUsage = [];
  let extKeyUsage = [];
  let basicConstraints = null;
  for (const ext of csr.extensions) {
    requested.push({ oid: ext.type, name: EXTENSION_NAMES[ext.type] || null, critical: !!ext.critical });
    if (ext instanceof x509.SubjectAlternativeNameExtension) {
      sans = ext.names.items.map(n => ({ type: n.type.toUpperCase(), value: n.value }));
    } else if (ext instanceof x509.KeyUsagesExtension) {
      keyUsage = KEY_USAGE_FLAGS.filter(f => ext.usages & x509.KeyUsageFlags[f]);
    } else if (ext instanceof x509.ExtendedKeyUsageExtension) {
      extKeyUsage = ext.usages.map(oid => EKU_NAMES[oid] || oid);
    } else if (ext instanceof x509.BasicConstraintsExtension) {
      basicConstraints = { ca: ext.ca, pathLength: ext.pathLength === undefined ? null : ext.pathLength };
    }
  }

  const hash = csr.signatureAlgorithm && csr.signatureAlgorithm.hash;
  const warnings = [];
  const add = (level, message) => warnings.push({ level, message });
  if (!signatureValid) add('danger', 'The CSR signature does not verify: the request was altered or not signed by the matching private key.');
  if (keyObject.asymmetricKeyType === 'rsa' && keyObject.asymmetricKeyDetails.modulusLength < 2048) {
    add('danger', `Weak RSA key (${keyObject.asymmetricKeyDetails.modulusLength}-bit); 2048 bits or more is recommended.`);
  }
  if (hash && WEAK_HASHES.test(hash.name)) add('danger', `Weak signature hash (${hash.name}).`);
  if (!sans.length) add('warning', 'No subject alternative names. Browsers ignore the common name, so most CAs will require SANs.');
  if (!csr.subjectName.toJSON().length) add('info', 'The subject is empty; the CA will have to supply a name or rely on the SANs.');

  return {
    type: 'csr',
    subject: nameParts(csr.subjectName),
    publicKey: keyDescription,
    keyId: colonHex(sha256Hex(spki)),
    signatureAlgorithm: signatureName(csr.signatureAlgorithm),
    signatureValid,
    sans,
    keyUsage,
    extKeyUsage,
    basicConstraints,
    requestedExtensions: requested,
    fingerprintSha256: colonHex(sha256Hex(der)),
    warnings
  };
}

// ---- CRL ----

// The CRL number is a DER INTEGER inside the extension value.
function readCrlNumber(ext) {
  if (!ext) return null;
  const v = Buffer.from(ext.value);
  if (v.length < 3 || v[0] !== 0x02) return null;
  const len = v[1];
  return v.length >= 2 + len && len > 0 ? BigInt('0x' + v.subarray(2, 2 + len).toString('hex')).toString() : null;
}

async function decodeCrl(der, issuerCandidates) {
  const crl = new x509.X509Crl(der);
  const now = new Date();
  const entries = crl.entries.map(e => ({
    serialNumber: colonHex(e.serialNumber.length % 2 ? '0' + e.serialNumber.toUpperCase() : e.serialNumber.toUpperCase()),
    serialKey: normalizeSerial(e.serialNumber),
    revocationDate: isoOrNull(e.revocationDate),
    reason: e.reason === undefined ? null : REVOCATION_REASONS[e.reason] || `Reason ${e.reason}`
  }));

  const issuerMatches = issuerCandidates.filter(c => c.subject === crl.issuer || c.subjectName.toString() === crl.issuer);
  let signature = 'unchecked';
  if (issuerMatches.length) {
    signature = 'invalid';
    for (const candidate of issuerMatches) {
      try {
        if (await crl.verify({ publicKey: candidate })) { signature = 'valid'; break; }
      } catch (e) {
        // try the next candidate
      }
    }
  }

  const expired = crl.nextUpdate ? crl.nextUpdate < now : null;
  const warnings = [];
  if (expired) warnings.push({ level: 'warning', message: 'This CRL is past its next-update time; clients will treat it as stale.' });
  if (signature === 'invalid') warnings.push({ level: 'danger', message: 'The CRL signature does not verify with the matching issuer certificate you supplied.' });

  return {
    type: 'crl',
    issuer: nameParts(crl.issuerName),
    thisUpdate: isoOrNull(crl.thisUpdate),
    nextUpdate: isoOrNull(crl.nextUpdate),
    expired,
    crlNumber: readCrlNumber(crl.extensions.find(e => e.type === CRL_NUMBER_OID)),
    delta: crl.extensions.some(e => e.type === DELTA_CRL_OID),
    signatureAlgorithm: signatureName(crl.signatureAlgorithm),
    signature,
    revokedCount: entries.length,
    entries: entries.slice(0, MAX_CRL_ENTRIES).map(({ serialKey, ...rest }) => rest),
    entriesTruncated: entries.length > MAX_CRL_ENTRIES,
    fingerprintSha256: colonHex(sha256Hex(der)),
    warnings,
    entryIndex: new Map(entries.map(e => [e.serialKey, e])),
    issuerName: crl.issuer
  };
}

// For each supplied certificate issued by this CRL's issuer, say whether its serial is on the list.
function crlStatusForCertificates(crl, certificateDers) {
  const rows = [];
  for (const der of certificateDers) {
    const cert = new crypto.X509Certificate(der);
    const issuedByCrlIssuer = new x509.X509Certificate(der).issuerName.toString() === crl.issuerName;
    if (!issuedByCrlIssuer) continue;
    const hit = crl.entryIndex.get(normalizeSerial(cert.serialNumber));
    const cn = /^CN=(.*)$/m.exec(cert.subject);
    rows.push({
      subject: cn ? cn[1] : cert.subject.replace(/\n/g, ', '),
      serialNumber: colonHex(cert.serialNumber.length % 2 ? '0' + cert.serialNumber : cert.serialNumber),
      revoked: !!hit,
      revocationDate: hit ? hit.revocationDate : null,
      reason: hit ? hit.reason : null
    });
  }
  return rows;
}

// ---- entry point ----

/**
 * Decode whatever the inputs ({ name, buffer } each) contain.
 * Returns { csrs, crls, certificates: report | null, privateKeys, publicKeys, notes }.
 * Private keys are only described (algorithm and size), never returned.
 */
async function decode(inputs, { password } = {}) {
  const bundle = extractBundle(inputs, { password });
  if (!bundle.csrs.length && !bundle.crls.length && !bundle.certificates.length && !bundle.privateKeys.length && !bundle.publicKeys.length) {
    throw new Error('Nothing recognisable was found in the input.');
  }
  const candidates = bundle.certificates.map(d => new x509.X509Certificate(d));
  const crls = [];
  for (const der of bundle.crls) {
    const crl = await decodeCrl(der, candidates);
    crl.certificateStatus = crlStatusForCertificates(crl, bundle.certificates);
    delete crl.entryIndex;
    delete crl.issuerName;
    crls.push(crl);
  }
  return {
    csrs: await Promise.all(bundle.csrs.map(decodeCsr)),
    crls,
    certificates: bundle.certificates.length ? buildReport(bundle.certificates.map(wrapDer)) : null,
    privateKeys: bundle.privateKeys.map(k => ({ description: describeKey(k.keyObject) })),
    publicKeys: bundle.publicKeys.length,
    keystoreAliases: bundle.keystoreAliases,
    notes: bundle.notes
  };
}

module.exports = { decode, decodeCsr, decodeCrl };
