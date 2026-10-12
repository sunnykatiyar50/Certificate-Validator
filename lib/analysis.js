const crypto = require('crypto');
const net = require('net');
const tls = require('tls');
const { X509Certificate: PeculiarX509 } = require('@peculiar/x509');
const { lookupRoot } = require('./rootStores');
const { parseEmbeddedScts } = require('./sct');

const DAY_MS = 24 * 60 * 60 * 1000;
const EXPIRY_WARNING_DAYS = 30;
const MAX_TLS_VALIDITY_DAYS = 398;
const MIN_RSA_BITS = 2048;
const WEAK_HASHES = /^(sha-?1|md[245])$/i;

let trustStore = null;

// Lazily load Node's bundled Mozilla root store.
function getTrustStore() {
  if (!trustStore) {
    const roots = [];
    for (const pem of tls.rootCertificates) {
      try {
        roots.push(new crypto.X509Certificate(pem));
      } catch (e) {
        // skip roots Node cannot parse
      }
    }
    trustStore = { roots, fingerprints: new Set(roots.map(r => r.fingerprint256)) };
  }
  return trustStore;
}

function toNodeCert(der) {
  if (!der) return null;
  try {
    return new crypto.X509Certificate(der);
  } catch (e) {
    return null;
  }
}

function safeVerify(cert, issuer) {
  try {
    return cert.verify(issuer.publicKey);
  } catch (e) {
    return false;
  }
}

// Find who issued `cert` among `candidates`. Returns { index, signature } where signature is
// 'valid' (a candidate with a matching name also verifies the signature), 'invalid' (names match
// but the signature does not verify) or 'unverifiable' (no candidate has a matching name).
function findIssuer(cert, candidates, skipIndex) {
  let nameMatch = false;
  for (let j = 0; j < candidates.length; j++) {
    const cand = candidates[j];
    if (!cand || j === skipIndex || !cert.checkIssued(cand)) continue;
    nameMatch = true;
    if (safeVerify(cert, cand)) return { index: j, signature: 'valid' };
  }
  return { index: -1, signature: nameMatch ? 'invalid' : 'unverifiable' };
}

function commonName(cert) {
  const m = /^CN=(.*)$/m.exec(cert.subject);
  return m ? m[1] : cert.subject.replace(/\n/g, ', ');
}

// Same subject and issuer and a signature that verifies with its own key. checkIssued() is not used here
// because it rejects issuers without the keyCertSign usage, which self-signed leaf certificates lack.
function isSelfSigned(cert) {
  return cert.subject === cert.issuer && safeVerify(cert, cert);
}

function collectWarnings(cert, der, daysRemaining, selfSigned) {
  const warnings = [];
  const add = (level, message) => warnings.push({ level, message });
  const validFrom = new Date(cert.validFrom);
  const validTo = new Date(cert.validTo);

  if (daysRemaining >= 0 && daysRemaining <= EXPIRY_WARNING_DAYS) {
    add('warning', `Expires in ${daysRemaining} day${daysRemaining === 1 ? '' : 's'}.`);
  }

  const key = cert.publicKey;
  if (key.asymmetricKeyType === 'rsa') {
    const bits = key.asymmetricKeyDetails && key.asymmetricKeyDetails.modulusLength;
    if (bits && bits < MIN_RSA_BITS) add('danger', `Weak RSA key (${bits}-bit); ${MIN_RSA_BITS} bits or more is recommended.`);
  }

  try {
    const hash = new PeculiarX509(der).signatureAlgorithm.hash;
    if (hash && WEAK_HASHES.test(hash.name)) add('danger', `Weak signature hash (${hash.name}).`);
  } catch (e) {
    // signature algorithm unavailable; skip the check
  }

  if (selfSigned && !cert.ca) add('warning', 'Self-signed certificate that is not a CA.');

  const validityDays = Math.round((validTo - validFrom) / DAY_MS);
  if (!cert.ca && !selfSigned && validityDays > MAX_TLS_VALIDITY_DAYS) {
    add('info', `Validity period is ${validityDays} days; publicly trusted TLS certificates are limited to ${MAX_TLS_VALIDITY_DAYS}.`);
  }
  return warnings;
}

// Is the chain's anchor trusted by each root program? Mozilla comes from Node's bundled store, the others from
// trust-data/root-stores.json. The anchor is the self-signed root in the chain, or the store root that issued the last certificate.
function platformTrust(anchorFingerprint, allCurrent, anchoredInMozilla) {
  const status = included => !included ? 'not-trusted' : allCurrent ? 'trusted' : 'expired';
  const extra = anchorFingerprint ? lookupRoot(anchorFingerprint) : null;
  const platforms = [{ id: 'mozilla', name: 'Mozilla', status: anchorFingerprint ? status(anchoredInMozilla) : 'unknown' }];
  if (extra) {
    for (const m of extra.members) platforms.push({ id: m.id, name: m.name, status: status(m.included) });
  }
  return { asOf: extra ? extra.asOf : null, platforms };
}

// Browsers expect publicly trusted TLS certificates issued after this date to be logged in Certificate Transparency logs.
const CT_REQUIRED_FROM = new Date('2018-04-30T00:00:00Z');

function warnIfNoTransparency(leaf, leafInfo, chain) {
  if (!leaf || !leafInfo || !chain || chain.status !== 'trusted' || leaf.ca || leafInfo.selfSigned) return;
  if (leafInfo.scts.length || new Date(leaf.validFrom) < CT_REQUIRED_FROM) return;
  leafInfo.warnings.push({
    level: 'info',
    message: 'No embedded Certificate Transparency SCTs. Publicly trusted certificates are normally logged; the proof may instead be delivered in the TLS handshake or OCSP response, which is not checked here.'
  });
}

// Walk the chain from the leaf (index 0) and decide whether it ends at a trusted root.
function summarizeChain(nodeCerts, links, now) {
  const store = getTrustStore();
  const path = [];
  const seen = new Set();
  let i = 0;
  let end = null;

  while (i !== null && !seen.has(i)) {
    seen.add(i);
    path.push(i);
    const link = links[i];
    if (link.signature === 'invalid') {
      end = 'bad-signature';
      break;
    }
    if (link.source === 'chain') {
      i = link.index;
    } else {
      end = link.source; // 'self' | 'trust-store' | 'missing'
      i = null;
    }
  }
  if (end === null) end = 'loop';

  const lastCert = nodeCerts[path[path.length - 1]];
  const rootInStore = end === 'self' && store.fingerprints.has(lastCert.fingerprint256);
  const anchoredInStore = end === 'trust-store' || rootInStore;
  const allCurrent = path.every(idx => {
    const c = nodeCerts[idx];
    return now >= new Date(c.validFrom) && now <= new Date(c.validTo);
  });

  const lastLink = links[path[path.length - 1]];
  const anchorFingerprint = end === 'self' ? lastCert.fingerprint256 : end === 'trust-store' ? lastLink.rootFingerprint : null;

  let status, message;
  if (end === 'bad-signature') {
    status = 'broken';
    message = 'A certificate in the chain has an issuer with a matching name, but its signature does not verify.';
  } else if (anchoredInStore && allCurrent) {
    status = 'trusted';
    message = 'Chain is complete and ends at a root in the Mozilla CA store.';
  } else if (anchoredInStore) {
    status = 'expired';
    message = 'Chain reaches a trusted root, but a certificate in the chain is expired or not yet valid.';
  } else if (end === 'self') {
    status = 'untrusted-root';
    message = 'Chain ends at a self-signed root that is not in the Mozilla CA store.';
  } else if (end === 'missing') {
    status = 'incomplete';
    message = 'The issuer of the last certificate is not provided and is not a known root. Include the intermediate certificate(s).';
  } else {
    status = 'broken';
    message = 'The certificates form a loop.';
  }

  return {
    status,
    trusted: status === 'trusted',
    message,
    path,
    unusedCerts: nodeCerts.map((_, idx) => idx).filter(idx => !seen.has(idx)),
    trustStore: 'Mozilla CA store bundled with Node.js',
    ...(end === 'bad-signature' || end === 'loop' ? {} : { platformTrust: platformTrust(anchorFingerprint, allCurrent, anchoredInStore) })
  };
}

function checkHostname(leaf, hostname) {
  if (!leaf || !hostname) return null;
  let matched;
  try {
    matched = net.isIP(hostname) ? leaf.checkIP(hostname) : leaf.checkHost(hostname);
  } catch (e) {
    matched = undefined;
  }
  return { hostname, matches: matched !== undefined, matchedName: matched || null };
}

/**
 * Analyze a list of DER certificates (index 0 is treated as the leaf).
 * Returns per-cert extras (aligned with the input), a chain summary and an optional hostname check.
 */
function analyzeChain(ders, { hostname, now = new Date() } = {}) {
  const nodeCerts = ders.map(toNodeCert);
  const store = getTrustStore();

  const links = nodeCerts.map((cert, i) => {
    if (!cert) return { source: 'missing', index: -1, signature: 'unverifiable' };
    const inChain = findIssuer(cert, nodeCerts, i);
    if (inChain.index >= 0) return { source: 'chain', index: inChain.index, signature: 'valid' };
    if (isSelfSigned(cert)) return { source: 'self', index: i, signature: 'valid' };
    const inStore = findIssuer(cert, store.roots, -1);
    if (inStore.index >= 0) return { source: 'trust-store', index: -1, signature: 'valid', rootName: commonName(store.roots[inStore.index]), rootFingerprint: store.roots[inStore.index].fingerprint256 };
    return { source: 'missing', index: -1, signature: inChain.signature === 'invalid' || inStore.signature === 'invalid' ? 'invalid' : 'unverifiable' };
  });

  const certs = nodeCerts.map((cert, i) => {
    if (!cert) return { warnings: [] };
    const daysRemaining = Math.floor((new Date(cert.validTo) - now) / DAY_MS);
    const link = links[i];
    const selfSigned = link.source === 'self';
    return {
      isCA: cert.ca,
      selfSigned,
      daysRemaining,
      signatureCheck: link.signature,
      issuedBy: link.source === 'chain'
        ? { source: 'chain', index: link.index }
        : link.source === 'trust-store'
          ? { source: 'trust-store', name: link.rootName }
          : { source: link.source },
      scts: cert.ca ? [] : parseEmbeddedScts(ders[i]),
      warnings: collectWarnings(cert, ders[i], daysRemaining, selfSigned)
    };
  });

  const chain = nodeCerts.length && nodeCerts[0] ? summarizeChain(nodeCerts, links, now) : null;
  warnIfNoTransparency(nodeCerts[0], certs[0], chain);
  return { certs, chain, hostnameCheck: checkHostname(nodeCerts[0], hostname) };
}

module.exports = { analyzeChain };
