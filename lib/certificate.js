const path = require('path');
const crypto = require('crypto');
const { analyzeChain } = require('./analysis');
const forge = require('node-forge');
const {
  X509Certificate,
  SubjectAlternativeNameExtension,
  KeyUsagesExtension,
  KeyUsageFlags,
  ExtendedKeyUsageExtension
} = require('@peculiar/x509');

const EKU_OID_NAMES = {
  '1.3.6.1.5.5.7.3.1': 'TLS Web Server Authentication',
  '1.3.6.1.5.5.7.3.2': 'TLS Web Client Authentication',
  '1.3.6.1.5.5.7.3.3': 'Code Signing',
  '1.3.6.1.5.5.7.3.4': 'Email Protection',
  '1.3.6.1.5.5.7.3.8': 'Time Stamping',
  '1.3.6.1.5.5.7.3.9': 'OCSP Signing'
};

// Try to build a @peculiar/x509 certificate from raw DER bytes; null on failure.
function tryPeculiarFromDer(der) {
  try {
    return new X509Certificate(der);
  } catch (e) {
    return null;
  }
}

// Get the raw DER bytes of a node-forge certificate as a Buffer.
function derFromForgeCert(forgeCert) {
  try {
    return Buffer.from(forge.asn1.toDer(forge.pki.certificateToAsn1(forgeCert)).getBytes(), 'binary');
  } catch (e) {
    return null;
  }
}

// Wrap a node-forge certificate together with its @peculiar/x509 equivalent (when parseable).
function wrapForgeCert(forgeCert) {
  const der = derFromForgeCert(forgeCert);
  const peculiarCert = der ? tryPeculiarFromDer(der) : null;
  return { forge: forgeCert, peculiar: peculiarCert || undefined };
}

function getCertsAndKeysFromPem(pemText) {
  const certs = [];
  let hasPrivateKey = false;
  let hasUnknownBlock = false;
  const blocks = forge.pem.decode(pemText);
  for (const block of blocks) {
    const type = block.type.trim().toUpperCase();
    const bodyLen = block.body ? block.body.length : 0;
    if (type === 'CERTIFICATE' && bodyLen > 0) {
      // forge.pem.decode already base64-decodes the body into raw DER bytes (as a binary string).
      const der = Buffer.from(block.body, 'binary');
      const peculiarCert = tryPeculiarFromDer(der);
      let forgeCert = null;
      try {
        forgeCert = forge.pki.certificateFromPem(forge.pem.encode(block));
      } catch (e) {
        forgeCert = null;
      }
      if (peculiarCert || forgeCert) {
        certs.push({ peculiar: peculiarCert || undefined, forge: forgeCert || undefined });
      }
    } else if (type.includes('PRIVATE KEY')) {
      hasPrivateKey = true;
    } else {
      hasUnknownBlock = true;
    }
  }
  return { certs, hasPrivateKey, hasUnknownBlock };
}

function getCertsFromPfx(p12, password) {
  const certs = [];
  const bags = p12.getBags({ bagType: forge.pki.oids.certBag });
  for (const bag of bags[forge.pki.oids.certBag]) {
    if (bag.cert) certs.push(wrapForgeCert(bag.cert));
  }
  // Check for private key
  const keyBags = p12.getBags({ bagType: forge.pki.oids.keyBag });
  const hasPrivateKey = keyBags[forge.pki.oids.keyBag] && keyBags[forge.pki.oids.keyBag].length > 0;
  return { certs, hasPrivateKey };
}

function hexColon(hex) {
  if (!hex) return null;
  let h = hex.toLowerCase().replace(/[^0-9a-f]/g, '');
  if (h.length % 2 !== 0) h = '0' + h;
  return h.toUpperCase().match(/.{2}/g).join(':');
}

function getSerialNumber(certObj) {
  if (certObj.peculiar) return hexColon(certObj.peculiar.serialNumber);
  if (certObj.forge) return hexColon(certObj.forge.serialNumber);
  return null;
}

function getFingerprints(certObj) {
  const der = certObj.peculiar ? Buffer.from(certObj.peculiar.rawData) : (certObj.forge ? derFromForgeCert(certObj.forge) : null);
  if (!der) return { sha1: null, sha256: null };
  return {
    sha1: crypto.createHash('sha1').update(der).digest('hex').toUpperCase().match(/.{2}/g).join(':'),
    sha256: crypto.createHash('sha256').update(der).digest('hex').toUpperCase().match(/.{2}/g).join(':')
  };
}

function getVersion(certObj) {
  if (certObj.forge && typeof certObj.forge.version === 'number') {
    return `v${certObj.forge.version + 1}`;
  }
  if (certObj.peculiar) {
    const match = /^(v\d+)/.exec(certObj.peculiar.toTextObject().Data.Version || '');
    if (match) return match[1];
  }
  return null;
}

function getSignatureAlgorithm(certObj) {
  if (certObj.forge && certObj.forge.siginfo && certObj.forge.siginfo.algorithmOid) {
    const oid = certObj.forge.siginfo.algorithmOid;
    return forge.pki.oids[oid] || oid;
  }
  if (certObj.peculiar && certObj.peculiar.signatureAlgorithm) {
    const sa = certObj.peculiar.signatureAlgorithm;
    return sa.hash ? `${sa.hash.name} with ${sa.name}` : sa.name;
  }
  return null;
}

function getPublicKeyInfo(certObj) {
  if (certObj.peculiar && certObj.peculiar.publicKey && certObj.peculiar.publicKey.algorithm) {
    const alg = certObj.peculiar.publicKey.algorithm;
    if (alg.modulusLength) return `RSA (${alg.modulusLength}-bit)`;
    if (alg.namedCurve) return `${alg.name} (${alg.namedCurve})`;
    return alg.name || null;
  }
  if (certObj.forge && certObj.forge.publicKey && certObj.forge.publicKey.n) {
    return `RSA (${certObj.forge.publicKey.n.bitLength()}-bit)`;
  }
  return null;
}

function normalizeName(certObj, which) {
  if (certObj.forge) {
    const attrs = (which === 'subject' ? certObj.forge.subject : certObj.forge.issuer).attributes;
    return attrs.map(a => ({ shortName: a.shortName || a.name || a.type, value: a.value }));
  }
  if (certObj.peculiar) {
    const nameObj = which === 'subject' ? certObj.peculiar.subjectName : certObj.peculiar.issuerName;
    return nameObj.toJSON().flatMap(rdn => Object.entries(rdn).map(([shortName, value]) => ({
      shortName,
      value: Array.isArray(value) ? value.join(', ') : value
    })));
  }
  return [];
}

const FORGE_SAN_TYPE_NAMES = { 1: 'EMAIL', 2: 'DNS', 6: 'URI', 7: 'IP' };

function getSANs(certObj) {
  if (certObj.forge) {
    const ext = certObj.forge.getExtension('subjectAltName');
    if (ext && ext.altNames) {
      return ext.altNames.map(n => ({
        type: FORGE_SAN_TYPE_NAMES[n.type] || String(n.type),
        value: n.ip || n.value
      }));
    }
  }
  if (certObj.peculiar) {
    const ext = certObj.peculiar.getExtension(SubjectAlternativeNameExtension);
    if (ext) return ext.names.items.map(n => ({ type: n.type.toUpperCase(), value: n.value }));
  }
  return [];
}

const KEY_USAGE_FLAG_NAMES = ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly'];

function getKeyUsage(certObj) {
  if (certObj.forge) {
    const ext = certObj.forge.getExtension('keyUsage');
    if (ext) return KEY_USAGE_FLAG_NAMES.filter(f => ext[f]);
  }
  if (certObj.peculiar) {
    const ext = certObj.peculiar.getExtension(KeyUsagesExtension);
    if (ext) return KEY_USAGE_FLAG_NAMES.filter(f => ext.usages & KeyUsageFlags[f]);
  }
  return [];
}

const FORGE_EKU_FLAG_NAMES = { serverAuth: 'TLS Web Server Authentication', clientAuth: 'TLS Web Client Authentication', codeSigning: 'Code Signing', emailProtection: 'Email Protection', timeStamping: 'Time Stamping' };

function getExtKeyUsage(certObj) {
  if (certObj.forge) {
    const ext = certObj.forge.getExtension('extKeyUsage');
    if (ext) return Object.keys(FORGE_EKU_FLAG_NAMES).filter(f => ext[f]).map(f => FORGE_EKU_FLAG_NAMES[f]);
  }
  if (certObj.peculiar) {
    const ext = certObj.peculiar.getExtension(ExtendedKeyUsageExtension);
    if (ext) return ext.usages.map(oid => EKU_OID_NAMES[oid] || oid);
  }
  return [];
}

function certValidity(certObj) {
  if (!certObj.peculiar && !certObj.forge) {
    return { valid: false, error: 'Could not parse certificate.' };
  }
  const notBefore = certObj.peculiar ? certObj.peculiar.notBefore : certObj.forge.validity.notBefore;
  const notAfter = certObj.peculiar ? certObj.peculiar.notAfter : certObj.forge.validity.notAfter;
  let valid = false, error = null;
  const validFrom = new Date(notBefore).toLocaleString();
  const validTo = new Date(notAfter).toLocaleString();
  const now = new Date();
  if (now < notBefore) {
    error = 'Certificate is not yet valid.';
  } else if (now > notAfter) {
    error = 'Certificate has expired.';
  } else {
    valid = true;
  }
  const fingerprints = getFingerprints(certObj);
  return {
    valid,
    validFrom,
    validTo,
    error,
    subject: normalizeName(certObj, 'subject'),
    issuer: normalizeName(certObj, 'issuer'),
    serialNumber: getSerialNumber(certObj),
    version: getVersion(certObj),
    signatureAlgorithm: getSignatureAlgorithm(certObj),
    publicKeyInfo: getPublicKeyInfo(certObj),
    fingerprintSha1: fingerprints.sha1,
    fingerprintSha256: fingerprints.sha256,
    sans: getSANs(certObj),
    keyUsage: getKeyUsage(certObj),
    extKeyUsage: getExtKeyUsage(certObj)
  };
}

// DER bytes of a wrapped certificate (peculiar preferred, forge as fallback).
function derOf(certObj) {
  if (certObj.peculiar) return Buffer.from(certObj.peculiar.rawData);
  if (certObj.forge) return derFromForgeCert(certObj.forge);
  return null;
}

// Wrap raw DER bytes the same way PEM/PFX parsing does.
function wrapDer(der) {
  const peculiar = tryPeculiarFromDer(der);
  if (peculiar) return { peculiar };
  try {
    return { forge: forge.pki.certificateFromAsn1(forge.asn1.fromDer(der.toString('binary'))) };
  } catch (e) {
    return {};
  }
}

// Turn parsed certificates into the API report: per-cert details plus chain and hostname analysis.
function buildReport(certObjs, { hostname } = {}) {
  const ders = certObjs.map(derOf);
  const analysis = analyzeChain(ders, { hostname });
  const certs = certObjs.map((c, i) => ({ ...certValidity(c), ...analysis.certs[i] }));
  return { certs, chain: analysis.chain, hostnameCheck: analysis.hostnameCheck };
}

async function parseCertificateInput({ buffer, originalName, certText, password, hostname }) {
  let certs = [], hasPrivateKey = false, error = null, hasUnknownBlock = false;
  try {
    let ext = originalName ? path.extname(originalName).toLowerCase() : '';
    let data;
    if (certText) {
      if (certText.includes('-----BEGIN CERTIFICATE-----') || certText.includes('PRIVATE KEY')) {
        // PEM chain or key
        const result = getCertsAndKeysFromPem(certText);
        certs = result.certs;
        hasPrivateKey = result.hasPrivateKey;
        hasUnknownBlock = result.hasUnknownBlock;
        if (certs.length === 0) {
          if (hasUnknownBlock) {
            throw new Error('No valid certificate found in input. Only certificate and private key PEM blocks are supported.');
          } else {
            throw new Error('No certificate found in input.');
          }
        }
      } else if (certText.includes('-----BEGIN PKCS12-----')) {
        // PEM encoded PFX/P12
        const pemMessage = forge.pem.decode(certText)[0];
        const p12Der = forge.util.decode64(pemMessage.body);
        const p12Asn1 = forge.asn1.fromDer(p12Der);
        const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password || '');
        const result = getCertsFromPfx(p12, password);
        certs = result.certs;
        hasPrivateKey = result.hasPrivateKey;
        if (certs.length === 0) throw new Error('No certificate found in PFX/P12.');
      } else {
        // Try base64 DER or PFX/P12
        try {
          data = Buffer.from(certText, 'base64');
          try {
            const p12Asn1 = forge.asn1.fromDer(data.toString('binary'));
            const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password || '');
            const result = getCertsFromPfx(p12, password);
            certs = result.certs;
            hasPrivateKey = result.hasPrivateKey;
            if (certs.length === 0) throw new Error('No certificate found in PFX/P12.');
          } catch (e) {
            // Try DER X.509
            certs = [wrapForgeCert(forge.pki.certificateFromAsn1(forge.asn1.fromDer(data.toString('binary'))))]
          }
        } catch (e) {
          throw new Error('Unsupported or corrupt certificate text.');
        }
      }
    } else if (buffer && originalName) {
      ext = path.extname(originalName).toLowerCase();
      data = buffer;
      if (ext === '.pfx' || ext === '.p12') {
        let p12Asn1;
        try {
          p12Asn1 = forge.asn1.fromDer(data.toString('binary'));
        } catch (e) {
          throw new Error('Invalid PFX/P12 file.');
        }
        let p12;
        try {
          p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password || '');
        } catch (e) {
          throw new Error('Incorrect password or corrupt PFX/P12 file.');
        }
        const result = getCertsFromPfx(p12, password);
        certs = result.certs;
        hasPrivateKey = result.hasPrivateKey;
        if (certs.length === 0) throw new Error('No certificate found in PFX/P12.');
      } else {
        // Try PEM first
        let pem;
        try {
          pem = data.toString();
          const result = getCertsAndKeysFromPem(pem);
          certs = result.certs;
          hasPrivateKey = result.hasPrivateKey;
          hasUnknownBlock = result.hasUnknownBlock;
          if (certs.length === 0) {
            if (hasUnknownBlock) {
              throw new Error('No valid certificate found in input. Only certificate and private key PEM blocks are supported.');
            } else {
              throw new Error('No certificate found in input.');
            }
          }
        } catch (e) {
          // Try DER
          try {
            certs = [wrapForgeCert(forge.pki.certificateFromAsn1(forge.asn1.fromDer(data.toString('binary'))))]
          } catch (e2) {
            throw new Error('Unsupported or corrupt certificate format.');
          }
        }
      }
    } else {
      throw new Error('No certificate data provided.');
    }
    return { ...buildReport(certs, { hostname }), hasPrivateKey, error: null };
  } catch (err) {
    error = err.message || 'Unknown error parsing certificate.';
  }
  return { certs: [], chain: null, hostnameCheck: null, hasPrivateKey, error };
}


module.exports = { parseCertificateInput, buildReport, wrapDer };
