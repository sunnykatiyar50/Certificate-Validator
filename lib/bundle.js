// Reads certificates, private keys, CSRs and CRLs out of whatever the user supplies: PEM text (any mix of blocks),
// DER, base64 DER, PKCS#7/P7B, PKCS#12/PFX and JKS keystores. Shared by the converter, decoder and key matcher.
const crypto = require('crypto');
const forge = require('node-forge');
const { X509Certificate, Pkcs10CertificateRequest, X509Crl } = require('@peculiar/x509');
const { readJks, isJks, JksError } = require('./jks');
const { readPrivateKey, pkcs8Of, spkiOf, KeyError } = require('./keys');

class InputError extends Error {}

const PEM_BLOCK = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;
const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';

function emptyBundle() {
  return { certificates: [], privateKeys: [], publicKeys: [], csrs: [], crls: [], keystoreAliases: [], notes: [] };
}

// Length of the first DER element (used to drop OpenSSL's trailing trust data in TRUSTED CERTIFICATE blocks).
function firstDerLength(buf) {
  if (buf.length < 2) return buf.length;
  let len = buf[1];
  let header = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 4 || buf.length < 2 + n) return buf.length;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[2 + i];
    header = 2 + n;
  }
  return Math.min(buf.length, header + len);
}

// Certificates and CRLs of a PKCS#7 SignedData, as DER, without going through forge's RSA-only certificate parser.
function readPkcs7(derBuf) {
  let root;
  try {
    root = forge.asn1.fromDer(derBuf.toString('binary'));
  } catch (e) {
    throw new InputError('Not a valid PKCS#7 file.');
  }
  const oid = root.value && root.value[0] && root.value[0].type === forge.asn1.Type.OID ? forge.asn1.derToOid(root.value[0].value) : null;
  if (oid !== OID_SIGNED_DATA) throw new InputError('Not a PKCS#7 SignedData bundle.');
  const signedData = root.value[1] && root.value[1].value && root.value[1].value[0];
  const certs = [];
  const crls = [];
  for (const el of (signedData && signedData.value) || []) {
    if (el.tagClass !== forge.asn1.Class.CONTEXT_SPECIFIC || !Array.isArray(el.value)) continue;
    const target = el.type === 0 ? certs : el.type === 1 ? crls : null;
    if (target) for (const item of el.value) target.push(Buffer.from(forge.asn1.toDer(item).getBytes(), 'binary'));
  }
  return { certs, crls };
}

function readPfx(derBuf, password) {
  let p12;
  try {
    p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(derBuf.toString('binary')), password || '');
  } catch (err) {
    if (/MAC|password/i.test(err.message)) throw new InputError('Incorrect password or corrupt PFX/P12 file.');
    throw new InputError('Not a valid PFX/P12 file.');
  }
  const certs = [];
  const keys = [];
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [];
  for (const bag of certBags) {
    // forge cannot parse some certificates (e.g. ECDSA) and hands back their ASN.1 in bag.asn1 instead.
    // certificateToAsn1 reuses a parsed certificate's original TBS bytes, so both paths return the original DER.
    const asn1 = bag.asn1 || (bag.cert && forge.pki.certificateToAsn1(bag.cert));
    if (asn1) certs.push(Buffer.from(forge.asn1.toDer(asn1).getBytes(), 'binary'));
  }
  for (const type of [forge.pki.oids.pkcs8ShroudedKeyBag, forge.pki.oids.keyBag]) {
    for (const bag of p12.getBags({ bagType: type })[type] || []) {
      if (bag.asn1) keys.push(Buffer.from(forge.asn1.toDer(bag.asn1).getBytes(), 'binary'));
      else if (bag.key) keys.push(Buffer.from(forge.asn1.toDer(forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(bag.key))).getBytes(), 'binary'));
    }
  }
  return { certs, keys };
}

function addPrivateKey(bundle, source, password) {
  const keyObject = readPrivateKey(source, password);
  bundle.privateKeys.push({ pkcs8: pkcs8Of(keyObject), keyObject });
}

function addCertificate(bundle, der) {
  try {
    new X509Certificate(der);
  } catch (e) {
    throw new InputError('A certificate in the input could not be parsed.');
  }
  bundle.certificates.push(Buffer.from(der));
}

function addFromPem(bundle, text, password) {
  let found = 0;
  for (const match of text.matchAll(PEM_BLOCK)) {
    const label = match[1].trim();
    const block = match[0];
    const body = match[2].split(/\r?\n/).filter(l => l.trim() && !l.includes(':')).join('');
    const der = Buffer.from(body, 'base64');
    found++;
    if (label === 'CERTIFICATE' || label === 'X509 CERTIFICATE') addCertificate(bundle, der);
    else if (label === 'TRUSTED CERTIFICATE') addCertificate(bundle, der.subarray(0, firstDerLength(der)));
    else if (label === 'CERTIFICATE REQUEST' || label === 'NEW CERTIFICATE REQUEST') bundle.csrs.push(der);
    else if (label === 'X509 CRL' || label === 'CRL') bundle.crls.push(der);
    else if (label === 'PKCS7' || label === 'CMS') {
      const p7 = readPkcs7(der);
      p7.certs.forEach(c => addCertificate(bundle, c));
      bundle.crls.push(...p7.crls);
    } else if (/PRIVATE KEY$/.test(label)) addPrivateKey(bundle, block, password);
    else if (label === 'PUBLIC KEY' || label === 'RSA PUBLIC KEY') {
      try {
        bundle.publicKeys.push(spkiOf(crypto.createPublicKey(block)));
      } catch (e) {
        throw new InputError('A public key in the input could not be parsed.');
      }
    } else if (label === 'PKCS12') addFromDer(bundle, der, password);
    else {
      found--;
      bundle.notes.push(`Ignored a ${label} block.`);
    }
  }
  return found;
}

function addFromDer(bundle, buf, password) {
  const attempts = [
    () => { new X509Certificate(buf); bundle.certificates.push(buf); },
    () => { new Pkcs10CertificateRequest(buf); bundle.csrs.push(buf); },
    () => { new X509Crl(buf); bundle.crls.push(buf); },
    () => {
      const p7 = readPkcs7(buf);
      p7.certs.forEach(c => addCertificate(bundle, c));
      bundle.crls.push(...p7.crls);
    },
    () => {
      const pfx = readPfx(buf, password);
      pfx.certs.forEach(c => addCertificate(bundle, c));
      pfx.keys.forEach(k => addPrivateKey(bundle, k, password));
    },
    () => addPrivateKey(bundle, buf, password),
    () => bundle.publicKeys.push(spkiOf(crypto.createPublicKey({ key: buf, format: 'der', type: 'spki' })))
  ];
  let passwordError = null;
  for (const attempt of attempts) {
    try {
      attempt();
      return;
    } catch (err) {
      // A recognised container with the wrong password beats "unrecognised format".
      if ((err instanceof InputError && /password/i.test(err.message)) || (err instanceof KeyError && /password/i.test(err.message))) {
        passwordError = passwordError || err;
      }
      if (err instanceof InputError && /^A certificate in the input/.test(err.message)) throw err;
    }
  }
  if (passwordError) throw passwordError instanceof InputError ? passwordError : new InputError(passwordError.message);
  throw new InputError('Unrecognised format. Supported: PEM, DER, PKCS#7, PFX/P12 and JKS.');
}

function looksLikeBase64(buf) {
  if (buf.length < 16 || buf.length > 2 * 1024 * 1024) return false;
  return /^[A-Za-z0-9+/=\r\n\s]+$/.test(buf.toString('latin1'));
}

/**
 * Collect everything found in the inputs ({ name, buffer } each) into one bundle:
 * { certificates, privateKeys, publicKeys, csrs, crls: Buffer[], keystoreAliases, notes }.
 * Throws InputError with a user-facing message when an input cannot be read.
 */
function extractBundle(inputs, { password } = {}) {
  const bundle = emptyBundle();
  for (const { name, buffer } of inputs) {
    const label = name ? ` (${name})` : '';
    try {
      if (isJks(buffer)) {
        for (const entry of readJks(buffer, password)) {
          bundle.keystoreAliases.push(entry.alias);
          entry.chain.forEach(c => addCertificate(bundle, c));
          if (entry.type === 'key') addPrivateKey(bundle, entry.pkcs8);
        }
        continue;
      }
      const text = buffer.toString('latin1');
      if (text.includes('-----BEGIN ')) {
        if (!addFromPem(bundle, text, password)) throw new InputError('No certificate, key or request found in the input.');
      } else if (looksLikeBase64(buffer)) {
        addFromDer(bundle, Buffer.from(text.replace(/\s+/g, ''), 'base64'), password);
      } else {
        addFromDer(bundle, buffer, password);
      }
    } catch (err) {
      if (err instanceof InputError || err instanceof KeyError || err instanceof JksError) {
        throw new InputError(`${err.message}${label}`);
      }
      throw err;
    }
  }
  return bundle;
}

module.exports = { extractBundle, readPkcs7, InputError };
