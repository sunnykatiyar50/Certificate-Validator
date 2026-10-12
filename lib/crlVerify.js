const crypto = require('crypto');

// Verifies a CRL's signature directly on the original signed bytes with Node's crypto.
//
// @peculiar/x509's X509Crl.verify() re-encodes the list before checking it, and gets that wrong for CRLs whose
// entries have no extensions (no reason code), reporting a valid signature as invalid. OpenSSL agrees the
// signatures are fine, so this checks the exact DER bytes that were signed instead.

// signature algorithm OID -> how to verify with crypto.verify (digest name, or null for Ed25519)
const ALGORITHMS = {
  '1.2.840.113549.1.1.5': 'sha1',     // sha1WithRSAEncryption
  '1.2.840.113549.1.1.11': 'sha256',
  '1.2.840.113549.1.1.12': 'sha384',
  '1.2.840.113549.1.1.13': 'sha512',
  '1.2.840.10045.4.1': 'sha1',        // ecdsa-with-SHA1
  '1.2.840.10045.4.3.2': 'sha256',
  '1.2.840.10045.4.3.3': 'sha384',
  '1.2.840.10045.4.3.4': 'sha512',
  '1.3.101.112': null                 // Ed25519
};

// One DER element: where it starts, where its content starts, and where it ends.
function readTlv(buf, offset) {
  if (offset + 2 > buf.length) throw new Error('truncated');
  let length = buf[offset + 1];
  let header = 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count < 1 || count > 4 || offset + 2 + count > buf.length) throw new Error('bad length');
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + buf[offset + 2 + i];
    header = 2 + count;
  }
  const end = offset + header + length;
  if (end > buf.length) throw new Error('truncated');
  return { tag: buf[offset], start: offset, contentStart: offset + header, end };
}

// Decode the content bytes of an OBJECT IDENTIFIER into dotted form, e.g. "1.2.840.10045.4.3.2".
function oidString(content) {
  const arcs = [];
  let value = 0;
  for (const byte of content) {
    value = value * 128 + (byte & 0x7f);
    if (!(byte & 0x80)) {
      arcs.push(value);
      value = 0;
    }
  }
  const first = arcs.shift();
  const top = Math.min(Math.floor(first / 40), 2);
  return [top, first - 40 * top, ...arcs].join('.');
}

/**
 * Check a CRL (DER) against the certificate (DER) that should have signed it.
 * Returns true or false, or null when the signature algorithm is one this check does not handle
 * (callers can then fall back to another method).
 */
function verifyCrlSignature(crlDer, issuerCertDer) {
  let tbs;
  let algorithm;
  let signature;
  try {
    const crl = readTlv(crlDer, 0);
    tbs = readTlv(crlDer, crl.contentStart);
    const algorithmTlv = readTlv(crlDer, tbs.end);
    const signatureTlv = readTlv(crlDer, algorithmTlv.end);
    const oidTlv = readTlv(crlDer, algorithmTlv.contentStart);
    if (oidTlv.tag !== 0x06 || signatureTlv.tag !== 0x03) return null;
    algorithm = oidString(crlDer.subarray(oidTlv.contentStart, oidTlv.end));
    signature = crlDer.subarray(signatureTlv.contentStart + 1, signatureTlv.end); // skip the unused-bits byte
  } catch (err) {
    return null;
  }
  if (!(algorithm in ALGORITHMS)) return null;
  try {
    const publicKey = new crypto.X509Certificate(issuerCertDer).publicKey;
    return crypto.verify(ALGORITHMS[algorithm], crlDer.subarray(tbs.start, tbs.end), publicKey, signature);
  } catch (err) {
    return false;
  }
}

module.exports = { verifyCrlSignature };
