const { webcrypto, X509Certificate } = require('node:crypto');
const tls = require('node:tls');
const x509 = require('@peculiar/x509');

x509.cryptoProvider.set(webcrypto);

const DAY = 24 * 60 * 60 * 1000;
let serial = 1;

async function generateKeys({ bits = 2048, hash = 'SHA-256' } = {}) {
  return webcrypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', hash, publicExponent: new Uint8Array([1, 0, 1]), modulusLength: bits },
    true,
    ['sign', 'verify']
  );
}

/**
 * Create a certificate. `issuer` is { name, keys } of the signing CA; omit it for a self-signed cert.
 * Returns { name, keys, cert, pem, der }.
 */
async function createCert({
  name, issuer, isCA = false, sans = [], bits = 2048, hash = 'SHA-256',
  notBefore = new Date(Date.now() - DAY), notAfter = new Date(Date.now() + 90 * DAY)
}) {
  const keys = await generateKeys({ bits, hash });
  const extensions = [new x509.BasicConstraintsExtension(isCA, undefined, true)];
  if (sans.length) extensions.push(new x509.SubjectAlternativeNameExtension(sans));
  const params = {
    serialNumber: String(serial++).padStart(2, '0'),
    notBefore,
    notAfter,
    signingAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash },
    extensions
  };
  const cert = issuer
    ? await x509.X509CertificateGenerator.create({ ...params, subject: name, issuer: issuer.name, signingKey: issuer.keys.privateKey, publicKey: keys.publicKey })
    : await x509.X509CertificateGenerator.createSelfSigned({ ...params, name, keys });
  return { name, keys, cert, pem: cert.toString('pem').trim() + '\n', der: Buffer.from(cert.rawData) };
}

async function privateKeyPem(keys) {
  const pkcs8 = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', keys.privateKey)).toString('base64');
  return `-----BEGIN PRIVATE KEY-----\n${pkcs8.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----\n`;
}

// Flip the last byte of the DER signature so the certificate no longer verifies.
function tamperPem(c) {
  const der = Buffer.from(c.der);
  der[der.length - 1] ^= 0xff;
  const b64 = der.toString('base64').match(/.{1,64}/g).join('\n');
  return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
}

// A currently valid, self-signed root from Node's bundled trust store.
function validTrustedRoot() {
  const now = Date.now();
  return tls.rootCertificates
    .map(p => new X509Certificate(p))
    .find(c => new Date(c.validTo) > now + 30 * DAY && c.checkIssued(c));
}

const { loadAuthConfig } = require('../lib/auth');

// Auth settings for tests that are not about authentication.
const noAuth = loadAuthConfig({ AUTH_DISABLED: '1' });

module.exports = { noAuth, DAY, createCert, generateKeys, privateKeyPem, tamperPem, validTrustedRoot };
