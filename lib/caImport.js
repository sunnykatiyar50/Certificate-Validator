// Check a CA that a user uploads (certificate + private key, PEM/PFX/JKS, possibly encrypted) and normalise it:
// the CA certificate, any parent certificates that came with it, and the key as unencrypted PKCS#8, so it can be
// saved in the browser or on the server and used later without a password.
const { extractBundle } = require('./bundle');
const { loadIssuer, CaError, certPem, fingerprint } = require('./ca');
const { describeKey, spkiOf } = require('./keys');

async function inspectCa(inputs, { password } = {}) {
  if (!inputs.length) throw new CaError('Provide the CA certificate and its private key (PEM, PFX/P12 or JKS).');
  // loadIssuer does the real checks: a key that matches a certificate, CA:TRUE, keyCertSign, not expired.
  const issuer = await loadIssuer(inputs, password);

  const bundle = extractBundle(inputs, { password });
  const keyObject = bundle.privateKeys[0].keyObject;
  const cert = issuer.cert;
  const cn = (cert.subjectName.getField('CN') || [])[0];

  return {
    subject: cn || cert.subject,
    subjectFull: cert.subject,
    issuer: cert.issuer,
    selfSigned: cert.subject === cert.issuer,
    serialNumber: cert.serialNumber.toUpperCase(),
    notBefore: cert.notBefore.toISOString(),
    notAfter: cert.notAfter.toISOString(),
    pathLength: issuer.pathLength === undefined ? null : issuer.pathLength,
    keyDescription: describeKey(keyObject),
    limited: !!cert.getExtension('2.5.29.30'),
    fingerprintSha256: fingerprint(cert),
    spkiLength: spkiOf(keyObject).length,
    certificatePem: certPem(cert),
    chainPem: issuer.chain.map(certPem).join(''),
    privateKeyPem: keyObject.export({ type: 'pkcs8', format: 'pem' })
  };
}

module.exports = { inspectCa };
