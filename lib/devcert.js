// One-step certificates for local development: a key, a leaf certificate for localhost-style names, the CA that
// signed it, and everything in the formats developers need (PEM, PFX, JKS, trust store), plus a ZIP of it all.
// Nothing is stored. Keys exist only for the request.
const crypto = require('crypto');
const net = require('net');
const x509 = require('@peculiar/x509');
const { ALGORITHMS, helpers } = require('./keygen');
const { pem } = require('./keys');
const { extractBundle } = require('./bundle');
const { buildPfx } = require('./convert');
const { writeJks } = require('./jks');
const { createZip } = require('./zip');
const { constraintsFor } = require('./nameConstraints');
const {
  CaError, createCa, loadIssuer, randomSerial, certPem, fingerprint, days, crlUrlOption, DAY_MS
} = require('./ca');

x509.cryptoProvider.set(crypto.webcrypto);
const { webcrypto } = crypto;
const { parseSans, buildName } = helpers;

const MAX_LEAF_DAYS = 825;          // Apple rejects longer-lived leaves from user-added roots
const BROWSER_MAX_DAYS = 398;
const MAX_NAMES = 50;
const DEFAULT_NAMES = ['localhost', '127.0.0.1', '::1'];
const DEV_ALGORITHMS = ['ECDSA-P256', 'ECDSA-P384', 'RSA-2048', 'RSA-3072', 'RSA-4096'];
const SCOPES = ['local', 'names', 'none'];
const DEFAULT_BUNDLE_PASSWORD = 'changeit';

class DevCertError extends CaError {}

const textFile = (name, content, note, secret = false) => ({ name, mime: 'application/x-pem-file', note: note || null, secret, encoding: 'text', content });
const binaryFile = (name, mime, content, note, secret = false) => ({ name, mime, note: note || null, secret, encoding: 'base64', content: Buffer.from(content).toString('base64') });

// A safe file-name stem from the first name: "*.app.test" -> "wildcard.app.test", "::1" -> "dev".
function fileBase(name) {
  if (net.isIPv6(String(name))) return 'ipv6';
  const base = String(name).toLowerCase().replace(/^\*\./, 'wildcard.').replace(/[^a-z0-9.-]+/g, '-').replace(/^[-.]+|[-.]+$/g, '');
  return base && base.length <= 60 ? base : 'dev';
}

function parseNames(value) {
  const input = value === undefined || value === null || String(Array.isArray(value) ? value.join('') : value).trim() === '' ? DEFAULT_NAMES : value;
  let sans;
  try {
    sans = parseSans(input);
  } catch (err) {
    throw new DevCertError(err.message);
  }
  if (sans.some(s => s.type !== 'dns' && s.type !== 'ip')) throw new DevCertError('Dev certificates are for host names and IP addresses. Remove any email addresses or URLs.');
  if (!sans.length) throw new DevCertError('Enter at least one host name or IP address.');
  if (sans.length > MAX_NAMES) throw new DevCertError(`Too many names (max ${MAX_NAMES}).`);
  return sans;
}

function bundlePasswordOption(value) {
  const password = value === undefined || value === null || String(value) === '' ? DEFAULT_BUNDLE_PASSWORD : String(value);
  if (password.length < 6 || password.length > 64 || /[\u0000-\u001f]/.test(password)) {
    throw new DevCertError('The PFX/JKS password must be 6 to 64 characters (a Java keytool requirement).');
  }
  return password;
}

function trustReadme({ names, ca, notAfter, password, base, created }) {
  return [
    'Certificate Workbench: development certificate',
    '================================================',
    '',
    `Names:        ${names.join(', ')}`,
    `Valid until:  ${notAfter}`,
    `Issued by:    ${ca.subject}${created ? ' (created for this bundle)' : ''}`,
    `PFX / JKS password: ${password}`,
    '',
    'Files',
    `  ${base}.pem / ${base}-key.pem / ${base}-fullchain.pem   certificate, private key, certificate + CA`,
    `  ${base}.pfx / ${base}.jks                                 the same key and chain for Windows, .NET and Java`,
    '  ca.crt (PEM) / ca.cer (DER)                               the CA certificate: install this so browsers trust the certificate',
    '  truststore.jks                                            Java trust store holding only the CA certificate',
    created ? '  ca-key.pem                                                the CA private key. Keep it secret; it lets you issue more certificates' : '',
    '',
    'Trust the CA (once per machine)',
    '  macOS:    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt',
    '  Windows:  certutil -addstore -f Root ca.cer        (run as administrator)',
    '  Debian/Ubuntu:  sudo cp ca.crt /usr/local/share/ca-certificates/dev-ca.crt && sudo update-ca-certificates',
    '  Fedora/RHEL:    sudo cp ca.crt /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust',
    '  Node.js:  NODE_EXTRA_CA_CERTS=/path/to/ca.crt node app.js',
    '  curl / git / Python requests:  --cacert ca.crt  /  git config http.sslCAInfo ca.crt  /  REQUESTS_CA_BUNDLE=ca.crt',
    '  Firefox uses its own store: Settings > Privacy & Security > Certificates > View Certificates > Authorities > Import.',
    '',
    ca.nameConstraints
      ? `This CA is restricted to: ${ca.nameConstraints.join(', ')}. Clients refuse any certificate it signs for other names, so a leaked key cannot be used to impersonate real websites.`
      : 'WARNING: this CA has no name restrictions. Anyone with its private key could issue a certificate for ANY website that devices trusting it would accept. Guard ca-key.pem, or remove the CA from your trust stores when finished.',
    ''
  ].filter(line => line !== null).join('\n');
}

/**
 * Issue a development certificate.
 * options: names, algorithm, hash, validityDays, clientAuth, crlUrl, bundlePassword, and for a new CA:
 *   caName, caAlgorithm, caValidityDays, scope ("local" default, "names", "none").
 * caInputs: optional [{ name, buffer }] holding an existing CA certificate and private key to sign with.
 */
async function issueDevCertificate(options = {}, { caInputs, caPassword } = {}) {
  const sans = parseNames(options.names);
  const algorithmId = options.algorithm || 'ECDSA-P256';
  if (!DEV_ALGORITHMS.includes(algorithmId)) throw new DevCertError(`Algorithm must be one of: ${DEV_ALGORITHMS.join(', ')}.`);
  const algorithm = ALGORITHMS[algorithmId];
  const hash = options.hash || (algorithmId === 'ECDSA-P384' ? 'SHA-384' : 'SHA-256');
  const clientAuth = options.clientAuth === true || options.clientAuth === 'true' || options.clientAuth === 'on';
  const crlUrl = crlUrlOption(options.crlUrl);
  const bundlePassword = bundlePasswordOption(options.bundlePassword);
  const warnings = [];

  const commonName = sans[0].value;
  if (commonName.length > 64) throw new DevCertError('The first name is too long (max 64 characters).');
  const validityDays = days(options.validityDays, 365, MAX_LEAF_DAYS, 'Validity');
  if (validityDays > BROWSER_MAX_DAYS) warnings.push(`Validity is over ${BROWSER_MAX_DAYS} days. That is fine for a private CA, but some browsers and clients complain about long-lived certificates.`);

  const wildcardOnTld = sans.filter(s => s.type === 'dns' && /^\*\.[^.]+$/.test(s.value));
  if (wildcardOnTld.length) warnings.push(`Some clients refuse a wildcard directly under a top-level name (${wildcardOnTld.map(s => s.value).join(', ')}). Use something like *.app.test instead.`);

  // The CA: an existing one supplied by the caller, or a new one limited to local names.
  let caCreated = null;
  let issuer;
  let constraints = null;
  const useExisting = !!(caInputs && caInputs.length);
  if (useExisting) {
    issuer = await loadIssuer(caInputs, caPassword, hash);
  } else {
    const scope = options.scope || 'local';
    if (!SCOPES.includes(scope)) throw new DevCertError(`CA scope must be one of: ${SCOPES.join(', ')}.`);
    constraints = scope === 'none' ? null : constraintsFor(sans, scope);
    if (!constraints) warnings.push('The new CA has no name restrictions. If its key leaks, it could be used to impersonate any website on devices that trust it.');
    const caName = String(options.caName || '').trim() || `Workbench Dev CA ${crypto.randomBytes(2).toString('hex')}`;
    const caAlgorithm = options.caAlgorithm || 'ECDSA-P256';
    if (!DEV_ALGORITHMS.includes(caAlgorithm)) throw new DevCertError(`CA algorithm must be one of: ${DEV_ALGORITHMS.join(', ')}.`);
    caCreated = await createCa({
      commonName: caName,
      organization: 'Certificate Workbench Dev',
      algorithm: caAlgorithm,
      hash,
      validityDays: options.caValidityDays === undefined || options.caValidityDays === '' ? 3650 : options.caValidityDays,
      pathLength: 0,
      nameConstraints: constraints
    });
    issuer = await loadIssuer([{ name: 'ca.pem', buffer: Buffer.from(caCreated.certificatePem + caCreated.privateKeyPem) }], undefined, hash);
  }

  // The leaf: a fresh key and a certificate for the names, signed by the CA.
  const notBefore = new Date(Date.now() - 60 * 1000);
  let notAfter = new Date(notBefore.getTime() + validityDays * DAY_MS);
  if (notAfter > issuer.cert.notAfter) {
    notAfter = issuer.cert.notAfter;
    warnings.push(`Validity was shortened to ${Math.floor((notAfter - notBefore) / DAY_MS)} days so it does not outlive the CA certificate.`);
  }

  const keyGen = algorithm.rsa ? { ...algorithm.keyGen, hash } : algorithm.keyGen;
  const keys = await webcrypto.subtle.generateKey(keyGen, true, ['sign', 'verify']);
  let keyUsage = x509.KeyUsageFlags.digitalSignature;
  if (algorithm.rsa) keyUsage |= x509.KeyUsageFlags.keyEncipherment;
  const extensions = [
    new x509.BasicConstraintsExtension(false, undefined, true),
    new x509.KeyUsagesExtension(keyUsage, true),
    new x509.ExtendedKeyUsageExtension(clientAuth ? [x509.ExtendedKeyUsage.serverAuth, x509.ExtendedKeyUsage.clientAuth] : [x509.ExtendedKeyUsage.serverAuth]),
    new x509.SubjectAlternativeNameExtension(sans),
    await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
    await x509.AuthorityKeyIdentifierExtension.create(issuer.cert)
  ];
  if (crlUrl) extensions.push(new x509.CRLDistributionPointsExtension([crlUrl]));

  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: randomSerial(),
    subject: buildName({ commonName }),
    issuer: issuer.cert.subjectName,
    notBefore,
    notAfter,
    signingAlgorithm: issuer.signingAlgorithm,
    signingKey: issuer.signingKey,
    publicKey: keys.publicKey,
    extensions
  });

  // Everything in the formats developers ask for.
  const base = fileBase(commonName);
  const leafDer = Buffer.from(cert.rawData);
  const chainDers = [issuer.cert, ...issuer.chain].map(c => Buffer.from(c.rawData));
  const pkcs8 = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', keys.privateKey));
  const leafPem = certPem(cert);
  const caPems = [issuer.cert, ...issuer.chain].map(certPem).join('');
  const alias = base.slice(0, 64);

  const files = [
    textFile(`${base}.pem`, leafPem, 'The certificate.'),
    textFile(`${base}-key.pem`, pem('PRIVATE KEY', pkcs8), 'The private key (unencrypted PKCS#8). Keep it secret.', true),
    textFile(`${base}-fullchain.pem`, leafPem + caPems, 'Certificate followed by the CA. Most servers want this.'),
    textFile('ca.crt', caPems, 'The CA certificate (PEM). Install this so browsers and tools trust the certificate.'),
    binaryFile('ca.cer', 'application/x-x509-ca-cert', chainDers[0], 'The CA certificate in binary DER form, for Windows and macOS double-click install.'),
    binaryFile(`${base}.pfx`, 'application/x-pkcs12', buildPfx({ certs: [leafDer, ...chainDers], pkcs8, password: bundlePassword, alias, legacy: false }), `Key and certificate chain for Windows, .NET and Java. Password: ${bundlePassword}`, true),
    binaryFile(`${base}.jks`, 'application/x-java-keystore', writeJks([{ alias, type: 'key', pkcs8, chain: [leafDer, ...chainDers] }], bundlePassword), `Java keystore with the key and chain. Password: ${bundlePassword}`, true),
    binaryFile('truststore.jks', 'application/x-java-keystore', writeJks([{ alias: 'workbench-dev-ca', type: 'cert', chain: [chainDers[0]] }], bundlePassword), `Java trust store holding only the CA certificate. Password: ${bundlePassword}`)
  ];
  if (caCreated) files.push(textFile('ca-key.pem', caCreated.privateKeyPem, 'The CA private key. Keep it: you need it to issue more certificates from this CA. Anyone who has it can issue certificates your devices trust.', true));

  const caSubject = useExisting ? issuer.cert.subjectName.toString() : caCreated.subject;
  const caInfo = {
    created: !useExisting,
    subject: caSubject,
    fingerprintSha256: fingerprint(issuer.cert),
    notAfter: issuer.cert.notAfter.toISOString(),
    nameConstraints: caCreated ? caCreated.nameConstraints : null,
    scope: useExisting ? null : (options.scope || 'local')
  };

  const notAfterIso = notAfter.toISOString();
  const readme = trustReadme({ names: sans.map(s => s.value), ca: caInfo, notAfter: notAfterIso, password: bundlePassword, base, created: !useExisting });
  const zipName = `${base}-dev-cert.zip`;
  const zipBytes = createZip([...files.map(f => ({ name: f.name, content: f.encoding === 'text' ? f.content : Buffer.from(f.content, 'base64') })), { name: 'README.txt', content: readme }]);
  files.push(binaryFile(zipName, 'application/zip', zipBytes, 'Everything above in one download, with a README that explains how to trust the CA.', true));

  return {
    base,
    zipName,
    files,
    readme,
    summary: {
      names: sans.map(s => `${s.type === 'ip' ? 'IP' : 'DNS'}: ${s.value}`),
      algorithmLabel: algorithm.label,
      hash: algorithm.hashed ? hash : null,
      serialNumber: cert.serialNumber.toUpperCase(),
      notBefore: notBefore.toISOString(),
      notAfter: notAfterIso,
      fingerprintSha256: fingerprint(cert),
      clientAuth,
      crlUrl,
      bundlePassword,
      ca: caInfo
    },
    warnings
  };
}

module.exports = { issueDevCertificate, DevCertError, DEV_ALGORITHMS, DEFAULT_NAMES, SCOPES, DEFAULT_BUNDLE_PASSWORD };
