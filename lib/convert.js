// Converts certificates, keys, CSRs and CRLs between PEM, DER, PKCS#7 (P7B), PFX/PKCS#12 and JKS.
const crypto = require('crypto');
const forge = require('node-forge');
const { extractBundle } = require('./bundle');
const { writeJks } = require('./jks');
const { spkiOf, pem } = require('./keys');

const OUTPUT_FORMATS = ['pem', 'der', 'p7b', 'pfx', 'jks'];
const MAX_ALIAS = 64;

class ConvertError extends Error {}

function commonName(der) {
  const m = /^CN=(.*)$/m.exec(new crypto.X509Certificate(der).subject);
  return m ? m[1] : new crypto.X509Certificate(der).subject.replace(/\n/g, ', ');
}

// Put the leaf first and follow the issuers; unrelated certificates go last. Duplicates are dropped.
function orderChain(ders, keySpki) {
  const unique = [];
  const seen = new Set();
  for (const der of ders) {
    const fp = crypto.createHash('sha256').update(der).digest('hex');
    if (!seen.has(fp)) { seen.add(fp); unique.push(der); }
  }
  const nodes = unique.map(d => new crypto.X509Certificate(d));
  let leaf = keySpki ? nodes.findIndex(n => n.publicKey.export({ type: 'spki', format: 'der' }).equals(keySpki)) : -1;
  if (leaf < 0) {
    // the certificate that did not issue any other certificate in the set
    leaf = nodes.findIndex((n, i) => !nodes.some((o, j) => j !== i && o.checkIssued(n) && !n.checkIssued(o)));
  }
  if (leaf < 0) leaf = 0;

  const order = [leaf];
  for (let current = leaf; ;) {
    const next = nodes.findIndex((n, j) => !order.includes(j) && nodes[current].checkIssued(n));
    if (next < 0) break;
    order.push(next);
    current = next;
  }
  nodes.forEach((_, i) => { if (!order.includes(i)) order.push(i); });
  return order.map(i => unique[i]);
}

// ---- PKCS#7 (certificates only) ----

function buildP7b(ders) {
  const { asn1 } = forge;
  const oid = value => asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(value).getBytes());
  const seq = items => asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, items);
  const set = items => asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, items);
  const signedData = seq([
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, asn1.integerToDer(1).getBytes()),
    set([]),
    seq([oid('1.2.840.113549.1.7.1')]),
    asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, ders.map(d => asn1.fromDer(d.toString('binary')))),
    set([])
  ]);
  const root = seq([oid('1.2.840.113549.1.7.2'), asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [signedData])]);
  return Buffer.from(asn1.toDer(root).getBytes(), 'binary');
}

// ---- PKCS#12 ----

// node-forge only knows RSA keys and certificates it can parse. It accepts raw ASN.1 here by swapping three of its
// helpers for the duration of this synchronous call, which lets ECDSA and Ed25519 material go into a PFX unchanged.
function buildPfx({ certs, pkcs8, password, alias, legacy }) {
  const { pki, asn1 } = forge;
  const originals = { certificateToAsn1: pki.certificateToAsn1, privateKeyToAsn1: pki.privateKeyToAsn1, wrapRsaPrivateKey: pki.wrapRsaPrivateKey };
  const wrapped = der => ({ rawAsn1: asn1.fromDer(der.toString('binary')) });
  pki.certificateToAsn1 = c => c.rawAsn1 || originals.certificateToAsn1(c);
  pki.privateKeyToAsn1 = k => k.rawAsn1;
  pki.wrapRsaPrivateKey = a => a; // already a PrivateKeyInfo
  try {
    const options = { algorithm: legacy ? '3des' : 'aes256', count: 10000, generateLocalKeyId: true };
    if (alias) options.friendlyName = alias; // forge writes it as a BMPString (UTF-16BE) itself
    const tree = forge.pkcs12.toPkcs12Asn1(pkcs8 ? wrapped(pkcs8) : null, certs.map(wrapped), password, options);
    return Buffer.from(asn1.toDer(tree).getBytes(), 'binary');
  } finally {
    Object.assign(pki, originals);
  }
}

// ---- main entry point ----

const file = (name, mime, content, note) => ({
  name, mime, note: note || null,
  encoding: Buffer.isBuffer(content) ? 'base64' : 'text',
  content: Buffer.isBuffer(content) ? content.toString('base64') : content
});

function cleanAlias(value, fallback) {
  const alias = String(value || '').trim() || fallback;
  if (alias.length > MAX_ALIAS) throw new ConvertError(`Alias is too long (max ${MAX_ALIAS} characters).`);
  if (/[\u0000-\u001f]/.test(alias)) throw new ConvertError('Alias contains invalid characters.');
  return alias;
}

/**
 * Convert the supplied inputs ({ name, buffer } each) to `format`.
 * options: password (to open inputs), outputPassword (PFX/JKS password, or to encrypt the PEM private key),
 * alias, legacy (3DES PFX for old Windows and Java).
 * Returns { files, summary, warnings }.
 */
function convert(inputs, format, { password, outputPassword, alias, legacy } = {}) {
  if (!OUTPUT_FORMATS.includes(format)) throw new ConvertError(`Output format must be one of: ${OUTPUT_FORMATS.join(', ')}.`);
  if (!inputs.length) throw new ConvertError('Provide a file or paste some text to convert.');

  const bundle = extractBundle(inputs, { password });
  const warnings = bundle.notes.slice();
  const key = bundle.privateKeys[0] || null;
  if (bundle.privateKeys.length > 1) warnings.push('More than one private key was found; only the first one is converted.');
  const keySpki = key ? spkiOf(key.keyObject) : null;

  if (!bundle.certificates.length && !key && !bundle.csrs.length && !bundle.crls.length) {
    throw new ConvertError('Nothing to convert: no certificate, private key, CSR or CRL was found.');
  }
  const certs = bundle.certificates.length ? orderChain(bundle.certificates, keySpki) : [];
  const leaf = certs[0] || null;
  let keyMatchesLeaf = null;
  if (key && leaf) {
    keyMatchesLeaf = new crypto.X509Certificate(leaf).publicKey.export({ type: 'spki', format: 'der' }).equals(keySpki);
    if (!keyMatchesLeaf) warnings.push('The private key does not match the first certificate, so the certificate order may not be what you expect.');
  }

  const files = [];
  const needsCertsOrKey = format === 'pfx' || format === 'jks';
  if (needsCertsOrKey && !certs.length && !key) throw new ConvertError(`A ${format.toUpperCase()} needs at least one certificate or a private key.`);
  if (format === 'p7b' && !certs.length) throw new ConvertError('A PKCS#7 bundle needs at least one certificate.');

  if (format === 'pem') {
    if (leaf) files.push(file('certificate.pem', 'application/x-pem-file', pem('CERTIFICATE', leaf)));
    if (certs.length > 1) {
      files.push(file('chain.pem', 'application/x-pem-file', certs.slice(1).map(c => pem('CERTIFICATE', c)).join(''), 'Intermediates and root, without the leaf.'));
      files.push(file('fullchain.pem', 'application/x-pem-file', certs.map(c => pem('CERTIFICATE', c)).join(''), 'Leaf first, then the issuers.'));
    }
    if (key) {
      const encrypted = !!outputPassword;
      const text = encrypted
        ? key.keyObject.export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: outputPassword })
        : pem('PRIVATE KEY', key.pkcs8);
      files.push(file('private-key.pem', 'application/x-pem-file', text, encrypted ? 'Encrypted PKCS#8 (AES-256).' : 'Unencrypted PKCS#8. Keep it secret.'));
    }
    bundle.csrs.forEach((c, i) => files.push(file(`request${bundle.csrs.length > 1 ? `-${i + 1}` : ''}.csr`, 'application/pkcs10', pem('CERTIFICATE REQUEST', c))));
    bundle.crls.forEach((c, i) => files.push(file(`revocations${bundle.crls.length > 1 ? `-${i + 1}` : ''}.crl`, 'application/pkix-crl', pem('X509 CRL', c))));
  } else if (format === 'der') {
    certs.forEach((c, i) => files.push(file(i === 0 ? 'certificate.der' : `chain-${i}.der`, 'application/x-x509-ca-cert', c)));
    if (key) files.push(file('private-key.der', 'application/pkcs8', key.pkcs8, 'Unencrypted PKCS#8. Keep it secret.'));
    bundle.csrs.forEach((c, i) => files.push(file(`request${bundle.csrs.length > 1 ? `-${i + 1}` : ''}.csr.der`, 'application/pkcs10', c)));
    bundle.crls.forEach((c, i) => files.push(file(`revocations${bundle.crls.length > 1 ? `-${i + 1}` : ''}.crl.der`, 'application/pkix-crl', c)));
  } else if (format === 'p7b') {
    const bytes = buildP7b(certs);
    files.push(file('certificates.p7b', 'application/x-pkcs7-certificates', pem('PKCS7', bytes), 'PEM-encoded PKCS#7 (certificates only).'));
    files.push(file('certificates-der.p7b', 'application/x-pkcs7-certificates', bytes, 'The same bundle in binary DER form.'));
    if (key) warnings.push('PKCS#7 bundles cannot hold private keys; the key was left out.');
  } else if (format === 'pfx') {
    if (!outputPassword) throw new ConvertError('Choose a password for the PFX file.');
    const bytes = buildPfx({ certs, pkcs8: key && key.pkcs8, password: outputPassword, alias: cleanAlias(alias, ''), legacy: !!legacy });
    files.push(file('bundle.pfx', 'application/x-pkcs12', bytes, legacy
      ? 'Legacy 3DES encryption, readable by old Windows and Java versions.'
      : 'AES-256 encrypted. Windows 10/11, OpenSSL 1.1+ and current Java read this.'));
  } else if (format === 'jks') {
    if (!outputPassword) throw new ConvertError('Choose a password for the keystore.');
    if (outputPassword.length < 6) throw new ConvertError('Keystore passwords must be at least 6 characters (a keytool requirement).');
    const base = cleanAlias(alias, key ? 'server' : 'cert');
    let entries;
    if (key) {
      if (!certs.length) throw new ConvertError('A JKS private key entry needs its certificate. Add the certificate (and chain) as well.');
      entries = [{ alias: base, type: 'key', pkcs8: key.pkcs8, chain: certs }];
    } else {
      entries = certs.map((c, i) => ({ alias: certs.length > 1 ? `${base}-${i + 1}` : base, type: 'cert', chain: [c] }));
    }
    files.push(file('keystore.jks', 'application/x-java-keystore', writeJks(entries, outputPassword),
      key ? 'The key password is the same as the keystore password.' : 'Trusted certificate entries.'));
  }

  if (format !== 'pem' && format !== 'der' && (bundle.csrs.length || bundle.crls.length)) {
    warnings.push(`CSRs and CRLs can only be converted to PEM or DER; they were left out of the ${format.toUpperCase()} output.`);
  }
  if (!files.length) throw new ConvertError('Nothing in the input could be written in that format.');

  return {
    files,
    warnings,
    summary: {
      certificates: certs.length,
      privateKey: !!key,
      csrs: bundle.csrs.length,
      crls: bundle.crls.length,
      keystoreAliases: bundle.keystoreAliases,
      chain: certs.map(commonName),
      keyMatchesLeaf
    }
  };
}

module.exports = { convert, orderChain, buildP7b, buildPfx, ConvertError, OUTPUT_FORMATS };
