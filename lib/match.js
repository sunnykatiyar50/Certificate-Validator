// Checks which certificates, CSRs and private keys belong together by comparing their public keys.
const crypto = require('crypto');
const x509 = require('@peculiar/x509');
const { extractBundle } = require('./bundle');
const { spkiOf, describeKey, sha256Hex, colonHex } = require('./keys');

function subjectLabel(subject, fallback) {
  const m = /^CN=(.*)$/m.exec(subject);
  return m ? m[1] : subject.replace(/\n/g, ', ') || fallback;
}

function publicKeyDescription(spki) {
  return describeKey(crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' }));
}

/**
 * Compare every private key, certificate, CSR and public key in the inputs.
 * Returns { items, groups, verdicts } where items that share a public key land in the same group.
 */
function matchKeys(inputs, { password } = {}) {
  const bundle = extractBundle(inputs, { password });
  const items = [];
  const add = (kind, label, spki) => {
    items.push({
      id: `${kind}-${items.filter(i => i.kind === kind).length + 1}`,
      kind,
      label,
      algorithm: publicKeyDescription(spki),
      keyHash: sha256Hex(spki)
    });
  };

  bundle.privateKeys.forEach((k, i) => {
    const spki = spkiOf(k.keyObject);
    add('private-key', `${publicKeyDescription(spki)} key${bundle.privateKeys.length > 1 ? ` ${i + 1}` : ''}`, spki);
  });
  bundle.certificates.forEach(der => {
    const cert = new crypto.X509Certificate(der);
    add('certificate', subjectLabel(cert.subject, 'Certificate'), cert.publicKey.export({ type: 'spki', format: 'der' }));
  });
  bundle.csrs.forEach(der => {
    const csr = new x509.Pkcs10CertificateRequest(der);
    add('csr', subjectLabel(csr.subject.replace(/, /g, '\n'), 'CSR'), Buffer.from(csr.publicKey.rawData));
  });
  bundle.publicKeys.forEach((spki, i) => add('public-key', `Public key ${bundle.publicKeys.length > 1 ? i + 1 : ''}`.trim(), spki));

  if (!items.length) throw new Error('No certificate, CSR, private key or public key found in the input.');

  const byHash = new Map();
  for (const item of items) {
    if (!byHash.has(item.keyHash)) byHash.set(item.keyHash, []);
    byHash.get(item.keyHash).push(item);
  }
  const groups = [...byHash.entries()].map(([hash, members], i) => {
    members.forEach(m => { m.group = i + 1; });
    return { number: i + 1, keyId: colonHex(hash), algorithm: members[0].algorithm, members: members.map(m => m.id), matched: members.length > 1 };
  });
  items.forEach(i => { i.keyId = colonHex(i.keyHash).slice(0, 23); delete i.keyHash; });

  // One plain-language verdict per private key, and per CSR/certificate when there is no key to compare against.
  const verdicts = [];
  const label = id => items.find(i => i.id === id).label;
  for (const key of items.filter(i => i.kind === 'private-key')) {
    const group = groups.find(g => g.number === key.group);
    const partners = group.members.filter(id => id !== key.id && !id.startsWith('private-key')).map(label);
    verdicts.push({ subject: key.label, matches: partners.length > 0, partners });
  }
  const certs = items.filter(i => i.kind === 'certificate');
  const csrs = items.filter(i => i.kind === 'csr');
  if (!bundle.privateKeys.length) {
    for (const csr of csrs) {
      const partners = certs.filter(c => c.group === csr.group).map(c => c.label);
      verdicts.push({ subject: `CSR ${csr.label}`, matches: partners.length > 0, partners });
    }
  }

  return { items, groups, verdicts, notes: bundle.notes };
}

module.exports = { matchKeys };
