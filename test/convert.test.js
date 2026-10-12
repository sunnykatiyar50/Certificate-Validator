const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { webcrypto } = crypto;
const x509 = require('@peculiar/x509');
const { writeJks, readJks, isJks } = require('../lib/jks');
const { extractBundle } = require('../lib/bundle');
const { convert, ConvertError } = require('../lib/convert');
const { generateKeyPair } = require('../lib/keygen');
const { createCert, privateKeyPem } = require('./helpers');

x509.cryptoProvider.set(webcrypto);

const text = (name, content) => ({ name, buffer: Buffer.from(content) });
const fileBuffer = (result, name) => {
  const f = result.files.find(x => x.name === name);
  assert.ok(f, `expected output file ${name}`);
  return f.encoding === 'base64' ? Buffer.from(f.content, 'base64') : f.content;
};

test('JKS writer and reader round-trip and check the password', () => {
  const key = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ type: 'pkcs8', format: 'der' });
  const certA = Buffer.from('certificate-a');
  const certB = Buffer.from('certificate-b');
  const store = writeJks([
    { alias: 'Server', type: 'key', pkcs8: key, chain: [certA, certB] },
    { alias: 'root', type: 'cert', chain: [certB] }
  ], 'changeit');

  assert.ok(isJks(store));
  const entries = readJks(store, 'changeit');
  assert.deepEqual(entries.map(e => [e.alias, e.type]), [['server', 'key'], ['root', 'cert']]);
  assert.ok(entries[0].pkcs8.equals(key));
  assert.deepEqual(entries[0].chain, [certA, certB]);
  assert.throws(() => readJks(store, 'wrong'), /Incorrect password/);
  assert.throws(() => writeJks([{ alias: 'a', type: 'cert', chain: [certA] }, { alias: 'A', type: 'cert', chain: [certA] }], 'changeit'), /Duplicate alias/);

  const tampered = Buffer.from(store);
  tampered[40] ^= 0xff;
  assert.throws(() => readJks(tampered, 'changeit'), /Incorrect password or corrupt/);
});

test('conversion between PEM, DER, P7B, PFX and JKS', async t => {
  const root = await createCert({ name: 'CN=Convert Root', isCA: true });
  const leaf = await createCert({ name: 'CN=convert.test', issuer: root, sans: [{ type: 'dns', value: 'convert.test' }] });
  const keyPem = await privateKeyPem(leaf.keys);
  // deliberately out of order: root first, key in the middle
  const bundleInput = [text('all.pem', root.pem + keyPem + leaf.pem)];

  await t.test('PEM output puts the leaf first and splits the key', () => {
    const r = convert(bundleInput, 'pem');
    assert.deepEqual(r.files.map(f => f.name), ['certificate.pem', 'chain.pem', 'fullchain.pem', 'private-key.pem']);
    assert.equal(r.summary.keyMatchesLeaf, true);
    assert.deepEqual(r.summary.chain, ['convert.test', 'Convert Root']);
    assert.equal(new crypto.X509Certificate(fileBuffer(r, 'certificate.pem')).subject, 'CN=convert.test');
    assert.equal(new crypto.X509Certificate(fileBuffer(r, 'chain.pem')).subject, 'CN=Convert Root');
    assert.match(fileBuffer(r, 'private-key.pem'), /BEGIN PRIVATE KEY/);
  });

  await t.test('PEM output can encrypt the private key', () => {
    const r = convert(bundleInput, 'pem', { outputPassword: 'hunter22' });
    const encrypted = fileBuffer(r, 'private-key.pem');
    assert.match(encrypted, /BEGIN ENCRYPTED PRIVATE KEY/);
    assert.throws(() => crypto.createPrivateKey(encrypted));
    assert.ok(crypto.createPrivateKey({ key: encrypted, passphrase: 'hunter22' }));
  });

  await t.test('DER output returns binary certificates and key', () => {
    const r = convert(bundleInput, 'der');
    assert.deepEqual(r.files.map(f => f.name), ['certificate.der', 'chain-1.der', 'private-key.der']);
    assert.ok(new crypto.X509Certificate(fileBuffer(r, 'certificate.der')));
    assert.ok(crypto.createPrivateKey({ key: fileBuffer(r, 'private-key.der'), format: 'der', type: 'pkcs8' }));
  });

  await t.test('P7B bundles certificates only and reads back', () => {
    const r = convert(bundleInput, 'p7b');
    assert.match(r.warnings.join(' '), /cannot hold private keys/);
    for (const name of ['certificates.p7b', 'certificates-der.p7b']) {
      const back = extractBundle([{ name, buffer: Buffer.from(fileBuffer(r, name)) }]);
      assert.equal(back.certificates.length, 2, name);
    }
  });

  for (const legacy of [false, true]) {
    await t.test(`PFX (${legacy ? '3DES' : 'AES-256'}) round-trips with its key`, () => {
      const r = convert(bundleInput, 'pfx', { outputPassword: 'pfx-pass', alias: 'my cert', legacy });
      const back = extractBundle([{ name: 'bundle.pfx', buffer: fileBuffer(r, 'bundle.pfx') }], { password: 'pfx-pass' });
      assert.equal(back.certificates.length, 2);
      assert.equal(back.privateKeys.length, 1);
      assert.ok(crypto.createPublicKey(back.privateKeys[0].keyObject).equals(new crypto.X509Certificate(leaf.der).publicKey));
      assert.throws(() => extractBundle([{ name: 'bundle.pfx', buffer: fileBuffer(r, 'bundle.pfx') }], { password: 'nope' }), /Incorrect password/);
    });
  }

  await t.test('JKS key entry round-trips and trust-store form keeps only certificates', () => {
    const r = convert(bundleInput, 'jks', { outputPassword: 'changeit', alias: 'Web' });
    const entries = readJks(fileBuffer(r, 'keystore.jks'), 'changeit');
    assert.equal(entries.length, 1);
    assert.equal(entries[0].alias, 'web');
    assert.equal(entries[0].chain.length, 2);
    assert.ok(crypto.createPrivateKey({ key: entries[0].pkcs8, format: 'der', type: 'pkcs8' }));

    const trust = convert([text('c.pem', root.pem + leaf.pem)], 'jks', { outputPassword: 'changeit' });
    assert.deepEqual(readJks(fileBuffer(trust, 'keystore.jks'), 'changeit').map(e => e.type), ['cert', 'cert']);
  });

  await t.test('reads PFX and JKS input and converts onward', () => {
    const pfx = convert(bundleInput, 'pfx', { outputPassword: 'pfx-pass' });
    const pem = convert([{ name: 'x.pfx', buffer: fileBuffer(pfx, 'bundle.pfx') }], 'pem', { password: 'pfx-pass' });
    assert.equal(pem.summary.certificates, 2);
    assert.equal(pem.summary.privateKey, true);
    const jks = convert([{ name: 'x.jks', buffer: fileBuffer(convert(bundleInput, 'jks', { outputPassword: 'changeit' }), 'keystore.jks') }], 'der', { password: 'changeit' });
    assert.equal(jks.summary.keystoreAliases[0], 'server');
  });

  await t.test('warns when the key does not belong to the certificate', async () => {
    const other = await createCert({ name: 'CN=other.test' });
    const r = convert([text('a.pem', leaf.pem + await privateKeyPem(other.keys))], 'pem');
    assert.equal(r.summary.keyMatchesLeaf, false);
    assert.match(r.warnings.join(' '), /does not match/);
  });

  await t.test('validates options', () => {
    assert.throws(() => convert(bundleInput, 'pfx'), ConvertError);
    assert.throws(() => convert(bundleInput, 'jks', { outputPassword: 'abc' }), /at least 6/);
    assert.throws(() => convert(bundleInput, 'zip'), /Output format/);
    assert.throws(() => convert([], 'pem'), /Provide a file/);
    assert.throws(() => convert([text('x', 'hello')], 'pem'), /Unrecognised format|No certificate/);
  });
});

test('ECDSA and Ed25519 material survives PFX and JKS conversion', async t => {
  for (const algorithm of ['ECDSA-P256', 'Ed25519']) {
    await t.test(algorithm, async () => {
      const gen = await generateKeyPair({ algorithm, commonName: 'ec.test' });
      const input = [text('p.pem', gen.certificatePem + gen.privateKeyPem)];
      const pfx = convert(input, 'pfx', { outputPassword: 'pfx-pass' });
      const back = extractBundle([{ name: 'a.pfx', buffer: fileBuffer(pfx, 'bundle.pfx') }], { password: 'pfx-pass' });
      assert.equal(back.certificates.length, 1);
      assert.ok(back.certificates[0].equals(new crypto.X509Certificate(gen.certificatePem).raw));
      assert.ok(crypto.createPublicKey(back.privateKeys[0].keyObject).equals(crypto.createPublicKey(gen.privateKeyPem)));

      const jks = convert(input, 'jks', { outputPassword: 'changeit' });
      assert.equal(readJks(fileBuffer(jks, 'keystore.jks'), 'changeit')[0].type, 'key');
    });
  }
});

test('CSRs and CRLs convert between PEM and DER', async () => {
  const gen = await generateKeyPair({ algorithm: 'ECDSA-P256', output: 'csr', commonName: 'csr.test' });
  const der = convert([text('r.csr', gen.csrPem)], 'der');
  assert.equal(der.files[0].name, 'request.csr.der');
  const back = convert([{ name: 'r.der', buffer: fileBuffer(der, 'request.csr.der') }], 'pem');
  assert.equal(fileBuffer(back, 'request.csr').replace(/\s/g, ''), gen.csrPem.replace(/\s/g, ''));
});
