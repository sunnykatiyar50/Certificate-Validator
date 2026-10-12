const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const x509 = require('@peculiar/x509');
const { createApp } = require('../server');
const { generateKeyPair } = require('../lib/keygen');
const { createCa, signCsr, createCsr, CaError } = require('../lib/ca');
const { decode } = require('../lib/decode');
const { analyzeChain } = require('../lib/analysis');
const { DAY, createCert, privateKeyPem } = require('./helpers');

x509.cryptoProvider.set(crypto.webcrypto);

const text = (name, content) => ({ name, buffer: Buffer.from(content) });

function listen(app) {
  return new Promise(resolve => {
    const server = app.listen(0, '127.0.0.1', () => resolve({ server, base: `http://127.0.0.1:${server.address().port}` }));
  });
}
const close = server => new Promise(resolve => server.close(resolve));

async function postForm(base, url, fields = {}, files = []) {
  const form = new FormData();
  for (const [k, v] of Object.entries(fields)) form.append(k, v);
  for (const f of files) form.append(f.field, new Blob([f.content]), f.name);
  const res = await fetch(`${base}${url}`, { method: 'POST', body: form });
  return { res, body: await res.json() };
}

test('CSR decoding', async t => {
  const gen = await generateKeyPair({ algorithm: 'RSA-2048', output: 'csr', commonName: 'csr.test', sans: 'csr.test alt.test 10.0.0.9', organization: 'Org' });
  const { csrs } = await decode([text('r.csr', gen.csrPem)]);
  assert.equal(csrs.length, 1);
  const csr = csrs[0];
  assert.equal(csr.signatureValid, true);
  assert.equal(csr.publicKey, 'RSA 2048');
  assert.deepEqual(csr.sans.map(s => s.value), ['csr.test', 'alt.test', '10.0.0.9']);
  assert.ok(csr.subject.some(p => p.shortName === 'CN' && p.value === 'csr.test'));
  assert.match(csr.keyId, /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);

  await t.test('flags a tampered signature', async () => {
    const der = Buffer.from(gen.csrPem.replace(/-----[^-]+-----/g, '').replace(/\s/g, ''), 'base64');
    der[der.length - 1] ^= 0xff;
    const b64 = der.toString('base64').match(/.{1,64}/g).join('\n');
    const bad = await decode([text('bad.csr', `-----BEGIN CERTIFICATE REQUEST-----\n${b64}\n-----END CERTIFICATE REQUEST-----\n`)]);
    assert.equal(bad.csrs[0].signatureValid, false);
    assert.ok(bad.csrs[0].warnings.some(w => w.level === 'danger'));
  });
});

test('CRL decoding', async t => {
  const ca = await createCert({ name: 'CN=CRL CA', isCA: true });
  const revoked = await createCert({ name: 'CN=revoked.test', issuer: ca });
  const good = await createCert({ name: 'CN=good.test', issuer: ca });
  const crl = await x509.X509CrlGenerator.create({
    issuer: ca.name,
    thisUpdate: new Date(Date.now() - DAY),
    nextUpdate: new Date(Date.now() + 7 * DAY),
    entries: [{ serialNumber: revoked.cert.serialNumber, revocationDate: new Date(Date.now() - 2 * DAY), reason: x509.X509CrlReason.keyCompromise }],
    signingAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    signingKey: ca.keys.privateKey
  });
  const crlPem = crl.toString('pem');

  await t.test('lists entries and verifies the signature against a supplied issuer', async () => {
    const out = await decode([text('list.crl', crlPem), text('ca.pem', ca.pem)]);
    const c = out.crls[0];
    assert.equal(c.revokedCount, 1);
    assert.equal(c.entries[0].reason, 'Key compromise');
    assert.equal(c.expired, false);
    assert.equal(c.signature, 'valid');
    assert.ok(c.issuer.some(p => p.value === 'CRL CA'));
  });

  await t.test('says which supplied certificates are revoked', async () => {
    const out = await decode([text('list.crl', crlPem), text('certs.pem', revoked.pem + good.pem)]);
    const status = Object.fromEntries(out.crls[0].certificateStatus.map(s => [s.subject, s.revoked]));
    assert.deepEqual(status, { 'revoked.test': true, 'good.test': false });
    assert.equal(out.crls[0].signature, 'unchecked');
  });

  await t.test('accepts DER', async () => {
    const out = await decode([{ name: 'list.crl', buffer: Buffer.from(crl.rawData) }]);
    assert.equal(out.crls.length, 1);
  });
});

test('PKCS#7 bundles decode into a chain report', async () => {
  const { convert } = require('../lib/convert');
  const root = await createCert({ name: 'CN=P7 Root', isCA: true });
  const leaf = await createCert({ name: 'CN=p7.test', issuer: root });
  const p7b = convert([text('c.pem', leaf.pem + root.pem)], 'p7b').files[0].content;
  const out = await decode([text('bundle.p7b', p7b)]);
  assert.equal(out.certificates.certs.length, 2);
  assert.equal(out.certificates.chain.status, 'untrusted-root');
});

test('local CA issues chains that OpenSSL-style verification accepts', async t => {
  for (const algorithm of ['ECDSA-P256', 'RSA-2048', 'Ed25519']) {
    await t.test(algorithm, async () => {
      const root = await createCa({ commonName: 'Lab Root', algorithm, pathLength: 1 });
      assert.equal(root.kind, 'root');
      const rootNode = new crypto.X509Certificate(root.certificatePem);
      assert.equal(rootNode.ca, true);
      assert.ok(rootNode.verify(rootNode.publicKey));

      const inter = await createCa({ commonName: 'Lab Intermediate', algorithm, validityDays: 400, pathLength: 0 }, { issuerInputs: [text('root', root.certificatePem + root.privateKeyPem)] });
      const interNode = new crypto.X509Certificate(inter.certificatePem);
      assert.ok(interNode.verify(rootNode.publicKey));
      assert.equal(interNode.ca, true);
      assert.equal(inter.pathLength, 0);

      const leafKey = await generateKeyPair({ algorithm: 'ECDSA-P256', output: 'csr', commonName: 'svc.lab.test', sans: 'svc.lab.test 10.9.8.7' });
      const leaf = await signCsr([text('r.csr', leafKey.csrPem)], [text('ca', inter.certificatePem + inter.privateKeyPem + root.certificatePem)], { validityDays: 30 });
      const leafNode = new crypto.X509Certificate(leaf.certificatePem);
      assert.ok(leafNode.verify(interNode.publicKey));
      assert.equal(leafNode.ca, false);
      assert.match(leafNode.subjectAltName, /DNS:svc\.lab\.test/);
      assert.match(leafNode.subjectAltName, /IP Address:10\.9\.8\.7/);
      assert.equal(leafNode.keyUsage.includes('1.3.6.1.5.5.7.3.1'), true);
      assert.ok(crypto.createPublicKey(leafKey.privateKeyPem).equals(leafNode.publicKey), 'leaf carries the CSR key');
      assert.equal(leafNode.issuer, interNode.subject);
      assert.equal(leaf.fullchainPem, leaf.certificatePem + leaf.chainPem);

      // the analysis code agrees: leaf -> intermediate -> root, ending at an untrusted private root
      const report = analyzeChain([leafNode.raw, interNode.raw, rootNode.raw]);
      assert.equal(report.chain.status, 'untrusted-root');
      assert.deepEqual(report.chain.path, [0, 1, 2]);
      assert.ok(report.certs.every(c => c.signatureCheck === 'valid'));
    });
  }

  await t.test('enforces CA rules', async () => {
    const root = await createCa({ commonName: 'Strict Root', pathLength: 0 });
    const issuer = [text('root', root.certificatePem + root.privateKeyPem)];
    await assert.rejects(createCa({ commonName: 'Too Deep' }, { issuerInputs: issuer }), /path length of 0/);

    const leafCsr = await generateKeyPair({ algorithm: 'ECDSA-P256', output: 'csr', commonName: 'x.test' });
    const leaf = await signCsr([text('r', leafCsr.csrPem)], issuer, {});
    // a leaf certificate cannot act as a CA
    const other = await generateKeyPair({ algorithm: 'ECDSA-P256', output: 'csr', commonName: 'y.test' });
    await assert.rejects(signCsr([text('r', other.csrPem)], [text('l', leaf.certificatePem + leafCsr.privateKeyPem)], {}), /not a CA/);
    // key and certificate must pair up
    await assert.rejects(signCsr([text('r', other.csrPem)], [text('m', root.certificatePem + leafCsr.privateKeyPem)], {}), /does not match/);
    await assert.rejects(signCsr([text('r', 'nope')], issuer, {}), CaError);
    await assert.rejects(createCa({ commonName: '' }), /Common name/);
    await assert.rejects(createCa({ commonName: 'x', validityDays: 99999 }), /Validity/);
  });

  await t.test('shortens validity to the CA lifetime and mirrors the CN into the SANs', async () => {
    const root = await createCa({ commonName: 'Short Root', validityDays: 10 });
    const csr = await generateKeyPair({ algorithm: 'ECDSA-P256', output: 'csr', commonName: 'cn-only.test' });
    const csrNoSan = csr.csrPem; // keygen adds the CN as a SAN, so use a CSR from createCsr without names
    const k = await generateKeyPair({ algorithm: 'ECDSA-P256', output: 'keys' });
    const bare = await createCsr([text('k', k.privateKeyPem)], { commonName: 'Not A Host' });
    const out = await signCsr([text('r', bare.csrPem)], [text('c', root.certificatePem + root.privateKeyPem)], { validityDays: 90 });
    assert.match(out.warnings.join(' '), /shortened/);
    assert.match(out.warnings.join(' '), /no subject alternative names/);
    assert.ok(new Date(out.notAfter) <= new Date(root.notAfter));
    const withSan = await signCsr([text('r', csrNoSan)], [text('c', root.certificatePem + root.privateKeyPem)], { validityDays: 5 });
    assert.deepEqual(withSan.sans, ['DNS: cn-only.test']);
  });
});

test('CSR from an existing key', async t => {
  const key = await generateKeyPair({ algorithm: 'RSA-2048', output: 'keys' });
  const keyInput = [text('k.pem', key.privateKeyPem)];

  await t.test('uses the supplied names and the key signs it', async () => {
    const out = await createCsr(keyInput, { commonName: 'example.test', sans: 'www.example.test, 10.1.1.1', hash: 'SHA-384', organization: 'Example Org' });
    const decoded = await decode([text('r.csr', out.csrPem)]);
    assert.equal(decoded.csrs[0].signatureValid, true);
    assert.match(decoded.csrs[0].signatureAlgorithm, /SHA-384/);
    assert.deepEqual(decoded.csrs[0].sans.map(s => s.value), ['www.example.test', '10.1.1.1']);
    assert.ok(decoded.csrs[0].subject.some(p => p.shortName === 'O' && p.value === 'Example Org'));
  });

  await t.test('copies the subject and names from an existing certificate', async () => {
    const existing = await generateKeyPair({ algorithm: 'ECDSA-P256', commonName: 'renew.test', sans: 'renew.test www.renew.test', organization: 'Renew Org' });
    const out = await createCsr(keyInput, { certificateInputs: [text('c.pem', existing.certificatePem)] });
    const decoded = (await decode([text('r.csr', out.csrPem)])).csrs[0];
    assert.deepEqual(decoded.sans.map(s => s.value), ['renew.test', 'www.renew.test']);
    assert.ok(decoded.subject.some(p => p.shortName === 'O' && p.value === 'Renew Org'));
  });

  await t.test('validates input', async () => {
    await assert.rejects(createCsr(keyInput, {}), /Common name is required/);
    await assert.rejects(createCsr([text('x', 'not a key')], { commonName: 'x.test' }), CaError);
    await assert.rejects(createCsr(keyInput, { commonName: 'x.test', hash: 'MD5' }), /hash/);
  });
});

test('tool endpoints', async t => {
  const { server, base } = await listen(createApp({ enableRateLimit: false }));
  t.after(() => close(server));

  await t.test('convert returns files, with the PFX as base64', async () => {
    const gen = await generateKeyPair({ algorithm: 'ECDSA-P256', commonName: 'api.convert.test' });
    const { res, body } = await postForm(base, '/api/convert', { format: 'pfx', outputPassword: 'pfx-pass', text: gen.certificatePem + gen.privateKeyPem });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('cache-control'), 'no-store');
    assert.equal(body.files[0].name, 'bundle.pfx');
    assert.equal(body.files[0].encoding, 'base64');
    assert.equal(body.summary.keyMatchesLeaf, true);
  });

  await t.test('convert accepts uploaded files and rejects bad requests', async () => {
    const gen = await generateKeyPair({ algorithm: 'ECDSA-P256', commonName: 'upload.test' });
    const ok = await postForm(base, '/api/convert', { format: 'der' }, [{ field: 'files', name: 'cert.pem', content: gen.certificatePem }]);
    assert.equal(ok.body.files[0].name, 'certificate.der');
    assert.match((await postForm(base, '/api/convert', { format: 'pfx', text: gen.certificatePem })).body.error, /password/i);
    assert.match((await postForm(base, '/api/convert', { format: 'pem' })).body.error, /Provide a file/);
    const bad = await postForm(base, '/api/convert', { format: 'pem' }, [{ field: 'files', name: 'evil.exe', content: 'x' }]);
    assert.equal(bad.res.status, 400);
    assert.match(bad.body.error, /Unsupported file type/);
  });

  await t.test('decode', async () => {
    const gen = await generateKeyPair({ algorithm: 'RSA-2048', commonName: 'ep.test', output: 'csr' });
    const decoded = await postForm(base, '/api/decode', { text: gen.csrPem });
    assert.equal(decoded.body.csrs[0].signatureValid, true);
    assert.equal(decoded.body.privateKeys.length, 0);
    const keyed = await postForm(base, '/api/decode', { text: gen.privateKeyPem });
    assert.deepEqual(keyed.body.privateKeys, [{ description: 'RSA 2048' }]);
    assert.doesNotMatch(JSON.stringify(keyed.body), /PRIVATE KEY|MII/, 'private keys are never echoed back');
    assert.match((await postForm(base, '/api/decode', {})).body.error, /Provide a file/);
  });

  await t.test('CA create, CSR create and CA sign', async () => {
    const root = (await postForm(base, '/api/ca/create', { commonName: 'API Root', algorithm: 'ECDSA-P256' })).body;
    assert.equal(root.kind, 'root');
    const key = await generateKeyPair({ algorithm: 'RSA-2048', output: 'keys' });
    const csr = (await postForm(base, '/api/csr/create', { keyText: key.privateKeyPem, commonName: 'api.lab.test', sans: 'api.lab.test' })).body;
    assert.match(csr.csrPem, /BEGIN CERTIFICATE REQUEST/);
    const signed = await postForm(base, '/api/ca/sign', { csrText: csr.csrPem, caText: root.certificatePem + root.privateKeyPem, usage: 'server', validityDays: '30' });
    assert.equal(signed.res.status, 200);
    const leaf = new crypto.X509Certificate(signed.body.certificatePem);
    assert.ok(leaf.verify(new crypto.X509Certificate(root.certificatePem).publicKey));
    assert.match(leaf.subjectAltName, /DNS:api\.lab\.test/);

    const noKey = await postForm(base, '/api/ca/sign', { csrText: csr.csrPem, caText: root.certificatePem });
    assert.equal(noKey.res.status, 400);
    assert.match(noKey.body.error, /private key was not found/);
  });

  await t.test('does not leak internals on unexpected errors', async () => {
    const { res, body } = await postForm(base, '/api/ca/sign', { csrText: 'x'.repeat(10), caText: 'y' });
    assert.equal(res.status, 400);
    assert.ok(body.error);
  });

  await t.test('private keys are never written to the console', async () => {
    const original = console.error;
    const logged = [];
    console.error = (...args) => logged.push(args.join(' '));
    try {
      const key = await privateKeyPem((await createCert({ name: 'CN=log.test' })).keys);
      await postForm(base, '/api/convert', { format: 'pfx', outputPassword: 'pfx-pass', text: key });
    } finally {
      console.error = original;
    }
    assert.doesNotMatch(logged.join('\n'), /PRIVATE KEY/);
  });
});
