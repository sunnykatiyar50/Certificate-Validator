const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const x509 = require('@peculiar/x509');
const { createApp } = require('../server');
const { generateKeyPair } = require('../lib/keygen');
const { createCa, signCsr, createCsr, CaError } = require('../lib/ca');
const { decode } = require('../lib/decode');
const { matchKeys } = require('../lib/match');
const { analyzeChain } = require('../lib/analysis');
const { parseEmbeddedScts } = require('../lib/sct');
const { lookupRoot } = require('../lib/rootStores');
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

test('key, certificate and CSR matching', async t => {
  const a = await generateKeyPair({ algorithm: 'ECDSA-P256', commonName: 'a.test' });
  const b = await generateKeyPair({ algorithm: 'RSA-2048', commonName: 'b.test', output: 'csr' });
  const aCsr = await createCsr([text('k', a.privateKeyPem)], { commonName: 'a.test' });

  await t.test('matches a key with its certificate and CSR, and not with another key', () => {
    const r = matchKeys([text('all.pem', a.privateKeyPem + a.certificatePem + aCsr.csrPem + b.privateKeyPem + b.csrPem)]);
    const groupOf = kind => r.items.filter(i => i.kind === kind).map(i => i.group);
    assert.equal(r.groups.length, 2);
    assert.deepEqual(groupOf('private-key'), [1, 2]);
    assert.equal(r.items.find(i => i.kind === 'certificate').group, 1);
    assert.deepEqual(r.verdicts.map(v => v.matches), [true, true]);
  });

  await t.test('reports a key that matches nothing', () => {
    const r = matchKeys([text('a.pem', a.certificatePem), text('b.pem', b.privateKeyPem)]);
    assert.equal(r.groups.length, 2);
    assert.deepEqual(r.verdicts, [{ subject: 'RSA 2048 key', matches: false, partners: [] }]);
  });

  await t.test('compares a CSR with a certificate when there is no private key', () => {
    const r = matchKeys([text('a.pem', a.certificatePem + aCsr.csrPem)]);
    assert.equal(r.verdicts[0].matches, true);
  });

  await t.test('needs the password of an encrypted key', () => {
    const encrypted = crypto.createPrivateKey(a.privateKeyPem).export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: 'pw123456' });
    assert.throws(() => matchKeys([text('k.pem', encrypted)]), /encrypted/);
    assert.throws(() => matchKeys([text('k.pem', encrypted)], { password: 'wrong' }), /Incorrect password/);
    assert.equal(matchKeys([text('k.pem', encrypted + a.certificatePem)], { password: 'pw123456' }).groups.length, 1);
  });
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
    assert.equal(matchKeys([text('a', out.csrPem + key.privateKeyPem)]).verdicts[0].matches, true);
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

test('Certificate Transparency SCT parsing', async t => {
  const logs = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', 'ct-logs.json'), 'utf8')).logs;
  const [knownId, known] = Object.entries(logs)[0];

  const sct = (logId, ms) => {
    const body = Buffer.concat([Buffer.from([0]), logId, Buffer.alloc(8), Buffer.from([0, 0]), Buffer.from([4, 3, 0, 2, 0xab, 0xcd])]);
    body.writeBigUInt64BE(BigInt(ms), 33);
    const framed = Buffer.alloc(2 + body.length);
    framed.writeUInt16BE(body.length);
    body.copy(framed, 2);
    return framed;
  };
  const embed = async list => {
    const total = Buffer.alloc(2);
    total.writeUInt16BE(list.reduce((n, s) => n + s.length, 0));
    const tlsList = Buffer.concat([total, ...list]);
    const value = Buffer.concat([Buffer.from([0x04, tlsList.length < 128 ? tlsList.length : 0x82]), ...(tlsList.length < 128 ? [] : [Buffer.from([tlsList.length >> 8, tlsList.length & 0xff])]), tlsList]);
    const keys = await crypto.webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const cert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: '01', name: 'CN=sct.test', notBefore: new Date(Date.now() - DAY), notAfter: new Date(Date.now() + DAY),
      signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' }, keys,
      extensions: [new x509.Extension('1.3.6.1.4.1.11129.2.4.2', false, value)]
    });
    return Buffer.from(cert.rawData);
  };

  await t.test('reads log ID, time and algorithm, and names known logs', async () => {
    const when = Date.UTC(2026, 0, 15, 12, 0, 0);
    const scts = parseEmbeddedScts(await embed([sct(Buffer.from(knownId, 'base64'), when), sct(Buffer.alloc(32, 7), when + 1000)]));
    assert.equal(scts.length, 2);
    assert.equal(scts[0].logName, known.name);
    assert.equal(scts[0].timestamp, '2026-01-15T12:00:00.000Z');
    assert.equal(scts[0].signatureAlgorithm, 'SHA-256 with ECDSA');
    assert.equal(scts[1].logName, null);
    assert.equal(scts[1].logId, Buffer.alloc(32, 7).toString('base64'));
  });

  await t.test('returns nothing for certificates without SCTs or with junk', async () => {
    const plain = await createCert({ name: 'CN=plain.test' });
    assert.deepEqual(parseEmbeddedScts(plain.der), []);
    assert.deepEqual(parseEmbeddedScts(Buffer.from('junk')), []);
  });

  await t.test('is reported per certificate in the analysis', async () => {
    const report = analyzeChain([await embed([sct(Buffer.alloc(32, 1), Date.now())])]);
    assert.equal(report.certs[0].scts.length, 1);
  });
});

test('root program membership', async t => {
  const data = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', 'root-stores.json'), 'utf8'));

  await t.test('looks up a root by fingerprint', () => {
    const fp = data.stores.apple.find(f => data.stores.chrome.includes(f) && data.stores.microsoft.includes(f));
    assert.ok(fp, 'expected at least one root in all three stores');
    const r = lookupRoot(fp.match(/.{2}/g).join(':'));
    assert.deepEqual(r.members.map(m => [m.id, m.included]), [['apple', true], ['chrome', true], ['microsoft', true]]);
    assert.equal(r.asOf, data.generatedAt);
    assert.ok(lookupRoot('00'.repeat(32)).members.every(m => !m.included));
  });

  await t.test('a private chain is reported as not trusted by any program', async () => {
    const root = await createCert({ name: 'CN=Private Root', isCA: true });
    const leaf = await createCert({ name: 'CN=private.test', issuer: root });
    const { chain } = analyzeChain([leaf.der, root.der]);
    assert.deepEqual(chain.platformTrust.platforms.map(p => [p.id, p.status]), [
      ['mozilla', 'not-trusted'], ['apple', 'not-trusted'], ['chrome', 'not-trusted'], ['microsoft', 'not-trusted']
    ]);
  });

  await t.test('an incomplete chain is reported as unknown for Mozilla', async () => {
    const root = await createCert({ name: 'CN=Missing Root', isCA: true });
    const leaf = await createCert({ name: 'CN=lonely.test', issuer: root });
    const { chain } = analyzeChain([leaf.der]);
    assert.equal(chain.status, 'incomplete');
    assert.equal(chain.platformTrust.platforms[0].status, 'unknown');
    assert.equal(chain.platformTrust.platforms.length, 1);
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

  await t.test('decode and match', async () => {
    const gen = await generateKeyPair({ algorithm: 'RSA-2048', commonName: 'ep.test', output: 'csr' });
    const decoded = await postForm(base, '/api/decode', { text: gen.csrPem });
    assert.equal(decoded.body.csrs[0].signatureValid, true);
    assert.equal(decoded.body.privateKeys.length, 0);
    const keyed = await postForm(base, '/api/decode', { text: gen.privateKeyPem });
    assert.deepEqual(keyed.body.privateKeys, [{ description: 'RSA 2048' }]);
    assert.doesNotMatch(JSON.stringify(keyed.body), /PRIVATE KEY|MII/, 'private keys are never echoed back');

    const matched = await postForm(base, '/api/match', { text: gen.csrPem + gen.privateKeyPem });
    assert.equal(matched.body.verdicts[0].matches, true);
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
