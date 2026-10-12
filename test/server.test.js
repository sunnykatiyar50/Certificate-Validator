const test = require('node:test');
const assert = require('node:assert/strict');
const tls = require('node:tls');
const { createApp, parseTrustProxy } = require('../server');
const { isBlockedAddress } = require('../lib/liveCheck');
const { DAY, createCert, privateKeyPem, noAuth } = require('./helpers');

function listen(app) {
  return new Promise(resolve => {
    const server = app.listen(0, '127.0.0.1', () => resolve({ server, base: `http://127.0.0.1:${server.address().port}` }));
  });
}

function close(server) {
  return new Promise(resolve => server.close(resolve));
}

async function postText(base, certText, extra = {}) {
  const form = new FormData();
  form.append('certText', certText);
  for (const [k, v] of Object.entries(extra)) form.append(k, v);
  const res = await fetch(`${base}/api/validate-certificate`, { method: 'POST', body: form });
  return { res, body: await res.json() };
}

async function postFile(base, name, content, extra = {}) {
  const form = new FormData();
  form.append('certificate', new Blob([content]), name);
  for (const [k, v] of Object.entries(extra)) form.append(k, v);
  const res = await fetch(`${base}/api/validate-certificate`, { method: 'POST', body: form });
  return { res, body: await res.json() };
}

test('validate-certificate endpoint', async t => {
  const { server, base } = await listen(createApp({ auth: noAuth, enableRateLimit: false }));
  t.after(() => close(server));

  const root = await createCert({ name: 'CN=Endpoint Root', isCA: true });
  const leaf = await createCert({ name: 'CN=api.test', issuer: root, sans: [{ type: 'dns', value: 'api.test' }] });
  const expired = await createCert({ name: 'CN=old.test', notBefore: new Date(Date.now() - 30 * DAY), notAfter: new Date(Date.now() - DAY) });

  await t.test('parses pasted PEM and reports details', async () => {
    const { body } = await postText(base, leaf.pem);
    assert.equal(body.error, null);
    assert.equal(body.certs.length, 1);
    assert.equal(body.certs[0].valid, true);
    assert.deepEqual(body.certs[0].sans, [{ type: 'DNS', value: 'api.test' }]);
    assert.match(body.certs[0].fingerprintSha256, /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
  });

  await t.test('parses an uploaded file and checks the hostname', async () => {
    const ok = await postFile(base, 'leaf.pem', leaf.pem, { hostname: 'api.test' });
    assert.equal(ok.body.hostnameCheck.matches, true);
    const bad = await postFile(base, 'leaf.pem', leaf.pem, { hostname: 'other.test' });
    assert.equal(bad.body.hostnameCheck.matches, false);
  });

  await t.test('analyses a pasted chain', async () => {
    const { body } = await postText(base, leaf.pem + root.pem);
    assert.equal(body.certs.length, 2);
    assert.equal(body.chain.status, 'untrusted-root');
    assert.deepEqual(body.chain.path, [0, 1]);
  });

  await t.test('flags expired certificates', async () => {
    const { body } = await postText(base, expired.pem);
    assert.equal(body.certs[0].valid, false);
    assert.equal(body.certs[0].error, 'Certificate has expired.');
  });

  await t.test('notes private keys without treating them as certificates', async () => {
    const { body } = await postText(base, leaf.pem + await privateKeyPem(leaf.keys));
    assert.equal(body.hasPrivateKey, true);
    assert.equal(body.certs.length, 1);
  });

  await t.test('accepts DER uploads', async () => {
    const { body } = await postFile(base, 'leaf.der', leaf.der);
    assert.equal(body.error, null);
    assert.equal(body.certs[0].subject[0].value, 'api.test');
  });

  await t.test('reports garbage input as an error', async () => {
    const { body } = await postText(base, 'not a certificate');
    assert.ok(body.error);
  });

  await t.test('rejects files with a disallowed extension', async () => {
    const { res, body } = await postFile(base, 'evil.exe', leaf.pem);
    assert.equal(res.status, 400);
    assert.match(body.error, /Unsupported file type/);
  });

  await t.test('rejects oversized uploads', async () => {
    const { res, body } = await postFile(base, 'big.pem', Buffer.alloc(1024 * 1024 + 10, 'a'));
    assert.equal(res.status, 400);
    assert.match(body.error, /too large/i);
  });
});

test('rate limiting applies to live checks', async t => {
  const { server, base } = await listen(createApp({ auth: noAuth }));
  t.after(() => close(server));
  let lastStatus;
  for (let i = 0; i < 12; i++) {
    const res = await fetch(`${base}/api/check-host`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ host: 'localhost' })
    });
    lastStatus = res.status;
  }
  assert.equal(lastStatus, 429);
});

test('isBlockedAddress covers private and reserved ranges', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '192.168.0.5', '172.16.0.1', '169.254.169.254', '0.0.0.0', '::1', 'fe80::1', 'fd00::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1']) {
    assert.equal(isBlockedAddress(ip), true, ip);
  }
  for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111', '::ffff:8.8.8.8']) {
    assert.equal(isBlockedAddress(ip), false, ip);
  }
});

test('live check endpoint', async t => {
  const blockedApp = await listen(createApp({ auth: noAuth, enableRateLimit: false }));
  t.after(() => close(blockedApp.server));

  const post = (base, body) => fetch(`${base}/api/check-host`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
  }).then(async res => ({ res, body: await res.json() }));

  await t.test('refuses loopback and private targets', async () => {
    for (const host of ['localhost', '127.0.0.1', '10.0.0.1', '169.254.169.254', '[::1]']) {
      const { res, body } = await post(blockedApp.base, { host });
      assert.equal(res.status, 400, host);
      assert.ok(body.error, host);
    }
  });

  await t.test('validates input', async () => {
    assert.match((await post(blockedApp.base, {})).body.error, /hostname/i);
    assert.match((await post(blockedApp.base, { host: 'bad host!' })).body.error, /Invalid hostname/);
    assert.match((await post(blockedApp.base, { host: 'example.com', port: 99999 })).body.error, /Port/);
  });

  // With private targets allowed (test only), check a local TLS server end to end.
  const root = await createCert({ name: 'CN=Live Root', isCA: true });
  const leaf = await createCert({
    name: 'CN=localhost', issuer: root,
    sans: [{ type: 'dns', value: 'localhost' }, { type: 'ip', value: '127.0.0.1' }]
  });
  const tlsServer = tls.createServer({ key: await privateKeyPem(leaf.keys), cert: leaf.pem + root.pem }, s => s.end());
  await new Promise(resolve => tlsServer.listen(0, '127.0.0.1', resolve));
  t.after(() => close(tlsServer));
  const tlsPort = tlsServer.address().port;

  const openApp = await listen(createApp({ auth: noAuth, enableRateLimit: false, allowPrivateHosts: true }));
  t.after(() => close(openApp.server));

  await t.test('fetches and analyses the chain a server presents', async () => {
    const { res, body } = await post(openApp.base, { host: '127.0.0.1', port: tlsPort });
    assert.equal(res.status, 200);
    assert.equal(body.certs.length, 2);
    assert.equal(body.live.port, tlsPort);
    assert.match(body.live.protocol, /^TLSv1\.[23]$/);
    assert.equal(body.live.authorized, false);
    assert.equal(body.chain.status, 'untrusted-root');
    assert.equal(body.hostnameCheck.matches, true);
  });

  await t.test('reports connection failures cleanly', async () => {
    const { res, body } = await post(openApp.base, { host: '127.0.0.1', port: 1 });
    assert.equal(res.status, 400);
    assert.match(body.error, /Could not connect/);
  });
});

test('health and version endpoints', async t => {
  const { server, base } = await listen(createApp({ auth: noAuth, enableRateLimit: false }));
  t.after(() => close(server));
  assert.deepEqual(await (await fetch(`${base}/healthz`)).json(), { status: 'ok' });
  const { version } = await (await fetch(`${base}/api/version`)).json();
  assert.equal(version, require('../package.json').version);
});

test('key pair generation endpoint', async t => {
  const { server, base } = await listen(createApp({ auth: noAuth, enableRateLimit: false }));
  t.after(() => close(server));
  const crypto = require('node:crypto');
  const generate = body => fetch(`${base}/api/generate-keypair`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
  }).then(async res => ({ res, body: await res.json() }));

  const { algorithms } = await (await fetch(`${base}/api/algorithms`)).json();
  assert.deepEqual(algorithms.map(a => a.id), ['RSA-2048', 'RSA-3072', 'RSA-4096', 'ECDSA-P256', 'ECDSA-P384', 'ECDSA-P521', 'Ed25519']);

  for (const { id } of algorithms) {
    await t.test(`${id}: certificate matches its private key and validates`, async () => {
      const { res, body } = await generate({ algorithm: id, commonName: 'gen.test', sans: 'alt.test 10.1.2.3', validityDays: 30 });
      assert.equal(res.status, 200);
      assert.equal(res.headers.get('cache-control'), 'no-store');
      const cert = new crypto.X509Certificate(body.certificatePem);
      assert.ok(cert.verify(cert.publicKey), 'self-signature verifies');
      assert.ok(crypto.createPublicKey(crypto.createPrivateKey(body.privateKeyPem)).equals(cert.publicKey), 'key pair matches');
      assert.ok(crypto.createPublicKey(body.publicKeyPem).equals(cert.publicKey), 'exported public key matches');
      assert.match(cert.subjectAltName, /DNS:alt\.test/);
      assert.match(cert.subjectAltName, /IP Address:10\.1\.2\.3/);
      assert.equal(cert.ca, false);
      assert.match(body.fingerprintSha256, /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);

      // The generated certificate round-trips through the validator.
      const validated = await postText(base, body.certificatePem, { hostname: 'alt.test' });
      assert.equal(validated.body.error, null);
      assert.equal(validated.body.certs[0].valid, true);
      assert.equal(validated.body.hostnameCheck.matches, true);
    });
  }

  await t.test('uses the common name as a SAN when none are given, and honours hash and CA options', async () => {
    const { body } = await generate({ algorithm: 'ECDSA-P384', commonName: 'solo.test', hash: 'SHA-512', isCA: true, organization: 'Acme, Inc.', country: 'us' });
    const cert = new crypto.X509Certificate(body.certificatePem);
    assert.match(cert.subjectAltName, /DNS:solo\.test/);
    assert.equal(cert.ca, true);
    assert.match(cert.subject, /O=Acme\\, Inc\./); // Node escapes the comma in its string form
    assert.match(cert.subject, /C=US/);
    assert.equal(body.hash, 'SHA-512');
  });

  await t.test('generates a CSR or bare keys', async () => {
    const csr = await generate({ algorithm: 'RSA-2048', commonName: 'csr.test', output: 'csr' });
    assert.match(csr.body.csrPem, /BEGIN CERTIFICATE REQUEST/);
    assert.equal(csr.body.certificatePem, null);
    const keys = await generate({ algorithm: 'Ed25519', output: 'keys' });
    assert.equal(keys.body.certificatePem, null);
    assert.match(keys.body.privateKeyPem, /BEGIN PRIVATE KEY/);
  });

  await t.test('rejects invalid input', async () => {
    for (const bad of [
      { algorithm: 'DSA', commonName: 'x.test' },
      { algorithm: 'RSA-2048', commonName: '' },
      { algorithm: 'RSA-2048', commonName: 'x.test', validityDays: 99999 },
      { algorithm: 'RSA-2048', commonName: 'x.test', hash: 'MD5' },
      { algorithm: 'RSA-2048', commonName: 'x.test', sans: 'not a host!!' },
      { algorithm: 'RSA-2048', commonName: 'x.test', country: 'USA' },
      { algorithm: 'RSA-2048', commonName: 'x'.repeat(65) }
    ]) {
      const { res, body } = await generate(bad);
      assert.equal(res.status, 400, JSON.stringify(bad));
      assert.ok(body.error);
    }
  });
});

test('TRUST_PROXY values are converted for Express', () => {
  assert.equal(parseTrustProxy(undefined), undefined);
  assert.equal(parseTrustProxy(''), undefined);
  assert.equal(parseTrustProxy('1'), 1);
  assert.equal(parseTrustProxy(' 2 '), 2);
  assert.equal(parseTrustProxy('true'), true);
  assert.equal(parseTrustProxy('TRUE'), true);
  assert.equal(parseTrustProxy('false'), false);
  assert.equal(parseTrustProxy('loopback, 10.0.0.0/8'), 'loopback, 10.0.0.0/8');

  // Every supported form must produce an app without throwing (the old code crashed on "true" and "1").
  const original = process.env.TRUST_PROXY;
  try {
    for (const value of ['true', '1', 'false', 'loopback, 172.16.0.0/12', '10.0.0.1']) {
      process.env.TRUST_PROXY = value;
      assert.doesNotThrow(() => createApp({ auth: noAuth, enableRateLimit: false }), value);
    }
  } finally {
    if (original === undefined) delete process.env.TRUST_PROXY; else process.env.TRUST_PROXY = original;
  }
});
