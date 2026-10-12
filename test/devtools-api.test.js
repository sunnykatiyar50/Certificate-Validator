const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const x509 = require('@peculiar/x509');
const { createApp } = require('../server');
const { noAuth } = require('./helpers');

x509.cryptoProvider.set(crypto.webcrypto);

function listen(app) {
  return new Promise(resolve => {
    const server = app.listen(0, '127.0.0.1', () => resolve({ server, base: `http://127.0.0.1:${server.address().port}` }));
  });
}

// multipart POST like the browser does. `fields` values may be strings or { file: Buffer|string, name }.
async function post(base, path, fields = {}) {
  const form = new FormData();
  for (const [key, value] of Object.entries(fields)) {
    if (value && typeof value === 'object' && 'file' in value) form.append(key, new Blob([value.file]), value.name || 'input.pem');
    else form.append(key, value);
  }
  const res = await fetch(`${base}${path}`, { method: 'POST', body: form });
  return { res, body: await res.json() };
}

const file = (result, name) => {
  const f = result.files.find(x => x.name === name);
  assert.ok(f, `${name} in [${result.files.map(x => x.name).join(', ')}]`);
  return f.encoding === 'text' ? f.content : Buffer.from(f.content, 'base64');
};

async function app(t) {
  const { server, base } = await listen(createApp({ auth: noAuth, enableRateLimit: false }));
  t.after(() => new Promise(r => server.close(r)));
  return base;
}

test('POST /api/dev-cert returns the whole bundle for the defaults', async t => {
  const base = await app(t);
  const { res, body } = await post(base, '/api/dev-cert');
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('cache-control'), 'no-store', 'responses with keys are never cached');
  assert.deepEqual(body.summary.names, ['DNS: localhost', 'IP: 127.0.0.1', 'IP: ::1']);
  assert.equal(body.summary.ca.created, true);
  assert.ok(body.files.some(f => f.name === 'localhost.pfx' && f.encoding === 'base64'));
  assert.ok(body.files.some(f => f.name === 'localhost-dev-cert.zip'));
  assert.match(body.readme, /Trust the CA/);
  const leaf = new crypto.X509Certificate(file(body, 'localhost.pem'));
  assert.ok(leaf.verify(new crypto.X509Certificate(file(body, 'ca.crt')).publicKey));
});

test('POST /api/dev-cert reads every option from the form', async t => {
  const base = await app(t);
  const { res, body } = await post(base, '/api/dev-cert', {
    names: 'app.test, *.api.test 10.9.8.7', algorithm: 'RSA-2048', validityDays: '90', clientAuth: 'true',
    crlUrl: 'http://localhost:9000/ca.crl', bundlePassword: 'my-bundle-pw', caName: 'Team Dev CA', scope: 'names'
  });
  assert.equal(res.status, 200, JSON.stringify(body));
  assert.equal(body.summary.algorithmLabel, 'RSA 2048');
  assert.equal(body.summary.clientAuth, true);
  assert.equal(body.summary.bundlePassword, 'my-bundle-pw');
  assert.equal(body.summary.ca.subject, 'Team Dev CA');
  assert.deepEqual(body.summary.ca.nameConstraints.sort(), ['10.9.8.7/32', 'api.test', 'app.test']);
  assert.equal(body.summary.crlUrl, 'http://localhost:9000/ca.crl');
  assert.deepEqual(new crypto.X509Certificate(file(body, 'app.test.pem')).keyUsage.sort(), ['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2']);
});

test('POST /api/dev-cert can sign with an uploaded or pasted CA, including an encrypted key', async t => {
  const base = await app(t);
  const { body: made } = await post(base, '/api/ca/create', { commonName: 'Uploaded CA' });

  const uploaded = await post(base, '/api/dev-cert', { names: 'one.test', ca: { file: made.certificatePem + made.privateKeyPem, name: 'ca.pem' } });
  assert.equal(uploaded.res.status, 200, JSON.stringify(uploaded.body));
  assert.equal(uploaded.body.summary.ca.created, false);
  assert.equal(uploaded.body.summary.ca.subject, 'CN=Uploaded CA');
  assert.ok(!uploaded.body.files.some(f => f.name === 'ca-key.pem'), 'the uploaded CA key is not echoed back');

  const pasted = await post(base, '/api/dev-cert', { names: 'two.test', caText: made.certificatePem + made.privateKeyPem });
  assert.equal(pasted.res.status, 200);
  assert.equal(pasted.body.summary.ca.created, false);

  const encryptedKey = crypto.createPrivateKey(made.privateKeyPem).export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: 'ca-pass-123' });
  const noPassword = await post(base, '/api/dev-cert', { caText: made.certificatePem + encryptedKey });
  assert.equal(noPassword.res.status, 400);
  assert.match(noPassword.body.error, /encrypted/);
  const withPassword = await post(base, '/api/dev-cert', { caText: made.certificatePem + encryptedKey, caPassword: 'ca-pass-123' });
  assert.equal(withPassword.res.status, 200, JSON.stringify(withPassword.body));
});

test('POST /api/dev-cert reports mistakes as clear 400 errors without leaking anything', async t => {
  const base = await app(t);
  const bad = [
    [{ names: 'someone@example.com' }, /host names and IP addresses/],
    [{ algorithm: 'Ed25519' }, /Algorithm must be one of/],
    [{ validityDays: '9999' }, /between 1 and 825/],
    [{ bundlePassword: 'abc' }, /6 to 128|6 to 64/],
    [{ crlUrl: 'ftp://nope' }, /http:\/\/ or https:\/\//],
    [{ scope: 'galaxy' }, /CA scope/],
    [{ caText: 'not a CA at all' }, /./]
  ];
  for (const [fields, pattern] of bad) {
    const { res, body } = await post(base, '/api/dev-cert', fields);
    assert.equal(res.status, 400, JSON.stringify(fields));
    assert.match(body.error, pattern);
    assert.deepEqual(Object.keys(body), ['error'], 'only an error message is returned');
  }
});

test('POST /api/ca/create accepts name restrictions and POST /api/ca/sign a CRL URL', async t => {
  const base = await app(t);
  const { res, body: ca } = await post(base, '/api/ca/create', { commonName: 'Scoped CA', nameConstraints: 'corp.test 10.0.0.0/8' });
  assert.equal(res.status, 200);
  assert.deepEqual(ca.nameConstraints, ['corp.test', '10.0.0.0/8']);
  assert.ok(new x509.X509Certificate(ca.certificatePem).extensions.some(e => e.type === '2.5.29.30'));
  const bad = await post(base, '/api/ca/create', { commonName: 'Bad Scope CA', nameConstraints: 'bad name!x' });
  assert.equal(bad.res.status, 400);
  assert.match(bad.body.error, /Invalid name restriction/);

  const key = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ type: 'pkcs8', format: 'pem' });
  const csr = await post(base, '/api/csr/create', { key: { file: key, name: 'k.pem' }, commonName: 'host.corp.test' });
  const signed = await post(base, '/api/ca/sign', { csrText: csr.body.csrPem, caText: ca.certificatePem + ca.privateKeyPem, crlUrl: 'https://pki.corp.test/ca.crl' });
  assert.equal(signed.res.status, 200, JSON.stringify(signed.body));
  assert.ok(new x509.X509Certificate(signed.body.certificatePem).getExtension(x509.CRLDistributionPointsExtension));
});

test('POST /api/crl/create: serials, certificates to revoke and carrying over a previous CRL', async t => {
  const base = await app(t);
  const { body: ca } = await post(base, '/api/ca/create', { commonName: 'CRL API CA' });
  const caBundle = ca.certificatePem + ca.privateKeyPem;
  const { body: dev } = await post(base, '/api/dev-cert', { names: 'revokeme.test', caText: caBundle });

  const first = await post(base, '/api/crl/create', {
    caText: caBundle, serials: '0A1B2C keyCompromise', cert: { file: file(dev, 'revokeme.test.pem'), name: 'leaf.pem' }, nextUpdateDays: '14'
  });
  assert.equal(first.res.status, 200, JSON.stringify(first.body));
  assert.equal(first.res.headers.get('cache-control'), 'no-store');
  assert.equal(first.body.summary.crlNumber, '1');
  assert.equal(first.body.summary.entries.length, 2);
  assert.deepEqual(first.body.files.map(f => f.name), ['ca.crl', 'ca.crl.der']);
  assert.match(first.body.files[0].content, /BEGIN X509 CRL/);

  const second = await post(base, '/api/crl/create', {
    ca: { file: caBundle, name: 'ca.pem' }, previous: { file: Buffer.from(first.body.files[1].content, 'base64'), name: 'old.crl' }, serials: 'FF'
  });
  assert.equal(second.res.status, 200, JSON.stringify(second.body));
  assert.equal(second.body.summary.crlNumber, '2');
  assert.equal(second.body.summary.carriedOver, 2);
  assert.equal(second.body.summary.entries.length, 3);

  // The new CRL decodes as valid with the CA certificate.
  const decoded = await post(base, '/api/decode', { text: second.body.files[0].content, caText: ca.certificatePem, files: { file: ca.certificatePem, name: 'ca.pem' } });
  assert.equal(decoded.res.status, 200);
  assert.equal(decoded.body.crls[0].signature, 'valid');
});

test('POST /api/crl/create errors', async t => {
  const base = await app(t);
  const { body: ca } = await post(base, '/api/ca/create', { commonName: 'Err CA' });
  const missingCa = await post(base, '/api/crl/create', { serials: '0A' });
  assert.equal(missingCa.res.status, 400);
  assert.match(missingCa.body.error, /Provide the CA certificate and private key/);
  const noKey = await post(base, '/api/crl/create', { caText: ca.certificatePem, serials: '0A' });
  assert.equal(noKey.res.status, 400);
  assert.match(noKey.body.error, /private key was not found/);
  const badSerial = await post(base, '/api/crl/create', { caText: ca.certificatePem + ca.privateKeyPem, serials: 'zzz' });
  assert.equal(badSerial.res.status, 400);
  assert.match(badSerial.body.error, /Not a valid serial number/);
  const badDays = await post(base, '/api/crl/create', { caText: ca.certificatePem + ca.privateKeyPem, nextUpdateDays: '9999' });
  assert.equal(badDays.res.status, 400);
});

test('POST /api/key-tools: inspect, convert, change the password and fail clearly', async t => {
  const base = await app(t);
  const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
  const pkcs1 = rsa.export({ type: 'pkcs1', format: 'pem' });

  const inspect = await post(base, '/api/key-tools', { text: pkcs1, action: 'inspect' });
  assert.equal(inspect.res.status, 200);
  assert.equal(inspect.res.headers.get('cache-control'), 'no-store');
  assert.equal(inspect.body.summary.keyDescription, 'RSA 2048');
  assert.equal(inspect.body.summary.sourceFormat, 'PKCS#1 (RSA)');

  const encrypted = await post(base, '/api/key-tools', { files: { file: pkcs1, name: 'old.key' }, action: 'pkcs8', newPassword: 'brand-new-pw' });
  assert.equal(encrypted.res.status, 200);
  const encPem = encrypted.body.files[0].content;
  assert.match(encPem, /BEGIN ENCRYPTED PRIVATE KEY/);

  const missing = await post(base, '/api/key-tools', { text: encPem, action: 'inspect' });
  assert.equal(missing.res.status, 400);
  assert.match(missing.body.error, /encrypted/);
  const wrong = await post(base, '/api/key-tools', { text: encPem, password: 'nope-nope', action: 'inspect' });
  assert.equal(wrong.res.status, 400);
  assert.match(wrong.body.error, /Incorrect password/);
  assert.ok(!JSON.stringify(wrong.body).includes('nope-nope'), 'the wrong password is not echoed');

  const removed = await post(base, '/api/key-tools', { text: encPem, password: 'brand-new-pw', action: 'pkcs8' });
  assert.equal(removed.res.status, 200);
  assert.match(removed.body.files[0].content, /BEGIN PRIVATE KEY/);

  const wrongType = await post(base, '/api/key-tools', { text: pkcs1, action: 'sec1' });
  assert.equal(wrongType.res.status, 400);
  assert.match(wrongType.body.error, /SEC1 only holds elliptic curve/);
  const noInput = await post(base, '/api/key-tools', { action: 'inspect' });
  assert.equal(noInput.res.status, 400);
  assert.match(noInput.body.error, /Provide a private key/);
  const notAKey = await post(base, '/api/key-tools', { text: 'hello world', action: 'inspect' });
  assert.equal(notAKey.res.status, 400);
});

test('the dev tools refuse files with unexpected extensions and oversized uploads', async t => {
  const base = await app(t);
  const exe = await post(base, '/api/key-tools', { files: { file: 'x', name: 'virus.exe' } });
  assert.equal(exe.res.status, 400);
  assert.match(exe.body.error, /Unsupported file type/);
  const big = await post(base, '/api/crl/create', { ca: { file: Buffer.alloc(1024 * 1024 + 10, 'a'), name: 'ca.pem' } });
  assert.equal(big.res.status, 400);
  assert.match(big.body.error, /too large/i);
});
