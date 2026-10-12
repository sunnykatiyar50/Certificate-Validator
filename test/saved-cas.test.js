const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createApp } = require('../server');
const { loadAuthConfig } = require('../lib/auth');
const { HistoryStore } = require('../lib/historyStore');
const { Vault, VaultError, loadVaultKey } = require('../lib/vault');
const { createCa } = require('../lib/ca');
const { generateKeyPair } = require('../lib/keygen');

const env = { ADMIN_USERNAME: 'root', ADMIN_PASSWORD: 'admin-password-1', SESSION_SECRET: 'x'.repeat(40), USERS: 'alice:alice-password,bob:bob-password' };

function listen(app) {
  return new Promise(resolve => {
    const server = app.listen(0, '127.0.0.1', () => resolve({ server, base: `http://127.0.0.1:${server.address().port}` }));
  });
}

// A client that keeps its session cookie and sends the CSRF header, like the browser.
function client(base) {
  let cookie = '';
  const send = async (url, { method = 'GET', json, form } = {}) => {
    const headers = { 'X-Requested-With': 'fetch' };
    if (cookie) headers.cookie = cookie;
    let body;
    if (json !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(json);
    } else if (form) {
      body = new FormData();
      for (const [k, v] of Object.entries(form)) body.append(k, v);
    }
    const res = await fetch(base + url, { method, headers, body });
    for (const c of res.headers.getSetCookie()) cookie = c.split(';')[0];
    let data = null;
    try { data = await res.json(); } catch (e) { /* not JSON */ }
    return { res, data };
  };
  return {
    send,
    login: (username, password) => send('/auth/login', { method: 'POST', json: { username, password } })
  };
}

async function setup(t) {
  const vault = new Vault(':memory:', crypto.randomBytes(32));
  const { server, base } = await listen(createApp({ auth: loadAuthConfig(env), historyStore: new HistoryStore(':memory:'), vault, enableRateLimit: false }));
  t.after(() => new Promise(r => server.close(r)));
  const people = {};
  for (const [name, password] of [['root', 'admin-password-1'], ['alice', 'alice-password'], ['bob', 'bob-password']]) {
    people[name] = client(base);
    await people[name].login(name, password);
  }
  return { vault, ...people };
}

async function myCa(commonName = 'Team CA') {
  return createCa({ commonName, algorithm: 'ECDSA-P256', validityDays: 365 });
}

const pair = ca => ca.certificatePem + ca.privateKeyPem;

// ---------- the vault ----------

test('private keys are encrypted at rest and bound to their owner', t => {
  const key = crypto.randomBytes(32);
  const vault = new Vault(':memory:', key);
  const pem = '-----BEGIN PRIVATE KEY-----\nQUJDREVGR0g=\n-----END PRIVATE KEY-----\n';
  vault.putKey('alice', 'item-1', pem);

  const stored = vault.db.prepare('SELECT key_enc FROM vault WHERE id = ?').get('item-1').key_enc;
  assert.ok(!stored.includes('QUJDREVGR0g'), 'the key is not stored as plain text');
  assert.equal(vault.getKey('alice', 'item-1'), pem);
  assert.equal(vault.getKey('bob', 'item-1'), null, 'another user gets nothing');
  assert.throws(() => vault.putKey('bob', 'item-1', pem), VaultError, 'and cannot overwrite it');

  // Moving a row to another owner must not let that owner decrypt it.
  vault.db.prepare('UPDATE vault SET owner = ? WHERE id = ?').run('bob', 'item-1');
  assert.throws(() => vault.getKey('bob', 'item-1'));

  // A different master key cannot read it either.
  vault.db.prepare('UPDATE vault SET owner = ? WHERE id = ?').run('alice', 'item-1');
  vault.key = crypto.randomBytes(32);
  assert.throws(() => vault.getKey('alice', 'item-1'));
});

test('only unencrypted PKCS#8 keys and PEM certificates are accepted', async () => {
  const vault = new Vault(':memory:', crypto.randomBytes(32));
  assert.throws(() => vault.putKey('alice', 'x', 'not a key'), /PKCS#8/);
  assert.throws(() => vault.putKey('alice', 'x', '-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----'), /PKCS#8/);
  const ca = await myCa();
  assert.throws(() => vault.addCa('alice', { name: '', certificatePem: ca.certificatePem, privateKeyPem: ca.privateKeyPem }), /name/i);
  assert.throws(() => vault.addCa('alice', { name: 'n', certificatePem: 'nope', privateKeyPem: ca.privateKeyPem }), /certificate/i);
});

test('the master key comes from VAULT_KEY or a key file that is created once', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const first = loadVaultKey({ env: {}, dataDir: dir });
  assert.equal(first.length, 32);
  assert.ok(fs.existsSync(path.join(dir, 'vault.key')));
  assert.deepEqual(loadVaultKey({ env: {}, dataDir: dir }), first, 'the same key on the next start');

  const fromEnv = loadVaultKey({ env: { VAULT_KEY: 'k'.repeat(40) }, dataDir: dir });
  assert.equal(fromEnv.length, 32);
  assert.notDeepEqual(fromEnv, first);
  assert.deepEqual(loadVaultKey({ env: { VAULT_KEY: 'k'.repeat(40) }, dataDir: dir }), fromEnv);
  assert.throws(() => loadVaultKey({ env: { VAULT_KEY: 'short' }, dataDir: dir }), /at least 32/);
});

// ---------- uploading a CA ----------

test('/api/cas/check normalises an uploaded CA without storing it', async t => {
  const { alice, vault } = await setup(t);
  const ca = await myCa('Uploaded CA');
  const { res, data } = await alice.send('/api/cas/check', { method: 'POST', form: { caText: pair(ca) } });
  assert.equal(res.status, 200, JSON.stringify(data));
  assert.equal(data.subject, 'Uploaded CA');
  assert.equal(data.selfSigned, true);
  assert.equal(data.keyDescription, 'ECDSA P-256');
  assert.match(data.privateKeyPem, /BEGIN PRIVATE KEY/);
  assert.equal(vault.listCas('alice').length, 0);
});

test('/api/cas/check rejects what cannot sign certificates', async t => {
  const { alice } = await setup(t);
  const leaf = await generateKeyPair({ algorithm: 'ECDSA-P256', commonName: 'leaf.test', output: 'certificate' });
  let r = await alice.send('/api/cas/check', { method: 'POST', form: { caText: leaf.certificatePem + leaf.privateKeyPem } });
  assert.equal(r.res.status, 400);
  assert.match(r.data.error, /not a CA/);

  const ca = await myCa();
  r = await alice.send('/api/cas/check', { method: 'POST', form: { caText: ca.certificatePem } });
  assert.equal(r.res.status, 400);
  assert.match(r.data.error, /private key/);

  r = await alice.send('/api/cas/check', { method: 'POST', form: {} });
  assert.equal(r.res.status, 400);
});

// ---------- saving CAs on the server ----------

test('a CA saved on the server is private to its owner', async t => {
  const { alice, bob, root, vault } = await setup(t);
  const ca = await myCa('Alice CA');
  const saved = await alice.send('/api/cas', { method: 'POST', form: { caText: pair(ca), name: 'My team CA' } });
  assert.equal(saved.res.status, 200, JSON.stringify(saved.data));
  const id = saved.data.ca.id;
  assert.equal(saved.data.ca.name, 'My team CA');
  assert.ok(!JSON.stringify(saved.data).includes('PRIVATE KEY'), 'the response never contains the key');

  const stored = vault.db.prepare('SELECT * FROM vault WHERE id = ?').get(id);
  assert.ok(!JSON.stringify(stored).includes(Buffer.from(ca.privateKeyPem.split('\n')[1]).toString()), 'not plain text in the database');

  const list = await alice.send('/api/cas');
  assert.equal(list.data.cas.length, 1);
  assert.ok(!JSON.stringify(list.data).includes('PRIVATE KEY'));
  assert.deepEqual((await bob.send('/api/cas')).data.cas, []);
  assert.deepEqual((await root.send('/api/cas')).data.cas, [], 'even the admin does not see it');

  assert.equal((await alice.send(`/api/cas/${id}/key`)).data.privateKeyPem, ca.privateKeyPem.trim() + '\n');
  assert.equal((await bob.send(`/api/cas/${id}/key`)).res.status, 404);
  assert.equal((await root.send(`/api/cas/${id}/key`)).res.status, 404);
  assert.equal((await bob.send(`/api/cas/${id}`, { method: 'PATCH', json: { name: 'mine now' } })).res.status, 404);
  assert.equal((await bob.send(`/api/cas/${id}`, { method: 'DELETE' })).res.status, 404);

  const renamed = await alice.send(`/api/cas/${id}`, { method: 'PATCH', json: { name: 'Renamed' } });
  assert.equal(renamed.data.ca.name, 'Renamed');
  assert.equal((await alice.send(`/api/cas/${id}`, { method: 'DELETE' })).res.status, 200);
  assert.deepEqual((await alice.send('/api/cas')).data.cas, []);
});

test('saved-CA routes need a session', async t => {
  const { server, base } = await listen(createApp({ auth: loadAuthConfig(env), historyStore: new HistoryStore(':memory:'), vault: new Vault(':memory:', crypto.randomBytes(32)), enableRateLimit: false }));
  t.after(() => new Promise(r => server.close(r)));
  for (const [method, url] of [['GET', '/api/cas'], ['POST', '/api/cas'], ['POST', '/api/cas/check'], ['POST', '/api/ca/issue'], ['GET', '/api/cas/x/key'], ['DELETE', '/api/cas/x'], ['PUT', '/api/history/x/key'], ['GET', '/api/history/x/key']]) {
    const res = await fetch(base + url, { method, headers: { 'X-Requested-With': 'fetch' } });
    assert.equal(res.status, 401, `${method} ${url}`);
  }
});

// ---------- using a saved CA ----------

test('every CA tool can use a saved CA by id, and only its owner can', async t => {
  const { alice, bob, vault } = await setup(t);
  const ca = await myCa('Saved Signer');
  const id = (await alice.send('/api/cas', { method: 'POST', form: { caText: pair(ca), name: 'Signer' } })).data.ca.id;
  const caCert = new crypto.X509Certificate(ca.certificatePem);

  await t.test('issue a certificate and a new key', async () => {
    const { res, data } = await alice.send('/api/ca/issue', { method: 'POST', form: { caId: id, commonName: 'svc.internal', sans: 'svc.internal, 10.1.2.3', usage: 'both', validityDays: '30', algorithm: 'ECDSA-P256' } });
    assert.equal(res.status, 200, JSON.stringify(data));
    const leaf = new crypto.X509Certificate(data.certificatePem);
    assert.ok(leaf.verify(caCert.publicKey), 'signed by the saved CA');
    assert.ok(leaf.checkPrivateKey(crypto.createPrivateKey(data.privateKeyPem)), 'the new key belongs to the certificate');
    assert.match(leaf.subjectAltName, /DNS:svc\.internal/);
    assert.match(leaf.subjectAltName, /IP Address:10\.1\.2\.3/);
    assert.deepEqual(leaf.keyUsage.sort(), ['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2']);
    assert.equal(data.algorithmLabel, 'ECDSA P-256');
    assert.match(data.fullchainPem, /BEGIN CERTIFICATE[\s\S]*BEGIN CERTIFICATE/);
  });

  await t.test('issue with an RSA key and a CRL URL', async () => {
    const { res, data } = await alice.send('/api/ca/issue', { method: 'POST', form: { caId: id, commonName: 'rsa.test', algorithm: 'RSA-2048', crlUrl: 'http://crl.test/ca.crl' } });
    assert.equal(res.status, 200, JSON.stringify(data));
    assert.equal(data.algorithmLabel, 'RSA 2048');
    assert.match(new crypto.X509Certificate(data.certificatePem).infoAccess || data.certificatePem, /./);
  });

  await t.test('sign a CSR', async () => {
    const csr = await generateKeyPair({ algorithm: 'ECDSA-P256', commonName: 'csr.test', sans: 'csr.test', output: 'csr' });
    const { res, data } = await alice.send('/api/ca/sign', { method: 'POST', form: { caId: id, csrText: csr.csrPem, usage: 'server' } });
    assert.equal(res.status, 200, JSON.stringify(data));
    assert.ok(new crypto.X509Certificate(data.certificatePem).verify(caCert.publicKey));
  });

  await t.test('create an intermediate under it', async () => {
    const { res, data } = await alice.send('/api/ca/create', { method: 'POST', form: { issuerId: id, commonName: 'Sub CA', algorithm: 'ECDSA-P256' } });
    assert.equal(res.status, 200, JSON.stringify(data));
    assert.ok(new crypto.X509Certificate(data.certificatePem).verify(caCert.publicKey));
  });

  await t.test('make a dev certificate', async () => {
    const { res, data } = await alice.send('/api/dev-cert', { method: 'POST', form: { caId: id } });
    assert.equal(res.status, 200, JSON.stringify(data));
    assert.equal(data.summary.ca.created, false);
    assert.equal(data.summary.ca.subject, 'CN=Saved Signer');
  });

  await t.test('create a revocation list', async () => {
    const { res, data } = await alice.send('/api/crl/create', { method: 'POST', form: { caId: id, serials: 'ABCD01' } });
    assert.equal(res.status, 200, JSON.stringify(data));
    assert.deepEqual(data.summary.entries.map(e => e.serialNumber), ['ABCD01']);
  });

  await t.test("another user cannot use someone else's saved CA", async () => {
    for (const [url, form] of [
      ['/api/ca/issue', { caId: id, commonName: 'x.test' }],
      ['/api/dev-cert', { caId: id }],
      ['/api/crl/create', { caId: id, serials: '01' }],
      ['/api/ca/create', { issuerId: id, commonName: 'Sub' }]
    ]) {
      const { res, data } = await bob.send(url, { method: 'POST', form });
      assert.equal(res.status, 400, url);
      assert.match(data.error, /saved CA was not found/);
    }
  });

  await t.test('a deleted CA can no longer be used', async () => {
    vault.delete('alice', id);
    const { res, data } = await alice.send('/api/ca/issue', { method: 'POST', form: { caId: id, commonName: 'late.test' } });
    assert.equal(res.status, 400);
    assert.match(data.error, /not found/);
  });
});

test('/api/ca/issue works with an uploaded CA and checks its input', async t => {
  const { alice } = await setup(t);
  const ca = await myCa();
  const ok = await alice.send('/api/ca/issue', { method: 'POST', form: { caText: pair(ca), commonName: 'upload.test', sans: 'upload.test' } });
  assert.equal(ok.res.status, 200, JSON.stringify(ok.data));
  assert.ok(new crypto.X509Certificate(ok.data.certificatePem).verify(new crypto.X509Certificate(ca.certificatePem).publicKey));

  for (const [form, pattern] of [
    [{ commonName: 'x.test' }, /Choose a CA/],
    [{ caText: pair(ca) }, /Common name/],
    [{ caText: pair(ca), commonName: 'x.test', usage: 'ca' }, /Usage must be/]
  ]) {
    const { res, data } = await alice.send('/api/ca/issue', { method: 'POST', form });
    assert.equal(res.status, 400);
    assert.match(data.error, pattern);
  }
});

// ---------- private keys kept on the server for history items ----------

test('a private key can be kept on the server for a history item, for its owner only', async t => {
  const { alice, bob, root } = await setup(t);
  const k = await generateKeyPair({ algorithm: 'ECDSA-P256', commonName: 'kept.test', output: 'certificate' });
  const entry = (await alice.send('/api/history', { method: 'POST', json: {
    name: 'kept', algorithm: k.algorithm, algorithmLabel: k.algorithmLabel, hash: k.hash, subject: k.subject, sans: k.sans,
    notBefore: k.notBefore, notAfter: k.notAfter, fingerprintSha256: k.fingerprintSha256, certificatePem: k.certificatePem, publicKeyPem: k.publicKeyPem
  } })).data.entry;

  assert.ok(!(await alice.send('/api/history')).data.history[0].keyOnServer);
  assert.equal((await alice.send(`/api/history/${entry.id}/key`)).res.status, 404, 'nothing kept yet');

  const put = await alice.send(`/api/history/${entry.id}/key`, { method: 'PUT', json: { privateKeyPem: k.privateKeyPem } });
  assert.equal(put.res.status, 200, JSON.stringify(put.data));
  assert.equal((await alice.send(`/api/history/${entry.id}/key`)).data.privateKeyPem, k.privateKeyPem);
  assert.equal((await alice.send('/api/history')).data.history[0].keyOnServer, true);
  assert.ok(!JSON.stringify((await root.send('/api/history')).data).includes('PRIVATE KEY'), 'the history list never carries keys');

  for (const person of [bob, root]) {
    assert.equal((await person.send(`/api/history/${entry.id}/key`)).res.status, 404);
    assert.equal((await person.send(`/api/history/${entry.id}/key`, { method: 'PUT', json: { privateKeyPem: k.privateKeyPem } })).res.status, 404);
  }
  assert.equal((await alice.send(`/api/history/${entry.id}/key`, { method: 'PUT', json: { privateKeyPem: 'junk' } })).res.status, 400);

  // Deleting the item (even by an admin) deletes the key with it.
  assert.equal((await root.send(`/api/history/${entry.id}`, { method: 'DELETE' })).res.status, 200);
  assert.equal((await alice.send(`/api/history/${entry.id}/key`)).res.status, 404);
});

test('removing a kept key, and clearing history, removes the keys held on the server', async t => {
  const { alice, vault } = await setup(t);
  const k = await generateKeyPair({ algorithm: 'ECDSA-P256', commonName: 'a.test', output: 'certificate' });
  const add = async name => (await alice.send('/api/history', { method: 'POST', json: {
    name, algorithm: k.algorithm, algorithmLabel: k.algorithmLabel, subject: k.subject, notBefore: k.notBefore, notAfter: k.notAfter,
    certificatePem: k.certificatePem, publicKeyPem: k.publicKeyPem
  } })).data.entry.id;
  const one = await add('one');
  const two = await add('two');
  for (const id of [one, two]) await alice.send(`/api/history/${id}/key`, { method: 'PUT', json: { privateKeyPem: k.privateKeyPem } });
  assert.equal(vault.keyIds('alice').length, 2);

  await alice.send(`/api/history/${one}/key`, { method: 'DELETE' });
  assert.deepEqual(vault.keyIds('alice'), [two]);
  await alice.send('/api/history', { method: 'DELETE' });
  assert.deepEqual(vault.keyIds('alice'), []);
});
