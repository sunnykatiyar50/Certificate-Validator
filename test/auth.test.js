const test = require('node:test');
const assert = require('node:assert/strict');
const { createApp } = require('../server');
const { loadAuthConfig, hashPassword, verifyPassword, createToken, readToken, AuthConfigError, COOKIE_NAME } = require('../lib/auth');
const { HistoryStore, MAX_ENTRIES_PER_OWNER } = require('../lib/historyStore');
const { generateKeyPair } = require('../lib/keygen');

const SECRET = 'x'.repeat(40);
const baseEnv = { ADMIN_USERNAME: 'root', ADMIN_PASSWORD: 'admin-password-1', SESSION_SECRET: SECRET };
const usersEnv = { ...baseEnv, USERS: 'alice:alice-password,bob:bob-password' };

function listen(app) {
  return new Promise(resolve => {
    const server = app.listen(0, '127.0.0.1', () => resolve({ server, base: `http://127.0.0.1:${server.address().port}` }));
  });
}
const close = server => new Promise(resolve => server.close(resolve));

// A tiny HTTP client that keeps the session cookie between requests.
function client(base) {
  let cookie = '';
  async function request(path, { method = 'GET', json, csrf = true, headers = {}, cookieOverride } = {}) {
    const h = { ...headers };
    const sent = cookieOverride !== undefined ? cookieOverride : cookie;
    if (sent) h.cookie = sent;
    if (csrf && method !== 'GET') h['X-Requested-With'] = 'fetch';
    let body;
    if (json !== undefined) {
      h['Content-Type'] = 'application/json';
      body = JSON.stringify(json);
    }
    const res = await fetch(base + path, { method, headers: h, body, redirect: 'manual' });
    const setCookie = res.headers.getSetCookie();
    for (const c of setCookie) {
      const pair = c.split(';')[0];
      cookie = /;\s*Expires=Thu, 01 Jan 1970/i.test(c) || pair.endsWith('=') ? '' : pair;
    }
    let data = null;
    try { data = await res.json(); } catch (e) { /* not JSON */ }
    return { res, data, setCookie };
  }
  return {
    request,
    login: (username, password) => request('/auth/login', { method: 'POST', json: { username, password } }),
    get cookie() { return cookie; }
  };
}

async function sampleEntry(name, extra = {}) {
  const k = await generateKeyPair({ algorithm: 'ECDSA-P256', commonName: 'hist.test' });
  return {
    name, algorithm: k.algorithm, algorithmLabel: k.algorithmLabel, hash: k.hash, subject: k.subject, sans: k.sans,
    notBefore: k.notBefore, notAfter: k.notAfter, fingerprintSha256: k.fingerprintSha256,
    certificatePem: k.certificatePem, publicKeyPem: k.publicKeyPem, ...extra
  };
}

// Every state-changing API route. All of them must require a session and the CSRF header.
const TOOL_POSTS = [
  '/api/validate-certificate', '/api/check-host', '/api/generate-keypair', '/api/history',
  '/api/convert', '/api/decode', '/api/csr/create', '/api/ca/create', '/api/ca/sign'
];

// ---------- configuration ----------

test('auth configuration is validated at startup', () => {
  const cfg = loadAuthConfig(usersEnv);
  assert.equal(cfg.disabled, false);
  assert.deepEqual(cfg.accounts.map(a => [a.username, a.role]), [['root', 'admin'], ['alice', 'user'], ['bob', 'user']]);
  assert.equal(cfg.ttlMs, 12 * 3600 * 1000);
  assert.equal(loadAuthConfig({ ...baseEnv, SESSION_TTL_HOURS: '2' }).ttlMs, 2 * 3600 * 1000);
  assert.equal(loadAuthConfig({ AUTH_DISABLED: '1' }).disabled, true);
  assert.equal(loadAuthConfig({ ...baseEnv, ADMIN_USERNAME: undefined }).accounts[0].username, 'admin');

  const bad = [
    [{ SESSION_SECRET: SECRET }, /ADMIN_PASSWORD/],
    [{ ...baseEnv, ADMIN_PASSWORD: 'short' }, /ADMIN_PASSWORD.*at least 8/],
    [{ ...baseEnv, ADMIN_PASSWORD: 'change-me-please' }, /placeholder/],
    [{ ...baseEnv, SESSION_SECRET: 'too-short' }, /SESSION_SECRET/],
    [{ ...baseEnv, SESSION_SECRET: 'change-me'.padEnd(40, 'x') }, /SESSION_SECRET/],
    [{ ...baseEnv, SESSION_TTL_HOURS: '0' }, /SESSION_TTL_HOURS/],
    [{ ...baseEnv, USERS: 'bad name:password1' }, /invalid username/],
    [{ ...baseEnv, USERS: 'alice' }, /password is missing/],
    [{ ...baseEnv, USERS: 'alice:short' }, /at least 8/],
    [{ ...baseEnv, USERS: 'ROOT:password-123' }, /Duplicate username/],
    [{ ...baseEnv, USERS: 'alice:password-1,Alice:password-2' }, /Duplicate username/]
  ];
  for (const [env, pattern] of bad) {
    assert.throws(() => loadAuthConfig(env), err => err instanceof AuthConfigError && pattern.test(err.message), JSON.stringify(env));
  }
});

test('passwords can be plain text or scrypt hashes', () => {
  const hash = hashPassword('correct horse');
  assert.match(hash, /^scrypt:\d+:\d+:\d+:[\w-]+:[\w-]+$/);
  assert.ok(!/[$,\s]/.test(hash), 'safe for .env files, Compose and the USERS list');
  assert.notEqual(hashPassword('correct horse'), hash, 'salted');
  assert.equal(verifyPassword(hash, 'correct horse'), true);
  assert.equal(verifyPassword(hash, 'wrong'), false);
  assert.equal(verifyPassword('plain-secret', 'plain-secret'), true);
  assert.equal(verifyPassword('plain-secret', 'plain-secreT'), false);
  assert.equal(verifyPassword('scrypt:1:2', 'x'), false);
  assert.equal(verifyPassword('scrypt:16384:8:1::', 'x'), false);

  // A hashed password works in config (no length rule applies to the hash itself).
  const cfg = loadAuthConfig({ ...baseEnv, USERS: `carol:${hash}` });
  assert.equal(cfg.accounts[1].password, hash);
});

test('session tokens are signed, expire, and die when the password changes', () => {
  const cfg = loadAuthConfig(usersEnv);
  const alice = cfg.accounts[1];
  const token = createToken(cfg, alice);
  assert.deepEqual(readToken(cfg, token), { username: 'alice', role: 'user' });

  assert.equal(readToken(cfg, token.slice(0, -2) + 'xx'), null, 'tampered signature');
  const [body, mac] = token.split('.');
  const forged = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(body, 'base64url')), r: 'admin' })).toString('base64url');
  assert.equal(readToken(cfg, `${forged}.${mac}`), null, 'role cannot be changed');
  assert.equal(readToken(cfg, createToken(cfg, alice, Date.now() - 13 * 3600 * 1000)), null, 'expired');
  assert.equal(readToken(cfg, ''), null);
  assert.equal(readToken(cfg, 'garbage'), null);
  assert.equal(readToken(cfg, undefined), null);

  const changed = loadAuthConfig({ ...usersEnv, USERS: 'alice:a-new-password,bob:bob-password' });
  assert.equal(readToken(changed, token), null, 'new password invalidates old sessions');
  const removed = loadAuthConfig({ ...usersEnv, USERS: 'bob:bob-password' });
  assert.equal(readToken(removed, token), null, 'removed users are signed out');
  const otherSecret = loadAuthConfig({ ...usersEnv, SESSION_SECRET: 'y'.repeat(40) });
  assert.equal(readToken(otherSecret, token), null, 'different secret');
});

// ---------- login, sessions and route protection ----------

test('login, sessions and route protection', async t => {
  const hashed = hashPassword('hashed-user-pass');
  const { server, base } = await listen(createApp({
    auth: loadAuthConfig({ ...usersEnv, USERS: `alice:alice-password,hank:${hashed}` }),
    historyStore: new HistoryStore(':memory:'),
    enableRateLimit: false
  }));
  t.after(() => close(server));

  await t.test('signed-out visitors only reach public endpoints and the login page', async () => {
    const c = client(base);
    assert.equal((await c.request('/healthz')).res.status, 200);
    assert.equal((await c.request('/api/version')).res.status, 200);
    assert.equal((await c.request('/login.html')).res.status, 200);
    assert.equal((await c.request('/style.css')).res.status, 200);
    const home = await c.request('/');
    assert.equal(home.res.status, 302);
    assert.equal(home.res.headers.get('location'), '/login.html');
    assert.equal((await c.request('/index.html')).res.status, 302);
    assert.deepEqual((await c.request('/auth/status')).data, { authenticated: false });
    for (const path of ['/api/algorithms', '/api/history']) {
      const { res, data } = await c.request(path);
      assert.equal(res.status, 401, path);
      assert.match(data.error, /Authentication required/);
    }
    for (const path of TOOL_POSTS) {
      assert.equal((await c.request(path, { method: 'POST', json: {} })).res.status, 401, path);
    }
  });

  await t.test('rejects bad credentials without revealing which part was wrong', async () => {
    const c = client(base);
    const wrongPass = await c.login('root', 'nope-nope-nope');
    const wrongUser = await c.login('nobody', 'admin-password-1');
    assert.equal(wrongPass.res.status, 401);
    assert.equal(wrongUser.res.status, 401);
    assert.equal(wrongPass.data.error, wrongUser.data.error);
    assert.equal(wrongPass.setCookie.length, 0);
    assert.equal((await c.login('', '')).res.status, 400);
    assert.equal((await c.request('/auth/login', { method: 'POST', json: { username: 'root', password: ['x'] } })).res.status, 400);
    assert.equal((await c.request('/auth/login', { method: 'POST', json: { username: 'root', password: 'x'.repeat(300) } })).res.status, 400);
    assert.equal((await c.request('/auth/login', { method: 'POST', json: { username: 'root', password: 'admin-password-1' }, csrf: false })).res.status, 403);
  });

  await t.test('admin, plain and hashed users can sign in; the cookie is hardened', async () => {
    for (const [user, pass, role, name] of [['root', 'admin-password-1', 'admin', 'root'], ['ALICE', 'alice-password', 'user', 'alice'], ['hank', 'hashed-user-pass', 'user', 'hank']]) {
      const c = client(base);
      const { res, data, setCookie } = await c.login(user, pass);
      assert.equal(res.status, 200, user);
      assert.deepEqual(data, { username: name, role });
      assert.equal(setCookie.length, 1);
      assert.ok(setCookie[0].startsWith(`${COOKIE_NAME}=`));
      assert.match(setCookie[0], /HttpOnly/i);
      assert.match(setCookie[0], /SameSite=Strict/i);
      assert.match(setCookie[0], /Max-Age=43200/);
      assert.deepEqual((await c.request('/auth/status')).data, { authenticated: true, username: name, role, authDisabled: false });
    }
  });

  await t.test('a signed-in user reaches the app and the API', async () => {
    const c = client(base);
    await c.login('alice', 'alice-password');
    const home = await c.request('/');
    assert.equal(home.res.status, 200);
    assert.equal(home.res.headers.get('cache-control'), 'no-store');
    assert.equal((await c.request('/login.html')).res.headers.get('location'), '/');
    assert.equal((await c.request('/api/algorithms')).res.status, 200);
    const gen = await c.request('/api/generate-keypair', { method: 'POST', json: { algorithm: 'Ed25519', commonName: 'ok.test' } });
    assert.equal(gen.res.status, 200);
    assert.match(gen.data.privateKeyPem, /BEGIN PRIVATE KEY/);
  });

  await t.test('writes need the X-Requested-With header (CSRF defence)', async () => {
    const c = client(base);
    await c.login('alice', 'alice-password');
    const { res, data } = await c.request('/api/generate-keypair', { method: 'POST', json: { algorithm: 'Ed25519', commonName: 'ok.test' }, csrf: false });
    assert.equal(res.status, 403);
    assert.match(data.error, /X-Requested-With/);
    for (const path of TOOL_POSTS) {
      assert.equal((await c.request(path, { method: 'POST', json: {}, csrf: false })).res.status, 403, `${path} without the CSRF header`);
    }
    assert.equal((await c.request('/auth/logout', { method: 'POST', csrf: false })).res.status, 403);
    assert.equal((await c.request('/api/history', { method: 'DELETE', csrf: false })).res.status, 403);
  });

  await t.test('tampered, forged and cleared cookies are rejected', async () => {
    const c = client(base);
    await c.login('alice', 'alice-password');
    const good = c.cookie;
    assert.equal((await c.request('/api/algorithms', { cookieOverride: good.slice(0, -3) + 'AAA' })).res.status, 401);
    assert.equal((await c.request('/api/algorithms', { cookieOverride: `${COOKIE_NAME}=abc.def` })).res.status, 401);
    assert.equal((await c.request('/api/algorithms', { cookieOverride: 'other=1' })).res.status, 401);
    assert.equal((await c.request('/api/algorithms')).res.status, 200);
  });

  await t.test('logout clears the cookie', async () => {
    const c = client(base);
    await c.login('alice', 'alice-password');
    const { res, setCookie } = await c.request('/auth/logout', { method: 'POST' });
    assert.equal(res.status, 200);
    assert.match(setCookie[0], /Expires=Thu, 01 Jan 1970/i);
    assert.equal(c.cookie, '');
    assert.equal((await c.request('/api/algorithms')).res.status, 401);
  });
});

test('failed logins are rate limited, successful ones are not counted', async t => {
  const { server, base } = await listen(createApp({
    auth: loadAuthConfig(usersEnv), historyStore: new HistoryStore(':memory:')
  }));
  t.after(() => close(server));
  const c = client(base);
  for (let i = 0; i < 5; i++) assert.equal((await c.login('root', 'admin-password-1')).res.status, 200);
  let last;
  for (let i = 0; i < 11; i++) last = await c.login('root', 'wrong-password');
  assert.equal(last.res.status, 429);
  assert.match(last.data.error, /Too many failed/);
});

test('with AUTH_DISABLED everyone is the local admin', async t => {
  const { server, base } = await listen(createApp({
    auth: loadAuthConfig({ AUTH_DISABLED: '1' }), historyStore: new HistoryStore(':memory:'), enableRateLimit: false
  }));
  t.after(() => close(server));
  const c = client(base);
  assert.equal((await c.request('/')).res.status, 200);
  assert.deepEqual((await c.request('/auth/status')).data, { authenticated: true, username: 'local', role: 'admin', authDisabled: true });
  assert.equal((await c.request('/api/algorithms')).res.status, 200);
  assert.equal((await c.request('/login.html')).res.headers.get('location'), '/');
});

test('responses carry security headers', async t => {
  const { server, base } = await listen(createApp({ auth: loadAuthConfig(usersEnv), historyStore: new HistoryStore(':memory:'), enableRateLimit: false }));
  t.after(() => close(server));
  const { res } = await client(base).request('/login.html');
  const csp = res.headers.get('content-security-policy');
  assert.match(csp, /default-src 'self'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.ok(!/upgrade-insecure-requests/.test(csp), 'plain-HTTP deployments must keep working');
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('x-powered-by'), null);
});

// ---------- history: users see their own items, admins see everyone's ----------

test('history visibility and ownership', async t => {
  const { server, base } = await listen(createApp({
    auth: loadAuthConfig(usersEnv), historyStore: new HistoryStore(':memory:'), enableRateLimit: false
  }));
  t.after(() => close(server));

  const admin = client(base), alice = client(base), bob = client(base);
  await admin.login('root', 'admin-password-1');
  await alice.login('alice', 'alice-password');
  await bob.login('bob', 'bob-password');

  const a1 = (await alice.request('/api/history', { method: 'POST', json: await sampleEntry('alice cert') })).data.entry;
  const a2 = (await alice.request('/api/history', { method: 'POST', json: await sampleEntry('alice second') })).data.entry;
  const b1 = (await bob.request('/api/history', { method: 'POST', json: await sampleEntry('bob cert') })).data.entry;
  const r1 = (await admin.request('/api/history', { method: 'POST', json: await sampleEntry('admin cert') })).data.entry;

  await t.test('stores the entry under the signed-in user', () => {
    assert.equal(a1.owner, 'alice');
    assert.equal(b1.owner, 'bob');
    assert.equal(r1.owner, 'root');
    assert.equal(a1.name, 'alice cert');
    assert.match(a1.certificatePem, /BEGIN CERTIFICATE/);
    assert.equal(a1.privateKeyPem, undefined);
  });

  const names = list => list.history.map(e => e.name).sort();

  await t.test('users see only their own history', async () => {
    assert.deepEqual(names((await alice.request('/api/history')).data), ['alice cert', 'alice second']);
    assert.deepEqual(names((await bob.request('/api/history')).data), ['bob cert']);
    // The owner filter is ignored for non-admins.
    assert.deepEqual(names((await bob.request('/api/history?owner=alice')).data), ['bob cert']);
  });

  await t.test('admin sees everyone\'s history and can filter by user', async () => {
    const all = (await admin.request('/api/history')).data;
    assert.deepEqual(names(all), ['admin cert', 'alice cert', 'alice second', 'bob cert']);
    assert.deepEqual(all.history.map(e => e.owner).sort(), ['alice', 'alice', 'bob', 'root']);
    assert.deepEqual(all.user, { username: 'root', role: 'admin' });
    assert.deepEqual(names((await admin.request('/api/history?owner=alice')).data), ['alice cert', 'alice second']);
    assert.deepEqual(names((await admin.request('/api/history?owner=nobody')).data), []);
  });

  await t.test('users cannot see, rename or delete other users\' items', async () => {
    assert.equal((await bob.request(`/api/history/${a1.id}`, { method: 'PATCH', json: { name: 'hijacked' } })).res.status, 404);
    assert.equal((await bob.request(`/api/history/${a1.id}`, { method: 'DELETE' })).res.status, 404);
    assert.equal((await alice.request(`/api/history/${b1.id}`, { method: 'DELETE' })).res.status, 404);
    assert.equal((await alice.request('/api/history/does-not-exist', { method: 'DELETE' })).res.status, 404);
    assert.deepEqual(names((await alice.request('/api/history')).data), ['alice cert', 'alice second']);
  });

  await t.test('owners can rename and delete their own items', async () => {
    const renamed = await alice.request(`/api/history/${a2.id}`, { method: 'PATCH', json: { name: '  renamed  ' } });
    assert.equal(renamed.res.status, 200);
    assert.equal(renamed.data.entry.name, 'renamed');
    assert.equal((await alice.request(`/api/history/${a2.id}`, { method: 'PATCH', json: { name: '' } })).res.status, 400);
    assert.equal((await alice.request(`/api/history/${a2.id}`, { method: 'DELETE' })).res.status, 200);
    assert.deepEqual(names((await alice.request('/api/history')).data), ['alice cert']);
  });

  await t.test('admin can remove any item', async () => {
    assert.equal((await admin.request(`/api/history/${b1.id}`, { method: 'DELETE' })).res.status, 200);
    assert.deepEqual(names((await bob.request('/api/history')).data), []);
  });

  await t.test('clearing history only clears the caller\'s own items', async () => {
    await bob.request('/api/history', { method: 'POST', json: await sampleEntry('bob again') });
    const cleared = await alice.request('/api/history', { method: 'DELETE' });
    assert.equal(cleared.data.deleted, 1);
    assert.deepEqual(names((await bob.request('/api/history')).data), ['bob again']);
    assert.deepEqual(names((await admin.request('/api/history')).data), ['admin cert', 'bob again']);
  });

  await t.test('the server refuses private keys and malformed entries', async () => {
    const entry = await sampleEntry('with key');
    const withKey = await alice.request('/api/history', { method: 'POST', json: { ...entry, privateKeyPem: '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----' } });
    assert.equal(withKey.res.status, 400);
    assert.match(withKey.data.error, /never stored/);
    for (const bad of [
      { ...entry, name: '' },
      { ...entry, name: 'x'.repeat(81) },
      { ...entry, algorithm: undefined },
      { ...entry, certificatePem: 'not pem' },
      { ...entry, certificatePem: entry.certificatePem + 'A'.repeat(21000) },
      { ...entry, notAfter: 'tomorrow-ish' },
      { ...entry, sans: 'not-a-list' },
      { ...entry, sans: Array(51).fill('a.test') }
    ]) {
      assert.equal((await alice.request('/api/history', { method: 'POST', json: bad })).res.status, 400, JSON.stringify(bad).slice(0, 80));
    }
    assert.equal((await alice.request('/api/history', { method: 'POST', json: [] })).res.status, 400);
    assert.deepEqual(names((await alice.request('/api/history')).data), []);
  });

  await t.test('unknown fields are dropped before storing', async () => {
    const saved = (await alice.request('/api/history', { method: 'POST', json: { ...(await sampleEntry('extras')), owner: 'root', evil: '<script>', id: 'custom' } })).data.entry;
    assert.equal(saved.owner, 'alice');
    assert.notEqual(saved.id, 'custom');
    assert.equal(saved.evil, undefined);
  });
});

test('history store enforces a per-user limit and persists to disk', async t => {
  const store = new HistoryStore(':memory:');
  const entry = await sampleEntry('bulk');
  for (let i = 0; i < MAX_ENTRIES_PER_OWNER; i++) store.add('alice', entry);
  assert.throws(() => store.add('alice', entry), err => err.status === 409 && /full/.test(err.message));
  assert.doesNotThrow(() => store.add('bob', entry), 'limits are per user');
  store.close();

  const fs = require('node:fs');
  const os = require('node:os');
  const path = require('node:path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'certval-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'nested', 'history.db');
  const first = new HistoryStore(file);
  const saved = first.add('alice', entry);
  first.close();
  const second = new HistoryStore(file);
  assert.equal(second.get(saved.id).name, 'bulk');
  second.close();
});

test('the server refuses to start with missing or weak authentication settings', () => {
  const { spawnSync } = require('node:child_process');
  const path = require('node:path');
  const run = env => spawnSync(process.execPath, [path.join(__dirname, '..', 'server.js')], {
    env: { PATH: process.env.PATH, PORT: '0', ...env }, encoding: 'utf8', timeout: 15000
  });

  const missing = run({});
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /ADMIN_PASSWORD/);
  assert.match(missing.stderr, /SESSION_SECRET/);
  assert.match(missing.stderr, /AUTH_DISABLED/);

  const weak = run({ ADMIN_PASSWORD: 'short', SESSION_SECRET: 'tiny', USERS: 'alice:x' });
  assert.equal(weak.status, 1);
  assert.match(weak.stderr, /at least 8/);
});
