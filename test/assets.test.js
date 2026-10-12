const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn, spawnSync } = require('node:child_process');
const { createApp } = require('../server');
const { createAssetVersioner } = require('../lib/assets');
const { loadAuthConfig } = require('../lib/auth');

const ROOT = path.join(__dirname, '..');
const sha10 = text => crypto.createHash('sha256').update(text).digest('hex').slice(0, 10);

function tempDir(t, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'assets-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 3 }));
  for (const [name, content] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), content);
  return dir;
}

function listen(app) {
  return new Promise(resolve => {
    const server = app.listen(0, '127.0.0.1', () => resolve({ server, base: `http://127.0.0.1:${server.address().port}` }));
  });
}

test('page references to local .css and .js files get a content fingerprint', t => {
  const dir = tempDir(t, { 'style.css': 'body{}', 'app.js': 'console.log(1)' });
  const { versionPage, hashOf } = createAssetVersioner(dir);
  assert.equal(hashOf('style.css'), sha10('body{}'));

  const html = '<link rel="stylesheet" href="style.css"><script src="app.js"></script>';
  assert.equal(versionPage(html), `<link rel="stylesheet" href="style.css?v=${sha10('body{}')}"><script src="app.js?v=${sha10('console.log(1)')}"></script>`);

  const untouched = [
    '<link href="https://cdn.example.com/x.css">',      // external
    '<script src="/api/thing.js"></script>',            // absolute path
    '<script src="missing.js"></script>',               // no such file
    '<a href="login.html">',                            // not css/js
    '<img src="logo.png">',
    '<link href="../secret.css">',                      // path tricks
    '<link href="style.css?v=1">'                       // already has a query
  ];
  for (const piece of untouched) assert.equal(versionPage(piece), piece, piece);
});

test('the fingerprint changes when a file changes, and is stable otherwise', t => {
  const dir = tempDir(t, { 'style.css': 'body{color:red}' });
  const { hashOf } = createAssetVersioner(dir);
  const first = hashOf('style.css');
  assert.equal(hashOf('style.css'), first);
  fs.writeFileSync(path.join(dir, 'style.css'), 'body{color:blue}');
  const later = new Date(Date.now() + 5000);
  fs.utimesSync(path.join(dir, 'style.css'), later, later);
  assert.notEqual(hashOf('style.css'), first);
  assert.equal(hashOf('nope.css'), null);
  assert.equal(hashOf('../package.json'), null, 'cannot hash files outside the folder');
});

test('pages carry fingerprinted links and assets are cached accordingly', async t => {
  const dir = tempDir(t, {
    'login.html': '<!doctype html><link rel="stylesheet" href="style.css"><script src="login.js"></script>',
    'style.css': 'body{color:red}',
    'login.js': 'void 0;'
  });
  const auth = loadAuthConfig({ ADMIN_PASSWORD: 'admin-password-1', SESSION_SECRET: 'x'.repeat(40) });
  const { server, base } = await listen(createApp({ auth, publicDir: dir, enableRateLimit: false }));
  t.after(() => new Promise(r => server.close(r)));

  const page = await fetch(`${base}/login.html`);
  assert.equal(page.status, 200);
  assert.equal(page.headers.get('cache-control'), 'no-store', 'the page itself is never cached');
  assert.match(page.headers.get('content-type'), /text\/html/);
  const html = await page.text();
  const cssUrl = `style.css?v=${sha10('body{color:red}')}`;
  assert.ok(html.includes(`href="${cssUrl}"`), html);
  assert.ok(html.includes(`src="login.js?v=${sha10('void 0;')}"`), html);

  // A fingerprinted URL may be cached for a year...
  const versioned = await fetch(`${base}/${cssUrl}`);
  assert.equal(versioned.status, 200);
  assert.equal(versioned.headers.get('cache-control'), 'public, max-age=31536000, immutable');
  assert.match(versioned.headers.get('content-type'), /text\/css/);
  assert.equal(await versioned.text(), 'body{color:red}');

  // ...but a bare URL, or a stale fingerprint, must always be revalidated.
  for (const url of ['style.css', 'style.css?v=oldoldold1', 'style.css?v=']) {
    const res = await fetch(`${base}/${url}`);
    assert.equal(res.headers.get('cache-control'), 'no-cache', url);
    assert.equal(await res.text(), 'body{color:red}');
  }
});

test('after an upgrade the new page points at a new URL, and the old URL never serves a cached-forever copy', async t => {
  const dir = tempDir(t, {
    'login.html': '<link rel="stylesheet" href="style.css">',
    'style.css': '/* old styles */'
  });
  const auth = loadAuthConfig({ ADMIN_PASSWORD: 'admin-password-1', SESSION_SECRET: 'x'.repeat(40) });
  const { server, base } = await listen(createApp({ auth, publicDir: dir, enableRateLimit: false }));
  t.after(() => new Promise(r => server.close(r)));

  const oldUrl = /href="([^"]+)"/.exec(await (await fetch(`${base}/login.html`)).text())[1];

  // The stylesheet is replaced by a new release.
  fs.writeFileSync(path.join(dir, 'style.css'), '/* new styles with .login-shell */');
  const later = new Date(Date.now() + 5000);
  fs.utimesSync(path.join(dir, 'style.css'), later, later);

  const newUrl = /href="([^"]+)"/.exec(await (await fetch(`${base}/login.html`)).text())[1];
  assert.notEqual(newUrl, oldUrl, 'the page now links to a different URL, so a cached old copy cannot be used');
  const fresh = await fetch(`${base}/${newUrl}`);
  assert.equal(await fresh.text(), '/* new styles with .login-shell */');
  assert.equal(fresh.headers.get('cache-control'), 'public, max-age=31536000, immutable');

  // A proxy asking for the old URL gets the current file, marked revalidate-always so it is not frozen in a cache.
  const stale = await fetch(`${base}/${oldUrl}`);
  assert.equal(stale.headers.get('cache-control'), 'no-cache');
  assert.equal(await stale.text(), '/* new styles with .login-shell */');
});

test('the real login and app pages link fingerprinted assets that exist', async t => {
  const auth = loadAuthConfig({ ADMIN_PASSWORD: 'admin-password-1', SESSION_SECRET: 'x'.repeat(40) });
  const { server, base } = await listen(createApp({ auth, enableRateLimit: false }));
  t.after(() => new Promise(r => server.close(r)));

  const html = await (await fetch(`${base}/login.html`)).text();
  const links = [...html.matchAll(/(?:href|src)="([\w.-]+\.(?:css|js))\?v=([0-9a-f]{10})"/g)];
  assert.deepEqual(links.map(m => m[1]).sort(), ['login.js', 'style.css', 'theme.js']);
  for (const [, name, hash] of links) {
    const res = await fetch(`${base}/${name}?v=${hash}`);
    assert.equal(res.status, 200, name);
    assert.equal(res.headers.get('cache-control'), 'public, max-age=31536000, immutable', name);
    assert.equal(sha10(fs.readFileSync(path.join(ROOT, 'public', name))), hash, `${name} fingerprint matches the file`);
  }
});

// ---------- startup log ----------

function startServer(env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(ROOT, 'server.js')], {
      cwd: ROOT, env: { PATH: process.env.PATH, PORT: '0', ...env }, stdio: ['ignore', 'pipe', 'pipe']
    });
    let out = '';
    const timer = setTimeout(() => { child.kill(); reject(new Error(`server did not start: ${out}`)); }, 15000);
    child.stdout.on('data', chunk => {
      out += chunk;
      if (out.includes('Server running')) {
        clearTimeout(timer);
        child.kill();
        resolve(out);
      }
    });
    child.on('error', reject);
  });
}

test('the startup log names the version first, then the sign-in mode', async t => {
  const dir = tempDir(t, {});
  const version = require('../package.json').version;
  const out = (await startServer({ AUTH_DISABLED: '1', DATA_DIR: dir })).split('\n');
  assert.equal(out[0], `Certificate Workbench v${version} (Node.js ${process.version})`);
  const ready = out.find(l => l.startsWith('Server running'));
  assert.match(ready, new RegExp(`\\| v${version.replace(/\./g, '\\.')} \\| sign-in DISABLED \\| data `));

  const signedIn = await startServer({ ADMIN_PASSWORD: 'admin-password-1', SESSION_SECRET: 'x'.repeat(40), USERS: 'alice:alice-password,bob:bob-password', DATA_DIR: dir });
  assert.match(signedIn, /sign-in enabled \(1 admin, 2 users\)/);
});

test('an APP_VERSION from the Docker build is what the log reports', async t => {
  const out = await startServer({ AUTH_DISABLED: '1', APP_VERSION: '9.8.7', DATA_DIR: tempDir(t, {}) });
  assert.ok(out.startsWith('Certificate Workbench v9.8.7 '), out);
  // An empty build argument (ENV APP_VERSION=) falls back to package.json instead of printing "v".
  const fallback = await startServer({ AUTH_DISABLED: '1', APP_VERSION: '', DATA_DIR: tempDir(t, {}) });
  assert.ok(fallback.startsWith(`Certificate Workbench v${require('../package.json').version} `), fallback);
});

test('the version is logged even when the start-up fails', () => {
  const result = spawnSync(process.execPath, [path.join(ROOT, 'server.js')], { cwd: ROOT, env: { PATH: process.env.PATH }, encoding: 'utf8', timeout: 15000 });
  assert.equal(result.status, 1);
  assert.ok(result.stdout.startsWith(`Certificate Workbench v${require('../package.json').version} `), result.stdout);
  assert.match(result.stderr, /ADMIN_PASSWORD/);
});
