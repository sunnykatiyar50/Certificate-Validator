const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { createApp } = require('../server');
const { parseChangelog, loadReleaseNotes, CHANGELOG_FILE } = require('../lib/changelog');
const { loadAuthConfig } = require('../lib/auth');
const { noAuth } = require('./helpers');

const SAMPLE = `# Changelog

Intro that is ignored.

## Unreleased

### Added
- Not released yet

## [2.0.0] - 2026-02-02

### Breaking
- First **bold** thing with \`code\`
  continued on a second line
- Second thing

### Fixed
* Star bullets work too

## 1.1.0 - 2026-01-01
- Bullets without a section heading

## 1.0.1 - 2026-01-01

### Changed

## 1.0.0
### Added
- Date is optional
`;

test('parses releases, sections and bullets, newest first', () => {
  const releases = parseChangelog(SAMPLE);
  assert.deepEqual(releases.map(r => r.version), ['2.0.0', '1.1.0', '1.0.0']);
  assert.deepEqual(releases.map(r => r.date), ['2026-02-02', '2026-01-01', null]);
  assert.deepEqual(releases[0].sections.map(s => s.title), ['Breaking', 'Fixed']);
  assert.deepEqual(releases[0].sections[0].items, [
    'First **bold** thing with `code` continued on a second line',
    'Second thing'
  ]);
  assert.deepEqual(releases[0].sections[1].items, ['Star bullets work too']);
  assert.deepEqual(releases[1].sections, [{ title: 'Changes', items: ['Bullets without a section heading'] }]);
});

test('skips Unreleased and releases with no bullets, and tolerates odd input', () => {
  const versions = parseChangelog(SAMPLE).map(r => r.version);
  assert.ok(!versions.includes('Unreleased') && !versions.includes('1.0.1'));
  assert.deepEqual(parseChangelog(''), []);
  assert.deepEqual(parseChangelog('no headings at all\n- just a bullet'), []);
  assert.equal(parseChangelog(SAMPLE.replace(/\n/g, '\r\n'))[0].sections[0].items[1], 'Second thing', 'CRLF files parse the same');
  assert.equal(parseChangelog('## v3.0.0 - 2026-03-03\n- x')[0].version, '3.0.0', 'a leading v is dropped');
});

test('the real CHANGELOG.md is well formed', () => {
  const releases = parseChangelog(fs.readFileSync(CHANGELOG_FILE, 'utf8'));
  assert.ok(releases.length >= 5, 'has release history');
  const seen = new Set();
  for (const r of releases) {
    assert.match(r.version, /^\d+\.\d+\.\d+$/, `version ${r.version}`);
    assert.ok(!seen.has(r.version), `duplicate ${r.version}`);
    seen.add(r.version);
    if (r.date) assert.match(r.date, /^\d{4}-\d{2}-\d{2}$/, `date of ${r.version}`);
    for (const s of r.sections) {
      assert.ok(s.items.length, `empty section ${r.version} ${s.title}`);
      s.items.forEach(item => assert.ok(item.length < 400, `bullet too long in ${r.version}: ${item.slice(0, 40)}`));
    }
  }
  assert.ok(releases.length <= 100);
});

test('loadReleaseNotes returns a capped list, and no notes when the file is missing', () => {
  const notes = loadReleaseNotes();
  assert.ok(notes.length >= 1 && notes.length <= 12);
  assert.deepEqual(loadReleaseNotes('does-not-exist.md'), []);
});

function listen(app) {
  return new Promise(resolve => {
    const server = app.listen(0, '127.0.0.1', () => resolve({ server, base: `http://127.0.0.1:${server.address().port}` }));
  });
}

test('GET /api/release-notes returns the notes for signed-in users only', async t => {
  const open = await listen(createApp({ auth: noAuth, enableRateLimit: false }));
  t.after(() => new Promise(r => open.server.close(r)));
  const res = await fetch(`${open.base}/api/release-notes`);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.version, require('../package.json').version);
  assert.ok(body.releases.length >= 1);
  assert.ok(body.releases[0].sections[0].items.length >= 1);

  const locked = await listen(createApp({
    auth: loadAuthConfig({ ADMIN_PASSWORD: 'admin-password-1', SESSION_SECRET: 'x'.repeat(40) }), enableRateLimit: false
  }));
  t.after(() => new Promise(r => locked.server.close(r)));
  assert.equal((await fetch(`${locked.base}/api/release-notes`)).status, 401);
});
