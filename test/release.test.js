const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');

const SCRIPT = path.join(__dirname, '..', 'scripts', 'release.js');

// Isolated git environment: no user or system config (signing, hooks, identities) can leak in.
// (A real empty file is used because os.devNull is not a readable path for git on Windows.)
const EMPTY_CONFIG = path.join(os.tmpdir(), `release-test-empty-gitconfig-${process.pid}`);
fs.writeFileSync(EMPTY_CONFIG, '');
process.on('exit', () => fs.rmSync(EMPTY_CONFIG, { force: true }));
const ENV = {
  ...process.env,
  GIT_CONFIG_GLOBAL: EMPTY_CONFIG,
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_AUTHOR_NAME: 'Test', GIT_AUTHOR_EMAIL: 'test@example.com',
  GIT_COMMITTER_NAME: 'Test', GIT_COMMITTER_EMAIL: 'test@example.com'
};

const git = (cwd, ...args) => execFileSync('git', args, { cwd, env: ENV, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();

// A bare "GitHub", the maintainer's clone with the script, and a teammate's clone.
function sandbox(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'release-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 3 }));
  const origin = path.join(dir, 'origin.git');
  const work = path.join(dir, 'work');
  const teammate = path.join(dir, 'teammate');

  git(dir, 'init', '--bare', '-b', 'main', origin);
  fs.mkdirSync(path.join(work, 'scripts'), { recursive: true });
  git(work, 'init', '-b', 'main');
  fs.copyFileSync(SCRIPT, path.join(work, 'scripts', 'release.js'));
  fs.writeFileSync(path.join(work, 'package.json'), JSON.stringify({ name: 'demo', version: '1.0.0' }, null, 2) + '\n');
  fs.writeFileSync(path.join(work, 'package-lock.json'), JSON.stringify({ name: 'demo', version: '1.0.0', lockfileVersion: 3, packages: { '': { name: 'demo', version: '1.0.0' } } }, null, 2) + '\n');
  git(work, 'add', '-A');
  git(work, 'commit', '-m', 'base');
  git(work, 'remote', 'add', 'origin', origin);
  git(work, 'push', '-u', 'origin', 'main');
  git(dir, 'clone', origin, teammate);

  const release = (...args) => spawnSync(process.execPath, [path.join(work, 'scripts', 'release.js'), ...args], { cwd: work, env: ENV, encoding: 'utf8' });
  const version = () => JSON.parse(fs.readFileSync(path.join(work, 'package.json'), 'utf8')).version;
  // Another person merges a PR on GitHub: origin/main moves ahead of the maintainer's clone.
  const teammateMerges = (file = 'feature.txt') => {
    fs.writeFileSync(path.join(teammate, file), 'change\n');
    git(teammate, 'add', '-A');
    git(teammate, 'commit', '-m', `merged ${file}`);
    git(teammate, 'push', 'origin', 'main');
  };
  const remoteTags = () => git(work, 'ls-remote', '--tags', 'origin').split('\n').filter(l => l && !l.endsWith('^{}')).map(l => l.split('refs/tags/')[1]);
  return { dir, origin, work, teammate, git, release, version, teammateMerges, remoteTags };
}

test('releases an up-to-date main: bumps, commits, tags and prints an atomic push', t => {
  const s = sandbox(t);
  const result = s.release('patch');
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /1\.0\.0 -> 1\.0\.1/);
  assert.match(result.stdout, /git push --atomic origin main v1\.0\.1/);
  assert.equal(s.version(), '1.0.1');
  assert.equal(JSON.parse(fs.readFileSync(path.join(s.work, 'package-lock.json'), 'utf8')).packages[''].version, '1.0.1');
  assert.equal(git(s.work, 'log', '-1', '--format=%s'), 'Release v1.0.1');
  assert.equal(git(s.work, 'tag', '--list', 'v1.0.1'), 'v1.0.1');
  assert.deepEqual(s.remoteTags(), [], 'nothing is pushed without --push');
});

test('--push publishes the commit and tag together', t => {
  const s = sandbox(t);
  const result = s.release('minor', '--push');
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(s.remoteTags(), ['v1.1.0']);
  assert.equal(git(s.work, 'rev-parse', 'origin/main'), git(s.work, 'rev-parse', 'HEAD'));
  assert.equal(git(s.work, 'rev-parse', 'v1.1.0^{commit}'), git(s.work, 'ls-remote', 'origin', 'refs/heads/main').split('\t')[0]);
});

test('supports major and explicit versions', t => {
  const s = sandbox(t);
  assert.equal(s.release('2.5.0').status, 0);
  assert.equal(s.version(), '2.5.0');
  const next = s.release('major');
  assert.equal(next.status, 1, 'the previous release is not on origin yet, so main is ahead');
});

test('REFUSES when local main is behind origin/main (the stale-main mistake)', t => {
  const s = sandbox(t);
  s.teammateMerges();
  const result = s.release('patch');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /1 commit behind origin\/main/);
  assert.match(result.stderr, /git pull/);
  assert.equal(s.version(), '1.0.0', 'package.json untouched');
  assert.equal(git(s.work, 'tag', '--list'), '', 'no tag created');
  assert.equal(git(s.work, 'log', '-1', '--format=%s'), 'base', 'no release commit created');

  // After pulling, the release works and sits on top of the merged work.
  git(s.work, 'pull');
  assert.equal(s.release('patch').status, 0);
  assert.equal(git(s.work, 'log', '-2', '--format=%s').split('\n')[1], 'merged feature.txt');
});

test('REFUSES when local main has commits that are not on origin', t => {
  const s = sandbox(t);
  fs.writeFileSync(path.join(s.work, 'unreviewed.txt'), 'x\n');
  git(s.work, 'add', '-A');
  git(s.work, 'commit', '-m', 'local only');
  const result = s.release('patch');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /1 commit that is not on origin\/main/);
  assert.equal(git(s.work, 'tag', '--list'), '');
});

test('REFUSES when both behind and ahead', t => {
  const s = sandbox(t);
  s.teammateMerges();
  fs.writeFileSync(path.join(s.work, 'local.txt'), 'x\n');
  git(s.work, 'add', '-A');
  git(s.work, 'commit', '-m', 'local only');
  const result = s.release('patch');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /behind origin\/main \(and 1 ahead\)/);
});

test('REFUSES to release from a branch other than main', t => {
  const s = sandbox(t);
  git(s.work, 'checkout', '-b', 'feature/x');
  const result = s.release('patch');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Releases are made from "main", but you are on "feature\/x"/);
  assert.equal(git(s.work, 'tag', '--list'), '');
});

test('REFUSES with uncommitted changes', t => {
  const s = sandbox(t);
  fs.writeFileSync(path.join(s.work, 'dirty.txt'), 'x\n');
  const result = s.release('patch');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /not clean/);
});

test('REFUSES when the tag already exists on origin, even if this clone has not fetched it', t => {
  const s = sandbox(t);
  git(s.teammate, 'tag', '-a', 'v1.0.1', '-m', 'already released');
  git(s.teammate, 'push', 'origin', 'v1.0.1');
  assert.equal(git(s.work, 'tag', '--list'), '', 'this clone does not know the tag');
  const result = s.release('patch');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /v1\.0\.1 already exists on origin/);
  assert.equal(s.version(), '1.0.0');
});

test('REFUSES when the tag already exists locally', t => {
  const s = sandbox(t);
  git(s.work, 'tag', 'v1.0.1');
  const result = s.release('patch');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /already exists locally/);
});

test('reports an unreachable origin instead of releasing blind', t => {
  const s = sandbox(t);
  git(s.work, 'remote', 'set-url', 'origin', path.join(s.dir, 'does-not-exist.git'));
  const result = s.release('patch');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Could not reach "origin"/);
  assert.equal(git(s.work, 'tag', '--list'), '');
});

test('input validation and --show', t => {
  const s = sandbox(t);
  assert.equal(s.release('--show').stdout.trim(), '1.0.0');
  for (const bad of [[], ['bogus'], ['1.2'], ['1.0.0']]) {
    const result = s.release(...bad);
    assert.equal(result.status, 1, JSON.stringify(bad));
  }
  assert.equal(git(s.work, 'tag', '--list'), '');
});

test('an atomic push never sends the tag when the branch is rejected', t => {
  const s = sandbox(t);
  assert.equal(s.release('patch').status, 0, 'release made while up to date');
  s.teammateMerges('raced.txt'); // origin/main moves before the push happens

  // The old command: the tag is published even though the branch is rejected.
  const old = spawnSync('git', ['push', 'origin', 'main', 'v1.0.1'], { cwd: s.work, env: ENV, encoding: 'utf8' });
  assert.notEqual(old.status, 0);
  assert.deepEqual(s.remoteTags(), ['v1.0.1'], 'non-atomic push leaks the tag');
  git(s.work, 'push', 'origin', ':refs/tags/v1.0.1');

  // The command the script now prints: all or nothing.
  const atomic = spawnSync('git', ['push', '--atomic', 'origin', 'main', 'v1.0.1'], { cwd: s.work, env: ENV, encoding: 'utf8' });
  assert.notEqual(atomic.status, 0);
  assert.deepEqual(s.remoteTags(), [], 'atomic push sends neither');
});

test('--push that fails publishes nothing and explains how to recover', t => {
  const s = sandbox(t);
  // Make the push fail after the checks pass: a pre-receive hook on origin rejects everything.
  const hook = path.join(s.origin, 'hooks', 'pre-receive');
  fs.writeFileSync(hook, '#!/bin/sh\necho "rejected by test hook" >&2\nexit 1\n', { mode: 0o755 });
  const result = s.release('patch', '--push');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /nothing was published/);
  assert.match(result.stderr, /git tag -d v1\.0\.1/);
  assert.deepEqual(s.remoteTags(), []);
});
