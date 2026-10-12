#!/usr/bin/env node
// Bump the app version, commit it and tag it. The pushed tag triggers the Docker image release.
//
//   node scripts/release.js patch|minor|major|<x.y.z> [--push]
//   node scripts/release.js --show        print the current version
//
// package.json (repo root) is the single source of truth for the version.
//
// A release is built from the tagged commit, so the script only runs from `main` when it is exactly
// level with `origin/main` and the tree is clean. It never tags a stale or unpushed commit.
// Push the commit and the tag in ONE atomic push (`--push` does this): pushed separately, git can
// reject the branch but still publish the tag, which would build an image from the wrong commit.
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const pkgPath = path.join(root, 'package.json');
const lockPath = path.join(root, 'package-lock.json');
const RELEASE_BRANCH = 'main';
const REMOTE = 'origin';

const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
const fail = message => {
  console.error(message);
  process.exit(1);
};

function readJson(file) {
  const text = fs.readFileSync(file, 'utf8');
  return { data: JSON.parse(text), eol: text.includes('\r\n') ? '\r\n' : '\n' };
}

function writeJson(file, { data, eol }) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2).replace(/\n/g, eol) + eol);
}

function nextVersion(current, bump) {
  if (/^\d+\.\d+\.\d+$/.test(bump)) return bump;
  const [major, minor, patch] = current.split('.').map(Number);
  if (bump === 'major') return `${major + 1}.0.0`;
  if (bump === 'minor') return `${major}.${minor + 1}.0`;
  return `${major}.${minor}.${patch + 1}`;
}

// Refuse to release anything but the exact, current tip of origin/main.
function checkReleasable(tag) {
  const branch = git('rev-parse', '--abbrev-ref', 'HEAD');
  if (branch !== RELEASE_BRANCH) {
    fail(`Releases are made from "${RELEASE_BRANCH}", but you are on "${branch}". Merge your work first, then run:\n  git checkout ${RELEASE_BRANCH} && git pull`);
  }
  if (git('status', '--porcelain')) fail('Working tree is not clean. Commit or stash your changes first.');

  try {
    git('fetch', REMOTE, RELEASE_BRANCH, '--quiet');
  } catch (err) {
    fail(`Could not reach "${REMOTE}" to check that ${RELEASE_BRANCH} is up to date:\n${String(err.stderr || err.message).trim()}`);
  }
  const [behind, ahead] = git('rev-list', '--left-right', '--count', `${REMOTE}/${RELEASE_BRANCH}...HEAD`).split(/\s+/).map(Number);
  if (behind) {
    fail(`Your ${RELEASE_BRANCH} is ${behind} commit${behind === 1 ? '' : 's'} behind ${REMOTE}/${RELEASE_BRANCH}${ahead ? ` (and ${ahead} ahead)` : ''}.\nReleasing now would tag an out-of-date commit. Run this first, then try again:\n  git pull`);
  }
  if (ahead) {
    fail(`Your ${RELEASE_BRANCH} has ${ahead} commit${ahead === 1 ? '' : 's'} that ${ahead === 1 ? 'is' : 'are'} not on ${REMOTE}/${RELEASE_BRANCH}.\nRelease only what has been merged. Push or merge them first, or drop them, then try again.`);
  }

  if (git('tag', '--list', tag)) fail(`Tag ${tag} already exists locally. Delete it first if it is a leftover: git tag -d ${tag}`);
  if (git('ls-remote', '--tags', REMOTE, `refs/tags/${tag}`)) fail(`Tag ${tag} already exists on ${REMOTE}. Pick a new version.`);
}

const args = process.argv.slice(2);
const push = args.includes('--push');
const bump = args.find(a => !a.startsWith('--'));
const pkg = readJson(pkgPath);

if (args.includes('--show')) {
  console.log(pkg.data.version);
  process.exit(0);
}
if (!bump || !/^(major|minor|patch|\d+\.\d+\.\d+)$/.test(bump)) {
  fail('Usage: node scripts/release.js <patch|minor|major|x.y.z> [--push] | --show');
}

const previous = pkg.data.version;
const version = nextVersion(previous, bump);
const tag = `v${version}`;
if (version === previous) fail(`Version is already ${version}.`);
checkReleasable(tag);

pkg.data.version = version;
writeJson(pkgPath, pkg);
const files = ['package.json'];
if (fs.existsSync(lockPath)) {
  const lock = readJson(lockPath);
  lock.data.version = version;
  if (lock.data.packages && lock.data.packages['']) lock.data.packages[''].version = version;
  writeJson(lockPath, lock);
  files.push('package-lock.json');
}

git('add', ...files);
git('commit', '-m', `Release ${tag}`);
git('tag', '-a', tag, '-m', `Release ${tag}`);

console.log(`${previous} -> ${version}`);
const pushCommand = ['push', '--atomic', REMOTE, RELEASE_BRANCH, tag];
if (push) {
  console.log(`Created commit and tag ${tag}. Pushing: git ${pushCommand.join(' ')}`);
  try {
    execFileSync('git', pushCommand, { cwd: root, stdio: 'inherit' });
  } catch (err) {
    fail(`\nThe push failed, so nothing was published (the push is atomic). Fix the problem and run:\n  git ${pushCommand.join(' ')}\nOr undo the release: git reset --hard ${REMOTE}/${RELEASE_BRANCH} && git tag -d ${tag}`);
  }
  console.log(`Published ${tag}. The Docker image build starts on GitHub now.`);
} else {
  console.log(`Created commit and tag ${tag}. To publish the image (one atomic push, so the tag cannot go out without the commit):\n  git ${pushCommand.join(' ')}`);
}
