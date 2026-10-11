#!/usr/bin/env node
// Bump the app version, commit it and tag it. The pushed tag triggers the Docker image release.
//
//   node scripts/release.js patch|minor|major|<x.y.z>
//   node scripts/release.js --show        print the current version
//
// backend/package.json is the single source of truth for the version.
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const pkgPath = path.join(root, 'backend', 'package.json');
const lockPath = path.join(root, 'backend', 'package-lock.json');

const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();
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

const bump = process.argv[2];
const pkg = readJson(pkgPath);
if (bump === '--show') {
  console.log(pkg.data.version);
  process.exit(0);
}
if (!bump || !/^(major|minor|patch|\d+\.\d+\.\d+)$/.test(bump)) {
  fail('Usage: node scripts/release.js <patch|minor|major|x.y.z> | --show');
}
if (git('status', '--porcelain')) fail('Working tree is not clean. Commit or stash your changes first.');

const previous = pkg.data.version;
const version = nextVersion(previous, bump);
const tag = `v${version}`;
if (version === previous) fail(`Version is already ${version}.`);
if (git('tag', '--list', tag)) fail(`Tag ${tag} already exists.`);

pkg.data.version = version;
writeJson(pkgPath, pkg);
const files = ['backend/package.json'];
if (fs.existsSync(lockPath)) {
  const lock = readJson(lockPath);
  lock.data.version = version;
  if (lock.data.packages && lock.data.packages['']) lock.data.packages[''].version = version;
  writeJson(lockPath, lock);
  files.push('backend/package-lock.json');
}

git('add', ...files);
git('commit', '-m', `Release ${tag}`);
git('tag', '-a', tag, '-m', `Release ${tag}`);

console.log(`${previous} -> ${version}`);
console.log(`Created commit and tag ${tag}. To publish the image:\n  git push origin HEAD ${tag}`);
