const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8').replace(/\r\n/g, '\n');

// Instructions of the final image stage that copy from the build context (not `--from=` stages).
function contextCopies(dockerfile) {
  return dockerfile.split('\n')
    .map(line => line.trim())
    .filter(line => /^COPY\s/i.test(line) && !/--from=/i.test(line))
    .map(line => line.replace(/^COPY\s+(--\S+\s+)*/i, '').split(/\s+/));
}

// Minimal .dockerignore matching: names, trailing "dir/*", "**/name" and "*.ext" patterns, with "!" re-includes.
function isIgnored(file, patterns) {
  let ignored = false;
  for (const raw of patterns) {
    const negate = raw.startsWith('!');
    const pattern = (negate ? raw.slice(1) : raw).replace(/\/$/, '');
    const regex = new RegExp('^' + pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*\//g, '(?:.*/)?').replace(/\*/g, '[^/]*') + '(?:/.*)?$');
    if (regex.test(file)) ignored = !negate;
  }
  return ignored;
}

test('every file the Dockerfile copies exists and is not excluded by .dockerignore', () => {
  const patterns = read('.dockerignore').split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
  const copies = contextCopies(read('Dockerfile'));
  assert.ok(copies.length > 0, 'found COPY instructions');
  for (const parts of copies) {
    for (const source of parts.slice(0, -1).filter(p => !p.startsWith('--'))) {
      const clean = source.replace(/^\.\//, '').replace(/\/$/, '');
      assert.ok(fs.existsSync(path.join(root, clean)), `COPY source "${source}" does not exist`);
      assert.ok(!isIgnored(clean, patterns), `COPY source "${source}" is excluded by .dockerignore, so the image build would fail`);
    }
  }
});

test('nothing is copied into a path that a volume is mounted over', () => {
  const dockerfile = read('Dockerfile');
  const workdir = (/^WORKDIR\s+(\S+)/m.exec(dockerfile.split(/^FROM /m).pop()) || [, '/'])[1];
  const volumes = [...dockerfile.matchAll(/^VOLUME\s+(.+)$/gm)].flatMap(m => m[1].match(/\/[\w./-]+/g) || []);
  const compose = read('docker-compose.yml');
  for (const m of compose.matchAll(/^\s*-\s+[\w.-]+:(\/[\w./-]+)/gm)) volumes.push(m[1]);
  assert.ok(volumes.includes('/app/data'), 'the history volume is declared');

  for (const parts of contextCopies(dockerfile)) {
    const dest = path.posix.resolve(workdir, parts[parts.length - 1]);
    for (const volume of volumes) {
      const clash = dest === volume || dest.startsWith(volume + '/');
      assert.ok(!clash, `COPY destination ${dest} is inside the mounted volume ${volume}; the volume would hide it at runtime`);
    }
  }
});

test('static datasets live outside the history data directory', () => {
  // The history database (and a mounted volume) use data/; the bundled trust datasets must not.
  assert.ok(fs.existsSync(path.join(root, 'trust-data', 'root-stores.json')));
  assert.ok(fs.existsSync(path.join(root, 'trust-data', 'ct-logs.json')));
  assert.ok(!fs.existsSync(path.join(root, 'data', 'root-stores.json')), 'data/ is reserved for the history database');
});
