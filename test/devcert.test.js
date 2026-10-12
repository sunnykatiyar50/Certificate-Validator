const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const tls = require('node:tls');
const zlib = require('node:zlib');
const x509 = require('@peculiar/x509');
const { issueDevCertificate, DevCertError } = require('../lib/devcert');
const { createCa, signCsr, createCsr, CaError } = require('../lib/ca');
const { createZip } = require('../lib/zip');
const { readJks } = require('../lib/jks');
const { extractBundle } = require('../lib/bundle');
const { networkBytes, ipBytes, parseConstraintText, constraintsFor } = require('../lib/nameConstraints');

x509.cryptoProvider.set(crypto.webcrypto);

const file = (result, name) => {
  const f = result.files.find(x => x.name === name);
  assert.ok(f, `file ${name} in [${result.files.map(x => x.name).join(', ')}]`);
  return f.encoding === 'text' ? f.content : Buffer.from(f.content, 'base64');
};

// Read a ZIP back: the central directory is the source of truth, and every entry is checked against its CRC.
function readZip(buffer) {
  const end = buffer.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  assert.ok(end >= 0, 'end of central directory');
  const count = buffer.readUInt16LE(end + 10);
  let offset = buffer.readUInt32LE(end + 16);
  const entries = new Map();
  for (let i = 0; i < count; i++) {
    assert.equal(buffer.readUInt32LE(offset), 0x02014b50, 'central header');
    const method = buffer.readUInt16LE(offset + 10);
    const crc = buffer.readUInt32LE(offset + 16);
    const size = buffer.readUInt32LE(offset + 24);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const localOffset = buffer.readUInt32LE(offset + 42);
    const name = buffer.toString('utf8', offset + 46, offset + 46 + nameLength);
    assert.equal(method, 0, 'stored');
    assert.equal(buffer.readUInt32LE(localOffset), 0x04034b50, 'local header');
    const localNameLength = buffer.readUInt16LE(localOffset + 26);
    const localExtra = buffer.readUInt16LE(localOffset + 28);
    const start = localOffset + 30 + localNameLength + localExtra;
    const data = buffer.subarray(start, start + size);
    assert.equal(zlib.crc32(data), crc, `crc of ${name}`);
    entries.set(name, data);
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

// ---------- ZIP ----------

test('createZip writes a valid archive that reads back byte for byte', () => {
  const zip = createZip([
    { name: 'a.txt', content: 'hello' },
    { name: 'dir/b.bin', content: Buffer.from([0, 1, 2, 255]) },
    { name: 'unicode-é.txt', content: 'ünï' }
  ]);
  const entries = readZip(zip);
  assert.deepEqual([...entries.keys()], ['a.txt', 'dir/b.bin', 'unicode-é.txt']);
  assert.equal(entries.get('a.txt').toString(), 'hello');
  assert.deepEqual([...entries.get('dir/b.bin')], [0, 1, 2, 255]);
  assert.equal(entries.get('unicode-é.txt').toString('utf8'), 'ünï');
});

test('createZip refuses unsafe, duplicate and empty input', () => {
  for (const name of ['../evil', '/abs', 'a/../b', '', 'a//b', 'bad\u0000name', 'x\\..\\y']) {
    assert.throws(() => createZip([{ name, content: 'x' }]), /Unsafe file name/, JSON.stringify(name));
  }
  assert.throws(() => createZip([{ name: 'a', content: '1' }, { name: 'a', content: '2' }]), /Duplicate/);
  assert.throws(() => createZip([]), /between 1 and 200/);
  assert.throws(() => createZip([{ name: 'big', content: Buffer.alloc(33 * 1024 * 1024) }]), /too large/);
});

// ---------- name constraints encoding ----------

test('network and address encodings', () => {
  assert.equal(networkBytes('127.0.0.1/8').toString('hex'), '7f000000ff000000');
  assert.equal(networkBytes('192.168.1.5').toString('hex'), 'c0a80105ffffffff', 'a bare address is a /32');
  assert.equal(networkBytes('fc00::/7').subarray(0, 1).toString('hex'), 'fc');
  assert.equal(networkBytes('fc00::/7').subarray(16, 17).toString('hex'), 'fe');
  assert.equal(ipBytes('::1').toString('hex'), '00000000000000000000000000000001');
  assert.equal(ipBytes('2001:db8::ff00:42:8329').toString('hex'), '20010db80000000000ff008329'.padEnd(32, '0').slice(0, 0) + '20010db8000000000000ff0000428329');
  assert.equal(ipBytes('::ffff:1.2.3.4').toString('hex'), '00000000000000000000ffff01020304');
  assert.throws(() => networkBytes('10.0.0.0/33'), /Bad network prefix/);
  assert.throws(() => ipBytes('nope'), /Not an IP/);
});

test('constraint text is parsed and validated', () => {
  assert.deepEqual(parseConstraintText('localhost *.test .dev.example 10.0.0.0/8 ::1, 192.168.1.5'), {
    dns: ['localhost', 'test', 'dev.example'], networks: ['10.0.0.0/8', '::1/128', '192.168.1.5/32']
  });
  for (const bad of ['bad name!x', '10.0.0.0/99', 'a..b', '-x.test']) assert.throws(() => parseConstraintText(bad), /Invalid/, bad);
  assert.throws(() => parseConstraintText(Array(51).fill('a.test').join(' ')), /Too many/);
  assert.deepEqual(parseConstraintText(''), { dns: [], networks: [] });
});

test('constraintsFor limits a CA to local names plus what was asked for', () => {
  const names = [{ type: 'dns', value: '*.app.dev.acme.com' }, { type: 'ip', value: '203.0.113.7' }];
  const local = constraintsFor(names, 'local');
  assert.ok(local.dns.includes('localhost') && local.dns.includes('test') && local.dns.includes('app.dev.acme.com'));
  assert.ok(local.networks.includes('127.0.0.0/8') && local.networks.includes('203.0.113.7/32'));
  const only = constraintsFor(names, 'names');
  assert.deepEqual(only, { dns: ['app.dev.acme.com'], networks: ['203.0.113.7/32'] });
  assert.ok(!local.dns.includes('google.com'));
});

// ---------- dev certificates ----------

test('defaults: localhost, 127.0.0.1 and ::1 with a new, restricted CA', async () => {
  const r = await issueDevCertificate({});
  assert.deepEqual(r.summary.names, ['DNS: localhost', 'IP: 127.0.0.1', 'IP: ::1']);
  assert.equal(r.summary.algorithmLabel, 'ECDSA P-256');
  assert.equal(r.summary.ca.created, true);
  assert.equal(r.summary.bundlePassword, 'changeit');
  assert.match(r.summary.ca.subject, /^Workbench Dev CA [0-9a-f]{4}$/);

  const leaf = new crypto.X509Certificate(file(r, 'localhost.pem'));
  const ca = new crypto.X509Certificate(file(r, 'ca.crt'));
  assert.equal(leaf.subject, 'CN=localhost');
  assert.match(leaf.subjectAltName, /DNS:localhost/);
  assert.match(leaf.subjectAltName, /IP Address:127\.0\.0\.1/);
  assert.ok(leaf.checkIssued(ca) && leaf.verify(ca.publicKey), 'signed by the CA');
  assert.equal(leaf.ca, false);
  assert.equal(ca.ca, true);
  assert.deepEqual(leaf.keyUsage, ['1.3.6.1.5.5.7.3.1'], 'server authentication only by default');

  const days = (new Date(leaf.validTo) - new Date(leaf.validFrom)) / 86400000;
  assert.ok(days > 364 && days < 366.1, `validity ${days}`);

  // The CA: 10 years, path length 0, critical name constraints, named and organised for easy recognition.
  const caParsed = new x509.X509Certificate(file(r, 'ca.crt'));
  const constraints = caParsed.extensions.find(e => e.type === '2.5.29.30');
  assert.ok(constraints, 'name constraints present');
  assert.equal(constraints.critical, true);
  assert.equal(caParsed.getExtension(x509.BasicConstraintsExtension).pathLength, 0);
  assert.match(caParsed.subject, /O=Certificate Workbench Dev/);
  assert.ok(r.summary.ca.nameConstraints.includes('localhost') && r.summary.ca.nameConstraints.includes('127.0.0.0/8'));
});

test('the bundle: every file is present, consistent and in the right format', async () => {
  const r = await issueDevCertificate({ names: 'app.test', bundlePassword: 'secret-pass' });
  assert.deepEqual(r.files.map(f => f.name), [
    'app.test.pem', 'app.test-key.pem', 'app.test-fullchain.pem', 'ca.crt', 'ca.cer', 'app.test.pfx', 'app.test.jks',
    'truststore.jks', 'ca-key.pem', 'app.test-dev-cert.zip'
  ]);
  assert.deepEqual(r.files.filter(f => f.secret).map(f => f.name), ['app.test-key.pem', 'app.test.pfx', 'app.test.jks', 'ca-key.pem', 'app.test-dev-cert.zip']);

  const leaf = new crypto.X509Certificate(file(r, 'app.test.pem'));
  const key = crypto.createPrivateKey(file(r, 'app.test-key.pem'));
  assert.ok(crypto.createPublicKey(key).equals(leaf.publicKey), 'private key matches the certificate');
  assert.match(file(r, 'app.test-key.pem'), /^-----BEGIN PRIVATE KEY-----/);
  const caKey = crypto.createPrivateKey(file(r, 'ca-key.pem'));
  assert.ok(crypto.createPublicKey(caKey).equals(new crypto.X509Certificate(file(r, 'ca.crt')).publicKey), 'CA key matches the CA');

  const fullchain = file(r, 'app.test-fullchain.pem');
  assert.equal((fullchain.match(/BEGIN CERTIFICATE/g) || []).length, 2, 'leaf then CA');
  assert.ok(fullchain.startsWith(file(r, 'app.test.pem')));
  assert.equal(new crypto.X509Certificate(file(r, 'ca.cer')).fingerprint256, new crypto.X509Certificate(file(r, 'ca.crt')).fingerprint256, 'DER matches PEM');

  // PFX: opens with the chosen password, holds the key and both certificates.
  const pfx = extractBundle([{ name: 'a.pfx', buffer: file(r, 'app.test.pfx') }], { password: 'secret-pass' });
  assert.equal(pfx.privateKeys.length, 1);
  assert.equal(pfx.certificates.length, 2);
  assert.throws(() => extractBundle([{ name: 'a.pfx', buffer: file(r, 'app.test.pfx') }], { password: 'wrong' }));

  // JKS: a key entry with its chain, and a trust store with just the CA.
  const jks = readJks(file(r, 'app.test.jks'), 'secret-pass'); // returns the list of entries
  assert.equal(jks.length, 1);
  assert.equal(jks[0].type, 'key');
  assert.equal(jks[0].chain.length, 2);
  assert.ok(crypto.createPublicKey(crypto.createPrivateKey({ key: jks[0].pkcs8, format: 'der', type: 'pkcs8' })).equals(leaf.publicKey), 'the JKS key matches');
  const trust = readJks(file(r, 'truststore.jks'), 'secret-pass');
  assert.deepEqual(trust.map(e => [e.alias, e.type, e.chain.length]), [['workbench-dev-ca', 'cert', 1]]);

  // ZIP: everything above plus a README with the trust instructions.
  const entries = readZip(file(r, 'app.test-dev-cert.zip'));
  assert.deepEqual([...entries.keys()].sort(), [...r.files.filter(f => !f.name.endsWith('.zip')).map(f => f.name), 'README.txt'].sort());
  assert.equal(entries.get('app.test-key.pem').toString(), file(r, 'app.test-key.pem'));
  const readme = entries.get('README.txt').toString();
  assert.match(readme, /Names:\s+app\.test/);
  assert.match(readme, /PFX \/ JKS password: secret-pass/);
  assert.match(readme, /update-ca-certificates/);
  assert.match(readme, /certutil -addstore/);
  assert.match(readme, /NODE_EXTRA_CA_CERTS/);
  assert.match(readme, /restricted to/);
});

test('REAL TLS: a client that trusts the new CA accepts the certificate for its names', async t => {
  const r = await issueDevCertificate({ names: 'localhost 127.0.0.1' });
  const server = tls.createServer({ key: file(r, 'localhost-key.pem'), cert: file(r, 'localhost-fullchain.pem') }, s => s.end('ok'));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const { port } = server.address();

  const result = await new Promise((resolve, reject) => {
    const socket = tls.connect({ host: '127.0.0.1', port, servername: 'localhost', ca: file(r, 'ca.crt'), rejectUnauthorized: true }, () => {
      resolve({ authorized: socket.authorized, error: socket.authorizationError });
      socket.end();
    });
    socket.on('error', reject);
  });
  assert.equal(result.authorized, true, String(result.error));

  // Without the CA the same certificate is untrusted: it really is a private CA.
  const untrusted = await new Promise(resolve => {
    const socket = tls.connect({ host: '127.0.0.1', port, servername: 'localhost', rejectUnauthorized: false }, () => {
      resolve(socket.authorized);
      socket.end();
    });
  });
  assert.equal(untrusted, false);
});

test('REAL TLS: the CA is name-restricted, so a leaked key cannot impersonate other sites', async t => {
  const created = await issueDevCertificate({ names: 'app.test' });
  const caPem = file(created, 'ca.crt');
  const caBundle = file(created, 'ca.crt') + file(created, 'ca-key.pem');

  // Use the CA key to sign a certificate for a name the CA was never meant to issue for.
  const evilKey = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const evilKeyPem = evilKey.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const csr = await createCsr([{ name: 'k.pem', buffer: Buffer.from(evilKeyPem) }], { commonName: 'www.evil-bank.com', sans: 'www.evil-bank.com' });
  const evil = await signCsr([{ name: 'c.csr', buffer: Buffer.from(csr.csrPem) }], [{ name: 'ca.pem', buffer: Buffer.from(caBundle) }], { usage: 'server' });
  // ...and for a name it is allowed to issue for.
  const good = await signCsr([{ name: 'c.csr', buffer: Buffer.from((await createCsr([{ name: 'k.pem', buffer: Buffer.from(evilKeyPem) }], { commonName: 'api.app.test', sans: 'api.app.test' })).csrPem) }], [{ name: 'ca.pem', buffer: Buffer.from(caBundle) }], { usage: 'server' });

  const handshake = async (certPem, servername) => {
    const server = tls.createServer({ key: evilKeyPem, cert: certPem }, s => s.end());
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    try {
      return await new Promise((resolve, reject) => {
        // Hostname matching is switched off so that only the CA's restriction is being tested.
        const socket = tls.connect({ host: '127.0.0.1', port: server.address().port, servername, ca: caPem, rejectUnauthorized: false }, () => {
          resolve({ authorized: socket.authorized, error: socket.authorizationError });
          socket.end();
        });
        socket.on('error', reject);
      });
    } finally {
      server.close();
    }
  };

  // Same CA, same key, same server: only the certificate's name differs. Node reports the violated constraint as a
  // generic failure code, so the proof is the contrast between the two.
  const bad = await handshake(evil.certificatePem + evil.chainPem, 'www.evil-bank.com');
  assert.equal(bad.authorized, false, 'a certificate outside the CA scope is refused');
  assert.ok(bad.error, 'with a verification error');
  const fine = await handshake(good.certificatePem + good.chainPem, 'api.app.test');
  assert.equal(fine.authorized, true, String(fine.error));

  // Without the restriction (scope "none") the very same abuse succeeds, which is why the default matters.
  const open = await issueDevCertificate({ names: 'app.test', scope: 'none' });
  const openBundle = file(open, 'ca.crt') + file(open, 'ca-key.pem');
  const evilOpen = await signCsr([{ name: 'c.csr', buffer: Buffer.from(csr.csrPem) }], [{ name: 'ca.pem', buffer: Buffer.from(openBundle) }], { usage: 'server' });
  const server = tls.createServer({ key: evilKeyPem, cert: evilOpen.certificatePem + evilOpen.chainPem }, s => s.end());
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const unrestricted = await new Promise(resolve => {
    const socket = tls.connect({ host: '127.0.0.1', port: server.address().port, servername: 'www.evil-bank.com', ca: file(open, 'ca.crt'), rejectUnauthorized: false }, () => {
      resolve(socket.authorized);
      socket.end();
    });
  });
  assert.equal(unrestricted, true, 'an unrestricted CA can vouch for any name');
});

test('CA scope: "names" limits to the requested names, "none" removes the restriction (with a warning)', async () => {
  const only = await issueDevCertificate({ names: 'foo.dev.test 10.1.2.3', scope: 'names' });
  assert.deepEqual(only.summary.ca.nameConstraints.sort(), ['10.1.2.3/32', 'foo.dev.test']);
  assert.equal(only.warnings.length, 0);

  const none = await issueDevCertificate({ names: 'localhost', scope: 'none' });
  assert.equal(none.summary.ca.nameConstraints, null);
  assert.equal(new x509.X509Certificate(file(none, 'ca.crt')).extensions.some(e => e.type === '2.5.29.30'), false);
  assert.ok(none.warnings.some(w => /no name restrictions/.test(w)));
  assert.match(none.readme, /WARNING: this CA has no name restrictions/);

  await assert.rejects(() => issueDevCertificate({ scope: 'everything' }), /CA scope must be one of/);
});

test('names: wildcards, IPs, client auth, and a CRL distribution point', async () => {
  const r = await issueDevCertificate({
    names: '*.app.test localhost 192.168.1.20', algorithm: 'ECDSA-P384', clientAuth: true, validityDays: 30,
    crlUrl: 'http://localhost:8080/ca.crl'
  });
  const leaf = new x509.X509Certificate(file(r, 'wildcard.app.test.pem'));
  assert.equal(leaf.subject, 'CN=*.app.test');
  const sans = leaf.getExtension(x509.SubjectAlternativeNameExtension).names.items.map(n => `${n.type}:${n.value}`);
  assert.deepEqual(sans, ['dns:*.app.test', 'dns:localhost', 'ip:192.168.1.20']);
  assert.deepEqual(new crypto.X509Certificate(file(r, 'wildcard.app.test.pem')).keyUsage.sort(), ['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2']);
  assert.equal(r.summary.clientAuth, true);
  assert.equal(r.summary.algorithmLabel, 'ECDSA P-384');
  assert.equal(r.summary.hash, 'SHA-384');
  assert.ok(leaf.getExtension(x509.CRLDistributionPointsExtension), 'CRL distribution point present');
  assert.equal(r.summary.crlUrl, 'http://localhost:8080/ca.crl');
  assert.ok(r.summary.ca.nameConstraints.includes('app.test') && r.summary.ca.nameConstraints.includes('192.168.1.20/32'));
});

test('validation of names and options', async () => {
  const bad = [
    [{ names: 'a@b.com' }, /host names and IP addresses/],
    [{ names: 'https://example.com/x' }, /host names and IP addresses/],
    [{ names: 'not a host!!' }, /Invalid subject alternative name/],
    [{ names: Array.from({ length: 51 }, (_, i) => `h${i}.test`).join(' ') }, /Too many/],
    [{ names: `${'a'.repeat(63)}.${'b'.repeat(63)}.test` }, /too long/],
    [{ algorithm: 'Ed25519' }, /Algorithm must be one of/],
    [{ caAlgorithm: 'DSA' }, /CA algorithm must be one of/],
    [{ validityDays: 826 }, /between 1 and 825/],
    [{ validityDays: 0 }, /between 1 and 825/],
    [{ validityDays: 'abc' }, /between 1 and 825/],
    [{ crlUrl: 'ftp://x/y.crl' }, /http:\/\/ or https:\/\//],
    [{ crlUrl: 'javascript:alert(1)' }, /http:\/\/ or https:\/\//],
    [{ bundlePassword: 'abc' }, /6 to 64 characters/],
    [{ bundlePassword: 'x'.repeat(65) }, /6 to 64 characters/],
    [{ caValidityDays: 99999 }, /Validity must be between/]
  ];
  for (const [options, pattern] of bad) {
    await assert.rejects(() => issueDevCertificate(options), err => err instanceof CaError && pattern.test(err.message), JSON.stringify(options).slice(0, 80));
  }
});

test('warnings for long validity and wildcards directly under a top-level name', async () => {
  const r = await issueDevCertificate({ names: '*.test', validityDays: 800 });
  assert.ok(r.warnings.some(w => /over 398 days/.test(w)));
  assert.ok(r.warnings.some(w => /wildcard directly under a top-level name \(\*\.test\)/.test(w)));
});

test('RSA keys work, and the file stem is a safe name', async () => {
  const r = await issueDevCertificate({ names: '*.shop.test', algorithm: 'RSA-2048' });
  assert.equal(r.summary.algorithmLabel, 'RSA 2048');
  assert.ok(r.files.some(f => f.name === 'wildcard.shop.test.pem'));
  const ip = await issueDevCertificate({ names: '::1' });
  assert.ok(ip.files.some(f => f.name === 'ipv6.pem'), 'an IPv6 address gets a readable file name');
  const keyUsage = new x509.X509Certificate(file(r, 'wildcard.shop.test.pem')).getExtension(x509.KeyUsagesExtension).usages;
  assert.ok(keyUsage & x509.KeyUsageFlags.keyEncipherment, 'RSA leaf allows key encipherment');
});

test('signing with your own existing CA', async () => {
  const myCa = await createCa({ commonName: 'My Existing CA', algorithm: 'ECDSA-P256', validityDays: 60 });
  const inputs = [{ name: 'ca.pem', buffer: Buffer.from(myCa.certificatePem + myCa.privateKeyPem) }];
  const r = await issueDevCertificate({ names: 'mine.test', validityDays: 365 }, { caInputs: inputs });

  assert.equal(r.summary.ca.created, false);
  assert.equal(r.summary.ca.subject, 'CN=My Existing CA');
  assert.equal(r.summary.ca.nameConstraints, null);
  assert.ok(!r.files.some(f => f.name === 'ca-key.pem'), 'the CA key is not copied back out');
  assert.ok(!readZip(file(r, 'mine.test-dev-cert.zip')).has('ca-key.pem'));
  const leaf = new crypto.X509Certificate(file(r, 'mine.test.pem'));
  assert.ok(leaf.verify(new crypto.X509Certificate(myCa.certificatePem).publicKey));
  assert.ok(r.warnings.some(w => /shortened to 59 days|shortened to 60 days/.test(w)), r.warnings.join('|'));
  assert.ok((new Date(leaf.validTo) - Date.now()) / 86400000 <= 60, 'does not outlive the CA');
  assert.match(r.readme, /Issued by:\s+CN=My Existing CA\n/);
  assert.doesNotMatch(r.readme, /ca-key\.pem  /);

  // Errors from the CA are reported clearly.
  await assert.rejects(() => issueDevCertificate({}, { caInputs: [{ name: 'x.pem', buffer: Buffer.from(myCa.certificatePem) }] }), /private key was not found/);
  const encrypted = crypto.createPrivateKey(myCa.privateKeyPem).export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: 'pw-123456' });
  await assert.rejects(() => issueDevCertificate({}, { caInputs: [{ name: 'x.pem', buffer: Buffer.from(myCa.certificatePem + encrypted) }] }), /encrypted/);
  const ok = await issueDevCertificate({}, { caInputs: [{ name: 'x.pem', buffer: Buffer.from(myCa.certificatePem + encrypted) }], caPassword: 'pw-123456' });
  assert.equal(ok.summary.ca.created, false);
  const leafOnly = await issueDevCertificate({}); // a leaf is not a CA
  await assert.rejects(() => issueDevCertificate({}, { caInputs: [{ name: 'x.pem', buffer: Buffer.from(leafOnly.files.find(f => f.name === 'localhost.pem').content + leafOnly.files.find(f => f.name === 'localhost-key.pem').content) }] }), /not a CA/);
});

test('createCa honours name restrictions from text and rejects bad ones', async () => {
  const ca = await createCa({ commonName: 'Limited CA', nameConstraints: 'corp.test 10.0.0.0/8' });
  assert.deepEqual(ca.nameConstraints, ['corp.test', '10.0.0.0/8']);
  assert.ok(new x509.X509Certificate(ca.certificatePem).extensions.some(e => e.type === '2.5.29.30'));
  assert.equal((await createCa({ commonName: 'Open CA' })).nameConstraints, null);
  assert.equal((await createCa({ commonName: 'Blank', nameConstraints: '   ' })).nameConstraints, null);
  await assert.rejects(() => createCa({ commonName: 'X', nameConstraints: 'bad name!x' }), err => err instanceof CaError && /Invalid name restriction/.test(err.message));
});

test('signCsr adds a CRL distribution point when asked', async () => {
  const ca = await createCa({ commonName: 'CDP CA' });
  const key = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ type: 'pkcs8', format: 'pem' });
  const csr = await createCsr([{ name: 'k.pem', buffer: Buffer.from(key) }], { commonName: 'x.test' });
  const signed = await signCsr([{ name: 'c.csr', buffer: Buffer.from(csr.csrPem) }], [{ name: 'ca.pem', buffer: Buffer.from(ca.certificatePem + ca.privateKeyPem) }], { crlUrl: 'https://pki.example.test/ca.crl' });
  assert.ok(new x509.X509Certificate(signed.certificatePem).getExtension(x509.CRLDistributionPointsExtension));
  const plain = await signCsr([{ name: 'c.csr', buffer: Buffer.from(csr.csrPem) }], [{ name: 'ca.pem', buffer: Buffer.from(ca.certificatePem + ca.privateKeyPem) }], {});
  assert.equal(new x509.X509Certificate(plain.certificatePem).getExtension(x509.CRLDistributionPointsExtension), null);
  await assert.rejects(() => signCsr([{ name: 'c.csr', buffer: Buffer.from(csr.csrPem) }], [{ name: 'ca.pem', buffer: Buffer.from(ca.certificatePem + ca.privateKeyPem) }], { crlUrl: 'gopher://x' }), /http:\/\/ or https:\/\//);
});
