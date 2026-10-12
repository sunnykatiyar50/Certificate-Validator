const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { keyTools, KeyToolsError } = require('../lib/keytools');
const { convert } = require('../lib/convert');
const { createCa } = require('../lib/ca');
const { KeyError } = require('../lib/keys');
const { InputError } = require('../lib/bundle');

const RSA = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
const EC = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey;
const ED = crypto.generateKeyPairSync('ed25519').privateKey;

const input = (key, type, extra = {}) => [{ name: 'key.pem', buffer: Buffer.from(key.export({ type, format: 'pem', ...extra })) }];
const text = (result, name) => result.files.find(f => f.name === name).content;
const sameKey = (pem, key, password) => crypto.createPrivateKey({ key: pem, passphrase: password }).export({ type: 'pkcs8', format: 'der' }).equals(key.export({ type: 'pkcs8', format: 'der' }));

// ---------- inspect ----------

test('inspect: describes the key, where it came from, and its fingerprints', () => {
  const cases = [
    [RSA, 'pkcs1', 'RSA 2048', 'PKCS#1 (RSA)'],
    [RSA, 'pkcs8', 'RSA 2048', 'PKCS#8'],
    [EC, 'sec1', 'ECDSA P-256', 'SEC1 (EC)'],
    [EC, 'pkcs8', 'ECDSA P-256', 'PKCS#8'],
    [ED, 'pkcs8', 'Ed25519', 'PKCS#8']
  ];
  for (const [key, type, description, format] of cases) {
    const { summary, files, warnings } = keyTools(input(key, type), { action: 'inspect' });
    assert.equal(summary.keyDescription, description);
    assert.equal(summary.sourceFormat, format);
    assert.equal(summary.wasEncrypted, false);
    assert.match(summary.fingerprintSha256, /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
    assert.equal(Buffer.from(summary.spkiPinSha256, 'base64').length, 32);
    assert.deepEqual(files.map(f => f.name), ['public-key.pem']);
    assert.equal(files[0].secret, false);
    assert.deepEqual(warnings, []);
    assert.equal(summary.result, null);
  }
  // The public key fingerprint is stable and identifies the key whatever format it is stored in.
  const a = keyTools(input(RSA, 'pkcs1'), {}).summary;
  const b = keyTools(input(RSA, 'pkcs8'), {}).summary;
  assert.equal(a.fingerprintSha256, b.fingerprintSha256);
  assert.equal(a.spkiPinSha256, b.spkiPinSha256);
  assert.notEqual(a.fingerprintSha256, keyTools(input(EC, 'pkcs8'), {}).summary.fingerprintSha256);
  // ...and it is the standard SPKI pin: base64(SHA-256(DER of the public key)).
  const expected = crypto.createHash('sha256').update(crypto.createPublicKey(RSA).export({ type: 'spki', format: 'der' })).digest('base64');
  assert.equal(a.spkiPinSha256, expected);
});

test('inspect: encrypted keys are recognised in every storage format', () => {
  const cases = [
    [RSA, 'pkcs8', 'PKCS#8'],
    [RSA, 'pkcs1', 'PKCS#1 (RSA)'],
    [EC, 'sec1', 'SEC1 (EC)']
  ];
  for (const [key, type, format] of cases) {
    const result = keyTools(input(key, type, { cipher: 'aes-256-cbc', passphrase: 'open-sesame' }), { password: 'open-sesame' });
    assert.equal(result.summary.wasEncrypted, true, `${type} encrypted`);
    assert.equal(result.summary.sourceFormat, format);
    assert.equal(result.summary.keyDescription, key === RSA ? 'RSA 2048' : 'ECDSA P-256');
  }
});

// ---------- converting formats ----------

test('PKCS#1 and SEC1 convert to PKCS#8 and back, keeping the very same key', () => {
  const rsa8 = keyTools(input(RSA, 'pkcs1'), { action: 'pkcs8' });
  assert.match(text(rsa8, 'private-key-pkcs8.pem'), /^-----BEGIN PRIVATE KEY-----/);
  assert.ok(sameKey(text(rsa8, 'private-key-pkcs8.pem'), RSA));
  const rsa1 = keyTools([{ name: 'k.pem', buffer: Buffer.from(text(rsa8, 'private-key-pkcs8.pem')) }], { action: 'pkcs1' });
  assert.match(text(rsa1, 'private-key-pkcs1.pem'), /^-----BEGIN RSA PRIVATE KEY-----/);
  assert.ok(sameKey(text(rsa1, 'private-key-pkcs1.pem'), RSA));

  const ec8 = keyTools(input(EC, 'sec1'), { action: 'pkcs8' });
  assert.ok(sameKey(text(ec8, 'private-key-pkcs8.pem'), EC));
  const ec1 = keyTools(input(EC, 'pkcs8'), { action: 'sec1' });
  assert.match(text(ec1, 'private-key-sec1.pem'), /^-----BEGIN EC PRIVATE KEY-----/);
  assert.ok(sameKey(text(ec1, 'private-key-sec1.pem'), EC));

  assert.ok(sameKey(text(keyTools(input(ED, 'pkcs8'), { action: 'pkcs8' }), 'private-key-pkcs8.pem'), ED), 'Ed25519 round trip');
  for (const r of [rsa8, rsa1, ec8, ec1]) assert.equal(r.files[0].secret, true);
});

test('adding, removing and changing a password', () => {
  // add
  const encrypted = keyTools(input(RSA, 'pkcs1'), { action: 'pkcs8', newPassword: 'first-pass' });
  const encPem = text(encrypted, 'private-key-pkcs8.pem');
  assert.match(encPem, /^-----BEGIN ENCRYPTED PRIVATE KEY-----/);
  assert.equal(encrypted.summary.resultEncrypted, true);
  assert.equal(encrypted.summary.result, 'Encrypted PKCS#8');
  assert.equal(encrypted.warnings.length, 0);
  assert.ok(sameKey(encPem, RSA, 'first-pass'));
  assert.throws(() => crypto.createPrivateKey({ key: encPem, passphrase: 'wrong' }));

  // change
  const changed = keyTools([{ name: 'e.pem', buffer: Buffer.from(encPem) }], { action: 'pkcs8', password: 'first-pass', newPassword: 'second-pass' });
  assert.equal(changed.summary.wasEncrypted, true);
  assert.ok(sameKey(text(changed, 'private-key-pkcs8.pem'), RSA, 'second-pass'));
  assert.throws(() => crypto.createPrivateKey({ key: text(changed, 'private-key-pkcs8.pem'), passphrase: 'first-pass' }));

  // remove
  const removed = keyTools([{ name: 'e.pem', buffer: Buffer.from(text(changed, 'private-key-pkcs8.pem')) }], { action: 'pkcs8', password: 'second-pass' });
  assert.match(text(removed, 'private-key-pkcs8.pem'), /^-----BEGIN PRIVATE KEY-----/);
  assert.equal(removed.summary.resultEncrypted, false);
  assert.ok(removed.warnings.some(w => /not password protected/.test(w)));
  assert.ok(removed.warnings.some(w => /password was removed/.test(w)));
  assert.ok(sameKey(text(removed, 'private-key-pkcs8.pem'), RSA));
});

test('traditional encrypted PKCS#1 and SEC1 can be produced and read back', () => {
  const rsa = keyTools(input(RSA, 'pkcs8'), { action: 'pkcs1', newPassword: 'legacy-pass' });
  assert.match(text(rsa, 'private-key-pkcs1.pem'), /Proc-Type: 4,ENCRYPTED/);
  assert.ok(sameKey(text(rsa, 'private-key-pkcs1.pem'), RSA, 'legacy-pass'));
  const reopened = keyTools([{ name: 'k.pem', buffer: Buffer.from(text(rsa, 'private-key-pkcs1.pem')) }], { password: 'legacy-pass' });
  assert.equal(reopened.summary.sourceFormat, 'PKCS#1 (RSA)');
  assert.equal(reopened.summary.wasEncrypted, true);

  const ec = keyTools(input(EC, 'pkcs8'), { action: 'sec1', newPassword: 'legacy-pass' });
  assert.match(text(ec, 'private-key-sec1.pem'), /Proc-Type: 4,ENCRYPTED/);
  assert.ok(sameKey(text(ec, 'private-key-sec1.pem'), EC, 'legacy-pass'));
});

test('keys inside PFX files and binary DER are read too', async () => {
  const ca = await createCa({ commonName: 'KeyTools CA' });
  const pfx = convert([{ name: 'a.pem', buffer: Buffer.from(ca.certificatePem + ca.privateKeyPem) }], 'pfx', { outputPassword: 'pfx-pass-1' });
  const pfxBytes = Buffer.from(pfx.files[0].content, 'base64');
  const fromPfx = keyTools([{ name: 'a.pfx', buffer: pfxBytes }], { password: 'pfx-pass-1', action: 'pkcs8' });
  assert.ok(sameKey(text(fromPfx, 'private-key-pkcs8.pem'), crypto.createPrivateKey(ca.privateKeyPem)));
  assert.equal(fromPfx.summary.sourceFormat, 'Binary file (DER, PFX or keystore)');

  const der = RSA.export({ type: 'pkcs8', format: 'der' });
  const fromDer = keyTools([{ name: 'k.der', buffer: der }], { action: 'inspect' });
  assert.equal(fromDer.summary.keyDescription, 'RSA 2048');
});

// ---------- public key ----------

test('public key extraction', () => {
  const rsa = keyTools(input(RSA, 'pkcs8'), { action: 'public' });
  assert.deepEqual(rsa.files.map(f => f.name), ['public-key.pem', 'public-key-pkcs1.pem']);
  assert.ok(crypto.createPublicKey(text(rsa, 'public-key.pem')).equals(crypto.createPublicKey(RSA)));
  assert.match(text(rsa, 'public-key-pkcs1.pem'), /^-----BEGIN RSA PUBLIC KEY-----/);
  assert.ok(crypto.createPublicKey(text(rsa, 'public-key-pkcs1.pem')).equals(crypto.createPublicKey(RSA)));
  assert.ok(rsa.files.every(f => f.secret === false));
  assert.equal(rsa.summary.result, 'Public key');

  for (const key of [EC, ED]) {
    const r = keyTools(input(key, 'pkcs8'), { action: 'public' });
    assert.deepEqual(r.files.map(f => f.name), ['public-key.pem']);
    assert.ok(crypto.createPublicKey(text(r, 'public-key.pem')).equals(crypto.createPublicKey(key)));
  }
  // A new password has no meaning for a public key and must not leak the private key into the output.
  const withPassword = keyTools(input(RSA, 'pkcs8'), { action: 'public', newPassword: 'ignored-pass' });
  assert.ok(!withPassword.files.some(f => /PRIVATE/.test(f.content)));
});

// ---------- errors ----------

test('clear errors for the common mistakes', () => {
  const bad = [
    [[], {}, /Provide a private key/],
    [input(RSA, 'pkcs8'), { action: 'explode' }, /Action must be one of/],
    [input(EC, 'pkcs8'), { action: 'pkcs1' }, /PKCS#1 only holds RSA keys, and this is ECDSA P-256/],
    [input(ED, 'pkcs8'), { action: 'pkcs1' }, /PKCS#1 only holds RSA keys, and this is Ed25519/],
    [input(RSA, 'pkcs8'), { action: 'sec1' }, /SEC1 only holds elliptic curve/],
    [input(ED, 'pkcs8'), { action: 'sec1' }, /SEC1 only holds elliptic curve/],
    [input(RSA, 'pkcs8'), { action: 'pkcs8', newPassword: 'abc' }, /6 to 128 characters/],
    [input(RSA, 'pkcs8'), { action: 'pkcs8', newPassword: 'x'.repeat(129) }, /6 to 128 characters/],
    [input(RSA, 'pkcs8'), { action: 'pkcs8', newPassword: 'bad\u0007pass' }, /6 to 128 characters/],
    [[{ name: 'x.pem', buffer: Buffer.from('hello, this is not a key') }], {}, /./]
  ];
  for (const [inputs, options, pattern] of bad) {
    assert.throws(() => keyTools(inputs, options), err => err instanceof Error && pattern.test(err.message), JSON.stringify(options));
  }
  const encrypted = input(RSA, 'pkcs8', { cipher: 'aes-256-cbc', passphrase: 'right-pass' });
  assert.throws(() => keyTools(encrypted, {}), err => err instanceof InputError && /encrypted/.test(err.message));
  assert.throws(() => keyTools(encrypted, { password: 'wrong-pass' }), err => err instanceof InputError && /Incorrect password/.test(err.message));
  assert.ok(keyTools(encrypted, { password: 'right-pass' }));
  assert.throws(() => keyTools([{ name: 'cert.pem', buffer: Buffer.from('-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----') }], {}), /./);
});

test('KeyToolsError is a KeyError so the API reports it as a user error', () => {
  assert.throws(() => keyTools(input(EC, 'pkcs8'), { action: 'pkcs1' }), err => err instanceof KeyToolsError && err instanceof KeyError);
});

test('more than one key: the first is used and the user is told', () => {
  const both = [{ name: 'k.pem', buffer: Buffer.from(RSA.export({ type: 'pkcs8', format: 'pem' }) + EC.export({ type: 'pkcs8', format: 'pem' })) }];
  const r = keyTools(both, { action: 'inspect' });
  assert.equal(r.summary.keyDescription, 'RSA 2048');
  assert.ok(r.warnings.some(w => /only the first one/.test(w)));
});

test('nothing sensitive leaks into errors or summaries', () => {
  const secret = 'super-secret-passphrase-123';
  const encrypted = input(RSA, 'pkcs8', { cipher: 'aes-256-cbc', passphrase: secret });
  let message = '';
  try { keyTools(encrypted, { password: 'wrong' }); } catch (err) { message = err.message; }
  assert.ok(!message.includes(secret) && !message.includes('wrong') && !/BEGIN/.test(message));

  const result = keyTools(encrypted, { password: secret, action: 'pkcs8', newPassword: 'another-secret-pass' });
  const dump = JSON.stringify(result);
  assert.ok(!dump.includes(secret), 'the old password is not echoed');
  assert.ok(!dump.includes('another-secret-pass'), 'the new password is not echoed');
  assert.ok(!JSON.stringify(result.summary).includes('PRIVATE KEY'), 'the summary holds no key material');
});
