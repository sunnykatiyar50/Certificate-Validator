const test = require('node:test');
const assert = require('node:assert/strict');
const { X509Certificate } = require('node:crypto');
const { analyzeChain } = require('../lib/analysis');
const { DAY, createCert, tamperPem, validTrustedRoot } = require('./helpers');

async function makeHierarchy() {
  const root = await createCert({ name: 'CN=Test Root', isCA: true, notAfter: new Date(Date.now() + 3650 * DAY) });
  const inter = await createCert({ name: 'CN=Test Intermediate', issuer: root, isCA: true, notAfter: new Date(Date.now() + 1825 * DAY) });
  const leaf = await createCert({
    name: 'CN=www.example.test', issuer: inter,
    sans: [{ type: 'dns', value: 'www.example.test' }, { type: 'dns', value: '*.wild.test' }]
  });
  return { root, inter, leaf };
}

test('full chain to an unknown root verifies signatures but is untrusted', async () => {
  const { root, inter, leaf } = await makeHierarchy();
  const { certs, chain } = analyzeChain([leaf.der, inter.der, root.der]);
  assert.deepEqual(chain.path, [0, 1, 2]);
  assert.equal(chain.status, 'untrusted-root');
  assert.equal(chain.trusted, false);
  assert.deepEqual(certs[0].issuedBy, { source: 'chain', index: 1 });
  assert.equal(certs[0].signatureCheck, 'valid');
  assert.equal(certs[2].selfSigned, true);
  assert.equal(certs[1].isCA, true);
  assert.equal(certs[0].isCA, false);
});

test('missing intermediate is reported as incomplete', async () => {
  const { leaf } = await makeHierarchy();
  const { certs, chain } = analyzeChain([leaf.der]);
  assert.equal(chain.status, 'incomplete');
  assert.equal(certs[0].issuedBy.source, 'missing');
});

test('order of the issuing certificates does not matter', async () => {
  const { root, inter, leaf } = await makeHierarchy();
  const { chain } = analyzeChain([leaf.der, root.der, inter.der]);
  assert.deepEqual(chain.path, [0, 2, 1]);
  assert.equal(chain.status, 'untrusted-root');
});

test('a root in the Mozilla store is trusted', () => {
  const root = validTrustedRoot();
  const { chain, certs } = analyzeChain([root.raw]);
  assert.equal(chain.status, 'trusted');
  assert.equal(chain.trusted, true);
  assert.equal(certs[0].selfSigned, true);
});

test('a tampered signature is flagged as broken', async () => {
  const { root, inter, leaf } = await makeHierarchy();
  const tampered = new X509Certificate(tamperPem(leaf)).raw;
  const { certs, chain } = analyzeChain([tampered, inter.der, root.der]);
  assert.equal(certs[0].signatureCheck, 'invalid');
  assert.equal(chain.status, 'broken');
});

test('hostname matching covers SANs, wildcards and mismatches', async () => {
  const { leaf } = await makeHierarchy();
  assert.equal(analyzeChain([leaf.der], { hostname: 'www.example.test' }).hostnameCheck.matches, true);
  assert.equal(analyzeChain([leaf.der], { hostname: 'a.wild.test' }).hostnameCheck.matches, true);
  assert.equal(analyzeChain([leaf.der], { hostname: 'a.b.wild.test' }).hostnameCheck.matches, false);
  assert.equal(analyzeChain([leaf.der], { hostname: 'evil.test' }).hostnameCheck.matches, false);
  assert.equal(analyzeChain([leaf.der]).hostnameCheck, null);
});

test('warnings: weak RSA key, SHA-1 signature, near expiry, self-signed leaf', async () => {
  const weak = await createCert({ name: 'CN=weak.test', bits: 1024, hash: 'SHA-1', notAfter: new Date(Date.now() + 10 * DAY) });
  const { certs } = analyzeChain([weak.der]);
  const messages = certs[0].warnings.map(w => w.message).join('\n');
  assert.match(messages, /Weak RSA key \(1024-bit\)/);
  assert.match(messages, /Weak signature hash \(SHA-1\)/);
  assert.match(messages, /Expires in (9|10) days/);
  assert.match(messages, /Self-signed certificate that is not a CA/);
});

test('warns when a CA-issued leaf is valid for more than 398 days', async () => {
  const { inter } = await makeHierarchy();
  const long = await createCert({ name: 'CN=long.test', issuer: inter, notAfter: new Date(Date.now() + 800 * DAY) });
  const { certs } = analyzeChain([long.der, inter.der]);
  assert.ok(certs[0].warnings.some(w => /398/.test(w.message)));
});

test('a chain to a trusted root is reported as expired once a certificate has lapsed', () => {
  const root = validTrustedRoot();
  const future = new Date(new Date(root.validTo).getTime() + DAY);
  const { chain } = analyzeChain([root.raw], { now: future });
  assert.equal(chain.status, 'expired');
  assert.equal(chain.trusted, false);
});

test('daysRemaining is negative for expired certificates', async () => {
  const expired = await createCert({ name: 'CN=old.test', notBefore: new Date(Date.now() - 30 * DAY), notAfter: new Date(Date.now() - 5 * DAY) });
  const { certs } = analyzeChain([expired.der]);
  assert.ok(certs[0].daysRemaining < 0);
});
