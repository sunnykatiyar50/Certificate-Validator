const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const tls = require('node:tls');
const x509 = require('@peculiar/x509');
const { createCrl, parseSerialList, normalizeSerial, CrlError } = require('../lib/crl');
const { createCa, createCsr, signCsr, CaError } = require('../lib/ca');
const { issueDevCertificate } = require('../lib/devcert');
const { verifyCrlSignature } = require('../lib/crlVerify');
const { decode } = require('../lib/decode');
const { pem } = require('../lib/keys');

x509.cryptoProvider.set(crypto.webcrypto);

const caInputs = ca => [{ name: 'ca.pem', buffer: Buffer.from(ca.certificatePem + ca.privateKeyPem) }];
const fileText = (result, name) => result.files.find(f => f.name === name).content;
const crlDer = result => Buffer.from(fileText(result, 'ca.crl.der'), 'base64');

async function leafFor(ca, name) {
  const key = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ type: 'pkcs8', format: 'pem' });
  const csr = await createCsr([{ name: 'k.pem', buffer: Buffer.from(key) }], { commonName: name, sans: name });
  const signed = await signCsr([{ name: 'c.csr', buffer: Buffer.from(csr.csrPem) }], caInputs(ca), { usage: 'server' });
  return { ...signed, keyPem: key };
}

// ---------- parsing ----------

test('serial numbers are normalised however they are written', () => {
  assert.equal(normalizeSerial('0A1B2C'), 'A1B2C');
  assert.equal(normalizeSerial('0x0a:1b:2c'), 'A1B2C');
  assert.equal(normalizeSerial('  0a-1b-2c '), 'A1B2C');
  assert.equal(normalizeSerial('00'), '0');
  assert.equal(normalizeSerial('ff'), 'FF');
  assert.equal(normalizeSerial('xyz'), null);
  assert.equal(normalizeSerial(''), null);
  assert.equal(normalizeSerial('a'.repeat(81)), null);
});

test('serial lists accept reasons, dates, comments and blank lines', () => {
  const now = new Date('2026-06-01T12:00:00Z');
  const list = parseSerialList(`
    # revoked after the laptop theft
    0A1B2C keyCompromise
    0x00ff, superseded, 2026-03-01
    1234;4
    ABCD cACompromise 2026-05-01T08:30:00Z

    7f
  `, 0, now);
  assert.deepEqual(list.map(e => [e.serial, e.reason]), [['A1B2C', 1], ['FF', 4], ['1234', 4], ['ABCD', 2], ['7F', 0]]);
  assert.equal(list[0].date, now, 'defaults to now');
  assert.equal(list[1].date.toISOString(), '2026-03-01T00:00:00.000Z');
  assert.equal(list[3].date.toISOString(), '2026-05-01T08:30:00.000Z');
  assert.deepEqual(parseSerialList('', 0, now), []);
  assert.deepEqual(parseSerialList(undefined, 0, now), []);
  assert.equal(parseSerialList('0a', 5, now)[0].reason, 5, 'the default reason applies');
});

test('bad serial lists are rejected with clear messages', () => {
  const now = new Date();
  const bad = [
    ['zzz', /Not a valid serial number: zzz/],
    ['0a unknownreason', /Unknown revocation reason "unknownreason"/],
    ['0a 99', /Unknown revocation reason: 99/],
    ['0a 8', /Unknown revocation reason: 8/],
    ['0a keyCompromise not-a-date', /Not a valid revocation date/],
    [`0a keyCompromise ${new Date(Date.now() + 5 * 86400000).toISOString()}`, /in the future/]
  ];
  for (const [text, pattern] of bad) assert.throws(() => parseSerialList(text, 0, now), err => err instanceof CrlError && pattern.test(err.message), text);
  assert.throws(() => parseSerialList(Array.from({ length: 5001 }, (_, i) => (i + 1).toString(16)).join('\n'), 0, now), /Too many entries/);
});

// ---------- signature check ----------

test('CRL signatures are verified on the original bytes, including CRLs without reason codes', async () => {
  const ca = await createCa({ commonName: 'Verify CA' });
  const other = await createCa({ commonName: 'Verify CA' });
  // These are exactly the CRLs @peculiar/x509's own verify() rejects, although the signature is fine.
  const crl = await createCrl(caInputs(ca), { serials: '0A\n0B\nFF\n80' });
  const der = crlDer(crl);
  const caDer = Buffer.from(new x509.X509Certificate(ca.certificatePem).rawData);
  const otherDer = Buffer.from(new x509.X509Certificate(other.certificatePem).rawData);

  assert.equal(verifyCrlSignature(der, caDer), true);
  assert.equal(verifyCrlSignature(der, otherDer), false, 'a different CA key, even with the same name');
  const tampered = Buffer.from(der);
  tampered[tampered.length - 5] ^= 0x01; // inside the signature value
  assert.equal(verifyCrlSignature(tampered, caDer), false);
  const tbsTampered = Buffer.from(der);
  tbsTampered[Math.floor(der.length / 2)] ^= 0x01; // inside the signed content
  assert.equal(verifyCrlSignature(tbsTampered, caDer), false);
  assert.equal(verifyCrlSignature(Buffer.from('not a crl'), caDer), null);
  assert.equal(verifyCrlSignature(Buffer.alloc(0), caDer), null);

  // The library check really is wrong for this CRL, which is why the direct check exists.
  const library = new x509.X509Crl(der);
  assert.equal(await library.verify({ publicKey: new x509.X509Certificate(ca.certificatePem) }), false);
});

test('RSA, P-384 and Ed25519 CA signatures verify too', async () => {
  for (const algorithm of ['RSA-2048', 'ECDSA-P384', 'Ed25519']) {
    const ca = await createCa({ commonName: `${algorithm} CA`, algorithm });
    const crl = await createCrl(caInputs(ca), { serials: '0A\n0B' });
    const caDer = Buffer.from(new x509.X509Certificate(ca.certificatePem).rawData);
    assert.equal(verifyCrlSignature(crlDer(crl), caDer), true, algorithm);
  }
});

// ---------- creating a CRL ----------

test('creates a standard CRL that the decoder verifies', async () => {
  const ca = await createCa({ commonName: 'Lab CA' });
  const result = await createCrl(caInputs(ca), { serials: '0A1B2C keyCompromise\n7f superseded', nextUpdateDays: 7 });

  assert.deepEqual(result.files.map(f => f.name), ['ca.crl', 'ca.crl.der']);
  assert.match(fileText(result, 'ca.crl'), /^-----BEGIN X509 CRL-----\n/);
  assert.match(fileText(result, 'ca.crl'), /-----END X509 CRL-----\n$/);
  assert.equal(result.summary.crlNumber, '1');
  assert.equal(result.summary.issuer, 'CN=Lab CA');
  assert.equal(result.summary.added, 2);
  assert.equal(result.summary.carriedOver, 0);
  assert.deepEqual(result.summary.entries.map(e => [e.serialNumber, e.reason]), [['A1B2C', 'Key compromise'], ['7F', 'Superseded']]);
  const days = (new Date(result.summary.nextUpdate) - new Date(result.summary.thisUpdate)) / 86400000;
  assert.ok(days > 6.9 && days < 7.1, `next update in ${days} days`);

  const decoded = (await decode([{ name: 'a.crl', buffer: Buffer.from(fileText(result, 'ca.crl')) }, { name: 'ca.pem', buffer: Buffer.from(ca.certificatePem) }], {})).crls[0];
  assert.equal(decoded.signature, 'valid');
  assert.equal(decoded.crlNumber, '1');
  assert.equal(decoded.revokedCount, 2);
  assert.deepEqual(decoded.warnings, []);
  assert.equal(decoded.expired, false);
});

test('serials with the high bit set are stored as positive numbers', async () => {
  const ca = await createCa({ commonName: 'High Bit CA' });
  const result = await createCrl(caInputs(ca), { serials: 'FF\n80\n7F\n0100\nFFFF' });
  const stored = new x509.X509Crl(crlDer(result)).entries.map(e => e.serialNumber);
  // A leading 00 keeps ASN.1 INTEGERs positive; without it 0xFF would be read as -1.
  assert.deepEqual(stored, ['00ff', '0080', '7f', '0100', '00ffff']);
});

test('revoking certificates by file: the serial comes from the certificate, and it must be this CA\'s', async () => {
  const ca = await createCa({ commonName: 'Issuing CA' });
  const leaf = await leafFor(ca, 'one.test');
  const second = await leafFor(ca, 'two.test');
  const result = await createCrl(caInputs(ca), {
    certificateInputs: [{ name: 'a.pem', buffer: Buffer.from(leaf.certificatePem + second.certificatePem) }], reason: 'cessationOfOperation'
  });
  assert.deepEqual(result.summary.entries.map(e => e.serialNumber).sort(), [normalizeSerial(leaf.serialNumber), normalizeSerial(second.serialNumber)].sort());
  assert.ok(result.summary.entries.every(e => e.reason === 'Cessation of operation'));
  assert.deepEqual(result.summary.revokedCertificates.sort(), ['CN=one.test', 'CN=two.test']);

  const stranger = await createCa({ commonName: 'Someone Else CA' });
  const foreign = await leafFor(stranger, 'foreign.test');
  await assert.rejects(
    () => createCrl(caInputs(ca), { certificateInputs: [{ name: 'f.pem', buffer: Buffer.from(foreign.certificatePem) }] }),
    err => err instanceof CrlError && /was not issued by this CA/.test(err.message) && /foreign\.test/.test(err.message)
  );
  await assert.rejects(() => createCrl(caInputs(ca), { certificateInputs: [{ name: 'x.pem', buffer: Buffer.from('nothing useful here') }] }), /Certificates to revoke/);
});

test('the same serial from several sources is listed once', async () => {
  const ca = await createCa({ commonName: 'Dedupe CA' });
  const leaf = await leafFor(ca, 'dup.test');
  const result = await createCrl(caInputs(ca), {
    serials: `${leaf.serialNumber}\n${leaf.serialNumber.toLowerCase()}\n0A`,
    certificateInputs: [{ name: 'a.pem', buffer: Buffer.from(leaf.certificatePem) }]
  });
  assert.equal(result.summary.entries.length, 2);
  assert.ok(result.warnings.some(w => /2 serial numbers were already revoked/.test(w)), result.warnings.join('|'));
});

test('adding to an existing CRL carries entries over, keeps their dates and bumps the number', async () => {
  const ca = await createCa({ commonName: 'Carry CA' });
  const first = await createCrl(caInputs(ca), { serials: '0A keyCompromise 2026-01-15\n0B' });
  assert.equal(first.summary.crlNumber, '1');

  const second = await createCrl(caInputs(ca), {
    previousCrlInputs: [{ name: 'old.crl', buffer: Buffer.from(fileText(first, 'ca.crl')) }], serials: '0C superseded'
  });
  assert.equal(second.summary.crlNumber, '2');
  assert.equal(second.summary.carriedOver, 2);
  assert.equal(second.summary.added, 1);
  const byserial = Object.fromEntries(second.summary.entries.map(e => [e.serialNumber, e]));
  assert.equal(byserial.A.carried, true);
  assert.equal(byserial.A.reason, 'Key compromise');
  assert.equal(byserial.A.revocationDate, '2026-01-15T00:00:00.000Z', 'the original revocation date is kept');
  assert.equal(byserial.B.reason, 'Unspecified');
  assert.equal(byserial.C.carried, false);

  const third = await createCrl(caInputs(ca), { previousCrlInputs: [{ name: 'c.crl', buffer: crlDer(second) }] });
  assert.equal(third.summary.crlNumber, '3');
  assert.equal(third.summary.entries.length, 3);

  // A CRL from a different CA cannot be carried over.
  const stranger = await createCa({ commonName: 'Carry CA' });
  await assert.rejects(
    () => createCrl(caInputs(stranger), { previousCrlInputs: [{ name: 'old.crl', buffer: Buffer.from(fileText(first, 'ca.crl')) }] }),
    err => err instanceof CrlError && /not signed by this CA/.test(err.message)
  );
  await assert.rejects(() => createCrl(caInputs(ca), { previousCrlInputs: [{ name: 'x.crl', buffer: Buffer.from('junk') }] }), /Previous CRL/);
});

test('an empty CRL is allowed and says so', async () => {
  const ca = await createCa({ commonName: 'Empty CA' });
  const result = await createCrl(caInputs(ca), {});
  assert.equal(result.summary.entries.length, 0);
  assert.ok(result.warnings.some(w => /lists no revoked certificates/.test(w)));
  const decoded = (await decode([{ name: 'a.crl', buffer: Buffer.from(fileText(result, 'ca.crl')) }, { name: 'ca.pem', buffer: Buffer.from(ca.certificatePem) }], {})).crls[0];
  assert.equal(decoded.signature, 'valid');
  assert.equal(decoded.revokedCount, 0);
});

test('validation: bad options, and a CA that may not sign CRLs', async () => {
  const ca = await createCa({ commonName: 'Option CA' });
  for (const [options, pattern] of [
    [{ nextUpdateDays: 0 }, /Next update must be between 1 and 365/],
    [{ nextUpdateDays: 366 }, /Next update must be between 1 and 365/],
    [{ reason: 'nonsense' }, /Unknown revocation reason/],
    [{ hash: 'MD5' }, /Unsupported hash/],
    [{ serials: 'not-hex' }, /Not a valid serial/]
  ]) {
    await assert.rejects(() => createCrl(caInputs(ca), options), err => err instanceof CaError && pattern.test(err.message), JSON.stringify(options));
  }

  // A CA whose key usage lacks cRLSign.
  const keys = await crypto.webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const noCrlSign = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01', name: 'CN=No CRL Sign CA', notBefore: new Date(Date.now() - 60000), notAfter: new Date(Date.now() + 86400000),
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' }, keys,
    extensions: [new x509.BasicConstraintsExtension(true, undefined, true), new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign, true)]
  });
  const keyPem = pem('PRIVATE KEY', Buffer.from(await crypto.webcrypto.subtle.exportKey('pkcs8', keys.privateKey)));
  await assert.rejects(
    () => createCrl([{ name: 'ca.pem', buffer: Buffer.from(noCrlSign.toString('pem') + keyPem) }], {}),
    err => err instanceof CrlError && /cRLSign is missing/.test(err.message)
  );

  await assert.rejects(() => createCrl([{ name: 'x.pem', buffer: Buffer.from(ca.certificatePem) }], {}), /private key was not found/);
});

// ---------- the real thing: does a TLS client honour the CRL? ----------

test('REAL TLS: a client given the CRL rejects the revoked certificate and still accepts the others', async t => {
  const ca = await createCa({ commonName: 'Revocation Test CA' });
  const revoked = await issueDevCertificate({ names: 'revoked.test' }, { caInputs: caInputs(ca) });
  const healthy = await issueDevCertificate({ names: 'healthy.test' }, { caInputs: caInputs(ca) });
  const get = (r, name) => r.files.find(f => f.name === name).content;

  const crl = await createCrl(caInputs(ca), {
    certificateInputs: [{ name: 'r.pem', buffer: Buffer.from(get(revoked, 'revoked.test.pem')) }], reason: 'keyCompromise'
  });

  const handshake = async (bundle, base, servername, crlPem) => {
    const server = tls.createServer({ key: get(bundle, `${base}-key.pem`), cert: get(bundle, `${base}-fullchain.pem`) }, s => s.end());
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    try {
      return await new Promise((resolve, reject) => {
        const options = { host: '127.0.0.1', port: server.address().port, servername, ca: ca.certificatePem, rejectUnauthorized: false };
        if (crlPem) options.crl = crlPem;
        const socket = tls.connect(options, () => {
          resolve({ authorized: socket.authorized, error: socket.authorizationError });
          socket.end();
        });
        socket.on('error', reject);
      });
    } finally {
      server.close();
    }
  };

  // Without the CRL nothing is wrong with the certificate...
  assert.equal((await handshake(revoked, 'revoked.test', 'revoked.test', null)).authorized, true);
  // ...with it, the revoked one is refused for the right reason, and the other certificate is unaffected.
  const refused = await handshake(revoked, 'revoked.test', 'revoked.test', fileText(crl, 'ca.crl'));
  assert.equal(refused.authorized, false);
  assert.equal(refused.error, 'CERT_REVOKED');
  const fine = await handshake(healthy, 'healthy.test', 'healthy.test', fileText(crl, 'ca.crl'));
  assert.equal(fine.authorized, true, String(fine.error));
});

test('a CRL distribution point in the certificate points at the CRL URL (dev certificate to CRL round trip)', async () => {
  const ca = await createCa({ commonName: 'CDP Round Trip CA' });
  const dev = await issueDevCertificate({ names: 'cdp.test', crlUrl: 'http://localhost:8080/ca.crl' }, { caInputs: caInputs(ca) });
  const leaf = new x509.X509Certificate(dev.files.find(f => f.name === 'cdp.test.pem').content);
  const cdp = leaf.getExtension(x509.CRLDistributionPointsExtension);
  assert.ok(cdp);
  const crl = await createCrl(caInputs(ca), { certificateInputs: [{ name: 'l.pem', buffer: Buffer.from(leaf.toString('pem')) }] });
  assert.equal(crl.summary.entries.length, 1);
  assert.equal(crl.summary.entries[0].serialNumber, normalizeSerial(leaf.serialNumber));
});
