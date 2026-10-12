const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const { convert } = require('../lib/convert');
const { createCa, createCsr, signCsr } = require('../lib/ca');
const { generateKeyPair } = require('../lib/keygen');
const { decode } = require('../lib/decode');
const { matchKeys } = require('../lib/match');
const { parseCertificateInput } = require('../lib/certificate');

// The browser code has no unit tests of its own, and a missing helper function only shows up when a user clicks the
// right button (it once broke every PFX, JKS and DER conversion). These tests run public/script.js in a stub browser
// and feed its renderers real data from the server code, so such mistakes fail the build instead.

const PUBLIC = path.join(__dirname, '..', 'public');
const SCRIPT = fs.readFileSync(path.join(PUBLIC, 'script.js'), 'utf8');
const HTML = fs.readFileSync(path.join(PUBLIC, 'index.html'), 'utf8');

// An element that accepts anything a page might do to it.
function stubElement() {
  const state = {
    value: '', hidden: false, checked: false, disabled: false, textContent: '', innerHTML: '', innerText: '', className: '',
    id: '', title: '', files: [], children: [], options: [], selectedOptions: [], dataset: {}, style: {}
  };
  const classList = { add() {}, remove() {}, toggle() {}, contains: () => false };
  return new Proxy(state, {
    get(target, prop) {
      if (prop in target) return target[prop];
      if (typeof prop === 'symbol' || prop === 'then') return undefined;
      if (prop === 'classList') return classList;
      if (prop === 'querySelectorAll') return () => [];
      if (prop === 'getBoundingClientRect') return () => ({ top: 0, bottom: 0, left: 0, right: 0, width: 0, height: 0 });
      if (prop === 'matches' || prop === 'contains') return () => false;
      return (...args) => (prop === 'closest' ? null : prop === 'querySelector' ? stubElement() : undefined);
    },
    set(target, prop, value) {
      target[prop] = value;
      return true;
    }
  });
}

function loadBrowserScript() {
  const elements = new Map();
  const document = {
    getElementById: id => {
      if (!elements.has(id)) elements.set(id, stubElement());
      return elements.get(id);
    },
    querySelector: () => stubElement(),
    querySelectorAll: () => [],
    createElement: () => stubElement(),
    addEventListener() {},
    documentElement: stubElement(),
    body: stubElement()
  };
  const sandbox = {
    document,
    console,
    setTimeout, clearTimeout,
    URL, Blob, FormData, atob, btoa,
    crypto: { randomUUID: () => crypto.randomUUID() },
    location: { hash: '', href: '', pathname: '/' },
    history: { replaceState() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    navigator: { clipboard: { writeText: async () => {} } },
    confirm: () => true, alert() {}, prompt: () => null,
    fetch: () => new Promise(() => {}) // never answers, so the start-up sign-in check just waits
  };
  sandbox.window = sandbox;
  const context = vm.createContext(sandbox);
  vm.runInContext(SCRIPT, context, { filename: 'public/script.js' });
  return {
    elements,
    // Run a renderer with some data and return its output.
    render(expression, data, extra) {
      context.__data = data;
      context.__extra = extra;
      return vm.runInContext(expression, context);
    }
  };
}

const bytes = text => Buffer.from(text);

test('public/script.js loads in a browser-like environment without throwing', () => {
  assert.doesNotThrow(() => loadBrowserScript());
});

test('every element the script looks up by id exists in index.html', () => {
  const used = new Set([...SCRIPT.matchAll(/(?:\$|getElementById)\('([\w-]+)'\)/g)].map(m => m[1]));
  const present = new Set([...HTML.matchAll(/\sid="([\w-]+)"/g)].map(m => m[1]));
  const missing = [...used].filter(id => !present.has(id));
  assert.deepEqual(missing, [], `ids used by script.js but missing from index.html: ${missing.join(', ')}`);
});

test('every button action in the page has a handler', () => {
  const html = [...HTML.matchAll(/data-action="([\w-]+)"/g)].map(m => m[1]);
  const script = [...SCRIPT.matchAll(/data-action="([\w-]+)"/g)].map(m => m[1]);
  const handled = new Set([...SCRIPT.matchAll(/action === '([\w-]+)'/g)].map(m => m[1]));
  const unhandled = [...new Set([...html, ...script])].filter(a => !handled.has(a));
  assert.deepEqual(unhandled, [], `data-action values without a handler: ${unhandled.join(', ')}`);
});

test('every nav item opens a view that exists', () => {
  const views = [...HTML.matchAll(/data-view="([\w-]+)"/g)].map(m => m[1]);
  const present = new Set([...HTML.matchAll(/<section class="view[^"]*" id="view-([\w-]+)"/g)].map(m => m[1]));
  assert.deepEqual(views.filter(v => !present.has(v)), []);
  assert.deepEqual([...present].filter(v => !views.includes(v)), [], 'every view has a nav item');
});

test('file results render for text and binary files (binary downloads need newId)', async () => {
  const { render } = loadBrowserScript();
  const ca = await createCa({ commonName: 'Frontend CA' });
  const input = [{ name: 'a.pem', buffer: bytes(ca.certificatePem + ca.privateKeyPem) }];
  for (const format of ['pem', 'der', 'p7b', 'pfx', 'jks']) {
    const data = convert(input, format, { outputPassword: 'changeit' });
    const html = render('renderConverted(__data)', data);
    assert.ok(html.length > 100, format);
    assert.ok(!html.includes('undefined'), `${format}: no "undefined" in the output`);
    for (const file of data.files) assert.ok(html.includes(file.name), `${format}: ${file.name} is listed`);
    if (data.files.some(f => f.encoding === 'base64')) assert.match(html, /data-action="download-b64" data-id="[\w-]+"/, `${format}: binary files get a download button`);
  }
});

test('results escape anything the user or a certificate could control', async () => {
  const { render } = loadBrowserScript();
  const evil = '<img src=x onerror=alert(1)>';
  const files = [
    { name: `${evil}.pem`, mime: 'text/plain', note: evil, encoding: 'text', content: evil },
    { name: `${evil}.pfx`, mime: 'application/x-pkcs12', note: evil, encoding: 'base64', content: Buffer.from('x').toString('base64') }
  ];
  const html = render('renderFiles(__data)', files);
  assert.ok(!html.includes('<img'), 'no raw tag in the file list');
  assert.ok(html.includes('&lt;img'));

  const ca = await createCa({ commonName: 'Evil <script>alert(1)</script> CA' });
  const issued = render('renderIssued(__data, __extra)', ca, { title: 'Root CA', usage: 'ca' });
  assert.ok(!/<script/i.test(issued), 'no script tag from a certificate name');
});

test('every tool result renders from real server output', async () => {
  const { render } = loadBrowserScript();
  const ca = await createCa({ commonName: 'Render CA' });
  const caInput = [{ name: 'ca.pem', buffer: bytes(ca.certificatePem + ca.privateKeyPem) }];

  const issued = render('renderIssued(__data, __extra)', ca, { title: 'Root CA', usage: 'ca' });
  assert.match(issued, /Render CA/);
  assert.match(issued, /data-action="use-ca"/);

  const key = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ type: 'pkcs8', format: 'pem' });
  const csr = await createCsr([{ name: 'k.pem', buffer: bytes(key) }], { commonName: 'host.test' });
  assert.match(render('renderCsrCreated(__data)', csr), /host\.test/);

  const signed = await signCsr([{ name: 'c.csr', buffer: bytes(csr.csrPem) }], caInput, {});
  assert.match(render('renderIssued(__data, __extra)', signed, { title: 'Signed certificate', usage: 'leaf' }), /host\.test/);

  const decoded = await decode([{ name: 'c.csr', buffer: bytes(csr.csrPem) }, { name: 'ca.pem', buffer: bytes(ca.certificatePem) }], {});
  assert.ok(render('renderDecode(__data)', decoded).length > 100);

  const matched = matchKeys([{ name: 'a.pem', buffer: bytes(signed.certificatePem + key) }], {});
  assert.ok(render('renderMatch(__data)', matched).length > 50);

  const pair = await generateKeyPair({ algorithm: 'ECDSA-P256', commonName: 'pair.test' });
  const entry = { ...pair, name: 'pair', createdAt: new Date().toISOString() };
  assert.match(render('renderKeyPair(__data, {})', entry), /pair\.test/);

  const report = await parseCertificateInput({ certText: signed.fullchainPem });
  const { elements } = loadBrowserScript();
  void elements;
  const out = stubElement();
  render('renderCertResults(__data, __extra)', report, out);
  assert.ok(out.innerHTML.length > 200, 'certificate report rendered into the page');
  assert.ok(!out.innerHTML.includes('undefined'));
});

test('the local development tools render from real server output', async () => {
  const { issueDevCertificate } = require('../lib/devcert');
  const { createCrl } = require('../lib/crl');
  const { keyTools } = require('../lib/keytools');
  const { render } = loadBrowserScript();

  // Dev certificate: one prominent ZIP button, the files without the ZIP repeated, and the how-to guides.
  const dev = await issueDevCertificate({ names: 'app.test 10.0.0.5', bundlePassword: 'my-pass-1' });
  const devHtml = render('renderDevCert(__data)', dev);
  assert.match(devHtml, /Download everything \(\.zip\)/);
  assert.equal((devHtml.match(/app\.test-dev-cert\.zip/g) || []).length, 0, 'the ZIP is a button, not a second file card');
  assert.match(devHtml, /data-action="download-b64" data-id="[\w-]+"/);
  for (const name of ['app.test.pem', 'app.test-key.pem', 'app.test.pfx', 'app.test.jks', 'truststore.jks', 'ca.crt', 'ca-key.pem']) assert.ok(devHtml.includes(name), name);
  assert.match(devHtml, /Trust the CA/);
  assert.match(devHtml, /update-ca-certificates/);
  assert.match(devHtml, /server\.ssl\.key-store=app\.test\.pfx/);
  assert.match(devHtml, /server\.ssl\.key-store-password=my-pass-1/);
  assert.match(devHtml, /ssl_certificate\s+app\.test-fullchain\.pem/);
  assert.match(devHtml, /A new CA was created/);
  assert.ok(!devHtml.includes('undefined'));
  assert.ok((devHtml.match(/class="pem-block secret"/g) || []).length >= 4, 'keys, PFX, JKS and the CA key are marked secret');

  // Using an existing CA: no "new CA" notice, no CA key file.
  const mine = await createCa({ commonName: 'Mine' });
  const existing = await issueDevCertificate({ names: 'mine.test' }, { caInputs: [{ name: 'ca.pem', buffer: bytes(mine.certificatePem + mine.privateKeyPem) }] });
  const existingHtml = render('renderDevCert(__data)', existing);
  assert.ok(!existingHtml.includes('A new CA was created'));
  assert.ok(!existingHtml.includes('ca-key.pem'));

  // CRL: summary, the table of serials and the "try it" commands.
  const crl = await createCrl([{ name: 'ca.pem', buffer: bytes(mine.certificatePem + mine.privateKeyPem) }], { serials: '0A1B2C keyCompromise\n7f' });
  const crlHtml = render('renderCrl(__data)', crl);
  assert.match(crlHtml, /CRL #1/);
  assert.match(crlHtml, /A1B2C/);
  assert.match(crlHtml, /Key compromise/);
  assert.match(crlHtml, /ca\.crl\.der/);
  assert.match(crlHtml, /openssl verify -crl_check/);
  assert.ok(!crlHtml.includes('undefined'));

  // Key tools: details and the converted file.
  const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
  const tools = keyTools([{ name: 'k.pem', buffer: bytes(rsa.export({ type: 'pkcs1', format: 'pem' })) }], { action: 'pkcs8', newPassword: 'new-pass-1' });
  const toolsHtml = render('renderKeyTools(__data)', tools);
  assert.match(toolsHtml, /RSA 2048/);
  assert.match(toolsHtml, /PKCS#1 \(RSA\)/);
  assert.match(toolsHtml, /Encrypted PKCS#8/);
  assert.match(toolsHtml, /private-key-pkcs8\.pem/);
  assert.ok(!toolsHtml.includes('new-pass-1'), 'the password is never shown');
  assert.ok(!toolsHtml.includes('undefined'));
  const inspect = render('renderKeyTools(__data)', keyTools([{ name: 'k.pem', buffer: bytes(rsa.export({ type: 'pkcs8', format: 'pem' })) }], {}));
  assert.match(inspect, /SPKI pin/);
});
