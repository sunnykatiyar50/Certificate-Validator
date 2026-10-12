const express = require('express');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { parseCertificateInput, buildReport, wrapDer } = require('./lib/certificate');
const { fetchServerChain, LiveCheckError } = require('./lib/liveCheck');
const { generateKeyPair, listAlgorithms, KeygenError } = require('./lib/keygen');
const { InputError } = require('./lib/bundle');
const { KeyError } = require('./lib/keys');
const { JksError } = require('./lib/jks');
const { convert, ConvertError } = require('./lib/convert');
const { decode } = require('./lib/decode');
const { matchKeys } = require('./lib/match');
const { createCa, signCsr, createCsr, CaError } = require('./lib/ca');
const { version: PACKAGE_VERSION } = require('./package.json');

// package.json is the single source of truth for the version; images are tagged from it.
const APP_VERSION = process.env.APP_VERSION || PACKAGE_VERSION;

const MAX_UPLOAD_BYTES = 1024 * 1024; // 1 MB is far more than any certificate or PFX bundle needs
const ALLOWED_EXTENSIONS = new Set(['.pem', '.crt', '.cer', '.der', '.pfx', '.p12']);
// The converter, decoder and CA tools also take keys, requests, revocation lists and keystores.
const TOOL_EXTENSIONS = new Set([...ALLOWED_EXTENSIONS, '.cert', '.key', '.csr', '.crl', '.p7b', '.p7c', '.jks', '.keystore']);
const MAX_TOOL_FILES = 6;
const USER_ERRORS = [InputError, ConvertError, CaError, KeygenError, KeyError, JksError];

// Express treats a "trust proxy" string as a list of IPs/subnets, so values from an environment
// variable must be converted: "1" is a hop count, "true"/"false" are booleans, anything else
// (e.g. "loopback, 10.0.0.0/8") is passed through as an address list.
function parseTrustProxy(value) {
  if (value === undefined || value === null) return undefined;
  const v = String(value).trim();
  if (v === '') return undefined;
  if (/^(true|yes|on)$/i.test(v)) return true;
  if (/^(false|no|off)$/i.test(v)) return false;
  if (/^[0-9]+$/.test(v)) return Number(v);
  return v;
}

function createApp({ allowPrivateHosts = false, enableRateLimit = true, corsOrigin = process.env.CORS_ORIGIN } = {}) {
  const app = express();
  const trustProxy = parseTrustProxy(process.env.TRUST_PROXY);
  if (trustProxy !== undefined) app.set('trust proxy', trustProxy);

  // The frontend is served from the same origin, so CORS stays off unless explicitly configured.
  if (corsOrigin) app.use(cors({ origin: corsOrigin.split(',') }));
  app.use(express.static(path.join(__dirname, 'public')));
  app.use(express.json({ limit: '1mb' }));

  app.get('/healthz', (req, res) => res.json({ status: 'ok' }));
  app.get('/api/version', (req, res) => res.json({ version: APP_VERSION }));

  const limiter = (max, message) => enableRateLimit
    ? rateLimit({ windowMs: 60 * 1000, limit: max, standardHeaders: true, legacyHeaders: false, message: { error: message } })
    : (req, res, next) => next();

  // Files are kept in memory and never written to disk.
  const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: MAX_UPLOAD_BYTES, files: 1 },
    fileFilter: (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      if (!ALLOWED_EXTENSIONS.has(ext)) {
        return cb(new Error(`Unsupported file type. Allowed: ${[...ALLOWED_EXTENSIONS].join(', ')}`));
      }
      cb(null, true);
    }
  });

  // The converter, decoder, key matcher and CA tools accept several files plus pasted text. Everything stays in memory
  // and responses are marked no-store because they can contain private keys.
  const toolUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: MAX_UPLOAD_BYTES, files: MAX_TOOL_FILES, fields: 30 },
    fileFilter: (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      if (!TOOL_EXTENSIONS.has(ext)) return cb(new Error(`Unsupported file type. Allowed: ${[...TOOL_EXTENSIONS].join(', ')}`));
      cb(null, true);
    }
  }).any();

  // Inputs for one tool field: uploaded files with that field name, then the pasted text (if any).
  const inputsFor = (req, fileField, textField) => {
    const inputs = (req.files || []).filter(f => f.fieldname === fileField).map(f => ({ name: f.originalname, buffer: f.buffer }));
    const text = req.body && req.body[textField];
    if (typeof text === 'string' && text.trim()) inputs.push({ name: null, buffer: Buffer.from(text) });
    return inputs;
  };

  const flag = value => value === true || value === 'true' || value === 'on' || value === '1';

  const tool = (max, message, handler) => [
    limiter(max, message),
    toolUpload,
    async (req, res) => {
      res.set('Cache-Control', 'no-store');
      try {
        res.json(await handler(req));
      } catch (err) {
        if (USER_ERRORS.some(E => err instanceof E)) return res.status(400).json({ error: err.message });
        console.error('Tool request failed:', err.message);
        res.status(500).json({ error: 'The request failed.' });
      }
    }
  ];

  app.post('/api/convert', ...tool(30, 'Too many conversions, please try again shortly.', req => {
    const b = req.body || {};
    return convert(inputsFor(req, 'files', 'text'), b.format, {
      password: b.password, outputPassword: b.outputPassword, alias: b.alias, legacy: flag(b.legacy)
    });
  }));

  app.post('/api/decode', ...tool(60, 'Too many requests, please try again shortly.', req => {
    const inputs = inputsFor(req, 'files', 'text');
    if (!inputs.length) throw new InputError('Provide a file or paste some text to decode.');
    return decode(inputs, { password: (req.body || {}).password });
  }));

  app.post('/api/match', ...tool(60, 'Too many requests, please try again shortly.', req => {
    const inputs = inputsFor(req, 'files', 'text');
    if (!inputs.length) throw new InputError('Provide at least one file or some pasted text.');
    return matchKeys(inputs, { password: (req.body || {}).password });
  }));

  app.post('/api/csr/create', ...tool(30, 'Too many requests, please try again shortly.', req => {
    const b = req.body || {};
    return createCsr(inputsFor(req, 'key', 'keyText'), {
      keyPassword: b.keyPassword, certificateInputs: inputsFor(req, 'cert', 'certText'),
      commonName: b.commonName, sans: b.sans, hash: b.hash,
      organization: b.organization, organizationalUnit: b.organizationalUnit, country: b.country, state: b.state, locality: b.locality
    });
  }));

  app.post('/api/ca/create', ...tool(20, 'Too many requests, please try again shortly.', req => {
    const b = req.body || {};
    return createCa(b, { issuerInputs: inputsFor(req, 'issuer', 'issuerText'), issuerPassword: b.issuerPassword });
  }));

  app.post('/api/ca/sign', ...tool(30, 'Too many requests, please try again shortly.', req => {
    const b = req.body || {};
    return signCsr(inputsFor(req, 'csr', 'csrText'), inputsFor(req, 'ca', 'caText'), {
      caPassword: b.caPassword, validityDays: b.validityDays, hash: b.hash, usage: b.usage,
      copySans: b.copySans === undefined ? undefined : flag(b.copySans), sans: b.sans, pathLength: b.pathLength
    });
  }));

  app.post('/api/validate-certificate', limiter(60, 'Too many requests, please try again shortly.'), upload.single('certificate'), async (req, res) => {
    const password = req.body.password || '';
    const hostname = (req.body.hostname || '').trim() || undefined;
    const certText = req.body.certText;
    let result;
    if (certText) {
      result = await parseCertificateInput({ certText, password, hostname });
    } else if (req.file) {
      result = await parseCertificateInput({ buffer: req.file.buffer, originalName: req.file.originalname, password, hostname });
    } else {
      result = { certs: [], error: 'No certificate provided.' };
    }
    res.json(result);
  });

  app.post('/api/check-host', limiter(10, 'Too many live checks, please try again in a minute.'), async (req, res) => {
    const { host, port } = req.body || {};
    try {
      const live = await fetchServerChain(host, port, { allowPrivate: allowPrivateHosts });
      const report = buildReport(live.ders.map(wrapDer), { hostname: live.host });
      res.json({ ...report, hasPrivateKey: false, error: null, live: { host: live.host, port: live.port, address: live.address, ...live.tlsInfo } });
    } catch (err) {
      const status = err instanceof LiveCheckError ? 400 : 500;
      res.status(status).json({ certs: [], error: err instanceof LiveCheckError ? err.message : 'Live check failed.' });
    }
  });

  app.get('/api/algorithms', (req, res) => res.json({ algorithms: listAlgorithms() }));

  // Generated private keys are returned once in the response and never stored or logged by the server.
  app.post('/api/generate-keypair', limiter(20, 'Too many key generation requests, please try again in a minute.'), async (req, res) => {
    res.set('Cache-Control', 'no-store');
    try {
      res.json(await generateKeyPair(req.body || {}));
    } catch (err) {
      if (err instanceof KeygenError) return res.status(400).json({ error: err.message });
      console.error('Key generation failed:', err.message);
      res.status(500).json({ error: 'Key generation failed.' });
    }
  });

  // JSON error responses for upload problems (size, type) and anything unexpected.
  app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
      const message = err.code === 'LIMIT_FILE_SIZE'
        ? `File too large (max ${MAX_UPLOAD_BYTES / 1024 / 1024} MB).`
        : `Upload error: ${err.message}`;
      return res.status(400).json({ certs: [], error: message });
    }
    if (err.type === 'entity.too.large' || err.type === 'entity.parse.failed') {
      return res.status(400).json({ certs: [], error: 'Invalid or oversized request body.' });
    }
    if (err.message && err.message.startsWith('Unsupported file type')) {
      return res.status(400).json({ certs: [], error: err.message });
    }
    console.error(err);
    res.status(500).json({ certs: [], error: 'Internal server error.' });
  });

  return app;
}

if (require.main === module) {
  const PORT = process.env.PORT || 33003;
  createApp({ allowPrivateHosts: process.env.ALLOW_PRIVATE_HOSTS === '1' }).listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

module.exports = { createApp, parseTrustProxy };
