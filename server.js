const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { parseCertificateInput, buildReport, wrapDer } = require('./lib/certificate');
const { fetchServerChain, LiveCheckError } = require('./lib/liveCheck');
const { generateKeyPair, listAlgorithms, KeygenError } = require('./lib/keygen');
const { AuthConfigError, loadAuthConfig, createAuth } = require('./lib/auth');
const { HistoryStore, HistoryError } = require('./lib/historyStore');
const { loadReleaseNotes } = require('./lib/changelog');
const { InputError } = require('./lib/bundle');
const { KeyError } = require('./lib/keys');
const { JksError } = require('./lib/jks');
const { convert, ConvertError } = require('./lib/convert');
const { decode } = require('./lib/decode');
const { matchKeys } = require('./lib/match');
const { createCa, signCsr, createCsr, CaError } = require('./lib/ca');
const { issueDevCertificate } = require('./lib/devcert');
const { createCrl } = require('./lib/crl');
const { keyTools } = require('./lib/keytools');
const { createAssetVersioner } = require('./lib/assets');
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

function createApp({
  allowPrivateHosts = false,
  enableRateLimit = true,
  corsOrigin = process.env.CORS_ORIGIN,
  auth: authConfig = loadAuthConfig(process.env),
  historyStore = null,
  dataDir = process.env.DATA_DIR || path.join(__dirname, 'data'),
  publicDir = path.join(__dirname, 'public')
} = {}) {
  const app = express();
  app.disable('x-powered-by');
  const trustProxy = parseTrustProxy(process.env.TRUST_PROXY);
  if (trustProxy !== undefined) app.set('trust proxy', trustProxy);

  const auth = createAuth(authConfig);
  // The history database is opened on first use, so apps that never touch history create no files.
  let store = historyStore;
  const getStore = () => (store = store || new HistoryStore(path.join(dataDir, 'history.db')));

  app.use(helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"]
      }
    }
  }));

  // The frontend is served from the same origin, so CORS stays off unless explicitly configured.
  if (corsOrigin) app.use(cors({ origin: corsOrigin.split(','), credentials: true }));
  app.use(express.json({ limit: '1mb' }));

  const limiter = (max, message) => enableRateLimit
    ? rateLimit({ windowMs: 60 * 1000, limit: max, standardHeaders: true, legacyHeaders: false, message: { error: message } })
    : (req, res, next) => next();

  // Failed sign-ins only: 10 per 15 minutes per client address.
  const loginLimiter = enableRateLimit
    ? rateLimit({
      windowMs: 15 * 60 * 1000, limit: 10, skipSuccessfulRequests: true, standardHeaders: true, legacyHeaders: false,
      message: { error: 'Too many failed sign-in attempts. Try again in 15 minutes.' }
    })
    : (req, res, next) => next();

  // ----- public endpoints -----
  app.get('/healthz', (req, res) => res.json({ status: 'ok' }));
  app.get('/api/version', (req, res) => res.json({ version: APP_VERSION }));
  app.post('/auth/login', loginLimiter, auth.login);
  app.post('/auth/logout', auth.logout);
  app.get('/auth/status', auth.status);

  // ----- pages: the app itself needs a session, the login page is public -----
  // Pages are never cached, and their style and script links carry a fingerprint of the file (style.css?v=...),
  // so a proxy, CDN or browser holding an old copy of an asset can never be paired with a newer page.
  const assets = createAssetVersioner(publicDir);
  const sendPage = (res, file) => {
    res.set('Cache-Control', 'no-store');
    res.type('html').send(assets.versionPage(fs.readFileSync(path.join(publicDir, file), 'utf8')));
  };
  app.get(['/', '/index.html'], (req, res) => (auth.currentUser(req) ? sendPage(res, 'index.html') : res.redirect('/login.html')));
  app.get('/login.html', (req, res) => (auth.currentUser(req) ? res.redirect('/') : sendPage(res, 'login.html')));

  // A fingerprinted asset URL can be cached for a year because its URL changes with its content. Anything else
  // (no fingerprint, or an old one from a stale page) must be revalidated every time.
  app.use((req, res, next) => {
    const name = req.path.slice(1);
    const current = /\.(?:css|js)$/.test(name) && req.query.v && req.query.v === assets.hashOf(name);
    res.set('Cache-Control', current ? 'public, max-age=31536000, immutable' : 'no-cache');
    next();
  });
  app.use(express.static(publicDir, { index: false, cacheControl: false }));

  // ----- everything under /api (except /api/version) requires a signed-in user -----
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

  // Every tool needs a signed-in user: they accept private keys, keystores and CA material.
  const tool = (max, message, handler) => [
    auth.requireAuth,
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
      copySans: b.copySans === undefined ? undefined : flag(b.copySans), sans: b.sans, pathLength: b.pathLength,
      crlUrl: b.crlUrl
    });
  }));

  // Local development helpers. Like the other tools they take keys, so they need a session, run in memory and
  // are never cached. A dev certificate comes with a new CA unless an existing CA is supplied.
  app.post('/api/dev-cert', ...tool(20, 'Too many requests, please try again shortly.', req => {
    const b = req.body || {};
    return issueDevCertificate({
      names: b.names, algorithm: b.algorithm, hash: b.hash, validityDays: b.validityDays, clientAuth: flag(b.clientAuth),
      crlUrl: b.crlUrl, bundlePassword: b.bundlePassword,
      caName: b.caName, caAlgorithm: b.caAlgorithm, caValidityDays: b.caValidityDays, scope: b.scope
    }, { caInputs: inputsFor(req, 'ca', 'caText'), caPassword: b.caPassword });
  }));

  app.post('/api/crl/create', ...tool(30, 'Too many requests, please try again shortly.', req => {
    const b = req.body || {};
    const caInputs = inputsFor(req, 'ca', 'caText');
    if (!caInputs.length) throw new InputError('Provide the CA certificate and private key that sign the CRL.');
    return createCrl(caInputs, {
      caPassword: b.caPassword, serials: b.serials, reason: b.reason, nextUpdateDays: b.nextUpdateDays, hash: b.hash,
      certificateInputs: inputsFor(req, 'cert', 'certText'), previousCrlInputs: inputsFor(req, 'previous', 'previousText')
    });
  }));

  app.post('/api/key-tools', ...tool(60, 'Too many requests, please try again shortly.', req => {
    const b = req.body || {};
    return keyTools(inputsFor(req, 'files', 'text'), { password: b.password, action: b.action, newPassword: b.newPassword });
  }));

  app.post('/api/validate-certificate', auth.requireAuth, limiter(60, 'Too many requests, please try again shortly.'), upload.single('certificate'), async (req, res) => {
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

  app.post('/api/check-host', auth.requireAuth, limiter(10, 'Too many live checks, please try again in a minute.'), async (req, res) => {
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

  // Release notes for the "what's new" popover, from CHANGELOG.md.
  app.get('/api/release-notes', auth.requireAuth, (req, res) => {
    res.json({ version: APP_VERSION, releases: loadReleaseNotes() });
  });

  app.get('/api/algorithms', auth.requireAuth, (req, res) => res.json({ algorithms: listAlgorithms() }));

  // Generated private keys are returned once in the response and never stored or logged by the server.
  app.post('/api/generate-keypair', auth.requireAuth, limiter(20, 'Too many key generation requests, please try again in a minute.'), async (req, res) => {
    res.set('Cache-Control', 'no-store');
    try {
      res.json(await generateKeyPair(req.body || {}));
    } catch (err) {
      if (err instanceof KeygenError) return res.status(400).json({ error: err.message });
      console.error('Key generation failed:', err.message);
      res.status(500).json({ error: 'Key generation failed.' });
    }
  });

  // ----- history: users see their own items, admins see everyone's -----
  const isAdmin = req => req.user.role === 'admin';
  // A user may only touch their own entries (admins any). Others get 404 so IDs cannot be probed.
  const findAccessible = (req, id) => {
    const entry = getStore().get(id);
    return entry && (isAdmin(req) || entry.owner === req.user.username) ? entry : null;
  };

  app.get('/api/history', auth.requireAuth, (req, res) => {
    res.set('Cache-Control', 'no-store');
    let owner = req.user.username;
    if (isAdmin(req)) owner = typeof req.query.owner === 'string' && req.query.owner ? req.query.owner : null;
    res.json({ history: getStore().list(owner), user: { username: req.user.username, role: req.user.role } });
  });

  app.post('/api/history', auth.requireAuth, limiter(60, 'Too many requests, please try again shortly.'), (req, res) => {
    res.status(201).json({ entry: getStore().add(req.user.username, req.body) });
  });

  app.patch('/api/history/:id', auth.requireAuth, (req, res) => {
    if (!findAccessible(req, req.params.id)) return res.status(404).json({ error: 'History item not found.' });
    res.json({ entry: getStore().rename(req.params.id, (req.body || {}).name) });
  });

  app.delete('/api/history/:id', auth.requireAuth, (req, res) => {
    if (!findAccessible(req, req.params.id)) return res.status(404).json({ error: 'History item not found.' });
    getStore().delete(req.params.id);
    res.json({ ok: true });
  });

  // Clears the signed-in user's own history only.
  app.delete('/api/history', auth.requireAuth, (req, res) => {
    res.json({ deleted: getStore().deleteAllFor(req.user.username) });
  });

  // JSON error responses for upload problems (size, type), bad history input and anything unexpected.
  app.use((err, req, res, next) => {
    if (err instanceof HistoryError) return res.status(err.status).json({ error: err.message });
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
  // First line of the log, so it is always clear which build is running (even if the start-up fails below).
  console.log(`Certificate Workbench v${APP_VERSION} (Node.js ${process.version})`);
  let authConfig;
  try {
    authConfig = loadAuthConfig(process.env);
  } catch (err) {
    if (!(err instanceof AuthConfigError)) throw err;
    console.error(`${err.message}\n\nSee sample.env. To run without a login for local development, set AUTH_DISABLED=1.`);
    process.exit(1);
  }
  if (authConfig.disabled) console.warn('WARNING: AUTH_DISABLED is set. Everyone can use the app as an admin without signing in.');

  const PORT = process.env.PORT || 33003;
  createApp({ auth: authConfig, allowPrivateHosts: process.env.ALLOW_PRIVATE_HOSTS === '1' }).listen(PORT, () => {
    const users = authConfig.accounts.filter(a => a.role === 'user').length;
    const signIn = authConfig.disabled ? 'DISABLED' : `enabled (1 admin, ${users} user${users === 1 ? '' : 's'})`;
    console.log(`Server running on http://localhost:${PORT} | v${APP_VERSION} | sign-in ${signIn} | data ${process.env.DATA_DIR || path.join(__dirname, 'data')}`);
  });
}

module.exports = { createApp, parseTrustProxy };
