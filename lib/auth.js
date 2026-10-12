const crypto = require('crypto');

const COOKIE_NAME = 'cv_session';
const USERNAME_RE = /^[A-Za-z0-9._@-]{1,64}$/;
const PLACEHOLDER_RE = /change[-_ ]?me/i;
const MIN_PASSWORD_LENGTH = 8;
const MIN_SECRET_LENGTH = 32;
const MAX_INPUT_LENGTH = 256;
const SCRYPT = { N: 16384, r: 8, p: 1, keyLength: 32 };

class AuthConfigError extends Error {}

// ---------- passwords ----------

const sha256 = value => crypto.createHash('sha256').update(String(value)).digest();

// Constant-time string comparison (hashing first makes both sides the same length).
function safeEqual(a, b) {
  return crypto.timingSafeEqual(sha256(a), sha256(b));
}

// Hashed passwords look like "scrypt:N:r:p:salt:hash" (base64url). The format avoids "$" and ","
// so the value survives .env files, Docker Compose interpolation and the comma-separated USERS list.
function isHashed(stored) {
  return typeof stored === 'string' && stored.startsWith('scrypt:');
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(password), salt, SCRYPT.keyLength, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: 256 * SCRYPT.N * SCRYPT.r });
  return `scrypt:${SCRYPT.N}:${SCRYPT.r}:${SCRYPT.p}:${salt.toString('base64url')}:${hash.toString('base64url')}`;
}

function parseHash(stored) {
  const parts = stored.split(':');
  if (parts.length !== 6) return null;
  const [, N, r, p, salt, hash] = parts;
  const params = { N: Number(N), r: Number(r), p: Number(p) };
  if (!Object.values(params).every(Number.isInteger) || params.N < 2 || params.N > 1 << 20 || params.r < 1 || params.r > 32 || params.p < 1 || params.p > 16) return null;
  const saltBuf = Buffer.from(salt, 'base64url');
  const hashBuf = Buffer.from(hash, 'base64url');
  if (!saltBuf.length || !hashBuf.length) return null;
  return { ...params, salt: saltBuf, hash: hashBuf };
}

// Check a supplied password against a stored value (plain text or a scrypt hash).
function verifyPassword(stored, supplied) {
  const password = String(supplied);
  if (!isHashed(stored)) return safeEqual(stored, password);
  const parsed = parseHash(stored);
  if (!parsed) return false;
  try {
    const derived = crypto.scryptSync(password, parsed.salt, parsed.hash.length, { N: parsed.N, r: parsed.r, p: parsed.p, maxmem: 256 * parsed.N * parsed.r });
    return crypto.timingSafeEqual(derived, parsed.hash);
  } catch (e) {
    return false;
  }
}

// Used when the username is unknown so a failed login costs about the same as a real check.
const DUMMY_HASH = hashPassword(crypto.randomBytes(16).toString('hex'));

// ---------- configuration ----------

const isTruthy = value => /^(1|true|yes|on)$/i.test(String(value || '').trim());

function parseUsers(value, errors) {
  const users = [];
  for (const entry of String(value || '').split(',').map(s => s.trim()).filter(Boolean)) {
    const split = entry.indexOf(':');
    const username = split < 0 ? entry : entry.slice(0, split);
    const password = split < 0 ? '' : entry.slice(split + 1);
    if (!USERNAME_RE.test(username)) {
      errors.push(`USERS: invalid username "${username.slice(0, 40)}" (letters, digits and . _ @ - only, up to 64 characters).`);
      continue;
    }
    checkPassword(`USERS entry "${username}"`, password, errors);
    users.push({ username, password, role: 'user' });
  }
  return users;
}

function checkPassword(label, password, errors) {
  if (!password) errors.push(`${label}: password is missing.`);
  else if (PLACEHOLDER_RE.test(password)) errors.push(`${label}: replace the placeholder password.`);
  else if (!isHashed(password) && password.length < MIN_PASSWORD_LENGTH) errors.push(`${label}: password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
}

/**
 * Read the authentication settings from environment variables.
 *   ADMIN_USERNAME  (default "admin"), ADMIN_PASSWORD  - the admin account
 *   USERS           - regular users as "alice:password,bob:password"
 *   SESSION_SECRET  - at least 32 characters; signs the session cookie
 *   SESSION_TTL_HOURS (default 12), AUTH_DISABLED=1 (no login; everyone is "local" admin)
 * Passwords may be plain text or a hash from `npm run hash-password`.
 * Throws AuthConfigError listing everything that is wrong.
 */
function loadAuthConfig(env = process.env) {
  if (isTruthy(env.AUTH_DISABLED)) return { disabled: true, accounts: [] };

  const errors = [];
  const adminUsername = (env.ADMIN_USERNAME || 'admin').trim();
  if (!USERNAME_RE.test(adminUsername)) errors.push('ADMIN_USERNAME: letters, digits and . _ @ - only, up to 64 characters.');
  checkPassword('ADMIN_PASSWORD', env.ADMIN_PASSWORD || '', errors);

  const secret = env.SESSION_SECRET || '';
  if (secret.length < MIN_SECRET_LENGTH || PLACEHOLDER_RE.test(secret)) {
    errors.push(`SESSION_SECRET: set a random value of at least ${MIN_SECRET_LENGTH} characters (generate one with: npm run hash-password -- --secret).`);
  }

  const ttlHours = env.SESSION_TTL_HOURS === undefined || env.SESSION_TTL_HOURS === '' ? 12 : Number(env.SESSION_TTL_HOURS);
  if (!(ttlHours > 0 && ttlHours <= 24 * 30)) errors.push('SESSION_TTL_HOURS: must be a number between 0 and 720.');

  const accounts = [{ username: adminUsername, password: env.ADMIN_PASSWORD || '', role: 'admin' }, ...parseUsers(env.USERS, errors)];
  const seen = new Set();
  for (const account of accounts) {
    const key = account.username.toLowerCase();
    if (seen.has(key)) errors.push(`Duplicate username "${account.username}" (usernames are case-insensitive).`);
    seen.add(key);
  }

  if (errors.length) throw new AuthConfigError(`Invalid authentication settings:\n  - ${errors.join('\n  - ')}`);
  return { disabled: false, accounts, secret, ttlMs: ttlHours * 3600 * 1000 };
}

// ---------- sessions ----------

// A short fingerprint of the stored password, so changing a password signs that account out everywhere.
function passwordFingerprint(secret, account) {
  return crypto.createHmac('sha256', secret).update(`pw:${account.password}`).digest('base64url').slice(0, 16);
}

function sign(secret, body) {
  return crypto.createHmac('sha256', secret).update(body).digest('base64url');
}

function createToken(config, account, now = Date.now()) {
  const payload = { u: account.username, r: account.role, p: passwordFingerprint(config.secret, account), exp: now + config.ttlMs };
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${body}.${sign(config.secret, body)}`;
}

function readToken(config, token, now = Date.now()) {
  if (typeof token !== 'string') return null;
  const dot = token.indexOf('.');
  if (dot < 1) return null;
  const body = token.slice(0, dot);
  const mac = Buffer.from(token.slice(dot + 1), 'base64url');
  const expected = Buffer.from(sign(config.secret, body), 'base64url');
  if (mac.length !== expected.length || !crypto.timingSafeEqual(mac, expected)) return null;
  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch (e) {
    return null;
  }
  if (!payload || typeof payload.exp !== 'number' || payload.exp <= now) return null;
  // The account must still exist with the same role and password.
  const account = config.accounts.find(a => a.username === payload.u && a.role === payload.r);
  if (!account || payload.p !== passwordFingerprint(config.secret, account)) return null;
  return { username: account.username, role: account.role };
}

function readCookie(req, name) {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq > 0 && part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return null;
}

// ---------- express middleware ----------

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const LOCAL_USER = { username: 'local', role: 'admin', authDisabled: true };

function createAuth(config) {
  const accountsByName = new Map(config.accounts.map(a => [a.username.toLowerCase(), a]));

  function currentUser(req) {
    if (config.disabled) return LOCAL_USER;
    return readToken(config, readCookie(req, COOKIE_NAME));
  }

  // For API routes: 401 JSON when signed out. Cookie-authenticated writes must also carry the
  // X-Requested-With header, which a cross-site form or image request cannot add (CSRF defence
  // alongside SameSite=Strict).
  function requireAuth(req, res, next) {
    const user = currentUser(req);
    if (!user) return res.status(401).json({ error: 'Authentication required', certs: [] });
    if (!config.disabled && !SAFE_METHODS.has(req.method) && req.get('X-Requested-With') !== 'fetch') {
      return res.status(403).json({ error: 'Missing X-Requested-With header', certs: [] });
    }
    req.user = user;
    next();
  }

  function requireAdmin(req, res, next) {
    requireAuth(req, res, () => {
      if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required', certs: [] });
      next();
    });
  }

  function login(req, res) {
    if (config.disabled) return res.json({ username: LOCAL_USER.username, role: LOCAL_USER.role });
    if (req.get('X-Requested-With') !== 'fetch') return res.status(403).json({ error: 'Missing X-Requested-With header' });
    const { username, password } = req.body || {};
    if (typeof username !== 'string' || typeof password !== 'string' || !username || !password ||
        username.length > MAX_INPUT_LENGTH || password.length > MAX_INPUT_LENGTH) {
      return res.status(400).json({ error: 'Enter a username and password.' });
    }
    const account = accountsByName.get(username.trim().toLowerCase());
    const ok = verifyPassword(account ? account.password : DUMMY_HASH, password) && !!account;
    if (!ok) {
      console.warn(`Failed login for ${JSON.stringify(username.slice(0, 40))} from ${req.ip}`);
      return res.status(401).json({ error: 'Invalid username or password.' });
    }
    res.cookie(COOKIE_NAME, createToken(config, account), {
      httpOnly: true, sameSite: 'strict', secure: req.secure, path: '/', maxAge: config.ttlMs
    });
    res.json({ username: account.username, role: account.role });
  }

  function logout(req, res) {
    if (!config.disabled && req.get('X-Requested-With') !== 'fetch') return res.status(403).json({ error: 'Missing X-Requested-With header' });
    res.clearCookie(COOKIE_NAME, { httpOnly: true, sameSite: 'strict', secure: req.secure, path: '/' });
    res.json({ ok: true });
  }

  function status(req, res) {
    res.set('Cache-Control', 'no-store');
    const user = currentUser(req);
    res.json(user
      ? { authenticated: true, username: user.username, role: user.role, authDisabled: !!user.authDisabled }
      : { authenticated: false });
  }

  return { currentUser, requireAuth, requireAdmin, login, logout, status, disabled: config.disabled };
}

module.exports = {
  AuthConfigError, COOKIE_NAME, loadAuthConfig, createAuth, hashPassword, verifyPassword, isHashed,
  createToken, readToken, USERNAME_RE
};
