// Server-side storage for private keys and CAs that a user chose to keep on the server.
// Every private key is encrypted at rest (AES-256-GCM) with a key that is not in the database: VAULT_KEY if set,
// otherwise a random key created once in the data folder. Rows are bound to their owner, so one user can never
// read another's keys, and an administrator is no exception.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('./sqlite');

const MAX_CAS_PER_OWNER = 50;
const MAX_KEYS_PER_OWNER = 500;
const MAX_NAME_LENGTH = 80;
const MAX_KEY_LENGTH = 20000;
const MAX_CERT_LENGTH = 40000;

class VaultError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

/** The 32-byte key that protects stored private keys. */
function loadVaultKey({ env = process.env, dataDir }) {
  const configured = env.VAULT_KEY;
  if (configured) {
    if (configured.length < 32) throw new Error('VAULT_KEY must be at least 32 characters (generate one with: npm run hash-password -- --secret).');
    return Buffer.from(crypto.hkdfSync('sha256', configured, 'certificate-workbench', 'vault-v1', 32));
  }
  const file = path.join(dataDir, 'vault.key');
  try {
    return Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'base64');
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }
  fs.mkdirSync(dataDir, { recursive: true });
  const key = crypto.randomBytes(32);
  try {
    fs.writeFileSync(file, key.toString('base64'), { mode: 0o600, flag: 'wx' });
  } catch (err) {
    if (err.code === 'EEXIST') return Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'base64');
    throw err;
  }
  return key;
}

const seal = (key, id, owner, plain) => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(`${id}\n${owner}`));
  const data = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), data]).toString('base64');
};

const open = (key, id, owner, blob) => {
  const raw = Buffer.from(blob, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, raw.subarray(0, 12));
  decipher.setAAD(Buffer.from(`${id}\n${owner}`));
  decipher.setAuthTag(raw.subarray(12, 28));
  return Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString('utf8');
};

const PEM_KEY = /^-----BEGIN PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END PRIVATE KEY-----\s*$/;
const PEM_CERT = /^(-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*)+$/;

const keyPem = value => {
  if (typeof value !== 'string' || value.length > MAX_KEY_LENGTH || !PEM_KEY.test(value)) {
    throw new VaultError('The private key must be an unencrypted PKCS#8 PEM.');
  }
  return value;
};

const nameOf = value => {
  const name = typeof value === 'string' ? value.trim() : '';
  if (!name) throw new VaultError('A name is required.');
  if (name.length > MAX_NAME_LENGTH) throw new VaultError('That name is too long.');
  return name;
};

class Vault {
  constructor(file, key) {
    if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
    this.key = key;
    this.db = new DatabaseSync(file);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS vault (
        id TEXT PRIMARY KEY,
        owner TEXT NOT NULL,
        kind TEXT NOT NULL,
        name TEXT,
        created_at TEXT NOT NULL,
        meta TEXT,
        cert_pem TEXT,
        key_enc TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_vault_owner ON vault (owner, kind);
    `);
  }

  count(owner, kind) {
    return this.db.prepare('SELECT COUNT(*) AS n FROM vault WHERE owner = ? AND kind = ?').get(owner, kind).n;
  }

  // ----- a private key kept for a history item (the certificate itself lives in the history) -----

  putKey(owner, id, privateKeyPem) {
    const pem = keyPem(privateKeyPem);
    const existing = this.db.prepare('SELECT owner FROM vault WHERE id = ?').get(id);
    if (existing && existing.owner !== owner) throw new VaultError('Not found.', 404);
    if (!existing && this.count(owner, 'key') >= MAX_KEYS_PER_OWNER) {
      throw new VaultError(`You can keep up to ${MAX_KEYS_PER_OWNER} private keys on the server.`, 409);
    }
    this.db.prepare('INSERT OR REPLACE INTO vault (id, owner, kind, name, created_at, meta, cert_pem, key_enc) VALUES (?, ?, ?, NULL, ?, NULL, NULL, ?)')
      .run(id, owner, 'key', new Date().toISOString(), seal(this.key, id, owner, pem));
  }

  keyIds(owner) {
    return this.db.prepare('SELECT id FROM vault WHERE owner = ? AND kind = ?').all(owner, 'key').map(r => r.id);
  }

  getKey(owner, id) {
    const row = this.db.prepare('SELECT * FROM vault WHERE id = ? AND owner = ? AND kind = ?').get(id, owner, 'key');
    return row ? open(this.key, row.id, row.owner, row.key_enc) : null;
  }

  // ----- certificate authorities -----

  static toCa(row) {
    return { id: row.id, name: row.name, createdAt: row.created_at, ...JSON.parse(row.meta), certificatePem: row.cert_pem };
  }

  listCas(owner) {
    return this.db.prepare('SELECT * FROM vault WHERE owner = ? AND kind = ? ORDER BY created_at DESC, rowid DESC').all(owner, 'ca').map(Vault.toCa);
  }

  getCa(owner, id) {
    const row = this.db.prepare('SELECT * FROM vault WHERE id = ? AND owner = ? AND kind = ?').get(id, owner, 'ca');
    return row ? Vault.toCa(row) : null;
  }

  /** A saved CA with its private key (PKCS#8 PEM), ready to sign with. */
  getCaMaterial(owner, id) {
    const row = this.db.prepare('SELECT * FROM vault WHERE id = ? AND owner = ? AND kind = ?').get(id, owner, 'ca');
    return row ? { ...Vault.toCa(row), privateKeyPem: open(this.key, row.id, row.owner, row.key_enc) } : null;
  }

  addCa(owner, { name, certificatePem, privateKeyPem, summary }) {
    if (this.count(owner, 'ca') >= MAX_CAS_PER_OWNER) {
      throw new VaultError(`You can keep up to ${MAX_CAS_PER_OWNER} CAs on the server. Delete one first.`, 409);
    }
    if (typeof certificatePem !== 'string' || certificatePem.length > MAX_CERT_LENGTH || !PEM_CERT.test(certificatePem)) {
      throw new VaultError('The CA certificate is not valid PEM.');
    }
    const id = crypto.randomUUID();
    this.db.prepare('INSERT INTO vault (id, owner, kind, name, created_at, meta, cert_pem, key_enc) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(id, owner, 'ca', nameOf(name), new Date().toISOString(), JSON.stringify(summary || {}), certificatePem, seal(this.key, id, owner, keyPem(privateKeyPem)));
    return this.getCa(owner, id);
  }

  rename(owner, id, name) {
    const changed = this.db.prepare('UPDATE vault SET name = ? WHERE id = ? AND owner = ? AND kind = ?').run(nameOf(name), id, owner, 'ca').changes;
    return changed ? this.getCa(owner, id) : null;
  }

  // Works for CAs and kept keys alike.
  delete(owner, id) {
    return this.db.prepare('DELETE FROM vault WHERE id = ? AND owner = ?').run(id, owner).changes > 0;
  }

  deleteKeys(owner) {
    return Number(this.db.prepare('DELETE FROM vault WHERE owner = ? AND kind = ?').run(owner, 'key').changes);
  }

  close() {
    this.db.close();
  }
}

module.exports = { Vault, VaultError, loadVaultKey, MAX_CAS_PER_OWNER };
