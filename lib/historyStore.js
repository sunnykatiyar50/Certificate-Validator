const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const { DatabaseSync } = require('./sqlite');

const MAX_ENTRIES_PER_OWNER = 500;
const MAX_NAME_LENGTH = 80;
const MAX_PEM_LENGTH = 20000;

class HistoryError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

const string = (value, max, field, { required = false } = {}) => {
  if (value === undefined || value === null || value === '') {
    if (required) throw new HistoryError(`${field} is required.`);
    return null;
  }
  if (typeof value !== 'string') throw new HistoryError(`${field} must be text.`);
  if (value.length > max) throw new HistoryError(`${field} is too long.`);
  return value;
};

const pem = (value, label, field) => {
  const text = string(value, MAX_PEM_LENGTH, field);
  if (text !== null && !new RegExp(`^-----BEGIN ${label}-----[A-Za-z0-9+/=\\s]+-----END ${label}-----\\s*$`).test(text)) {
    throw new HistoryError(`${field} is not valid PEM.`);
  }
  return text;
};

const isoDate = (value, field) => {
  const text = string(value, 40, field);
  if (text !== null && Number.isNaN(Date.parse(text))) throw new HistoryError(`${field} is not a valid date.`);
  return text;
};

/**
 * Validate a history entry sent by a client and return only the fields we store.
 * Private keys are refused outright: the server never stores them.
 */
function sanitizeEntry(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new HistoryError('Invalid history entry.');
  if (input.privateKeyPem !== undefined && input.privateKeyPem !== null) {
    throw new HistoryError('Private keys are never stored on the server.');
  }
  const sans = input.sans === undefined || input.sans === null ? [] : input.sans;
  if (!Array.isArray(sans) || sans.length > 50 || sans.some(s => typeof s !== 'string' || s.length > 300)) {
    throw new HistoryError('sans must be a list of up to 50 short strings.');
  }
  const output = input.certificatePem ? 'certificate' : input.csrPem ? 'csr' : 'keys';
  return {
    name: string(typeof input.name === 'string' ? input.name.trim() : input.name, MAX_NAME_LENGTH, 'name', { required: true }),
    data: {
      output,
      algorithm: string(input.algorithm, 40, 'algorithm', { required: true }),
      algorithmLabel: string(input.algorithmLabel, 60, 'algorithmLabel') || string(input.algorithm, 40, 'algorithm'),
      hash: string(input.hash, 20, 'hash'),
      subject: string(input.subject, 200, 'subject'),
      sans,
      isCA: input.isCA === true,
      notBefore: isoDate(input.notBefore, 'notBefore'),
      notAfter: isoDate(input.notAfter, 'notAfter'),
      fingerprintSha256: string(input.fingerprintSha256, 120, 'fingerprintSha256'),
      certificatePem: pem(input.certificatePem, 'CERTIFICATE', 'certificatePem'),
      csrPem: pem(input.csrPem, 'CERTIFICATE REQUEST', 'csrPem'),
      publicKeyPem: pem(input.publicKeyPem, 'PUBLIC KEY', 'publicKeyPem')
    }
  };
}

function cleanName(name) {
  const value = string(typeof name === 'string' ? name.trim() : name, MAX_NAME_LENGTH, 'name', { required: true });
  return value;
}

class HistoryStore {
  constructor(file = ':memory:') {
    if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
    this.db = new DatabaseSync(file);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS history (
        id TEXT PRIMARY KEY,
        owner TEXT NOT NULL,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL,
        data TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_history_owner ON history (owner, created_at DESC);
    `);
  }

  static toEntry(row) {
    return { id: row.id, owner: row.owner, name: row.name, createdAt: row.created_at, ...JSON.parse(row.data) };
  }

  // owner === null lists everyone's entries (admin view).
  list(owner = null) {
    const rows = owner === null
      ? this.db.prepare('SELECT * FROM history ORDER BY created_at DESC, rowid DESC').all()
      : this.db.prepare('SELECT * FROM history WHERE owner = ? ORDER BY created_at DESC, rowid DESC').all(owner);
    return rows.map(HistoryStore.toEntry);
  }

  get(id) {
    const row = this.db.prepare('SELECT * FROM history WHERE id = ?').get(id);
    return row ? HistoryStore.toEntry(row) : null;
  }

  add(owner, input) {
    const { count } = this.db.prepare('SELECT COUNT(*) AS count FROM history WHERE owner = ?').get(owner);
    if (count >= MAX_ENTRIES_PER_OWNER) {
      throw new HistoryError(`History is full (${MAX_ENTRIES_PER_OWNER} items). Delete some items first.`, 409);
    }
    const { name, data } = sanitizeEntry(input);
    const id = crypto.randomUUID();
    const createdAt = new Date().toISOString();
    this.db.prepare('INSERT INTO history (id, owner, name, created_at, data) VALUES (?, ?, ?, ?, ?)')
      .run(id, owner, name, createdAt, JSON.stringify(data));
    return this.get(id);
  }

  rename(id, name) {
    this.db.prepare('UPDATE history SET name = ? WHERE id = ?').run(cleanName(name), id);
    return this.get(id);
  }

  delete(id) {
    return this.db.prepare('DELETE FROM history WHERE id = ?').run(id).changes > 0;
  }

  deleteAllFor(owner) {
    return Number(this.db.prepare('DELETE FROM history WHERE owner = ?').run(owner).changes);
  }

  close() {
    this.db.close();
  }
}

module.exports = { HistoryStore, HistoryError, sanitizeEntry, MAX_ENTRIES_PER_OWNER };
