// Reader and writer for Java KeyStore (JKS) files, the classic "Sun" format.
//
// Layout: magic 0xFEEDFEED, version 2, entry count, entries, then a SHA-1 integrity digest of
// (password as UTF-16BE + "Mighty Aphrodite" + everything before it). Private keys are protected with Sun's
// own scheme (SHA-1 keystream XOR plus a SHA-1 check value) wrapped in an EncryptedPrivateKeyInfo.
// Both are weak by modern standards; JKS exists here for compatibility with older Java tools.
const crypto = require('crypto');

const MAGIC = 0xfeedfeed;
const MAGIC_JCEKS = 0xfeedfeee;
const VERSION = 2;
const TAG_KEY = 1;
const TAG_CERT = 2;
const KEY_PROTECTOR_OID = '1.3.6.1.4.1.42.2.17.1.1';
const WHITENER = Buffer.from('Mighty Aphrodite', 'utf8');
const MAX_ENTRIES = 1000;

class JksError extends Error {}

const sha1 = (...parts) => {
  const h = crypto.createHash('sha1');
  parts.forEach(p => h.update(p));
  return h.digest();
};

// Java hashes the password as UTF-16BE code units.
function passwordBytes(password) {
  const bytes = Buffer.alloc(password.length * 2);
  for (let i = 0; i < password.length; i++) bytes.writeUInt16BE(password.charCodeAt(i), i * 2);
  return bytes;
}

function integrityDigest(password, body) {
  return sha1(passwordBytes(password), WHITENER, body);
}

// ---- minimal DER helpers for EncryptedPrivateKeyInfo ----

function derLength(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

const der = (tag, ...parts) => {
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([tag]), derLength(body.length), body]);
};

function readDer(buf, offset) {
  if (offset + 2 > buf.length) throw new JksError('Corrupt private key entry.');
  const tag = buf[offset];
  let len = buf[offset + 1];
  let start = offset + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 4 || start + n > buf.length) throw new JksError('Corrupt private key entry.');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[start + i];
    start += n;
  }
  if (start + len > buf.length) throw new JksError('Corrupt private key entry.');
  return { tag, start, end: start + len };
}

function oidBytes(oid) {
  const parts = oid.split('.').map(Number);
  const out = [parts[0] * 40 + parts[1]];
  for (const p of parts.slice(2)) {
    const chunk = [p & 0x7f];
    for (let v = p >>> 7; v > 0; v >>>= 7) chunk.unshift((v & 0x7f) | 0x80);
    out.push(...chunk);
  }
  return Buffer.from(out);
}

// ---- Sun key protector ----

function keystream(pw, salt, length) {
  const stream = Buffer.alloc(length);
  let digest = salt;
  for (let i = 0; i < length; i += 20) {
    digest = sha1(pw, digest);
    digest.copy(stream, i, 0, Math.min(20, length - i));
  }
  return stream;
}

function xor(data, stream) {
  const out = Buffer.alloc(data.length);
  for (let i = 0; i < data.length; i++) out[i] = data[i] ^ stream[i];
  return out;
}

function protectKey(pkcs8, password) {
  const pw = passwordBytes(password);
  const salt = crypto.randomBytes(20);
  const blob = Buffer.concat([salt, xor(pkcs8, keystream(pw, salt, pkcs8.length)), sha1(pw, pkcs8)]);
  return der(0x30, der(0x30, der(0x06, oidBytes(KEY_PROTECTOR_OID)), der(0x05)), der(0x04, blob));
}

function unprotectKey(encrypted, password) {
  const outer = readDer(encrypted, 0);
  const alg = readDer(encrypted, outer.start);
  const oid = readDer(encrypted, alg.start);
  if (!encrypted.subarray(oid.start, oid.end).equals(oidBytes(KEY_PROTECTOR_OID))) {
    throw new JksError('This keystore entry uses an unsupported key protection algorithm.');
  }
  const blobDer = readDer(encrypted, alg.end);
  const blob = encrypted.subarray(blobDer.start, blobDer.end);
  if (blob.length < 40) throw new JksError('Corrupt private key entry.');
  const pw = passwordBytes(password);
  const salt = blob.subarray(0, 20);
  const masked = blob.subarray(20, blob.length - 20);
  const plain = xor(masked, keystream(pw, salt, masked.length));
  if (!sha1(pw, plain).equals(blob.subarray(blob.length - 20))) {
    throw new JksError('Wrong password for a private key in the keystore.');
  }
  return plain;
}

// ---- reader ----

function isJks(buf) {
  return buf.length >= 12 && (buf.readUInt32BE(0) === MAGIC || buf.readUInt32BE(0) === MAGIC_JCEKS);
}

/**
 * Parse a JKS keystore. Returns entries: { alias, type: 'key', pkcs8, chain: [der...] } or
 * { alias, type: 'cert', chain: [der] }. Throws JksError on a wrong password or corrupt file.
 */
function readJks(buf, password) {
  if (buf.length >= 4 && buf.readUInt32BE(0) === MAGIC_JCEKS) {
    throw new JksError('JCEKS keystores are not supported. Convert it to JKS or PKCS#12 with keytool first.');
  }
  if (!isJks(buf)) throw new JksError('Not a JKS keystore.');
  if (buf.length < 12 + 20) throw new JksError('Corrupt keystore.');
  const body = buf.subarray(0, buf.length - 20);
  if (!integrityDigest(password || '', body).equals(buf.subarray(buf.length - 20))) {
    throw new JksError('Incorrect password or corrupt keystore.');
  }

  let pos = 4;
  const need = n => { if (n < 0 || pos + n > body.length) throw new JksError('Corrupt keystore.'); };
  const u16 = () => { need(2); const v = body.readUInt16BE(pos); pos += 2; return v; };
  const i32 = () => { need(4); const v = body.readInt32BE(pos); pos += 4; return v; };
  const bytes = n => { need(n); const v = Buffer.from(body.subarray(pos, pos + n)); pos += n; return v; };
  const utf = () => bytes(u16()).toString('utf8');

  const version = i32();
  if (version !== VERSION && version !== 1) throw new JksError('Unsupported keystore version.');
  const count = i32();
  if (count < 0 || count > MAX_ENTRIES) throw new JksError('Corrupt keystore.');

  const entries = [];
  for (let i = 0; i < count; i++) {
    const tag = i32();
    const alias = utf();
    need(8);
    pos += 8; // creation timestamp
    if (tag === TAG_KEY) {
      const encrypted = bytes(i32());
      const chainLength = i32();
      if (chainLength < 0 || chainLength > 100) throw new JksError('Corrupt keystore.');
      const chain = [];
      for (let c = 0; c < chainLength; c++) {
        utf(); // certificate type, "X.509"
        chain.push(bytes(i32()));
      }
      entries.push({ alias, type: 'key', pkcs8: unprotectKey(encrypted, password || ''), chain });
    } else if (tag === TAG_CERT) {
      utf();
      entries.push({ alias, type: 'cert', chain: [bytes(i32())] });
    } else {
      throw new JksError('Corrupt keystore: unknown entry type.');
    }
  }
  return entries;
}

// ---- writer ----

/**
 * Build a JKS keystore. Entries: { alias, type: 'key', pkcs8: Buffer, chain: [Buffer...] } or
 * { alias, type: 'cert', chain: [Buffer] }. Aliases are stored in lower case, as Java does.
 */
function writeJks(entries, password) {
  if (!password) throw new JksError('A keystore password is required.');
  const i32 = v => { const b = Buffer.alloc(4); b.writeUInt32BE(v >>> 0); return b; };
  const utf = s => {
    const b = Buffer.from(s, 'utf8');
    if (b.length > 0xffff) throw new JksError('Alias is too long.');
    const len = Buffer.alloc(2);
    len.writeUInt16BE(b.length);
    return Buffer.concat([len, b]);
  };
  const timestamp = () => { const b = Buffer.alloc(8); b.writeBigInt64BE(BigInt(Date.now())); return b; };
  const cert = c => Buffer.concat([utf('X.509'), i32(c.length), c]);

  const parts = [i32(MAGIC), i32(VERSION), i32(entries.length)];
  const seen = new Set();
  for (const e of entries) {
    const alias = String(e.alias).toLowerCase();
    if (seen.has(alias)) throw new JksError(`Duplicate alias: ${alias}`);
    seen.add(alias);
    if (e.type === 'key') {
      const protectedKey = protectKey(e.pkcs8, password);
      parts.push(i32(TAG_KEY), utf(alias), timestamp(), i32(protectedKey.length), protectedKey, i32(e.chain.length), ...e.chain.map(cert));
    } else {
      parts.push(i32(TAG_CERT), utf(alias), timestamp(), cert(e.chain[0]));
    }
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, integrityDigest(password, body)]);
}

module.exports = { readJks, writeJks, isJks, JksError };
