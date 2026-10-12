const crypto = require('crypto');

const { webcrypto } = crypto;

class KeyError extends Error {}

const CURVES = { prime256v1: 'P-256', secp384r1: 'P-384', secp521r1: 'P-521' };

// Parse a private key (PEM text or DER bytes, any of PKCS#8, PKCS#1, SEC1, encrypted or not).
function readPrivateKey(input, password) {
  const opts = Buffer.isBuffer(input)
    ? { key: input, format: 'der', type: 'pkcs8' }
    : { key: input };
  if (password) opts.passphrase = password;
  try {
    return crypto.createPrivateKey(opts);
  } catch (err) {
    if (err.code === 'ERR_MISSING_PASSPHRASE') throw new KeyError('The private key is encrypted. Enter its password.');
    if (/bad decrypt|interrupted or cancelled|wrong final block|unsupported/i.test(err.message) || err.code === 'ERR_OSSL_BAD_DECRYPT') {
      throw new KeyError(password ? 'Incorrect password for the private key.' : 'The private key is encrypted. Enter its password.');
    }
    throw new KeyError('Could not read the private key.');
  }
}

function spkiOf(keyObject) {
  const pub = keyObject.type === 'private' ? crypto.createPublicKey(keyObject) : keyObject;
  return pub.export({ type: 'spki', format: 'der' });
}

function pkcs8Of(keyObject) {
  return keyObject.export({ type: 'pkcs8', format: 'der' });
}

// A short human-readable description such as "RSA 2048" or "ECDSA P-256".
function describeKey(keyObject) {
  const type = keyObject.asymmetricKeyType;
  const details = keyObject.asymmetricKeyDetails || {};
  if (type === 'rsa' || type === 'rsa-pss') return `RSA ${details.modulusLength || ''}`.trim();
  if (type === 'ec') return `ECDSA ${CURVES[details.namedCurve] || details.namedCurve || ''}`.trim();
  if (type === 'ed25519') return 'Ed25519';
  if (type === 'ed448') return 'Ed448';
  return type ? type.toUpperCase() : 'Unknown';
}

/**
 * Turn a Node key into WebCrypto keys that @peculiar/x509 can sign with.
 * Returns { keys: { privateKey, publicKey }, signingAlgorithm, description }.
 */
async function toSigningKeys(privateKeyObject, hash = 'SHA-256') {
  const type = privateKeyObject.asymmetricKeyType;
  const details = privateKeyObject.asymmetricKeyDetails || {};
  let importAlgorithm;
  let signingAlgorithm;
  if (type === 'rsa') {
    importAlgorithm = { name: 'RSASSA-PKCS1-v1_5', hash };
    signingAlgorithm = { name: 'RSASSA-PKCS1-v1_5', hash };
  } else if (type === 'ec' && CURVES[details.namedCurve]) {
    importAlgorithm = { name: 'ECDSA', namedCurve: CURVES[details.namedCurve] };
    signingAlgorithm = { name: 'ECDSA', hash };
  } else if (type === 'ed25519') {
    importAlgorithm = { name: 'Ed25519' };
    signingAlgorithm = { name: 'Ed25519' };
  } else {
    throw new KeyError('Unsupported key type. Use RSA, ECDSA (P-256, P-384, P-521) or Ed25519.');
  }
  const privateKey = await webcrypto.subtle.importKey('pkcs8', pkcs8Of(privateKeyObject), importAlgorithm, true, ['sign']);
  const publicKey = await webcrypto.subtle.importKey('spki', spkiOf(privateKeyObject), importAlgorithm, true, ['verify']);
  return { keys: { privateKey, publicKey }, signingAlgorithm, description: describeKey(privateKeyObject) };
}

function pem(label, derBuffer) {
  const b64 = Buffer.from(derBuffer).toString('base64').match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`;
}

const sha256Hex = buf => crypto.createHash('sha256').update(buf).digest('hex').toUpperCase();
const colonHex = hex => hex.match(/.{2}/g).join(':');

module.exports = { KeyError, readPrivateKey, spkiOf, pkcs8Of, describeKey, toSigningKeys, pem, sha256Hex, colonHex };
