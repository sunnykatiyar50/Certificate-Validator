// Everyday private key chores without remembering openssl flags: see what a key is, change its format
// (PKCS#8, PKCS#1, SEC1), add, remove or change its password, and extract the public key.
// Keys are processed in memory and never stored or logged.
const crypto = require('crypto');
const { extractBundle } = require('./bundle');
const { KeyError, describeKey, sha256Hex, colonHex } = require('./keys');

const ACTIONS = ['inspect', 'pkcs8', 'pkcs1', 'sec1', 'public'];
const MIN_PASSWORD = 6;
const MAX_PASSWORD = 128;
const CIPHER = 'aes-256-cbc';

class KeyToolsError extends KeyError {}

const textFile = (name, content, note, secret = false) => ({ name, mime: 'application/x-pem-file', note: note || null, secret, encoding: 'text', content });

// What the key looked like when it came in, read from the PEM header of the supplied input.
function sourceFormat(inputs) {
  for (const input of inputs) {
    const text = input.buffer.toString('latin1');
    const match = /-----BEGIN ((?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY)-----([\s\S]*?)-----END/.exec(text);
    if (!match) continue;
    const legacyEncrypted = /Proc-Type:\s*4,ENCRYPTED/i.test(match[2]);
    const labels = {
      'PRIVATE KEY': ['PKCS#8', false],
      'ENCRYPTED PRIVATE KEY': ['PKCS#8', true],
      'RSA PRIVATE KEY': ['PKCS#1 (RSA)', legacyEncrypted],
      'EC PRIVATE KEY': ['SEC1 (EC)', legacyEncrypted],
      'DSA PRIVATE KEY': ['Traditional (DSA)', legacyEncrypted]
    };
    const [label, encrypted] = labels[match[1]];
    return { format: label, encrypted };
  }
  return { format: 'Binary file (DER, PFX or keystore)', encrypted: null };
}

function passwordOption(value) {
  if (value === undefined || value === null || value === '') return null;
  const password = String(value);
  if (password.length < MIN_PASSWORD || password.length > MAX_PASSWORD || /[\u0000-\u001f]/.test(password)) {
    throw new KeyToolsError(`The new password must be ${MIN_PASSWORD} to ${MAX_PASSWORD} characters.`);
  }
  return password;
}

function exportPrivate(keyObject, type, password) {
  const options = { type, format: 'pem' };
  if (password) Object.assign(options, { cipher: CIPHER, passphrase: password });
  return keyObject.export(options);
}

/**
 * Work with the first private key found in `inputs` ({ name, buffer } each).
 * options: password (to open an encrypted key), action (inspect | pkcs8 | pkcs1 | sec1 | public),
 *          newPassword (encrypts the result; leave empty for an unencrypted result).
 * Returns { files, summary, warnings }.
 */
function keyTools(inputs, { password, action = 'inspect', newPassword } = {}) {
  if (!ACTIONS.includes(action)) throw new KeyToolsError(`Action must be one of: ${ACTIONS.join(', ')}.`);
  if (!inputs.length) throw new KeyToolsError('Provide a private key: upload a file or paste it.');
  const outputPassword = passwordOption(newPassword);

  const bundle = extractBundle(inputs, { password });
  if (!bundle.privateKeys.length) throw new KeyToolsError('No private key was found in the input.');
  const warnings = [];
  if (bundle.privateKeys.length > 1) warnings.push('More than one private key was found; only the first one is used.');
  const keyObject = bundle.privateKeys[0].keyObject;
  const type = keyObject.asymmetricKeyType;
  const source = sourceFormat(inputs);

  const publicKey = crypto.createPublicKey(keyObject);
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const summary = {
    keyDescription: describeKey(keyObject),
    keyType: type,
    sourceFormat: source.format,
    wasEncrypted: source.encrypted === null ? !!password : source.encrypted,
    fingerprintSha256: colonHex(sha256Hex(spki)),
    // The value used for HTTP public key pinning and many "pin" checks.
    spkiPinSha256: crypto.createHash('sha256').update(spki).digest('base64'),
    result: null,
    resultEncrypted: false
  };

  const files = [];
  if (action === 'inspect') {
    files.push(textFile('public-key.pem', publicKey.export({ type: 'spki', format: 'pem' }), 'The public key (SPKI). Safe to share.'));
  } else if (action === 'public') {
    files.push(textFile('public-key.pem', publicKey.export({ type: 'spki', format: 'pem' }), 'The public key (SPKI). Safe to share.'));
    if (type === 'rsa') files.push(textFile('public-key-pkcs1.pem', publicKey.export({ type: 'pkcs1', format: 'pem' }), 'The same RSA public key in the older PKCS#1 form ("BEGIN RSA PUBLIC KEY").'));
    summary.result = 'Public key';
  } else {
    let name;
    let text;
    let note;
    if (action === 'pkcs8') {
      text = exportPrivate(keyObject, 'pkcs8', outputPassword);
      name = 'private-key-pkcs8.pem';
      note = outputPassword ? `Encrypted PKCS#8 (${CIPHER.toUpperCase().replace('-CBC', '')}, PBES2). Needs the password to use.` : 'Unencrypted PKCS#8 ("BEGIN PRIVATE KEY"). Keep it secret.';
      summary.result = outputPassword ? 'Encrypted PKCS#8' : 'Unencrypted PKCS#8';
    } else if (action === 'pkcs1') {
      if (type !== 'rsa') throw new KeyToolsError(`PKCS#1 only holds RSA keys, and this is ${summary.keyDescription}. Use PKCS#8 instead.`);
      text = exportPrivate(keyObject, 'pkcs1', outputPassword);
      name = 'private-key-pkcs1.pem';
      note = outputPassword ? 'Traditional OpenSSL encryption (AES-256-CBC, "Proc-Type" header). PKCS#8 is the modern choice.' : 'Unencrypted PKCS#1 ("BEGIN RSA PRIVATE KEY"). Keep it secret.';
      summary.result = outputPassword ? 'Encrypted PKCS#1 (RSA)' : 'Unencrypted PKCS#1 (RSA)';
    } else {
      if (type !== 'ec') throw new KeyToolsError(`SEC1 only holds elliptic curve (ECDSA) keys, and this is ${summary.keyDescription}. Use PKCS#8 instead.`);
      text = exportPrivate(keyObject, 'sec1', outputPassword);
      name = 'private-key-sec1.pem';
      note = outputPassword ? 'Traditional OpenSSL encryption (AES-256-CBC, "Proc-Type" header). PKCS#8 is the modern choice.' : 'Unencrypted SEC1 ("BEGIN EC PRIVATE KEY"). Keep it secret.';
      summary.result = outputPassword ? 'Encrypted SEC1 (EC)' : 'Unencrypted SEC1 (EC)';
    }
    summary.resultEncrypted = !!outputPassword;
    files.push(textFile(name, text, note, true));
    if (!outputPassword) warnings.push('The result is not password protected. Anyone who gets the file can use the key.');
    if (summary.wasEncrypted && !outputPassword) warnings.push('The password was removed from the key.');
  }

  return { files, summary, warnings };
}

module.exports = { keyTools, KeyToolsError, ACTIONS };
