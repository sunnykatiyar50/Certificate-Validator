// Issue a certificate together with a brand-new private key from a CA, in one step (no CSR needed).
// The CA comes from an upload or from a saved CA; nothing is stored here.
const { generateKeyPair } = require('./keygen');
const { signCsr, CaError } = require('./ca');
const { KeygenError } = require('./keygen');

const USAGES = ['server', 'client', 'both'];

async function issueCertificate(options, caInputs, { caPassword } = {}) {
  const o = options || {};
  const usage = o.usage || 'server';
  if (!USAGES.includes(usage)) throw new CaError(`Usage must be one of: ${USAGES.join(', ')}.`);
  if (!caInputs.length) throw new CaError('Choose a CA, or provide the CA certificate and private key.');
  if (!o.commonName || !String(o.commonName).trim()) throw new CaError('Common name is required.');

  const pair = await generateKeyPair({
    algorithm: o.algorithm || 'ECDSA-P256', output: 'csr', hash: o.hash, commonName: o.commonName, sans: o.sans,
    organization: o.organization, organizationalUnit: o.organizationalUnit, country: o.country, state: o.state, locality: o.locality
  });
  const signed = await signCsr([{ name: 'request.csr', buffer: Buffer.from(pair.csrPem) }], caInputs, {
    caPassword, usage, validityDays: o.validityDays, hash: o.hash, crlUrl: o.crlUrl, copySans: true
  });
  return {
    ...signed,
    algorithm: pair.algorithm,
    algorithmLabel: pair.algorithmLabel,
    hash: pair.hash,
    privateKeyPem: pair.privateKeyPem,
    publicKeyPem: pair.publicKeyPem
  };
}

module.exports = { issueCertificate, KeygenError };
