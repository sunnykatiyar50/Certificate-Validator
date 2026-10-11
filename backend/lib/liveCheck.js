const dns = require('dns').promises;
const net = require('net');
const tls = require('tls');

const CONNECT_TIMEOUT_MS = 8000;
const MAX_CHAIN_LENGTH = 10;
const HOSTNAME_RE = /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$/i;

// Addresses a public-facing service must never connect to (SSRF protection).
const blocked = new net.BlockList();
[
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]
].forEach(([net_, prefix]) => blocked.addSubnet(net_, prefix, 'ipv4'));
[
  ['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8], ['2001:db8::', 32], ['64:ff9b::', 96]
].forEach(([net_, prefix]) => blocked.addSubnet(net_, prefix, 'ipv6'));

function isBlockedAddress(address) {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
  if (mapped) return blocked.check(mapped[1], 'ipv4');
  const family = net.isIPv6(address) ? 'ipv6' : 'ipv4';
  return blocked.check(address, family);
}

class LiveCheckError extends Error {}

function validateTarget(host, port) {
  const cleanHost = String(host || '').trim().replace(/\.$/, '');
  if (!cleanHost) throw new LiveCheckError('Enter a hostname to check.');
  if (!net.isIP(cleanHost) && !HOSTNAME_RE.test(cleanHost)) throw new LiveCheckError('Invalid hostname.');
  const portNum = port === undefined || port === '' || port === null ? 443 : Number(port);
  if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) throw new LiveCheckError('Port must be between 1 and 65535.');
  return { host: cleanHost, port: portNum };
}

// Resolve the host and pick an address that is safe to connect to. The socket then connects to
// that exact address, so a second (rebinding) DNS lookup cannot redirect it to an internal host.
async function resolveSafeAddress(host, allowPrivate) {
  let addresses;
  if (net.isIP(host)) {
    addresses = [{ address: host }];
  } else {
    try {
      addresses = await dns.lookup(host, { all: true });
    } catch (e) {
      throw new LiveCheckError(`Could not resolve ${host}.`);
    }
  }
  if (!addresses.length) throw new LiveCheckError(`Could not resolve ${host}.`);
  if (!allowPrivate && addresses.some(a => isBlockedAddress(a.address))) {
    throw new LiveCheckError('Connections to private, loopback or reserved addresses are not allowed.');
  }
  return addresses[0].address;
}

function connectAndGetChain({ host, port, address }) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: address,
      port,
      // SNI must be a hostname, not an IP literal.
      servername: net.isIP(host) ? undefined : host,
      rejectUnauthorized: false,
      timeout: CONNECT_TIMEOUT_MS
    });
    const fail = err => {
      socket.destroy();
      reject(err);
    };
    socket.once('timeout', () => fail(new LiveCheckError(`Connection to ${host}:${port} timed out.`)));
    socket.once('error', err => fail(new LiveCheckError(`Could not connect to ${host}:${port} (${err.code || err.message}).`)));
    socket.once('secureConnect', () => {
      try {
        const ders = [];
        const seen = new Set();
        let cert = socket.getPeerCertificate(true);
        while (cert && cert.raw && !seen.has(cert.fingerprint256) && ders.length < MAX_CHAIN_LENGTH) {
          seen.add(cert.fingerprint256);
          ders.push(cert.raw);
          cert = cert.issuerCertificate;
        }
        const cipher = socket.getCipher();
        const tlsInfo = {
          protocol: socket.getProtocol(),
          cipher: cipher && cipher.name,
          // Whether the platform trust store and hostname check accept this connection.
          authorized: socket.authorized,
          authorizationError: socket.authorizationError ? String(socket.authorizationError.message || socket.authorizationError) : null
        };
        socket.end();
        resolve({ ders, tlsInfo });
      } catch (err) {
        fail(err);
      }
    });
  });
}

/**
 * Connect to host:port over TLS and return the certificate chain the server presents (DER buffers,
 * leaf first) plus negotiated TLS details.
 */
async function fetchServerChain(host, port, { allowPrivate = false } = {}) {
  const target = validateTarget(host, port);
  const address = await resolveSafeAddress(target.host, allowPrivate);
  const { ders, tlsInfo } = await connectAndGetChain({ ...target, address });
  if (!ders.length) throw new LiveCheckError('The server did not present a certificate.');
  return { host: target.host, port: target.port, address, ders, tlsInfo };
}

module.exports = { fetchServerChain, isBlockedAddress, LiveCheckError };
