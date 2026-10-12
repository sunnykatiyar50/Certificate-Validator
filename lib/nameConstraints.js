const net = require('net');
const forge = require('node-forge');
const x509 = require('@peculiar/x509');

const { asn1 } = forge;
const NAME_CONSTRAINTS_OID = '2.5.29.30';

// Names a locally trusted development CA is limited to by default: reserved and private-use names that can
// never belong to a real website. A leaked key for such a CA cannot be used to impersonate public sites.
const LOCAL_DNS = ['localhost', 'test', 'example', 'invalid', 'local', 'localdomain', 'internal', 'home.arpa', 'lan'];
const LOCAL_NETWORKS = [
  '127.0.0.0/8', '::1/128', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', 'fc00::/7', 'fe80::/10'
];

function ipv4Bytes(ip) {
  return Buffer.from(ip.split('.').map(Number));
}

function ipv6Bytes(ip) {
  let text = ip.toLowerCase().split('%')[0];
  // An embedded IPv4 tail (::ffff:1.2.3.4) becomes two 16-bit groups.
  const tail = /(\d+\.\d+\.\d+\.\d+)$/.exec(text);
  if (tail) {
    const v4 = ipv4Bytes(tail[1]);
    text = text.slice(0, -tail[1].length) + v4.readUInt16BE(0).toString(16) + ':' + v4.readUInt16BE(2).toString(16);
  }
  const [head, rest] = text.split('::');
  const left = head ? head.split(':') : [];
  const right = rest === undefined ? [] : (rest ? rest.split(':') : []);
  const groups = rest === undefined ? left : [...left, ...Array(8 - left.length - right.length).fill('0'), ...right];
  const out = Buffer.alloc(16);
  groups.forEach((g, i) => out.writeUInt16BE(parseInt(g || '0', 16), i * 2));
  return out;
}

function ipBytes(ip) {
  if (net.isIPv4(ip)) return ipv4Bytes(ip);
  if (net.isIPv6(ip)) return ipv6Bytes(ip);
  throw new Error(`Not an IP address: ${ip}`);
}

// An iPAddress constraint is the address followed by its netmask.
function networkBytes(cidr) {
  const [address, prefixText] = String(cidr).split('/');
  const bytes = ipBytes(address);
  const prefix = prefixText === undefined ? bytes.length * 8 : Number(prefixText);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bytes.length * 8) throw new Error(`Bad network prefix: ${cidr}`);
  const mask = Buffer.alloc(bytes.length);
  for (let i = 0; i < prefix; i++) mask[i >> 3] |= 0x80 >> (i & 7);
  const base = Buffer.from(bytes.map((b, i) => b & mask[i]));
  return Buffer.concat([base, mask]);
}

const generalName = (tag, value) => asn1.create(asn1.Class.CONTEXT_SPECIFIC, tag, false, value);
const subtree = base => asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [base]);

/**
 * Build the Name Constraints extension (RFC 5280 4.2.1.10) permitting only the given DNS names (which also cover
 * their subdomains) and networks (CIDR strings). Marked critical, as the RFC advises.
 */
function nameConstraintsExtension({ dns = [], networks = [] }, critical = true) {
  const subtrees = [
    ...dns.map(name => subtree(generalName(2, name))),
    ...networks.map(cidr => subtree(generalName(7, networkBytes(cidr).toString('binary'))))
  ];
  if (!subtrees.length) throw new Error('A name constraint needs at least one permitted name or network.');
  const permitted = asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, subtrees);
  const sequence = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [permitted]);
  return new x509.Extension(NAME_CONSTRAINTS_OID, critical, Buffer.from(asn1.toDer(sequence).getBytes(), 'binary'));
}

/**
 * Work out what a dev CA should be limited to for the names being issued.
 *  scope "local": the reserved/private-use names above plus the requested names (reusable for many projects)
 *  scope "names": only the requested names
 * `names` are { type: 'dns' | 'ip', value } entries; wildcards are covered by their parent domain.
 */
function constraintsFor(names, scope) {
  const dns = new Set(scope === 'names' ? [] : LOCAL_DNS);
  const networks = new Set(scope === 'names' ? [] : LOCAL_NETWORKS);
  for (const n of names) {
    if (n.type === 'dns') dns.add(n.value.replace(/^\*\./, '').toLowerCase());
    else if (n.type === 'ip') networks.add(`${n.value}/${net.isIPv4(n.value) ? 32 : 128}`);
  }
  return { dns: [...dns], networks: [...networks] };
}

const MAX_CONSTRAINTS = 50;
const HOST_LABEL_RE = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;

/**
 * Parse free text such as "localhost *.test 10.0.0.0/8" into { dns, networks } for a name constraint.
 * Anything that looks like an IP address or CIDR network becomes a network; the rest must be a host name
 * (a leading "*." or "." is dropped because a DNS constraint already covers subdomains). Throws a plain Error
 * with a message fit to show to the user.
 */
function parseConstraintText(text) {
  const dns = new Set();
  const networks = new Set();
  const items = String(text || '').split(/[\s,]+/).filter(Boolean);
  if (items.length > MAX_CONSTRAINTS) throw new Error(`Too many name restrictions (max ${MAX_CONSTRAINTS}).`);
  for (const item of items) {
    const address = item.split('/')[0];
    if (net.isIP(address)) {
      try {
        networkBytes(item);
      } catch (err) {
        throw new Error(`Invalid network restriction: ${item.slice(0, 60)}`);
      }
      networks.add(item.includes('/') ? item : `${item}/${net.isIPv4(item) ? 32 : 128}`);
    } else {
      const host = item.replace(/^\*?\./, '').toLowerCase();
      if (!HOST_LABEL_RE.test(host)) throw new Error(`Invalid name restriction: ${item.slice(0, 60)}`);
      dns.add(host);
    }
  }
  return { dns: [...dns], networks: [...networks] };
}

module.exports = { nameConstraintsExtension, constraintsFor, parseConstraintText, ipBytes, networkBytes, LOCAL_DNS, LOCAL_NETWORKS, NAME_CONSTRAINTS_OID };
