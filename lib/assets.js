const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Local stylesheet and script references in a page: href="style.css" / src="app.js".
const ASSET_REF = /(\b(?:href|src)=")([A-Za-z0-9._-]+\.(?:css|js))(")/g;

/**
 * Cache busting for the static frontend. Reverse proxies, CDNs and browsers can keep serving an old
 * /style.css after an upgrade, and the new HTML then renders with the old stylesheet (a "broken" page).
 * Adding a fingerprint of each file's content to its URL (style.css?v=3f9a1c0d2b) means a changed file
 * always has a URL nobody has cached.
 */
function createAssetVersioner(publicDir) {
  const cache = new Map(); // file name -> { mtimeMs, size, hash }

  // Short content hash of a file in publicDir, or null if there is no such file.
  function hashOf(name) {
    if (!/^[A-Za-z0-9._-]+$/.test(name)) return null;
    const file = path.join(publicDir, name);
    let stat;
    try {
      stat = fs.statSync(file);
    } catch (err) {
      return null;
    }
    const hit = cache.get(name);
    if (hit && hit.mtimeMs === stat.mtimeMs && hit.size === stat.size) return hit.hash;
    const hash = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex').slice(0, 10);
    cache.set(name, { mtimeMs: stat.mtimeMs, size: stat.size, hash });
    return hash;
  }

  // Rewrite local .css and .js references in an HTML page to carry their fingerprint.
  function versionPage(html) {
    return html.replace(ASSET_REF, (match, before, name, after) => {
      const hash = hashOf(name);
      return hash ? `${before}${name}?v=${hash}${after}` : match;
    });
  }

  return { hashOf, versionPage };
}

module.exports = { createAssetVersioner };
