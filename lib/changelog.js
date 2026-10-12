const fs = require('fs');
const path = require('path');

const CHANGELOG_FILE = path.join(__dirname, '..', 'CHANGELOG.md');
const MAX_RELEASES = 12;

/**
 * Parse CHANGELOG.md ("Keep a Changelog" style) into
 *   [{ version, date, sections: [{ title, items: [text, ...] }] }]   newest first, in file order.
 * "## 1.2.3 - 2026-01-31" starts a release, "### Added" a section, "- text" an item (indented
 * continuation lines extend the previous item). The "Unreleased" heading and releases without items are skipped.
 */
function parseChangelog(text) {
  const releases = [];
  let release = null;
  let section = null;

  for (const line of String(text).replace(/\r\n/g, '\n').split('\n')) {
    let m;
    if ((m = /^##\s+\[?([^\]\s]+)\]?(?:\s+[-–]\s+(\S+))?\s*$/.exec(line))) {
      release = { version: m[1].replace(/^v/i, ''), date: m[2] || null, sections: [] };
      releases.push(release);
      section = null;
    } else if (!release) {
      continue;
    } else if ((m = /^###\s+(.+?)\s*$/.exec(line))) {
      section = { title: m[1], items: [] };
      release.sections.push(section);
    } else if ((m = /^[-*]\s+(.+)$/.exec(line))) {
      if (!section) {
        section = { title: 'Changes', items: [] };
        release.sections.push(section);
      }
      section.items.push(m[1].trim());
    } else if (/^\s{2,}\S/.test(line) && section && section.items.length) {
      section.items[section.items.length - 1] += ' ' + line.trim();
    }
  }

  return releases
    .filter(r => r.version.toLowerCase() !== 'unreleased')
    .map(r => ({ ...r, sections: r.sections.filter(s => s.items.length) }))
    .filter(r => r.sections.length);
}

let cache = null;

// The file is read once. A missing file just means there are no notes to show.
function loadReleaseNotes(file = CHANGELOG_FILE) {
  if (file !== CHANGELOG_FILE) return parseChangelog(fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '').slice(0, MAX_RELEASES);
  if (!cache) {
    try {
      cache = parseChangelog(fs.readFileSync(file, 'utf8')).slice(0, MAX_RELEASES);
    } catch (err) {
      cache = [];
    }
  }
  return cache;
}

module.exports = { parseChangelog, loadReleaseNotes, CHANGELOG_FILE };
