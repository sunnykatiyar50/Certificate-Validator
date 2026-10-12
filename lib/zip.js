const zlib = require('zlib');

// A minimal ZIP writer (stored entries, no compression, no ZIP64). The files here are a few KB of certificates
// and keys, so compression is not worth a dependency. Used to offer a whole bundle as one download.

const MAX_FILES = 200;
const MAX_TOTAL = 32 * 1024 * 1024;

// ZIP stores local time as DOS date/time words.
function dosDateTime(date) {
  const year = Math.max(date.getFullYear(), 1980);
  return {
    time: (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2),
    date: ((year - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate()
  };
}

// Reject anything that could escape the extraction folder or confuse an unzip tool.
function safeName(name) {
  const clean = String(name).replace(/\\/g, '/');
  if (!clean || clean.startsWith('/') || clean.split('/').some(part => part === '..' || part === '') || /[\u0000-\u001f]/.test(clean)) {
    throw new Error(`Unsafe file name in ZIP: ${JSON.stringify(name)}`);
  }
  return clean;
}

/** Build a ZIP archive from [{ name, content }] where content is a Buffer or string. Returns a Buffer. */
function createZip(files, now = new Date()) {
  if (!Array.isArray(files) || files.length === 0 || files.length > MAX_FILES) throw new Error('A ZIP needs between 1 and 200 files.');
  const stamp = dosDateTime(now);
  const seen = new Set();
  const locals = [];
  const centrals = [];
  let offset = 0;
  let total = 0;

  for (const file of files) {
    const name = safeName(file.name);
    if (seen.has(name)) throw new Error(`Duplicate file name in ZIP: ${name}`);
    seen.add(name);
    const data = Buffer.isBuffer(file.content) ? file.content : Buffer.from(String(file.content), 'utf8');
    total += data.length;
    if (total > MAX_TOTAL) throw new Error('The ZIP would be too large.');
    const nameBytes = Buffer.from(name, 'utf8');
    const crc = zlib.crc32(data);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);   // local file header signature
    local.writeUInt16LE(20, 4);           // version needed
    local.writeUInt16LE(0x0800, 6);       // flags: file names are UTF-8
    local.writeUInt16LE(0, 8);            // method 0 = stored
    local.writeUInt16LE(stamp.time, 10);
    local.writeUInt16LE(stamp.date, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18); // compressed size
    local.writeUInt32LE(data.length, 22); // uncompressed size
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(0, 28);           // extra field length
    locals.push(local, nameBytes, data);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0); // central directory signature
    central.writeUInt16LE(20, 4);         // version made by
    central.writeUInt16LE(20, 6);         // version needed
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt16LE(stamp.time, 12);
    central.writeUInt16LE(stamp.date, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt16LE(0, 30);         // extra length
    central.writeUInt16LE(0, 32);         // comment length
    central.writeUInt16LE(0, 34);         // disk number
    central.writeUInt16LE(0, 36);         // internal attributes
    central.writeUInt32LE(0, 38);         // external attributes
    central.writeUInt32LE(offset, 42);    // offset of the local header
    centrals.push(central, nameBytes);

    offset += local.length + nameBytes.length + data.length;
  }

  const centralBuffer = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);       // end of central directory
  end.writeUInt16LE(files.length, 8);     // entries on this disk
  end.writeUInt16LE(files.length, 10);    // total entries
  end.writeUInt32LE(centralBuffer.length, 12);
  end.writeUInt32LE(offset, 16);          // where the central directory starts
  return Buffer.concat([...locals, centralBuffer, end]);
}

module.exports = { createZip };
