#!/usr/bin/env node
// Helper for the authentication settings in .env.
//
//   npm run hash-password                prompts for a password (hidden) and prints a hash
//   npm run hash-password -- "my pass"   hashes the given password (it may end up in shell history)
//   npm run hash-password -- --secret    prints a random SESSION_SECRET
//
// Use the printed hash in place of a plain-text password for ADMIN_PASSWORD or in USERS=name:hash.
const crypto = require('crypto');
const { hashPassword } = require('../lib/auth');

function promptHidden(question) {
  return new Promise(resolve => {
    const stdin = process.stdin;
    process.stderr.write(question);
    if (!stdin.isTTY) {
      // Piped input: use the first line.
      let data = '';
      stdin.setEncoding('utf8');
      stdin.on('data', chunk => { data += chunk; });
      stdin.on('end', () => resolve(data.split(/\r?\n/)[0]));
      return;
    }
    let value = '';
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    stdin.on('data', function onData(char) {
      if (char === '\u0003') { // Ctrl+C
        process.stderr.write('\n');
        process.exit(130);
      } else if (char === '\r' || char === '\n') {
        stdin.setRawMode(false);
        stdin.pause();
        stdin.removeListener('data', onData);
        process.stderr.write('\n');
        resolve(value);
      } else if (char === '\u007f' || char === '\b') {
        value = value.slice(0, -1);
      } else {
        value += char;
      }
    });
  });
}

(async () => {
  const [arg] = process.argv.slice(2);
  if (arg === '--secret') {
    console.log(crypto.randomBytes(48).toString('base64url'));
    return;
  }
  if (arg === '--help' || arg === '-h') {
    console.log('Usage: npm run hash-password [-- <password> | --secret]');
    return;
  }
  const password = arg !== undefined ? arg : await promptHidden('Password: ');
  if (!password) {
    console.error('No password given.');
    process.exit(1);
  }
  if (password.length < 8) console.error('Warning: use at least 8 characters.');
  console.log(hashPassword(password));
})();
