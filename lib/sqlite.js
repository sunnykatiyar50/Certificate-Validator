// node:sqlite still prints an "experimental" warning when it is first loaded. It is stable enough for
// this use, so hide that one message (and only that one) instead of letting it clutter every start.
const { DatabaseSync } = (() => {
  const emitWarning = process.emitWarning;
  process.emitWarning = function (warning, ...args) {
    const message = typeof warning === 'string' ? warning : (warning && warning.message) || '';
    if (message.includes('SQLite is an experimental feature')) return undefined;
    return emitWarning.call(this, warning, ...args);
  };
  try {
    return require('node:sqlite');
  } finally {
    process.emitWarning = emitWarning;
  }
})();

module.exports = { DatabaseSync };
