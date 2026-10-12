// Light / dark / system theme. Loaded in <head> so the saved theme applies before first paint.
(function () {
  var KEY = 'cv-theme';
  var MODES = ['system', 'light', 'dark'];
  var LABELS = { system: '◐ System theme', light: '☀ Light theme', dark: '☾ Dark theme' };

  function stored() {
    try {
      var value = localStorage.getItem(KEY);
      return MODES.indexOf(value) >= 0 ? value : 'system';
    } catch (e) {
      return 'system';
    }
  }

  function apply(mode) {
    var root = document.documentElement;
    if (mode === 'light' || mode === 'dark') root.setAttribute('data-theme', mode);
    else root.removeAttribute('data-theme');
  }

  function updateLabels() {
    var label = LABELS[stored()];
    document.querySelectorAll('[data-theme-toggle]').forEach(function (button) {
      button.textContent = label;
      button.title = 'Change theme';
    });
  }

  apply(stored());

  document.addEventListener('click', function (event) {
    var button = event.target.closest('[data-theme-toggle]');
    if (!button) return;
    var next = MODES[(MODES.indexOf(stored()) + 1) % MODES.length];
    try { localStorage.setItem(KEY, next); } catch (e) { /* the choice just will not persist */ }
    apply(next);
    updateLabels();
  });

  document.addEventListener('DOMContentLoaded', updateLabels);
})();
