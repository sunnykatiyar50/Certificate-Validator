// Light / dark / system theme. Loaded in <head> so the saved theme applies before first paint.
// The switch (data-theme-set buttons) shows which of Auto / Light / Dark is selected, so it is always
// clear what a click will do. "Auto" follows the operating system setting.
(function () {
  var KEY = 'cv-theme';
  var MODES = ['system', 'light', 'dark'];

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

  // Mark the selected button in every switch on the page.
  function updateSwitches() {
    var mode = stored();
    document.querySelectorAll('[data-theme-set]').forEach(function (button) {
      var active = button.getAttribute('data-theme-set') === mode;
      button.setAttribute('aria-pressed', String(active));
      button.classList.toggle('active', active);
    });
  }

  apply(stored());

  document.addEventListener('click', function (event) {
    var button = event.target.closest('[data-theme-set]');
    if (!button) return;
    var mode = button.getAttribute('data-theme-set');
    if (MODES.indexOf(mode) < 0) return;
    try { localStorage.setItem(KEY, mode); } catch (e) { /* the choice just will not persist */ }
    apply(mode);
    updateSwitches();
  });

  // Keep several open tabs in step.
  window.addEventListener('storage', function (event) {
    if (event.key === KEY) {
      apply(stored());
      updateSwitches();
    }
  });

  document.addEventListener('DOMContentLoaded', updateSwitches);
})();
