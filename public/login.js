const $ = id => document.getElementById(id);
const USERNAME_KEY = 'cv-last-username';

const form = $('loginForm');
const errorBox = $('loginError');
const button = $('loginBtn');

function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = false;
}

// Remember the last username and jump straight to the password field.
try {
  const last = localStorage.getItem(USERNAME_KEY);
  if (last) $('username').value = last;
} catch (e) { /* storage unavailable */ }
($('username').value ? $('password') : $('username')).focus();

$('togglePassword').addEventListener('click', event => {
  const input = $('password');
  const show = input.type === 'password';
  input.type = show ? 'text' : 'password';
  event.currentTarget.textContent = show ? 'Hide' : 'Show';
  event.currentTarget.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
  event.currentTarget.setAttribute('aria-pressed', String(show));
});

$('password').addEventListener('keyup', event => {
  $('capsHint').hidden = !(event.getModifierState && event.getModifierState('CapsLock'));
});

form.addEventListener('submit', async event => {
  event.preventDefault();
  errorBox.hidden = true;
  const username = $('username').value.trim();
  const password = $('password').value;
  if (!username || !password) return showError('Enter your username and password.');

  button.disabled = true;
  button.textContent = 'Signing in...';
  try {
    const response = await fetch('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'fetch' },
      body: JSON.stringify({ username, password })
    });
    const data = await response.json().catch(() => ({}));
    if (response.ok) {
      try { localStorage.setItem(USERNAME_KEY, username); } catch (e) { /* ignore */ }
      location.href = '/';
      return;
    }
    $('password').value = '';
    $('password').focus();
    showError(data.error || 'Sign in failed.');
  } catch (err) {
    showError('Could not reach the server. Try again.');
  } finally {
    button.disabled = false;
    button.textContent = 'Sign in';
  }
});

fetch('/api/version')
  .then(r => r.json())
  .then(d => { $('version').textContent = `v${d.version}`; })
  .catch(() => {});
