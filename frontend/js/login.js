import { apiGet, apiPost, ensureHttpsOrRedirect } from './api.js';
import { fetchAndVerifyPin } from './cert_pin.js';

const tabLogin = document.getElementById('tabLogin');
const tabRegister = document.getElementById('tabRegister');
const loginForm = document.getElementById('loginForm');
const registerForm = document.getElementById('registerForm');
const forgotForm = document.getElementById('forgotForm');
const resetForm = document.getElementById('resetForm');
const authError = document.getElementById('authError');

function setError(msg) {
  authError.textContent = msg || '';
}

function setTab(which) {
  tabLogin.classList.toggle('active', which === 'login');
  tabRegister.classList.toggle('active', which === 'register');
  loginForm.style.display = which === 'login' ? '' : 'none';
  registerForm.style.display = which === 'register' ? '' : 'none';
  forgotForm.style.display = which === 'forgot' ? '' : 'none';
  resetForm.style.display = which === 'reset' ? '' : 'none';
  setError('');
}

tabLogin.addEventListener('click', () => setTab('login'));
tabRegister.addEventListener('click', () => setTab('register'));

async function guardAlreadyLoggedIn() {
  try {
    await apiGet('/api/auth/me');
    location.href = '/';
  } catch {
    return;
  }
}

async function doLogin() {
  setError('');
  const username = document.getElementById('loginUsername').value.trim();
  const password = document.getElementById('loginPassword').value;
  if (!username || !password) {
    setError('Please enter your username and password');
    return;
  }
  try {
    await apiPost('/api/auth/login', { username, password });
    location.href = '/';
  } catch (e) {
    setError(e.message);
  }
}

async function doRegister() {
  setError('');
  const name = document.getElementById('regName').value.trim();
  const username = document.getElementById('regUsername').value.trim();
  const email = document.getElementById('regEmail').value.trim().toLowerCase();
  const password = document.getElementById('regPassword').value;
  if (!name || !username || !email || !password) {
    setError('Please fill in all fields');
    return;
  }
  const pwRe = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[^A-Za-z0-9]).{8,}$/;
  if (!pwRe.test(password)) {
    setError('Password must be at least 8 characters and contain uppercase, lowercase, and special characters');
    return;
  }
  if (password.toLowerCase() === username.toLowerCase()) {
    setError('Password cannot be the same as username');
    return;
  }
  if (!email.includes('@')) {
    setError('Please enter a valid email');
    return;
  }
  try {
    await apiPost('/api/auth/register', { name, username, email, password });
    location.href = '/';
  } catch (e) {
    setError(e.message);
  }
}

document.getElementById('btnLogin').addEventListener('click', doLogin);
document.getElementById('btnRegister').addEventListener('click', doRegister);
document.getElementById('btnForgotPassword').addEventListener('click', () => setTab('forgot'));
document.getElementById('btnForgotSubmit').addEventListener('click', doForgotPassword);
document.getElementById('btnResetSubmit').addEventListener('click', doResetPassword);
document.getElementById('btnBackToLogin1').addEventListener('click', () => setTab('login'));
document.getElementById('btnBackToLogin2').addEventListener('click', () => setTab('login'));

async function doForgotPassword() {
  setError('');
  const email = document.getElementById('forgotEmail').value.trim().toLowerCase();
  if (!email) {
    setError('Please enter your email');
    return;
  }
  const btn = document.getElementById('btnForgotSubmit');
  btn.disabled = true;
  btn.textContent = 'Sending...';
  try {
    const resp = await apiPost('/api/auth/forgot_password', { email });
    location.href = `/login?reset_email=${encodeURIComponent(email)}`;
  } catch (e) {
    setError(e.message);
    btn.disabled = false;
    btn.textContent = 'Send code';
  }
}

async function doResetPassword() {
  setError('');
  const email = resetEmail || '';
  const code = document.getElementById('resetCode').value.trim();
  const password = document.getElementById('resetPassword').value;
  if (!email || !code || !password) {
    setError('Please fill in all fields');
    return;
  }
  const pwRe = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[^A-Za-z0-9]).{8,}$/;
  if (!pwRe.test(password)) {
    setError('Password must be at least 8 characters and contain uppercase, lowercase, and special characters');
    return;
  }
  try {
    await apiPost('/api/auth/reset_password', { email, code, new_password: password });
    setError('Password reset successfully. Logging you in...');
    setTab('login');
  } catch (e) {
    setError(e.message);
  }
}
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Enter') return;
  if (loginForm.style.display !== 'none') void doLogin();
  else if (registerForm.style.display !== 'none') void doRegister();
  else if (forgotForm.style.display !== 'none') void doForgotPassword();
  else if (resetForm.style.display !== 'none') void doResetPassword();
});

setTab('login');
ensureHttpsOrRedirect();

const urlParams = new URLSearchParams(location.search);
const resetEmail = urlParams.get('reset_email');
if (resetEmail) {
  setTab('reset');
}

// Verify certificate pin before allowing any interaction.
// In dev mode (localhost) a mismatch is only a warning; in production it throws.
fetchAndVerifyPin().then(() => {
  guardAlreadyLoggedIn();
}).catch((err) => {
  setError('⚠ Security error: ' + err.message);
});
