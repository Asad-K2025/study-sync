import { assertPinValid } from './cert_pin.js';

const SECURE_PROTOCOL = 'https:';

export function ensureHttpsOrRedirect() {
  if (location.protocol === SECURE_PROTOCOL) return;
  const secureUrl = `${SECURE_PROTOCOL}//${location.host}${location.pathname}${location.search}${location.hash}`;
  location.replace(secureUrl);
  throw new Error('Blocked insecure HTTP access. Redirecting to HTTPS.');
}

export function buildApiUrl(path) {
  const normalizedPath = String(path || '');
  const baseOrigin = `${SECURE_PROTOCOL}//${location.host}`;
  return new URL(normalizedPath, baseOrigin).toString();
}

export async function apiGet(path) {
  ensureHttpsOrRedirect();
  assertPinValid();
  return await requestJson(path, { method: 'GET' });
}

export async function apiPost(path, body) {
  ensureHttpsOrRedirect();
  assertPinValid();
  return await requestJson(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  });
}

export async function apiPut(path, body) {
  ensureHttpsOrRedirect();
  assertPinValid();
  return await requestJson(path, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  });
}

export async function apiDelete(path) {
  ensureHttpsOrRedirect();
  assertPinValid();
  return await requestJson(path, { method: 'DELETE' });
}

async function requestJson(path, init) {
  const resp = await fetch(buildApiUrl(path), { ...init, credentials: 'include' });
  let payload = null;
  try {
    payload = await resp.json();
  } catch {
    payload = null;
  }
  if (resp.status === 401) {
    if (!location.pathname.startsWith('/login')) location.href = '/login';
  }
  if (!resp.ok) {
    const msg = payload && payload.error ? payload.error : `Request failed (${resp.status})`;
    throw new Error(msg);
  }
  return payload;
}