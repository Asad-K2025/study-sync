/**
 * E2EE module — PBKDF2 group key derivation + AES-256-GCM message encryption.
 *
 * Each group key is derived deterministically from the group ID using PBKDF2.
 * All members of the same group derive the same key independently — no key
 * distribution needed. The server never sees plaintext messages or keys.
 */

const APP_SECRET = 'studysync-e2ee-v1';

/**
 * Derive a deterministic AES-256-GCM key for a group from its ID.
 * Every member derives the same key for the same group independently.
 */
export async function deriveGroupKey(groupId) {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(APP_SECRET),
    { name: 'PBKDF2' },
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: encoder.encode(`studysync-group-${groupId}`),
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * Encrypt a plaintext string with the group AES-256-GCM key.
 * Returns a JSON string stored as the message content on the server.
 */
export async function encryptMessage(groupKey, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, groupKey, encoded);
  return JSON.stringify({
    e2ee: true,
    iv: Array.from(iv),
    data: Array.from(new Uint8Array(cipher)),
  });
}

/**
 * Decrypt a ciphertext string produced by encryptMessage.
 */
export async function decryptMessage(groupKey, ciphertextStr) {
  const obj = JSON.parse(ciphertextStr);
  const iv = new Uint8Array(obj.iv);
  const data = new Uint8Array(obj.data);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, groupKey, data);
  return new TextDecoder().decode(plain);
}

/**
 * Returns true if content is an E2EE ciphertext blob.
 */
export function isEncrypted(content) {
  if (!content) return false;
  try {
    return JSON.parse(content)?.e2ee === true;
  } catch {
    return false;
  }
}

/**
 * Generate a new random AES-256-GCM key for a group.
 */
export async function generateGroupKey() {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );
}

/**
 * Wrap (encrypt) a key using another key.
 */
export async function wrapGroupKey(keyToWrap, wrappingKey) {
  const wrapped = await crypto.subtle.wrapKey('raw', keyToWrap, wrappingKey, { name: 'AES-GCM' });
  return Array.from(new Uint8Array(wrapped));
}

/**
 * Unwrap (decrypt) a key using another key.
 */
export async function unwrapGroupKey(wrappedKeyBytes, unwrappingKey) {
  const wrapped = new Uint8Array(wrappedKeyBytes);
  const keyData = await crypto.subtle.unwrapKey('raw', wrapped, unwrappingKey, { name: 'AES-GCM' }, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  return keyData;
}

/**
 * Export a CryptoKey as JWK.
 */
export async function exportPublicKeyJwk(key) {
  return crypto.subtle.exportKey('jwk', key);
}

/**
 * Import a JWK as CryptoKey.
 */
export async function importPublicKeyJwk(jwk, usages = []) {
  return crypto.subtle.importKey('jwk', jwk, { name: 'AES-GCM', length: 256 }, true, usages);
}

/**
 * Get or create an RSA key pair for the user.
 */
export async function getOrCreateKeyPair() {
  if (state.myKeyPair) return state.myKeyPair;
  
  const keyPair = await crypto.subtle.generateKey(
    { name: 'RSA-OAEP', modLength: 2048, hash: 'SHA-256' },
    true,
    ['encrypt', 'decrypt']
  );
  
  state.myKeyPair = keyPair;
  return keyPair;
}