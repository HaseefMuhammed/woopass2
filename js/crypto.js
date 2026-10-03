/**
 * ============================================================================
 * WOO PASS — Cryptography Module (js/crypto.js)
 * High-assurance client-side cryptographic functions built on Web Crypto API.
 * ============================================================================
 * 
 * SECURITY SPECIFICATIONS:
 * 1. Randomness: Uses window.crypto.getRandomValues() exclusively. Math.random() is forbidden.
 * 2. Key Derivation: PBKDF2 with HMAC-SHA-256 and high iteration counts (>= 100,000).
 * 3. Key Hierarchy:
 *    - User PIN + Unique Salt -> PBKDF2 (100k rounds) -> Key Encryption Key (KEK)
 *    - Vault Encryption Key (VEK): 256-bit cryptographically random AES-GCM key
 *    - KEK encrypts/wraps the VEK (allows PIN changes without re-encrypting records)
 *    - VEK encrypts all vault items with AES-256-GCM + unique 12-byte IV per record
 * 4. Authenticated Encryption: AES-256-GCM with fresh 12-byte (96-bit) IV per operation.
 * 5. IV Replay Prevention: A fresh IV is generated for every single encrypt operation.
 * 6. Secret Protection: Raw PINs and plaintext secrets are never stored in localStorage,
 *    URLs, or sent unencrypted over the network.
 */

// Global constant salt for application-level domain separation
const APP_DOMAIN_SALT = 'woopass_family_vault_v1_secure_domain_separation';
const DEFAULT_GATE_SALT_HEX = 'e9f4c3a1b8d7e6f50123456789abcdef0123456789abcdef0123456789abcdef';

/**
 * Generate cryptographically secure random bytes
 * @param {number} length - Number of bytes to generate
 * @returns {Uint8Array}
 */
export function generateRandomBytes(length = 32) {
  if (!window.crypto || !window.crypto.getRandomValues) {
    throw new Error('Web Crypto API is not supported in this environment');
  }
  const bytes = new Uint8Array(length);
  window.crypto.getRandomValues(bytes);
  return bytes;
}

/**
 * Convert Uint8Array buffer to Hex string
 * @param {ArrayBuffer|Uint8Array} buffer 
 * @returns {string}
 */
export function bufferToHex(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert Hex string to Uint8Array
 * @param {string} hexString 
 * @returns {Uint8Array}
 */
export function hexToBuffer(hexString) {
  if (typeof hexString !== 'string' || hexString.length % 2 !== 0) {
    throw new Error('Invalid hexadecimal string');
  }
  const bytes = new Uint8Array(hexString.length / 2);
  for (let i = 0; i < hexString.length; i += 2) {
    bytes[i / 2] = parseInt(hexString.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Convert UTF-8 string to Uint8Array
 * @param {string} str 
 * @returns {Uint8Array}
 */
export function stringToBuffer(str) {
  return new TextEncoder().encode(str);
}

/**
 * Convert Uint8Array to UTF-8 string
 * @param {ArrayBuffer|Uint8Array} buffer 
 * @returns {string}
 */
export function bufferToString(buffer) {
  return new TextDecoder().decode(buffer);
}

/**
 * Import raw string password/PIN into a CryptoKey for PBKDF2 derivation
 * @param {string} secret 
 * @returns {Promise<CryptoKey>}
 */
async function importKeyMaterial(secret) {
  const encoded = stringToBuffer(secret);
  return await window.crypto.subtle.importKey(
    'raw',
    encoded,
    'PBKDF2',
    false,
    ['deriveKey', 'deriveBits']
  );
}

/**
 * Derive raw cryptographic bits using PBKDF2-HMAC-SHA256
 * @param {string} pinOrPassword - User PIN or input secret
 * @param {Uint8Array|string} salt - Salt buffer or string
 * @param {number} iterations - Work factor (default: 100,000)
 * @param {number} bitLength - Output bit length (default: 256)
 * @returns {Promise<Uint8Array>}
 */
export async function derivePBKDF2Bits(pinOrPassword, salt, iterations = 100000, bitLength = 256) {
  const saltBuffer = typeof salt === 'string' ? stringToBuffer(salt) : salt;
  const keyMaterial = await importKeyMaterial(pinOrPassword);
  
  const derivedBits = await window.crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBuffer,
      iterations: iterations,
      hash: 'SHA-256'
    },
    keyMaterial,
    bitLength
  );
  
  return new Uint8Array(derivedBits);
}

/**
 * Derive Key Encryption Key (KEK) as AES-GCM CryptoKey from PIN + unique vault salt
 * @param {string} pin - 6-digit user PIN
 * @param {string} vaultSaltHex - Unique 32-byte hex salt
 * @param {string} email - Normalized user email
 * @returns {Promise<CryptoKey>}
 */
export async function deriveKEK(pin, vaultSaltHex, email) {
  const normalizedEmail = (email || '').trim().toLowerCase();
  const saltCombined = `${APP_DOMAIN_SALT}_kek_${vaultSaltHex}_${normalizedEmail}`;
  const saltBuffer = stringToBuffer(saltCombined);
  const keyMaterial = await importKeyMaterial(pin);

  return await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBuffer,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
  );
}

/**
 * Import raw 256-bit bytes into AES-GCM CryptoKey
 * @param {Uint8Array|ArrayBuffer} rawBytes 
 * @returns {Promise<CryptoKey>}
 */
export async function importRawAESKey(rawBytes) {
  return await window.crypto.subtle.importKey(
    'raw',
    rawBytes,
    { name: 'AES-GCM', length: 256 },
    true, // extractable for backup wrapping
    ['encrypt', 'decrypt']
  );
}

/**
 * Generate a new random 256-bit Vault Encryption Key (VEK)
 * @returns {Uint8Array}
 */
export function generateVaultKeyBytes() {
  return generateRandomBytes(32);
}

/**
 * Wrap (encrypt) the raw Vault Encryption Key using KEK
 * @param {Uint8Array} rawVekBytes - 32-byte raw VEK
 * @param {CryptoKey} kek - Key Encryption Key
 * @returns {Promise<{ encryptedVekHex: string, ivHex: string }>}
 */
export async function wrapVaultKey(rawVekBytes, kek) {
  const iv = generateRandomBytes(12);
  const encryptedBuffer = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    kek,
    rawVekBytes
  );

  return {
    encryptedVekHex: bufferToHex(encryptedBuffer),
    ivHex: bufferToHex(iv)
  };
}

/**
 * Unwrap (decrypt) the wrapped Vault Encryption Key using KEK
 * @param {string} encryptedVekHex - Hex encrypted VEK
 * @param {string} ivHex - Hex 12-byte IV
 * @param {CryptoKey} kek - Key Encryption Key
 * @returns {Promise<CryptoKey>} Active VEK CryptoKey
 */
export async function unwrapVaultKey(encryptedVekHex, ivHex, kek) {
  const ciphertextBuffer = hexToBuffer(encryptedVekHex);
  const ivBuffer = hexToBuffer(ivHex);

  const decryptedRawBytes = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivBuffer },
    kek,
    ciphertextBuffer
  );

  return await importRawAESKey(decryptedRawBytes);
}

/**
 * Re-wrap Vault Encryption Key when user changes PIN
 * Decrypts with old PIN KEK, derives new KEK from new PIN, and encrypts VEK with fresh IV
 * @param {string} currentPin 
 * @param {string} newPin 
 * @param {string} email 
 * @param {string} vaultSaltHex 
 * @param {string} encryptedVekHex 
 * @param {string} ivHex 
 * @returns {Promise<{ newEncryptedVekHex: string, newIvHex: string, newVekKey: CryptoKey }>}
 */
export async function rewrapVaultKey(currentPin, newPin, email, vaultSaltHex, encryptedVekHex, ivHex) {
  const currentKek = await deriveKEK(currentPin, vaultSaltHex, email);
  const ciphertextBuffer = hexToBuffer(encryptedVekHex);
  const ivBuffer = hexToBuffer(ivHex);

  // Decrypt VEK raw bytes
  const rawVekBytes = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivBuffer },
    currentKek,
    ciphertextBuffer
  );

  // Derive new KEK from new PIN
  const newKek = await deriveKEK(newPin, vaultSaltHex, email);

  // Wrap VEK with new KEK + fresh IV
  const newIv = generateRandomBytes(12);
  const newEncryptedBuffer = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: newIv },
    newKek,
    rawVekBytes
  );

  const newVekKey = await importRawAESKey(rawVekBytes);

  return {
    newEncryptedVekHex: bufferToHex(newEncryptedBuffer),
    newIvHex: bufferToHex(newIv),
    newVekKey
  };
}

/**
 * Derive high-entropy Firebase Auth password from user PIN + Email.
 * This guarantees the raw 6-digit PIN is never transmitted over network or stored in Firebase Auth.
 * 
 * @param {string} pin - 6-digit user PIN
 * @param {string} email - Normalized lowercase user email
 * @returns {Promise<string>} 64-character hexadecimal password string
 */
export async function deriveAuthSecret(pin, email) {
  const normalizedEmail = (email || '').trim().toLowerCase();
  const combinedSalt = `${APP_DOMAIN_SALT}_auth_${normalizedEmail}`;
  const derivedBits = await derivePBKDF2Bits(pin, combinedSalt, 100000, 256);
  return bufferToHex(derivedBits);
}

/**
 * Derive verification hash for Family Admin Gate
 * @param {string} pin - 6-digit family admin PIN
 * @param {string} saltHex - Salt in hex format (optional, uses default if omitted)
 * @returns {Promise<string>} Hexadecimal hash string
 */
export async function deriveFamilyGateHash(pin, saltHex = DEFAULT_GATE_SALT_HEX) {
  const saltBuffer = hexToBuffer(saltHex);
  const derivedBits = await derivePBKDF2Bits(pin, saltBuffer, 100000, 256);
  return bufferToHex(derivedBits);
}

/**
 * Encrypt a Vault Record (JS object) using the Vault Encryption Key (VEK)
 * @param {Object} recordData - Plaintext record object
 * @param {CryptoKey} vek - Vault Encryption Key
 * @returns {Promise<{ ciphertextHex: string, ivHex: string, version: number }>}
 */
export async function encryptVaultRecord(recordData, vek) {
  const jsonString = JSON.stringify(recordData);
  const iv = generateRandomBytes(12); // Fresh 96-bit IV
  const encodedPlaintext = stringToBuffer(jsonString);

  const encryptedBuffer = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    vek,
    encodedPlaintext
  );

  return {
    ciphertextHex: bufferToHex(encryptedBuffer),
    ivHex: bufferToHex(iv),
    version: 1
  };
}

/**
 * Decrypt a Vault Record using the Vault Encryption Key (VEK)
 * @param {string} ciphertextHex - Hex encoded ciphertext
 * @param {string} ivHex - Hex encoded 12-byte IV
 * @param {CryptoKey} vek - Vault Encryption Key
 * @returns {Promise<Object>} Decrypted JS object
 */
export async function decryptVaultRecord(ciphertextHex, ivHex, vek) {
  const ciphertextBuffer = hexToBuffer(ciphertextHex);
  const ivBuffer = hexToBuffer(ivHex);

  const decryptedBuffer = await window.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: ivBuffer
    },
    vek,
    ciphertextBuffer
  );

  const jsonString = bufferToString(decryptedBuffer);
  return JSON.parse(jsonString);
}

/**
 * Generate a cryptographically secure random password
 * @param {number} length - Length of password (16–64, default: 24)
 * @param {Object} options - Character pool options
 * @returns {string}
 */
export function generateSecurePassword(length = 24, options = { uppercase: true, lowercase: true, numbers: true, symbols: true }) {
  const cleanLength = Math.max(16, Math.min(64, length || 24));
  let charset = '';
  if (options.uppercase) charset += 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  if (options.lowercase) charset += 'abcdefghijkmnopqrstuvwxyz';
  if (options.numbers) charset += '23456789';
  if (options.symbols) charset += '!@#$%^&*()-_=+[]{}|;:,.<>?';
  
  if (!charset) charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
  
  const randomBytes = generateRandomBytes(cleanLength);
  let password = '';
  for (let i = 0; i < cleanLength; i++) {
    password += charset[randomBytes[i] % charset.length];
  }
  return password;
}

/**
 * Calculate password strength score and entropy estimation
 * @param {string} password 
 * @returns {{ score: number, label: string, color: string, percent: number }}
 */
export function calculatePasswordStrength(password) {
  if (!password) {
    return { score: 0, label: 'Empty', color: '#666666', percent: 0 };
  }

  let poolSize = 0;
  if (/[a-z]/.test(password)) poolSize += 26;
  if (/[A-Z]/.test(password)) poolSize += 26;
  if (/[0-9]/.test(password)) poolSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) poolSize += 32;

  const entropy = password.length * Math.log2(Math.max(poolSize, 2));

  if (entropy < 40 || password.length < 10) {
    return { score: 1, label: 'Weak', color: '#ff453a', percent: 25 };
  } else if (entropy < 65 || password.length < 14) {
    return { score: 2, label: 'Fair', color: '#ff9f0a', percent: 50 };
  } else if (entropy < 90 || password.length < 18) {
    return { score: 3, label: 'Strong', color: '#30d158', percent: 75 };
  } else {
    return { score: 4, label: 'Military-grade', color: '#ffffff', percent: 100 };
  }
}

/**
 * Validate PIN strength (6 digits, reject obvious repeating or sequence patterns)
 * @param {string} pin 
 * @returns {{ valid: boolean, reason?: string }}
 */
export function validatePinStrength(pin) {
  if (!pin || typeof pin !== 'string') {
    return { valid: false, reason: 'PIN is required.' };
  }
  if (!/^\d{6}$/.test(pin)) {
    return { valid: false, reason: 'PIN must be exactly 6 digits.' };
  }
  
  const weakPins = [
    '000000', '111111', '222222', '333333', '444444',
    '555555', '666666', '777777', '888888', '999999',
    '123456', '654321', '012345', '543210', '121212',
    '696969', '112233', '123123', '007007'
  ];
  
  if (weakPins.includes(pin)) {
    return { valid: false, reason: 'This PIN is too common. Please choose a stronger 6-digit PIN.' };
  }
  
  return { valid: true };
}

export const GATE_SALT_HEX = DEFAULT_GATE_SALT_HEX;
