// management-server/lib/totp.js
// TOTP (Time-based One-Time Password) utilities for MFA
// Compatible with Google Authenticator, Authy, and other TOTP apps

import argon2 from "argon2";
import crypto from "crypto";
import { encrypt, decrypt } from "../db/core.js";

// TOTP Configuration (RFC 6238)
const TOTP_CONFIG = {
  issuer: "OCMT",
  algorithm: "SHA1", // Most authenticator apps expect SHA1
  digits: 6,
  period: 30, // seconds
  secretSize: 20, // bytes (160 bits, standard for TOTP)
};

// Backup code configuration
const BACKUP_CODE_COUNT = 8;
const BACKUP_CODE_LENGTH = 8;
// Exclude ambiguous characters (0, O, 1, I, l)
const BACKUP_CODE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

// Argon2id configuration for backup code hashing
const ARGON2_CONFIG = {
  type: argon2.argon2id,
  memoryCost: 65536, // 64 MB
  timeCost: 3,
  parallelism: 1,
};

// Base32 alphabet (RFC 4648)
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/**
 * Encode bytes to base32 string
 * @param {Buffer} buffer - Bytes to encode
 * @returns {string} Base32 encoded string
 */
function base32Encode(buffer) {
  let result = "";
  let bits = 0;
  let value = 0;

  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      bits -= 5;
      result += BASE32_ALPHABET[(value >>> bits) & 0x1f];
    }
  }

  if (bits > 0) {
    result += BASE32_ALPHABET[(value << (5 - bits)) & 0x1f];
  }

  return result;
}

/**
 * Decode base32 string to bytes
 * @param {string} str - Base32 encoded string
 * @returns {Buffer} Decoded bytes
 */
function base32Decode(str) {
  const cleaned = str.toUpperCase().replace(/[^A-Z2-7]/g, "");
  const bytes = [];
  let bits = 0;
  let value = 0;

  for (const char of cleaned) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) {
      continue;
    }

    value = (value << 5) | index;
    bits += 5;

    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >>> bits) & 0xff);
    }
  }

  return Buffer.from(bytes);
}

/**
 * Generate a TOTP counter value for the current time
 * @param {number} [offset=0] - Time step offset for window tolerance
 * @returns {bigint} Counter value
 */
function getTimeCounter(offset = 0) {
  const now = Math.floor(Date.now() / 1000);
  return BigInt(Math.floor(now / TOTP_CONFIG.period) + offset);
}

/**
 * Generate TOTP code for a given secret and counter
 * @param {Buffer} secret - Secret key bytes
 * @param {bigint} counter - Time counter value
 * @returns {string} 6-digit TOTP code
 */
function generateTotpCode(secret, counter) {
  // Convert counter to 8-byte big-endian buffer
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(counter);

  // Calculate HMAC-SHA1
  const hmac = crypto.createHmac("sha1", secret);
  hmac.update(counterBuffer);
  const hash = hmac.digest();

  // Dynamic truncation (RFC 4226)
  const offset = hash[hash.length - 1] & 0x0f;
  const code =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);

  // Modulo to get desired number of digits
  const otp = code % Math.pow(10, TOTP_CONFIG.digits);
  return otp.toString().padStart(TOTP_CONFIG.digits, "0");
}

/**
 * Generate a new TOTP secret
 * Returns both the raw base32 secret (for QR codes) and encrypted version (for storage)
 * @returns {{ secret: string, encryptedSecret: string }}
 */
export function generateTotpSecret() {
  const secretBytes = crypto.randomBytes(TOTP_CONFIG.secretSize);
  const secret = base32Encode(secretBytes);
  const encryptedSecret = encrypt(secret);
  return { secret, encryptedSecret };
}

/**
 * Generate otpauth:// URI for authenticator apps
 * @param {string} email - User's email address (used as account name)
 * @param {string} secret - Base32 encoded secret
 * @returns {string} otpauth:// URI
 */
export function generateTotpUri(email, secret) {
  const issuer = encodeURIComponent(TOTP_CONFIG.issuer);
  const account = encodeURIComponent(email);
  const params = new URLSearchParams({
    secret: secret.toUpperCase(),
    issuer: TOTP_CONFIG.issuer,
    algorithm: TOTP_CONFIG.algorithm,
    digits: String(TOTP_CONFIG.digits),
    period: String(TOTP_CONFIG.period),
  });
  return `otpauth://totp/${issuer}:${account}?${params.toString()}`;
}

/**
 * Generate QR code data URL for authenticator apps
 * Note: This generates a simple ASCII QR representation that can be converted
 * to an image URL on the frontend, or use a dedicated QR library
 * @param {string} email - User's email address
 * @param {string} secret - Base32 encoded secret
 * @returns {string} otpauth:// URI (frontend should convert to QR code)
 */
export function generateTotpQRCodeUri(email, secret) {
  // Return the URI - frontend will render QR code using a library
  // This avoids adding qrcode dependency to the backend
  return generateTotpUri(email, secret);
}

/**
 * Verify a TOTP code against an encrypted secret
 * Uses a time window of +/- 1 step (90 seconds total) to allow for clock drift
 * @param {string} encryptedSecret - Encrypted base32 secret from database
 * @param {string} code - 6-digit code from user
 * @returns {boolean} True if code is valid
 */
export function verifyTotpCode(encryptedSecret, code) {
  if (!encryptedSecret || !code) {
    return false;
  }

  // Normalize code (remove spaces, ensure 6 digits)
  const normalizedCode = code.replace(/\s/g, "").trim();
  if (!/^\d{6}$/.test(normalizedCode)) {
    return false;
  }

  try {
    const secret = decrypt(encryptedSecret);
    const secretBytes = base32Decode(secret);

    // Check current time step and +/- 1 step for clock drift tolerance
    for (const offset of [0, -1, 1]) {
      const counter = getTimeCounter(offset);
      const expectedCode = generateTotpCode(secretBytes, counter);

      // Use timing-safe comparison to prevent timing attacks
      if (crypto.timingSafeEqual(Buffer.from(normalizedCode), Buffer.from(expectedCode))) {
        return true;
      }
    }

    return false;
  } catch {
    return false;
  }
}

/**
 * Generate backup codes for account recovery
 * Returns plaintext codes (to show user once) and hashed codes (for storage)
 * @returns {Promise<{ codes: string[], hashedCodes: string[] }>}
 */
export async function generateBackupCodes() {
  const codes = [];
  const hashedCodes = [];

  for (let i = 0; i < BACKUP_CODE_COUNT; i++) {
    // Generate random code using cryptographically secure random bytes
    let code = "";
    const randomBytes = crypto.randomBytes(BACKUP_CODE_LENGTH);
    for (let j = 0; j < BACKUP_CODE_LENGTH; j++) {
      code += BACKUP_CODE_CHARS[randomBytes[j] % BACKUP_CODE_CHARS.length];
    }

    // Format as XXXX-XXXX for readability
    const formattedCode = `${code.slice(0, 4)}-${code.slice(4)}`;
    codes.push(formattedCode);

    // Hash the raw code (without dash) using Argon2id
    const hash = await argon2.hash(code, ARGON2_CONFIG);
    hashedCodes.push(hash);
  }

  return { codes, hashedCodes };
}

/**
 * Verify a backup code against a stored hash
 * @param {string} code - Backup code from user (with or without dash)
 * @param {string} hash - Argon2id hash from database
 * @returns {Promise<boolean>} True if code matches hash
 */
export async function verifyBackupCode(code, hash) {
  if (!code || !hash) {
    return false;
  }

  // Normalize: remove dashes, convert to uppercase
  const normalizedCode = code.replace(/-/g, "").toUpperCase();

  // Validate format (should be 8 alphanumeric characters)
  if (normalizedCode.length !== BACKUP_CODE_LENGTH) {
    return false;
  }

  try {
    return await argon2.verify(hash, normalizedCode);
  } catch {
    return false;
  }
}

/**
 * Get the current TOTP code for a secret (for testing purposes)
 * @param {string} secret - Base32 encoded secret
 * @returns {string} Current 6-digit TOTP code
 */
export function getCurrentTotpCode(secret) {
  const secretBytes = base32Decode(secret);
  const counter = getTimeCounter(0);
  return generateTotpCode(secretBytes, counter);
}
