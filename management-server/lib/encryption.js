// management-server/lib/encryption.js
// Encryption key versioning and rotation support
// Supports multiple key versions for seamless key rotation without downtime

import crypto from "crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;

// Cached keys - loaded once at startup
let encryptionKeys = null;
let currentVersion = null;

/**
 * Load encryption keys from environment variables.
 * Supports multiple versions for rotation:
 * - ENCRYPTION_KEY: Current key (required)
 * - ENCRYPTION_KEY_VERSION: Current version number (default: 0)
 * - ENCRYPTION_KEY_V0, ENCRYPTION_KEY_V1, etc.: Previous keys for decryption
 *
 * @returns {{ keys: Map<number, Buffer>, currentVersion: number }}
 */
function loadEncryptionKeys() {
  if (encryptionKeys !== null) {
    return { keys: encryptionKeys, currentVersion };
  }

  const keys = new Map();

  // Current key (required)
  const currentKey = process.env.ENCRYPTION_KEY;
  if (!currentKey) {
    throw new Error("ENCRYPTION_KEY environment variable is required");
  }

  // Validate key length (32 bytes = 64 hex chars for AES-256)
  if (currentKey.length !== 64) {
    throw new Error("ENCRYPTION_KEY must be 64 hex characters (32 bytes)");
  }

  // Determine current version
  const version = parseInt(process.env.ENCRYPTION_KEY_VERSION || "0", 10);
  keys.set(version, Buffer.from(currentKey, "hex"));

  // Load previous keys for decryption (optional)
  // ENCRYPTION_KEY_V0, ENCRYPTION_KEY_V1, etc.
  for (let v = 0; v < version; v++) {
    const envVar = `ENCRYPTION_KEY_V${v}`;
    const key = process.env[envVar];
    if (key) {
      if (key.length !== 64) {
        throw new Error(`${envVar} must be 64 hex characters (32 bytes)`);
      }
      keys.set(v, Buffer.from(key, "hex"));
    }
  }

  // Cache for future calls
  encryptionKeys = keys;
  currentVersion = version;

  return { keys, currentVersion: version };
}

/**
 * Get the current encryption key version.
 * @returns {number} Current key version
 */
export function getCurrentKeyVersion() {
  const { currentVersion } = loadEncryptionKeys();
  return currentVersion;
}

/**
 * Check if a specific key version is available.
 * @param {number} version - Version number to check
 * @returns {boolean} True if key version is available
 */
export function hasKeyVersion(version) {
  const { keys } = loadEncryptionKeys();
  return keys.has(version);
}

/**
 * Encrypt plaintext with the current key version.
 * Output format: v{version}:{iv}:{authTag}:{encrypted} (all base64)
 *
 * @param {string} plaintext - Text to encrypt
 * @param {number} [keyVersion] - Optional key version to use (defaults to current)
 * @returns {string|null} Versioned ciphertext or null if plaintext is empty
 */
export function encrypt(plaintext, keyVersion) {
  if (!plaintext) return null;

  const { keys, currentVersion: defaultVersion } = loadEncryptionKeys();
  const version = keyVersion !== undefined ? keyVersion : defaultVersion;

  const key = keys.get(version);
  if (!key) {
    throw new Error(`Encryption key version ${version} not available`);
  }

  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  let encrypted = cipher.update(plaintext, "utf8", "base64");
  encrypted += cipher.final("base64");

  const authTag = cipher.getAuthTag().toString("base64");

  // New versioned format
  return `v${version}:${iv.toString("base64")}:${authTag}:${encrypted}`;
}

/**
 * Decrypt ciphertext, automatically detecting the key version.
 * Supports both:
 * - Legacy format: {iv}:{authTag}:{encrypted} (hex encoded, treated as v0)
 * - Versioned format: v{version}:{iv}:{authTag}:{encrypted} (base64 encoded)
 *
 * @param {string} ciphertext - Encrypted text to decrypt
 * @returns {string|null} Decrypted plaintext or null if ciphertext is empty
 */
export function decrypt(ciphertext) {
  if (!ciphertext) return null;

  const { keys } = loadEncryptionKeys();

  let version, iv, authTag, encrypted, encoding;

  // Parse format - check for version prefix
  if (ciphertext.startsWith("v")) {
    // New versioned format: v{version}:{iv}:{authTag}:{encrypted}
    const parts = ciphertext.split(":");
    if (parts.length !== 4) {
      throw new Error("Invalid encrypted data format");
    }

    version = parseInt(parts[0].substring(1), 10);
    iv = Buffer.from(parts[1], "base64");
    authTag = Buffer.from(parts[2], "base64");
    encrypted = parts[3];
    encoding = "base64";
  } else {
    // Legacy format: {iv}:{authTag}:{encrypted} (hex encoded, no version = v0)
    const parts = ciphertext.split(":");
    if (parts.length !== 3) {
      throw new Error("Invalid encrypted data format");
    }

    version = 0;
    iv = Buffer.from(parts[0], "hex");
    authTag = Buffer.from(parts[1], "hex");
    encrypted = parts[2];
    encoding = "hex";
  }

  // Get key for this version
  const key = keys.get(version);
  if (!key) {
    throw new Error(`Encryption key version ${version} not available`);
  }

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(encrypted, encoding, "utf8");
  decrypted += decipher.final("utf8");

  return decrypted;
}

/**
 * Get the key version from encrypted data.
 *
 * @param {string} encryptedText - Encrypted text to inspect
 * @returns {number|null} Key version or null if text is empty
 */
export function getKeyVersion(encryptedText) {
  if (!encryptedText) return null;

  if (encryptedText.startsWith("v")) {
    const versionPart = encryptedText.split(":")[0];
    return parseInt(versionPart.substring(1), 10);
  }

  // Legacy format = v0
  return 0;
}

/**
 * Check if encrypted data needs re-encryption (uses old key version).
 *
 * @param {string} encryptedText - Encrypted text to check
 * @returns {boolean} True if data uses an older key version
 */
export function needsReEncryption(encryptedText) {
  if (!encryptedText) return false;

  const { currentVersion } = loadEncryptionKeys();
  const version = getKeyVersion(encryptedText);

  return version < currentVersion;
}

/**
 * Re-encrypt data with the current key version.
 * Decrypts with the original key and re-encrypts with current key.
 *
 * @param {string} encryptedText - Encrypted text to re-encrypt
 * @returns {string} Re-encrypted text with current key version
 */
export function reEncrypt(encryptedText) {
  const decrypted = decrypt(encryptedText);
  return encrypt(decrypted);
}

/**
 * Generate a new encryption key suitable for AES-256.
 *
 * @returns {string} 64-character hex string (32 bytes)
 */
export function generateKey() {
  return crypto.randomBytes(32).toString("hex");
}

/**
 * Rotate to a new encryption key.
 * This generates a new key and returns the configuration needed for rotation.
 *
 * Note: This function does NOT automatically update environment variables.
 * The returned configuration should be:
 * 1. Stored securely
 * 2. Used to update environment configuration
 * 3. Deployed with proper migration
 *
 * @returns {{ newKey: string, newVersion: number, currentKeyEnvVar: string }}
 */
export function rotateKey() {
  const { currentVersion } = loadEncryptionKeys();
  const newVersion = currentVersion + 1;
  const newKey = generateKey();

  return {
    newKey,
    newVersion,
    currentKeyEnvVar: `ENCRYPTION_KEY_V${currentVersion}`,
    instructions: [
      `1. Store current ENCRYPTION_KEY as ENCRYPTION_KEY_V${currentVersion}`,
      `2. Set ENCRYPTION_KEY=${newKey}`,
      `3. Set ENCRYPTION_KEY_VERSION=${newVersion}`,
      "4. Deploy with new environment variables",
      "5. Run migration script to re-encrypt existing data",
    ],
  };
}

/**
 * Validate that an encryption key is properly formatted.
 *
 * @param {string} key - Key to validate (hex string)
 * @returns {{ valid: boolean, error?: string }}
 */
export function validateKey(key) {
  if (!key) {
    return { valid: false, error: "Key is required" };
  }

  if (typeof key !== "string") {
    return { valid: false, error: "Key must be a string" };
  }

  if (key.length !== 64) {
    return { valid: false, error: "Key must be 64 hex characters (32 bytes)" };
  }

  if (!/^[0-9a-fA-F]+$/.test(key)) {
    return { valid: false, error: "Key must contain only hex characters" };
  }

  return { valid: true };
}

/**
 * Get encryption metadata (for debugging/monitoring).
 * Does not expose actual keys.
 *
 * @returns {{ currentVersion: number, availableVersions: number[], keyCount: number }}
 */
export function getEncryptionMetadata() {
  const { keys, currentVersion } = loadEncryptionKeys();

  return {
    currentVersion,
    availableVersions: Array.from(keys.keys()).sort((a, b) => a - b),
    keyCount: keys.size,
  };
}

/**
 * Clear cached keys (for testing or key refresh).
 * After calling this, keys will be reloaded from environment on next operation.
 */
export function clearKeyCache() {
  encryptionKeys = null;
  currentVersion = null;
}
