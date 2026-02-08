// management-server/lib/vault.js
// Zero-knowledge vault encryption library

import argon2 from "argon2";
import * as bip39 from "bip39";
import crypto from "crypto";

const ARGON2_CONFIG = {
  type: argon2.argon2id,
  memoryCost: 65536, // 64 MB
  timeCost: 3,
  parallelism: 4,
  hashLength: 32,
};

/**
 * Derive encryption key from password
 * @param {string} password - User's vault password
 * @param {Buffer} salt - 16-byte random salt
 * @returns {Promise<Buffer>} 32-byte encryption key
 */
export async function deriveKey(password, salt) {
  return argon2.hash(password, {
    ...ARGON2_CONFIG,
    salt,
    raw: true,
  });
}

/**
 * Encrypt data with AES-256-GCM
 * @param {Buffer} key - 32-byte encryption key
 * @param {Buffer} plaintext - Data to encrypt
 * @returns {{ nonce: Buffer, tag: Buffer, ciphertext: Buffer }}
 */
export function encrypt(key, plaintext) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);

  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);

  const tag = cipher.getAuthTag();

  return { nonce, tag, ciphertext };
}

/**
 * Decrypt data with AES-256-GCM
 * @param {Buffer} key - 32-byte encryption key
 * @param {Buffer} nonce - 12-byte nonce
 * @param {Buffer} tag - 16-byte auth tag
 * @param {Buffer} ciphertext - Encrypted data
 * @returns {Buffer} Decrypted plaintext
 */
export function decrypt(key, nonce, tag, ciphertext) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);

  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * Generate 12-word recovery phrase
 * @returns {{ phrase: string, seed: Buffer }}
 */
export function generateRecoveryPhrase() {
  const entropy = crypto.randomBytes(16); // 128 bits
  const phrase = bip39.entropyToMnemonic(entropy);
  const seed = bip39.mnemonicToSeedSync(phrase).slice(0, 32);
  return { phrase, seed };
}

/**
 * Recover seed from phrase
 * @param {string} phrase - 12-word BIP39 mnemonic
 * @returns {Buffer} 32-byte seed
 */
export function recoverSeedFromPhrase(phrase) {
  if (!bip39.validateMnemonic(phrase)) {
    throw new Error("Invalid recovery phrase");
  }
  return bip39.mnemonicToSeedSync(phrase).slice(0, 32);
}

/**
 * Create a new vault
 * @param {string} password - User's chosen password
 * @returns {Promise<{ vault: object, recoveryPhrase: string }>}
 */
export async function createVault(password) {
  // Generate salt for password derivation
  const salt = crypto.randomBytes(16);

  // Derive key from password
  const key = await deriveKey(password, salt);

  // Generate recovery phrase
  const { phrase, seed } = generateRecoveryPhrase();

  // Encrypt the seed with password-derived key (so recovery works)
  const encryptedSeed = encrypt(key, seed);

  // Initial empty vault data
  const vaultData = {
    credentials: [],
    memory: { preferences: {}, facts: [] },
    conversations: [],
    files: [],
  };

  // Encrypt vault data
  const plaintext = Buffer.from(JSON.stringify(vaultData), "utf8");
  const encrypted = encrypt(key, plaintext);

  // Also encrypt vault with seed (for recovery)
  const seedEncrypted = encrypt(seed, plaintext);

  const vault = {
    version: 1,
    format: "ocmt-vault",
    created: new Date().toISOString(),
    updated: new Date().toISOString(),
    kdf: {
      algorithm: "argon2id",
      version: 19,
      memory: ARGON2_CONFIG.memoryCost,
      iterations: ARGON2_CONFIG.timeCost,
      parallelism: ARGON2_CONFIG.parallelism,
      salt: salt.toString("base64"),
    },
    encryption: {
      algorithm: "aes-256-gcm",
      nonce: encrypted.nonce.toString("base64"),
      tag: encrypted.tag.toString("base64"),
    },
    recovery: {
      encrypted_seed: encryptedSeed.ciphertext.toString("base64"),
      nonce: encryptedSeed.nonce.toString("base64"),
      tag: encryptedSeed.tag.toString("base64"),
      // Seed-encrypted copy of vault for recovery
      vault_nonce: seedEncrypted.nonce.toString("base64"),
      vault_tag: seedEncrypted.tag.toString("base64"),
      vault_ciphertext: seedEncrypted.ciphertext.toString("base64"),
    },
    ciphertext: encrypted.ciphertext.toString("base64"),
  };

  return { vault, recoveryPhrase: phrase };
}

/**
 * Unlock vault with password
 * @param {object} vault - Vault object from DB
 * @param {string} password - User's password
 * @returns {Promise<object>} Decrypted vault data
 */
export async function unlockVault(vault, password) {
  const salt = Buffer.from(vault.kdf.salt, "base64");
  const key = await deriveKey(password, salt);

  const nonce = Buffer.from(vault.encryption.nonce, "base64");
  const tag = Buffer.from(vault.encryption.tag, "base64");
  const ciphertext = Buffer.from(vault.ciphertext, "base64");

  try {
    const plaintext = decrypt(key, nonce, tag, ciphertext);
    return JSON.parse(plaintext.toString("utf8"));
  } catch {
    throw new Error("Invalid password");
  }
}

/**
 * Unlock vault with password and return both data and key
 * Key is kept in memory for session operations (zero-knowledge pattern)
 * @param {object} vault - Vault object from DB
 * @param {string} password - User's password
 * @returns {Promise<{ data: object, key: Buffer }>} Decrypted data and derived key
 */
export async function unlockVaultWithPasswordAndKey(vault, password) {
  const salt = Buffer.from(vault.kdf.salt, "base64");
  const key = await deriveKey(password, salt);

  const nonce = Buffer.from(vault.encryption.nonce, "base64");
  const tag = Buffer.from(vault.encryption.tag, "base64");
  const ciphertext = Buffer.from(vault.ciphertext, "base64");

  try {
    const plaintext = decrypt(key, nonce, tag, ciphertext);
    return {
      data: JSON.parse(plaintext.toString("utf8")),
      key, // Return key for session storage (in-memory only)
    };
  } catch {
    throw new Error("Invalid password");
  }
}

/**
 * Unlock vault with key directly (for biometric unlock)
 * @param {object} vault - Vault object from DB
 * @param {Buffer} key - 32-byte encryption key
 * @returns {object} Decrypted vault data
 */
export function unlockVaultWithKey(vault, key) {
  const nonce = Buffer.from(vault.encryption.nonce, "base64");
  const tag = Buffer.from(vault.encryption.tag, "base64");
  const ciphertext = Buffer.from(vault.ciphertext, "base64");

  try {
    const plaintext = decrypt(key, nonce, tag, ciphertext);
    return JSON.parse(plaintext.toString("utf8"));
  } catch {
    throw new Error("Invalid key");
  }
}

/**
 * Unlock vault with recovery phrase
 * @param {object} vault - Vault object from DB
 * @param {string} phrase - 12-word recovery phrase
 * @returns {{ data: object, seed: Buffer }}
 */
export function unlockVaultWithRecovery(vault, phrase) {
  const seed = recoverSeedFromPhrase(phrase);

  // Decrypt using seed-encrypted vault copy
  const nonce = Buffer.from(vault.recovery.vault_nonce, "base64");
  const tag = Buffer.from(vault.recovery.vault_tag, "base64");
  const ciphertext = Buffer.from(vault.recovery.vault_ciphertext, "base64");

  try {
    const plaintext = decrypt(seed, nonce, tag, ciphertext);
    return {
      data: JSON.parse(plaintext.toString("utf8")),
      seed,
    };
  } catch {
    throw new Error("Invalid recovery phrase");
  }
}

/**
 * Update vault data (re-encrypt with same key)
 * @param {object} vault - Current vault object
 * @param {string} password - User's password
 * @param {object} newData - New vault data to encrypt
 * @returns {Promise<object>} Updated vault object
 */
export async function updateVault(vault, password, newData) {
  const salt = Buffer.from(vault.kdf.salt, "base64");
  const key = await deriveKey(password, salt);

  const plaintext = Buffer.from(JSON.stringify(newData), "utf8");
  const encrypted = encrypt(key, plaintext);

  // Also get the seed to re-encrypt recovery copy
  const seedNonce = Buffer.from(vault.recovery.nonce, "base64");
  const seedTag = Buffer.from(vault.recovery.tag, "base64");
  const seedCiphertext = Buffer.from(vault.recovery.encrypted_seed, "base64");
  const seed = decrypt(key, seedNonce, seedTag, seedCiphertext);

  // Re-encrypt with seed for recovery
  const seedEncrypted = encrypt(seed, plaintext);

  return {
    ...vault,
    updated: new Date().toISOString(),
    encryption: {
      algorithm: "aes-256-gcm",
      nonce: encrypted.nonce.toString("base64"),
      tag: encrypted.tag.toString("base64"),
    },
    recovery: {
      ...vault.recovery,
      vault_nonce: seedEncrypted.nonce.toString("base64"),
      vault_tag: seedEncrypted.tag.toString("base64"),
      vault_ciphertext: seedEncrypted.ciphertext.toString("base64"),
    },
    ciphertext: encrypted.ciphertext.toString("base64"),
  };
}

/**
 * Update vault data using derived key directly (zero-knowledge pattern)
 * Use this when the key is stored in session memory (e.g., OAuth callback)
 * @param {object} vault - Current vault object
 * @param {Buffer} key - 32-byte encryption key (from unlockVaultWithPasswordAndKey)
 * @param {object} newData - New vault data to encrypt
 * @returns {object} Updated vault object
 */
export function updateVaultWithKey(vault, key, newData) {
  const plaintext = Buffer.from(JSON.stringify(newData), "utf8");
  const encrypted = encrypt(key, plaintext);

  // Get the seed to re-encrypt recovery copy
  const seedNonce = Buffer.from(vault.recovery.nonce, "base64");
  const seedTag = Buffer.from(vault.recovery.tag, "base64");
  const seedCiphertext = Buffer.from(vault.recovery.encrypted_seed, "base64");
  const seed = decrypt(key, seedNonce, seedTag, seedCiphertext);

  // Re-encrypt with seed for recovery
  const seedEncrypted = encrypt(seed, plaintext);

  return {
    ...vault,
    updated: new Date().toISOString(),
    encryption: {
      algorithm: "aes-256-gcm",
      nonce: encrypted.nonce.toString("base64"),
      tag: encrypted.tag.toString("base64"),
    },
    recovery: {
      ...vault.recovery,
      vault_nonce: seedEncrypted.nonce.toString("base64"),
      vault_tag: seedEncrypted.tag.toString("base64"),
      vault_ciphertext: seedEncrypted.ciphertext.toString("base64"),
    },
    ciphertext: encrypted.ciphertext.toString("base64"),
  };
}

/**
 * Create vault with existing data (for recovery password reset)
 * @param {string} password - New password
 * @param {object} data - Existing vault data
 * @param {Buffer} seed - Recovery seed (to keep same recovery phrase)
 * @returns {Promise<{ vault: object }>}
 */
export async function createVaultWithData(password, data, seed) {
  // Generate new salt for password derivation
  const salt = crypto.randomBytes(16);

  // Derive key from new password
  const key = await deriveKey(password, salt);

  // Encrypt the existing seed with new password-derived key
  const encryptedSeed = encrypt(key, seed);

  // Encrypt vault data with new key
  const plaintext = Buffer.from(JSON.stringify(data), "utf8");
  const encrypted = encrypt(key, plaintext);

  // Also encrypt with seed (for recovery)
  const seedEncrypted = encrypt(seed, plaintext);

  const vault = {
    version: 1,
    format: "ocmt-vault",
    created: new Date().toISOString(),
    updated: new Date().toISOString(),
    kdf: {
      algorithm: "argon2id",
      version: 19,
      memory: ARGON2_CONFIG.memoryCost,
      iterations: ARGON2_CONFIG.timeCost,
      parallelism: ARGON2_CONFIG.parallelism,
      salt: salt.toString("base64"),
    },
    encryption: {
      algorithm: "aes-256-gcm",
      nonce: encrypted.nonce.toString("base64"),
      tag: encrypted.tag.toString("base64"),
    },
    recovery: {
      encrypted_seed: encryptedSeed.ciphertext.toString("base64"),
      nonce: encryptedSeed.nonce.toString("base64"),
      tag: encryptedSeed.tag.toString("base64"),
      vault_nonce: seedEncrypted.nonce.toString("base64"),
      vault_tag: seedEncrypted.tag.toString("base64"),
      vault_ciphertext: seedEncrypted.ciphertext.toString("base64"),
    },
    ciphertext: encrypted.ciphertext.toString("base64"),
  };

  return { vault };
}

/**
 * Change vault password
 * @param {object} vault - Current vault object
 * @param {string} oldPassword - Current password
 * @param {string} newPassword - New password
 * @returns {Promise<object>} Updated vault with new password
 */
export async function changePassword(vault, oldPassword, newPassword) {
  // Unlock with old password to get data and seed
  const data = await unlockVault(vault, oldPassword);

  // Get the seed
  const oldSalt = Buffer.from(vault.kdf.salt, "base64");
  const oldKey = await deriveKey(oldPassword, oldSalt);
  const seedNonce = Buffer.from(vault.recovery.nonce, "base64");
  const seedTag = Buffer.from(vault.recovery.tag, "base64");
  const seedCiphertext = Buffer.from(vault.recovery.encrypted_seed, "base64");
  const seed = decrypt(oldKey, seedNonce, seedTag, seedCiphertext);

  // Re-create vault with new password (same data, same seed for recovery phrase)
  return createVaultWithData(newPassword, data, seed);
}

/**
 * Export vault for backup (already encrypted, just format nicely)
 * @param {object} vault - Vault object
 * @returns {string} JSON string for download
 */
export function exportVault(vault) {
  return JSON.stringify(vault, null, 2);
}

/**
 * Validate vault structure
 * @param {object} vault - Vault object to validate
 * @returns {boolean}
 */
export function isValidVault(vault) {
  return !!(
    vault &&
    vault.version === 1 &&
    vault.format === "ocmt-vault" &&
    vault.kdf?.algorithm === "argon2id" &&
    vault.encryption?.algorithm === "aes-256-gcm" &&
    vault.ciphertext &&
    vault.recovery
  );
}

/**
 * Check if biometrics can be used (password was entered recently enough)
 * @param {string|null} lastPasswordAt - ISO timestamp of last password entry
 * @param {number} maxAgeDays - Maximum days since last password entry
 * @returns {boolean}
 */
export function canUseBiometrics(lastPasswordAt, maxAgeDays = 7) {
  if (!lastPasswordAt) {
    return false;
  }

  const lastPassword = new Date(lastPasswordAt);
  const now = new Date();
  const diffMs = now.getTime() - lastPassword.getTime();
  const diffDays = diffMs / (1000 * 60 * 60 * 24);

  return diffDays <= maxAgeDays;
}
