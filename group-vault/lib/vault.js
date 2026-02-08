// group-vault/lib/vault.js
// Encrypted storage for group-level secrets
// Reuses crypto primitives from management-server vault

import argon2 from "argon2";
import crypto from "crypto";

const ARGON2_CONFIG = {
  type: argon2.argon2id,
  memoryCost: 65536, // 64 MB
  timeCost: 3,
  parallelism: 4,
  hashLength: 32,
};

/**
 * Derive encryption key from vault password
 * @param {string} password - Group vault password
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
 * Create a new group vault
 * @param {string} password - Vault password (shared among threshold admins)
 * @returns {Promise<{ vault: object }>}
 */
export async function createGroupVault(password) {
  const salt = crypto.randomBytes(16);
  const key = await deriveKey(password, salt);

  // Initial empty secrets store
  const vaultData = {
    secrets: {},
    metadata: {
      version: 1,
      createdAt: new Date().toISOString(),
    },
  };

  const plaintext = Buffer.from(JSON.stringify(vaultData), "utf8");
  const encrypted = encrypt(key, plaintext);

  const vault = {
    version: 1,
    format: "ocmt-group-vault",
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
    ciphertext: encrypted.ciphertext.toString("base64"),
  };

  return { vault };
}

/**
 * Unlock group vault with password or key
 * @param {object} vault - Vault object
 * @param {string|null} password - Vault password (null if using key)
 * @param {Buffer} [existingKey] - Pre-derived key (for session-based access)
 * @returns {Promise<{ data: object, key: Buffer }>}
 */
export async function unlockGroupVault(vault, password, existingKey) {
  let key;
  if (existingKey) {
    key = existingKey;
  } else if (password) {
    const salt = Buffer.from(vault.kdf.salt, "base64");
    key = await deriveKey(password, salt);
  } else {
    throw new Error("Password or key required");
  }

  const nonce = Buffer.from(vault.encryption.nonce, "base64");
  const tag = Buffer.from(vault.encryption.tag, "base64");
  const ciphertext = Buffer.from(vault.ciphertext, "base64");

  try {
    const plaintext = decrypt(key, nonce, tag, ciphertext);
    return {
      data: JSON.parse(plaintext.toString("utf8")),
      key,
    };
  } catch {
    throw new Error("Invalid password or key");
  }
}

/**
 * Update group vault data
 * @param {object} vault - Current vault object
 * @param {Buffer} key - Encryption key (from unlockGroupVault)
 * @param {object} newData - New vault data
 * @returns {object} Updated vault object
 */
export function updateGroupVault(vault, key, newData) {
  const plaintext = Buffer.from(JSON.stringify(newData), "utf8");
  const encrypted = encrypt(key, plaintext);

  return {
    ...vault,
    updated: new Date().toISOString(),
    encryption: {
      algorithm: "aes-256-gcm",
      nonce: encrypted.nonce.toString("base64"),
      tag: encrypted.tag.toString("base64"),
    },
    ciphertext: encrypted.ciphertext.toString("base64"),
  };
}

/**
 * Validate group vault structure
 * @param {object} vault - Vault object to validate
 * @returns {boolean}
 */
export function isValidGroupVault(vault) {
  return !!(
    vault &&
    vault.version === 1 &&
    vault.format === "ocmt-group-vault" &&
    vault.kdf?.algorithm === "argon2id" &&
    vault.encryption?.algorithm === "aes-256-gcm" &&
    vault.ciphertext
  );
}

/**
 * In-memory session store for unlocked vaults
 * Key: groupId, Value: { key: Buffer, expiresAt: number }
 */
const vaultSessions = new Map();

const VAULT_SESSION_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes

/**
 * Create vault session (after unlock)
 */
export function createVaultSession(groupId, key) {
  vaultSessions.set(groupId, {
    key,
    expiresAt: Date.now() + VAULT_SESSION_TIMEOUT_MS,
  });
}

/**
 * Get vault session
 */
export function getVaultSession(groupId) {
  const session = vaultSessions.get(groupId);
  if (!session) {
    return null;
  }
  if (session.expiresAt < Date.now()) {
    vaultSessions.delete(groupId);
    return null;
  }
  return session;
}

/**
 * Delete vault session (lock)
 */
export function deleteVaultSession(groupId) {
  vaultSessions.delete(groupId);
}

/**
 * Extend vault session
 */
export function extendVaultSession(groupId) {
  const session = vaultSessions.get(groupId);
  if (session && session.expiresAt > Date.now()) {
    session.expiresAt = Date.now() + VAULT_SESSION_TIMEOUT_MS;
    return true;
  }
  return false;
}

// Clean up expired sessions periodically
setInterval(() => {
  const now = Date.now();
  for (const [groupId, session] of vaultSessions) {
    if (session.expiresAt < now) {
      vaultSessions.delete(groupId);
    }
  }
}, 60000);

export { vaultSessions, VAULT_SESSION_TIMEOUT_MS };
