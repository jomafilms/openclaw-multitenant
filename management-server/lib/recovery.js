// management-server/lib/recovery.js
// Multi-method recovery system for vault access

import argon2 from "argon2";
import crypto from "crypto";
import { split, combine, encodeShare, decodeShare, reconstructFromShards } from "./shamir.js";
import { encrypt, decrypt, deriveKey } from "./vault.js";

const ARGON2_CONFIG = {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 4,
  hashLength: 32,
};

/**
 * Recovery method types
 */
export const RecoveryMethodType = {
  BIP39: "bip39", // Existing 12-word phrase
  SOCIAL: "social", // 3-of-5 friends (Shamir)
  HARDWARE: "hardware", // Backup key for YubiKey/paper
};

// ============================================================
// SOCIAL RECOVERY (Shamir's Secret Sharing)
// ============================================================

/**
 * Set up social recovery with trusted contacts
 * @param {Buffer} vaultSeed - The vault's recovery seed (32 bytes)
 * @param {Array<{email: string, name: string}>} contacts - 5 trusted contacts
 * @param {number} threshold - Minimum contacts needed (default: 3)
 * @returns {Object} Setup data including encrypted shards for each contact
 */
export function setupSocialRecovery(vaultSeed, contacts, threshold = 3) {
  if (contacts.length < 3) {
    throw new Error("Need at least 3 contacts for social recovery");
  }
  if (contacts.length > 10) {
    throw new Error("Maximum 10 contacts allowed");
  }
  if (threshold < 2 || threshold > contacts.length) {
    throw new Error(`Threshold must be between 2 and ${contacts.length}`);
  }

  // Generate a unique recovery ID for this setup
  const recoveryId = crypto.randomBytes(16).toString("hex");

  // Split the seed using Shamir's Secret Sharing
  const shares = split(vaultSeed, contacts.length, threshold);

  // Create shard data for each contact
  const contactShards = contacts.map((contact, idx) => {
    // Generate a per-contact encryption key (derived from recovery ID + contact email)
    // This adds a layer of protection so shards aren't useful without the recovery context
    const contactSalt = crypto
      .createHash("sha256")
      .update(recoveryId + contact.email.toLowerCase())
      .digest();

    // Encrypt the shard with contact-specific key
    // encodeShare returns a base64 string, store it as utf8 bytes for encryption
    const shardData = encodeShare(shares[idx]);
    const shardBuffer = Buffer.from(shardData, "utf8");

    // Use simple AES encryption with the salt-derived key
    const key = contactSalt.slice(0, 32);
    const encrypted = encrypt(key, shardBuffer);

    return {
      email: contact.email.toLowerCase(),
      name: contact.name,
      shareIndex: shares[idx].x,
      encryptedShard: {
        nonce: encrypted.nonce.toString("base64"),
        tag: encrypted.tag.toString("base64"),
        ciphertext: encrypted.ciphertext.toString("base64"),
      },
    };
  });

  return {
    recoveryId,
    threshold,
    totalShares: contacts.length,
    contacts: contactShards,
    createdAt: new Date().toISOString(),
  };
}

/**
 * Decrypt a shard for submission (contact side)
 * @param {string} recoveryId - The recovery ID
 * @param {string} contactEmail - Contact's email
 * @param {Object} encryptedShard - The encrypted shard data
 * @returns {string} Decrypted shard (base64 encoded)
 */
export function decryptContactShard(recoveryId, contactEmail, encryptedShard) {
  const contactSalt = crypto
    .createHash("sha256")
    .update(recoveryId + contactEmail.toLowerCase())
    .digest();

  const key = contactSalt.slice(0, 32);
  const nonce = Buffer.from(encryptedShard.nonce, "base64");
  const tag = Buffer.from(encryptedShard.tag, "base64");
  const ciphertext = Buffer.from(encryptedShard.ciphertext, "base64");

  const shardBuffer = decrypt(key, nonce, tag, ciphertext);
  // shardBuffer contains the base64-encoded share as utf8 bytes
  return shardBuffer.toString("utf8");
}

/**
 * Combine shards to recover the vault seed
 * @param {Array<{shard: string}>} shards - Array of decrypted shards (base64)
 * @returns {Buffer} Recovered vault seed
 */
export function recoverSeedFromShards(shards) {
  if (shards.length < 2) {
    throw new Error("Need at least 2 shards to recover");
  }

  const decodedShares = shards.map((s) => decodeShare(s.shard));
  return combine(decodedShares);
}

// ============================================================
// HARDWARE BACKUP KEY
// ============================================================

/**
 * Generate a hardware backup key
 * This key can be stored on a YubiKey (as static password or HMAC-SHA1 challenge)
 * or written down as a secondary recovery method
 * @returns {{ backupKey: string, keyHash: string }}
 */
export function generateHardwareBackupKey() {
  // Generate a 32-byte random key
  const keyBytes = crypto.randomBytes(32);

  // Encode as base32 for easier manual entry (YubiKey compatible)
  // Group in 4-character chunks for readability
  const base32Key = base32Encode(keyBytes);
  const formattedKey = base32Key.match(/.{1,4}/g).join("-");

  // Create a verification hash (stored in vault to verify key)
  const keyHash = crypto.createHash("sha256").update(keyBytes).digest("base64");

  return {
    backupKey: formattedKey,
    keyBytes,
    keyHash,
  };
}

/**
 * Derive encryption key from hardware backup key
 * @param {string} backupKey - The formatted backup key (with dashes)
 * @returns {Buffer} 32-byte encryption key
 */
export function deriveKeyFromHardwareBackup(backupKey) {
  // Remove formatting
  const cleanKey = backupKey.replace(/-/g, "").toUpperCase();
  const keyBytes = base32Decode(cleanKey);

  // Use Argon2 to derive the actual encryption key
  // This adds computational cost if someone tries to brute force
  const salt = Buffer.from("ocmt-hardware-backup-v1");
  return argon2.hash(keyBytes, {
    ...ARGON2_CONFIG,
    salt,
    raw: true,
  });
}

/**
 * Set up hardware backup recovery
 * @param {Buffer} vaultSeed - The vault's recovery seed
 * @param {Buffer} hardwareKey - The hardware backup key bytes
 * @returns {Object} Encrypted seed and verification data
 */
export async function setupHardwareRecovery(vaultSeed, hardwareKey) {
  // Derive encryption key from hardware key
  const salt = Buffer.from("ocmt-hardware-backup-v1");
  const encryptionKey = await argon2.hash(hardwareKey, {
    ...ARGON2_CONFIG,
    salt,
    raw: true,
  });

  // Encrypt the vault seed with hardware-derived key
  const encrypted = encrypt(encryptionKey, vaultSeed);

  // Create verification hash
  const keyHash = crypto.createHash("sha256").update(hardwareKey).digest("base64");

  return {
    encryptedSeed: {
      nonce: encrypted.nonce.toString("base64"),
      tag: encrypted.tag.toString("base64"),
      ciphertext: encrypted.ciphertext.toString("base64"),
    },
    keyHash,
    createdAt: new Date().toISOString(),
  };
}

/**
 * Recover vault seed using hardware backup key
 * @param {string} backupKey - The formatted backup key
 * @param {Object} encryptedSeed - The encrypted seed data
 * @returns {Promise<Buffer>} Recovered vault seed
 */
export async function recoverWithHardwareKey(backupKey, encryptedSeed) {
  // Remove formatting and decode
  const cleanKey = backupKey.replace(/-/g, "").toUpperCase();
  const keyBytes = base32Decode(cleanKey);

  // Derive encryption key
  const salt = Buffer.from("ocmt-hardware-backup-v1");
  const encryptionKey = await argon2.hash(keyBytes, {
    ...ARGON2_CONFIG,
    salt,
    raw: true,
  });

  // Decrypt the seed
  const nonce = Buffer.from(encryptedSeed.nonce, "base64");
  const tag = Buffer.from(encryptedSeed.tag, "base64");
  const ciphertext = Buffer.from(encryptedSeed.ciphertext, "base64");

  return decrypt(encryptionKey, nonce, tag, ciphertext);
}

// ============================================================
// BASE32 ENCODING (RFC 4648)
// ============================================================

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(buffer) {
  let result = "";
  let bits = 0;
  let value = 0;

  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;

    while (bits >= 5) {
      bits -= 5;
      result += BASE32_ALPHABET[(value >>> bits) & 31];
    }
  }

  if (bits > 0) {
    result += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return result;
}

function base32Decode(str) {
  const cleanStr = str.toUpperCase().replace(/[^A-Z2-7]/g, "");
  const bytes = [];
  let bits = 0;
  let value = 0;

  for (let i = 0; i < cleanStr.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(cleanStr[i]);
    if (idx === -1) {
      throw new Error("Invalid base32 character");
    }

    value = (value << 5) | idx;
    bits += 5;

    while (bits >= 8) {
      bits -= 8;
      bytes.push((value >>> bits) & 255);
    }
  }

  return Buffer.from(bytes);
}

// ============================================================
// RECOVERY SESSION MANAGEMENT
// ============================================================

/**
 * Create a recovery request token
 * Used when initiating social recovery to track the process
 */
export function createRecoveryToken() {
  return crypto.randomBytes(32).toString("hex");
}

/**
 * Hash a recovery token for storage
 */
export function hashRecoveryToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}
