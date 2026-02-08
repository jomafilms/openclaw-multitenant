// management-server/lib/encryption.test.js
// Tests for encryption key versioning module

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  encrypt,
  decrypt,
  getKeyVersion,
  needsReEncryption,
  reEncrypt,
  generateKey,
  rotateKey,
  validateKey,
  getEncryptionMetadata,
  getCurrentKeyVersion,
  hasKeyVersion,
  clearKeyCache,
} from "./encryption.js";

// Test keys (32 bytes = 64 hex chars)
const TEST_KEY_V0 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TEST_KEY_V1 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
const TEST_KEY_V2 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

// Save original env
let originalEnv;

describe("encryption", () => {
  beforeEach(() => {
    // Save original env
    originalEnv = { ...process.env };
    // Clear key cache before each test
    clearKeyCache();
  });

  afterEach(() => {
    // Restore original env
    process.env = originalEnv;
    clearKeyCache();
  });

  describe("encrypt/decrypt", () => {
    it("encrypts and decrypts with current key", () => {
      process.env.ENCRYPTION_KEY = TEST_KEY_V0;
      process.env.ENCRYPTION_KEY_VERSION = "0";

      const plaintext = "secret data";
      const encrypted = encrypt(plaintext);

      expect(encrypted).toBeTruthy();
      expect(encrypted).not.toEqual(plaintext);
      expect(encrypted.startsWith("v0:")).toBe(true);

      const decrypted = decrypt(encrypted);
      expect(decrypted).toEqual(plaintext);
    });

    it("returns null for null/empty input", () => {
      process.env.ENCRYPTION_KEY = TEST_KEY_V0;

      expect(encrypt(null)).toBeNull();
      expect(encrypt("")).toBeNull();
      expect(decrypt(null)).toBeNull();
      expect(decrypt("")).toBeNull();
    });

    it("encrypts with versioned format", () => {
      process.env.ENCRYPTION_KEY = TEST_KEY_V1;
      process.env.ENCRYPTION_KEY_VERSION = "1";

      const encrypted = encrypt("test");

      // Format: v{version}:{iv}:{authTag}:{encrypted}
      const parts = encrypted.split(":");
      expect(parts.length).toBe(4);
      expect(parts[0]).toBe("v1");
    });

    it("produces different ciphertext for same plaintext (random IV)", () => {
      process.env.ENCRYPTION_KEY = TEST_KEY_V0;

      const encrypted1 = encrypt("same data");
      const encrypted2 = encrypt("same data");

      expect(encrypted1).not.toEqual(encrypted2);

      // But both decrypt to same value
      expect(decrypt(encrypted1)).toEqual("same data");
      expect(decrypt(encrypted2)).toEqual("same data");
    });

    it("handles unicode and special characters", () => {
      process.env.ENCRYPTION_KEY = TEST_KEY_V0;

      const testCases = [
        "Hello, World!",
        "Special chars: !@#$%^&*()",
        "Unicode: \u00e9\u00e8\u00ea\u00eb\u4e2d\u6587\u65e5\u672c\u8a9e",
        "Emoji: Test",
        "Newlines:\nLine 2\nLine 3",
        JSON.stringify({ key: "value", nested: { array: [1, 2, 3] } }),
      ];

      for (const text of testCases) {
        const encrypted = encrypt(text);
        const decrypted = decrypt(encrypted);
        expect(decrypted).toEqual(text);
      }
    });
  });

  describe("legacy format support", () => {
    it("decrypts legacy hex format as v0", async () => {
      process.env.ENCRYPTION_KEY = TEST_KEY_V0;
      process.env.ENCRYPTION_KEY_VERSION = "0";
      clearKeyCache();

      // Simulate legacy format (hex encoded, no version prefix)
      // Create using the old format manually
      const crypto = await import("crypto");
      const key = Buffer.from(TEST_KEY_V0, "hex");
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
      let encrypted = cipher.update("legacy secret", "utf8", "hex");
      encrypted += cipher.final("hex");
      const authTag = cipher.getAuthTag();

      // Legacy format: {iv}:{authTag}:{encrypted}
      const legacyFormat = `${iv.toString("hex")}:${authTag.toString("hex")}:${encrypted}`;

      // Should be able to decrypt
      const decrypted = decrypt(legacyFormat);
      expect(decrypted).toEqual("legacy secret");
    });

    it("identifies legacy format as v0", () => {
      // Legacy format (no v prefix)
      const legacyFormat = "abcd1234:efgh5678:encrypted_data";
      expect(getKeyVersion(legacyFormat)).toBe(0);
    });
  });

  describe("multi-version support", () => {
    it("decrypts data encrypted with old key version", () => {
      // First, encrypt with v0
      process.env.ENCRYPTION_KEY = TEST_KEY_V0;
      process.env.ENCRYPTION_KEY_VERSION = "0";
      clearKeyCache();

      const encrypted = encrypt("secret from v0");
      expect(encrypted.startsWith("v0:")).toBe(true);

      // Now switch to v1 but keep v0 available
      process.env.ENCRYPTION_KEY = TEST_KEY_V1;
      process.env.ENCRYPTION_KEY_VERSION = "1";
      process.env.ENCRYPTION_KEY_V0 = TEST_KEY_V0;
      clearKeyCache();

      // Should still decrypt v0 data
      const decrypted = decrypt(encrypted);
      expect(decrypted).toEqual("secret from v0");

      // New encryptions use v1
      const newEncrypted = encrypt("new secret");
      expect(newEncrypted.startsWith("v1:")).toBe(true);
    });

    it("throws when key version is not available", () => {
      process.env.ENCRYPTION_KEY = TEST_KEY_V1;
      process.env.ENCRYPTION_KEY_VERSION = "1";
      // Intentionally NOT setting ENCRYPTION_KEY_V0

      // v0 encrypted data
      const v0Data = "v0:abc:def:ghi";

      expect(() => decrypt(v0Data)).toThrow("Encryption key version 0 not available");
    });
  });

  describe("getKeyVersion", () => {
    it("extracts version from versioned format", () => {
      expect(getKeyVersion("v0:iv:tag:data")).toBe(0);
      expect(getKeyVersion("v1:iv:tag:data")).toBe(1);
      expect(getKeyVersion("v99:iv:tag:data")).toBe(99);
    });

    it("returns 0 for legacy format", () => {
      expect(getKeyVersion("iv:tag:data")).toBe(0);
    });

    it("returns null for empty input", () => {
      expect(getKeyVersion(null)).toBeNull();
      expect(getKeyVersion("")).toBeNull();
    });
  });

  describe("needsReEncryption", () => {
    it("returns true for old version data", () => {
      process.env.ENCRYPTION_KEY = TEST_KEY_V1;
      process.env.ENCRYPTION_KEY_VERSION = "1";

      expect(needsReEncryption("v0:iv:tag:data")).toBe(true);
      expect(needsReEncryption("iv:tag:data")).toBe(true); // legacy = v0
    });

    it("returns false for current version data", () => {
      process.env.ENCRYPTION_KEY = TEST_KEY_V1;
      process.env.ENCRYPTION_KEY_VERSION = "1";

      expect(needsReEncryption("v1:iv:tag:data")).toBe(false);
    });

    it("returns false for future version (should not happen)", () => {
      process.env.ENCRYPTION_KEY = TEST_KEY_V1;
      process.env.ENCRYPTION_KEY_VERSION = "1";

      expect(needsReEncryption("v2:iv:tag:data")).toBe(false);
    });

    it("returns false for empty input", () => {
      process.env.ENCRYPTION_KEY = TEST_KEY_V0;

      expect(needsReEncryption(null)).toBe(false);
      expect(needsReEncryption("")).toBe(false);
    });
  });

  describe("reEncrypt", () => {
    it("re-encrypts with current key version", () => {
      // Encrypt with v0
      process.env.ENCRYPTION_KEY = TEST_KEY_V0;
      process.env.ENCRYPTION_KEY_VERSION = "0";
      clearKeyCache();

      const originalEncrypted = encrypt("migrate me");

      // Switch to v1
      process.env.ENCRYPTION_KEY = TEST_KEY_V1;
      process.env.ENCRYPTION_KEY_VERSION = "1";
      process.env.ENCRYPTION_KEY_V0 = TEST_KEY_V0;
      clearKeyCache();

      const reEncrypted = reEncrypt(originalEncrypted);

      // Should now be v1
      expect(getKeyVersion(reEncrypted)).toBe(1);

      // Should decrypt correctly
      expect(decrypt(reEncrypted)).toEqual("migrate me");

      // Should no longer need re-encryption
      expect(needsReEncryption(reEncrypted)).toBe(false);
    });
  });

  describe("generateKey", () => {
    it("generates valid 64-char hex key", () => {
      const key = generateKey();

      expect(key).toBeTruthy();
      expect(key.length).toBe(64);
      expect(/^[0-9a-f]+$/.test(key)).toBe(true);
    });

    it("generates unique keys", () => {
      const key1 = generateKey();
      const key2 = generateKey();

      expect(key1).not.toEqual(key2);
    });
  });

  describe("rotateKey", () => {
    it("returns rotation configuration", () => {
      process.env.ENCRYPTION_KEY = TEST_KEY_V0;
      process.env.ENCRYPTION_KEY_VERSION = "0";

      const rotation = rotateKey();

      expect(rotation.newKey).toBeTruthy();
      expect(rotation.newKey.length).toBe(64);
      expect(rotation.newVersion).toBe(1);
      expect(rotation.currentKeyEnvVar).toBe("ENCRYPTION_KEY_V0");
      expect(rotation.instructions).toBeInstanceOf(Array);
      expect(rotation.instructions.length).toBeGreaterThan(0);
    });

    it("increments version correctly", () => {
      process.env.ENCRYPTION_KEY = TEST_KEY_V2;
      process.env.ENCRYPTION_KEY_VERSION = "5";

      const rotation = rotateKey();

      expect(rotation.newVersion).toBe(6);
      expect(rotation.currentKeyEnvVar).toBe("ENCRYPTION_KEY_V5");
    });
  });

  describe("validateKey", () => {
    it("validates correct keys", () => {
      expect(validateKey(TEST_KEY_V0)).toEqual({ valid: true });
      expect(validateKey(generateKey())).toEqual({ valid: true });
    });

    it("rejects missing key", () => {
      expect(validateKey(null).valid).toBe(false);
      expect(validateKey("").valid).toBe(false);
    });

    it("rejects wrong length", () => {
      expect(validateKey("short").valid).toBe(false);
      expect(validateKey(TEST_KEY_V0 + "extra").valid).toBe(false);
    });

    it("rejects non-hex characters", () => {
      const invalidKey = "xyz3456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
      expect(validateKey(invalidKey).valid).toBe(false);
    });
  });

  describe("getEncryptionMetadata", () => {
    it("returns current version and available versions", () => {
      process.env.ENCRYPTION_KEY = TEST_KEY_V2;
      process.env.ENCRYPTION_KEY_VERSION = "2";
      process.env.ENCRYPTION_KEY_V0 = TEST_KEY_V0;
      process.env.ENCRYPTION_KEY_V1 = TEST_KEY_V1;

      const metadata = getEncryptionMetadata();

      expect(metadata.currentVersion).toBe(2);
      expect(metadata.availableVersions).toEqual([0, 1, 2]);
      expect(metadata.keyCount).toBe(3);
    });
  });

  describe("getCurrentKeyVersion", () => {
    it("returns current key version", () => {
      process.env.ENCRYPTION_KEY = TEST_KEY_V0;
      process.env.ENCRYPTION_KEY_VERSION = "3";

      expect(getCurrentKeyVersion()).toBe(3);
    });

    it("defaults to 0 when not specified", () => {
      process.env.ENCRYPTION_KEY = TEST_KEY_V0;
      delete process.env.ENCRYPTION_KEY_VERSION;

      expect(getCurrentKeyVersion()).toBe(0);
    });
  });

  describe("hasKeyVersion", () => {
    it("returns true for available versions", () => {
      process.env.ENCRYPTION_KEY = TEST_KEY_V1;
      process.env.ENCRYPTION_KEY_VERSION = "1";
      process.env.ENCRYPTION_KEY_V0 = TEST_KEY_V0;

      expect(hasKeyVersion(0)).toBe(true);
      expect(hasKeyVersion(1)).toBe(true);
    });

    it("returns false for unavailable versions", () => {
      process.env.ENCRYPTION_KEY = TEST_KEY_V1;
      process.env.ENCRYPTION_KEY_VERSION = "1";

      expect(hasKeyVersion(0)).toBe(false);
      expect(hasKeyVersion(99)).toBe(false);
    });
  });

  describe("error handling", () => {
    it("throws for missing ENCRYPTION_KEY", () => {
      delete process.env.ENCRYPTION_KEY;

      expect(() => encrypt("test")).toThrow("ENCRYPTION_KEY environment variable is required");
    });

    it("throws for invalid key length", () => {
      process.env.ENCRYPTION_KEY = "tooshort";

      expect(() => encrypt("test")).toThrow("must be 64 hex characters");
    });

    it("throws for invalid ciphertext format", () => {
      process.env.ENCRYPTION_KEY = TEST_KEY_V0;

      expect(() => decrypt("invalid")).toThrow("Invalid encrypted data format");
      expect(() => decrypt("a:b")).toThrow("Invalid encrypted data format");
      expect(() => decrypt("v1:a:b")).toThrow("Invalid encrypted data format");
      expect(() => decrypt("v1:a:b:c:d")).toThrow("Invalid encrypted data format");
    });

    it("throws for tampered ciphertext", () => {
      process.env.ENCRYPTION_KEY = TEST_KEY_V0;

      const encrypted = encrypt("test");
      // Tamper with the encrypted data
      const parts = encrypted.split(":");
      parts[3] = "tampered" + parts[3];
      const tampered = parts.join(":");

      expect(() => decrypt(tampered)).toThrow();
    });
  });
});
