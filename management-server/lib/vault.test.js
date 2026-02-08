import crypto from "crypto";
import { describe, it, expect } from "vitest";
import {
  deriveKey,
  encrypt,
  decrypt,
  generateRecoveryPhrase,
  recoverSeedFromPhrase,
  createVault,
  unlockVault,
  unlockVaultWithKey,
  unlockVaultWithPasswordAndKey,
  unlockVaultWithRecovery,
  updateVault,
  updateVaultWithKey,
  createVaultWithData,
  changePassword,
  isValidVault,
  exportVault,
  canUseBiometrics,
} from "./vault.js";

describe("vault crypto", () => {
  it("should derive consistent key from password", async () => {
    const salt = Buffer.alloc(16, "a");
    const key1 = await deriveKey("test-password", salt);
    const key2 = await deriveKey("test-password", salt);
    expect(key1.equals(key2)).toBe(true);
    expect(key1.length).toBe(32);
  });

  it("should derive different keys for different passwords", async () => {
    const salt = Buffer.alloc(16, "a");
    const key1 = await deriveKey("password-one", salt);
    const key2 = await deriveKey("password-two", salt);
    expect(key1.equals(key2)).toBe(false);
  });

  it("should derive different keys for different salts", async () => {
    const salt1 = Buffer.alloc(16, "a");
    const salt2 = Buffer.alloc(16, "b");
    const key1 = await deriveKey("same-password", salt1);
    const key2 = await deriveKey("same-password", salt2);
    expect(key1.equals(key2)).toBe(false);
  });

  it("should encrypt and decrypt data", async () => {
    const salt = Buffer.alloc(16, "b");
    const key = await deriveKey("test-password", salt);
    const plaintext = Buffer.from("hello world", "utf8");

    const { nonce, tag, ciphertext } = encrypt(key, plaintext);
    const decrypted = decrypt(key, nonce, tag, ciphertext);

    expect(decrypted.toString("utf8")).toBe("hello world");
  });

  it("should fail decryption with wrong key", async () => {
    const salt = Buffer.alloc(16, "c");
    const key1 = await deriveKey("correct-password", salt);
    const key2 = await deriveKey("wrong-password", salt);
    const plaintext = Buffer.from("secret data", "utf8");

    const { nonce, tag, ciphertext } = encrypt(key1, plaintext);

    expect(() => decrypt(key2, nonce, tag, ciphertext)).toThrow();
  });

  it("should generate valid recovery phrase", () => {
    const { phrase, seed } = generateRecoveryPhrase();
    expect(phrase.split(" ")).toHaveLength(12);
    expect(seed).toHaveLength(32);
  });

  it("should generate unique phrases", () => {
    const { phrase: phrase1 } = generateRecoveryPhrase();
    const { phrase: phrase2 } = generateRecoveryPhrase();
    expect(phrase1).not.toBe(phrase2);
  });

  it("should recover seed from phrase", () => {
    const { phrase, seed } = generateRecoveryPhrase();
    const recovered = recoverSeedFromPhrase(phrase);
    expect(recovered.equals(seed)).toBe(true);
  });

  it("should reject invalid recovery phrase", () => {
    expect(() => recoverSeedFromPhrase("invalid phrase here")).toThrow("Invalid recovery phrase");
  });

  it("should create and unlock vault", async () => {
    const { vault, recoveryPhrase } = await createVault("my-password");

    expect(vault.version).toBe(1);
    expect(vault.format).toBe("ocmt-vault");
    expect(vault.kdf.algorithm).toBe("argon2id");
    expect(recoveryPhrase.split(" ")).toHaveLength(12);

    const data = await unlockVault(vault, "my-password");
    expect(data.credentials).toEqual([]);
    expect(data.memory).toEqual({ preferences: {}, facts: [] });
  });

  it("should reject wrong password", async () => {
    const { vault } = await createVault("correct-password");

    await expect(unlockVault(vault, "wrong-password")).rejects.toThrow("Invalid password");
  });

  it("should unlock with recovery phrase", async () => {
    const { vault, recoveryPhrase } = await createVault("my-password");

    const { data } = unlockVaultWithRecovery(vault, recoveryPhrase);
    expect(data.credentials).toEqual([]);
  });

  it("should reject invalid recovery phrase for unlock", async () => {
    const { vault } = await createVault("my-password");
    const { phrase: wrongPhrase } = generateRecoveryPhrase();

    expect(() => unlockVaultWithRecovery(vault, wrongPhrase)).toThrow("Invalid recovery phrase");
  });

  it("should update vault data", async () => {
    const { vault } = await createVault("my-password");

    const newData = {
      credentials: [{ provider: "test", value: "secret" }],
      memory: { preferences: { theme: "dark" }, facts: [] },
      conversations: [],
      files: [],
    };

    const updated = await updateVault(vault, "my-password", newData);
    const unlocked = await unlockVault(updated, "my-password");

    expect(unlocked.credentials).toHaveLength(1);
    expect(unlocked.credentials[0].value).toBe("secret");
    expect(unlocked.memory.preferences.theme).toBe("dark");
  });

  it("should preserve recovery after update", async () => {
    const { vault, recoveryPhrase } = await createVault("my-password");

    const newData = {
      credentials: [{ provider: "updated", value: "new-secret" }],
      memory: {},
      conversations: [],
      files: [],
    };

    const updated = await updateVault(vault, "my-password", newData);
    const { data } = unlockVaultWithRecovery(updated, recoveryPhrase);

    expect(data.credentials[0].value).toBe("new-secret");
  });

  it("should change password", async () => {
    const { vault, recoveryPhrase } = await createVault("old-password");

    const { vault: newVault } = await changePassword(vault, "old-password", "new-password");

    // Old password should not work
    await expect(unlockVault(newVault, "old-password")).rejects.toThrow("Invalid password");

    // New password should work
    const data = await unlockVault(newVault, "new-password");
    expect(data.credentials).toEqual([]);

    // Recovery phrase should still work (same phrase)
    const { data: recoveredData } = unlockVaultWithRecovery(newVault, recoveryPhrase);
    expect(recoveredData.credentials).toEqual([]);
  });

  it("should validate vault structure", async () => {
    const { vault } = await createVault("test-password");
    expect(isValidVault(vault)).toBe(true);

    expect(isValidVault(null)).toBe(false);
    expect(isValidVault({})).toBe(false);
    expect(isValidVault({ version: 2 })).toBe(false);
  });

  it("should handle large data", async () => {
    const { vault } = await createVault("my-password");

    const largeData = {
      credentials: Array(100)
        .fill(null)
        .map((_, i) => ({
          provider: `provider-${i}`,
          value: "x".repeat(1000),
        })),
      memory: { preferences: {}, facts: [] },
      conversations: [],
      files: [],
    };

    const updated = await updateVault(vault, "my-password", largeData);
    const unlocked = await unlockVault(updated, "my-password");

    expect(unlocked.credentials).toHaveLength(100);
  });

  // Additional tests for missing coverage

  it("should unlock vault with password and return key", async () => {
    const { vault } = await createVault("my-password");

    const { data, key } = await unlockVaultWithPasswordAndKey(vault, "my-password");

    expect(data.credentials).toEqual([]);
    expect(key).toBeDefined();
    expect(key.length).toBe(32);
    expect(Buffer.isBuffer(key)).toBe(true);
  });

  it("should reject wrong password with unlockVaultWithPasswordAndKey", async () => {
    const { vault } = await createVault("correct-password");

    await expect(unlockVaultWithPasswordAndKey(vault, "wrong-password")).rejects.toThrow(
      "Invalid password",
    );
  });

  it("should unlock vault with key directly (biometric unlock)", async () => {
    const { vault } = await createVault("my-password");

    // Get the key first
    const { key } = await unlockVaultWithPasswordAndKey(vault, "my-password");

    // Now unlock with just the key
    const data = unlockVaultWithKey(vault, key);

    expect(data.credentials).toEqual([]);
    expect(data.memory).toEqual({ preferences: {}, facts: [] });
  });

  it("should reject wrong key with unlockVaultWithKey", async () => {
    const { vault } = await createVault("my-password");

    const wrongKey = crypto.randomBytes(32);

    expect(() => unlockVaultWithKey(vault, wrongKey)).toThrow("Invalid key");
  });

  it("should update vault with key directly", async () => {
    const { vault } = await createVault("my-password");

    // Get the key
    const { key } = await unlockVaultWithPasswordAndKey(vault, "my-password");

    const newData = {
      credentials: [{ provider: "github", value: "token-123" }],
      memory: { preferences: { theme: "dark" }, facts: [] },
      conversations: [],
      files: [],
    };

    // Update with key
    const updated = updateVaultWithKey(vault, key, newData);

    // Verify with password
    const unlocked = await unlockVault(updated, "my-password");
    expect(unlocked.credentials[0].provider).toBe("github");
    expect(unlocked.memory.preferences.theme).toBe("dark");
  });

  it("should preserve recovery after updateVaultWithKey", async () => {
    const { vault, recoveryPhrase } = await createVault("my-password");

    const { key } = await unlockVaultWithPasswordAndKey(vault, "my-password");

    const newData = {
      credentials: [{ provider: "key-updated", value: "secret-456" }],
      memory: {},
      conversations: [],
      files: [],
    };

    const updated = updateVaultWithKey(vault, key, newData);
    const { data } = unlockVaultWithRecovery(updated, recoveryPhrase);

    expect(data.credentials[0].provider).toBe("key-updated");
  });

  it("should create vault with existing data (recovery reset)", async () => {
    // First create a vault and get data + seed
    const { vault: originalVault, recoveryPhrase } = await createVault("old-password");

    // Add some data
    const existingData = {
      credentials: [{ provider: "existing", value: "preserved-data" }],
      memory: { preferences: {}, facts: ["important fact"] },
      conversations: [{ id: "1", messages: [] }],
      files: [],
    };

    // Get the seed from recovery phrase
    const seed = (await unlockVaultWithRecovery(originalVault, recoveryPhrase)).seed;

    // Create new vault with new password but same data and seed
    const { vault: newVault } = await createVaultWithData("new-password", existingData, seed);

    // New password should work
    const unlocked = await unlockVault(newVault, "new-password");
    expect(unlocked.credentials[0].value).toBe("preserved-data");
    expect(unlocked.memory.facts[0]).toBe("important fact");

    // Recovery phrase should still work
    const { data: recoveredData } = unlockVaultWithRecovery(newVault, recoveryPhrase);
    expect(recoveredData.credentials[0].value).toBe("preserved-data");
  });

  it("should export vault as formatted JSON", async () => {
    const { vault } = await createVault("export-test");

    const exported = exportVault(vault);

    expect(typeof exported).toBe("string");
    expect(exported).toContain('"version": 1');
    expect(exported).toContain('"format": "ocmt-vault"');

    // Should be valid JSON
    const parsed = JSON.parse(exported);
    expect(parsed.version).toBe(1);
    expect(parsed.format).toBe("ocmt-vault");
  });

  it("should allow biometrics when password was entered recently", () => {
    const now = new Date();
    const lastPasswordAt = now.toISOString();

    expect(canUseBiometrics(lastPasswordAt)).toBe(true);
  });

  it("should allow biometrics within 7 days by default", () => {
    const sixDaysAgo = new Date();
    sixDaysAgo.setDate(sixDaysAgo.getDate() - 6);

    expect(canUseBiometrics(sixDaysAgo.toISOString())).toBe(true);
  });

  it("should deny biometrics after 7 days", () => {
    const eightDaysAgo = new Date();
    eightDaysAgo.setDate(eightDaysAgo.getDate() - 8);

    expect(canUseBiometrics(eightDaysAgo.toISOString())).toBe(false);
  });

  it("should use custom maxAgeDays for biometrics", () => {
    const threeDaysAgo = new Date();
    threeDaysAgo.setDate(threeDaysAgo.getDate() - 3);

    // With 2 day limit, should fail
    expect(canUseBiometrics(threeDaysAgo.toISOString(), 2)).toBe(false);

    // With 5 day limit, should pass
    expect(canUseBiometrics(threeDaysAgo.toISOString(), 5)).toBe(true);
  });

  it("should deny biometrics when no lastPasswordAt", () => {
    expect(canUseBiometrics(null)).toBe(false);
    expect(canUseBiometrics(undefined)).toBe(false);
  });

  it("should fail decryption with tampered ciphertext", async () => {
    const { vault } = await createVault("tamper-test");

    // Tamper with ciphertext
    const originalCiphertext = Buffer.from(vault.ciphertext, "base64");
    originalCiphertext[0] ^= 0xff;
    vault.ciphertext = originalCiphertext.toString("base64");

    await expect(unlockVault(vault, "tamper-test")).rejects.toThrow();
  });

  it("should fail decryption with tampered tag", async () => {
    const { vault } = await createVault("tag-test");

    // Tamper with tag
    const originalTag = Buffer.from(vault.encryption.tag, "base64");
    originalTag[0] ^= 0xff;
    vault.encryption.tag = originalTag.toString("base64");

    await expect(unlockVault(vault, "tag-test")).rejects.toThrow();
  });

  it("should produce different ciphertext for same plaintext", async () => {
    const { vault: vault1 } = await createVault("same-password");
    const { vault: vault2 } = await createVault("same-password");

    // Different nonce means different ciphertext
    expect(vault1.ciphertext).not.toBe(vault2.ciphertext);
    expect(vault1.encryption.nonce).not.toBe(vault2.encryption.nonce);
  });

  it("should handle unicode in vault data", async () => {
    const { vault } = await createVault("unicode-test");

    const unicodeData = {
      credentials: [{ provider: "unicode-provider", value: "token-\u4e2d\u6587-\ud83d\udd10" }],
      memory: { preferences: { language: "\u4e2d\u6587" }, facts: ["\u4e16\u754c"] },
      conversations: [],
      files: [],
    };

    const updated = await updateVault(vault, "unicode-test", unicodeData);
    const unlocked = await unlockVault(updated, "unicode-test");

    expect(unlocked.credentials[0].value).toBe("token-\u4e2d\u6587-\ud83d\udd10");
    expect(unlocked.memory.preferences.language).toBe("\u4e2d\u6587");
  });

  it("should handle empty password", async () => {
    const { vault } = await createVault("");
    const data = await unlockVault(vault, "");
    expect(data.credentials).toEqual([]);
  });

  it("should handle very long password", async () => {
    const longPassword = "x".repeat(10000);
    const { vault } = await createVault(longPassword);
    const data = await unlockVault(vault, longPassword);
    expect(data.credentials).toEqual([]);
  });

  it("should update vault timestamp on update", async () => {
    const { vault } = await createVault("timestamp-test");
    const originalUpdated = vault.updated;

    // Wait a tiny bit to ensure timestamp difference
    await new Promise((r) => setTimeout(r, 10));

    const newData = {
      credentials: [{ provider: "test", value: "value" }],
      memory: {},
      conversations: [],
      files: [],
    };

    const updated = await updateVault(vault, "timestamp-test", newData);

    expect(updated.updated).not.toBe(originalUpdated);
    expect(new Date(updated.updated).getTime()).toBeGreaterThan(
      new Date(originalUpdated).getTime(),
    );
  });
});
