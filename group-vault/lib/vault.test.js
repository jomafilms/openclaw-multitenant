// group-vault/lib/vault.test.js
// Tests for group vault encryption library

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  createGroupVault,
  unlockGroupVault,
  updateGroupVault,
  isValidGroupVault,
  createVaultSession,
  getVaultSession,
  deleteVaultSession,
  extendVaultSession,
  vaultSessions,
} from "./vault.js";

describe("GroupVault", () => {
  const password = "super-secure-group-password-123!";

  afterEach(() => {
    vaultSessions.clear();
  });

  describe("createGroupVault", () => {
    it("should create a valid vault structure", async () => {
      const { vault } = await createGroupVault(password);

      expect(vault.version).toBe(1);
      expect(vault.format).toBe("ocmt-group-vault");
      expect(vault.kdf.algorithm).toBe("argon2id");
      expect(vault.encryption.algorithm).toBe("aes-256-gcm");
      expect(vault.ciphertext).toBeTruthy();
      expect(isValidGroupVault(vault)).toBe(true);
    });

    it("should create unique vaults each time", async () => {
      const { vault: vault1 } = await createGroupVault(password);
      const { vault: vault2 } = await createGroupVault(password);

      expect(vault1.kdf.salt).not.toBe(vault2.kdf.salt);
      expect(vault1.ciphertext).not.toBe(vault2.ciphertext);
    });
  });

  describe("unlockGroupVault", () => {
    it("should unlock vault with correct password", async () => {
      const { vault } = await createGroupVault(password);
      const { data, key } = await unlockGroupVault(vault, password);

      expect(data).toBeDefined();
      expect(data.secrets).toEqual({});
      expect(key).toBeDefined();
      expect(key.length).toBe(32);
    });

    it("should fail with wrong password", async () => {
      const { vault } = await createGroupVault(password);

      await expect(unlockGroupVault(vault, "wrong-password")).rejects.toThrow(
        "Invalid password or key",
      );
    });

    it("should unlock with pre-derived key", async () => {
      const { vault } = await createGroupVault(password);
      const { key } = await unlockGroupVault(vault, password);

      const { data } = await unlockGroupVault(vault, null, key);
      expect(data.secrets).toEqual({});
    });
  });

  describe("updateGroupVault", () => {
    it("should update vault data", async () => {
      const { vault } = await createGroupVault(password);
      const { key } = await unlockGroupVault(vault, password);

      const newData = {
        secrets: {
          "api-key": { value: "sk-test-123", metadata: { provider: "openai" } },
        },
        metadata: { version: 1 },
      };

      const updatedVault = updateGroupVault(vault, key, newData);
      expect(updatedVault.ciphertext).not.toBe(vault.ciphertext);

      // Verify we can read the updated data
      const { data } = await unlockGroupVault(updatedVault, password);
      expect(data.secrets["api-key"].value).toBe("sk-test-123");
    });
  });

  describe("isValidGroupVault", () => {
    it("should validate correct vault structure", async () => {
      const { vault } = await createGroupVault(password);
      expect(isValidGroupVault(vault)).toBe(true);
    });

    it("should reject invalid vault", () => {
      expect(isValidGroupVault(null)).toBe(false);
      expect(isValidGroupVault({})).toBe(false);
      expect(isValidGroupVault({ version: 2 })).toBe(false);
      expect(isValidGroupVault({ version: 1, format: "wrong" })).toBe(false);
    });
  });

  describe("vault sessions", () => {
    const groupId = "test-group-123";
    const key = Buffer.alloc(32);

    it("should create and retrieve session", () => {
      createVaultSession(groupId, key);
      const session = getVaultSession(groupId);

      expect(session).toBeDefined();
      expect(session.key).toBe(key);
      expect(session.expiresAt).toBeGreaterThan(Date.now());
    });

    it("should return null for non-existent session", () => {
      const session = getVaultSession("non-existent");
      expect(session).toBeNull();
    });

    it("should delete session", () => {
      createVaultSession(groupId, key);
      deleteVaultSession(groupId);

      const session = getVaultSession(groupId);
      expect(session).toBeNull();
    });

    it("should extend session", () => {
      createVaultSession(groupId, key);
      const session1 = getVaultSession(groupId);

      // Set expiry to a short time in the future (still valid, but short)
      session1.expiresAt = Date.now() + 1000;
      const shortExpiry = session1.expiresAt;

      const extended = extendVaultSession(groupId);
      expect(extended).toBe(true);

      const session2 = getVaultSession(groupId);
      // After extending, expiry should be much longer than the short 1000ms we set
      expect(session2.expiresAt).toBeGreaterThan(shortExpiry);
    });

    it("should not extend expired session", () => {
      createVaultSession(groupId, key);
      const session = vaultSessions.get(groupId);
      session.expiresAt = Date.now() - 1000; // Expired

      const extended = extendVaultSession(groupId);
      expect(extended).toBe(false);
    });
  });
});
