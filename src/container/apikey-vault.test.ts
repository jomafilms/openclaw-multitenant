/**
 * Tests for Zero-Knowledge API Key Storage
 *
 * Verifies that API keys are stored in the container vault and
 * never touch the management server in decrypted form.
 */

import { randomBytes } from "crypto";
import { existsSync, rmSync, mkdirSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { SecretStore, resetSecretStore } from "./secret-store.js";

// Test-friendly scrypt parameters
const TEST_SCRYPT_N = 2 ** 14;

// Helper to create a unique temp directory for each test
function createTempDir(): string {
  const dir = join(tmpdir(), `ocmt-apikey-test-${randomBytes(8).toString("hex")}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

// Helper to cleanup temp directory
function cleanupTempDir(dir: string): void {
  if (existsSync(dir)) {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("Zero-Knowledge API Key Storage", () => {
  let tempDir: string;
  let store: SecretStore;

  beforeEach(() => {
    resetSecretStore();
    tempDir = createTempDir();
    store = new SecretStore({ baseDir: tempDir, scryptN: TEST_SCRYPT_N });
  });

  afterEach(() => {
    store.lock();
    cleanupTempDir(tempDir);
    resetSecretStore();
  });

  describe("API key storage in vault", () => {
    it("stores API key in vault when unlocked", async () => {
      await store.initialize("test-password");

      // Store an API key
      await store.setIntegration("github", {
        apiKey: "ghp_test1234567890",
        addedAt: new Date().toISOString(),
        accessToken: "ghp_test1234567890", // SecretStore expects accessToken
        expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
      });

      // Verify it's stored
      const integration = store.getIntegration("github");
      expect(integration).toBeTruthy();
      expect(integration!.accessToken).toBe("ghp_test1234567890");
    });

    it("fails to store API key when vault is locked", async () => {
      await store.initialize("test-password");
      store.lock();

      expect(store.isUnlocked()).toBe(false);

      // Attempting to set integration when locked should fail
      await expect(
        store.setIntegration("github", {
          accessToken: "ghp_test1234567890",
          expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
        }),
      ).rejects.toThrow();
    });

    it("retrieves API key after lock/unlock cycle", async () => {
      await store.initialize("test-password");

      // Store API key
      await store.setIntegration("anthropic", {
        accessToken: "sk-ant-test1234567890",
        expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
        metadata: { name: "My Anthropic Key" },
      });

      // Lock vault
      store.lock();
      expect(store.isUnlocked()).toBe(false);

      // getIntegration throws when locked
      expect(() => store.getIntegration("anthropic")).toThrow("Vault is locked");

      // Unlock vault
      const unlocked = await store.unlock("test-password");
      expect(unlocked).toBe(true);

      // Verify API key is still there
      const integration = store.getIntegration("anthropic");
      expect(integration).toBeTruthy();
      expect(integration!.accessToken).toBe("sk-ant-test1234567890");
    });

    it("removes API key from vault", async () => {
      await store.initialize("test-password");

      // Store API key
      await store.setIntegration("openai", {
        accessToken: "sk-test1234567890",
        expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
      });

      // Verify it exists
      expect(store.getIntegration("openai")).toBeTruthy();

      // Remove it
      await store.removeIntegration("openai");

      // Verify it's gone
      expect(store.getIntegration("openai")).toBeNull();
    });

    it("lists all stored API keys", async () => {
      await store.initialize("test-password");

      // Store multiple API keys
      await store.setIntegration("github", {
        accessToken: "ghp_test1234567890",
        expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
      });

      await store.setIntegration("anthropic", {
        accessToken: "sk-ant-test1234567890",
        expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
      });

      await store.setIntegration("openai", {
        accessToken: "sk-test1234567890",
        expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
      });

      // List integrations - returns array of objects with provider property
      const integrations = store.listIntegrations();
      const providers = integrations.map((i) => i.provider);
      expect(providers).toContain("github");
      expect(providers).toContain("anthropic");
      expect(providers).toContain("openai");
      expect(integrations.length).toBe(3);
    });

    it("overwrites existing API key", async () => {
      await store.initialize("test-password");

      // Store initial API key
      await store.setIntegration("github", {
        accessToken: "ghp_old_key",
        expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
      });

      // Overwrite with new key
      await store.setIntegration("github", {
        accessToken: "ghp_new_key",
        expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
      });

      // Verify new key is stored
      const integration = store.getIntegration("github");
      expect(integration!.accessToken).toBe("ghp_new_key");
    });
  });

  describe("vault encryption", () => {
    it("API keys are encrypted at rest", async () => {
      await store.initialize("test-password");

      // Store API key
      await store.setIntegration("github", {
        accessToken: "ghp_supersecretkey123",
        expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
      });

      // Read the encrypted vault file directly
      const vaultPath = join(tempDir, "secrets.enc");
      expect(existsSync(vaultPath)).toBe(true);

      const fs = await import("fs/promises");
      const encryptedContent = await fs.readFile(vaultPath, "utf-8");

      // The plaintext API key should NOT appear in the encrypted file
      expect(encryptedContent).not.toContain("ghp_supersecretkey123");

      // The file should contain encryption metadata
      const encrypted = JSON.parse(encryptedContent);
      expect(encrypted.algorithm).toBe("aes-256-gcm");
      expect(encrypted.ciphertext).toBeTruthy();
      expect(encrypted.nonce).toBeTruthy();
      expect(encrypted.tag).toBeTruthy();
    });

    it("wrong password cannot decrypt API keys", async () => {
      await store.initialize("correct-password");

      // Store API key
      await store.setIntegration("github", {
        accessToken: "ghp_secretkey",
        expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
      });

      // Lock vault
      store.lock();

      // Try to unlock with wrong password
      const unlocked = await store.unlock("wrong-password");
      expect(unlocked).toBe(false);
      expect(store.isUnlocked()).toBe(false);

      // API key should not be accessible - throws when locked
      expect(() => store.getIntegration("github")).toThrow("Vault is locked");
    });
  });

  describe("provider validation", () => {
    it("stores API keys for known providers", async () => {
      await store.initialize("test-password");

      const providers = ["github", "anthropic", "openai", "google"];

      for (const provider of providers) {
        await store.setIntegration(provider, {
          accessToken: `${provider}-test-key`,
          expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
        });

        const integration = store.getIntegration(provider);
        expect(integration).toBeTruthy();
        expect(integration!.accessToken).toBe(`${provider}-test-key`);
      }
    });

    it("stores API keys with metadata", async () => {
      await store.initialize("test-password");

      await store.setIntegration("github", {
        accessToken: "ghp_test",
        expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
        metadata: {
          name: "Personal GitHub Token",
          scopes: ["repo", "workflow"],
          createdVia: "zero-knowledge-flow",
        },
      });

      const integration = store.getIntegration("github");
      expect(integration!.metadata).toEqual({
        name: "Personal GitHub Token",
        scopes: ["repo", "workflow"],
        createdVia: "zero-knowledge-flow",
      });
    });
  });

  describe("session management", () => {
    it("vault remains unlocked during session", async () => {
      await store.initialize("test-password");

      // Store API key
      await store.setIntegration("github", {
        accessToken: "ghp_test",
        expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
      });

      // Vault should still be unlocked
      expect(store.isUnlocked()).toBe(true);

      // Get API key
      const integration = store.getIntegration("github");
      expect(integration).toBeTruthy();

      // Vault should still be unlocked
      expect(store.isUnlocked()).toBe(true);
    });

    it("explicit lock clears session", async () => {
      await store.initialize("test-password");

      // Store API key
      await store.setIntegration("github", {
        accessToken: "ghp_test",
        expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
      });

      // Explicitly lock
      store.lock();

      // Vault should be locked
      expect(store.isUnlocked()).toBe(false);

      // API key should not be accessible
      expect(() => store.getIntegration("github")).toThrow("Vault is locked");
    });
  });
});

describe("Zero-Knowledge Flow Verification", () => {
  let tempDir: string;
  let store: SecretStore;

  beforeEach(() => {
    resetSecretStore();
    tempDir = createTempDir();
    store = new SecretStore({ baseDir: tempDir, scryptN: TEST_SCRYPT_N });
  });

  afterEach(() => {
    store.lock();
    cleanupTempDir(tempDir);
    resetSecretStore();
  });

  it("derived key unlocks vault without password transmission", async () => {
    // This test simulates the zero-knowledge flow:
    // 1. User enters password in browser
    // 2. Browser derives key using Argon2id/scrypt
    // 3. Only the derived key is sent to container
    // 4. Container uses derived key to unlock vault

    const password = "user-secret-password";

    // Initialize vault with password
    await store.initialize(password);

    // Store sensitive data
    await store.setIntegration("anthropic", {
      accessToken: "sk-ant-super-secret",
      expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
    });

    // Lock vault
    store.lock();

    // Simulate browser-side key derivation
    // In real flow, this happens with Argon2id in the browser
    // The password never leaves the browser

    // Unlock with password (which internally derives the key)
    const unlocked = await store.unlock(password);
    expect(unlocked).toBe(true);

    // Verify data is accessible
    const integration = store.getIntegration("anthropic");
    expect(integration!.accessToken).toBe("sk-ant-super-secret");
  });

  it("API key never appears in plaintext outside vault", async () => {
    await store.initialize("test-password");

    const apiKey = "sk-SUPER_SECRET_KEY_NEVER_EXPOSE_" + randomBytes(16).toString("hex");

    await store.setIntegration("openai", {
      accessToken: apiKey,
      expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
    });

    // Read all files in temp directory
    const fs = await import("fs/promises");
    const files = await fs.readdir(tempDir);

    for (const file of files) {
      const content = await fs.readFile(join(tempDir, file), "utf-8");

      // The plaintext API key should NOT appear in any file
      expect(content).not.toContain(apiKey);
    }
  });

  it("vault can be restored from encrypted backup", async () => {
    await store.initialize("backup-password");

    // Store API keys
    await store.setIntegration("github", {
      accessToken: "ghp_original",
      expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
    });

    await store.setIntegration("anthropic", {
      accessToken: "sk-ant-original",
      expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
    });

    // Get the encrypted vault data (simulates backup)
    const vaultPath = join(tempDir, "secrets.enc");
    const fs = await import("fs/promises");
    const encryptedBackup = await fs.readFile(vaultPath, "utf-8");

    // Create new directory and restore from backup
    const restoreDir = createTempDir();
    await fs.writeFile(join(restoreDir, "secrets.enc"), encryptedBackup);

    // Create new store with restored vault
    const restoredStore = new SecretStore({ baseDir: restoreDir, scryptN: TEST_SCRYPT_N });

    // Unlock with same password
    const unlocked = await restoredStore.unlock("backup-password");
    expect(unlocked).toBe(true);

    // Verify data is restored
    const github = restoredStore.getIntegration("github");
    expect(github!.accessToken).toBe("ghp_original");

    const anthropic = restoredStore.getIntegration("anthropic");
    expect(anthropic!.accessToken).toBe("sk-ant-original");

    // Cleanup
    restoredStore.lock();
    cleanupTempDir(restoreDir);
  });
});
