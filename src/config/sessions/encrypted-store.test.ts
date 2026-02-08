import crypto from "node:crypto";
import fs from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SecureSessionStore, type Message, type SessionTranscript } from "./encrypted-store.js";

describe("SecureSessionStore", () => {
  let sessionDir: string;
  let store: SecureSessionStore;

  // 32-byte test key
  const testKey = Buffer.alloc(32);
  Buffer.from("test-key-material-for-testing!!").copy(testKey);

  beforeEach(async () => {
    sessionDir = await mkdtemp(path.join(os.tmpdir(), "session-test-"));
    store = new SecureSessionStore(sessionDir);
  });

  afterEach(async () => {
    store.lock();
    await rm(sessionDir, { recursive: true, force: true });
  });

  describe("lock state", () => {
    it("should start locked", () => {
      expect(store.isUnlocked()).toBe(false);
      expect(store.getExpiresAt()).toBe(null);
    });

    it("should unlock with valid 32-byte key", async () => {
      await store.unlock(testKey);
      expect(store.isUnlocked()).toBe(true);
      expect(store.getExpiresAt()).not.toBe(null);
    });

    it("should reject invalid key length (too short)", async () => {
      const shortKey = Buffer.alloc(16, "short");
      await expect(store.unlock(shortKey)).rejects.toThrow("Invalid key length");
    });

    it("should reject invalid key length (too long)", async () => {
      const longKey = Buffer.alloc(64, "long");
      await expect(store.unlock(longKey)).rejects.toThrow("Invalid key length");
    });

    it("should lock and clear key", async () => {
      await store.unlock(testKey);
      expect(store.isUnlocked()).toBe(true);

      store.lock();
      expect(store.isUnlocked()).toBe(false);
      expect(store.getExpiresAt()).toBe(null);
    });

    it("should extend session timeout", async () => {
      await store.unlock(testKey);
      const originalExpiry = store.getExpiresAt();

      // Wait a bit
      await new Promise((r) => setTimeout(r, 50));

      store.extend();
      const newExpiry = store.getExpiresAt();

      expect(newExpiry).toBeGreaterThan(originalExpiry!);
    });
  });

  describe("encryption/decryption", () => {
    it("should encrypt and decrypt sessions", async () => {
      await store.unlock(testKey);

      const session: SessionTranscript = {
        messages: [
          { role: "user", content: "Hello" },
          { role: "assistant", content: "Hi there!" },
        ],
      };

      await store.writeSession("test-session", session);
      const decrypted = await store.readSession("test-session");

      expect(decrypted.messages).toHaveLength(2);
      expect(decrypted.messages[0].content).toBe("Hello");
      expect(decrypted.messages[1].content).toBe("Hi there!");
    });

    it("should create encrypted file with .jsonl.enc extension", async () => {
      await store.unlock(testKey);

      await store.writeSession("test-session", { messages: [] });

      const encryptedPath = path.join(sessionDir, "test-session.jsonl.enc");
      expect(fs.existsSync(encryptedPath)).toBe(true);
    });

    it("should not create plaintext file", async () => {
      await store.unlock(testKey);

      await store.writeSession("test-session", { messages: [] });

      const plaintextPath = path.join(sessionDir, "test-session.jsonl");
      expect(fs.existsSync(plaintextPath)).toBe(false);
    });

    it("should use different nonces for each write", async () => {
      await store.unlock(testKey);

      const session: SessionTranscript = { messages: [] };

      await store.writeSession("test1", session);
      await store.writeSession("test2", session);

      const file1 = await fs.promises.readFile(path.join(sessionDir, "test1.jsonl.enc"));
      const file2 = await fs.promises.readFile(path.join(sessionDir, "test2.jsonl.enc"));

      // First 24 bytes are the nonce - should be different
      const nonce1 = file1.subarray(0, 24);
      const nonce2 = file2.subarray(0, 24);

      expect(nonce1.equals(nonce2)).toBe(false);
    });

    it("should fail to read when locked", async () => {
      await store.unlock(testKey);
      await store.writeSession("test", { messages: [] });
      store.lock();

      await expect(store.readSession("test")).rejects.toThrow("locked");
    });

    it("should fail to write when locked", async () => {
      await expect(store.writeSession("test", { messages: [] })).rejects.toThrow("locked");
    });

    it("should fail with wrong key", async () => {
      await store.unlock(testKey);
      await store.writeSession("test", { messages: [{ role: "user", content: "secret" }] });
      store.lock();

      // Create new store with different key
      const wrongKey = crypto.randomBytes(32);
      await store.unlock(wrongKey);

      // Should fail authentication
      await expect(store.readSession("test")).rejects.toThrow();
    });
  });

  describe("append message", () => {
    it("should append message to existing session", async () => {
      await store.unlock(testKey);

      await store.writeSession("test", {
        messages: [{ role: "user", content: "First" }],
      });

      await store.appendMessage("test", { role: "assistant", content: "Second" });

      const session = await store.readSession("test");
      expect(session.messages).toHaveLength(2);
      expect(session.messages[1].content).toBe("Second");
    });

    it("should create new session if not exists", async () => {
      await store.unlock(testKey);

      await store.appendMessage("new-session", { role: "user", content: "First" });

      const session = await store.readSession("new-session");
      expect(session.messages).toHaveLength(1);
      expect(session.messages[0].content).toBe("First");
    });
  });

  describe("migration", () => {
    it("should migrate plaintext sessions to encrypted", async () => {
      // Create plaintext session
      const plaintextPath = path.join(sessionDir, "legacy.jsonl");
      const plaintextContent = [
        JSON.stringify({ type: "session", version: "1.0", id: "legacy" }),
        JSON.stringify({ type: "message", message: { role: "user", content: "Legacy message" } }),
      ].join("\n");

      await fs.promises.writeFile(plaintextPath, plaintextContent + "\n");

      await store.unlock(testKey);
      const result = await store.migrateUnencryptedSessions();

      expect(result.migrated).toBe(1);
      expect(result.failed).toHaveLength(0);

      // Verify encrypted file exists and plaintext is gone
      expect(fs.existsSync(path.join(sessionDir, "legacy.jsonl.enc"))).toBe(true);
      expect(fs.existsSync(plaintextPath)).toBe(false);

      // Verify can read migrated session
      const session = await store.readSession("legacy");
      expect(session.messages[0].content).toBe("Legacy message");
    });

    it("should read plaintext fallback when encrypted not found", async () => {
      // Create plaintext session
      const plaintextPath = path.join(sessionDir, "fallback.jsonl");
      const plaintextContent = [
        JSON.stringify({ type: "session", version: "1.0", id: "fallback" }),
        JSON.stringify({ type: "message", message: { role: "user", content: "Fallback" } }),
      ].join("\n");

      await fs.promises.writeFile(plaintextPath, plaintextContent + "\n");

      await store.unlock(testKey);

      // Should read plaintext without migrating first
      const session = await store.readSession("fallback");
      expect(session.messages[0].content).toBe("Fallback");
    });

    it("should require unlock before migration", async () => {
      await expect(store.migrateUnencryptedSessions()).rejects.toThrow("unlock");
    });
  });

  describe("session management", () => {
    it("should check session existence", async () => {
      await store.unlock(testKey);

      expect(store.sessionExists("nonexistent")).toBe(false);

      await store.writeSession("exists", { messages: [] });
      expect(store.sessionExists("exists")).toBe(true);
    });

    it("should list all sessions", async () => {
      await store.unlock(testKey);

      await store.writeSession("session1", { messages: [] });
      await store.writeSession("session2", { messages: [] });

      const sessions = await store.listSessions();
      expect(sessions).toContain("session1");
      expect(sessions).toContain("session2");
      expect(sessions).toHaveLength(2);
    });

    it("should delete session", async () => {
      await store.unlock(testKey);

      await store.writeSession("to-delete", { messages: [] });
      expect(store.sessionExists("to-delete")).toBe(true);

      await store.deleteSession("to-delete");
      expect(store.sessionExists("to-delete")).toBe(false);
    });
  });

  describe("atomic writes", () => {
    it("should not leave temp files after successful write", async () => {
      await store.unlock(testKey);

      await store.writeSession("atomic-test", { messages: [] });

      const files = await fs.promises.readdir(sessionDir);
      const tempFiles = files.filter((f) => f.includes(".tmp"));
      expect(tempFiles).toHaveLength(0);
    });

    it("should set restrictive permissions on encrypted files", async () => {
      await store.unlock(testKey);

      await store.writeSession("permissions-test", { messages: [] });

      const encryptedPath = path.join(sessionDir, "permissions-test.jsonl.enc");
      const stats = await fs.promises.stat(encryptedPath);

      // Should be 0o600 (owner read/write only)
      const mode = stats.mode & 0o777;
      expect(mode).toBe(0o600);
    });
  });

  describe("complex content types", () => {
    it("should handle messages with array content", async () => {
      await store.unlock(testKey);

      const session: SessionTranscript = {
        messages: [
          {
            role: "user",
            content: [
              { type: "text", text: "Hello" },
              { type: "image_url", url: "https://example.com/image.png" },
            ],
          } as Message,
        ],
      };

      await store.writeSession("complex", session);
      const decrypted = await store.readSession("complex");

      expect(decrypted.messages[0].content).toHaveLength(2);
      expect((decrypted.messages[0].content as Array<{ type: string }>)[0].type).toBe("text");
    });

    it("should handle unicode content", async () => {
      await store.unlock(testKey);

      const session: SessionTranscript = {
        messages: [{ role: "user", content: "Hello " }],
      };

      await store.writeSession("unicode", session);
      const decrypted = await store.readSession("unicode");

      expect(decrypted.messages[0].content).toBe("Hello ");
    });

    it("should handle large sessions", async () => {
      await store.unlock(testKey);

      const messages: Message[] = [];
      for (let i = 0; i < 100; i++) {
        messages.push({
          role: i % 2 === 0 ? "user" : "assistant",
          content: `Message ${i}: ${"x".repeat(1000)}`,
        });
      }

      const session: SessionTranscript = { messages };

      await store.writeSession("large", session);
      const decrypted = await store.readSession("large");

      expect(decrypted.messages).toHaveLength(100);
      expect(decrypted.messages[50].content).toContain("Message 50");
    });
  });
});
