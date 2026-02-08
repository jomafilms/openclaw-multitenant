/**
 * Integration tests for encrypted session storage.
 *
 * Tests the full flow from unlock to encrypted session storage to lock.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  clearSecureSessionStore,
  getSecureSessionStore,
  initSecureSessionStore,
  SecureSessionStore,
} from "./encrypted-store.js";

// ============================================================================
// Test Setup
// ============================================================================

describe("Encrypted Session Integration", () => {
  let testDir: string;
  let store: SecureSessionStore;
  let testKey: Buffer;

  beforeEach(async () => {
    // Create isolated test directory
    testDir = path.join(
      process.cwd(),
      ".test-sessions",
      `test-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`,
    );
    await fs.promises.mkdir(testDir, { recursive: true });

    // Generate test key
    testKey = crypto.randomBytes(32);

    // Clear any existing global store
    clearSecureSessionStore();

    // Initialize store for this test
    store = initSecureSessionStore(testDir);
  });

  afterEach(async () => {
    // Clean up
    clearSecureSessionStore();

    // Remove test directory
    try {
      await fs.promises.rm(testDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  // ============================================================================
  // Core Encryption Flow
  // ============================================================================

  describe("Unlock → Write → Lock → Verify", () => {
    it("should encrypt sessions when unlocked and preserve data", async () => {
      // Unlock the store
      await store.unlock(testKey);
      expect(store.isUnlocked()).toBe(true);

      // Write a session
      const sessionId = "test-session-1";
      const messages = [
        { role: "user" as const, content: "Hello" },
        { role: "assistant" as const, content: "Hi there!" },
      ];
      await store.writeSession(sessionId, { messages });

      // Verify file is encrypted
      const encryptedFile = path.join(testDir, `${sessionId}.jsonl.enc`);
      expect(fs.existsSync(encryptedFile)).toBe(true);

      // Read back while unlocked
      const readback = await store.readSession(sessionId);
      expect(readback.messages).toHaveLength(2);
      expect(readback.messages[0].content).toBe("Hello");
      expect(readback.messages[1].content).toBe("Hi there!");

      // Lock the store
      store.lock();
      expect(store.isUnlocked()).toBe(false);

      // Verify raw file is not readable as plaintext
      const rawContent = await fs.promises.readFile(encryptedFile);
      const isPlaintext = rawContent.includes(Buffer.from("Hello"));
      expect(isPlaintext).toBe(false);

      // Re-unlock and verify data is preserved
      await store.unlock(testKey);
      const afterLock = await store.readSession(sessionId);
      expect(afterLock.messages).toHaveLength(2);
      expect(afterLock.messages[0].content).toBe("Hello");
    });

    it("should fail to read session when locked", async () => {
      // Unlock and write
      await store.unlock(testKey);
      await store.writeSession("test-locked", {
        messages: [{ role: "user" as const, content: "Test" }],
      });
      store.lock();

      // Attempt to read while locked should throw
      await expect(store.readSession("test-locked")).rejects.toThrow();
    });
  });

  // ============================================================================
  // Message Appending
  // ============================================================================

  describe("Message Appending", () => {
    it("should append messages to encrypted sessions", async () => {
      await store.unlock(testKey);

      const sessionId = "append-test";

      // Write initial message
      await store.appendMessage(sessionId, {
        role: "user",
        content: "First message",
      });

      // Append more messages
      await store.appendMessage(sessionId, {
        role: "assistant",
        content: "Response 1",
      });

      await store.appendMessage(sessionId, {
        role: "user",
        content: "Second message",
      });

      // Read back
      const session = await store.readSession(sessionId);
      expect(session.messages).toHaveLength(3);
      expect(session.messages[0].content).toBe("First message");
      expect(session.messages[1].content).toBe("Response 1");
      expect(session.messages[2].content).toBe("Second message");
    });

    it("should handle complex content in messages", async () => {
      await store.unlock(testKey);

      const sessionId = "complex-content";
      const complexContent = [
        { type: "text", text: "Hello" },
        { type: "image", data: "base64data..." },
      ];

      await store.appendMessage(sessionId, {
        role: "user",
        content: complexContent,
      });

      const session = await store.readSession(sessionId);
      expect(session.messages[0].content).toEqual(complexContent);
    });
  });

  // ============================================================================
  // Migration
  // ============================================================================

  describe("Plaintext to Encrypted Migration", () => {
    it("should migrate plaintext sessions to encrypted format", async () => {
      // Create a plaintext session file
      const sessionId = "plaintext-session";
      const plaintextFile = path.join(testDir, `${sessionId}.jsonl`);
      const plaintextContent = [
        JSON.stringify({ type: "session", version: "1.0", id: sessionId }),
        JSON.stringify({
          type: "message",
          message: { role: "user", content: "Plaintext message" },
        }),
      ].join("\n");
      await fs.promises.writeFile(plaintextFile, plaintextContent);

      // Unlock and migrate
      await store.unlock(testKey);
      const result = await store.migrateUnencryptedSessions();

      expect(result.migrated).toBe(1);
      expect(result.failed).toHaveLength(0);

      // Verify encrypted file exists
      const encryptedFile = path.join(testDir, `${sessionId}.jsonl.enc`);
      expect(fs.existsSync(encryptedFile)).toBe(true);

      // Read migrated session
      const session = await store.readSession(sessionId);
      expect(session.messages).toHaveLength(1);
      expect(session.messages[0].content).toBe("Plaintext message");

      // Original plaintext file should be removed
      expect(fs.existsSync(plaintextFile)).toBe(false);
    });

    it("should skip already encrypted sessions during migration", async () => {
      await store.unlock(testKey);

      // Write an encrypted session
      await store.writeSession("already-encrypted", {
        messages: [{ role: "user" as const, content: "Already encrypted" }],
      });

      // Migration should not fail
      const result = await store.migrateUnencryptedSessions();
      expect(result.failed).toHaveLength(0);
    });
  });

  // ============================================================================
  // Session Timeout
  // ============================================================================

  describe("Session Timeout", () => {
    it("should track expiration time", async () => {
      await store.unlock(testKey);

      const expiresAt = store.getExpiresAt();
      expect(expiresAt).not.toBeNull();
      expect(expiresAt!).toBeGreaterThan(Date.now());
    });

    it("should extend session timeout", async () => {
      await store.unlock(testKey);

      const initialExpiry = store.getExpiresAt();
      expect(initialExpiry).not.toBeNull();

      // Wait a moment
      await new Promise((r) => setTimeout(r, 100));

      // Extend
      store.extend();

      const newExpiry = store.getExpiresAt();
      expect(newExpiry).not.toBeNull();
      expect(newExpiry!).toBeGreaterThan(initialExpiry!);
    });

    it("should return null expiry when locked", () => {
      expect(store.getExpiresAt()).toBeNull();
    });
  });

  // ============================================================================
  // Key Validation
  // ============================================================================

  describe("Key Validation", () => {
    it("should reject invalid key lengths", async () => {
      const shortKey = crypto.randomBytes(16);
      await expect(store.unlock(shortKey)).rejects.toThrow("Invalid key length");

      const longKey = crypto.randomBytes(64);
      await expect(store.unlock(longKey)).rejects.toThrow("Invalid key length");
    });

    it("should accept 32-byte keys", async () => {
      const validKey = crypto.randomBytes(32);
      await store.unlock(validKey);
      expect(store.isUnlocked()).toBe(true);
    });
  });

  // ============================================================================
  // Singleton Management
  // ============================================================================

  describe("Singleton Store", () => {
    it("should return same instance from getSecureSessionStore", () => {
      const store1 = getSecureSessionStore(testDir);
      const store2 = getSecureSessionStore();

      expect(store1).toBe(store2);
    });

    it("should clear singleton on clearSecureSessionStore", () => {
      const store1 = getSecureSessionStore(testDir);
      expect(store1).not.toBeNull();

      clearSecureSessionStore();

      // After clear, should need to re-init with dir
      const store2 = getSecureSessionStore();
      expect(store2).toBeNull();
    });
  });

  // ============================================================================
  // Edge Cases
  // ============================================================================

  describe("Edge Cases", () => {
    it("should handle empty sessions", async () => {
      await store.unlock(testKey);

      await store.writeSession("empty-session", { messages: [] });
      const session = await store.readSession("empty-session");
      expect(session.messages).toHaveLength(0);
    });

    it("should handle session not found", async () => {
      await store.unlock(testKey);

      // readSession throws when session not found
      await expect(store.readSession("nonexistent")).rejects.toThrow("Session not found");
    });

    it("should handle unicode content", async () => {
      await store.unlock(testKey);

      const unicodeMessage = "Hello 👋 世界 مرحبا שלום";
      await store.appendMessage("unicode-test", {
        role: "user",
        content: unicodeMessage,
      });

      const session = await store.readSession("unicode-test");
      expect(session.messages[0].content).toBe(unicodeMessage);
    });

    it("should handle very large messages", async () => {
      await store.unlock(testKey);

      const largeContent = "x".repeat(100000);
      await store.appendMessage("large-test", {
        role: "user",
        content: largeContent,
      });

      const session = await store.readSession("large-test");
      expect(session.messages[0].content).toBe(largeContent);
    });
  });
});
