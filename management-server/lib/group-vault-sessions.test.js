// Tests for group vault session management
import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  generateSessionKey,
  createGroupVaultSession,
  getGroupVaultSession,
  validateGroupSessionKey,
  lockGroupVault,
  isGroupVaultUnlocked,
  getGroupVaultTimeRemaining,
  listActiveGroupVaultSessions,
  GROUP_VAULT_UNLOCK_DURATION_MS,
} from "./group-vault-sessions.js";

describe("group-vault-sessions", () => {
  beforeEach(() => {
    // Lock any existing test sessions
    lockGroupVault("test-group-1");
    lockGroupVault("test-group-2");
  });

  describe("generateSessionKey", () => {
    it("should generate a 64-character hex string", () => {
      const key = generateSessionKey();
      expect(key).toMatch(/^[a-f0-9]{64}$/);
    });

    it("should generate unique keys", () => {
      const key1 = generateSessionKey();
      const key2 = generateSessionKey();
      expect(key1).not.toBe(key2);
    });
  });

  describe("createGroupVaultSession", () => {
    it("should create a session with correct properties", () => {
      const result = createGroupVaultSession("test-group-1", "request-123", ["admin1", "admin2"]);

      expect(result.sessionKey).toMatch(/^[a-f0-9]{64}$/);
      expect(result.expiresAt).toBeInstanceOf(Date);
      expect(result.expiresAt.getTime()).toBeGreaterThan(Date.now());
    });

    it("should store the session for retrieval", () => {
      createGroupVaultSession("test-group-1", "request-123", ["admin1"]);

      const session = getGroupVaultSession("test-group-1");
      expect(session).not.toBeNull();
      expect(session.requestId).toBe("request-123");
      expect(session.approvers).toContain("admin1");
    });
  });

  describe("getGroupVaultSession", () => {
    it("should return null for non-existent session", () => {
      const session = getGroupVaultSession("non-existent-org");
      expect(session).toBeNull();
    });

    it("should return session for valid org", () => {
      createGroupVaultSession("test-group-1", "request-123", ["admin1"]);
      const session = getGroupVaultSession("test-group-1");

      expect(session).not.toBeNull();
      expect(session.sessionKey).toBeDefined();
      expect(session.expiresAt).toBeGreaterThan(Date.now());
    });
  });

  describe("validateGroupSessionKey", () => {
    it("should return true for valid session key", () => {
      const { sessionKey } = createGroupVaultSession("test-group-1", "request-123", ["admin1"]);
      const isValid = validateGroupSessionKey("test-group-1", sessionKey);
      expect(isValid).toBe(true);
    });

    it("should return false for invalid session key", () => {
      createGroupVaultSession("test-group-1", "request-123", ["admin1"]);
      const isValid = validateGroupSessionKey("test-group-1", "invalid-key");
      expect(isValid).toBe(false);
    });

    it("should return false for wrong org", () => {
      const { sessionKey } = createGroupVaultSession("test-group-1", "request-123", ["admin1"]);
      const isValid = validateGroupSessionKey("test-group-2", sessionKey);
      expect(isValid).toBe(false);
    });
  });

  describe("lockGroupVault", () => {
    it("should delete the session", () => {
      createGroupVaultSession("test-group-1", "request-123", ["admin1"]);
      expect(isGroupVaultUnlocked("test-group-1")).toBe(true);

      lockGroupVault("test-group-1");
      expect(isGroupVaultUnlocked("test-group-1")).toBe(false);
    });

    it("should return true if session existed", () => {
      createGroupVaultSession("test-group-1", "request-123", ["admin1"]);
      const result = lockGroupVault("test-group-1");
      expect(result).toBe(true);
    });

    it("should return false if session did not exist", () => {
      const result = lockGroupVault("non-existent-org");
      expect(result).toBe(false);
    });
  });

  describe("isGroupVaultUnlocked", () => {
    it("should return true for unlocked vault", () => {
      createGroupVaultSession("test-group-1", "request-123", ["admin1"]);
      expect(isGroupVaultUnlocked("test-group-1")).toBe(true);
    });

    it("should return false for locked vault", () => {
      expect(isGroupVaultUnlocked("test-group-1")).toBe(false);
    });
  });

  describe("getGroupVaultTimeRemaining", () => {
    it("should return remaining seconds for unlocked vault", () => {
      createGroupVaultSession("test-group-1", "request-123", ["admin1"]);
      const remaining = getGroupVaultTimeRemaining("test-group-1");

      // Should be close to 8 hours (within a few seconds)
      expect(remaining).toBeGreaterThan(GROUP_VAULT_UNLOCK_DURATION_MS / 1000 - 10);
      expect(remaining).toBeLessThanOrEqual(GROUP_VAULT_UNLOCK_DURATION_MS / 1000);
    });

    it("should return 0 for locked vault", () => {
      const remaining = getGroupVaultTimeRemaining("test-group-1");
      expect(remaining).toBe(0);
    });
  });

  describe("listActiveGroupVaultSessions", () => {
    it("should list all active sessions", () => {
      createGroupVaultSession("test-group-1", "request-1", ["admin1"]);
      createGroupVaultSession("test-group-2", "request-2", ["admin2"]);

      const sessions = listActiveGroupVaultSessions();
      expect(sessions.length).toBe(2);

      const org1Session = sessions.find((s) => s.groupId === "test-group-1");
      expect(org1Session).toBeDefined();
      expect(org1Session.requestId).toBe("request-1");
      expect(org1Session.approvers).toContain("admin1");
    });

    it("should not include locked sessions", () => {
      createGroupVaultSession("test-group-1", "request-1", ["admin1"]);
      lockGroupVault("test-group-1");

      const sessions = listActiveGroupVaultSessions();
      const org1Session = sessions.find((s) => s.groupId === "test-group-1");
      expect(org1Session).toBeUndefined();
    });
  });
});
