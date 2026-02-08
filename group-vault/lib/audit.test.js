/**
 * Group Vault Audit Log Tests
 *
 * Tests for the group-vault audit logging system that persists to mesh_audit_logs
 * while maintaining an in-memory cache for fast access.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock pg module - factory must not reference variables outside
vi.mock("pg", () => {
  const mockQueryFn = vi.fn().mockResolvedValue({ rows: [], rowCount: 0 });
  const mockEndFn = vi.fn().mockResolvedValue(undefined);

  return {
    default: {
      Pool: class MockPool {
        constructor() {}
        query(...args) {
          return mockQueryFn(...args);
        }
        end() {
          return mockEndFn();
        }
      },
    },
    // Export mocks for test access
    __mockQuery: mockQueryFn,
    __mockEnd: mockEndFn,
  };
});

import { __mockQuery as mockQuery, __mockEnd as mockEnd } from "pg";
// Import after mocking
import audit, { initDb, log, getLogs, getSecretLogs, clearOldLogs, close } from "./audit.js";

describe("group-vault audit", () => {
  const mockUserId = "user-456";

  beforeEach(() => {
    vi.clearAllMocks();
    mockQuery.mockResolvedValue({ rows: [], rowCount: 0 });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("initDb", () => {
    it("should initialize database pool", () => {
      const pool = initDb();
      expect(pool).toBeDefined();
    });

    it("should reuse existing pool on subsequent calls", () => {
      const pool1 = initDb();
      const pool2 = initDb();
      expect(pool1).toBe(pool2);
    });
  });

  describe("log", () => {
    it("should log an event with all fields", async () => {
      initDb();

      const mockGroupId = "group-fields-" + Date.now();

      await log(mockGroupId, {
        action: "vault.unlocked",
        userId: mockUserId,
        secretKey: "api-key-1",
        ipAddress: "192.168.1.1",
        success: true,
      });

      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining("INSERT INTO mesh_audit_logs"),
        expect.arrayContaining([
          "group_vault.unlocked",
          mockUserId,
          "api-key-1",
          mockGroupId,
          expect.any(String), // JSON details
          "192.168.1.1",
          true,
          null,
          "group-vault",
        ]),
      );
    });

    it("should log failed events with error message", async () => {
      initDb();

      const mockGroupId = "group-failed-" + Date.now();

      await log(mockGroupId, {
        action: "vault.unlock_failed",
        userId: mockUserId,
        success: false,
        error: "Invalid password",
      });

      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining("INSERT INTO mesh_audit_logs"),
        expect.arrayContaining([
          "group_vault.unlock_failed",
          mockUserId,
          null,
          mockGroupId,
          expect.any(String),
          null,
          false,
          "Invalid password",
          "group-vault",
        ]),
      );
    });

    it("should store in memory cache", async () => {
      initDb();

      const uniqueGroupId = "group-memory-" + Date.now();

      await log(uniqueGroupId, {
        action: "secret.read",
        userId: mockUserId,
        secretKey: "test-key",
        success: true,
      });

      // Clear mock so we can verify memory access
      mockQuery.mockClear();

      const logs = await getLogs(uniqueGroupId, 1);
      expect(logs).toHaveLength(1);
      expect(logs[0].action).toBe("secret.read");
      // Should not query DB since memory has logs
      expect(mockQuery).not.toHaveBeenCalled();
    });

    it("should handle database errors gracefully", async () => {
      initDb();
      mockQuery.mockRejectedValueOnce(new Error("Connection failed"));

      const mockGroupId = "group-error-" + Date.now();

      // Should not throw
      await expect(
        log(mockGroupId, {
          action: "vault.unlocked",
          userId: mockUserId,
          success: true,
        }),
      ).resolves.not.toThrow();
    });

    it("should map custom event types correctly", async () => {
      initDb();

      const mockGroupId = "group-map-" + Date.now();

      await log(mockGroupId, {
        action: "token.issued",
        userId: mockUserId,
        success: true,
      });

      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining("INSERT INTO mesh_audit_logs"),
        expect.arrayContaining(["group_vault.token_issued"]),
      );
    });

    it("should handle unmapped event types", async () => {
      initDb();

      const mockGroupId = "group-unmapped-" + Date.now();

      await log(mockGroupId, {
        action: "custom.event",
        userId: mockUserId,
        success: true,
      });

      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining("INSERT INTO mesh_audit_logs"),
        expect.arrayContaining(["group_vault.custom_event"]),
      );
    });
  });

  describe("getLogs", () => {
    it("should return logs from memory cache first", async () => {
      initDb();

      const uniqueGroupId = "group-cache-" + Date.now();

      // Add some logs to memory
      await log(uniqueGroupId, {
        action: "secret.created",
        userId: mockUserId,
        secretKey: "key-1",
        success: true,
      });
      await log(uniqueGroupId, {
        action: "secret.updated",
        userId: mockUserId,
        secretKey: "key-2",
        success: true,
      });

      // Clear query mock to ensure we're not hitting DB
      mockQuery.mockClear();

      const logs = await getLogs(uniqueGroupId, 10);

      expect(logs).toHaveLength(2);
      // Should be in reverse order (most recent first)
      expect(logs[0].action).toBe("secret.updated");
      expect(logs[1].action).toBe("secret.created");
      // Should not have queried DB since memory has logs
      expect(mockQuery).not.toHaveBeenCalled();
    });

    it("should fall back to database when memory is empty", async () => {
      initDb();

      // Mock DB response
      mockQuery.mockResolvedValueOnce({
        rows: [
          {
            timestamp: new Date(),
            userId: mockUserId,
            secretKey: "db-key",
            action: "secret.read",
            ipAddress: null,
            success: true,
            error: null,
          },
        ],
      });

      // Use a different group ID to ensure empty memory cache
      const newGroupId = "group-db-fallback-" + Date.now();
      await getLogs(newGroupId, 10);

      expect(mockQuery).toHaveBeenCalledWith(expect.stringContaining("SELECT"), [newGroupId, 10]);
    });

    it("should respect limit parameter", async () => {
      initDb();

      const uniqueGroupId = "group-limit-" + Date.now();

      // Add multiple logs
      for (let i = 0; i < 5; i++) {
        await log(uniqueGroupId, {
          action: `test.action.${i}`,
          userId: mockUserId,
          success: true,
        });
      }

      mockQuery.mockClear();

      const logs = await getLogs(uniqueGroupId, 3);

      expect(logs).toHaveLength(3);
    });
  });

  describe("getSecretLogs", () => {
    it("should return logs for a specific secret from memory", async () => {
      initDb();

      const uniqueGroupId = "group-secret-" + Date.now();
      const targetKey = "specific-key";

      await log(uniqueGroupId, {
        action: "secret.read",
        userId: mockUserId,
        secretKey: targetKey,
        success: true,
      });
      await log(uniqueGroupId, {
        action: "secret.updated",
        userId: mockUserId,
        secretKey: "other-key",
        success: true,
      });
      await log(uniqueGroupId, {
        action: "secret.deleted",
        userId: mockUserId,
        secretKey: targetKey,
        success: true,
      });

      mockQuery.mockClear();

      const logs = await getSecretLogs(uniqueGroupId, targetKey, 10);

      expect(logs).toHaveLength(2);
      expect(logs.every((l) => l.secretKey === targetKey)).toBe(true);
    });

    it("should fall back to database when memory has no matching logs", async () => {
      initDb();

      mockQuery.mockResolvedValueOnce({
        rows: [
          {
            timestamp: new Date(),
            userId: mockUserId,
            secretKey: "db-secret",
            action: "secret.read",
            success: true,
          },
        ],
      });

      const newGroupId = "group-secret-db-" + Date.now();
      await getSecretLogs(newGroupId, "db-secret", 10);

      expect(mockQuery).toHaveBeenCalledWith(expect.stringContaining("target_id = $2"), [
        newGroupId,
        "db-secret",
        10,
      ]);
    });
  });

  describe("clearOldLogs", () => {
    it("should clear logs older than specified time", async () => {
      initDb();

      const uniqueGroupId = "group-clear-" + Date.now();

      // Add some logs
      await log(uniqueGroupId, {
        action: "test.action",
        userId: mockUserId,
        success: true,
      });

      // Clear logs older than 30 days (default)
      clearOldLogs(uniqueGroupId, 30 * 24 * 60 * 60 * 1000);

      // Should not throw
      expect(() => clearOldLogs(uniqueGroupId, 30 * 24 * 60 * 60 * 1000)).not.toThrow();
    });

    it("should handle non-existent group gracefully", () => {
      expect(() => clearOldLogs("non-existent-group", 1000)).not.toThrow();
    });
  });

  describe("close", () => {
    it("should close database connection", async () => {
      initDb();

      await close();

      expect(mockEnd).toHaveBeenCalled();
    });
  });

  describe("Event Type Mapping", () => {
    const eventMappings = [
      ["vault.initialized", "group_vault.created"],
      ["vault.imported", "group_vault.imported"],
      ["vault.exported", "group_vault.exported"],
      ["vault.unlocked", "group_vault.unlocked"],
      ["vault.unlock_failed", "group_vault.unlock_failed"],
      ["vault.locked", "group_vault.locked"],
      ["token.issued", "group_vault.token_issued"],
      ["token.revoked", "group_vault.token_revoked"],
      ["tokens.revoked.user", "group_vault.tokens_revoked_user"],
      ["secret.read", "group_vault.secret_read"],
      ["secret.read.denied", "group_vault.secret_read_denied"],
      ["secret.write.denied", "group_vault.secret_write_denied"],
      ["secret.delete.denied", "group_vault.secret_delete_denied"],
      ["secrets.listed", "group_vault.secrets_listed"],
      ["secret.created", "group_vault.secret_created"],
      ["secret.updated", "group_vault.secret_updated"],
      ["secret.deleted", "group_vault.secret_deleted"],
    ];

    it.each(eventMappings)("should map %s to %s", async (input, expected) => {
      initDb();
      mockQuery.mockClear();

      const uniqueGroupId = "group-mapping-" + Date.now() + Math.random();

      await log(uniqueGroupId, {
        action: input,
        userId: mockUserId,
        success: true,
      });

      expect(mockQuery).toHaveBeenCalledWith(
        expect.any(String),
        expect.arrayContaining([expected]),
      );
    });
  });

  describe("Memory Cache Limits", () => {
    it("should store entries in memory cache", async () => {
      initDb();

      const uniqueGroupId = "group-cache-limit-" + Date.now();

      // Add entries
      for (let i = 0; i < 10; i++) {
        await log(uniqueGroupId, {
          action: `test.action.${i}`,
          userId: mockUserId,
          success: true,
        });
      }

      mockQuery.mockClear();

      const logs = await getLogs(uniqueGroupId, 20);
      expect(logs.length).toBe(10);
      // Should be from memory, not DB
      expect(mockQuery).not.toHaveBeenCalled();
    });
  });
});
