/**
 * Mesh Audit Log Tests
 *
 * Tests for the persistent mesh security audit logging system.
 * Verifies:
 * - Audit log persistence to database
 * - Query filtering and pagination
 * - User and group audit log retrieval
 * - Security summary generation
 * - Retention policy (cleanup)
 * - Compliance export
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock the db module before importing meshAuditLogs
vi.mock("../db/index.js", async (importOriginal) => {
  const mockQueryFn = vi.fn();

  return {
    query: mockQueryFn,
    meshAuditLogs: {
      log: vi.fn(),
      logBatch: vi.fn(),
      query: vi.fn(),
      getRecent: vi.fn(),
      getForUser: vi.fn(),
      getForGroup: vi.fn(),
      getFailedAuthAttempts: vi.fn(),
      getSecuritySummary: vi.fn(),
      cleanup: vi.fn(),
      exportForCompliance: vi.fn(),
    },
    MESH_AUDIT_EVENTS: {
      // Capability events
      CAPABILITY_ISSUED: "capability.issued",
      CAPABILITY_USED: "capability.used",
      CAPABILITY_REVOKED: "capability.revoked",
      CAPABILITY_EXPIRED: "capability.expired",
      CAPABILITY_DENIED: "capability.denied",

      // Vault events
      VAULT_UNLOCKED: "vault.unlocked",
      VAULT_LOCKED: "vault.locked",
      VAULT_UNLOCK_FAILED: "vault.unlock_failed",
      VAULT_CREATED: "vault.created",
      VAULT_PASSWORD_CHANGED: "vault.password_changed",
      VAULT_RECOVERED: "vault.recovered",

      // Org vault events
      ORG_VAULT_UNLOCKED: "org_vault.unlocked",
      ORG_VAULT_LOCKED: "org_vault.locked",
      ORG_VAULT_UNLOCK_REQUESTED: "org_vault.unlock_requested",
      ORG_VAULT_UNLOCK_APPROVED: "org_vault.unlock_approved",
      ORG_VAULT_THRESHOLD_MET: "org_vault.threshold_met",
      ORG_VAULT_TOKEN_ISSUED: "org_vault.token_issued",
      ORG_VAULT_TOKEN_REVOKED: "org_vault.token_revoked",

      // Sharing events
      SHARE_GRANTED: "share.granted",
      SHARE_REVOKED: "share.revoked",
      SHARE_REQUESTED: "share.requested",
      SHARE_APPROVED: "share.approved",
      SHARE_DENIED: "share.denied",
      SHARE_USED: "share.used",

      // Authentication events
      AUTH_LOGIN: "auth.login",
      AUTH_LOGOUT: "auth.logout",
      AUTH_FAILED: "auth.failed",
      AUTH_MFA_SUCCESS: "auth.mfa_success",
      AUTH_MFA_FAILED: "auth.mfa_failed",
      AUTH_TOKEN_REFRESHED: "auth.token_refreshed",

      // Relay/mesh events
      RELAY_MESSAGE_FORWARDED: "relay.message_forwarded",
      RELAY_MESSAGE_DENIED: "relay.message_denied",
      RELAY_REVOCATION_SUBMITTED: "relay.revocation_submitted",

      // Integration events
      INTEGRATION_CONNECTED: "integration.connected",
      INTEGRATION_DISCONNECTED: "integration.disconnected",
      INTEGRATION_TOKEN_REFRESHED: "integration.token_refreshed",
      INTEGRATION_ACCESS_DENIED: "integration.access_denied",
    },
  };
});

import { meshAuditLogs, MESH_AUDIT_EVENTS } from "../db/index.js";

describe("MESH_AUDIT_EVENTS", () => {
  it("should have all capability event types", () => {
    expect(MESH_AUDIT_EVENTS.CAPABILITY_ISSUED).toBe("capability.issued");
    expect(MESH_AUDIT_EVENTS.CAPABILITY_USED).toBe("capability.used");
    expect(MESH_AUDIT_EVENTS.CAPABILITY_REVOKED).toBe("capability.revoked");
    expect(MESH_AUDIT_EVENTS.CAPABILITY_EXPIRED).toBe("capability.expired");
    expect(MESH_AUDIT_EVENTS.CAPABILITY_DENIED).toBe("capability.denied");
  });

  it("should have all vault event types", () => {
    expect(MESH_AUDIT_EVENTS.VAULT_UNLOCKED).toBe("vault.unlocked");
    expect(MESH_AUDIT_EVENTS.VAULT_LOCKED).toBe("vault.locked");
    expect(MESH_AUDIT_EVENTS.VAULT_UNLOCK_FAILED).toBe("vault.unlock_failed");
    expect(MESH_AUDIT_EVENTS.VAULT_CREATED).toBe("vault.created");
    expect(MESH_AUDIT_EVENTS.VAULT_PASSWORD_CHANGED).toBe("vault.password_changed");
    expect(MESH_AUDIT_EVENTS.VAULT_RECOVERED).toBe("vault.recovered");
  });

  it("should have all org vault event types", () => {
    expect(MESH_AUDIT_EVENTS.ORG_VAULT_UNLOCKED).toBe("org_vault.unlocked");
    expect(MESH_AUDIT_EVENTS.ORG_VAULT_LOCKED).toBe("org_vault.locked");
    expect(MESH_AUDIT_EVENTS.ORG_VAULT_UNLOCK_REQUESTED).toBe("org_vault.unlock_requested");
    expect(MESH_AUDIT_EVENTS.ORG_VAULT_UNLOCK_APPROVED).toBe("org_vault.unlock_approved");
    expect(MESH_AUDIT_EVENTS.ORG_VAULT_THRESHOLD_MET).toBe("org_vault.threshold_met");
    expect(MESH_AUDIT_EVENTS.ORG_VAULT_TOKEN_ISSUED).toBe("org_vault.token_issued");
    expect(MESH_AUDIT_EVENTS.ORG_VAULT_TOKEN_REVOKED).toBe("org_vault.token_revoked");
  });

  it("should have all sharing event types", () => {
    expect(MESH_AUDIT_EVENTS.SHARE_GRANTED).toBe("share.granted");
    expect(MESH_AUDIT_EVENTS.SHARE_REVOKED).toBe("share.revoked");
    expect(MESH_AUDIT_EVENTS.SHARE_REQUESTED).toBe("share.requested");
    expect(MESH_AUDIT_EVENTS.SHARE_APPROVED).toBe("share.approved");
    expect(MESH_AUDIT_EVENTS.SHARE_DENIED).toBe("share.denied");
    expect(MESH_AUDIT_EVENTS.SHARE_USED).toBe("share.used");
  });

  it("should have all authentication event types", () => {
    expect(MESH_AUDIT_EVENTS.AUTH_LOGIN).toBe("auth.login");
    expect(MESH_AUDIT_EVENTS.AUTH_LOGOUT).toBe("auth.logout");
    expect(MESH_AUDIT_EVENTS.AUTH_FAILED).toBe("auth.failed");
    expect(MESH_AUDIT_EVENTS.AUTH_MFA_SUCCESS).toBe("auth.mfa_success");
    expect(MESH_AUDIT_EVENTS.AUTH_MFA_FAILED).toBe("auth.mfa_failed");
    expect(MESH_AUDIT_EVENTS.AUTH_TOKEN_REFRESHED).toBe("auth.token_refreshed");
  });

  it("should have all relay event types", () => {
    expect(MESH_AUDIT_EVENTS.RELAY_MESSAGE_FORWARDED).toBe("relay.message_forwarded");
    expect(MESH_AUDIT_EVENTS.RELAY_MESSAGE_DENIED).toBe("relay.message_denied");
    expect(MESH_AUDIT_EVENTS.RELAY_REVOCATION_SUBMITTED).toBe("relay.revocation_submitted");
  });

  it("should have all integration event types", () => {
    expect(MESH_AUDIT_EVENTS.INTEGRATION_CONNECTED).toBe("integration.connected");
    expect(MESH_AUDIT_EVENTS.INTEGRATION_DISCONNECTED).toBe("integration.disconnected");
    expect(MESH_AUDIT_EVENTS.INTEGRATION_TOKEN_REFRESHED).toBe("integration.token_refreshed");
    expect(MESH_AUDIT_EVENTS.INTEGRATION_ACCESS_DENIED).toBe("integration.access_denied");
  });
});

describe("meshAuditLogs", () => {
  const mockUserId = "user-123";
  const mockGroupId = "org-456";
  const mockTargetId = "target-789";

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("log", () => {
    it("should log an event with all fields", async () => {
      meshAuditLogs.log.mockResolvedValue(undefined);

      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.VAULT_UNLOCKED,
        actorId: mockUserId,
        targetId: mockTargetId,
        groupId: mockGroupId,
        details: { method: "password" },
        ipAddress: "192.168.1.1",
        success: true,
        source: "management-server",
      });

      expect(meshAuditLogs.log).toHaveBeenCalledWith({
        eventType: "vault.unlocked",
        actorId: mockUserId,
        targetId: mockTargetId,
        groupId: mockGroupId,
        details: { method: "password" },
        ipAddress: "192.168.1.1",
        success: true,
        source: "management-server",
      });
    });

    it("should log failed events with error message", async () => {
      meshAuditLogs.log.mockResolvedValue(undefined);

      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
        actorId: mockUserId,
        ipAddress: "10.0.0.1",
        success: false,
        errorMessage: "Invalid password",
      });

      expect(meshAuditLogs.log).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: "auth.failed",
          success: false,
          errorMessage: "Invalid password",
        }),
      );
    });

    it("should handle logging without optional fields", async () => {
      meshAuditLogs.log.mockResolvedValue(undefined);

      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.CAPABILITY_ISSUED,
      });

      expect(meshAuditLogs.log).toHaveBeenCalledWith({
        eventType: "capability.issued",
      });
    });
  });

  describe("logBatch", () => {
    it("should log multiple events in a batch", async () => {
      meshAuditLogs.logBatch.mockResolvedValue(undefined);

      const events = [
        {
          eventType: MESH_AUDIT_EVENTS.SHARE_GRANTED,
          actorId: "user-1",
          targetId: "user-2",
          success: true,
        },
        {
          eventType: MESH_AUDIT_EVENTS.SHARE_GRANTED,
          actorId: "user-1",
          targetId: "user-3",
          success: true,
        },
      ];

      await meshAuditLogs.logBatch(events);

      expect(meshAuditLogs.logBatch).toHaveBeenCalledWith(events);
    });

    it("should handle empty batch", async () => {
      meshAuditLogs.logBatch.mockResolvedValue(undefined);

      await meshAuditLogs.logBatch([]);

      expect(meshAuditLogs.logBatch).toHaveBeenCalledWith([]);
    });
  });

  describe("query", () => {
    it("should query logs with filters", async () => {
      const mockLogs = [
        {
          id: 1,
          event_type: "vault.unlocked",
          actor_id: mockUserId,
          timestamp: new Date(),
          success: true,
        },
      ];

      meshAuditLogs.query.mockResolvedValue({
        logs: mockLogs,
        total: 1,
        limit: 100,
        offset: 0,
      });

      const result = await meshAuditLogs.query({
        groupId: mockGroupId,
        actorId: mockUserId,
        eventType: "vault.*",
        successOnly: true,
        limit: 100,
        offset: 0,
      });

      expect(result.logs).toHaveLength(1);
      expect(result.total).toBe(1);
      expect(meshAuditLogs.query).toHaveBeenCalledWith(
        expect.objectContaining({
          groupId: mockGroupId,
          actorId: mockUserId,
          eventType: "vault.*",
          successOnly: true,
        }),
      );
    });

    it("should support time range filtering", async () => {
      const startTime = new Date("2025-01-01");
      const endTime = new Date("2025-01-31");

      meshAuditLogs.query.mockResolvedValue({
        logs: [],
        total: 0,
        limit: 100,
        offset: 0,
      });

      await meshAuditLogs.query({
        startTime,
        endTime,
      });

      expect(meshAuditLogs.query).toHaveBeenCalledWith(
        expect.objectContaining({
          startTime,
          endTime,
        }),
      );
    });

    it("should support failures-only filtering", async () => {
      meshAuditLogs.query.mockResolvedValue({
        logs: [],
        total: 0,
        limit: 100,
        offset: 0,
      });

      await meshAuditLogs.query({
        failuresOnly: true,
      });

      expect(meshAuditLogs.query).toHaveBeenCalledWith(
        expect.objectContaining({
          failuresOnly: true,
        }),
      );
    });

    it("should support pagination", async () => {
      meshAuditLogs.query.mockResolvedValue({
        logs: [],
        total: 500,
        limit: 50,
        offset: 100,
      });

      const result = await meshAuditLogs.query({
        limit: 50,
        offset: 100,
      });

      expect(result.limit).toBe(50);
      expect(result.offset).toBe(100);
      expect(result.total).toBe(500);
    });
  });

  describe("getRecent", () => {
    it("should return recent audit logs", async () => {
      const mockLogs = [
        { id: 3, event_type: "auth.login", timestamp: new Date() },
        { id: 2, event_type: "vault.unlocked", timestamp: new Date() },
        { id: 1, event_type: "share.granted", timestamp: new Date() },
      ];

      meshAuditLogs.getRecent.mockResolvedValue(mockLogs);

      const result = await meshAuditLogs.getRecent(50);

      expect(result).toHaveLength(3);
      expect(meshAuditLogs.getRecent).toHaveBeenCalledWith(50);
    });

    it("should use default limit if not specified", async () => {
      meshAuditLogs.getRecent.mockResolvedValue([]);

      await meshAuditLogs.getRecent();

      expect(meshAuditLogs.getRecent).toHaveBeenCalledWith();
    });
  });

  describe("getForUser", () => {
    it("should return audit logs for a specific user", async () => {
      const mockLogs = [
        { id: 1, event_type: "auth.login", actor_id: mockUserId },
        { id: 2, event_type: "vault.unlocked", actor_id: mockUserId },
        { id: 3, event_type: "share.granted", target_id: mockUserId },
      ];

      meshAuditLogs.getForUser.mockResolvedValue(mockLogs);

      const result = await meshAuditLogs.getForUser(mockUserId, 100);

      expect(result).toHaveLength(3);
      expect(meshAuditLogs.getForUser).toHaveBeenCalledWith(mockUserId, 100);
    });
  });

  describe("getForGroup", () => {
    it("should return audit logs for a group", async () => {
      const mockLogs = [
        { id: 1, event_type: "org_vault.unlocked", group_id: mockGroupId },
        { id: 2, event_type: "share.granted", group_id: mockGroupId },
      ];

      meshAuditLogs.getForGroup.mockResolvedValue(mockLogs);

      const result = await meshAuditLogs.getForGroup(mockGroupId, 100);

      expect(result).toHaveLength(2);
      expect(meshAuditLogs.getForGroup).toHaveBeenCalledWith(mockGroupId, 100);
    });
  });

  describe("getFailedAuthAttempts", () => {
    it("should return failed auth attempts for a user", async () => {
      const mockFailures = [
        {
          id: 1,
          event_type: "auth.failed",
          actor_id: mockUserId,
          success: false,
          error_message: "Invalid password",
        },
        {
          id: 2,
          event_type: "auth.mfa_failed",
          actor_id: mockUserId,
          success: false,
          error_message: "Invalid MFA code",
        },
      ];

      meshAuditLogs.getFailedAuthAttempts.mockResolvedValue(mockFailures);

      const result = await meshAuditLogs.getFailedAuthAttempts(mockUserId, 24);

      expect(result).toHaveLength(2);
      expect(result[0].success).toBe(false);
      expect(meshAuditLogs.getFailedAuthAttempts).toHaveBeenCalledWith(mockUserId, 24);
    });

    it("should use default time window if not specified", async () => {
      meshAuditLogs.getFailedAuthAttempts.mockResolvedValue([]);

      await meshAuditLogs.getFailedAuthAttempts(mockUserId);

      expect(meshAuditLogs.getFailedAuthAttempts).toHaveBeenCalledWith(mockUserId);
    });
  });

  describe("getSecuritySummary", () => {
    it("should return security event summary for a group", async () => {
      const mockSummary = {
        totalEvents: 150,
        successfulEvents: 140,
        failedEvents: 10,
        byEventType: {
          "vault.unlocked": { success: 50, failed: 2 },
          "auth.login": { success: 80, failed: 5 },
          "share.granted": { success: 10, failed: 3 },
        },
      };

      meshAuditLogs.getSecuritySummary.mockResolvedValue(mockSummary);

      const result = await meshAuditLogs.getSecuritySummary(mockGroupId, 7);

      expect(result.totalEvents).toBe(150);
      expect(result.successfulEvents).toBe(140);
      expect(result.failedEvents).toBe(10);
      expect(result.byEventType["vault.unlocked"].success).toBe(50);
      expect(meshAuditLogs.getSecuritySummary).toHaveBeenCalledWith(mockGroupId, 7);
    });

    it("should use default days if not specified", async () => {
      meshAuditLogs.getSecuritySummary.mockResolvedValue({
        totalEvents: 0,
        successfulEvents: 0,
        failedEvents: 0,
        byEventType: {},
      });

      await meshAuditLogs.getSecuritySummary(mockGroupId);

      expect(meshAuditLogs.getSecuritySummary).toHaveBeenCalledWith(mockGroupId);
    });
  });

  describe("cleanup", () => {
    it("should delete old audit logs based on retention policy", async () => {
      meshAuditLogs.cleanup.mockResolvedValue(1500);

      const deletedCount = await meshAuditLogs.cleanup(365);

      expect(deletedCount).toBe(1500);
      expect(meshAuditLogs.cleanup).toHaveBeenCalledWith(365);
    });

    it("should use default retention period if not specified", async () => {
      meshAuditLogs.cleanup.mockResolvedValue(0);

      await meshAuditLogs.cleanup();

      expect(meshAuditLogs.cleanup).toHaveBeenCalledWith();
    });
  });

  describe("exportForCompliance", () => {
    it("should export audit logs for compliance", async () => {
      const startTime = new Date("2025-01-01");
      const endTime = new Date("2025-03-31");
      const mockExport = [
        {
          id: 1,
          timestamp: new Date("2025-01-15"),
          event_type: "vault.unlocked",
          actor_id: mockUserId,
          group_id: mockGroupId,
          success: true,
        },
        {
          id: 2,
          timestamp: new Date("2025-02-20"),
          event_type: "share.granted",
          actor_id: mockUserId,
          group_id: mockGroupId,
          success: true,
        },
      ];

      meshAuditLogs.exportForCompliance.mockResolvedValue(mockExport);

      const result = await meshAuditLogs.exportForCompliance({
        groupId: mockGroupId,
        startTime,
        endTime,
      });

      expect(result).toHaveLength(2);
      expect(meshAuditLogs.exportForCompliance).toHaveBeenCalledWith({
        groupId: mockGroupId,
        startTime,
        endTime,
      });
    });

    it("should export without org filter", async () => {
      const startTime = new Date("2025-01-01");
      const endTime = new Date("2025-01-31");

      meshAuditLogs.exportForCompliance.mockResolvedValue([]);

      await meshAuditLogs.exportForCompliance({
        startTime,
        endTime,
      });

      expect(meshAuditLogs.exportForCompliance).toHaveBeenCalledWith({
        startTime,
        endTime,
      });
    });
  });
});

describe("Audit Log Event Type Categories", () => {
  it("should categorize capability events correctly", () => {
    const capabilityEvents = Object.entries(MESH_AUDIT_EVENTS)
      .filter(([key]) => key.startsWith("CAPABILITY_"))
      .map(([, value]) => value);

    expect(capabilityEvents).toContain("capability.issued");
    expect(capabilityEvents).toContain("capability.used");
    expect(capabilityEvents).toContain("capability.revoked");
    expect(capabilityEvents).toContain("capability.expired");
    expect(capabilityEvents).toContain("capability.denied");
    expect(capabilityEvents).toHaveLength(5);
  });

  it("should categorize vault events correctly", () => {
    const vaultEvents = Object.entries(MESH_AUDIT_EVENTS)
      .filter(([key]) => key.startsWith("VAULT_"))
      .map(([, value]) => value);

    expect(vaultEvents).toContain("vault.unlocked");
    expect(vaultEvents).toContain("vault.locked");
    expect(vaultEvents).toContain("vault.unlock_failed");
    expect(vaultEvents).toContain("vault.created");
    expect(vaultEvents).toContain("vault.password_changed");
    expect(vaultEvents).toContain("vault.recovered");
    expect(vaultEvents).toHaveLength(6);
  });

  it("should categorize org vault events correctly", () => {
    const orgVaultEvents = Object.entries(MESH_AUDIT_EVENTS)
      .filter(([key]) => key.startsWith("ORG_VAULT_"))
      .map(([, value]) => value);

    expect(orgVaultEvents).toContain("org_vault.unlocked");
    expect(orgVaultEvents).toContain("org_vault.locked");
    expect(orgVaultEvents).toContain("org_vault.unlock_requested");
    expect(orgVaultEvents).toContain("org_vault.unlock_approved");
    expect(orgVaultEvents).toContain("org_vault.threshold_met");
    expect(orgVaultEvents).toContain("org_vault.token_issued");
    expect(orgVaultEvents).toContain("org_vault.token_revoked");
    expect(orgVaultEvents).toHaveLength(7);
  });

  it("should categorize sharing events correctly", () => {
    const sharingEvents = Object.entries(MESH_AUDIT_EVENTS)
      .filter(([key]) => key.startsWith("SHARE_"))
      .map(([, value]) => value);

    expect(sharingEvents).toContain("share.granted");
    expect(sharingEvents).toContain("share.revoked");
    expect(sharingEvents).toContain("share.requested");
    expect(sharingEvents).toContain("share.approved");
    expect(sharingEvents).toContain("share.denied");
    expect(sharingEvents).toContain("share.used");
    expect(sharingEvents).toHaveLength(6);
  });

  it("should categorize auth events correctly", () => {
    const authEvents = Object.entries(MESH_AUDIT_EVENTS)
      .filter(([key]) => key.startsWith("AUTH_"))
      .map(([, value]) => value);

    expect(authEvents).toContain("auth.login");
    expect(authEvents).toContain("auth.logout");
    expect(authEvents).toContain("auth.failed");
    expect(authEvents).toContain("auth.mfa_success");
    expect(authEvents).toContain("auth.mfa_failed");
    expect(authEvents).toContain("auth.token_refreshed");
    expect(authEvents).toHaveLength(6);
  });

  it("should categorize relay events correctly", () => {
    const relayEvents = Object.entries(MESH_AUDIT_EVENTS)
      .filter(([key]) => key.startsWith("RELAY_"))
      .map(([, value]) => value);

    expect(relayEvents).toContain("relay.message_forwarded");
    expect(relayEvents).toContain("relay.message_denied");
    expect(relayEvents).toContain("relay.revocation_submitted");
    expect(relayEvents).toHaveLength(3);
  });

  it("should categorize integration events correctly", () => {
    const integrationEvents = Object.entries(MESH_AUDIT_EVENTS)
      .filter(([key]) => key.startsWith("INTEGRATION_"))
      .map(([, value]) => value);

    expect(integrationEvents).toContain("integration.connected");
    expect(integrationEvents).toContain("integration.disconnected");
    expect(integrationEvents).toContain("integration.token_refreshed");
    expect(integrationEvents).toContain("integration.access_denied");
    expect(integrationEvents).toHaveLength(4);
  });
});
