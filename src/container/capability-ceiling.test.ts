import { describe, it, expect } from "vitest";
import {
  PERMISSION_LEVELS,
  DEFAULT_AGENT_CEILING,
  isValidPermission,
  getPermissionOrder,
  isWithinCeiling,
  partitionPermissions,
  CeilingExceededError,
  CeilingManager,
  createEmptyCeilingStoreData,
  type PermissionLevel,
} from "./capability-ceiling.js";

describe("Permission Levels", () => {
  it("should have correct permission order", () => {
    expect(getPermissionOrder("read")).toBe(0);
    expect(getPermissionOrder("list")).toBe(1);
    expect(getPermissionOrder("write")).toBe(2);
    expect(getPermissionOrder("delete")).toBe(3);
    expect(getPermissionOrder("admin")).toBe(4);
    expect(getPermissionOrder("share-further")).toBe(5);
  });

  it("should validate permissions correctly", () => {
    expect(isValidPermission("read")).toBe(true);
    expect(isValidPermission("list")).toBe(true);
    expect(isValidPermission("write")).toBe(true);
    expect(isValidPermission("delete")).toBe(true);
    expect(isValidPermission("admin")).toBe(true);
    expect(isValidPermission("share-further")).toBe(true);
    expect(isValidPermission("unknown")).toBe(false);
    expect(isValidPermission("")).toBe(false);
  });

  it("should have default agent ceiling of read and list", () => {
    expect(DEFAULT_AGENT_CEILING).toEqual(["read", "list"]);
  });
});

describe("isWithinCeiling", () => {
  it("should return true when all permissions are within ceiling", () => {
    expect(isWithinCeiling(["read"], ["read", "list"])).toBe(true);
    expect(isWithinCeiling(["read", "list"], ["read", "list"])).toBe(true);
    expect(isWithinCeiling(["read"], ["write"])).toBe(true); // read < write
  });

  it("should return false when permissions exceed ceiling", () => {
    expect(isWithinCeiling(["write"], ["read", "list"])).toBe(false);
    expect(isWithinCeiling(["delete"], ["read", "list"])).toBe(false);
    expect(isWithinCeiling(["admin"], ["write"])).toBe(false);
    expect(isWithinCeiling(["share-further"], ["admin"])).toBe(false);
  });

  it("should return false for unknown permissions", () => {
    expect(isWithinCeiling(["unknown"], ["read", "list"])).toBe(false);
    expect(isWithinCeiling(["read", "unknown"], ["admin"])).toBe(false);
  });

  it("should return false for empty ceiling", () => {
    expect(isWithinCeiling(["read"], [])).toBe(false);
  });
});

describe("partitionPermissions", () => {
  it("should partition permissions correctly", () => {
    const result = partitionPermissions(["read", "write", "delete"], ["read", "list"]);
    expect(result.grantable).toEqual(["read"]);
    expect(result.escalated).toEqual(["write", "delete"]);
  });

  it("should handle all permissions within ceiling", () => {
    const result = partitionPermissions(["read", "list"], ["read", "list"]);
    expect(result.grantable).toEqual(["read", "list"]);
    expect(result.escalated).toEqual([]);
  });

  it("should handle all permissions exceeding ceiling", () => {
    const result = partitionPermissions(["admin", "share-further"], ["read"]);
    expect(result.grantable).toEqual([]);
    expect(result.escalated).toEqual(["admin", "share-further"]);
  });

  it("should treat unknown permissions as escalated", () => {
    const result = partitionPermissions(["read", "unknown"], ["admin"]);
    expect(result.grantable).toEqual(["read"]);
    expect(result.escalated).toEqual(["unknown"]);
  });

  it("should handle empty ceiling", () => {
    const result = partitionPermissions(["read"], []);
    expect(result.grantable).toEqual([]);
    expect(result.escalated).toEqual(["read"]);
  });
});

describe("CeilingExceededError", () => {
  it("should create error with correct properties", () => {
    const error = new CeilingExceededError(
      "agent-123",
      ["read", "delete"],
      ["read", "list"],
      ["delete"],
      "escalation-456",
    );

    expect(error.name).toBe("CeilingExceededError");
    expect(error.agentId).toBe("agent-123");
    expect(error.requestedScope).toEqual(["read", "delete"]);
    expect(error.ceiling).toEqual(["read", "list"]);
    expect(error.escalatedPermissions).toEqual(["delete"]);
    expect(error.escalationRequestId).toBe("escalation-456");
    expect(error.message).toContain("Agent 'agent-123'");
    expect(error.message).toContain("delete");
    expect(error.message).toContain("Human approval required");
  });
});

describe("CeilingManager", () => {
  const createManager = () => {
    const data = createEmptyCeilingStoreData();
    let saved = false;
    const onSave = async () => {
      saved = true;
    };
    return { manager: new CeilingManager(data, onSave), data, wasSaved: () => saved };
  };

  describe("getAgentCeiling", () => {
    it("should return default ceiling for unknown agents", () => {
      const { manager } = createManager();
      expect(manager.getAgentCeiling("unknown-agent")).toEqual(DEFAULT_AGENT_CEILING);
    });

    it("should return configured ceiling for known agents", async () => {
      const { manager } = createManager();
      await manager.setAgentCeiling("agent-1", ["read", "list", "write"], "human-1");
      expect(manager.getAgentCeiling("agent-1")).toEqual(["read", "list", "write"]);
    });
  });

  describe("setAgentCeiling", () => {
    it("should set ceiling for agent", async () => {
      const { manager, wasSaved } = createManager();
      await manager.setAgentCeiling(
        "agent-1",
        ["read", "list", "write"],
        "human-1",
        "Trusted agent",
      );

      expect(manager.getAgentCeiling("agent-1")).toEqual(["read", "list", "write"]);
      expect(wasSaved()).toBe(true);
    });

    it("should reject invalid permissions", async () => {
      const { manager } = createManager();
      await expect(
        manager.setAgentCeiling("agent-1", ["read", "invalid" as PermissionLevel], "human-1"),
      ).rejects.toThrow("Invalid permission level");
    });
  });

  describe("removeAgentCeiling", () => {
    it("should remove ceiling and revert to default", async () => {
      const { manager } = createManager();
      await manager.setAgentCeiling("agent-1", ["admin"], "human-1");
      expect(manager.getAgentCeiling("agent-1")).toEqual(["admin"]);

      await manager.removeAgentCeiling("agent-1");
      expect(manager.getAgentCeiling("agent-1")).toEqual(DEFAULT_AGENT_CEILING);
    });
  });

  describe("validateAgentPermissions", () => {
    it("should not throw when permissions are within ceiling", () => {
      const { manager } = createManager();
      expect(() => manager.validateAgentPermissions("agent-1", ["read"])).not.toThrow();
      expect(() => manager.validateAgentPermissions("agent-1", ["read", "list"])).not.toThrow();
    });

    it("should throw CeilingExceededError when permissions exceed ceiling", () => {
      const { manager } = createManager();
      expect(() => manager.validateAgentPermissions("agent-1", ["write"])).toThrow(
        CeilingExceededError,
      );
      expect(() => manager.validateAgentPermissions("agent-1", ["delete"])).toThrow(
        CeilingExceededError,
      );
    });
  });

  describe("escalation requests", () => {
    it("should create escalation request", async () => {
      const { manager } = createManager();
      const request = await manager.createEscalationRequest(
        "agent-1",
        "google-calendar",
        ["read", "write", "delete"],
        "subject-pubkey",
        3600,
        10,
      );

      expect(request.id).toBeDefined();
      expect(request.agentId).toBe("agent-1");
      expect(request.resource).toBe("google-calendar");
      expect(request.requestedScope).toEqual(["read", "write", "delete"]);
      expect(request.grantableScope).toEqual(["read"]);
      expect(request.escalatedScope).toEqual(["write", "delete"]);
      expect(request.status).toBe("pending");
    });

    it("should throw if no escalation needed", async () => {
      const { manager } = createManager();
      await expect(
        manager.createEscalationRequest("agent-1", "resource", ["read"], "pubkey", 3600),
      ).rejects.toThrow("No escalation needed");
    });

    it("should approve escalation request", async () => {
      const { manager } = createManager();
      const request = await manager.createEscalationRequest(
        "agent-1",
        "resource",
        ["read", "delete"],
        "pubkey",
        3600,
      );

      const approvedScope = await manager.approveEscalationRequest(request.id, "human-1");
      expect(approvedScope).toEqual(["read", "delete"]);

      const updated = manager.getEscalationRequest(request.id);
      expect(updated?.status).toBe("approved");
      expect(updated?.resolvedBy).toBe("human-1");
    });

    it("should deny escalation request", async () => {
      const { manager } = createManager();
      const request = await manager.createEscalationRequest(
        "agent-1",
        "resource",
        ["admin"],
        "pubkey",
        3600,
      );

      await manager.denyEscalationRequest(request.id, "human-1", "Too risky");

      const updated = manager.getEscalationRequest(request.id);
      expect(updated?.status).toBe("denied");
      expect(updated?.denialReason).toBe("Too risky");
    });

    it("should list pending escalation requests", async () => {
      const { manager } = createManager();
      await manager.createEscalationRequest("agent-1", "r1", ["delete"], "pk1", 3600);
      const req2 = await manager.createEscalationRequest("agent-2", "r2", ["admin"], "pk2", 3600);
      await manager.approveEscalationRequest(req2.id, "human");

      const pending = manager.listEscalationRequests("pending");
      expect(pending).toHaveLength(1);
      expect(pending[0].agentId).toBe("agent-1");

      const approved = manager.listEscalationRequests("approved");
      expect(approved).toHaveLength(1);
      expect(approved[0].agentId).toBe("agent-2");
    });
  });
});
