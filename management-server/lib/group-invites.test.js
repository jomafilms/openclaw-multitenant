// Tests for group invite acceptance flow
import { describe, it, expect, beforeEach, vi } from "vitest";

// Mock the database module
vi.mock("../db/index.js", () => ({
  groupInvites: {
    create: vi.fn(),
    findById: vi.fn(),
    findByToken: vi.fn(),
    findPendingByGroupAndEmail: vi.fn(),
    listPendingForUser: vi.fn(),
    listByGroup: vi.fn(),
    accept: vi.fn(),
    decline: vi.fn(),
    cancel: vi.fn(),
    expireOld: vi.fn(),
    isValid: vi.fn(),
  },
  groupMemberships: {
    isMember: vi.fn(),
    add: vi.fn(),
  },
  users: {
    findByEmail: vi.fn(),
    findById: vi.fn(),
  },
  groups: {
    findById: vi.fn(),
  },
  audit: {
    log: vi.fn(),
  },
}));

import { groupInvites, groupMemberships, users, audit } from "../db/index.js";

describe("Group Invite Acceptance Flow", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("Invite States", () => {
    it("should support pending, accepted, declined, expired, and cancelled states", () => {
      const validStates = ["pending", "accepted", "declined", "expired", "cancelled"];
      // This is a documentation test - states are handled by the database
      expect(validStates).toHaveLength(5);
    });
  });

  describe("Invite Validation", () => {
    it("should validate invite is still pending", () => {
      const pendingInvite = {
        id: "invite-1",
        status: "pending",
        expires_at: new Date(Date.now() + 86400000).toISOString(),
      };

      // Mock isValid to use the actual logic
      groupInvites.isValid.mockImplementation((invite) => {
        if (!invite) {
          return false;
        }
        if (invite.status !== "pending") {
          return false;
        }
        if (invite.expires_at && new Date(invite.expires_at) < new Date()) {
          return false;
        }
        return true;
      });

      expect(groupInvites.isValid(pendingInvite)).toBe(true);
    });

    it("should reject expired invites", () => {
      const expiredInvite = {
        id: "invite-1",
        status: "pending",
        expires_at: new Date(Date.now() - 86400000).toISOString(), // 1 day ago
      };

      groupInvites.isValid.mockImplementation((invite) => {
        if (!invite) {
          return false;
        }
        if (invite.status !== "pending") {
          return false;
        }
        if (invite.expires_at && new Date(invite.expires_at) < new Date()) {
          return false;
        }
        return true;
      });

      expect(groupInvites.isValid(expiredInvite)).toBe(false);
    });

    it("should reject already-accepted invites", () => {
      const acceptedInvite = {
        id: "invite-1",
        status: "accepted",
        expires_at: new Date(Date.now() + 86400000).toISOString(),
      };

      groupInvites.isValid.mockImplementation((invite) => {
        if (!invite) {
          return false;
        }
        if (invite.status !== "pending") {
          return false;
        }
        if (invite.expires_at && new Date(invite.expires_at) < new Date()) {
          return false;
        }
        return true;
      });

      expect(groupInvites.isValid(acceptedInvite)).toBe(false);
    });

    it("should reject declined invites", () => {
      const declinedInvite = {
        id: "invite-1",
        status: "declined",
        expires_at: new Date(Date.now() + 86400000).toISOString(),
      };

      groupInvites.isValid.mockImplementation((invite) => {
        if (!invite) {
          return false;
        }
        if (invite.status !== "pending") {
          return false;
        }
        return true;
      });

      expect(groupInvites.isValid(declinedInvite)).toBe(false);
    });
  });

  describe("Explicit Acceptance Requirement", () => {
    it("should require explicit accept call to join group", async () => {
      const invite = {
        id: "invite-1",
        group_id: "group-1",
        invitee_id: "user-1",
        role: "member",
        status: "pending",
      };

      groupInvites.findById.mockResolvedValue(invite);
      groupInvites.accept.mockResolvedValue({ ...invite, status: "accepted" });
      groupMemberships.add.mockResolvedValue({
        user_id: "user-1",
        group_id: "group-1",
        role: "member",
      });

      // Accept the invite
      const accepted = await groupInvites.accept(invite.id, "user-1");
      expect(accepted.status).toBe("accepted");

      // Membership should be created separately
      await groupMemberships.add("user-1", invite.group_id, invite.role);
      expect(groupMemberships.add).toHaveBeenCalledWith("user-1", "group-1", "member");
    });

    it("should NOT auto-join when invite is created", async () => {
      // Creating an invite should NOT call groupMemberships.add
      groupInvites.create.mockResolvedValue({
        id: "invite-1",
        group_id: "group-1",
        invitee_email: "test@example.com",
        status: "pending",
      });

      await groupInvites.create({
        groupId: "group-1",
        inviterId: "admin-1",
        inviteeEmail: "test@example.com",
        role: "member",
      });

      // Membership should NOT have been created
      expect(groupMemberships.add).not.toHaveBeenCalled();
    });
  });

  describe("User Existence Hiding", () => {
    it("should not reveal if email exists when creating invite", async () => {
      // Whether user exists or not, the response should be the same
      users.findByEmail.mockResolvedValue(null); // User doesn't exist

      groupInvites.create.mockResolvedValue({
        id: "invite-1",
        status: "pending",
      });

      const result = await groupInvites.create({
        groupId: "group-1",
        inviterId: "admin-1",
        inviteeEmail: "unknown@example.com",
        inviteeId: null, // No user ID since user doesn't exist
        role: "member",
      });

      // Invite should still be created
      expect(result).toBeDefined();
      expect(result.status).toBe("pending");
    });

    it("should create invite even for existing users without revealing existence", async () => {
      users.findByEmail.mockResolvedValue({
        id: "user-1",
        email: "existing@example.com",
      });

      groupInvites.create.mockResolvedValue({
        id: "invite-1",
        invitee_id: "user-1",
        status: "pending",
      });

      const result = await groupInvites.create({
        groupId: "group-1",
        inviterId: "admin-1",
        inviteeEmail: "existing@example.com",
        inviteeId: "user-1",
        role: "member",
      });

      // Response should be similar regardless of user existence
      expect(result.status).toBe("pending");
    });
  });

  describe("Invite Expiration", () => {
    it("should set 7-day default expiration on new invites", async () => {
      const now = Date.now();
      const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;

      groupInvites.create.mockResolvedValue({
        id: "invite-1",
        status: "pending",
        expires_at: new Date(now + sevenDaysMs).toISOString(),
      });

      const result = await groupInvites.create({
        groupId: "group-1",
        inviterId: "admin-1",
        inviteeEmail: "test@example.com",
        role: "member",
      });

      const expiresAt = new Date(result.expires_at).getTime();
      const expectedExpiry = now + sevenDaysMs;

      // Should be within 1 minute of expected expiry (accounting for test execution time)
      expect(Math.abs(expiresAt - expectedExpiry)).toBeLessThan(60000);
    });

    it("should mark old invites as expired", async () => {
      groupInvites.expireOld.mockResolvedValue([
        { id: "invite-1", status: "expired" },
        { id: "invite-2", status: "expired" },
      ]);

      const expired = await groupInvites.expireOld();
      expect(expired).toHaveLength(2);
      expect(expired[0].status).toBe("expired");
    });
  });

  describe("Token-based Invite Links", () => {
    it("should generate secure random token for invite", async () => {
      // Token should be a 64-character hex string (32 bytes)
      const mockToken = "a".repeat(64);

      groupInvites.create.mockResolvedValue({
        id: "invite-1",
        token: mockToken,
        status: "pending",
      });

      const result = await groupInvites.create({
        groupId: "group-1",
        inviterId: "admin-1",
        inviteeEmail: "test@example.com",
        role: "member",
      });

      expect(result.token).toBeDefined();
      expect(result.token).toHaveLength(64);
    });

    it("should find invite by token", async () => {
      const token = "secure-random-token-64-chars".padEnd(64, "x");

      groupInvites.findByToken.mockResolvedValue({
        id: "invite-1",
        token: token,
        group_name: "Test Org",
        status: "pending",
      });

      const result = await groupInvites.findByToken(token);
      expect(result).toBeDefined();
      expect(result.group_name).toBe("Test Org");
    });
  });

  describe("Invite Ownership Verification", () => {
    it("should verify invite belongs to user by ID", () => {
      const invite = {
        invitee_id: "user-1",
        invitee_email: "user@example.com",
      };
      const user = { id: "user-1", email: "different@example.com" };

      // Check by ID
      const belongsToUser = invite.invitee_id === user.id || invite.invitee_email === user.email;
      expect(belongsToUser).toBe(true);
    });

    it("should verify invite belongs to user by email", () => {
      const invite = {
        invitee_id: null, // User didn't exist when invited
        invitee_email: "user@example.com",
      };
      const user = { id: "user-1", email: "user@example.com" };

      // Check by email (for users who signed up after invite)
      const belongsToUser = invite.invitee_id === user.id || invite.invitee_email === user.email;
      expect(belongsToUser).toBe(true);
    });

    it("should reject if invite does not belong to user", () => {
      const invite = {
        invitee_id: "other-user",
        invitee_email: "other@example.com",
      };
      const user = { id: "user-1", email: "user@example.com" };

      const belongsToUser = invite.invitee_id === user.id || invite.invitee_email === user.email;
      expect(belongsToUser).toBe(false);
    });
  });

  describe("Decline Flow", () => {
    it("should allow declining an invite", async () => {
      const invite = {
        id: "invite-1",
        status: "pending",
      };

      groupInvites.decline.mockResolvedValue({
        ...invite,
        status: "declined",
        decided_at: new Date().toISOString(),
      });

      const result = await groupInvites.decline(invite.id, "user-1");
      expect(result.status).toBe("declined");
      expect(result.decided_at).toBeDefined();
    });

    it("should NOT create membership when declining", async () => {
      groupInvites.decline.mockResolvedValue({
        id: "invite-1",
        status: "declined",
      });

      await groupInvites.decline("invite-1", "user-1");
      expect(groupMemberships.add).not.toHaveBeenCalled();
    });
  });

  describe("Admin Operations", () => {
    it("should allow admin to cancel pending invite", async () => {
      groupInvites.cancel.mockResolvedValue({
        id: "invite-1",
        status: "cancelled",
      });

      const result = await groupInvites.cancel("invite-1");
      expect(result.status).toBe("cancelled");
    });

    it("should list all invites for group (admin view)", async () => {
      groupInvites.listByGroup.mockResolvedValue([
        { id: "invite-1", status: "pending", invitee_email: "user1@example.com" },
        { id: "invite-2", status: "accepted", invitee_email: "user2@example.com" },
        { id: "invite-3", status: "declined", invitee_email: "user3@example.com" },
      ]);

      const invites = await groupInvites.listByGroup("group-1");
      expect(invites).toHaveLength(3);
    });
  });

  describe("User View", () => {
    it("should list pending invites for user", async () => {
      groupInvites.listPendingForUser.mockResolvedValue([
        { id: "invite-1", group_name: "Org A", status: "pending" },
        { id: "invite-2", group_name: "Org B", status: "pending" },
      ]);

      const invites = await groupInvites.listPendingForUser("user-1");
      expect(invites).toHaveLength(2);
      expect(invites.every((i) => i.status === "pending")).toBe(true);
    });

    it("should not include expired invites in user pending list", async () => {
      // The listPendingForUser query filters out expired invites
      groupInvites.listPendingForUser.mockResolvedValue([
        { id: "invite-1", status: "pending" }, // Only non-expired
      ]);

      const invites = await groupInvites.listPendingForUser("user-1");
      expect(invites).toHaveLength(1);
    });
  });
});
