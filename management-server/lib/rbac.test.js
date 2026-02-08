/**
 * Tests for the RBAC (Role-Based Access Control) module
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  ROLES,
  ALL_PERMISSIONS,
  getAllPermissions,
  can,
  canAny,
  canAll,
  hasRole,
  compareRoles,
  getBuiltInRoles,
  canAssignRole,
} from "./rbac.js";

describe("RBAC Module", () => {
  describe("ROLES", () => {
    it("should have all expected built-in roles", () => {
      expect(ROLES).toHaveProperty("owner");
      expect(ROLES).toHaveProperty("admin");
      expect(ROLES).toHaveProperty("member");
      expect(ROLES).toHaveProperty("observer");
    });

    it("should have correct inheritance chain", () => {
      expect(ROLES.owner.inherits).toContain("admin");
      expect(ROLES.admin.inherits).toContain("member");
      expect(ROLES.member.inherits).toContain("observer");
      expect(ROLES.observer.inherits).toEqual([]);
    });
  });

  describe("getAllPermissions", () => {
    it("should return direct permissions for observer", () => {
      const perms = getAllPermissions("observer");
      expect(perms).toContain("resources.read");
      expect(perms).toContain("agents.view");
      expect(perms).not.toContain("resources.write");
    });

    it("should include inherited permissions for member", () => {
      const perms = getAllPermissions("member");
      // Direct permissions
      expect(perms).toContain("resources.write");
      expect(perms).toContain("agents.use");
      // Inherited from observer
      expect(perms).toContain("resources.read");
      expect(perms).toContain("agents.view");
    });

    it("should include all inherited permissions for admin", () => {
      const perms = getAllPermissions("admin");
      // Direct permissions
      expect(perms).toContain("users.manage");
      expect(perms).toContain("groups.manage");
      // Inherited from member
      expect(perms).toContain("resources.write");
      // Inherited from observer
      expect(perms).toContain("resources.read");
    });

    it("should include all permissions for owner", () => {
      const perms = getAllPermissions("owner");
      // Direct permissions
      expect(perms).toContain("tenant.delete");
      expect(perms).toContain("billing.manage");
      // Inherited from admin
      expect(perms).toContain("users.manage");
      // Inherited from member
      expect(perms).toContain("resources.write");
      // Inherited from observer
      expect(perms).toContain("resources.read");
    });

    it("should return empty array for unknown role", () => {
      const perms = getAllPermissions("nonexistent");
      expect(perms).toEqual([]);
    });

    it("should handle custom roles", () => {
      const customRoles = {
        "custom-reviewer": {
          permissions: ["resources.read", "audit.view"],
          inherits: ["observer"],
        },
      };
      const perms = getAllPermissions("custom-reviewer", customRoles);
      expect(perms).toContain("resources.read");
      expect(perms).toContain("audit.view");
      expect(perms).toContain("agents.view"); // inherited from observer
    });

    it("should handle circular inheritance without infinite loop", () => {
      const customRoles = {
        role1: {
          permissions: ["test.perm1"],
          inherits: ["role2"],
        },
        role2: {
          permissions: ["test.perm2"],
          inherits: ["role1"],
        },
      };
      // Should not throw or hang
      const perms = getAllPermissions("role1", customRoles);
      expect(perms).toContain("test.perm1");
      expect(perms).toContain("test.perm2");
    });
  });

  describe("can", () => {
    it("should return true for permission user has via role", () => {
      const user = { tenant_role: "admin" };
      expect(can(user, "users.manage")).toBe(true);
      expect(can(user, "resources.read")).toBe(true); // inherited
    });

    it("should return false for permission user does not have", () => {
      const user = { tenant_role: "member" };
      expect(can(user, "users.manage")).toBe(false);
    });

    it("should return true for platform admins", () => {
      const user = { is_platform_admin: true, tenant_role: "observer" };
      expect(can(user, "tenant.delete")).toBe(true);
      expect(can(user, "users.manage")).toBe(true);
    });

    it("should check resource-specific permissions", () => {
      const user = {
        tenant_role: "observer",
        resource_permissions: {
          "resource-123": ["write", "delete"],
        },
      };
      const resource = { id: "resource-123" };
      expect(can(user, "resources.write", resource)).toBe(true);
      expect(can(user, "resources.delete", resource)).toBe(true);
      expect(can(user, "resources.admin", resource)).toBe(false);
    });

    it("should fall back to role permissions if resource permissions empty", () => {
      const user = {
        tenant_role: "admin",
        resource_permissions: {},
      };
      expect(can(user, "users.manage")).toBe(true);
    });

    it("should use role field if tenant_role not set", () => {
      const user = { role: "admin" };
      expect(can(user, "users.manage")).toBe(true);
    });

    it("should default to observer if no role set", () => {
      const user = {};
      expect(can(user, "resources.read")).toBe(true);
      expect(can(user, "users.manage")).toBe(false);
    });
  });

  describe("canAny", () => {
    it("should return true if user has any of the permissions", () => {
      const user = { tenant_role: "member" };
      expect(canAny(user, ["users.manage", "resources.write"])).toBe(true);
    });

    it("should return false if user has none of the permissions", () => {
      const user = { tenant_role: "observer" };
      expect(canAny(user, ["users.manage", "billing.manage"])).toBe(false);
    });
  });

  describe("canAll", () => {
    it("should return true if user has all of the permissions", () => {
      const user = { tenant_role: "admin" };
      expect(canAll(user, ["users.manage", "resources.read"])).toBe(true);
    });

    it("should return false if user is missing any permission", () => {
      const user = { tenant_role: "admin" };
      expect(canAll(user, ["users.manage", "tenant.delete"])).toBe(false);
    });
  });

  describe("hasRole", () => {
    it("should return true for exact role match", () => {
      const user = { tenant_role: "admin" };
      expect(hasRole(user, "admin")).toBe(true);
    });

    it("should return true for higher role than required", () => {
      const user = { tenant_role: "owner" };
      expect(hasRole(user, "admin")).toBe(true);
      expect(hasRole(user, "member")).toBe(true);
      expect(hasRole(user, "observer")).toBe(true);
    });

    it("should return false for lower role than required", () => {
      const user = { tenant_role: "member" };
      expect(hasRole(user, "admin")).toBe(false);
      expect(hasRole(user, "owner")).toBe(false);
    });

    it("should return true for platform admins", () => {
      const user = { is_platform_admin: true, tenant_role: "observer" };
      expect(hasRole(user, "owner")).toBe(true);
    });

    it("should return false for unknown required role", () => {
      const user = { tenant_role: "admin" };
      expect(hasRole(user, "nonexistent")).toBe(false);
    });
  });

  describe("compareRoles", () => {
    it("should return -1 when first role is lower", () => {
      expect(compareRoles("observer", "member")).toBe(-1);
      expect(compareRoles("member", "admin")).toBe(-1);
      expect(compareRoles("admin", "owner")).toBe(-1);
    });

    it("should return 1 when first role is higher", () => {
      expect(compareRoles("member", "observer")).toBe(1);
      expect(compareRoles("admin", "member")).toBe(1);
      expect(compareRoles("owner", "admin")).toBe(1);
    });

    it("should return 0 for equal roles", () => {
      expect(compareRoles("admin", "admin")).toBe(0);
    });

    it("should treat unknown roles as observer", () => {
      expect(compareRoles("unknown", "observer")).toBe(0);
    });
  });

  describe("getBuiltInRoles", () => {
    it("should return all built-in roles with computed permissions", () => {
      const roles = getBuiltInRoles();
      expect(roles).toHaveLength(4);

      const ownerRole = roles.find((r) => r.name === "owner");
      expect(ownerRole).toBeDefined();
      expect(ownerRole.isBuiltIn).toBe(true);
      expect(ownerRole.permissions).toContain("tenant.delete");
      expect(ownerRole.permissions).toContain("resources.read"); // inherited
    });
  });

  describe("canAssignRole", () => {
    it("should allow platform admins to assign any role", () => {
      const admin = { is_platform_admin: true };
      expect(canAssignRole(admin, "owner")).toBe(true);
      expect(canAssignRole(admin, "admin")).toBe(true);
    });

    it("should allow owners to assign admin role", () => {
      const owner = { tenant_role: "owner" };
      expect(canAssignRole(owner, "admin")).toBe(true);
      expect(canAssignRole(owner, "member")).toBe(true);
      expect(canAssignRole(owner, "observer")).toBe(true);
    });

    it("should not allow owners to assign owner role", () => {
      const owner = { tenant_role: "owner" };
      expect(canAssignRole(owner, "owner")).toBe(false);
    });

    it("should allow admins to assign member role", () => {
      const admin = { tenant_role: "admin" };
      expect(canAssignRole(admin, "member")).toBe(true);
      expect(canAssignRole(admin, "observer")).toBe(true);
    });

    it("should not allow admins to assign admin or higher", () => {
      const admin = { tenant_role: "admin" };
      expect(canAssignRole(admin, "admin")).toBe(false);
      expect(canAssignRole(admin, "owner")).toBe(false);
    });

    it("should not allow members to assign any role", () => {
      const member = { tenant_role: "member" };
      expect(canAssignRole(member, "observer")).toBe(true);
      expect(canAssignRole(member, "member")).toBe(false);
      expect(canAssignRole(member, "admin")).toBe(false);
    });
  });

  describe("ALL_PERMISSIONS", () => {
    it("should contain expected permission categories", () => {
      expect(ALL_PERMISSIONS.some((p) => p.startsWith("tenant."))).toBe(true);
      expect(ALL_PERMISSIONS.some((p) => p.startsWith("users."))).toBe(true);
      expect(ALL_PERMISSIONS.some((p) => p.startsWith("resources."))).toBe(true);
      expect(ALL_PERMISSIONS.some((p) => p.startsWith("agents."))).toBe(true);
      expect(ALL_PERMISSIONS.some((p) => p.startsWith("groups."))).toBe(true);
      expect(ALL_PERMISSIONS.some((p) => p.startsWith("billing."))).toBe(true);
    });

    it("should contain wildcard permission", () => {
      expect(ALL_PERMISSIONS).toContain("*");
    });
  });
});
