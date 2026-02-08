/**
 * RBAC Routes
 * Wave 5.2 - Role-Based Access Control Management
 *
 * Provides endpoints for:
 * - Listing available roles and permissions
 * - Assigning roles to users
 * - Managing resource-level permissions
 * - Custom role management (enterprise)
 */

import { Router } from "express";
import { z } from "zod";
import { audit, users, query } from "../db/index.js";
import {
  ROLES,
  ALL_PERMISSIONS,
  getBuiltInRoles,
  getAllPermissions,
  can,
  hasRole,
  canAssignRole,
  requirePermission,
  assignUserRole,
  getUserRole,
  setResourcePermissions,
  removeResourcePermissions,
  createCustomRole,
  updateCustomRole,
  deleteCustomRole,
  listCustomRoles,
  getCustomRole,
} from "../lib/rbac.js";
import { requireUser } from "../middleware/auth.js";
import { requireTenant } from "../middleware/tenant-context.js";

const router = Router();

// ============================================================
// VALIDATION SCHEMAS
// ============================================================

const uuidSchema = z.string().uuid();

const assignRoleSchema = z.object({
  role: z.string().min(1).max(50),
});

const resourcePermissionsSchema = z.object({
  resourceId: z.string().uuid(),
  permissions: z.array(z.string().min(1).max(50)),
});

const customRoleSchema = z.object({
  name: z.string().regex(/^[a-z][a-z0-9_-]{0,49}$/),
  description: z.string().max(500).optional(),
  permissions: z.array(z.string()),
  inherits: z.array(z.string()).default([]),
});

const updateCustomRoleSchema = z.object({
  description: z.string().max(500).optional(),
  permissions: z.array(z.string()).optional(),
  inherits: z.array(z.string()).optional(),
});

// ============================================================
// PUBLIC ROLE/PERMISSION INFO
// ============================================================

/**
 * GET /api/rbac/roles
 * List all available roles (built-in and custom for the tenant)
 */
router.get("/roles", requireUser, requireTenant, async (req, res) => {
  try {
    // Get built-in roles
    const builtInRoles = getBuiltInRoles();

    // Get custom roles for tenant
    let customRoles = [];
    if (req.tenant) {
      try {
        customRoles = await listCustomRoles(req.tenant.id);
        // Add computed permissions to custom roles
        customRoles = customRoles.map((role) => ({
          ...role,
          computedPermissions: getAllPermissions(role.name, { [role.name]: role }),
          isBuiltIn: false,
        }));
      } catch (err) {
        // Custom roles table might not exist yet
        console.error("[rbac] Failed to load custom roles:", err.message);
      }
    }

    res.json({
      builtInRoles,
      customRoles,
      roleHierarchy: ["observer", "member", "admin", "owner"],
    });
  } catch (err) {
    console.error("[rbac] List roles error:", err);
    res.status(500).json({ error: "Failed to list roles" });
  }
});

/**
 * GET /api/rbac/permissions
 * List all available permissions
 */
router.get("/permissions", requireUser, async (req, res) => {
  try {
    // Group permissions by category
    const grouped = {};
    for (const perm of ALL_PERMISSIONS) {
      if (perm === "*") continue; // Skip wildcard in listing

      const [category, action] = perm.split(".");
      if (!grouped[category]) {
        grouped[category] = [];
      }
      grouped[category].push({
        permission: perm,
        action,
      });
    }

    res.json({
      permissions: ALL_PERMISSIONS.filter((p) => p !== "*"),
      grouped,
    });
  } catch (err) {
    console.error("[rbac] List permissions error:", err);
    res.status(500).json({ error: "Failed to list permissions" });
  }
});

/**
 * GET /api/rbac/my-permissions
 * Get the current user's effective permissions
 */
router.get("/my-permissions", requireUser, requireTenant, async (req, res) => {
  try {
    const userRole = req.user.tenant_role || req.user.role || "member";

    // Load custom roles for permission computation
    let customRoles = {};
    if (req.tenant) {
      try {
        const roles = await listCustomRoles(req.tenant.id);
        for (const role of roles) {
          customRoles[role.name] = role;
        }
      } catch {
        // Custom roles not available
      }
    }

    const permissions = getAllPermissions(userRole, customRoles);

    // Get resource-level permissions
    const userResult = await query("SELECT resource_permissions FROM users WHERE id = $1", [
      req.user.id,
    ]);
    const resourcePermissions = userResult.rows[0]?.resource_permissions || {};

    res.json({
      role: userRole,
      permissions,
      resourcePermissions,
      isPlatformAdmin: req.user.is_platform_admin || false,
    });
  } catch (err) {
    console.error("[rbac] Get my permissions error:", err);
    res.status(500).json({ error: "Failed to get permissions" });
  }
});

// ============================================================
// USER ROLE MANAGEMENT
// ============================================================

/**
 * GET /api/rbac/users/:id/role
 * Get a user's role
 */
router.get(
  "/users/:id/role",
  requireUser,
  requireTenant,
  requirePermission("users.view"),
  async (req, res) => {
    try {
      const parseResult = uuidSchema.safeParse(req.params.id);
      if (!parseResult.success) {
        return res.status(400).json({ error: "Invalid user ID" });
      }

      const userId = parseResult.data;

      // Verify user is in same tenant
      const user = await users.findById(userId);
      if (!user || user.tenant_id !== req.tenant.id) {
        return res.status(404).json({ error: "User not found in tenant" });
      }

      const role = await getUserRole(req.tenant.id, userId);

      res.json({
        userId,
        role,
        permissions: getAllPermissions(role, req.customRoles || {}),
      });
    } catch (err) {
      console.error("[rbac] Get user role error:", err);
      res.status(500).json({ error: "Failed to get user role" });
    }
  },
);

/**
 * PUT /api/rbac/users/:id/role
 * Assign a role to a user
 */
router.put(
  "/users/:id/role",
  requireUser,
  requireTenant,
  requirePermission("users.manage"),
  async (req, res) => {
    try {
      const parseResult = uuidSchema.safeParse(req.params.id);
      if (!parseResult.success) {
        return res.status(400).json({ error: "Invalid user ID" });
      }

      const bodyResult = assignRoleSchema.safeParse(req.body);
      if (!bodyResult.success) {
        return res.status(400).json({
          error: "Invalid request body",
          details: bodyResult.error.issues,
        });
      }

      const userId = parseResult.data;
      const { role } = bodyResult.data;

      // Verify user is in same tenant
      const user = await users.findById(userId);
      if (!user || user.tenant_id !== req.tenant.id) {
        return res.status(404).json({ error: "User not found in tenant" });
      }

      // Check if actor can assign this role
      if (!canAssignRole(req.user, role)) {
        return res.status(403).json({
          error: "Cannot assign role higher than or equal to your own",
          code: "ROLE_ASSIGNMENT_DENIED",
          yourRole: req.user.tenant_role || req.user.role,
          targetRole: role,
        });
      }

      // Cannot change tenant owner's role
      if (req.tenant.owner_id === userId && role !== "owner") {
        return res.status(400).json({
          error: "Cannot change tenant owner's role",
          code: "OWNER_ROLE_PROTECTED",
        });
      }

      const result = await assignUserRole(req.tenant.id, userId, role, req.user.id);

      // Audit log
      await audit.log(
        req.user.id,
        "rbac.role_assigned",
        {
          targetUserId: userId,
          targetUserEmail: user.email,
          newRole: role,
          previousRole: user.tenant_role || "member",
        },
        req.ip,
      );

      res.json({
        success: true,
        userId,
        role: result.tenant_role,
        permissions: getAllPermissions(role, req.customRoles || {}),
      });
    } catch (err) {
      console.error("[rbac] Assign role error:", err);

      if (err.code === "INVALID_ROLE") {
        return res.status(400).json({ error: err.message, code: err.code });
      }

      res.status(500).json({ error: "Failed to assign role" });
    }
  },
);

// ============================================================
// RESOURCE-LEVEL PERMISSIONS
// ============================================================

/**
 * GET /api/rbac/users/:id/permissions
 * Get a user's resource-level permissions
 */
router.get(
  "/users/:id/permissions",
  requireUser,
  requireTenant,
  requirePermission("users.view"),
  async (req, res) => {
    try {
      const parseResult = uuidSchema.safeParse(req.params.id);
      if (!parseResult.success) {
        return res.status(400).json({ error: "Invalid user ID" });
      }

      const userId = parseResult.data;

      // Verify user is in same tenant
      const user = await users.findById(userId);
      if (!user || user.tenant_id !== req.tenant.id) {
        return res.status(404).json({ error: "User not found in tenant" });
      }

      const userResult = await query("SELECT resource_permissions FROM users WHERE id = $1", [
        userId,
      ]);

      res.json({
        userId,
        resourcePermissions: userResult.rows[0]?.resource_permissions || {},
      });
    } catch (err) {
      console.error("[rbac] Get resource permissions error:", err);
      res.status(500).json({ error: "Failed to get resource permissions" });
    }
  },
);

/**
 * PUT /api/rbac/users/:id/permissions
 * Set resource-level permissions for a user
 */
router.put(
  "/users/:id/permissions",
  requireUser,
  requireTenant,
  requirePermission("users.manage"),
  async (req, res) => {
    try {
      const parseResult = uuidSchema.safeParse(req.params.id);
      if (!parseResult.success) {
        return res.status(400).json({ error: "Invalid user ID" });
      }

      const bodyResult = resourcePermissionsSchema.safeParse(req.body);
      if (!bodyResult.success) {
        return res.status(400).json({
          error: "Invalid request body",
          details: bodyResult.error.issues,
        });
      }

      const userId = parseResult.data;
      const { resourceId, permissions } = bodyResult.data;

      // Verify user is in same tenant
      const user = await users.findById(userId);
      if (!user || user.tenant_id !== req.tenant.id) {
        return res.status(404).json({ error: "User not found in tenant" });
      }

      const result = await setResourcePermissions(userId, resourceId, permissions);

      // Audit log
      await audit.log(
        req.user.id,
        "rbac.resource_permissions_set",
        {
          targetUserId: userId,
          targetUserEmail: user.email,
          resourceId,
          permissions,
        },
        req.ip,
      );

      res.json({
        success: true,
        userId,
        resourcePermissions: result,
      });
    } catch (err) {
      console.error("[rbac] Set resource permissions error:", err);

      if (err.code === "INVALID_PERMISSIONS") {
        return res.status(400).json({ error: err.message, code: err.code });
      }

      res.status(500).json({ error: "Failed to set resource permissions" });
    }
  },
);

/**
 * DELETE /api/rbac/users/:id/permissions/:resourceId
 * Remove resource-level permissions for a user
 */
router.delete(
  "/users/:id/permissions/:resourceId",
  requireUser,
  requireTenant,
  requirePermission("users.manage"),
  async (req, res) => {
    try {
      const userIdResult = uuidSchema.safeParse(req.params.id);
      const resourceIdResult = uuidSchema.safeParse(req.params.resourceId);

      if (!userIdResult.success || !resourceIdResult.success) {
        return res.status(400).json({ error: "Invalid ID" });
      }

      const userId = userIdResult.data;
      const resourceId = resourceIdResult.data;

      // Verify user is in same tenant
      const user = await users.findById(userId);
      if (!user || user.tenant_id !== req.tenant.id) {
        return res.status(404).json({ error: "User not found in tenant" });
      }

      const result = await removeResourcePermissions(userId, resourceId);

      // Audit log
      await audit.log(
        req.user.id,
        "rbac.resource_permissions_removed",
        {
          targetUserId: userId,
          targetUserEmail: user.email,
          resourceId,
        },
        req.ip,
      );

      res.json({
        success: true,
        userId,
        resourcePermissions: result,
      });
    } catch (err) {
      console.error("[rbac] Remove resource permissions error:", err);
      res.status(500).json({ error: "Failed to remove resource permissions" });
    }
  },
);

// ============================================================
// CUSTOM ROLES (ENTERPRISE)
// ============================================================

/**
 * GET /api/rbac/custom-roles
 * List custom roles for the tenant
 */
router.get(
  "/custom-roles",
  requireUser,
  requireTenant,
  requirePermission("rbac.view"),
  async (req, res) => {
    try {
      const roles = await listCustomRoles(req.tenant.id);

      res.json({
        roles: roles.map((role) => ({
          ...role,
          computedPermissions: getAllPermissions(role.name, { [role.name]: role }),
        })),
      });
    } catch (err) {
      console.error("[rbac] List custom roles error:", err);
      res.status(500).json({ error: "Failed to list custom roles" });
    }
  },
);

/**
 * GET /api/rbac/custom-roles/:id
 * Get a custom role
 */
router.get(
  "/custom-roles/:id",
  requireUser,
  requireTenant,
  requirePermission("rbac.view"),
  async (req, res) => {
    try {
      const parseResult = uuidSchema.safeParse(req.params.id);
      if (!parseResult.success) {
        return res.status(400).json({ error: "Invalid role ID" });
      }

      const role = await getCustomRole(req.tenant.id, parseResult.data);

      if (!role) {
        return res.status(404).json({ error: "Custom role not found" });
      }

      res.json({
        ...role,
        computedPermissions: getAllPermissions(role.name, { [role.name]: role }),
      });
    } catch (err) {
      console.error("[rbac] Get custom role error:", err);
      res.status(500).json({ error: "Failed to get custom role" });
    }
  },
);

/**
 * POST /api/rbac/custom-roles
 * Create a custom role (enterprise only)
 */
router.post(
  "/custom-roles",
  requireUser,
  requireTenant,
  requirePermission("rbac.manage"),
  async (req, res) => {
    try {
      const parseResult = customRoleSchema.safeParse(req.body);
      if (!parseResult.success) {
        return res.status(400).json({
          error: "Invalid request body",
          details: parseResult.error.issues,
        });
      }

      const { name, description, permissions, inherits } = parseResult.data;

      const role = await createCustomRole(req.tenant.id, name, permissions, inherits, req.user.id);

      // Update description if provided
      if (description) {
        await updateCustomRole(req.tenant.id, role.id, { description });
        role.description = description;
      }

      // Audit log
      await audit.log(
        req.user.id,
        "rbac.custom_role_created",
        {
          roleId: role.id,
          roleName: name,
          permissions,
          inherits,
        },
        req.ip,
      );

      res.status(201).json({
        success: true,
        role: {
          ...role,
          computedPermissions: getAllPermissions(name, { [name]: role }),
        },
      });
    } catch (err) {
      console.error("[rbac] Create custom role error:", err);

      if (err.code === "PLAN_REQUIRED") {
        return res.status(402).json({
          error: err.message,
          code: err.code,
          requiredPlan: err.requiredPlan,
          upgradeUrl: "/billing/upgrade",
        });
      }

      if (
        err.code === "INVALID_ROLE_NAME" ||
        err.code === "INVALID_PERMISSIONS" ||
        err.code === "INVALID_INHERITANCE"
      ) {
        return res.status(400).json({ error: err.message, code: err.code });
      }

      // Duplicate role name
      if (err.code === "23505") {
        return res.status(409).json({
          error: "Role name already exists",
          code: "DUPLICATE_ROLE",
        });
      }

      res.status(500).json({ error: "Failed to create custom role" });
    }
  },
);

/**
 * PUT /api/rbac/custom-roles/:id
 * Update a custom role
 */
router.put(
  "/custom-roles/:id",
  requireUser,
  requireTenant,
  requirePermission("rbac.manage"),
  async (req, res) => {
    try {
      const parseResult = uuidSchema.safeParse(req.params.id);
      if (!parseResult.success) {
        return res.status(400).json({ error: "Invalid role ID" });
      }

      const bodyResult = updateCustomRoleSchema.safeParse(req.body);
      if (!bodyResult.success) {
        return res.status(400).json({
          error: "Invalid request body",
          details: bodyResult.error.issues,
        });
      }

      const roleId = parseResult.data;
      const updates = bodyResult.data;

      const role = await updateCustomRole(req.tenant.id, roleId, updates);

      // Audit log
      await audit.log(
        req.user.id,
        "rbac.custom_role_updated",
        {
          roleId,
          roleName: role.name,
          updates,
        },
        req.ip,
      );

      res.json({
        success: true,
        role: {
          ...role,
          computedPermissions: getAllPermissions(role.name, { [role.name]: role }),
        },
      });
    } catch (err) {
      console.error("[rbac] Update custom role error:", err);

      if (err.code === "PLAN_REQUIRED") {
        return res.status(402).json({
          error: err.message,
          code: err.code,
          requiredPlan: err.requiredPlan,
          upgradeUrl: "/billing/upgrade",
        });
      }

      if (err.code === "NOT_FOUND") {
        return res.status(404).json({ error: err.message, code: err.code });
      }

      if (err.code === "INVALID_PERMISSIONS") {
        return res.status(400).json({ error: err.message, code: err.code });
      }

      res.status(500).json({ error: "Failed to update custom role" });
    }
  },
);

/**
 * DELETE /api/rbac/custom-roles/:id
 * Delete a custom role
 */
router.delete(
  "/custom-roles/:id",
  requireUser,
  requireTenant,
  requirePermission("rbac.manage"),
  async (req, res) => {
    try {
      const parseResult = uuidSchema.safeParse(req.params.id);
      if (!parseResult.success) {
        return res.status(400).json({ error: "Invalid role ID" });
      }

      const roleId = parseResult.data;

      const role = await deleteCustomRole(req.tenant.id, roleId);

      // Audit log
      await audit.log(
        req.user.id,
        "rbac.custom_role_deleted",
        {
          roleId,
          roleName: role.name,
        },
        req.ip,
      );

      res.json({
        success: true,
        role,
        message: `Custom role "${role.name}" has been deleted`,
      });
    } catch (err) {
      console.error("[rbac] Delete custom role error:", err);

      if (err.code === "PLAN_REQUIRED") {
        return res.status(402).json({
          error: err.message,
          code: err.code,
          requiredPlan: err.requiredPlan,
          upgradeUrl: "/billing/upgrade",
        });
      }

      if (err.code === "NOT_FOUND") {
        return res.status(404).json({ error: err.message, code: err.code });
      }

      if (err.code === "ROLE_IN_USE") {
        return res.status(409).json({
          error: err.message,
          code: err.code,
        });
      }

      res.status(500).json({ error: "Failed to delete custom role" });
    }
  },
);

export default router;
