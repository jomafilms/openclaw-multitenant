/**
 * Advanced Role-Based Access Control (RBAC) System
 * Wave 5.2 - Multi-tenant SaaS Enterprise Feature
 *
 * Provides:
 * - Role definitions with hierarchical inheritance
 * - Permission checking with resource-level overrides
 * - Custom roles for enterprise tenants
 * - Express middleware factories for permission enforcement
 */

import { query } from "../db/core.js";
import { tenants, subscriptions } from "../db/index.js";
import { isAtLeastPlan } from "./quotas.js";

// ============================================================
// BUILT-IN ROLE DEFINITIONS
// ============================================================

/**
 * Built-in roles with hierarchical permissions
 * Each role inherits all permissions from its parent roles
 */
export const ROLES = {
  owner: {
    inherits: ["admin"],
    permissions: [
      "tenant.delete",
      "tenant.transfer",
      "billing.manage",
      "rbac.manage", // Can manage custom roles
    ],
  },
  admin: {
    inherits: ["member"],
    permissions: [
      "users.manage",
      "users.invite",
      "users.remove",
      "groups.manage",
      "groups.create",
      "groups.delete",
      "settings.manage",
      "api_keys.manage",
      "audit.view",
    ],
  },
  member: {
    inherits: ["observer"],
    permissions: [
      "resources.write",
      "resources.create",
      "resources.delete",
      "agents.use",
      "agents.configure",
      "groups.join",
    ],
  },
  observer: {
    inherits: [],
    permissions: [
      "resources.read",
      "resources.list",
      "agents.view",
      "groups.view",
      "profile.read",
      "profile.update",
    ],
  },
};

/**
 * All available permission strings in the system
 * Used for validation and documentation
 */
export const ALL_PERMISSIONS = [
  // Tenant permissions (owner only)
  "tenant.delete",
  "tenant.transfer",

  // Billing permissions
  "billing.manage",
  "billing.view",

  // RBAC permissions (enterprise)
  "rbac.manage",
  "rbac.view",

  // User management
  "users.manage",
  "users.invite",
  "users.remove",
  "users.view",

  // Group management
  "groups.manage",
  "groups.create",
  "groups.delete",
  "groups.join",
  "groups.view",

  // Settings
  "settings.manage",
  "settings.view",

  // API keys
  "api_keys.manage",
  "api_keys.view",

  // Audit
  "audit.view",
  "audit.export",

  // Resources
  "resources.read",
  "resources.list",
  "resources.write",
  "resources.create",
  "resources.delete",
  "resources.share",

  // Agents
  "agents.view",
  "agents.use",
  "agents.configure",
  "agents.create",
  "agents.delete",

  // Profile
  "profile.read",
  "profile.update",

  // Wildcard (full access)
  "*",
];

/**
 * Role hierarchy order (lower index = lower privileges)
 */
const ROLE_HIERARCHY = ["observer", "member", "admin", "owner"];

// ============================================================
// PERMISSION COMPUTATION
// ============================================================

/**
 * Get all permissions for a role including inherited permissions
 *
 * @param {string} roleName - Name of the role
 * @param {object} customRoles - Optional custom role definitions from tenant
 * @param {Set} visited - Internal: track visited roles to prevent cycles
 * @returns {string[]} Array of all permissions for the role
 */
export function getAllPermissions(roleName, customRoles = {}, visited = new Set()) {
  // Prevent infinite loops from circular inheritance
  if (visited.has(roleName)) {
    return [];
  }
  visited.add(roleName);

  // Look up role in custom roles first, then built-in
  const role = customRoles[roleName] || ROLES[roleName];

  if (!role) {
    return [];
  }

  // Start with the role's direct permissions
  const permissions = new Set(role.permissions || []);

  // Add inherited permissions
  for (const parentRole of role.inherits || []) {
    const parentPermissions = getAllPermissions(parentRole, customRoles, visited);
    for (const perm of parentPermissions) {
      permissions.add(perm);
    }
  }

  return Array.from(permissions);
}

/**
 * Check if a permission is included in a permission set
 * Handles wildcard (*) matching
 *
 * @param {string[]} permissionSet - Set of permissions to check against
 * @param {string} permission - Permission to check
 * @returns {boolean} True if permission is granted
 */
function permissionMatches(permissionSet, permission) {
  // Wildcard grants everything
  if (permissionSet.includes("*")) {
    return true;
  }

  // Exact match
  if (permissionSet.includes(permission)) {
    return true;
  }

  // Category wildcard (e.g., "users.*" grants "users.manage")
  const [category] = permission.split(".");
  if (permissionSet.includes(`${category}.*`)) {
    return true;
  }

  return false;
}

// ============================================================
// PERMISSION CHECKING
// ============================================================

/**
 * Check if a user has a specific permission
 *
 * @param {object} user - User object with role and optional resource_permissions
 * @param {string} permission - Permission to check
 * @param {object} resource - Optional resource for resource-level permission check
 * @param {object} customRoles - Optional custom role definitions from tenant
 * @returns {boolean} True if user has the permission
 */
export function can(user, permission, resource = null, customRoles = {}) {
  if (!user || !permission) {
    return false;
  }

  // Platform admins have all permissions
  if (user.is_platform_admin) {
    return true;
  }

  // Tenant owners always have owner role permissions
  const userRole = user.tenant_role || user.role || "observer";

  // Get all permissions for the user's role
  const rolePermissions = getAllPermissions(userRole, customRoles);

  // Check role-based permission
  if (permissionMatches(rolePermissions, permission)) {
    return true;
  }

  // Check resource-specific permissions if a resource is provided
  if (resource && user.resource_permissions) {
    const resourcePerms = user.resource_permissions[resource.id];
    if (resourcePerms && Array.isArray(resourcePerms)) {
      // Resource permissions use simplified names (e.g., "read", "write")
      const simplePerm = permission.split(".").pop();
      if (resourcePerms.includes(simplePerm)) {
        return true;
      }
      // Also check full permission name
      if (resourcePerms.includes(permission)) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Check if a user has any of the specified permissions
 *
 * @param {object} user - User object
 * @param {string[]} permissions - Array of permissions to check
 * @param {object} resource - Optional resource
 * @param {object} customRoles - Optional custom roles
 * @returns {boolean} True if user has any of the permissions
 */
export function canAny(user, permissions, resource = null, customRoles = {}) {
  return permissions.some((perm) => can(user, perm, resource, customRoles));
}

/**
 * Check if a user has all of the specified permissions
 *
 * @param {object} user - User object
 * @param {string[]} permissions - Array of permissions to check
 * @param {object} resource - Optional resource
 * @param {object} customRoles - Optional custom roles
 * @returns {boolean} True if user has all of the permissions
 */
export function canAll(user, permissions, resource = null, customRoles = {}) {
  return permissions.every((perm) => can(user, perm, resource, customRoles));
}

/**
 * Check if a user has a specific role or higher
 *
 * @param {object} user - User object with role
 * @param {string} requiredRole - Role to check against
 * @returns {boolean} True if user has the role or higher
 */
export function hasRole(user, requiredRole) {
  if (!user) {
    return false;
  }

  // Platform admins have all roles
  if (user.is_platform_admin) {
    return true;
  }

  const userRole = user.tenant_role || user.role || "observer";
  const userRoleIndex = ROLE_HIERARCHY.indexOf(userRole);
  const requiredRoleIndex = ROLE_HIERARCHY.indexOf(requiredRole);

  // Unknown roles are treated as lowest privilege
  if (userRoleIndex === -1) {
    return false;
  }
  if (requiredRoleIndex === -1) {
    return false;
  }

  return userRoleIndex >= requiredRoleIndex;
}

/**
 * Compare two roles
 *
 * @param {string} role1 - First role
 * @param {string} role2 - Second role
 * @returns {number} -1 if role1 < role2, 1 if role1 > role2, 0 if equal
 */
export function compareRoles(role1, role2) {
  const index1 = ROLE_HIERARCHY.indexOf(role1);
  const index2 = ROLE_HIERARCHY.indexOf(role2);

  const safeIndex1 = index1 === -1 ? 0 : index1;
  const safeIndex2 = index2 === -1 ? 0 : index2;

  if (safeIndex1 < safeIndex2) return -1;
  if (safeIndex1 > safeIndex2) return 1;
  return 0;
}

// ============================================================
// EXPRESS MIDDLEWARE FACTORIES
// ============================================================

/**
 * Middleware factory to require a specific permission
 *
 * @param {string} permission - Permission required
 * @returns {Function} Express middleware
 */
export function requirePermission(permission) {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: "Authentication required",
        code: "AUTH_REQUIRED",
      });
    }

    // Load custom roles if tenant has them
    const customRoles = await loadCustomRoles(req.user.tenant_id);

    if (!can(req.user, permission, null, customRoles)) {
      return res.status(403).json({
        error: `Permission denied: ${permission} required`,
        code: "PERMISSION_DENIED",
        required: permission,
      });
    }

    // Attach custom roles to request for later use
    req.customRoles = customRoles;
    next();
  };
}

/**
 * Middleware factory to require any of the specified permissions
 *
 * @param {string[]} permissions - Array of permissions (any one is sufficient)
 * @returns {Function} Express middleware
 */
export function requireAnyPermission(permissions) {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: "Authentication required",
        code: "AUTH_REQUIRED",
      });
    }

    const customRoles = await loadCustomRoles(req.user.tenant_id);

    if (!canAny(req.user, permissions, null, customRoles)) {
      return res.status(403).json({
        error: `Permission denied: one of [${permissions.join(", ")}] required`,
        code: "PERMISSION_DENIED",
        required: permissions,
      });
    }

    req.customRoles = customRoles;
    next();
  };
}

/**
 * Middleware factory to require all of the specified permissions
 *
 * @param {string[]} permissions - Array of permissions (all are required)
 * @returns {Function} Express middleware
 */
export function requireAllPermissions(permissions) {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: "Authentication required",
        code: "AUTH_REQUIRED",
      });
    }

    const customRoles = await loadCustomRoles(req.user.tenant_id);

    if (!canAll(req.user, permissions, null, customRoles)) {
      const missing = permissions.filter((p) => !can(req.user, p, null, customRoles));
      return res.status(403).json({
        error: `Permission denied: [${missing.join(", ")}] required`,
        code: "PERMISSION_DENIED",
        required: permissions,
        missing,
      });
    }

    req.customRoles = customRoles;
    next();
  };
}

/**
 * Middleware factory to require a specific role or higher
 *
 * @param {string} role - Minimum role required
 * @returns {Function} Express middleware
 */
export function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: "Authentication required",
        code: "AUTH_REQUIRED",
      });
    }

    if (!hasRole(req.user, role)) {
      return res.status(403).json({
        error: `Role denied: ${role} or higher required`,
        code: "ROLE_DENIED",
        required: role,
        current: req.user.tenant_role || req.user.role || "observer",
      });
    }

    next();
  };
}

// ============================================================
// CUSTOM ROLES (ENTERPRISE FEATURE)
// ============================================================

/**
 * Load custom roles for a tenant from the database
 *
 * @param {string} tenantId - Tenant UUID
 * @returns {Promise<object>} Object mapping role names to role definitions
 */
async function loadCustomRoles(tenantId) {
  if (!tenantId) {
    return {};
  }

  try {
    const result = await query(
      `SELECT name, permissions, inherits
       FROM tenant_roles
       WHERE tenant_id = $1 AND deleted_at IS NULL`,
      [tenantId],
    );

    const customRoles = {};
    for (const row of result.rows) {
      customRoles[row.name] = {
        permissions: row.permissions || [],
        inherits: row.inherits || [],
      };
    }

    return customRoles;
  } catch (err) {
    // Table might not exist yet, return empty
    console.error("[rbac] Failed to load custom roles:", err.message);
    return {};
  }
}

/**
 * Check if tenant can use custom roles (enterprise feature)
 *
 * @param {string} tenantId - Tenant UUID
 * @returns {Promise<boolean>} True if tenant can use custom roles
 */
async function canUseCustomRoles(tenantId) {
  if (!tenantId) {
    return false;
  }

  try {
    const subscription = await subscriptions.findByTenantId(tenantId);
    return isAtLeastPlan(subscription?.plan, "enterprise");
  } catch {
    return false;
  }
}

/**
 * Create a custom role for a tenant
 *
 * @param {string} tenantId - Tenant UUID
 * @param {string} name - Role name (must be unique within tenant)
 * @param {string[]} permissions - Array of permission strings
 * @param {string[]} inherits - Array of role names to inherit from
 * @param {string} createdBy - User ID who created the role
 * @returns {Promise<object>} Created role
 */
export async function createCustomRole(
  tenantId,
  name,
  permissions,
  inherits = [],
  createdBy = null,
) {
  // Validate enterprise plan
  if (!(await canUseCustomRoles(tenantId))) {
    const error = new Error("Custom roles require Enterprise plan");
    error.code = "PLAN_REQUIRED";
    error.requiredPlan = "enterprise";
    throw error;
  }

  // Validate role name (no conflicts with built-in roles)
  if (ROLES[name]) {
    const error = new Error(`Cannot use built-in role name: ${name}`);
    error.code = "INVALID_ROLE_NAME";
    throw error;
  }

  // Validate role name format
  if (!/^[a-z][a-z0-9_-]{0,49}$/.test(name)) {
    const error = new Error(
      "Role name must be lowercase alphanumeric with underscores/hyphens, 1-50 chars",
    );
    error.code = "INVALID_ROLE_NAME";
    throw error;
  }

  // Validate permissions
  const invalidPerms = permissions.filter((p) => !ALL_PERMISSIONS.includes(p));
  if (invalidPerms.length > 0) {
    const error = new Error(`Invalid permissions: ${invalidPerms.join(", ")}`);
    error.code = "INVALID_PERMISSIONS";
    throw error;
  }

  // Validate inherits (must be valid role names)
  for (const inheritRole of inherits) {
    if (!ROLES[inheritRole] && inheritRole !== name) {
      // Custom roles can only inherit from built-in roles
      const error = new Error(`Cannot inherit from unknown role: ${inheritRole}`);
      error.code = "INVALID_INHERITANCE";
      throw error;
    }
  }

  const result = await query(
    `INSERT INTO tenant_roles (tenant_id, name, permissions, inherits, created_by)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING *`,
    [tenantId, name, JSON.stringify(permissions), JSON.stringify(inherits), createdBy],
  );

  return result.rows[0];
}

/**
 * Update a custom role
 *
 * @param {string} tenantId - Tenant UUID
 * @param {string} roleId - Role UUID
 * @param {object} updates - Updates to apply
 * @returns {Promise<object>} Updated role
 */
export async function updateCustomRole(tenantId, roleId, updates) {
  // Validate enterprise plan
  if (!(await canUseCustomRoles(tenantId))) {
    const error = new Error("Custom roles require Enterprise plan");
    error.code = "PLAN_REQUIRED";
    error.requiredPlan = "enterprise";
    throw error;
  }

  const { permissions, inherits, description } = updates;

  // Validate permissions if provided
  if (permissions) {
    const invalidPerms = permissions.filter((p) => !ALL_PERMISSIONS.includes(p));
    if (invalidPerms.length > 0) {
      const error = new Error(`Invalid permissions: ${invalidPerms.join(", ")}`);
      error.code = "INVALID_PERMISSIONS";
      throw error;
    }
  }

  // Build update query
  const setClauses = ["updated_at = NOW()"];
  const params = [tenantId, roleId];
  let paramIndex = 3;

  if (permissions !== undefined) {
    setClauses.push(`permissions = $${paramIndex}`);
    params.push(JSON.stringify(permissions));
    paramIndex++;
  }

  if (inherits !== undefined) {
    setClauses.push(`inherits = $${paramIndex}`);
    params.push(JSON.stringify(inherits));
    paramIndex++;
  }

  if (description !== undefined) {
    setClauses.push(`description = $${paramIndex}`);
    params.push(description);
    paramIndex++;
  }

  const result = await query(
    `UPDATE tenant_roles
     SET ${setClauses.join(", ")}
     WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL
     RETURNING *`,
    params,
  );

  if (result.rows.length === 0) {
    const error = new Error("Custom role not found");
    error.code = "NOT_FOUND";
    throw error;
  }

  return result.rows[0];
}

/**
 * Delete a custom role (soft delete)
 *
 * @param {string} tenantId - Tenant UUID
 * @param {string} roleId - Role UUID
 * @returns {Promise<object>} Deleted role
 */
export async function deleteCustomRole(tenantId, roleId) {
  // Validate enterprise plan
  if (!(await canUseCustomRoles(tenantId))) {
    const error = new Error("Custom roles require Enterprise plan");
    error.code = "PLAN_REQUIRED";
    error.requiredPlan = "enterprise";
    throw error;
  }

  // Check if any users have this role assigned
  const usageResult = await query(
    `SELECT COUNT(*) as count FROM tenant_user_roles
     WHERE tenant_id = $1 AND role_id = $2`,
    [tenantId, roleId],
  );

  if (parseInt(usageResult.rows[0]?.count || 0, 10) > 0) {
    const error = new Error("Cannot delete role that is assigned to users");
    error.code = "ROLE_IN_USE";
    throw error;
  }

  const result = await query(
    `UPDATE tenant_roles
     SET deleted_at = NOW()
     WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL
     RETURNING *`,
    [tenantId, roleId],
  );

  if (result.rows.length === 0) {
    const error = new Error("Custom role not found");
    error.code = "NOT_FOUND";
    throw error;
  }

  return result.rows[0];
}

/**
 * List custom roles for a tenant
 *
 * @param {string} tenantId - Tenant UUID
 * @returns {Promise<object[]>} Array of custom roles
 */
export async function listCustomRoles(tenantId) {
  const result = await query(
    `SELECT id, name, description, permissions, inherits, created_at, updated_at
     FROM tenant_roles
     WHERE tenant_id = $1 AND deleted_at IS NULL
     ORDER BY name`,
    [tenantId],
  );

  return result.rows;
}

/**
 * Get a custom role by ID
 *
 * @param {string} tenantId - Tenant UUID
 * @param {string} roleId - Role UUID
 * @returns {Promise<object|null>} Role or null
 */
export async function getCustomRole(tenantId, roleId) {
  const result = await query(
    `SELECT id, name, description, permissions, inherits, created_at, updated_at
     FROM tenant_roles
     WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`,
    [tenantId, roleId],
  );

  return result.rows[0] || null;
}

// ============================================================
// USER ROLE MANAGEMENT
// ============================================================

/**
 * Assign a role to a user within a tenant
 *
 * @param {string} tenantId - Tenant UUID
 * @param {string} userId - User UUID
 * @param {string} role - Role name (built-in or custom)
 * @param {string} assignedBy - User ID who assigned the role
 * @returns {Promise<object>} Assignment record
 */
export async function assignUserRole(tenantId, userId, role, assignedBy = null) {
  // Validate role exists (built-in or custom)
  const customRoles = await loadCustomRoles(tenantId);
  if (!ROLES[role] && !customRoles[role]) {
    const error = new Error(`Unknown role: ${role}`);
    error.code = "INVALID_ROLE";
    throw error;
  }

  // Update the user's tenant_role
  const result = await query(
    `UPDATE users
     SET tenant_role = $3, updated_at = NOW()
     WHERE id = $1 AND tenant_id = $2
     RETURNING id, tenant_role`,
    [userId, tenantId, role],
  );

  if (result.rows.length === 0) {
    const error = new Error("User not found in tenant");
    error.code = "NOT_FOUND";
    throw error;
  }

  return result.rows[0];
}

/**
 * Get a user's role within a tenant
 *
 * @param {string} tenantId - Tenant UUID
 * @param {string} userId - User UUID
 * @returns {Promise<string>} Role name or 'member' as default
 */
export async function getUserRole(tenantId, userId) {
  const result = await query(
    `SELECT tenant_role FROM users
     WHERE id = $1 AND tenant_id = $2`,
    [userId, tenantId],
  );

  return result.rows[0]?.tenant_role || "member";
}

/**
 * Set resource-level permissions for a user
 *
 * @param {string} userId - User UUID
 * @param {string} resourceId - Resource UUID
 * @param {string[]} permissions - Array of permission names
 * @returns {Promise<object>} Updated resource_permissions
 */
export async function setResourcePermissions(userId, resourceId, permissions) {
  // Validate permissions
  const validSimplePerms = ["read", "list", "write", "delete", "admin", "share"];
  const invalidPerms = permissions.filter(
    (p) => !validSimplePerms.includes(p) && !ALL_PERMISSIONS.includes(p),
  );

  if (invalidPerms.length > 0) {
    const error = new Error(`Invalid permissions: ${invalidPerms.join(", ")}`);
    error.code = "INVALID_PERMISSIONS";
    throw error;
  }

  // Get current resource_permissions
  const currentResult = await query(`SELECT resource_permissions FROM users WHERE id = $1`, [
    userId,
  ]);

  const current = currentResult.rows[0]?.resource_permissions || {};

  // Update with new permissions
  current[resourceId] = permissions;

  // Save back to database
  const result = await query(
    `UPDATE users
     SET resource_permissions = $2, updated_at = NOW()
     WHERE id = $1
     RETURNING resource_permissions`,
    [userId, JSON.stringify(current)],
  );

  return result.rows[0]?.resource_permissions || {};
}

/**
 * Remove resource-level permissions for a user
 *
 * @param {string} userId - User UUID
 * @param {string} resourceId - Resource UUID
 * @returns {Promise<object>} Updated resource_permissions
 */
export async function removeResourcePermissions(userId, resourceId) {
  const currentResult = await query(`SELECT resource_permissions FROM users WHERE id = $1`, [
    userId,
  ]);

  const current = currentResult.rows[0]?.resource_permissions || {};
  delete current[resourceId];

  const result = await query(
    `UPDATE users
     SET resource_permissions = $2, updated_at = NOW()
     WHERE id = $1
     RETURNING resource_permissions`,
    [userId, JSON.stringify(current)],
  );

  return result.rows[0]?.resource_permissions || {};
}

// ============================================================
// UTILITIES
// ============================================================

/**
 * Get all built-in roles with their computed permissions
 *
 * @returns {object[]} Array of role definitions with all permissions
 */
export function getBuiltInRoles() {
  return Object.entries(ROLES).map(([name, role]) => ({
    name,
    permissions: getAllPermissions(name),
    directPermissions: role.permissions,
    inherits: role.inherits,
    isBuiltIn: true,
  }));
}

/**
 * Check if a user can manage another user's role
 * (Users cannot assign roles higher than their own)
 *
 * @param {object} actor - User performing the action
 * @param {string} targetRole - Role to assign
 * @returns {boolean} True if actor can assign the role
 */
export function canAssignRole(actor, targetRole) {
  if (!actor) return false;

  // Platform admins can assign any role
  if (actor.is_platform_admin) return true;

  // Get actor's role level
  const actorRole = actor.tenant_role || actor.role || "member";
  const actorIndex = ROLE_HIERARCHY.indexOf(actorRole);
  const targetIndex = ROLE_HIERARCHY.indexOf(targetRole);

  // Unknown roles cannot be assigned by regular users
  if (targetIndex === -1) return false;

  // Actor can assign roles up to one level below their own
  // (Only owners can assign admin, only admins can assign member, etc.)
  return actorIndex > targetIndex;
}

// ============================================================
// EXPORTS
// ============================================================

export default {
  // Constants
  ROLES,
  ALL_PERMISSIONS,
  ROLE_HIERARCHY,

  // Permission computation
  getAllPermissions,

  // Permission checking
  can,
  canAny,
  canAll,
  hasRole,
  compareRoles,

  // Middleware
  requirePermission,
  requireAnyPermission,
  requireAllPermissions,
  requireRole,

  // Custom roles
  createCustomRole,
  updateCustomRole,
  deleteCustomRole,
  listCustomRoles,
  getCustomRole,

  // User role management
  assignUserRole,
  getUserRole,
  setResourcePermissions,
  removeResourcePermissions,

  // Utilities
  getBuiltInRoles,
  canAssignRole,
};
