/**
 * Tenant detection middleware for multi-tenant SaaS
 * Wave 2 Core Multi-Tenant (Task 2.1)
 *
 * Provides middleware for:
 * - Detecting tenant from various request sources (API key, session, subdomain)
 * - Requiring tenant context on protected routes
 * - Validating tenant status (active/suspended/deleted)
 * - Loading tenant from route parameters (admin routes)
 */

import { tenants, apiKeys, tenantMemberships } from "../db/index.js";
import {
  extractTenantFromRequest,
  setTenantContext,
  hasTenantContext,
  TENANT_SOURCE,
  logCrossTenantAttempt,
} from "../lib/tenant-context.js";

// ============================================================
// TENANT DETECTION MIDDLEWARE
// ============================================================

/**
 * Middleware to detect and attach tenant context to the request
 *
 * Priority order:
 * 1. API key header (x-api-key) - validate via apiKeys.validateKey()
 * 2. Session/JWT (req.user.tenant_id) - look up via tenants.findById()
 * 3. Subdomain parsing - look up via tenants.findBySlug()
 *
 * Sets req.tenant and req.tenantId on success
 * Passes through if no tenant found (for public routes)
 *
 * @param {object} req - Express request object
 * @param {object} res - Express response object
 * @param {function} next - Next middleware function
 */
export async function detectTenant(req, res, next) {
  try {
    const result = await extractTenantFromRequest(req, {
      validateApiKey: apiKeys.validateKey,
      findTenantById: tenants.findById,
      findTenantBySlug: tenants.findBySlug,
      allowQueryParam: false, // Only admin middleware should allow query params
    });

    if (result) {
      // Set tenant context on request
      setTenantContext(req, result.tenant, result.source);

      // If API key was used, attach the key data for scope checking
      if (result.source === TENANT_SOURCE.API_KEY && result.apiKeyData) {
        req.apiKey = result.apiKeyData;
      }

      // Log tenant context source for debugging (in development)
      if (process.env.NODE_ENV !== "production") {
        console.log(
          `[tenant-context] Detected tenant: ${result.tenant?.slug || result.tenantId} ` +
            `via ${result.source} for ${req.method} ${req.path}`,
        );
      }
    }

    // Always pass through - public routes don't require tenant
    next();
  } catch (err) {
    console.error("[tenant-context] Error detecting tenant:", err);
    // Pass through on error - requireTenant will catch missing tenant
    next();
  }
}

/**
 * Middleware variant that allows admin query parameter
 * Use this only on admin/platform routes
 *
 * Allows ?tenant=slug query parameter for admins to impersonate tenants
 */
export async function detectTenantAdmin(req, res, next) {
  try {
    const result = await extractTenantFromRequest(req, {
      validateApiKey: apiKeys.validateKey,
      findTenantById: tenants.findById,
      findTenantBySlug: tenants.findBySlug,
      allowQueryParam: true, // Allow query param for admins
    });

    if (result) {
      setTenantContext(req, result.tenant, result.source);

      if (result.source === TENANT_SOURCE.API_KEY && result.apiKeyData) {
        req.apiKey = result.apiKeyData;
      }

      if (process.env.NODE_ENV !== "production") {
        console.log(
          `[tenant-context] Admin detected tenant: ${result.tenant?.slug || result.tenantId} ` +
            `via ${result.source} for ${req.method} ${req.path}`,
        );
      }
    }

    next();
  } catch (err) {
    console.error("[tenant-context] Error detecting tenant (admin):", err);
    next();
  }
}

// ============================================================
// TENANT REQUIREMENT MIDDLEWARE
// ============================================================

/**
 * Middleware to require tenant context
 * Returns 403 if req.tenant is not set
 * Used on routes that require tenant context
 *
 * @param {object} req - Express request object
 * @param {object} res - Express response object
 * @param {function} next - Next middleware function
 */
export function requireTenant(req, res, next) {
  if (!hasTenantContext(req)) {
    return res.status(403).json({
      error: "Tenant context required",
      code: "TENANT_REQUIRED",
      message:
        "This endpoint requires a valid tenant context. " +
        "Provide an API key via x-api-key header, or ensure you are authenticated.",
    });
  }
  next();
}

/**
 * Middleware to require an active tenant
 * Requires tenant AND checks tenant.status === 'active'
 * Returns 403 if tenant is suspended/deleted
 *
 * @param {object} req - Express request object
 * @param {object} res - Express response object
 * @param {function} next - Next middleware function
 */
export function requireActiveTenant(req, res, next) {
  if (!hasTenantContext(req)) {
    return res.status(403).json({
      error: "Tenant context required",
      code: "TENANT_REQUIRED",
      message: "This endpoint requires a valid tenant context.",
    });
  }

  const tenant = req.tenant;

  if (tenant.status === "suspended") {
    return res.status(403).json({
      error: "Tenant suspended",
      code: "TENANT_SUSPENDED",
      message:
        "This tenant account has been suspended. " + "Please contact support for assistance.",
    });
  }

  if (tenant.status === "deleted") {
    return res.status(403).json({
      error: "Tenant not found",
      code: "TENANT_DELETED",
      message: "This tenant account no longer exists.",
    });
  }

  if (tenant.status !== "active") {
    return res.status(403).json({
      error: "Tenant inactive",
      code: "TENANT_INACTIVE",
      message: `Tenant is in '${tenant.status}' status and cannot perform this action.`,
    });
  }

  next();
}

// ============================================================
// TENANT FROM ROUTE PARAMETER
// ============================================================

/**
 * Middleware factory to extract tenant from route parameter
 * For admin routes like /admin/tenants/:tenantId
 *
 * Validates:
 * 1. Tenant exists
 * 2. User has access to that tenant (is platform admin OR tenant member/owner)
 *
 * @param {object} options - Options for the middleware
 * @param {string} options.paramName - Route param name (default: 'tenantId')
 * @param {boolean} options.requireOwner - Require user to be tenant owner (default: false)
 * @param {boolean} options.platformAdminOnly - Only allow platform admins (default: false)
 * @returns {function} Express middleware function
 */
export function tenantFromParam(options = {}) {
  const { paramName = "tenantId", requireOwner = false, platformAdminOnly = false } = options;

  return async function (req, res, next) {
    const tenantId = req.params[paramName];

    if (!tenantId) {
      return res.status(400).json({
        error: "Tenant ID required",
        code: "TENANT_ID_REQUIRED",
        message: `Missing required parameter: ${paramName}`,
      });
    }

    // Require authenticated user
    if (!req.user) {
      return res.status(401).json({
        error: "Authentication required",
        code: "AUTH_REQUIRED",
      });
    }

    try {
      // Look up tenant
      const tenant = await tenants.findById(tenantId);

      if (!tenant) {
        return res.status(404).json({
          error: "Tenant not found",
          code: "TENANT_NOT_FOUND",
        });
      }

      // Check access permissions
      const isPlatformAdmin = req.user.isPlatformAdmin || req.user.is_platform_admin;

      if (platformAdminOnly && !isPlatformAdmin) {
        // Log cross-tenant access attempt
        await logCrossTenantAttempt(req, tenantId, "admin route (platform admin only)", {
          paramName,
          route: req.path,
        });

        return res.status(403).json({
          error: "Platform admin access required",
          code: "PLATFORM_ADMIN_REQUIRED",
        });
      }

      // Check if user has access to this tenant
      let hasAccess = isPlatformAdmin;

      if (!hasAccess) {
        // Check if user is the tenant owner
        const isOwner = await tenantMemberships.isOwner(tenantId, req.user.id);

        if (isOwner) {
          hasAccess = true;
          req.isTenantOwner = true;
        } else if (!requireOwner) {
          // Check if user is a tenant member
          const isMember = await tenantMemberships.isMember(tenantId, req.user.id);
          hasAccess = isMember;
        }
      }

      if (!hasAccess) {
        // Log cross-tenant access attempt
        await logCrossTenantAttempt(req, tenantId, "admin route (unauthorized)", {
          paramName,
          route: req.path,
          requireOwner,
        });

        return res.status(403).json({
          error: "Access denied",
          code: "TENANT_ACCESS_DENIED",
          message: requireOwner
            ? "Only the tenant owner can perform this action"
            : "You do not have access to this tenant",
        });
      }

      // Set tenant context
      setTenantContext(req, tenant, "route_param");
      req.paramTenant = tenant; // Also set as paramTenant for clarity

      next();
    } catch (err) {
      console.error("[tenant-context] Error loading tenant from param:", err);
      res.status(500).json({
        error: "Failed to load tenant",
        code: "TENANT_LOAD_ERROR",
      });
    }
  };
}

/**
 * Convenience middleware for /tenants/:tenantId routes
 * Requires user to have access to the tenant (owner, member, or platform admin)
 */
export const loadTenantFromParam = tenantFromParam();

/**
 * Convenience middleware requiring tenant owner or platform admin
 */
export const requireTenantOwner = tenantFromParam({ requireOwner: true });

/**
 * Convenience middleware for platform admin only routes
 */
export const requirePlatformAdminForTenant = tenantFromParam({ platformAdminOnly: true });

// ============================================================
// HELPER MIDDLEWARE
// ============================================================

/**
 * Middleware to ensure current user belongs to the active tenant
 * Use after detectTenant and requireUser
 *
 * This validates that the authenticated user is actually a member of
 * the detected tenant (prevents API key + session mismatches)
 */
export async function requireUserInTenant(req, res, next) {
  if (!hasTenantContext(req)) {
    return res.status(403).json({
      error: "Tenant context required",
      code: "TENANT_REQUIRED",
    });
  }

  if (!req.user) {
    return res.status(401).json({
      error: "Authentication required",
      code: "AUTH_REQUIRED",
    });
  }

  try {
    const isMember = await tenantMemberships.isMember(req.tenantId, req.user.id);
    const isOwner = await tenantMemberships.isOwner(req.tenantId, req.user.id);

    if (!isMember && !isOwner) {
      // Log the access attempt
      await logCrossTenantAttempt(req, req.tenantId, "user tenant validation", {
        userId: req.user.id,
        userTenantId: req.user.tenant_id,
      });

      return res.status(403).json({
        error: "Access denied",
        code: "USER_NOT_IN_TENANT",
        message: "You are not a member of this tenant",
      });
    }

    req.isTenantOwner = isOwner;
    req.isTenantMember = isMember;

    next();
  } catch (err) {
    console.error("[tenant-context] Error checking user tenant membership:", err);
    res.status(500).json({
      error: "Failed to verify tenant membership",
      code: "TENANT_MEMBERSHIP_ERROR",
    });
  }
}

/**
 * Middleware to require tenant owner role
 * Use after detectTenant and requireUser
 */
export async function requireTenantOwnerRole(req, res, next) {
  if (!hasTenantContext(req)) {
    return res.status(403).json({
      error: "Tenant context required",
      code: "TENANT_REQUIRED",
    });
  }

  if (!req.user) {
    return res.status(401).json({
      error: "Authentication required",
      code: "AUTH_REQUIRED",
    });
  }

  try {
    // Check if already computed
    if (req.isTenantOwner !== undefined) {
      if (!req.isTenantOwner) {
        return res.status(403).json({
          error: "Tenant owner access required",
          code: "TENANT_OWNER_REQUIRED",
        });
      }
      return next();
    }

    const isOwner = await tenantMemberships.isOwner(req.tenantId, req.user.id);

    if (!isOwner) {
      return res.status(403).json({
        error: "Tenant owner access required",
        code: "TENANT_OWNER_REQUIRED",
        message: "Only the tenant owner can perform this action",
      });
    }

    req.isTenantOwner = true;
    next();
  } catch (err) {
    console.error("[tenant-context] Error checking tenant owner:", err);
    res.status(500).json({
      error: "Failed to verify tenant ownership",
      code: "TENANT_OWNER_ERROR",
    });
  }
}

// ============================================================
// DEFAULT EXPORT
// ============================================================

export default {
  // Detection
  detectTenant,
  detectTenantAdmin,

  // Requirements
  requireTenant,
  requireActiveTenant,

  // Route parameter
  tenantFromParam,
  loadTenantFromParam,
  requireTenantOwner,
  requirePlatformAdminForTenant,

  // User-tenant validation
  requireUserInTenant,
  requireTenantOwnerRole,
};
