/**
 * Quota enforcement middleware for multi-tenant SaaS
 * Wave 3 Billing & Onboarding (Task 3.2)
 *
 * Provides middleware for:
 * - Checking resource quotas before allowing operations
 * - Counting current usage for various resource types
 * - Returning 402 Payment Required when limits are exceeded
 * - Monthly reset support for API call quotas
 */

import { query } from "../db/core.js";
import { subscriptions } from "../db/subscriptions.js";
import {
  getLimit,
  isUnlimited,
  checkQuotaForAdd,
  createQuotaExceededResponse,
  TRACKABLE_RESOURCES,
} from "../lib/quotas.js";

// ============================================================
// USAGE COUNTING
// ============================================================

/**
 * Count current usage for a specific resource type within a tenant
 *
 * @param {string} tenantId - UUID of the tenant
 * @param {string} resource - Resource type from TRACKABLE_RESOURCES
 * @param {object} options - Optional context (e.g., groupId for resources_per_group)
 * @returns {Promise<number>} Current usage count
 */
export async function countUsage(tenantId, resource, options = {}) {
  switch (resource) {
    case "users": {
      // Count users in the tenant
      const res = await query("SELECT COUNT(*)::int AS count FROM users WHERE tenant_id = $1", [
        tenantId,
      ]);
      return res.rows[0]?.count || 0;
    }

    case "agents": {
      // Count active agents for the tenant
      // Try agent_containers table first, fall back to counting from integrations
      try {
        const res = await query(
          `SELECT COUNT(*)::int AS count FROM agent_containers
           WHERE tenant_id = $1 AND status != 'deleted'`,
          [tenantId],
        );
        return res.rows[0]?.count || 0;
      } catch {
        // Table may not exist yet - count from integrations as fallback
        const res = await query(
          `SELECT COUNT(DISTINCT agent_id)::int AS count FROM integrations
           WHERE tenant_id = $1 AND agent_id IS NOT NULL`,
          [tenantId],
        );
        return res.rows[0]?.count || 0;
      }
    }

    case "groups": {
      // Count groups owned by the tenant
      const res = await query("SELECT COUNT(*)::int AS count FROM groups WHERE tenant_id = $1", [
        tenantId,
      ]);
      return res.rows[0]?.count || 0;
    }

    case "resources_per_group": {
      // Count resources in a specific group
      // Requires groupId in options
      if (!options.groupId) {
        throw new Error("groupId required for resources_per_group quota check");
      }
      const res = await query(
        `SELECT COUNT(*)::int AS count FROM group_resources
         WHERE group_id = $1 AND status = 'active'`,
        [options.groupId],
      );
      return res.rows[0]?.count || 0;
    }

    case "api_calls_per_month": {
      // Count API calls in the current billing period
      const subscription = await subscriptions.findByTenantId(tenantId);
      const periodStart = subscription?.current_period_start || getMonthStart();

      // Use the existing usage table which has tenant_id added
      const res = await query(
        `SELECT COALESCE(SUM(api_calls), 0)::int AS count
         FROM usage
         WHERE tenant_id = $1 AND date >= $2`,
        [tenantId, periodStart],
      );
      return res.rows[0]?.count || 0;
    }

    case "storage_mb": {
      // Get current storage usage in MB
      // Try dedicated tenant_storage table first, fall back to tenant settings
      try {
        const res = await query(
          `SELECT COALESCE(SUM(storage_bytes), 0)::bigint AS bytes
           FROM tenant_storage
           WHERE tenant_id = $1`,
          [tenantId],
        );
        const bytes = res.rows[0]?.bytes || 0;
        return Math.ceil(bytes / (1024 * 1024)); // Convert to MB
      } catch {
        // Table may not exist - read from tenant settings as fallback
        const res = await query(
          `SELECT COALESCE((settings->>'storage_used_mb')::int, 0) AS mb
           FROM tenants
           WHERE id = $1`,
          [tenantId],
        );
        return res.rows[0]?.mb || 0;
      }
    }

    default:
      // Unknown resource type - return 0 to avoid false blocks
      console.warn(`[quota-check] Unknown resource type: ${resource}`);
      return 0;
  }
}

/**
 * Get the start of the current month for usage tracking
 * Used as fallback when subscription has no current_period_start
 *
 * @returns {Date} Start of current month
 */
function getMonthStart() {
  const now = new Date();
  return new Date(now.getFullYear(), now.getMonth(), 1);
}

// ============================================================
// USAGE INCREMENT/DECREMENT
// ============================================================

/**
 * Increment usage counter for a resource
 * Used to track consumption after successful operations
 *
 * @param {string} tenantId - UUID of the tenant
 * @param {string} resource - Resource type
 * @param {number} amount - Amount to increment (default: 1)
 * @returns {Promise<void>}
 */
export async function incrementUsage(tenantId, resource, amount = 1) {
  if (resource === "api_calls_per_month") {
    // Use the existing usage table which has tenant_id column
    // Note: This assumes the caller's user_id is available for proper tracking
    // For tenant-level tracking, we use a dedicated query
    try {
      await query(
        `INSERT INTO usage (tenant_id, date, api_calls, input_tokens, output_tokens)
         VALUES ($1, CURRENT_DATE, $2, 0, 0)
         ON CONFLICT (tenant_id, date) WHERE user_id IS NULL
         DO UPDATE SET api_calls = usage.api_calls + $2`,
        [tenantId, amount],
      );
    } catch {
      // If conflict handling fails, try update only
      await query(
        `UPDATE usage
         SET api_calls = api_calls + $2
         WHERE tenant_id = $1 AND date = CURRENT_DATE AND user_id IS NULL`,
        [tenantId, amount],
      );
    }
  } else if (resource === "storage_mb") {
    // Storage is tracked in tenant settings as fallback
    const bytes = amount * 1024 * 1024;
    try {
      await query(
        `INSERT INTO tenant_storage (tenant_id, storage_bytes)
         VALUES ($1, $2)
         ON CONFLICT (tenant_id)
         DO UPDATE SET storage_bytes = tenant_storage.storage_bytes + $2`,
        [tenantId, bytes],
      );
    } catch {
      // Fall back to updating tenant settings
      await query(
        `UPDATE tenants
         SET settings = jsonb_set(
           COALESCE(settings, '{}'),
           '{storage_used_mb}',
           to_jsonb(COALESCE((settings->>'storage_used_mb')::int, 0) + $2)
         ),
         updated_at = NOW()
         WHERE id = $1`,
        [tenantId, amount],
      );
    }
  }
  // Other resources (users, agents, groups) are counted directly from tables
  // No need to track them separately
}

/**
 * Decrement usage counter for a resource
 * Used to track consumption after deletion operations
 *
 * @param {string} tenantId - UUID of the tenant
 * @param {string} resource - Resource type
 * @param {number} amount - Amount to decrement (default: 1)
 * @returns {Promise<void>}
 */
export async function decrementUsage(tenantId, resource, amount = 1) {
  if (resource === "storage_mb") {
    const bytes = amount * 1024 * 1024;
    try {
      await query(
        `UPDATE tenant_storage
         SET storage_bytes = GREATEST(0, storage_bytes - $2)
         WHERE tenant_id = $1`,
        [tenantId, bytes],
      );
    } catch {
      // Fall back to updating tenant settings
      await query(
        `UPDATE tenants
         SET settings = jsonb_set(
           COALESCE(settings, '{}'),
           '{storage_used_mb}',
           to_jsonb(GREATEST(0, COALESCE((settings->>'storage_used_mb')::int, 0) - $2))
         ),
         updated_at = NOW()
         WHERE id = $1`,
        [tenantId, amount],
      );
    }
  }
  // API calls don't decrement
  // Other resources are counted directly from tables
}

// ============================================================
// QUOTA CHECK MIDDLEWARE
// ============================================================

/**
 * Middleware factory to check quota before allowing an operation
 * Returns 402 Payment Required if quota would be exceeded
 *
 * @param {string} resource - Resource type from TRACKABLE_RESOURCES
 * @param {object} options - Optional configuration
 * @param {function} options.getContext - Function to extract context from request (e.g., groupId)
 * @param {number} options.increment - Amount being added (default: 1)
 * @returns {function} Express middleware function
 */
export function checkQuota(resource, options = {}) {
  const { getContext = () => ({}), increment = 1 } = options;

  return async function quotaCheckMiddleware(req, res, next) {
    // Require tenant context
    if (!req.tenant || !req.tenantId) {
      return res.status(403).json({
        error: "Tenant context required",
        code: "TENANT_REQUIRED",
        message: "Quota check requires tenant context",
      });
    }

    try {
      // Get subscription and plan
      const subscription = await subscriptions.findByTenantId(req.tenantId);
      const plan = subscription?.plan || "free";

      // Check if unlimited for this resource
      if (isUnlimited(plan, resource)) {
        return next();
      }

      // Get context from request (e.g., groupId for resources_per_group)
      const context = getContext(req);

      // Count current usage
      const currentUsage = await countUsage(req.tenantId, resource, context);

      // Check if adding would exceed quota
      const quotaCheck = checkQuotaForAdd(plan, resource, currentUsage, increment);

      if (!quotaCheck.allowed) {
        // Quota exceeded - return 402 Payment Required
        const response = createQuotaExceededResponse(
          resource,
          quotaCheck.limit,
          quotaCheck.current,
        );

        return res.status(402).json(response);
      }

      // Attach quota info to request for downstream use
      req.quotaInfo = {
        resource,
        plan,
        limit: quotaCheck.limit,
        current: quotaCheck.current,
        remaining: quotaCheck.remaining,
        wouldUse: quotaCheck.wouldUse,
      };

      next();
    } catch (err) {
      console.error("[quota-check] Error checking quota:", err);
      // Fail open on errors to avoid blocking legitimate requests
      // Log for monitoring
      next();
    }
  };
}

// ============================================================
// PRE-CONFIGURED MIDDLEWARE
// ============================================================

/**
 * Check users quota before adding a user to the tenant
 */
export const checkUsersQuota = checkQuota("users");

/**
 * Check agents quota before creating a new agent
 */
export const checkAgentsQuota = checkQuota("agents");

/**
 * Check groups quota before creating a new group
 */
export const checkGroupsQuota = checkQuota("groups");

/**
 * Check API calls quota before processing an API request
 * Typically used on rate-limited endpoints
 */
export const checkApiQuota = checkQuota("api_calls_per_month");

/**
 * Check storage quota before uploading files
 * Accepts options.getSize to calculate storage increment from request
 *
 * @param {object} options - Configuration options
 * @param {function} options.getSize - Function to get size in MB from request
 * @returns {function} Express middleware function
 */
export function checkStorageQuota(options = {}) {
  const { getSize = () => 1 } = options;

  return checkQuota("storage_mb", {
    increment: 1, // Will be overridden per-request
    getContext: (req) => {
      // Calculate storage increment from request
      const sizeMb = getSize(req);
      return { increment: sizeMb };
    },
  });
}

/**
 * Check resources per group quota before adding a resource
 * Extracts groupId from request params or body
 */
export const checkResourcesPerGroupQuota = checkQuota("resources_per_group", {
  getContext: (req) => ({
    groupId: req.params.groupId || req.body?.groupId,
  }),
});

// ============================================================
// API CALL TRACKING MIDDLEWARE
// ============================================================

/**
 * Middleware to track API calls after successful responses
 * Use this after routes to increment usage counter
 *
 * @param {object} req - Express request object
 * @param {object} res - Express response object
 * @param {function} next - Next middleware function
 */
export async function trackApiCall(req, res, next) {
  // Store original end function
  const originalEnd = res.end;

  // Override end to track after response
  res.end = function (...args) {
    // Only track successful responses (2xx)
    if (res.statusCode >= 200 && res.statusCode < 300) {
      // Track asynchronously - don't block response
      if (req.tenantId) {
        incrementUsage(req.tenantId, "api_calls_per_month", 1).catch((err) => {
          console.error("[quota-check] Error tracking API call:", err);
        });
      }
    }

    // Call original end
    return originalEnd.apply(this, args);
  };

  next();
}

// ============================================================
// QUOTA INFO ENDPOINT HELPER
// ============================================================

/**
 * Get current quota usage for all resources
 * Useful for dashboard/billing pages
 *
 * @param {string} tenantId - UUID of the tenant
 * @param {string} plan - Current plan name
 * @returns {Promise<object[]>} Array of resource usage info
 */
export async function getQuotaUsage(tenantId, plan) {
  const usage = [];

  for (const resource of TRACKABLE_RESOURCES) {
    try {
      const current = await countUsage(tenantId, resource);
      const limit = getLimit(plan, resource);
      const unlimited = limit === -1;

      usage.push({
        resource,
        current,
        limit,
        unlimited,
        percentage: unlimited ? -1 : Math.min(100, Math.round((current / limit) * 100)),
        available: unlimited ? -1 : Math.max(0, limit - current),
      });
    } catch (err) {
      // Skip resources that fail (e.g., missing tables)
      console.warn(`[quota-check] Error counting ${resource}:`, err.message);
    }
  }

  return usage;
}

// ============================================================
// DEFAULT EXPORT
// ============================================================

export default {
  // Core functions
  countUsage,
  incrementUsage,
  decrementUsage,
  checkQuota,
  getQuotaUsage,

  // Pre-configured middleware
  checkUsersQuota,
  checkAgentsQuota,
  checkGroupsQuota,
  checkApiQuota,
  checkStorageQuota,
  checkResourcesPerGroupQuota,

  // Tracking middleware
  trackApiCall,
};
