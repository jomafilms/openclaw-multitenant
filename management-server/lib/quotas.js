/**
 * Quota definitions and utilities for multi-tenant SaaS
 *
 * Provides:
 * - Plan definitions with resource limits
 * - Utility functions for quota checking
 * - Error formatting for quota exceeded responses
 */

// ============================================================
// PLAN DEFINITIONS
// ============================================================

/**
 * Available subscription plans with their resource limits
 * Limit of -1 means unlimited
 */
export const PLANS = {
  free: {
    name: "Free",
    limits: {
      users: 3,
      agents: 1,
      api_calls_per_month: 1000,
      storage_mb: 100,
      groups: 1,
      resources_per_group: 5,
    },
  },
  pro: {
    name: "Pro",
    limits: {
      users: 25,
      agents: 5,
      api_calls_per_month: 50000,
      storage_mb: 5000,
      groups: 10,
      resources_per_group: 50,
    },
  },
  enterprise: {
    name: "Enterprise",
    limits: {
      users: -1, // unlimited
      agents: -1,
      api_calls_per_month: -1,
      storage_mb: -1,
      groups: -1,
      resources_per_group: -1,
    },
  },
};

/**
 * Plan tier order for comparison (lower index = lower tier)
 */
const PLAN_TIERS = ["free", "pro", "enterprise"];

/**
 * List of all trackable resources
 */
export const TRACKABLE_RESOURCES = [
  "users",
  "agents",
  "api_calls_per_month",
  "storage_mb",
  "groups",
  "resources_per_group",
];

/**
 * Human-readable labels for resources
 */
export const RESOURCE_LABELS = {
  users: "Users",
  agents: "Agents",
  api_calls_per_month: "API calls per month",
  storage_mb: "Storage (MB)",
  groups: "Groups",
  resources_per_group: "Resources per group",
};

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

/**
 * Get plan by name
 * Returns the free plan if the specified plan is not found
 *
 * @param {string} planName - Name of the plan to retrieve
 * @returns {object} Plan object with name and limits
 */
export function getPlan(planName) {
  const plan = PLANS[planName?.toLowerCase()];
  if (!plan) {
    return PLANS.free;
  }
  return plan;
}

/**
 * Get specific limit for a plan and resource
 * Returns -1 if unlimited, or the limit value otherwise
 *
 * @param {string} planName - Name of the plan
 * @param {string} resource - Resource type from TRACKABLE_RESOURCES
 * @returns {number} The limit value, or -1 if unlimited
 */
export function getLimit(planName, resource) {
  const plan = getPlan(planName);
  const limit = plan.limits[resource];

  // Return -1 for unknown resources (treat as unlimited to avoid false blocks)
  if (limit === undefined) {
    return -1;
  }

  return limit;
}

/**
 * Check if a resource is unlimited for a given plan
 *
 * @param {string} planName - Name of the plan
 * @param {string} resource - Resource type from TRACKABLE_RESOURCES
 * @returns {boolean} True if the resource is unlimited
 */
export function isUnlimited(planName, resource) {
  return getLimit(planName, resource) === -1;
}

/**
 * Compare two plans by tier level
 * Returns negative if plan1 < plan2, positive if plan1 > plan2, zero if equal
 *
 * @param {string} plan1 - First plan name
 * @param {string} plan2 - Second plan name
 * @returns {number} Comparison result (-1, 0, or 1)
 */
export function comparePlans(plan1, plan2) {
  const tier1 = PLAN_TIERS.indexOf(plan1?.toLowerCase() || "free");
  const tier2 = PLAN_TIERS.indexOf(plan2?.toLowerCase() || "free");

  // Unknown plans are treated as free tier
  const safeTier1 = tier1 === -1 ? 0 : tier1;
  const safeTier2 = tier2 === -1 ? 0 : tier2;

  if (safeTier1 < safeTier2) return -1;
  if (safeTier1 > safeTier2) return 1;
  return 0;
}

/**
 * Check if a plan is at least a certain tier
 *
 * @param {string} planName - Plan to check
 * @param {string} requiredPlan - Minimum required plan
 * @returns {boolean} True if planName >= requiredPlan
 */
export function isAtLeastPlan(planName, requiredPlan) {
  return comparePlans(planName, requiredPlan) >= 0;
}

// ============================================================
// QUOTA CHECKING
// ============================================================

/**
 * Check if an operation is allowed based on quota
 *
 * @param {string} planName - Current plan name
 * @param {string} resource - Resource type to check
 * @param {number} currentUsage - Current usage count
 * @returns {object} Result with { allowed, limit, current, remaining }
 */
export function checkQuota(planName, resource, currentUsage) {
  const limit = getLimit(planName, resource);
  const current = Math.max(0, currentUsage);

  // Unlimited resource
  if (limit === -1) {
    return {
      allowed: true,
      limit: -1,
      current,
      remaining: -1, // -1 indicates unlimited remaining
      unlimited: true,
    };
  }

  const remaining = Math.max(0, limit - current);
  const allowed = current < limit;

  return {
    allowed,
    limit,
    current,
    remaining,
    unlimited: false,
  };
}

/**
 * Check if adding N items would exceed quota
 *
 * @param {string} planName - Current plan name
 * @param {string} resource - Resource type to check
 * @param {number} currentUsage - Current usage count
 * @param {number} toAdd - Number of items to add (default: 1)
 * @returns {object} Result with { allowed, limit, current, remaining, wouldUse }
 */
export function checkQuotaForAdd(planName, resource, currentUsage, toAdd = 1) {
  const limit = getLimit(planName, resource);
  const current = Math.max(0, currentUsage);
  const wouldUse = current + toAdd;

  // Unlimited resource
  if (limit === -1) {
    return {
      allowed: true,
      limit: -1,
      current,
      remaining: -1,
      wouldUse,
      unlimited: true,
    };
  }

  const remaining = Math.max(0, limit - current);
  const allowed = wouldUse <= limit;

  return {
    allowed,
    limit,
    current,
    remaining,
    wouldUse,
    unlimited: false,
  };
}

// ============================================================
// ERROR FORMATTING
// ============================================================

/**
 * Format an error message for quota exceeded
 *
 * @param {string} resource - Resource type that exceeded quota
 * @param {number} limit - The limit that was exceeded
 * @param {number} current - Current usage
 * @returns {string} Formatted error message
 */
export function formatQuotaError(resource, limit, current) {
  const label = RESOURCE_LABELS[resource] || resource;
  return `Quota exceeded for ${label}: using ${current} of ${limit} allowed`;
}

/**
 * Create a quota exceeded response object
 * Suitable for returning as JSON response
 *
 * @param {string} resource - Resource type that exceeded quota
 * @param {number} limit - The limit that was exceeded
 * @param {number} current - Current usage
 * @returns {object} Response object for client
 */
export function createQuotaExceededResponse(resource, limit, current) {
  return {
    error: "Quota exceeded",
    code: "QUOTA_EXCEEDED",
    resource,
    limit,
    current,
    message: formatQuotaError(resource, limit, current),
    upgrade_url: "/billing/upgrade",
  };
}

// ============================================================
// USAGE HELPERS
// ============================================================

/**
 * Get usage percentage for a resource
 *
 * @param {string} planName - Current plan name
 * @param {string} resource - Resource type
 * @param {number} currentUsage - Current usage count
 * @returns {number} Usage percentage (0-100), or -1 if unlimited
 */
export function getUsagePercentage(planName, resource, currentUsage) {
  const limit = getLimit(planName, resource);

  if (limit === -1) {
    return -1; // Unlimited
  }

  if (limit === 0) {
    return currentUsage > 0 ? 100 : 0;
  }

  return Math.min(100, Math.round((currentUsage / limit) * 100));
}

/**
 * Check if usage is approaching the limit (>80%)
 *
 * @param {string} planName - Current plan name
 * @param {string} resource - Resource type
 * @param {number} currentUsage - Current usage count
 * @returns {boolean} True if usage is above 80% of limit
 */
export function isApproachingLimit(planName, resource, currentUsage) {
  const percentage = getUsagePercentage(planName, resource, currentUsage);
  return percentage !== -1 && percentage >= 80;
}

/**
 * Get all limits for a plan as a structured object
 *
 * @param {string} planName - Plan name
 * @returns {object} Object with all resource limits and their labels
 */
export function getPlanLimits(planName) {
  const plan = getPlan(planName);

  return TRACKABLE_RESOURCES.map((resource) => ({
    resource,
    label: RESOURCE_LABELS[resource] || resource,
    limit: plan.limits[resource],
    unlimited: plan.limits[resource] === -1,
  }));
}

// ============================================================
// EXPORTS
// ============================================================

export default {
  // Plan definitions
  PLANS,
  PLAN_TIERS,
  TRACKABLE_RESOURCES,
  RESOURCE_LABELS,

  // Utility functions
  getPlan,
  getLimit,
  isUnlimited,
  comparePlans,
  isAtLeastPlan,

  // Quota checking
  checkQuota,
  checkQuotaForAdd,

  // Error formatting
  formatQuotaError,
  createQuotaExceededResponse,

  // Usage helpers
  getUsagePercentage,
  isApproachingLimit,
  getPlanLimits,
};
