/**
 * Tenant health monitoring module for multi-tenant SaaS
 *
 * Wave 4.7 - Provides health metrics, monitoring, and alerting for tenants
 *
 * Features:
 * - Per-tenant health metrics (response times, error rates, container status)
 * - Health check functions (checkTenantHealth, getTenantStatus, getAllTenantHealth)
 * - Alerting thresholds (degraded, unhealthy)
 * - Background monitoring with configurable intervals
 * - Health dashboard data aggregation
 * - Redis or in-memory storage for metrics history
 */

import { tenants, subscriptions } from "../db/index.js";
import { getUsagePercentage } from "./quotas.js";
import { getRedisClient, isRedisConnected } from "./redis.js";

// ============================================================
// CONSTANTS
// ============================================================

// Health status levels
export const HEALTH_STATUS = {
  HEALTHY: "healthy",
  DEGRADED: "degraded",
  UNHEALTHY: "unhealthy",
  UNKNOWN: "unknown",
};

// Container states
export const CONTAINER_STATE = {
  RUNNING: "running",
  PAUSED: "paused",
  STOPPED: "stopped",
  UNHEALTHY: "unhealthy",
  NOT_FOUND: "not_found",
};

// Alerting thresholds
export const THRESHOLDS = {
  // Error rate thresholds
  ERROR_RATE_DEGRADED: 0.05, // 5%
  ERROR_RATE_UNHEALTHY: 0.2, // 20%

  // Response time thresholds (milliseconds)
  RESPONSE_TIME_P95_DEGRADED: 2000, // 2 seconds
  RESPONSE_TIME_P95_UNHEALTHY: 5000, // 5 seconds

  // Storage thresholds
  STORAGE_WARNING: 0.8, // 80%
  STORAGE_CRITICAL: 0.9, // 90%

  // Quota thresholds
  QUOTA_WARNING: 0.8, // 80%
  QUOTA_CRITICAL: 0.95, // 95%
};

// Metrics storage configuration
const METRICS_HISTORY_HOURS = 24;
const METRICS_BUCKET_MINUTES = 5; // Store metrics in 5-minute buckets
const METRICS_BUCKETS_PER_HOUR = 60 / METRICS_BUCKET_MINUTES;
const MAX_METRICS_BUCKETS = METRICS_HISTORY_HOURS * METRICS_BUCKETS_PER_HOUR;

// Redis key prefix
const REDIS_PREFIX = "ocmt:health";

// ============================================================
// IN-MEMORY STORAGE (FALLBACK)
// ============================================================

// In-memory stores for when Redis is unavailable
const metricsStore = new Map(); // tenantId -> MetricsBucket[]
const healthCache = new Map(); // tenantId -> { health, updatedAt }

// ============================================================
// METRICS DATA STRUCTURES
// ============================================================

/**
 * Create a new metrics bucket for a time window
 */
function createMetricsBucket(timestamp = Date.now()) {
  const bucketStart = getBucketTimestamp(timestamp);
  return {
    timestamp: bucketStart,
    requests: {
      total: 0,
      errors: 0,
      responseTimes: [], // Array of response times for percentile calculation
    },
    container: {
      state: null,
      lastChecked: null,
    },
    sessions: {
      active: 0,
    },
  };
}

/**
 * Get bucket timestamp (rounded to METRICS_BUCKET_MINUTES)
 */
function getBucketTimestamp(timestamp) {
  const ms = METRICS_BUCKET_MINUTES * 60 * 1000;
  return Math.floor(timestamp / ms) * ms;
}

/**
 * Get current metrics bucket for a tenant (creates if needed)
 */
function getCurrentBucket(tenantId) {
  const now = Date.now();
  const bucketTime = getBucketTimestamp(now);

  let buckets = metricsStore.get(tenantId);
  if (!buckets) {
    buckets = [];
    metricsStore.set(tenantId, buckets);
  }

  // Check if current bucket exists
  let currentBucket = buckets.find((b) => b.timestamp === bucketTime);
  if (!currentBucket) {
    currentBucket = createMetricsBucket(now);
    buckets.push(currentBucket);

    // Prune old buckets
    const cutoff = now - METRICS_HISTORY_HOURS * 60 * 60 * 1000;
    metricsStore.set(
      tenantId,
      buckets.filter((b) => b.timestamp >= cutoff),
    );
  }

  return currentBucket;
}

// ============================================================
// METRICS COLLECTION
// ============================================================

/**
 * Record an API request for a tenant
 * Call this from request middleware to track response times and errors
 *
 * @param {string} tenantId - Tenant UUID
 * @param {number} responseTimeMs - Response time in milliseconds
 * @param {boolean} isError - Whether the request resulted in an error (5xx)
 */
export function recordRequest(tenantId, responseTimeMs, isError = false) {
  if (!tenantId) {
    return;
  }

  const bucket = getCurrentBucket(tenantId);
  bucket.requests.total++;

  if (isError) {
    bucket.requests.errors++;
  }

  // Store response time (limit array size for memory)
  if (bucket.requests.responseTimes.length < 1000) {
    bucket.requests.responseTimes.push(responseTimeMs);
  }

  // Also persist to Redis if available
  if (isRedisConnected()) {
    persistMetricToRedis(tenantId, responseTimeMs, isError).catch((err) => {
      console.warn(`[tenant-health] Redis persist error: ${err.message}`);
    });
  }
}

/**
 * Record container status for a tenant
 * @param {string} tenantId - Tenant UUID
 * @param {string} state - Container state (running, paused, stopped, unhealthy)
 */
export function recordContainerStatus(tenantId, state) {
  if (!tenantId) {
    return;
  }

  const bucket = getCurrentBucket(tenantId);
  bucket.container.state = state;
  bucket.container.lastChecked = Date.now();
}

/**
 * Record active sessions count for a tenant
 * @param {string} tenantId - Tenant UUID
 * @param {number} count - Number of active sessions
 */
export function recordActiveSessions(tenantId, count) {
  if (!tenantId) {
    return;
  }

  const bucket = getCurrentBucket(tenantId);
  bucket.sessions.active = count;
}

/**
 * Persist metric to Redis (for distributed deployments)
 */
async function persistMetricToRedis(tenantId, responseTimeMs, isError) {
  const redis = getRedisClient();
  if (!redis) {
    return;
  }

  const bucketTime = getBucketTimestamp(Date.now());
  const key = `${REDIS_PREFIX}:${tenantId}:${bucketTime}`;

  try {
    await redis
      .multi()
      .hincrby(key, "total", 1)
      .hincrby(key, "errors", isError ? 1 : 0)
      .rpush(`${key}:rt`, responseTimeMs)
      .expire(key, METRICS_HISTORY_HOURS * 3600 + 600) // TTL: 24h + 10min buffer
      .expire(`${key}:rt`, METRICS_HISTORY_HOURS * 3600 + 600)
      .exec();
  } catch (err) {
    console.warn(`[tenant-health] Redis error: ${err.message}`);
  }
}

// ============================================================
// PERCENTILE CALCULATION
// ============================================================

/**
 * Calculate percentile from an array of values
 * @param {number[]} values - Array of values
 * @param {number} percentile - Percentile to calculate (0-100)
 * @returns {number} Percentile value or 0 if no values
 */
function calculatePercentile(values, percentile) {
  if (!values || values.length === 0) {
    return 0;
  }

  const sorted = [...values].toSorted((a, b) => a - b);
  const index = Math.ceil((percentile / 100) * sorted.length) - 1;
  return sorted[Math.max(0, index)];
}

// ============================================================
// HEALTH CHECK FUNCTIONS
// ============================================================

/**
 * Get aggregated metrics for a tenant over a time range
 * @param {string} tenantId - Tenant UUID
 * @param {number} hoursBack - Number of hours to look back (default: 1)
 * @returns {object} Aggregated metrics
 */
export function getAggregatedMetrics(tenantId, hoursBack = 1) {
  const buckets = metricsStore.get(tenantId) || [];
  const cutoff = Date.now() - hoursBack * 60 * 60 * 1000;

  const relevantBuckets = buckets.filter((b) => b.timestamp >= cutoff);

  if (relevantBuckets.length === 0) {
    return {
      requests: { total: 0, errors: 0, errorRate: 0 },
      responseTimes: { p50: 0, p95: 0, p99: 0 },
      container: { state: CONTAINER_STATE.NOT_FOUND, lastChecked: null },
      sessions: { active: 0 },
    };
  }

  // Aggregate request counts
  let totalRequests = 0;
  let totalErrors = 0;
  const allResponseTimes = [];

  for (const bucket of relevantBuckets) {
    totalRequests += bucket.requests.total;
    totalErrors += bucket.requests.errors;
    allResponseTimes.push(...bucket.requests.responseTimes);
  }

  // Get latest container and session info
  const latestBucket = relevantBuckets[relevantBuckets.length - 1];

  return {
    requests: {
      total: totalRequests,
      errors: totalErrors,
      errorRate: totalRequests > 0 ? totalErrors / totalRequests : 0,
    },
    responseTimes: {
      p50: calculatePercentile(allResponseTimes, 50),
      p95: calculatePercentile(allResponseTimes, 95),
      p99: calculatePercentile(allResponseTimes, 99),
    },
    container: {
      state: latestBucket.container.state || CONTAINER_STATE.NOT_FOUND,
      lastChecked: latestBucket.container.lastChecked,
    },
    sessions: {
      active: latestBucket.sessions.active || 0,
    },
  };
}

/**
 * Perform a full health check for a tenant
 *
 * @param {string} tenantId - Tenant UUID
 * @param {object} options - Optional configuration
 * @param {object} options.containerStatusFn - Function to get container status (tenantId) => state
 * @param {object} options.storageUsageFn - Function to get storage usage (tenantId) => { used, total }
 * @param {object} options.quotaUsageFn - Function to get quota usage (tenantId, resource) => percentage
 * @returns {Promise<object>} Full health status object
 */
export async function checkTenantHealth(tenantId, options = {}) {
  const { containerStatusFn, storageUsageFn, quotaUsageFn } = options;

  // Get tenant and subscription info
  const [tenant, subscription] = await Promise.all([
    tenants.findById(tenantId),
    subscriptions.findByTenantId(tenantId),
  ]);

  if (!tenant) {
    return {
      tenantId,
      status: HEALTH_STATUS.UNKNOWN,
      error: "Tenant not found",
      timestamp: Date.now(),
    };
  }

  // Get aggregated metrics
  const metrics = getAggregatedMetrics(tenantId, 1); // Last hour

  // Get container status if function provided
  let containerState = metrics.container.state;
  if (containerStatusFn) {
    try {
      containerState = await containerStatusFn(tenantId);
      recordContainerStatus(tenantId, containerState);
    } catch (err) {
      console.warn(`[tenant-health] Container status check failed: ${err.message}`);
    }
  }

  // Get storage usage if function provided
  let storageUsage = null;
  if (storageUsageFn) {
    try {
      storageUsage = await storageUsageFn(tenantId);
    } catch (err) {
      console.warn(`[tenant-health] Storage usage check failed: ${err.message}`);
    }
  }

  // Get quota usage if function provided
  let quotaUsage = {};
  if (quotaUsageFn) {
    try {
      const resources = ["users", "agents", "api_calls_per_month", "groups"];
      for (const resource of resources) {
        quotaUsage[resource] = await quotaUsageFn(tenantId, resource);
      }
    } catch (err) {
      console.warn(`[tenant-health] Quota usage check failed: ${err.message}`);
    }
  }

  // Collect issues
  const issues = [];

  // Check error rate
  if (metrics.requests.errorRate >= THRESHOLDS.ERROR_RATE_UNHEALTHY) {
    issues.push({
      type: "error_rate",
      severity: "critical",
      message: `Error rate is ${(metrics.requests.errorRate * 100).toFixed(1)}% (threshold: ${THRESHOLDS.ERROR_RATE_UNHEALTHY * 100}%)`,
      value: metrics.requests.errorRate,
    });
  } else if (metrics.requests.errorRate >= THRESHOLDS.ERROR_RATE_DEGRADED) {
    issues.push({
      type: "error_rate",
      severity: "warning",
      message: `Error rate is ${(metrics.requests.errorRate * 100).toFixed(1)}% (threshold: ${THRESHOLDS.ERROR_RATE_DEGRADED * 100}%)`,
      value: metrics.requests.errorRate,
    });
  }

  // Check response times
  if (metrics.responseTimes.p95 >= THRESHOLDS.RESPONSE_TIME_P95_UNHEALTHY) {
    issues.push({
      type: "response_time",
      severity: "critical",
      message: `P95 response time is ${metrics.responseTimes.p95}ms (threshold: ${THRESHOLDS.RESPONSE_TIME_P95_UNHEALTHY}ms)`,
      value: metrics.responseTimes.p95,
    });
  } else if (metrics.responseTimes.p95 >= THRESHOLDS.RESPONSE_TIME_P95_DEGRADED) {
    issues.push({
      type: "response_time",
      severity: "warning",
      message: `P95 response time is ${metrics.responseTimes.p95}ms (threshold: ${THRESHOLDS.RESPONSE_TIME_P95_DEGRADED}ms)`,
      value: metrics.responseTimes.p95,
    });
  }

  // Check container status
  if (
    containerState === CONTAINER_STATE.UNHEALTHY ||
    containerState === CONTAINER_STATE.NOT_FOUND
  ) {
    issues.push({
      type: "container",
      severity: "critical",
      message: `Container is ${containerState}`,
      value: containerState,
    });
  } else if (containerState === CONTAINER_STATE.STOPPED) {
    issues.push({
      type: "container",
      severity: "warning",
      message: "Container is stopped (hibernating)",
      value: containerState,
    });
  }

  // Check storage
  if (storageUsage) {
    const storagePercent = storageUsage.total > 0 ? storageUsage.used / storageUsage.total : 0;
    if (storagePercent >= THRESHOLDS.STORAGE_CRITICAL) {
      issues.push({
        type: "storage",
        severity: "critical",
        message: `Storage usage is ${(storagePercent * 100).toFixed(1)}% (threshold: ${THRESHOLDS.STORAGE_CRITICAL * 100}%)`,
        value: storagePercent,
      });
    } else if (storagePercent >= THRESHOLDS.STORAGE_WARNING) {
      issues.push({
        type: "storage",
        severity: "warning",
        message: `Storage usage is ${(storagePercent * 100).toFixed(1)}% (threshold: ${THRESHOLDS.STORAGE_WARNING * 100}%)`,
        value: storagePercent,
      });
    }
  }

  // Check quotas
  for (const [resource, percentage] of Object.entries(quotaUsage)) {
    if (percentage === -1) {
      continue;
    } // Unlimited

    if (percentage >= THRESHOLDS.QUOTA_CRITICAL * 100) {
      issues.push({
        type: "quota",
        severity: "critical",
        message: `${resource} quota is ${percentage}% (threshold: ${THRESHOLDS.QUOTA_CRITICAL * 100}%)`,
        resource,
        value: percentage,
      });
    } else if (percentage >= THRESHOLDS.QUOTA_WARNING * 100) {
      issues.push({
        type: "quota",
        severity: "warning",
        message: `${resource} quota is ${percentage}% (threshold: ${THRESHOLDS.QUOTA_WARNING * 100}%)`,
        resource,
        value: percentage,
      });
    }
  }

  // Determine overall status
  const hasCritical = issues.some((i) => i.severity === "critical");
  const hasWarning = issues.some((i) => i.severity === "warning");

  let status;
  if (hasCritical) {
    status = HEALTH_STATUS.UNHEALTHY;
  } else if (hasWarning) {
    status = HEALTH_STATUS.DEGRADED;
  } else {
    status = HEALTH_STATUS.HEALTHY;
  }

  const health = {
    tenantId,
    tenantName: tenant.name,
    tenantSlug: tenant.slug,
    status,
    issues,
    metrics: {
      requests: metrics.requests,
      responseTimes: metrics.responseTimes,
      container: {
        state: containerState,
        lastChecked: metrics.container.lastChecked,
      },
      sessions: metrics.sessions,
      storage: storageUsage,
      quota: quotaUsage,
    },
    subscription: subscription
      ? {
          plan: subscription.plan,
          status: subscription.status,
        }
      : null,
    timestamp: Date.now(),
  };

  // Cache health result
  healthCache.set(tenantId, {
    health,
    updatedAt: Date.now(),
  });

  return health;
}

/**
 * Get quick status for a tenant (uses cache if available)
 *
 * @param {string} tenantId - Tenant UUID
 * @param {number} maxAgeMs - Max age of cached result (default: 60000 = 1 minute)
 * @returns {string} Health status (healthy, degraded, unhealthy, unknown)
 */
export function getTenantStatus(tenantId, maxAgeMs = 60000) {
  const cached = healthCache.get(tenantId);
  if (cached && Date.now() - cached.updatedAt < maxAgeMs) {
    return cached.health.status;
  }

  // Quick check based on metrics only
  const metrics = getAggregatedMetrics(tenantId, 1);

  if (metrics.requests.total === 0) {
    return HEALTH_STATUS.UNKNOWN;
  }

  if (
    metrics.requests.errorRate >= THRESHOLDS.ERROR_RATE_UNHEALTHY ||
    metrics.container.state === CONTAINER_STATE.UNHEALTHY
  ) {
    return HEALTH_STATUS.UNHEALTHY;
  }

  if (
    metrics.requests.errorRate >= THRESHOLDS.ERROR_RATE_DEGRADED ||
    metrics.responseTimes.p95 >= THRESHOLDS.RESPONSE_TIME_P95_DEGRADED ||
    metrics.container.state === CONTAINER_STATE.STOPPED
  ) {
    return HEALTH_STATUS.DEGRADED;
  }

  return HEALTH_STATUS.HEALTHY;
}

/**
 * Get health summary for all tenants
 *
 * @param {object} options - Optional configuration
 * @param {boolean} options.includeDetails - Include full health details (default: false)
 * @param {object} options.containerStatusFn - Function to get container status
 * @returns {Promise<object>} Health summary for all tenants
 */
export async function getAllTenantHealth(options = {}) {
  const { includeDetails = false, containerStatusFn } = options;

  // Get all active tenants
  const allTenants = await tenants.list({ status: "active", limit: 1000 });

  const results = [];
  const summary = {
    total: allTenants.length,
    healthy: 0,
    degraded: 0,
    unhealthy: 0,
    unknown: 0,
  };

  for (const tenant of allTenants) {
    let health;
    if (includeDetails) {
      health = await checkTenantHealth(tenant.id, { containerStatusFn });
    } else {
      const status = getTenantStatus(tenant.id);
      health = {
        tenantId: tenant.id,
        tenantName: tenant.name,
        tenantSlug: tenant.slug,
        status,
      };
    }

    results.push(health);

    // Update summary counts
    switch (health.status) {
      case HEALTH_STATUS.HEALTHY:
        summary.healthy++;
        break;
      case HEALTH_STATUS.DEGRADED:
        summary.degraded++;
        break;
      case HEALTH_STATUS.UNHEALTHY:
        summary.unhealthy++;
        break;
      default:
        summary.unknown++;
    }
  }

  return {
    summary,
    tenants: results,
    timestamp: Date.now(),
  };
}

// ============================================================
// HEALTH DASHBOARD
// ============================================================

/**
 * Get health dashboard data for admin UI
 *
 * @param {object} options - Optional configuration
 * @param {number} options.topIssuesLimit - Max number of top issues to return (default: 10)
 * @returns {Promise<object>} Dashboard data
 */
export async function getHealthDashboard(options = {}) {
  const { topIssuesLimit = 10 } = options;

  // Get all tenant health (without full details for performance)
  const allHealth = await getAllTenantHealth({ includeDetails: true });

  // Collect all issues across tenants
  const allIssues = [];
  for (const health of allHealth.tenants) {
    if (health.issues) {
      for (const issue of health.issues) {
        allIssues.push({
          tenantId: health.tenantId,
          tenantName: health.tenantName,
          tenantSlug: health.tenantSlug,
          ...issue,
        });
      }
    }
  }

  // Sort issues by severity (critical first) and timestamp
  allIssues.sort((a, b) => {
    const severityOrder = { critical: 0, warning: 1 };
    return (severityOrder[a.severity] || 2) - (severityOrder[b.severity] || 2);
  });

  // Get top issues
  const topIssues = allIssues.slice(0, topIssuesLimit);

  // Calculate aggregate metrics
  let totalRequests = 0;
  let totalErrors = 0;
  const responseTimesSamples = [];

  for (const health of allHealth.tenants) {
    if (health.metrics) {
      totalRequests += health.metrics.requests?.total || 0;
      totalErrors += health.metrics.requests?.errors || 0;
      if (health.metrics.responseTimes?.p95 > 0) {
        responseTimesSamples.push(health.metrics.responseTimes.p95);
      }
    }
  }

  return {
    summary: allHealth.summary,
    topIssues,
    aggregateMetrics: {
      totalRequests,
      totalErrors,
      errorRate: totalRequests > 0 ? totalErrors / totalRequests : 0,
      avgP95ResponseTime:
        responseTimesSamples.length > 0
          ? responseTimesSamples.reduce((a, b) => a + b, 0) / responseTimesSamples.length
          : 0,
    },
    issuesByType: allIssues.reduce((acc, issue) => {
      acc[issue.type] = (acc[issue.type] || 0) + 1;
      return acc;
    }, {}),
    timestamp: Date.now(),
  };
}

// ============================================================
// BACKGROUND MONITORING
// ============================================================

let monitorInterval = null;
let monitorIntervalMs = 60000; // Default: 1 minute

/**
 * Start background health monitoring
 *
 * @param {number} intervalMs - Check interval in milliseconds (default: 60000)
 * @param {object} options - Optional configuration
 * @param {object} options.containerStatusFn - Function to get container status
 * @param {object} options.onHealthChange - Callback when health status changes (tenantId, oldStatus, newStatus, health)
 * @param {object} options.onIssueDetected - Callback when new issue detected (tenantId, issue, health)
 */
export function startHealthMonitor(intervalMs = 60000, options = {}) {
  if (monitorInterval) {
    console.log("[tenant-health] Health monitor already running");
    return;
  }

  monitorIntervalMs = intervalMs;
  const { containerStatusFn, onHealthChange, onIssueDetected } = options;

  console.log(`[tenant-health] Starting health monitor (interval: ${intervalMs}ms)`);

  // Track previous statuses for change detection
  const previousStatuses = new Map();

  async function runHealthCheck() {
    try {
      const allTenants = await tenants.list({ status: "active", limit: 1000 });

      for (const tenant of allTenants) {
        try {
          const previousStatus = previousStatuses.get(tenant.id);
          const health = await checkTenantHealth(tenant.id, { containerStatusFn });

          // Check for status change
          if (previousStatus && previousStatus !== health.status && onHealthChange) {
            try {
              await onHealthChange(tenant.id, previousStatus, health.status, health);
            } catch (err) {
              console.error(`[tenant-health] onHealthChange callback error: ${err.message}`);
            }
          }

          // Check for new critical issues
          if (health.issues && onIssueDetected) {
            for (const issue of health.issues) {
              if (issue.severity === "critical") {
                try {
                  await onIssueDetected(tenant.id, issue, health);
                } catch (err) {
                  console.error(`[tenant-health] onIssueDetected callback error: ${err.message}`);
                }
              }
            }
          }

          previousStatuses.set(tenant.id, health.status);
        } catch (err) {
          console.error(
            `[tenant-health] Health check failed for tenant ${tenant.id}: ${err.message}`,
          );
        }
      }
    } catch (err) {
      console.error(`[tenant-health] Monitor iteration error: ${err.message}`);
    }
  }

  // Run initial check
  runHealthCheck();

  // Set up interval
  monitorInterval = setInterval(runHealthCheck, intervalMs);
  monitorInterval.unref(); // Don't prevent process exit
}

/**
 * Stop background health monitoring
 */
export function stopHealthMonitor() {
  if (monitorInterval) {
    clearInterval(monitorInterval);
    monitorInterval = null;
    console.log("[tenant-health] Health monitor stopped");
  }
}

/**
 * Check if health monitor is running
 * @returns {boolean} True if monitor is running
 */
export function isMonitorRunning() {
  return monitorInterval !== null;
}

/**
 * Get monitor status
 * @returns {object} Monitor status info
 */
export function getMonitorStatus() {
  return {
    running: monitorInterval !== null,
    intervalMs: monitorIntervalMs,
    tenantsMonitored: metricsStore.size,
    cacheSize: healthCache.size,
  };
}

// ============================================================
// HEALTH HISTORY
// ============================================================

/**
 * Get health history for a tenant
 *
 * @param {string} tenantId - Tenant UUID
 * @param {number} hoursBack - Number of hours to look back (default: 24)
 * @returns {object[]} Array of metrics buckets
 */
export function getHealthHistory(tenantId, hoursBack = 24) {
  const buckets = metricsStore.get(tenantId) || [];
  const cutoff = Date.now() - hoursBack * 60 * 60 * 1000;

  return buckets
    .filter((b) => b.timestamp >= cutoff)
    .map((b) => ({
      timestamp: b.timestamp,
      requests: {
        total: b.requests.total,
        errors: b.requests.errors,
        errorRate: b.requests.total > 0 ? b.requests.errors / b.requests.total : 0,
      },
      responseTimes: {
        p50: calculatePercentile(b.requests.responseTimes, 50),
        p95: calculatePercentile(b.requests.responseTimes, 95),
        p99: calculatePercentile(b.requests.responseTimes, 99),
      },
      container: b.container,
      sessions: b.sessions,
    }))
    .toSorted((a, b) => a.timestamp - b.timestamp);
}

// ============================================================
// CLEANUP
// ============================================================

/**
 * Clean up old metrics data
 * Called automatically but can be invoked manually
 */
export function cleanupOldMetrics() {
  const cutoff = Date.now() - METRICS_HISTORY_HOURS * 60 * 60 * 1000;
  let cleaned = 0;

  for (const [tenantId, buckets] of metricsStore.entries()) {
    const newBuckets = buckets.filter((b) => b.timestamp >= cutoff);
    if (newBuckets.length < buckets.length) {
      cleaned += buckets.length - newBuckets.length;
      metricsStore.set(tenantId, newBuckets);
    }
    if (newBuckets.length === 0) {
      metricsStore.delete(tenantId);
    }
  }

  // Clean old health cache entries
  const cacheCutoff = Date.now() - 5 * 60 * 1000; // 5 minutes
  for (const [tenantId, cached] of healthCache.entries()) {
    if (cached.updatedAt < cacheCutoff) {
      healthCache.delete(tenantId);
    }
  }

  if (cleaned > 0) {
    console.log(`[tenant-health] Cleaned up ${cleaned} old metric buckets`);
  }

  return cleaned;
}

// Run cleanup every hour
const cleanupInterval = setInterval(cleanupOldMetrics, 60 * 60 * 1000);
cleanupInterval.unref();

// ============================================================
// EXPRESS MIDDLEWARE
// ============================================================

/**
 * Express middleware to track request metrics
 * Add this to your Express app to automatically track request times and errors
 *
 * Usage: app.use(trackRequestMetrics())
 *
 * @returns {Function} Express middleware
 */
export function trackRequestMetrics() {
  return (req, res, next) => {
    const startTime = Date.now();

    // Hook into response finish
    res.on("finish", () => {
      const tenantId = req.tenant?.id || req.tenantId;
      if (!tenantId) {
        return;
      }

      const responseTime = Date.now() - startTime;
      const isError = res.statusCode >= 500;

      recordRequest(tenantId, responseTime, isError);
    });

    next();
  };
}

// ============================================================
// EXPORTS
// ============================================================

export default {
  // Constants
  HEALTH_STATUS,
  CONTAINER_STATE,
  THRESHOLDS,

  // Metrics collection
  recordRequest,
  recordContainerStatus,
  recordActiveSessions,
  getAggregatedMetrics,

  // Health checks
  checkTenantHealth,
  getTenantStatus,
  getAllTenantHealth,

  // Dashboard
  getHealthDashboard,

  // Background monitoring
  startHealthMonitor,
  stopHealthMonitor,
  isMonitorRunning,
  getMonitorStatus,

  // History
  getHealthHistory,

  // Cleanup
  cleanupOldMetrics,

  // Middleware
  trackRequestMetrics,
};
