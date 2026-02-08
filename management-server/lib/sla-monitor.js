/**
 * SLA Monitoring Module
 * Wave 5.7 - Multi-tenant SaaS Enterprise Features
 *
 * Provides SLA tracking, monitoring, and reporting for multi-tenant platform:
 * - SLA definitions by plan (Free, Pro, Enterprise)
 * - Metrics tracking (uptime, response time, errors, support tickets)
 * - SLA calculations (uptime percentage, latency percentiles)
 * - Reporting and credit calculations
 * - Alerting when approaching SLA breaches
 *
 * Integrates with tenant-health.js for underlying metrics collection
 */

import { tenants, subscriptions, query } from "../db/index.js";
import { triggerAlert, ALERT_EVENTS } from "./alerting.js";
import { getPlan } from "./quotas.js";
import { getRedisClient, isRedisConnected } from "./redis.js";
import {
  getAggregatedMetrics,
  getHealthHistory,
  recordRequest,
  HEALTH_STATUS,
} from "./tenant-health.js";

// ============================================================
// SLA DEFINITIONS BY PLAN
// ============================================================

/**
 * SLA definitions for each plan tier
 * Values define minimum commitments
 */
export const SLA_DEFINITIONS = {
  free: {
    name: "Free",
    uptime: 0.99, // 99% uptime
    support: {
      responseType: "best_effort",
      responseHours: null, // Best effort, no SLA
      description: "Best effort support",
    },
    latencyP99: null, // No latency SLA
    errorRate: null, // No error rate SLA
    credits: {
      enabled: false,
    },
  },
  pro: {
    name: "Pro",
    uptime: 0.995, // 99.5% uptime
    support: {
      responseType: "guaranteed",
      responseHours: 24, // 24 hour response SLA
      description: "24-hour response SLA",
    },
    latencyP99: 2000, // 2 seconds P99 latency
    errorRate: 0.01, // 1% max error rate
    credits: {
      enabled: true,
      tiers: [
        { uptimeBelow: 0.995, creditPercent: 10 },
        { uptimeBelow: 0.99, creditPercent: 25 },
        { uptimeBelow: 0.95, creditPercent: 50 },
      ],
    },
  },
  enterprise: {
    name: "Enterprise",
    uptime: 0.999, // 99.9% uptime
    support: {
      responseType: "guaranteed",
      responseHours: 4, // 4 hour response SLA
      description: "4-hour response SLA with dedicated support",
      dedicatedSupport: true,
    },
    latencyP99: 1000, // 1 second P99 latency
    errorRate: 0.005, // 0.5% max error rate
    credits: {
      enabled: true,
      tiers: [
        { uptimeBelow: 0.999, creditPercent: 10 },
        { uptimeBelow: 0.995, creditPercent: 25 },
        { uptimeBelow: 0.99, creditPercent: 50 },
        { uptimeBelow: 0.95, creditPercent: 100 },
      ],
    },
  },
};

/**
 * Get SLA definition for a plan
 * @param {string} planName - Plan name (free, pro, enterprise)
 * @returns {object} SLA definition object
 */
export function getSLADefinition(planName) {
  return SLA_DEFINITIONS[planName?.toLowerCase()] || SLA_DEFINITIONS.free;
}

// ============================================================
// REDIS KEYS AND STORAGE
// ============================================================

const REDIS_PREFIX = "ocmt:sla";

// In-memory storage fallback
const uptimeStore = new Map(); // tenantId -> { checks, successful, lastCheck }
const responseTimeStore = new Map(); // tenantId -> { endpoint -> { times: [], count } }
const errorStore = new Map(); // tenantId -> { type -> count }
const supportTicketStore = new Map(); // tenantId -> { ticketId -> { status, createdAt, respondedAt } }
const alertThresholds = new Map(); // tenantId -> { metric -> threshold }
const creditStore = new Map(); // tenantId -> { period -> { amount, applied } }

// ============================================================
// METRICS TRACKING
// ============================================================

/**
 * Track uptime for a tenant
 * Records whether a health check succeeded or failed
 *
 * @param {string} tenantId - Tenant UUID
 * @param {boolean} isUp - Whether the service is available
 */
export async function trackUptime(tenantId, isUp = true) {
  if (!tenantId) {
    return;
  }

  const now = Date.now();
  const hourBucket = Math.floor(now / (60 * 60 * 1000));

  // In-memory tracking
  let data = uptimeStore.get(tenantId);
  if (!data) {
    data = { checks: 0, successful: 0, lastCheck: null, hourly: {} };
    uptimeStore.set(tenantId, data);
  }

  data.checks++;
  if (isUp) {
    data.successful++;
  }
  data.lastCheck = now;

  // Track hourly for granular reporting
  if (!data.hourly[hourBucket]) {
    data.hourly[hourBucket] = { checks: 0, successful: 0 };
  }
  data.hourly[hourBucket].checks++;
  if (isUp) {
    data.hourly[hourBucket].successful++;
  }

  // Prune old hourly data (keep last 30 days)
  const cutoffHour = hourBucket - 30 * 24;
  for (const hour of Object.keys(data.hourly)) {
    if (parseInt(hour, 10) < cutoffHour) {
      delete data.hourly[hour];
    }
  }

  // Persist to Redis if available
  if (isRedisConnected()) {
    try {
      const redis = getRedisClient();
      const key = `${REDIS_PREFIX}:uptime:${tenantId}:${hourBucket}`;
      await redis
        .multi()
        .hincrby(key, "checks", 1)
        .hincrby(key, "successful", isUp ? 1 : 0)
        .expire(key, 30 * 24 * 3600) // 30 day TTL
        .exec();
    } catch (err) {
      console.warn(`[sla-monitor] Redis uptime tracking error: ${err.message}`);
    }
  }

  // Check for SLA breach alerts
  await checkUptimeSLAAlert(tenantId);
}

/**
 * Track response time for an endpoint
 *
 * @param {string} tenantId - Tenant UUID
 * @param {string} endpoint - Endpoint path (e.g., "/api/chat")
 * @param {number} durationMs - Response time in milliseconds
 */
export async function trackResponseTime(tenantId, endpoint, durationMs) {
  if (!tenantId || typeof durationMs !== "number") {
    return;
  }

  // Also record in tenant-health for overall metrics
  recordRequest(tenantId, durationMs, false);

  // Track by endpoint
  let data = responseTimeStore.get(tenantId);
  if (!data) {
    data = {};
    responseTimeStore.set(tenantId, data);
  }

  if (!data[endpoint]) {
    data[endpoint] = { times: [], count: 0, sum: 0 };
  }

  // Keep last 1000 response times per endpoint for percentile calculation
  if (data[endpoint].times.length >= 1000) {
    data[endpoint].times.shift();
  }
  data[endpoint].times.push(durationMs);
  data[endpoint].count++;
  data[endpoint].sum += durationMs;

  // Persist to Redis if available
  if (isRedisConnected()) {
    try {
      const redis = getRedisClient();
      const now = Date.now();
      const minuteBucket = Math.floor(now / (60 * 1000));
      const key = `${REDIS_PREFIX}:latency:${tenantId}:${endpoint}:${minuteBucket}`;
      await redis
        .multi()
        .rpush(key, durationMs)
        .ltrim(key, -1000, -1) // Keep last 1000
        .expire(key, 24 * 3600) // 24 hour TTL
        .exec();
    } catch (err) {
      console.warn(`[sla-monitor] Redis latency tracking error: ${err.message}`);
    }
  }

  // Check for latency SLA alerts
  await checkLatencySLAAlert(tenantId);
}

/**
 * Track errors for a tenant
 *
 * @param {string} tenantId - Tenant UUID
 * @param {string} errorType - Error type/category (e.g., "5xx", "timeout", "validation")
 */
export async function trackError(tenantId, errorType) {
  if (!tenantId) {
    return;
  }

  // Record in tenant-health as well
  recordRequest(tenantId, 0, true);

  let data = errorStore.get(tenantId);
  if (!data) {
    data = { total: 0, byType: {} };
    errorStore.set(tenantId, data);
  }

  data.total++;
  data.byType[errorType] = (data.byType[errorType] || 0) + 1;

  // Persist to Redis if available
  if (isRedisConnected()) {
    try {
      const redis = getRedisClient();
      const now = Date.now();
      const hourBucket = Math.floor(now / (60 * 60 * 1000));
      const key = `${REDIS_PREFIX}:errors:${tenantId}:${hourBucket}`;
      await redis
        .multi()
        .hincrby(key, "total", 1)
        .hincrby(key, errorType, 1)
        .expire(key, 30 * 24 * 3600)
        .exec();
    } catch (err) {
      console.warn(`[sla-monitor] Redis error tracking error: ${err.message}`);
    }
  }

  // Check for error rate SLA alerts
  await checkErrorRateSLAAlert(tenantId);
}

/**
 * Track support ticket for SLA
 *
 * @param {string} tenantId - Tenant UUID
 * @param {string} ticketId - Support ticket ID
 * @param {string} status - Ticket status ("created", "responded", "resolved", "closed")
 */
export async function trackSupportTicket(tenantId, ticketId, status) {
  if (!tenantId || !ticketId) {
    return;
  }

  let tickets = supportTicketStore.get(tenantId);
  if (!tickets) {
    tickets = {};
    supportTicketStore.set(tenantId, tickets);
  }

  const now = Date.now();

  if (!tickets[ticketId]) {
    tickets[ticketId] = {
      createdAt: now,
      respondedAt: null,
      resolvedAt: null,
      closedAt: null,
      status: "created",
    };
  }

  const ticket = tickets[ticketId];
  ticket.status = status;

  switch (status) {
    case "responded":
      if (!ticket.respondedAt) {
        ticket.respondedAt = now;
        // Check if response was within SLA
        await checkSupportSLACompliance(tenantId, ticket);
      }
      break;
    case "resolved":
      ticket.resolvedAt = now;
      break;
    case "closed":
      ticket.closedAt = now;
      break;
  }

  // Persist to Redis if available
  if (isRedisConnected()) {
    try {
      const redis = getRedisClient();
      const key = `${REDIS_PREFIX}:tickets:${tenantId}:${ticketId}`;
      await redis.hmset(key, {
        createdAt: ticket.createdAt,
        respondedAt: ticket.respondedAt || "",
        resolvedAt: ticket.resolvedAt || "",
        closedAt: ticket.closedAt || "",
        status: ticket.status,
      });
      await redis.expire(key, 90 * 24 * 3600); // 90 day TTL
    } catch (err) {
      console.warn(`[sla-monitor] Redis ticket tracking error: ${err.message}`);
    }
  }
}

// ============================================================
// SLA CALCULATIONS
// ============================================================

/**
 * Calculate uptime percentage for a tenant over a period
 *
 * @param {string} tenantId - Tenant UUID
 * @param {string} period - Period ("hour", "day", "week", "month")
 * @returns {Promise<object>} Uptime data { percentage, checks, successful, period }
 */
export async function calculateUptime(tenantId, period = "month") {
  const data = uptimeStore.get(tenantId);

  if (!data || data.checks === 0) {
    return {
      percentage: 100, // Assume 100% if no data
      checks: 0,
      successful: 0,
      period,
      noData: true,
    };
  }

  // Calculate based on period
  const now = Date.now();
  const hourBucket = Math.floor(now / (60 * 60 * 1000));

  let hoursBack;
  switch (period) {
    case "hour":
      hoursBack = 1;
      break;
    case "day":
      hoursBack = 24;
      break;
    case "week":
      hoursBack = 24 * 7;
      break;
    case "month":
    default:
      hoursBack = 24 * 30;
      break;
  }

  let totalChecks = 0;
  let totalSuccessful = 0;

  for (let h = hourBucket - hoursBack; h <= hourBucket; h++) {
    const hourData = data.hourly[h];
    if (hourData) {
      totalChecks += hourData.checks;
      totalSuccessful += hourData.successful;
    }
  }

  const percentage = totalChecks > 0 ? (totalSuccessful / totalChecks) * 100 : 100;

  return {
    percentage: Math.round(percentage * 1000) / 1000, // 3 decimal places
    checks: totalChecks,
    successful: totalSuccessful,
    period,
    noData: totalChecks === 0,
  };
}

/**
 * Calculate latency percentile for a tenant
 *
 * @param {string} tenantId - Tenant UUID
 * @param {string} period - Period ("hour", "day", "week")
 * @returns {Promise<object>} Latency data { p50, p95, p99, avg, count }
 */
export async function calculateLatencyP99(tenantId, period = "hour") {
  // Get aggregated metrics from tenant-health
  let hoursBack;
  switch (period) {
    case "hour":
      hoursBack = 1;
      break;
    case "day":
      hoursBack = 24;
      break;
    case "week":
      hoursBack = 24 * 7;
      break;
    default:
      hoursBack = 1;
  }

  const metrics = getAggregatedMetrics(tenantId, hoursBack);

  // Also get endpoint-specific data
  const endpointData = responseTimeStore.get(tenantId) || {};
  const allTimes = [];

  for (const endpoint of Object.values(endpointData)) {
    allTimes.push(...endpoint.times);
  }

  // Calculate percentiles
  const sorted = allTimes.toSorted((a, b) => a - b);

  const p50 = getPercentile(sorted, 50);
  const p95 = getPercentile(sorted, 95);
  const p99 = getPercentile(sorted, 99);
  const avg = allTimes.length > 0 ? allTimes.reduce((a, b) => a + b, 0) / allTimes.length : 0;

  return {
    p50: Math.round(p50),
    p95: Math.round(p95),
    p99: Math.round(p99),
    avg: Math.round(avg),
    count: allTimes.length,
    period,
    // Include tenant-health metrics as well
    healthMetrics: {
      p50: metrics.responseTimes.p50,
      p95: metrics.responseTimes.p95,
      p99: metrics.responseTimes.p99,
    },
  };
}

/**
 * Calculate percentile from sorted array
 */
function getPercentile(sorted, percentile) {
  if (sorted.length === 0) {
    return 0;
  }
  const index = Math.ceil((percentile / 100) * sorted.length) - 1;
  return sorted[Math.max(0, index)];
}

/**
 * Check if SLA is being met for a specific metric
 *
 * @param {string} tenantId - Tenant UUID
 * @param {string} metric - Metric name ("uptime", "latency", "errorRate", "supportResponse")
 * @param {string} period - Period for calculation
 * @returns {Promise<object>} SLA status { met, current, required, metric, details }
 */
export async function isSLAMet(tenantId, metric, period = "month") {
  const subscription = await subscriptions.findByTenantId(tenantId);
  const planName = subscription?.plan || "free";
  const sla = getSLADefinition(planName);

  switch (metric) {
    case "uptime": {
      const uptimeData = await calculateUptime(tenantId, period);
      const required = sla.uptime * 100;
      return {
        met: uptimeData.percentage >= required,
        current: uptimeData.percentage,
        required,
        metric: "uptime",
        unit: "%",
        period,
        details: uptimeData,
      };
    }

    case "latency": {
      if (!sla.latencyP99) {
        return { met: true, current: null, required: null, metric: "latency", noSLA: true };
      }
      const latencyData = await calculateLatencyP99(tenantId, period);
      return {
        met: latencyData.p99 <= sla.latencyP99,
        current: latencyData.p99,
        required: sla.latencyP99,
        metric: "latency",
        unit: "ms",
        period,
        details: latencyData,
      };
    }

    case "errorRate": {
      if (!sla.errorRate) {
        return { met: true, current: null, required: null, metric: "errorRate", noSLA: true };
      }
      const metrics = getAggregatedMetrics(tenantId, period === "month" ? 24 * 30 : 1);
      const errorRate = metrics.requests.errorRate * 100;
      return {
        met: metrics.requests.errorRate <= sla.errorRate,
        current: errorRate,
        required: sla.errorRate * 100,
        metric: "errorRate",
        unit: "%",
        period,
        details: metrics.requests,
      };
    }

    case "supportResponse": {
      if (sla.support.responseType !== "guaranteed") {
        return { met: true, current: null, required: null, metric: "supportResponse", noSLA: true };
      }
      const supportStatus = await getSupportSLAStatus(tenantId, period);
      return {
        met: supportStatus.compliance >= 100,
        current: supportStatus.avgResponseHours,
        required: sla.support.responseHours,
        metric: "supportResponse",
        unit: "hours",
        period,
        details: supportStatus,
      };
    }

    default:
      return { met: true, current: null, required: null, metric, unknown: true };
  }
}

/**
 * Get support SLA status
 */
async function getSupportSLAStatus(tenantId, period) {
  const tickets = supportTicketStore.get(tenantId) || {};
  const now = Date.now();

  let periodMs;
  switch (period) {
    case "day":
      periodMs = 24 * 60 * 60 * 1000;
      break;
    case "week":
      periodMs = 7 * 24 * 60 * 60 * 1000;
      break;
    case "month":
    default:
      periodMs = 30 * 24 * 60 * 60 * 1000;
      break;
  }

  const cutoff = now - periodMs;
  let totalTickets = 0;
  let respondedInSLA = 0;
  let totalResponseMs = 0;

  const subscription = await subscriptions.findByTenantId(tenantId);
  const planName = subscription?.plan || "free";
  const sla = getSLADefinition(planName);
  const slaHours = sla.support.responseHours || 24;

  for (const ticket of Object.values(tickets)) {
    if (ticket.createdAt >= cutoff) {
      totalTickets++;
      if (ticket.respondedAt) {
        const responseMs = ticket.respondedAt - ticket.createdAt;
        totalResponseMs += responseMs;
        if (responseMs <= slaHours * 60 * 60 * 1000) {
          respondedInSLA++;
        }
      }
    }
  }

  return {
    totalTickets,
    respondedInSLA,
    compliance: totalTickets > 0 ? (respondedInSLA / totalTickets) * 100 : 100,
    avgResponseHours: totalTickets > 0 ? totalResponseMs / totalTickets / (60 * 60 * 1000) : 0,
  };
}

/**
 * Get overall SLA compliance status for a tenant
 *
 * @param {string} tenantId - Tenant UUID
 * @returns {Promise<object>} Overall SLA status with all metrics
 */
export async function getSLAStatus(tenantId) {
  const subscription = await subscriptions.findByTenantId(tenantId);
  const planName = subscription?.plan || "free";
  const sla = getSLADefinition(planName);
  const tenant = await tenants.findById(tenantId);

  const [uptime, latency, errorRate, supportResponse] = await Promise.all([
    isSLAMet(tenantId, "uptime", "month"),
    isSLAMet(tenantId, "latency", "hour"),
    isSLAMet(tenantId, "errorRate", "day"),
    isSLAMet(tenantId, "supportResponse", "month"),
  ]);

  const allMet = uptime.met && latency.met && errorRate.met && supportResponse.met;

  return {
    tenantId,
    tenantName: tenant?.name,
    plan: planName,
    slaDefinition: sla,
    overallStatus: allMet ? "compliant" : "breach",
    metrics: {
      uptime,
      latency,
      errorRate,
      supportResponse,
    },
    lastUpdated: new Date().toISOString(),
  };
}

// ============================================================
// REPORTING
// ============================================================

/**
 * Generate comprehensive SLA report for a tenant
 *
 * @param {string} tenantId - Tenant UUID
 * @param {string} period - Period ("day", "week", "month")
 * @returns {Promise<object>} Full SLA report
 */
export async function generateSLAReport(tenantId, period = "month") {
  const subscription = await subscriptions.findByTenantId(tenantId);
  const planName = subscription?.plan || "free";
  const sla = getSLADefinition(planName);
  const tenant = await tenants.findById(tenantId);

  // Calculate all metrics
  const uptimeData = await calculateUptime(tenantId, period);
  const latencyData = await calculateLatencyP99(tenantId, period);
  const slaStatus = await getSLAStatus(tenantId);

  // Get historical health data
  const hoursBack = period === "month" ? 24 * 30 : period === "week" ? 24 * 7 : 24;
  const healthHistory = getHealthHistory(tenantId, hoursBack);

  // Calculate credits if applicable
  const credits = await calculateCredits(tenantId, period);

  // Get error breakdown
  const errorData = errorStore.get(tenantId) || { total: 0, byType: {} };

  return {
    report: {
      generatedAt: new Date().toISOString(),
      period,
      periodStart: new Date(Date.now() - hoursBack * 60 * 60 * 1000).toISOString(),
      periodEnd: new Date().toISOString(),
    },
    tenant: {
      id: tenantId,
      name: tenant?.name,
      slug: tenant?.slug,
    },
    subscription: {
      plan: planName,
      planName: sla.name,
      status: subscription?.status || "active",
    },
    sla: {
      definition: sla,
      status: slaStatus.overallStatus,
    },
    metrics: {
      uptime: {
        ...uptimeData,
        target: sla.uptime * 100,
        met: uptimeData.percentage >= sla.uptime * 100,
      },
      latency: {
        ...latencyData,
        target: sla.latencyP99,
        met: !sla.latencyP99 || latencyData.p99 <= sla.latencyP99,
      },
      errors: {
        total: errorData.total,
        byType: errorData.byType,
        target: sla.errorRate ? sla.errorRate * 100 : null,
      },
      support: slaStatus.metrics.supportResponse.details,
    },
    credits: credits.enabled ? credits : null,
    history: {
      dataPoints: healthHistory.length,
      samples: healthHistory.slice(-48), // Last 48 data points
    },
  };
}

// ============================================================
// CREDITS/COMPENSATION
// ============================================================

/**
 * Calculate SLA credits owed to a tenant
 *
 * @param {string} tenantId - Tenant UUID
 * @param {string} period - Period ("month")
 * @returns {Promise<object>} Credit calculation
 */
export async function calculateCredits(tenantId, period = "month") {
  const subscription = await subscriptions.findByTenantId(tenantId);
  const planName = subscription?.plan || "free";
  const sla = getSLADefinition(planName);

  if (!sla.credits.enabled) {
    return {
      enabled: false,
      creditPercent: 0,
      reason: "Credits not available for this plan",
    };
  }

  const uptimeData = await calculateUptime(tenantId, period);
  const uptimePercent = uptimeData.percentage / 100;

  // Find applicable credit tier
  let creditPercent = 0;
  let tier = null;

  for (const t of sla.credits.tiers) {
    if (uptimePercent < t.uptimeBelow) {
      if (t.creditPercent > creditPercent) {
        creditPercent = t.creditPercent;
        tier = t;
      }
    }
  }

  // Get the billing amount for this period (simplified)
  // In production, this would fetch from Stripe or billing table
  const monthlyAmount = planName === "enterprise" ? 499 : planName === "pro" ? 49 : 0;
  const creditAmount = (monthlyAmount * creditPercent) / 100;

  return {
    enabled: true,
    creditPercent,
    creditAmount,
    currency: "USD",
    tier,
    uptime: uptimeData.percentage,
    uptimeTarget: sla.uptime * 100,
    period,
    applied: false,
    appliedAt: null,
  };
}

/**
 * Apply credits to a tenant's billing
 *
 * @param {string} tenantId - Tenant UUID
 * @param {string} period - Period identifier
 * @param {object} creditData - Credit data from calculateCredits
 * @returns {Promise<object>} Application result
 */
export async function applyCredits(tenantId, period, creditData) {
  if (!creditData.enabled || creditData.creditAmount === 0) {
    return { success: false, reason: "No credits to apply" };
  }

  // Store credit application
  let credits = creditStore.get(tenantId);
  if (!credits) {
    credits = {};
    creditStore.set(tenantId, credits);
  }

  credits[period] = {
    ...creditData,
    applied: true,
    appliedAt: new Date().toISOString(),
  };

  // In production, this would create a Stripe credit balance adjustment
  // For now, we just record it

  return {
    success: true,
    creditAmount: creditData.creditAmount,
    period,
    appliedAt: credits[period].appliedAt,
  };
}

/**
 * Get credit history for a tenant
 *
 * @param {string} tenantId - Tenant UUID
 * @returns {object} Credit history
 */
export function getCreditHistory(tenantId) {
  return creditStore.get(tenantId) || {};
}

// ============================================================
// ALERTING
// ============================================================

/**
 * Set SLA alert threshold for a tenant
 *
 * @param {string} tenantId - Tenant UUID
 * @param {string} metric - Metric name (uptime, latency, errorRate)
 * @param {number} threshold - Threshold value (percentage of SLA)
 */
export function setSLAAlertThreshold(tenantId, metric, threshold) {
  let thresholds = alertThresholds.get(tenantId);
  if (!thresholds) {
    thresholds = {};
    alertThresholds.set(tenantId, thresholds);
  }

  thresholds[metric] = {
    threshold,
    createdAt: Date.now(),
  };
}

/**
 * Get SLA alert thresholds for a tenant
 */
export function getSLAAlertThresholds(tenantId) {
  return alertThresholds.get(tenantId) || {};
}

/**
 * Check uptime SLA and trigger alert if approaching breach
 */
async function checkUptimeSLAAlert(tenantId) {
  const uptimeData = await calculateUptime(tenantId, "day");
  const subscription = await subscriptions.findByTenantId(tenantId);
  const planName = subscription?.plan || "free";
  const sla = getSLADefinition(planName);

  const target = sla.uptime * 100;
  const thresholds = alertThresholds.get(tenantId) || {};
  const alertThreshold = thresholds.uptime?.threshold || 95; // Default: alert at 95% of target

  const warningLevel = target * (alertThreshold / 100);

  if (uptimeData.percentage < warningLevel && !uptimeData.noData) {
    await triggerAlert({
      eventType: ALERT_EVENTS.ANOMALY_DETECTED,
      title: "SLA Uptime Warning",
      message: `Uptime is ${uptimeData.percentage.toFixed(2)}%, approaching SLA breach (target: ${target}%)`,
      severity: "warning",
      metadata: {
        tenantId,
        metric: "uptime",
        current: uptimeData.percentage,
        target,
        slaType: "uptime",
      },
    });
  }
}

/**
 * Check latency SLA and trigger alert if approaching breach
 */
async function checkLatencySLAAlert(tenantId) {
  const subscription = await subscriptions.findByTenantId(tenantId);
  const planName = subscription?.plan || "free";
  const sla = getSLADefinition(planName);

  if (!sla.latencyP99) {
    return;
  } // No latency SLA

  const latencyData = await calculateLatencyP99(tenantId, "hour");
  const thresholds = alertThresholds.get(tenantId) || {};
  const alertThreshold = thresholds.latency?.threshold || 80; // Default: alert at 80% of limit

  const warningLevel = sla.latencyP99 * (alertThreshold / 100);

  if (latencyData.p99 > warningLevel && latencyData.count > 0) {
    await triggerAlert({
      eventType: ALERT_EVENTS.ANOMALY_DETECTED,
      title: "SLA Latency Warning",
      message: `P99 latency is ${latencyData.p99}ms, approaching SLA limit (${sla.latencyP99}ms)`,
      severity: "warning",
      metadata: {
        tenantId,
        metric: "latency",
        current: latencyData.p99,
        target: sla.latencyP99,
        slaType: "latency",
      },
    });
  }
}

/**
 * Check error rate SLA and trigger alert if approaching breach
 */
async function checkErrorRateSLAAlert(tenantId) {
  const subscription = await subscriptions.findByTenantId(tenantId);
  const planName = subscription?.plan || "free";
  const sla = getSLADefinition(planName);

  if (!sla.errorRate) {
    return;
  } // No error rate SLA

  const metrics = getAggregatedMetrics(tenantId, 1);
  const errorRate = metrics.requests.errorRate;
  const thresholds = alertThresholds.get(tenantId) || {};
  const alertThreshold = thresholds.errorRate?.threshold || 80; // Default: alert at 80%

  const warningLevel = sla.errorRate * (alertThreshold / 100);

  if (errorRate > warningLevel && metrics.requests.total > 10) {
    await triggerAlert({
      eventType: ALERT_EVENTS.ANOMALY_DETECTED,
      title: "SLA Error Rate Warning",
      message: `Error rate is ${(errorRate * 100).toFixed(2)}%, approaching SLA limit (${sla.errorRate * 100}%)`,
      severity: "warning",
      metadata: {
        tenantId,
        metric: "errorRate",
        current: errorRate,
        target: sla.errorRate,
        slaType: "errorRate",
      },
    });
  }
}

/**
 * Check support SLA compliance for a ticket
 */
async function checkSupportSLACompliance(tenantId, ticket) {
  const subscription = await subscriptions.findByTenantId(tenantId);
  const planName = subscription?.plan || "free";
  const sla = getSLADefinition(planName);

  if (sla.support.responseType !== "guaranteed") {
    return;
  }

  const responseMs = ticket.respondedAt - ticket.createdAt;
  const slaMs = sla.support.responseHours * 60 * 60 * 1000;

  if (responseMs > slaMs) {
    await triggerAlert({
      eventType: ALERT_EVENTS.ANOMALY_CRITICAL,
      title: "Support SLA Breach",
      message: `Support ticket response time (${(responseMs / (60 * 60 * 1000)).toFixed(1)} hours) exceeded SLA (${sla.support.responseHours} hours)`,
      severity: "critical",
      metadata: {
        tenantId,
        metric: "supportResponse",
        responseMs,
        slaMs,
        slaType: "support",
      },
    });
  }
}

// ============================================================
// SLA HISTORY
// ============================================================

/**
 * Get SLA history for a tenant
 *
 * @param {string} tenantId - Tenant UUID
 * @param {number} days - Number of days to look back
 * @returns {Promise<object>} Historical SLA data
 */
export async function getSLAHistory(tenantId, days = 30) {
  const healthHistory = getHealthHistory(tenantId, days * 24);
  const uptimeData = uptimeStore.get(tenantId);

  // Calculate daily SLA metrics
  const dailyMetrics = [];
  const now = Date.now();
  const dayMs = 24 * 60 * 60 * 1000;

  for (let d = 0; d < days; d++) {
    const dayStart = now - (d + 1) * dayMs;
    const dayEnd = now - d * dayMs;

    // Filter health history for this day
    const dayData = healthHistory.filter((h) => h.timestamp >= dayStart && h.timestamp < dayEnd);

    // Calculate uptime for the day
    const startHour = Math.floor(dayStart / (60 * 60 * 1000));
    const endHour = Math.floor(dayEnd / (60 * 60 * 1000));
    let dayChecks = 0;
    let daySuccessful = 0;

    if (uptimeData?.hourly) {
      for (let h = startHour; h < endHour; h++) {
        const hourData = uptimeData.hourly[h];
        if (hourData) {
          dayChecks += hourData.checks;
          daySuccessful += hourData.successful;
        }
      }
    }

    dailyMetrics.push({
      date: new Date(dayStart).toISOString().split("T")[0],
      uptime: dayChecks > 0 ? (daySuccessful / dayChecks) * 100 : 100,
      dataPoints: dayData.length,
      requests: dayData.reduce((sum, h) => sum + (h.requests?.total || 0), 0),
      errors: dayData.reduce((sum, h) => sum + (h.requests?.errors || 0), 0),
    });
  }

  return {
    tenantId,
    days,
    daily: dailyMetrics.toReversed(), // Oldest first
    summary: {
      avgUptime:
        dailyMetrics.length > 0
          ? dailyMetrics.reduce((sum, d) => sum + d.uptime, 0) / dailyMetrics.length
          : 100,
      totalRequests: dailyMetrics.reduce((sum, d) => sum + d.requests, 0),
      totalErrors: dailyMetrics.reduce((sum, d) => sum + d.errors, 0),
    },
  };
}

// ============================================================
// EXPRESS MIDDLEWARE
// ============================================================

/**
 * Express middleware to track SLA metrics
 * Add this to routes to automatically track response times
 *
 * Usage: app.use(trackSLAMetrics())
 *
 * @returns {Function} Express middleware
 */
export function trackSLAMetrics() {
  return (req, res, next) => {
    const startTime = Date.now();

    res.on("finish", () => {
      const tenantId = req.tenant?.id || req.tenantId;
      if (!tenantId) {
        return;
      }

      const responseTime = Date.now() - startTime;
      const endpoint = req.route?.path || req.path;
      const isError = res.statusCode >= 500;

      // Track response time
      trackResponseTime(tenantId, endpoint, responseTime);

      // Track errors
      if (isError) {
        trackError(tenantId, `${res.statusCode}`);
      }
    });

    next();
  };
}

// ============================================================
// CLEANUP
// ============================================================

/**
 * Cleanup old SLA data
 * Call periodically to prevent memory bloat
 */
export function cleanupOldSLAData() {
  const now = Date.now();
  const thirtyDaysAgo = now - 30 * 24 * 60 * 60 * 1000;
  let cleaned = 0;

  // Cleanup old uptime hourly buckets
  for (const [tenantId, data] of uptimeStore.entries()) {
    if (data.hourly) {
      const cutoffHour = Math.floor(thirtyDaysAgo / (60 * 60 * 1000));
      for (const hour of Object.keys(data.hourly)) {
        if (parseInt(hour, 10) < cutoffHour) {
          delete data.hourly[hour];
          cleaned++;
        }
      }
    }
  }

  // Cleanup old support tickets
  for (const [tenantId, tickets] of supportTicketStore.entries()) {
    for (const [ticketId, ticket] of Object.entries(tickets)) {
      if (ticket.closedAt && ticket.closedAt < thirtyDaysAgo) {
        delete tickets[ticketId];
        cleaned++;
      }
    }
  }

  if (cleaned > 0) {
    console.log(`[sla-monitor] Cleaned up ${cleaned} old SLA data entries`);
  }

  return cleaned;
}

// Run cleanup daily
const cleanupInterval = setInterval(cleanupOldSLAData, 24 * 60 * 60 * 1000);
cleanupInterval.unref();

// ============================================================
// EXPORTS
// ============================================================

export default {
  // SLA definitions
  SLA_DEFINITIONS,
  getSLADefinition,

  // Metrics tracking
  trackUptime,
  trackResponseTime,
  trackError,
  trackSupportTicket,

  // SLA calculations
  calculateUptime,
  calculateLatencyP99,
  isSLAMet,
  getSLAStatus,

  // Reporting
  generateSLAReport,
  getSLAHistory,

  // Credits
  calculateCredits,
  applyCredits,
  getCreditHistory,

  // Alerting
  setSLAAlertThreshold,
  getSLAAlertThresholds,

  // Middleware
  trackSLAMetrics,

  // Cleanup
  cleanupOldSLAData,
};
