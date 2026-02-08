// Behavioral Anomaly Detection for Agent Activity
import {
  agentActivity,
  agentBaselines,
  anomalyAlerts,
  notifications,
  users,
  audit,
} from "../db/index.js";
import { vaultSessions, deleteVaultSession } from "./vault-sessions.js";

// Anomaly detection thresholds
const THRESHOLDS = {
  // Standard deviations from baseline to trigger alert
  WARNING_STDDEV: 2.5,
  CRITICAL_STDDEV: 4.0,

  // Absolute thresholds (for new users without baseline)
  MAX_API_CALLS_PER_HOUR: 500,
  MAX_API_CALLS_PER_DAY: 5000,
  MAX_CAPABILITY_TOKENS_PER_HOUR: 20,
  MAX_RESOURCE_ACCESSES_PER_HOUR: 100,

  // Burst detection (calls within short window)
  BURST_WINDOW_SECONDS: 60,
  BURST_THRESHOLD: 50,

  // Unusual hours (for users with established patterns)
  UNUSUAL_HOUR_THRESHOLD: 0.05, // Less than 5% of activity in this hour historically

  // Minimum samples before using baseline
  MIN_BASELINE_SAMPLES: 7,
};

// Action types that are tracked
export const ACTION_TYPES = {
  API_CALL: "api_call",
  MCP_TOOL_CALL: "mcp_tool_call",
  CAPABILITY_TOKEN: "capability_token",
  RESOURCE_ACCESS: "resource_access",
  VAULT_UNLOCK: "vault_unlock",
  CREDENTIAL_ACCESS: "credential_access",
  INTEGRATION_CONNECT: "integration_connect",
  ORG_RESOURCE_CALL: "org_resource_call",
};

/**
 * Log agent activity and check for anomalies
 */
export async function logActivity(userId, actionType, resource = null, metadata = {}) {
  // Log the activity
  await agentActivity.log(userId, actionType, resource, metadata);

  // Run anomaly checks in the background
  checkForAnomalies(userId, actionType).catch((err) => {
    console.error(`[anomaly-detection] Error checking anomalies: ${err.message}`);
  });
}

/**
 * Check for anomalous behavior
 */
async function checkForAnomalies(userId, actionType) {
  const anomalies = [];

  // Check hourly rate
  const hourlyCount = await agentActivity.getHourCount(userId, 1);
  const hourlyAnomaly = await checkMetricAnomaly(userId, "hourly_activity", hourlyCount, {
    absoluteMax: THRESHOLDS.MAX_API_CALLS_PER_HOUR,
  });
  if (hourlyAnomaly) {
    anomalies.push(hourlyAnomaly);
  }

  // Check daily rate
  const dailyCount = await agentActivity.getTodayCount(userId);
  const dailyAnomaly = await checkMetricAnomaly(userId, "daily_activity", dailyCount, {
    absoluteMax: THRESHOLDS.MAX_API_CALLS_PER_DAY,
  });
  if (dailyAnomaly) {
    anomalies.push(dailyAnomaly);
  }

  // Check for specific action type spikes
  if (actionType === ACTION_TYPES.CAPABILITY_TOKEN) {
    const tokenCount = await agentActivity.getHourCount(userId, 1);
    const tokenAnomaly = await checkMetricAnomaly(userId, "hourly_capability_tokens", tokenCount, {
      absoluteMax: THRESHOLDS.MAX_CAPABILITY_TOKENS_PER_HOUR,
    });
    if (tokenAnomaly) {
      anomalies.push(tokenAnomaly);
    }
  }

  // Check for unusual access hours
  const unusualHourAnomaly = await checkUnusualHours(userId);
  if (unusualHourAnomaly) {
    anomalies.push(unusualHourAnomaly);
  }

  // Process detected anomalies
  for (const anomaly of anomalies) {
    await handleAnomaly(userId, anomaly);
  }
}

/**
 * Check if a metric value is anomalous
 */
async function checkMetricAnomaly(userId, metricName, currentValue, options = {}) {
  const { absoluteMax } = options;

  // Update baseline with current value
  const baseline = await agentBaselines.upsert(userId, metricName, currentValue);

  // Check absolute threshold first
  if (absoluteMax && currentValue > absoluteMax) {
    return {
      type: "absolute_threshold",
      severity: "critical",
      metricName,
      expectedValue: absoluteMax,
      actualValue: currentValue,
      deviationFactor: currentValue / absoluteMax,
      description: `${metricName} exceeded absolute maximum (${currentValue} > ${absoluteMax})`,
    };
  }

  // Only use baseline if we have enough samples
  if (baseline.sample_count < THRESHOLDS.MIN_BASELINE_SAMPLES) {
    return null;
  }

  // Calculate deviation from baseline
  const deviation = Math.abs(currentValue - baseline.baseline_value);
  const deviationFactor = baseline.stddev_value > 0 ? deviation / baseline.stddev_value : 0;

  // Check for anomalous deviation
  if (deviationFactor >= THRESHOLDS.CRITICAL_STDDEV) {
    return {
      type: "statistical_anomaly",
      severity: "critical",
      metricName,
      expectedValue: baseline.baseline_value,
      actualValue: currentValue,
      deviationFactor,
      description: `${metricName} is ${deviationFactor.toFixed(1)} standard deviations from normal`,
    };
  } else if (deviationFactor >= THRESHOLDS.WARNING_STDDEV) {
    return {
      type: "statistical_anomaly",
      severity: "warning",
      metricName,
      expectedValue: baseline.baseline_value,
      actualValue: currentValue,
      deviationFactor,
      description: `${metricName} is elevated (${deviationFactor.toFixed(1)} std devs)`,
    };
  }

  return null;
}

/**
 * Check for activity at unusual hours
 */
async function checkUnusualHours(userId) {
  const currentHour = new Date().getUTCHours();
  const distribution = await agentActivity.getHourlyDistribution(userId, 30);

  if (distribution.length === 0) {
    return null; // Not enough data
  }

  const totalActivity = distribution.reduce((sum, row) => sum + parseInt(row.count, 10), 0);
  const hourActivity = distribution.find((row) => row.hour_of_day === currentHour);
  const hourCount = hourActivity ? parseInt(hourActivity.count, 10) : 0;
  const hourPercentage = totalActivity > 0 ? hourCount / totalActivity : 0;

  // If less than 5% of historical activity happens at this hour, and there's significant data
  if (totalActivity > 100 && hourPercentage < THRESHOLDS.UNUSUAL_HOUR_THRESHOLD) {
    const recentCount = await agentActivity.getHourCount(userId, 1);
    if (recentCount > 5) {
      // Only flag if there's meaningful activity now
      return {
        type: "unusual_hours",
        severity: "warning",
        metricName: "activity_hour",
        expectedValue: hourPercentage * 100,
        actualValue: currentHour,
        deviationFactor: null,
        description: `Activity at unusual hour (${currentHour}:00 UTC typically has ${(hourPercentage * 100).toFixed(1)}% of activity)`,
      };
    }
  }

  return null;
}

/**
 * Handle a detected anomaly
 */
async function handleAnomaly(userId, anomaly) {
  // Create alert record
  const alert = await anomalyAlerts.create({
    userId,
    alertType: anomaly.type,
    severity: anomaly.severity,
    metricName: anomaly.metricName,
    expectedValue: anomaly.expectedValue,
    actualValue: anomaly.actualValue,
    deviationFactor: anomaly.deviationFactor,
    description: anomaly.description,
    actionTaken: anomaly.severity === "critical" ? "vault_locked" : "notification_sent",
  });

  // Log to audit
  await audit.log(userId, "anomaly.detected", {
    alertId: alert.id,
    type: anomaly.type,
    severity: anomaly.severity,
    metric: anomaly.metricName,
  });

  // Take action based on severity
  if (anomaly.severity === "critical") {
    await lockVaultForAnomaly(userId, alert.id);
  }

  // Send notification
  await notifications.create({
    userId,
    type: "security_alert",
    title: anomaly.severity === "critical" ? "Security Alert: Vault Locked" : "Security Notice",
    message: anomaly.description,
    severity: anomaly.severity,
    metadata: {
      alertId: alert.id,
      type: anomaly.type,
      metric: anomaly.metricName,
    },
  });
}

/**
 * Lock vault due to anomaly detection
 */
async function lockVaultForAnomaly(userId, alertId) {
  // Delete all vault sessions for this user from in-memory store
  // Note: Redis sessions will expire naturally; for immediate invalidation
  // we'd need to track tokens per user, which is a future enhancement
  for (const [token, session] of vaultSessions) {
    if (session.userId === userId) {
      await deleteVaultSession(token);
    }
  }

  // Mark vault as locked by anomaly in the database
  (await users.query)
    ? users.query(
        `UPDATE users SET vault_locked_by_anomaly = true, vault_locked_at = NOW() WHERE id = $1`,
        [userId],
      )
    : null; // Fallback if query not available directly

  await audit.log(userId, "vault.locked_by_anomaly", { alertId });

  console.log(`[anomaly-detection] Vault locked for user ${userId} due to anomaly ${alertId}`);
}

/**
 * Unlock vault after anomaly (user must acknowledge)
 */
export async function unlockVaultAfterAnomaly(userId) {
  // Clear the anomaly lock flag
  const { query } = await import("../db/index.js");
  await query(
    `UPDATE users SET vault_locked_by_anomaly = false, vault_locked_at = NULL WHERE id = $1`,
    [userId],
  );

  // Acknowledge all pending alerts
  await anomalyAlerts.acknowledgeAll(userId);

  await audit.log(userId, "vault.unlocked_after_anomaly", {});
}

/**
 * Check if vault is locked due to anomaly
 */
export async function isVaultLockedByAnomaly(userId) {
  const { query } = await import("../db/index.js");
  const res = await query(
    `SELECT vault_locked_by_anomaly, vault_locked_at FROM users WHERE id = $1`,
    [userId],
  );
  return res.rows[0]?.vault_locked_by_anomaly || false;
}

/**
 * Get activity digest for a user
 */
export async function getActivityDigest(userId, days = 7) {
  const dailyStats = await agentActivity.getDailyStats(userId, days);
  const hourlyDist = await agentActivity.getHourlyDistribution(userId, days);
  const resourceStats = await agentActivity.getResourceStats(userId, days);
  const baselines = await agentBaselines.getAllForUser(userId);
  const recentAlerts = await anomalyAlerts.getRecent(userId, 10);
  const alertCounts = await anomalyAlerts.countBySeverity(userId, days);

  // Aggregate daily stats by action type
  const actionTotals = {};
  const dailyTotals = {};

  for (const row of dailyStats) {
    const date = row.date.toISOString().split("T")[0];
    const action = row.action_type;
    const count = parseInt(row.count, 10);

    actionTotals[action] = (actionTotals[action] || 0) + count;

    if (!dailyTotals[date]) {
      dailyTotals[date] = { total: 0, byAction: {} };
    }
    dailyTotals[date].total += count;
    dailyTotals[date].byAction[action] = count;
  }

  // Calculate totals
  const totalActivity = Object.values(actionTotals).reduce((a, b) => a + b, 0);
  const avgPerDay = totalActivity / days;

  // Find peak hours
  const peakHours = hourlyDist
    .toSorted((a, b) => parseInt(b.count, 10) - parseInt(a.count, 10))
    .slice(0, 3)
    .map((row) => ({
      hour: row.hour_of_day,
      count: parseInt(row.count, 10),
    }));

  return {
    period: {
      days,
      startDate: new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString(),
      endDate: new Date().toISOString(),
    },
    summary: {
      totalActivity,
      averagePerDay: Math.round(avgPerDay),
      byActionType: actionTotals,
    },
    dailyBreakdown: dailyTotals,
    hourlyDistribution: hourlyDist.map((row) => ({
      hour: row.hour_of_day,
      count: parseInt(row.count, 10),
    })),
    peakHours,
    topResources: resourceStats.map((row) => ({
      resource: row.resource,
      count: parseInt(row.count, 10),
    })),
    baselines: baselines.map((b) => ({
      metric: b.metric_name,
      baseline: parseFloat(b.baseline_value),
      stddev: parseFloat(b.stddev_value),
      samples: b.sample_count,
    })),
    securityAlerts: {
      total: recentAlerts.length,
      bySeverity: Object.fromEntries(
        alertCounts.map((row) => [row.severity, parseInt(row.count, 10)]),
      ),
      recent: recentAlerts.slice(0, 5).map((a) => ({
        id: a.id,
        type: a.alert_type,
        severity: a.severity,
        description: a.description,
        createdAt: a.created_at,
        acknowledged: !!a.acknowledged_at,
      })),
    },
  };
}

/**
 * Update baselines with end-of-day statistics
 * Should be called periodically (e.g., daily via cron)
 */
export async function updateDailyBaselines(userId) {
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const dailyCount = await agentActivity.getTodayCount(userId);
  await agentBaselines.upsert(userId, "daily_activity", dailyCount);

  // Update action-specific baselines
  for (const actionType of Object.values(ACTION_TYPES)) {
    const count = await agentActivity.getTodayCount(userId, actionType);
    if (count > 0) {
      await agentBaselines.upsert(userId, `daily_${actionType}`, count);
    }
  }
}

/**
 * Cleanup old activity logs
 */
export async function cleanupOldActivity(daysToKeep = 90) {
  return await agentActivity.cleanup(daysToKeep);
}
