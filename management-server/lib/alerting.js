// Security alerting service
// Handles alert rules, deduplication, throttling, and multi-channel delivery

import crypto from "crypto";
import { notifications } from "../db/index.js";
import { users } from "../db/index.js";
import { alertRules, alertChannels, alertHistory, alertCooldowns } from "../db/security-events.js";
import { sendSecurityAlertEmail, isEmailConfigured } from "./email.js";
import { broadcastToUser } from "./sse.js";

// Alert event types (used by alerting system)
export const ALERT_EVENTS = {
  // Authentication
  AUTH_FAILED_THRESHOLD: "auth.failed_threshold",
  AUTH_NEW_DEVICE: "auth.new_device",
  AUTH_UNUSUAL_LOCATION: "auth.unusual_location",

  // Vault
  VAULT_UNLOCK_FAILED_THRESHOLD: "vault.unlock_failed_threshold",
  VAULT_LOCKED_BY_ANOMALY: "vault.locked_by_anomaly",
  VAULT_PASSWORD_CHANGED: "vault.password_changed",

  // Rate Limits
  RATE_LIMIT_AUTH: "rate_limit.auth",
  RATE_LIMIT_VAULT: "rate_limit.vault",
  RATE_LIMIT_API: "rate_limit.api",

  // Anomaly Detection
  ANOMALY_DETECTED: "anomaly.detected",
  ANOMALY_CRITICAL: "anomaly.critical",

  // Admin Actions
  ADMIN_USER_DELETED: "admin.user_deleted",
  ADMIN_SETTINGS_CHANGED: "admin.settings_changed",

  // Group Security
  GROUP_ADMIN_CHANGED: "group.admin_changed",
  GROUP_VAULT_UNLOCKED: "group.vault_unlocked",

  // Tokens
  TOKEN_REVOKED_ALL: "token.revoked_all",
};

// Default severity levels for alert events
const DEFAULT_SEVERITY = {
  [ALERT_EVENTS.AUTH_FAILED_THRESHOLD]: "warning",
  [ALERT_EVENTS.AUTH_NEW_DEVICE]: "info",
  [ALERT_EVENTS.AUTH_UNUSUAL_LOCATION]: "warning",
  [ALERT_EVENTS.VAULT_UNLOCK_FAILED_THRESHOLD]: "critical",
  [ALERT_EVENTS.VAULT_LOCKED_BY_ANOMALY]: "critical",
  [ALERT_EVENTS.VAULT_PASSWORD_CHANGED]: "warning",
  [ALERT_EVENTS.RATE_LIMIT_AUTH]: "warning",
  [ALERT_EVENTS.RATE_LIMIT_VAULT]: "critical",
  [ALERT_EVENTS.RATE_LIMIT_API]: "warning",
  [ALERT_EVENTS.ANOMALY_DETECTED]: "warning",
  [ALERT_EVENTS.ANOMALY_CRITICAL]: "critical",
  [ALERT_EVENTS.ADMIN_USER_DELETED]: "warning",
  [ALERT_EVENTS.ADMIN_SETTINGS_CHANGED]: "warning",
  [ALERT_EVENTS.GROUP_ADMIN_CHANGED]: "warning",
  [ALERT_EVENTS.GROUP_VAULT_UNLOCKED]: "info",
  [ALERT_EVENTS.TOKEN_REVOKED_ALL]: "critical",
};

// Alert rate limiting (in-memory, per-channel)
// Key: `${channelType}:${channelId || userId}`, Value: { lastSent: timestamp, count: number }
const alertRateLimit = new Map();
const ALERT_RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const ALERT_RATE_LIMIT_MAX = 10; // Max 10 alerts per minute per channel

// Cleanup rate limit entries periodically
setInterval(
  () => {
    const now = Date.now();
    for (const [key, entry] of alertRateLimit.entries()) {
      if (now - entry.lastSent > ALERT_RATE_LIMIT_WINDOW_MS * 2) {
        alertRateLimit.delete(key);
      }
    }
  },
  5 * 60 * 1000,
); // Every 5 minutes

/**
 * Check if we're rate limited for this channel
 */
function isAlertRateLimited(channelKey) {
  const entry = alertRateLimit.get(channelKey);
  if (!entry) {
    return false;
  }

  const now = Date.now();
  if (now - entry.lastSent > ALERT_RATE_LIMIT_WINDOW_MS) {
    // Window expired, reset
    alertRateLimit.set(channelKey, { lastSent: now, count: 1 });
    return false;
  }

  return entry.count >= ALERT_RATE_LIMIT_MAX;
}

/**
 * Record an alert being sent
 */
function recordAlertSent(channelKey) {
  const now = Date.now();
  const entry = alertRateLimit.get(channelKey);

  if (!entry || now - entry.lastSent > ALERT_RATE_LIMIT_WINDOW_MS) {
    alertRateLimit.set(channelKey, { lastSent: now, count: 1 });
  } else {
    entry.count++;
  }
}

/**
 * Generate a deduplication key for an alert
 */
function generateDedupKey(eventType, userId, groupId, metadata = {}) {
  const components = [eventType, userId || "system", groupId || "none", metadata.ipAddress || ""];
  return crypto.createHash("sha256").update(components.join(":")).digest("hex").slice(0, 32);
}

/**
 * Check if an alert is in cooldown period
 */
async function isInCooldown(dedupKey, cooldownMinutes) {
  const cooldown = await alertCooldowns.findByKey(dedupKey);
  if (!cooldown) {
    return false;
  }
  return new Date() < new Date(cooldown.expires_at);
}

/**
 * Update cooldown for an alert
 */
async function updateCooldown(dedupKey, cooldownMinutes) {
  const expiresAt = new Date(Date.now() + cooldownMinutes * 60 * 1000);
  await alertCooldowns.upsert(dedupKey, expiresAt);
}

/**
 * Check if severity meets threshold
 */
function meetsThreshold(severity, threshold) {
  const levels = { debug: 0, info: 1, warning: 2, critical: 3 };
  return (levels[severity] || 0) >= (levels[threshold] || 0);
}

/**
 * Main alert dispatch function
 */
export async function triggerAlert({
  eventType,
  userId,
  groupId,
  title,
  message,
  severity,
  metadata = {},
}) {
  try {
    const effectiveSeverity = severity || DEFAULT_SEVERITY[eventType] || "info";
    const dedupKey = generateDedupKey(eventType, userId, groupId, metadata);

    // Get applicable rules (or use defaults)
    let rules = await alertRules.findApplicable(userId, groupId, eventType);
    if (rules.length === 0) {
      // Default rule: send to in_app and email for warning+ severity
      rules = [
        {
          id: null,
          threshold_count: 1,
          threshold_window_minutes: 15,
          cooldown_minutes: 60,
          severity_threshold: "warning",
          channels: ["in_app", "email"],
        },
      ];
    }

    for (const rule of rules) {
      // Check severity threshold
      if (!meetsThreshold(effectiveSeverity, rule.severity_threshold || "warning")) {
        continue;
      }

      // Check cooldown
      if (await isInCooldown(dedupKey, rule.cooldown_minutes || 60)) {
        console.log(`[alerting] Suppressed by cooldown: ${eventType}`);
        continue;
      }

      // Check threshold count (how many events before alerting)
      const recentCount = await alertHistory.countRecent(
        dedupKey,
        rule.threshold_window_minutes || 15,
      );
      if (recentCount + 1 < (rule.threshold_count || 1)) {
        // Haven't hit threshold yet, just record
        await alertHistory.create({
          ruleId: rule.id,
          userId,
          groupId,
          eventType,
          severity: effectiveSeverity,
          title,
          message,
          metadata,
          dedupKey,
          channelsSent: [],
        });
        continue;
      }

      // Send to channels
      const channels = rule.channels || ["in_app", "email"];
      const channelsSent = [];

      for (const channel of channels) {
        try {
          const sent = await sendToChannel(channel, {
            userId,
            groupId,
            eventType,
            title,
            message,
            severity: effectiveSeverity,
            metadata,
          });
          if (sent) {
            channelsSent.push(channel);
          }
        } catch (err) {
          console.error(`[alerting] Failed to send via ${channel}:`, err.message);
        }
      }

      // Record alert history
      await alertHistory.create({
        ruleId: rule.id,
        userId,
        groupId,
        eventType,
        severity: effectiveSeverity,
        title,
        message,
        metadata,
        dedupKey,
        channelsSent,
      });

      // Update cooldown
      await updateCooldown(dedupKey, rule.cooldown_minutes || 60);
    }
  } catch (err) {
    console.error("[alerting] Error triggering alert:", err);
  }
}

/**
 * Send alert to a specific channel
 */
async function sendToChannel(channel, alert) {
  const rateLimitKey = `${channel}:${alert.userId || "system"}`;

  // Check rate limit
  if (isAlertRateLimited(rateLimitKey)) {
    console.log(`[alerting] Rate limited for ${rateLimitKey}`);
    return false;
  }

  let sent = false;

  switch (channel) {
    case "in_app":
      sent = await sendInAppNotification(alert);
      break;
    case "email":
      sent = await sendEmailAlert(alert);
      break;
    case "slack":
    case "discord":
    case "webhook":
      sent = await sendWebhookAlert(channel, alert);
      break;
    default:
      console.warn(`[alerting] Unknown channel: ${channel}`);
      return false;
  }

  if (sent) {
    recordAlertSent(rateLimitKey);
  }

  return sent;
}

/**
 * Send in-app notification
 */
async function sendInAppNotification({ userId, title, message, severity, metadata, eventType }) {
  if (!userId) {
    return false;
  }

  try {
    const notification = await notifications.create({
      userId,
      type: "security_alert",
      title,
      message,
      severity,
      metadata: { ...metadata, eventType },
    });

    // Broadcast via SSE for real-time update
    broadcastToUser(userId, "security_alert", {
      id: notification.id,
      title,
      message,
      severity,
      eventType,
      timestamp: new Date().toISOString(),
    });

    console.log(`[alerting] In-app notification sent to user ${userId}`);
    return true;
  } catch (err) {
    console.error(`[alerting] Failed to send in-app notification:`, err.message);
    return false;
  }
}

/**
 * Send email alert
 */
async function sendEmailAlert({ userId, title, message, severity, metadata, eventType }) {
  if (!userId) {
    return false;
  }
  if (!isEmailConfigured()) {
    console.log("[alerting] Email not configured, skipping email alert");
    return false;
  }

  try {
    const user = await users.findById(userId);
    if (!user?.email) {
      console.log(`[alerting] User ${userId} has no email, skipping`);
      return false;
    }

    const sent = await sendSecurityAlertEmail({
      to: user.email,
      subject: title,
      eventType,
      severity,
      message,
      metadata,
      actionUrl: `${process.env.USER_UI_URL || "http://localhost:5173"}/activity`,
    });

    if (sent) {
      console.log(`[alerting] Email alert sent to ${user.email}`);
    }
    return sent;
  } catch (err) {
    console.error(`[alerting] Failed to send email alert:`, err.message);
    return false;
  }
}

/**
 * Send webhook alert (Slack, Discord, or generic webhook)
 */
async function sendWebhookAlert(channelType, alert) {
  const { userId, groupId, title, message, severity, metadata, eventType } = alert;

  try {
    const channels = await alertChannels.findByType(userId, groupId, channelType);
    if (channels.length === 0) {
      // No webhooks configured
      return false;
    }

    let anySent = false;

    for (const channel of channels) {
      if (!channel.enabled) {
        continue;
      }

      try {
        const config = await alertChannels.getDecryptedConfig(channel.id);
        if (!config?.webhookUrl) {
          console.warn(`[alerting] Channel ${channel.id} has no webhook URL`);
          continue;
        }

        const payload = formatWebhookPayload(channelType, {
          title,
          message,
          severity,
          metadata,
          eventType,
        });

        const response = await fetch(config.webhookUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...config.headers,
          },
          body: JSON.stringify(payload),
          signal: AbortSignal.timeout(10000),
        });

        if (!response.ok) {
          throw new Error(`Webhook returned ${response.status}`);
        }

        await alertChannels.recordSuccess(channel.id);
        console.log(`[alerting] Webhook alert sent to ${channelType} channel ${channel.name}`);
        anySent = true;
      } catch (err) {
        console.error(`[alerting] Webhook failed for channel ${channel.id}:`, err.message);
        await alertChannels.recordFailure(channel.id, err.message);
      }
    }

    return anySent;
  } catch (err) {
    console.error(`[alerting] Error sending webhook alert:`, err.message);
    return false;
  }
}

/**
 * Format webhook payload based on channel type
 */
function formatWebhookPayload(channelType, alert) {
  const { title, message, severity, metadata, eventType } = alert;
  const timestamp = new Date().toISOString();

  switch (channelType) {
    case "slack":
      return {
        blocks: [
          {
            type: "header",
            text: { type: "plain_text", text: `Security Alert: ${title}`, emoji: true },
          },
          {
            type: "section",
            text: { type: "mrkdwn", text: message },
          },
          {
            type: "context",
            elements: [
              { type: "mrkdwn", text: `*Severity:* ${severity}` },
              { type: "mrkdwn", text: `*Event:* ${eventType}` },
              { type: "mrkdwn", text: `*Time:* ${timestamp}` },
            ],
          },
        ],
        attachments: [
          {
            color:
              severity === "critical" ? "#dc2626" : severity === "warning" ? "#f59e0b" : "#6366f1",
          },
        ],
      };

    case "discord":
      return {
        embeds: [
          {
            title: `Security Alert: ${title}`,
            description: message,
            color:
              severity === "critical" ? 0xdc2626 : severity === "warning" ? 0xf59e0b : 0x6366f1,
            fields: [
              { name: "Severity", value: severity, inline: true },
              { name: "Event", value: eventType, inline: true },
            ],
            timestamp,
          },
        ],
      };

    default:
      // Generic webhook format
      return {
        event: eventType,
        title,
        message,
        severity,
        metadata,
        timestamp,
        source: "OCMT",
      };
  }
}

/**
 * Check alert rules for an event (used by external callers)
 */
export async function checkAlertRules(event) {
  const { eventType, userId, groupId } = event;
  const rules = await alertRules.findApplicable(userId, groupId, eventType);
  return rules;
}

/**
 * Send a test alert to a specific channel
 */
export async function sendTestAlert(channelId, userId) {
  const channel = await alertChannels
    .listForUser(userId)
    .then((channels) => channels.find((c) => c.id === channelId));

  if (!channel) {
    return { success: false, error: "Channel not found" };
  }

  try {
    const config = await alertChannels.getDecryptedConfig(channelId);
    if (!config?.webhookUrl) {
      return { success: false, error: "No webhook URL configured" };
    }

    const payload = formatWebhookPayload(channel.channel_type, {
      title: "Test Alert",
      message: "This is a test alert from OCMT to verify your webhook configuration.",
      severity: "info",
      metadata: { test: true },
      eventType: "test.webhook",
    });

    const response = await fetch(config.webhookUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...config.headers,
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(10000),
    });

    if (!response.ok) {
      return { success: false, error: `Webhook returned ${response.status}` };
    }

    await alertChannels.recordSuccess(channelId);
    return { success: true };
  } catch (err) {
    await alertChannels.recordFailure(channelId, err.message);
    return { success: false, error: err.message };
  }
}

/**
 * Cleanup expired cooldowns (call periodically)
 */
export async function cleanupExpiredCooldowns() {
  try {
    const deleted = await alertCooldowns.deleteExpired();
    if (deleted > 0) {
      console.log(`[alerting] Cleaned up ${deleted} expired cooldowns`);
    }
    return deleted;
  } catch (err) {
    console.error("[alerting] Failed to cleanup cooldowns:", err.message);
    return 0;
  }
}

// Run cooldown cleanup every hour
setInterval(cleanupExpiredCooldowns, 60 * 60 * 1000);

export default {
  triggerAlert,
  checkAlertRules,
  sendTestAlert,
  cleanupExpiredCooldowns,
  ALERT_EVENTS,
};
