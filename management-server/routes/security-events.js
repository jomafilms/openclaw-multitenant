// Security events and alerting API routes
// Provides endpoints for viewing security events and managing alert rules

import { Router } from "express";
import { securityEvents, alertRules, alertChannels, alertHistory } from "../db/security-events.js";
import { ALERT_EVENTS, sendTestAlert } from "../lib/alerting.js";
import { createRateLimiter } from "../lib/rate-limit.js";
import { SECURITY_EVENT_TYPES, SEVERITY } from "../lib/security-events.js";
import { requireUser, requireAdmin } from "../middleware/auth.js";
import { detectTenant } from "../middleware/tenant-context.js";

const router = Router();

// Rate limiter for alert channel creation (prevent spam)
const alertChannelLimiter = createRateLimiter({
  name: "alert-channel",
  windowMs: 60 * 60 * 1000, // 1 hour
  maxRequests: 20,
  message: "Too many alert channel requests. Please try again later.",
});

// ============================================================
// SECURITY EVENTS (Admin only - view all events)
// ============================================================

/**
 * GET /api/security-events
 * List security events (admin only)
 */
router.get("/", requireUser, detectTenant, requireAdmin, async (req, res) => {
  try {
    const {
      userId,
      groupId,
      eventType,
      severity,
      limit = 100,
      offset = 0,
      startDate,
      endDate,
    } = req.query;

    const events = await securityEvents.getEvents({
      userId,
      groupId,
      eventType,
      severity,
      limit: Math.min(parseInt(limit) || 100, 500),
      offset: parseInt(offset) || 0,
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
    });

    const total = await securityEvents.countEvents({
      userId,
      groupId,
      eventType,
      severity,
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
    });

    res.json({
      events,
      total,
      limit: Math.min(parseInt(limit) || 100, 500),
      offset: parseInt(offset) || 0,
    });
  } catch (err) {
    console.error("[security-events] Error fetching events:", err);
    res.status(500).json({ error: "Failed to fetch security events" });
  }
});

/**
 * GET /api/security-events/my-events
 * List security events for the current user
 */
router.get("/my-events", requireUser, detectTenant, async (req, res) => {
  try {
    const { limit = 50 } = req.query;
    const events = await securityEvents.getRecentForUser(
      req.user.id,
      Math.min(parseInt(limit) || 50, 200),
    );

    res.json({ events });
  } catch (err) {
    console.error("[security-events] Error fetching user events:", err);
    res.status(500).json({ error: "Failed to fetch security events" });
  }
});

/**
 * GET /api/security-events/types
 * List available event types
 */
router.get("/types", requireUser, detectTenant, (req, res) => {
  const eventTypes = Object.entries(SECURITY_EVENT_TYPES).map(([key, value]) => ({
    key,
    value,
    category: value.split("_")[0],
  }));

  const alertTypes = Object.entries(ALERT_EVENTS).map(([key, value]) => ({
    key,
    value,
    category: value.split(".")[0],
  }));

  const severities = Object.values(SEVERITY);

  res.json({
    eventTypes,
    alertTypes,
    severities,
  });
});

// ============================================================
// ALERT RULES
// ============================================================

/**
 * GET /api/security-events/alert-rules
 * List alert rules for current user
 */
router.get("/alert-rules", requireUser, detectTenant, async (req, res) => {
  try {
    const rules = await alertRules.listForUser(req.user.id);
    res.json({ rules });
  } catch (err) {
    console.error("[security-events] Error fetching alert rules:", err);
    res.status(500).json({ error: "Failed to fetch alert rules" });
  }
});

/**
 * POST /api/security-events/alert-rules
 * Create or update an alert rule
 */
router.post("/alert-rules", requireUser, detectTenant, async (req, res) => {
  try {
    const {
      id,
      eventType,
      severityThreshold,
      thresholdCount,
      thresholdWindowMinutes,
      enabled,
      cooldownMinutes,
      channels,
      metadata,
    } = req.body;

    // Validate eventType
    if (!eventType) {
      return res.status(400).json({ error: "eventType is required" });
    }

    // Validate channels if provided
    if (channels) {
      const validChannels = ["in_app", "email", "slack", "discord", "webhook"];
      if (!Array.isArray(channels) || !channels.every((c) => validChannels.includes(c))) {
        return res.status(400).json({
          error: "Invalid channels. Valid options: in_app, email, slack, discord, webhook",
        });
      }
    }

    // Validate severity threshold
    if (
      severityThreshold &&
      !["debug", "info", "warning", "critical"].includes(severityThreshold)
    ) {
      return res.status(400).json({
        error: "Invalid severityThreshold. Valid options: debug, info, warning, critical",
      });
    }

    const rule = await alertRules.upsert({
      id,
      userId: req.user.id,
      eventType,
      severityThreshold,
      thresholdCount: thresholdCount ? parseInt(thresholdCount) : undefined,
      thresholdWindowMinutes: thresholdWindowMinutes ? parseInt(thresholdWindowMinutes) : undefined,
      enabled,
      cooldownMinutes: cooldownMinutes ? parseInt(cooldownMinutes) : undefined,
      channels,
      metadata,
    });

    res.json({ rule });
  } catch (err) {
    console.error("[security-events] Error saving alert rule:", err);
    res.status(500).json({ error: "Failed to save alert rule" });
  }
});

/**
 * DELETE /api/security-events/alert-rules/:id
 * Delete an alert rule
 */
router.delete("/alert-rules/:id", requireUser, detectTenant, async (req, res) => {
  try {
    const { id } = req.params;

    // Validate UUID format
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(id)) {
      return res.status(400).json({ error: "Invalid rule ID" });
    }

    const deleted = await alertRules.delete(id, req.user.id);

    if (!deleted) {
      return res.status(404).json({ error: "Alert rule not found" });
    }

    res.json({ success: true });
  } catch (err) {
    console.error("[security-events] Error deleting alert rule:", err);
    res.status(500).json({ error: "Failed to delete alert rule" });
  }
});

// ============================================================
// ALERT CHANNELS (Webhooks)
// ============================================================

/**
 * GET /api/security-events/alert-channels
 * List alert channels for current user
 */
router.get("/alert-channels", requireUser, detectTenant, async (req, res) => {
  try {
    const channels = await alertChannels.listForUser(req.user.id);

    // Don't expose encrypted config
    const sanitizedChannels = channels.map((c) => ({
      id: c.id,
      channelType: c.channel_type,
      name: c.name,
      enabled: c.enabled,
      lastSuccessAt: c.last_success_at,
      lastFailureAt: c.last_failure_at,
      failureCount: c.failure_count,
      createdAt: c.created_at,
    }));

    res.json({ channels: sanitizedChannels });
  } catch (err) {
    console.error("[security-events] Error fetching alert channels:", err);
    res.status(500).json({ error: "Failed to fetch alert channels" });
  }
});

/**
 * POST /api/security-events/alert-channels
 * Create a new alert channel (webhook)
 */
router.post("/alert-channels", requireUser, detectTenant, alertChannelLimiter, async (req, res) => {
  try {
    const { channelType, name, webhookUrl, headers } = req.body;

    // Validate required fields
    if (!channelType || !name || !webhookUrl) {
      return res.status(400).json({ error: "channelType, name, and webhookUrl are required" });
    }

    // Validate channel type
    const validTypes = ["slack", "discord", "webhook"];
    if (!validTypes.includes(channelType)) {
      return res
        .status(400)
        .json({ error: "Invalid channelType. Valid options: slack, discord, webhook" });
    }

    // Validate webhook URL
    try {
      const url = new URL(webhookUrl);
      if (!["http:", "https:"].includes(url.protocol)) {
        return res.status(400).json({ error: "webhookUrl must be HTTP or HTTPS" });
      }
    } catch {
      return res.status(400).json({ error: "Invalid webhookUrl format" });
    }

    // Validate name length
    if (name.length > 255) {
      return res.status(400).json({ error: "name must be 255 characters or less" });
    }

    const channel = await alertChannels.create({
      userId: req.user.id,
      channelType,
      name,
      config: { webhookUrl, headers: headers || {} },
    });

    res.json({
      channel: {
        id: channel.id,
        channelType: channel.channel_type,
        name: channel.name,
        enabled: channel.enabled,
        createdAt: channel.created_at,
      },
    });
  } catch (err) {
    console.error("[security-events] Error creating alert channel:", err);
    res.status(500).json({ error: "Failed to create alert channel" });
  }
});

/**
 * POST /api/security-events/alert-channels/:id/test
 * Send a test alert to a channel
 */
router.post("/alert-channels/:id/test", requireUser, detectTenant, async (req, res) => {
  try {
    const { id } = req.params;

    // Validate UUID format
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(id)) {
      return res.status(400).json({ error: "Invalid channel ID" });
    }

    const result = await sendTestAlert(id, req.user.id);

    if (result.success) {
      res.json({ success: true, message: "Test alert sent successfully" });
    } else {
      res.status(400).json({ success: false, error: result.error });
    }
  } catch (err) {
    console.error("[security-events] Error testing alert channel:", err);
    res.status(500).json({ error: "Failed to test alert channel" });
  }
});

/**
 * PATCH /api/security-events/alert-channels/:id
 * Update channel enabled status
 */
router.patch("/alert-channels/:id", requireUser, detectTenant, async (req, res) => {
  try {
    const { id } = req.params;
    const { enabled } = req.body;

    // Validate UUID format
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(id)) {
      return res.status(400).json({ error: "Invalid channel ID" });
    }

    if (typeof enabled !== "boolean") {
      return res.status(400).json({ error: "enabled must be a boolean" });
    }

    const channel = await alertChannels.setEnabled(id, req.user.id, enabled);

    if (!channel) {
      return res.status(404).json({ error: "Alert channel not found" });
    }

    res.json({
      channel: {
        id: channel.id,
        channelType: channel.channel_type,
        name: channel.name,
        enabled: channel.enabled,
      },
    });
  } catch (err) {
    console.error("[security-events] Error updating alert channel:", err);
    res.status(500).json({ error: "Failed to update alert channel" });
  }
});

/**
 * DELETE /api/security-events/alert-channels/:id
 * Delete an alert channel
 */
router.delete("/alert-channels/:id", requireUser, detectTenant, async (req, res) => {
  try {
    const { id } = req.params;

    // Validate UUID format
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(id)) {
      return res.status(400).json({ error: "Invalid channel ID" });
    }

    const deleted = await alertChannels.delete(id, req.user.id);

    if (!deleted) {
      return res.status(404).json({ error: "Alert channel not found" });
    }

    res.json({ success: true });
  } catch (err) {
    console.error("[security-events] Error deleting alert channel:", err);
    res.status(500).json({ error: "Failed to delete alert channel" });
  }
});

// ============================================================
// ALERT HISTORY
// ============================================================

/**
 * GET /api/security-events/alert-history
 * List alert history for current user
 */
router.get("/alert-history", requireUser, detectTenant, async (req, res) => {
  try {
    const { limit = 50 } = req.query;
    const history = await alertHistory.listForUser(
      req.user.id,
      Math.min(parseInt(limit) || 50, 200),
    );

    res.json({ history });
  } catch (err) {
    console.error("[security-events] Error fetching alert history:", err);
    res.status(500).json({ error: "Failed to fetch alert history" });
  }
});

export default router;
