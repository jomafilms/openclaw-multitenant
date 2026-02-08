/**
 * Audit Log Export Routes - SIEM Integration
 * Wave 5.4 Enterprise Feature
 *
 * Provides:
 * - Export audit logs in multiple formats (JSON, CSV, CEF, Syslog)
 * - Real-time SSE stream for live events
 * - Webhook configuration for SIEM delivery
 * - Batch export for large date ranges
 * - Rate limiting on exports
 */

import crypto from "crypto";
import { Router } from "express";
import { z } from "zod";
import { meshAuditLogs, MESH_AUDIT_EVENTS, query, tenants } from "../db/index.js";
import { isAtLeastPlan } from "../lib/quotas.js";
import { getClientIp } from "../lib/rate-limit.js";
import { validate, uuidSchema } from "../lib/schemas.js";
import { requireUser, requireAdmin } from "../middleware/auth.js";
import { requireUserSSE } from "../middleware/sse-auth.js";
import { detectTenant, requireTenant, requireActiveTenant } from "../middleware/tenant-context.js";

const router = Router();

// ============================================================
// CONSTANTS AND CONFIGURATION
// ============================================================

// Supported export formats
const EXPORT_FORMATS = {
  JSON: "json",
  CSV: "csv",
  CEF: "cef", // Common Event Format
  SYSLOG: "syslog",
};

// Supported SIEM types
const SIEM_TYPES = {
  SPLUNK: "splunk",
  DATADOG: "datadog",
  ELASTIC: "elastic",
  CUSTOM: "custom",
};

// Rate limiting configuration
const EXPORT_LIMITS = {
  exports_per_hour: 10,
  max_records_per_export: 50000,
  max_stream_connections_per_tenant: 5,
  max_date_range_days: 90,
};

// Webhook retry configuration
const WEBHOOK_RETRY = {
  max_retries: 5,
  initial_delay_ms: 1000, // 1 second
  max_delay_ms: 60000, // 1 minute
  backoff_multiplier: 2,
};

// In-memory stores for rate limiting and SSE connections
const exportUsage = new Map(); // tenantId -> { count, windowStart }
const sseConnections = new Map(); // tenantId -> Set of response objects
const webhookStatus = new Map(); // tenantId -> { deliveries, failures, lastDelivery }

// ============================================================
// VALIDATION SCHEMAS
// ============================================================

// Export query parameters
const exportQuerySchema = z.object({
  format: z.enum(["json", "csv", "cef", "syslog"]).default("json"),
  startDate: z.coerce.date().optional(),
  endDate: z.coerce.date().optional(),
  actions: z.string().optional(), // Comma-separated list of action types
  userId: z.string().uuid().optional(),
  resourceId: z.string().uuid().optional(),
  severity: z.enum(["low", "medium", "high", "critical"]).optional(),
  limit: z.coerce.number().int().min(1).max(50000).default(1000),
  offset: z.coerce.number().int().min(0).default(0),
});

// Webhook configuration schema
const webhookConfigSchema = z.object({
  url: z.string().url("Invalid webhook URL"),
  secret: z.string().min(16, "Secret must be at least 16 characters").optional(),
  format: z.enum(["json", "cef", "syslog"]).default("json"),
  siemType: z.enum(["splunk", "datadog", "elastic", "custom"]).default("custom"),
  events: z.array(z.string()).optional(), // Filter specific event types
  headers: z.record(z.string()).optional(), // Custom headers
  enabled: z.boolean().default(true),
});

// Batch export request schema
const batchExportSchema = z.object({
  startDate: z.coerce.date(),
  endDate: z.coerce.date(),
  format: z.enum(["json", "csv", "cef", "syslog"]).default("json"),
  actions: z.array(z.string()).optional(),
  chunkSize: z.coerce.number().int().min(1000).max(50000).default(10000),
  email: z.string().email().optional(), // Email when ready
});

// ============================================================
// HELPER FUNCTIONS
// ============================================================

/**
 * Check export rate limit for a tenant
 */
function checkExportRateLimit(tenantId) {
  const now = Date.now();
  const windowMs = 60 * 60 * 1000; // 1 hour

  const usage = exportUsage.get(tenantId) || { count: 0, windowStart: now };

  // Reset window if expired
  if (now - usage.windowStart > windowMs) {
    usage.count = 0;
    usage.windowStart = now;
  }

  if (usage.count >= EXPORT_LIMITS.exports_per_hour) {
    return {
      allowed: false,
      remaining: 0,
      resetAt: new Date(usage.windowStart + windowMs),
    };
  }

  return {
    allowed: true,
    remaining: EXPORT_LIMITS.exports_per_hour - usage.count - 1,
    resetAt: new Date(usage.windowStart + windowMs),
  };
}

/**
 * Increment export usage counter
 */
function incrementExportUsage(tenantId) {
  const now = Date.now();
  const windowMs = 60 * 60 * 1000;
  const usage = exportUsage.get(tenantId) || { count: 0, windowStart: now };

  if (now - usage.windowStart > windowMs) {
    usage.count = 1;
    usage.windowStart = now;
  } else {
    usage.count++;
  }

  exportUsage.set(tenantId, usage);
}

/**
 * Map event to severity level
 */
function getEventSeverity(eventType, success) {
  if (!success) {
    return "high";
  }

  if (eventType.startsWith("auth.failed") || eventType.startsWith("auth.mfa_failed")) {
    return "medium";
  }
  if (eventType.includes("denied") || eventType.includes("revoked")) {
    return "medium";
  }
  if (eventType.startsWith("admin.") || eventType.includes("password")) {
    return "medium";
  }

  return "low";
}

/**
 * Convert audit log to CSV format
 */
function formatAsCSV(logs) {
  if (logs.length === 0) {
    return "";
  }

  const headers = [
    "timestamp",
    "event_type",
    "actor_id",
    "target_id",
    "group_id",
    "ip_address",
    "success",
    "error_message",
    "details",
  ];

  const rows = logs.map((log) => {
    return [
      log.timestamp?.toISOString() || "",
      log.event_type || "",
      log.actor_id || "",
      log.target_id || "",
      log.group_id || "",
      log.ip_address || "",
      log.success ? "true" : "false",
      (log.error_message || "").replace(/"/g, '""'),
      JSON.stringify(log.details || {}).replace(/"/g, '""'),
    ]
      .map((v) => `"${v}"`)
      .join(",");
  });

  return [headers.join(","), ...rows].join("\n");
}

/**
 * Convert audit log to CEF (Common Event Format)
 * Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
 */
function formatAsCEF(log) {
  const severity = getEventSeverity(log.event_type, log.success);
  const severityNum = { low: 1, medium: 4, high: 7, critical: 10 }[severity] || 1;

  const extension = [
    `dvc=${log.ip_address || "unknown"}`,
    `suser=${log.actor_id || "unknown"}`,
    `duser=${log.target_id || ""}`,
    `msg=${log.event_type}`,
    `outcome=${log.success ? "success" : "failure"}`,
    `rt=${new Date(log.timestamp).getTime()}`,
  ];

  if (log.group_id) {
    extension.push(`cs1=${log.group_id}`);
    extension.push(`cs1Label=GroupId`);
  }

  if (log.details) {
    extension.push(`cs2=${JSON.stringify(log.details).slice(0, 500)}`);
    extension.push(`cs2Label=Details`);
  }

  const signatureId = log.event_type.replace(/\./g, "_").toUpperCase();

  return (
    `CEF:0|OCMT|AuditLog|1.0|${signatureId}|${log.event_type}|${severityNum}|` + extension.join(" ")
  );
}

/**
 * Convert audit log to Syslog format (RFC 5424)
 */
function formatAsSyslog(log) {
  const severity = getEventSeverity(log.event_type, log.success);
  const priority = { low: 6, medium: 4, high: 2, critical: 1 }[severity] || 6;
  const facility = 10; // security/authorization
  const pri = facility * 8 + priority;

  const timestamp = new Date(log.timestamp).toISOString();
  const hostname = "ocmt";
  const appName = "audit";
  const procId = "-";
  const msgId = log.event_type.replace(/\./g, "_").toUpperCase();

  const structuredData = [
    `[meta actor="${log.actor_id || "-"}" target="${log.target_id || "-"}" ` +
      `ip="${log.ip_address || "-"}" success="${log.success}"]`,
  ];

  if (log.group_id) {
    structuredData.push(`[org groupId="${log.group_id}"]`);
  }

  const message = log.error_message || log.event_type;

  return `<${pri}>1 ${timestamp} ${hostname} ${appName} ${procId} ${msgId} ${structuredData.join("")} ${message}`;
}

/**
 * Format logs based on specified format
 */
function formatLogs(logs, format) {
  switch (format) {
    case EXPORT_FORMATS.CSV:
      return formatAsCSV(logs);
    case EXPORT_FORMATS.CEF:
      return logs.map(formatAsCEF).join("\n");
    case EXPORT_FORMATS.SYSLOG:
      return logs.map(formatAsSyslog).join("\n");
    case EXPORT_FORMATS.JSON:
    default:
      return JSON.stringify(logs, null, 2);
  }
}

/**
 * Get content type for format
 */
function getContentType(format) {
  switch (format) {
    case EXPORT_FORMATS.CSV:
      return "text/csv";
    case EXPORT_FORMATS.CEF:
    case EXPORT_FORMATS.SYSLOG:
      return "text/plain";
    case EXPORT_FORMATS.JSON:
    default:
      return "application/json";
  }
}

/**
 * Get file extension for format
 */
function getFileExtension(format) {
  switch (format) {
    case EXPORT_FORMATS.CSV:
      return "csv";
    case EXPORT_FORMATS.CEF:
      return "cef";
    case EXPORT_FORMATS.SYSLOG:
      return "log";
    case EXPORT_FORMATS.JSON:
    default:
      return "json";
  }
}

/**
 * Filter logs by action types
 */
function filterByActions(logs, actionsString) {
  if (!actionsString) {
    return logs;
  }

  const actions = actionsString.split(",").map((a) => a.trim().toLowerCase());

  return logs.filter((log) => {
    const eventType = (log.event_type || "").toLowerCase();

    return actions.some((action) => {
      // Support wildcard matching (auth.*, vault.*)
      if (action.endsWith("*")) {
        return eventType.startsWith(action.slice(0, -1));
      }
      return eventType === action;
    });
  });
}

/**
 * Sign webhook payload with HMAC-SHA256
 */
function signWebhookPayload(payload, secret) {
  const hmac = crypto.createHmac("sha256", secret);
  hmac.update(typeof payload === "string" ? payload : JSON.stringify(payload));
  return hmac.digest("hex");
}

/**
 * Deliver webhook with exponential backoff retry
 */
async function deliverWebhook(tenantId, config, event) {
  const payload = formatWebhookPayload(event, config);
  const payloadString = typeof payload === "string" ? payload : JSON.stringify(payload);

  const headers = {
    "Content-Type": getContentType(config.format),
    "X-OCMT-Event": event.event_type,
    "X-OCMT-Timestamp": new Date().toISOString(),
    ...config.headers,
  };

  // Add signature if secret is configured
  if (config.secret) {
    headers["X-OCMT-Signature"] = `sha256=${signWebhookPayload(payloadString, config.secret)}`;
  }

  // Add SIEM-specific headers
  if (config.siemType === SIEM_TYPES.SPLUNK) {
    headers["Authorization"] = config.headers?.Authorization || "";
  } else if (config.siemType === SIEM_TYPES.DATADOG) {
    headers["DD-API-KEY"] = config.headers?.["DD-API-KEY"] || "";
  }

  let lastError = null;
  let delay = WEBHOOK_RETRY.initial_delay_ms;

  for (let attempt = 0; attempt < WEBHOOK_RETRY.max_retries; attempt++) {
    try {
      const response = await fetch(config.url, {
        method: "POST",
        headers,
        body: payloadString,
        signal: AbortSignal.timeout(30000), // 30 second timeout
      });

      // Update status
      const status = webhookStatus.get(tenantId) || {
        deliveries: 0,
        failures: 0,
        lastDelivery: null,
        lastStatus: null,
      };

      if (response.ok) {
        status.deliveries++;
        status.lastDelivery = new Date();
        status.lastStatus = "success";
        webhookStatus.set(tenantId, status);

        return { success: true, statusCode: response.status };
      }

      // Non-retryable status codes
      if (response.status >= 400 && response.status < 500 && response.status !== 429) {
        status.failures++;
        status.lastStatus = `error_${response.status}`;
        webhookStatus.set(tenantId, status);

        return {
          success: false,
          statusCode: response.status,
          error: `HTTP ${response.status}`,
        };
      }

      lastError = new Error(`HTTP ${response.status}`);
    } catch (err) {
      lastError = err;
    }

    // Wait before retry with exponential backoff
    if (attempt < WEBHOOK_RETRY.max_retries - 1) {
      await new Promise((resolve) => setTimeout(resolve, delay));
      delay = Math.min(delay * WEBHOOK_RETRY.backoff_multiplier, WEBHOOK_RETRY.max_delay_ms);
    }
  }

  // All retries failed
  const status = webhookStatus.get(tenantId) || {
    deliveries: 0,
    failures: 0,
    lastDelivery: null,
    lastStatus: null,
  };
  status.failures++;
  status.lastStatus = "failed";
  webhookStatus.set(tenantId, status);

  return {
    success: false,
    error: lastError?.message || "Unknown error",
    retries: WEBHOOK_RETRY.max_retries,
  };
}

/**
 * Format event for webhook based on config
 */
function formatWebhookPayload(event, config) {
  switch (config.format) {
    case EXPORT_FORMATS.CEF:
      return formatAsCEF(event);
    case EXPORT_FORMATS.SYSLOG:
      return formatAsSyslog(event);
    case EXPORT_FORMATS.JSON:
    default:
      return {
        timestamp: event.timestamp,
        event_type: event.event_type,
        actor_id: event.actor_id,
        target_id: event.target_id,
        group_id: event.group_id,
        ip_address: event.ip_address,
        success: event.success,
        error_message: event.error_message,
        details: event.details,
        severity: getEventSeverity(event.event_type, event.success),
      };
  }
}

/**
 * Broadcast event to SSE connections for a tenant
 */
function broadcastToTenant(tenantId, event) {
  const connections = sseConnections.get(tenantId);
  if (!connections || connections.size === 0) {
    return;
  }

  const data = JSON.stringify({
    ...event,
    severity: getEventSeverity(event.event_type, event.success),
  });

  for (const res of connections) {
    try {
      res.write(`event: audit\ndata: ${data}\n\n`);
    } catch (err) {
      // Connection closed, will be cleaned up
    }
  }
}

/**
 * Check if user has access to audit exports (enterprise feature)
 */
async function checkEnterpriseAccess(req) {
  // System admins always have access
  if (req.user?.is_platform_admin) {
    return true;
  }

  // Check tenant plan
  if (req.tenant) {
    const tenant = await tenants.findById(req.tenant.id);
    if (tenant?.plan && isAtLeastPlan(tenant.plan, "enterprise")) {
      return true;
    }
  }

  return false;
}

// ============================================================
// ROUTES
// ============================================================

/**
 * GET /api/audit/export
 * Download audit logs in specified format
 */
router.get("/export", requireUser, detectTenant, async (req, res) => {
  try {
    // Parse and validate query params
    const parseResult = exportQuerySchema.safeParse(req.query);
    if (!parseResult.success) {
      return res.status(400).json({
        error: "Invalid query parameters",
        details: parseResult.error.issues,
      });
    }

    const { format, startDate, endDate, actions, userId, resourceId, severity, limit, offset } =
      parseResult.data;

    // Check enterprise access for non-JSON formats
    if (format !== "json") {
      const hasAccess = await checkEnterpriseAccess(req);
      if (!hasAccess) {
        return res.status(402).json({
          error: "Enterprise plan required",
          code: "UPGRADE_REQUIRED",
          message: "CEF, CSV, and Syslog formats require an Enterprise plan",
          upgrade_url: "/billing/upgrade",
        });
      }
    }

    // Check rate limit
    const tenantId = req.tenantId || req.user.id;
    const rateCheck = checkExportRateLimit(tenantId);
    if (!rateCheck.allowed) {
      return res.status(429).json({
        error: "Export rate limit exceeded",
        code: "RATE_LIMIT_EXCEEDED",
        remaining: rateCheck.remaining,
        resetAt: rateCheck.resetAt,
      });
    }

    // Validate date range
    if (startDate && endDate) {
      const rangeMs = endDate.getTime() - startDate.getTime();
      const maxRangeMs = EXPORT_LIMITS.max_date_range_days * 24 * 60 * 60 * 1000;
      if (rangeMs > maxRangeMs) {
        return res.status(400).json({
          error: `Date range cannot exceed ${EXPORT_LIMITS.max_date_range_days} days`,
          code: "DATE_RANGE_TOO_LARGE",
        });
      }
    }

    // Build query options
    const queryOptions = {
      groupId: req.tenantId,
      actorId: userId,
      targetId: resourceId,
      startTime: startDate,
      endTime: endDate,
      limit: Math.min(limit, EXPORT_LIMITS.max_records_per_export),
      offset,
    };

    // Query logs
    let result = await meshAuditLogs.query(queryOptions);
    let logs = result.logs;

    // Filter by actions if specified
    if (actions) {
      logs = filterByActions(logs, actions);
    }

    // Filter by severity if specified
    if (severity) {
      logs = logs.filter((log) => getEventSeverity(log.event_type, log.success) === severity);
    }

    // Increment usage counter
    incrementExportUsage(tenantId);

    // Log the export
    await meshAuditLogs.log({
      eventType: "admin.audit_export",
      actorId: req.user.id,
      groupId: req.tenantId,
      ipAddress: getClientIp(req),
      success: true,
      details: {
        format,
        recordCount: logs.length,
        dateRange: { startDate, endDate },
      },
    });

    // Format and send response
    const content = formatLogs(logs, format);
    const contentType = getContentType(format);
    const extension = getFileExtension(format);
    const filename = `audit-export-${new Date().toISOString().slice(0, 10)}.${extension}`;

    res.setHeader("Content-Type", contentType);
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.setHeader("X-Export-Record-Count", logs.length);
    res.setHeader("X-Export-Rate-Remaining", rateCheck.remaining);

    res.send(content);
  } catch (err) {
    console.error("Export audit logs error:", err);
    res.status(500).json({ error: "Failed to export audit logs" });
  }
});

/**
 * GET /api/audit/stream
 * SSE stream of real-time audit events
 */
router.get("/stream", requireUserSSE, detectTenant, async (req, res) => {
  try {
    // Check enterprise access
    const hasAccess = await checkEnterpriseAccess(req);
    if (!hasAccess) {
      return res.status(402).json({
        error: "Enterprise plan required",
        code: "UPGRADE_REQUIRED",
        message: "Real-time audit streaming requires an Enterprise plan",
        upgrade_url: "/billing/upgrade",
      });
    }

    const tenantId = req.tenantId || req.user.id;

    // Check connection limit
    const connections = sseConnections.get(tenantId);
    if (connections && connections.size >= EXPORT_LIMITS.max_stream_connections_per_tenant) {
      return res.status(429).json({
        error: "Too many stream connections",
        code: "CONNECTION_LIMIT_EXCEEDED",
        limit: EXPORT_LIMITS.max_stream_connections_per_tenant,
      });
    }

    // Setup SSE connection
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("X-Accel-Buffering", "no"); // Disable nginx buffering

    // Add to connections pool
    if (!sseConnections.has(tenantId)) {
      sseConnections.set(tenantId, new Set());
    }
    sseConnections.get(tenantId).add(res);

    // Send connected event
    res.write(
      `event: connected\ndata: ${JSON.stringify({
        tenantId,
        type: "audit-stream",
        timestamp: new Date().toISOString(),
      })}\n\n`,
    );

    // Log connection
    await meshAuditLogs.log({
      eventType: "admin.audit_stream_connected",
      actorId: req.user.id,
      groupId: tenantId,
      ipAddress: getClientIp(req),
      success: true,
    });

    // Heartbeat to keep connection alive
    const heartbeat = setInterval(() => {
      try {
        res.write(`: heartbeat\n\n`);
      } catch (e) {
        // Connection closed
      }
    }, 30000);

    // Cleanup on disconnect
    req.on("close", async () => {
      clearInterval(heartbeat);
      sseConnections.get(tenantId)?.delete(res);
      if (sseConnections.get(tenantId)?.size === 0) {
        sseConnections.delete(tenantId);
      }

      // Log disconnection
      await meshAuditLogs.log({
        eventType: "admin.audit_stream_disconnected",
        actorId: req.user.id,
        groupId: tenantId,
        ipAddress: getClientIp(req),
        success: true,
      });
    });
  } catch (err) {
    console.error("Audit stream error:", err);
    res.status(500).json({ error: "Failed to start audit stream" });
  }
});

/**
 * POST /api/audit/webhook
 * Configure webhook destination for audit events
 */
router.post("/webhook", requireUser, detectTenant, requireActiveTenant, async (req, res) => {
  try {
    // Check enterprise access
    const hasAccess = await checkEnterpriseAccess(req);
    if (!hasAccess) {
      return res.status(402).json({
        error: "Enterprise plan required",
        code: "UPGRADE_REQUIRED",
        message: "Webhook integration requires an Enterprise plan",
        upgrade_url: "/billing/upgrade",
      });
    }

    // Validate config
    const parseResult = webhookConfigSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        error: "Invalid webhook configuration",
        details: parseResult.error.issues,
      });
    }

    const config = parseResult.data;
    const tenantId = req.tenantId;

    // Generate secret if not provided
    if (!config.secret) {
      config.secret = crypto.randomBytes(32).toString("hex");
    }

    // Store webhook config in database
    await query(
      `INSERT INTO audit_webhooks (tenant_id, url, secret_hash, format, siem_type, events, headers, enabled, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       ON CONFLICT (tenant_id)
       DO UPDATE SET url = $2, secret_hash = $3, format = $4, siem_type = $5,
                     events = $6, headers = $7, enabled = $8, updated_at = NOW()`,
      [
        tenantId,
        config.url,
        crypto.createHash("sha256").update(config.secret).digest("hex"),
        config.format,
        config.siemType,
        JSON.stringify(config.events || []),
        JSON.stringify(config.headers || {}),
        config.enabled,
        req.user.id,
      ],
    );

    // Log configuration
    await meshAuditLogs.log({
      eventType: "admin.webhook_configured",
      actorId: req.user.id,
      groupId: tenantId,
      ipAddress: getClientIp(req),
      success: true,
      details: {
        url: config.url,
        format: config.format,
        siemType: config.siemType,
        eventsFilter: config.events?.length || "all",
      },
    });

    res.json({
      success: true,
      message: "Webhook configured successfully",
      webhook: {
        url: config.url,
        format: config.format,
        siemType: config.siemType,
        enabled: config.enabled,
        secret: config.secret, // Return generated secret once
      },
    });
  } catch (err) {
    console.error("Configure webhook error:", err);
    res.status(500).json({ error: "Failed to configure webhook" });
  }
});

/**
 * POST /api/audit/webhook/test
 * Send test event to webhook
 */
router.post("/webhook/test", requireUser, detectTenant, requireActiveTenant, async (req, res) => {
  try {
    // Check enterprise access
    const hasAccess = await checkEnterpriseAccess(req);
    if (!hasAccess) {
      return res.status(402).json({
        error: "Enterprise plan required",
        code: "UPGRADE_REQUIRED",
      });
    }

    const tenantId = req.tenantId;

    // Get webhook config
    const result = await query(
      `SELECT url, format, siem_type, headers FROM audit_webhooks WHERE tenant_id = $1 AND enabled = true`,
      [tenantId],
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "No webhook configured",
        code: "WEBHOOK_NOT_FOUND",
      });
    }

    const webhookConfig = result.rows[0];
    const config = {
      url: webhookConfig.url,
      format: webhookConfig.format,
      siemType: webhookConfig.siem_type,
      headers: webhookConfig.headers,
    };

    // Create test event
    const testEvent = {
      id: crypto.randomUUID(),
      timestamp: new Date(),
      event_type: "admin.webhook_test",
      actor_id: req.user.id,
      target_id: null,
      group_id: tenantId,
      ip_address: getClientIp(req),
      success: true,
      error_message: null,
      details: { test: true, message: "This is a test event from OCMT" },
    };

    // Deliver test event
    const deliveryResult = await deliverWebhook(tenantId, config, testEvent);

    // Log test
    await meshAuditLogs.log({
      eventType: "admin.webhook_test",
      actorId: req.user.id,
      groupId: tenantId,
      ipAddress: getClientIp(req),
      success: deliveryResult.success,
      errorMessage: deliveryResult.error,
    });

    if (deliveryResult.success) {
      res.json({
        success: true,
        message: "Test event delivered successfully",
        statusCode: deliveryResult.statusCode,
      });
    } else {
      res.status(502).json({
        error: "Test event delivery failed",
        code: "DELIVERY_FAILED",
        details: deliveryResult.error,
        retries: deliveryResult.retries,
      });
    }
  } catch (err) {
    console.error("Test webhook error:", err);
    res.status(500).json({ error: "Failed to test webhook" });
  }
});

/**
 * GET /api/audit/webhook/status
 * Get webhook delivery statistics
 */
router.get("/webhook/status", requireUser, detectTenant, async (req, res) => {
  try {
    // Check enterprise access
    const hasAccess = await checkEnterpriseAccess(req);
    if (!hasAccess) {
      return res.status(402).json({
        error: "Enterprise plan required",
        code: "UPGRADE_REQUIRED",
      });
    }

    const tenantId = req.tenantId;

    // Get webhook config
    const configResult = await query(
      `SELECT url, format, siem_type, enabled, created_at, updated_at
       FROM audit_webhooks WHERE tenant_id = $1`,
      [tenantId],
    );

    if (configResult.rows.length === 0) {
      return res.json({
        configured: false,
        message: "No webhook configured",
      });
    }

    const config = configResult.rows[0];

    // Get delivery stats from memory
    const stats = webhookStatus.get(tenantId) || {
      deliveries: 0,
      failures: 0,
      lastDelivery: null,
      lastStatus: null,
    };

    // Get recent delivery history from database
    const historyResult = await query(
      `SELECT event_type, success, error_message, timestamp
       FROM mesh_audit_logs
       WHERE group_id = $1
         AND event_type IN ('admin.webhook_delivery', 'admin.webhook_test')
       ORDER BY timestamp DESC
       LIMIT 20`,
      [tenantId],
    );

    res.json({
      configured: true,
      webhook: {
        url: config.url,
        format: config.format,
        siemType: config.siem_type,
        enabled: config.enabled,
        createdAt: config.created_at,
        updatedAt: config.updated_at,
      },
      stats: {
        totalDeliveries: stats.deliveries,
        totalFailures: stats.failures,
        lastDelivery: stats.lastDelivery,
        lastStatus: stats.lastStatus,
        successRate:
          stats.deliveries + stats.failures > 0
            ? Math.round((stats.deliveries / (stats.deliveries + stats.failures)) * 100)
            : 100,
      },
      recentHistory: historyResult.rows,
    });
  } catch (err) {
    console.error("Get webhook status error:", err);
    res.status(500).json({ error: "Failed to get webhook status" });
  }
});

/**
 * DELETE /api/audit/webhook
 * Remove webhook configuration
 */
router.delete("/webhook", requireUser, detectTenant, requireActiveTenant, async (req, res) => {
  try {
    // Check enterprise access
    const hasAccess = await checkEnterpriseAccess(req);
    if (!hasAccess) {
      return res.status(402).json({
        error: "Enterprise plan required",
        code: "UPGRADE_REQUIRED",
      });
    }

    const tenantId = req.tenantId;

    // Delete webhook config
    const result = await query(`DELETE FROM audit_webhooks WHERE tenant_id = $1 RETURNING id`, [
      tenantId,
    ]);

    if (result.rowCount === 0) {
      return res.status(404).json({
        error: "No webhook configured",
        code: "WEBHOOK_NOT_FOUND",
      });
    }

    // Clear status
    webhookStatus.delete(tenantId);

    // Log deletion
    await meshAuditLogs.log({
      eventType: "admin.webhook_deleted",
      actorId: req.user.id,
      groupId: tenantId,
      ipAddress: getClientIp(req),
      success: true,
    });

    res.json({
      success: true,
      message: "Webhook configuration deleted",
    });
  } catch (err) {
    console.error("Delete webhook error:", err);
    res.status(500).json({ error: "Failed to delete webhook" });
  }
});

/**
 * POST /api/audit/batch-export
 * Start background batch export for large date ranges
 */
router.post("/batch-export", requireUser, detectTenant, requireActiveTenant, async (req, res) => {
  try {
    // Check enterprise access
    const hasAccess = await checkEnterpriseAccess(req);
    if (!hasAccess) {
      return res.status(402).json({
        error: "Enterprise plan required",
        code: "UPGRADE_REQUIRED",
        message: "Batch export requires an Enterprise plan",
        upgrade_url: "/billing/upgrade",
      });
    }

    // Validate request
    const parseResult = batchExportSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        error: "Invalid batch export request",
        details: parseResult.error.issues,
      });
    }

    const { startDate, endDate, format, actions, chunkSize, email } = parseResult.data;
    const tenantId = req.tenantId;

    // Validate date range
    const rangeMs = endDate.getTime() - startDate.getTime();
    const maxRangeMs = EXPORT_LIMITS.max_date_range_days * 24 * 60 * 60 * 1000;
    if (rangeMs > maxRangeMs) {
      return res.status(400).json({
        error: `Date range cannot exceed ${EXPORT_LIMITS.max_date_range_days} days`,
        code: "DATE_RANGE_TOO_LARGE",
      });
    }

    // Create export job
    const jobId = crypto.randomUUID();
    const jobResult = await query(
      `INSERT INTO audit_export_jobs (id, tenant_id, user_id, start_date, end_date, format, actions, chunk_size, email, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending')
       RETURNING id, created_at`,
      [
        jobId,
        tenantId,
        req.user.id,
        startDate,
        endDate,
        format,
        JSON.stringify(actions || []),
        chunkSize,
        email,
      ],
    );

    // Log job creation
    await meshAuditLogs.log({
      eventType: "admin.batch_export_started",
      actorId: req.user.id,
      groupId: tenantId,
      ipAddress: getClientIp(req),
      success: true,
      details: {
        jobId,
        startDate,
        endDate,
        format,
      },
    });

    res.status(202).json({
      success: true,
      message: "Batch export job created",
      job: {
        id: jobId,
        status: "pending",
        createdAt: jobResult.rows[0].created_at,
        estimatedCompletion: null, // Would be calculated by worker
      },
    });

    // Note: In production, a background worker would process this job
    // For now, we just create the job record
  } catch (err) {
    console.error("Batch export error:", err);
    res.status(500).json({ error: "Failed to create batch export job" });
  }
});

/**
 * GET /api/audit/batch-export/:jobId
 * Get status of batch export job
 */
router.get("/batch-export/:jobId", requireUser, detectTenant, async (req, res) => {
  try {
    const { jobId } = req.params;
    const tenantId = req.tenantId;

    const result = await query(
      `SELECT id, status, progress, error_message, download_url, expires_at, created_at, completed_at
       FROM audit_export_jobs
       WHERE id = $1 AND tenant_id = $2`,
      [jobId, tenantId],
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "Export job not found",
        code: "JOB_NOT_FOUND",
      });
    }

    const job = result.rows[0];

    res.json({
      job: {
        id: job.id,
        status: job.status,
        progress: job.progress,
        error: job.error_message,
        downloadUrl: job.download_url,
        expiresAt: job.expires_at,
        createdAt: job.created_at,
        completedAt: job.completed_at,
      },
    });
  } catch (err) {
    console.error("Get batch export status error:", err);
    res.status(500).json({ error: "Failed to get export job status" });
  }
});

/**
 * GET /api/audit/formats
 * Get available export formats and their descriptions
 */
router.get("/formats", requireUser, detectTenant, (req, res) => {
  res.json({
    formats: [
      {
        id: "json",
        name: "JSON",
        description: "Standard JSON format with full event details",
        contentType: "application/json",
        enterpriseOnly: false,
      },
      {
        id: "csv",
        name: "CSV",
        description: "Comma-separated values for spreadsheet import",
        contentType: "text/csv",
        enterpriseOnly: true,
      },
      {
        id: "cef",
        name: "CEF (Common Event Format)",
        description: "ArcSight-compatible format for SIEM systems",
        contentType: "text/plain",
        enterpriseOnly: true,
      },
      {
        id: "syslog",
        name: "Syslog (RFC 5424)",
        description: "Standard syslog format for log aggregators",
        contentType: "text/plain",
        enterpriseOnly: true,
      },
    ],
    siemTypes: [
      { id: "splunk", name: "Splunk", description: "Splunk HTTP Event Collector" },
      { id: "datadog", name: "Datadog", description: "Datadog Logs API" },
      { id: "elastic", name: "Elastic", description: "Elasticsearch/Logstash" },
      { id: "custom", name: "Custom", description: "Custom HTTP endpoint" },
    ],
    eventCategories: Object.entries(MESH_AUDIT_EVENTS).reduce((acc, [key, value]) => {
      const category = key.split("_")[0].toLowerCase();
      if (!acc[category]) {
        acc[category] = [];
      }
      acc[category].push(value);
      return acc;
    }, {}),
  });
});

/**
 * GET /api/audit/usage
 * Get export usage statistics for current tenant
 */
router.get("/usage", requireUser, detectTenant, async (req, res) => {
  try {
    const tenantId = req.tenantId || req.user.id;
    const usage = exportUsage.get(tenantId) || { count: 0, windowStart: Date.now() };
    const windowMs = 60 * 60 * 1000;
    const resetAt = new Date(usage.windowStart + windowMs);

    // Get stream connection count
    const streamConnections = sseConnections.get(tenantId)?.size || 0;

    res.json({
      exports: {
        used: usage.count,
        limit: EXPORT_LIMITS.exports_per_hour,
        remaining: Math.max(0, EXPORT_LIMITS.exports_per_hour - usage.count),
        resetAt,
      },
      streams: {
        active: streamConnections,
        limit: EXPORT_LIMITS.max_stream_connections_per_tenant,
      },
      limits: {
        maxRecordsPerExport: EXPORT_LIMITS.max_records_per_export,
        maxDateRangeDays: EXPORT_LIMITS.max_date_range_days,
      },
    });
  } catch (err) {
    console.error("Get usage error:", err);
    res.status(500).json({ error: "Failed to get usage statistics" });
  }
});

// ============================================================
// EXPORTED FUNCTIONS (for use by other modules)
// ============================================================

/**
 * Broadcast audit event to connected SSE clients and webhooks
 * Called from meshAuditLogs.log() or event processing
 */
export async function broadcastAuditEvent(tenantId, event) {
  // Broadcast to SSE connections
  broadcastToTenant(tenantId, event);

  // Deliver to webhook if configured
  try {
    const result = await query(
      `SELECT url, secret_hash, format, siem_type, events, headers
       FROM audit_webhooks
       WHERE tenant_id = $1 AND enabled = true`,
      [tenantId],
    );

    if (result.rows.length > 0) {
      const webhookConfig = result.rows[0];

      // Check event filter
      const events = webhookConfig.events || [];
      if (events.length > 0 && !events.includes(event.event_type)) {
        return; // Event not in filter
      }

      const config = {
        url: webhookConfig.url,
        format: webhookConfig.format,
        siemType: webhookConfig.siem_type,
        headers: webhookConfig.headers,
      };

      // Fire and forget webhook delivery
      deliverWebhook(tenantId, config, event).catch((err) => {
        console.error(`Webhook delivery error for tenant ${tenantId}:`, err);
      });
    }
  } catch (err) {
    console.error(`Error checking webhook for tenant ${tenantId}:`, err);
  }
}

export default router;
