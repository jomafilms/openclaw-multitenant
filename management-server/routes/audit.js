// Audit log routes - User and Admin access to audit logs
import { Router } from "express";
import { z } from "zod";
import { audit, meshAuditLogs, MESH_AUDIT_EVENTS, groupMemberships } from "../db/index.js";
import { validate, groupIdParamSchema, uuidSchema } from "../lib/schemas.js";
import { requireUser } from "../middleware/auth.js";
import { requireGroupAdmin } from "../middleware/group-auth.js";
import { detectTenant } from "../middleware/tenant-context.js";

const router = Router();

// Admin email check
function isAdmin(user) {
  const adminEmails = (process.env.ADMIN_EMAILS || "")
    .split(",")
    .map((e) => e.trim().toLowerCase());
  return adminEmails.includes(user.email?.toLowerCase());
}

// Middleware: require system admin
function requireSystemAdmin(req, res, next) {
  if (!isAdmin(req.user)) {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
}

// Query schema for mesh audit logs
const meshAuditQuerySchema = z.object({
  groupId: z.string().uuid().optional(),
  actorId: z.string().max(128).optional(),
  targetId: z.string().max(128).optional(),
  eventType: z.string().max(64).optional(),
  successOnly: z.coerce.boolean().optional(),
  failuresOnly: z.coerce.boolean().optional(),
  startTime: z.coerce.date().optional(),
  endTime: z.coerce.date().optional(),
  limit: z.coerce.number().int().min(1).max(1000).default(100),
  offset: z.coerce.number().int().min(0).default(0),
});

// ─────────────────────────────────────────────────────────────────────────────
// User Audit Endpoints
// ─────────────────────────────────────────────────────────────────────────────

// Get user's activity log (for personal audit UI)
router.get("/", requireUser, detectTenant, async (req, res) => {
  try {
    const logs = await audit.getForUser(req.user.id, 100);
    res.json({ logs });
  } catch (err) {
    console.error("Get audit log error:", err);
    res.status(500).json({ error: "Failed to get audit log" });
  }
});

// Get user's mesh audit logs (security events)
router.get("/mesh", requireUser, detectTenant, async (req, res) => {
  try {
    const logs = await meshAuditLogs.getForUser(req.user.id, 100);
    res.json({ logs, total: logs.length });
  } catch (err) {
    console.error("Get mesh audit log error:", err);
    res.status(500).json({ error: "Failed to get mesh audit log" });
  }
});

// Get user's failed auth attempts
router.get("/auth-failures", requireUser, detectTenant, async (req, res) => {
  try {
    const hours = parseInt(req.query.hours || "24", 10);
    const logs = await meshAuditLogs.getFailedAuthAttempts(req.user.id, hours);
    res.json({ logs, total: logs.length, hours });
  } catch (err) {
    console.error("Get auth failures error:", err);
    res.status(500).json({ error: "Failed to get auth failures" });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Organization Admin Audit Endpoints
// ─────────────────────────────────────────────────────────────────────────────

// Get audit logs for an organization (org admin only)
router.get(
  "/group/:groupId",
  requireUser,
  detectTenant,
  validate({ params: groupIdParamSchema }),
  async (req, res) => {
    try {
      const { groupId } = req.validatedParams;

      // Check if user is org admin
      const membership = await groupMemberships.findByUserAndGroup(req.user.id, groupId);
      if (!membership || membership.role !== "admin") {
        return res.status(403).json({ error: "Group admin access required" });
      }

      const limit = parseInt(req.query.limit || "100", 10);
      const logs = await meshAuditLogs.getForGroup(groupId, Math.min(limit, 500));

      res.json({ logs, total: logs.length, groupId });
    } catch (err) {
      console.error("Get org audit log error:", err);
      res.status(500).json({ error: "Failed to get group audit log" });
    }
  },
);

// Get security summary for an organization (org admin only)
router.get(
  "/group/:groupId/summary",
  requireUser,
  detectTenant,
  validate({ params: groupIdParamSchema }),
  async (req, res) => {
    try {
      const { groupId } = req.validatedParams;

      // Check if user is org admin
      const membership = await groupMemberships.findByUserAndGroup(req.user.id, groupId);
      if (!membership || membership.role !== "admin") {
        return res.status(403).json({ error: "Group admin access required" });
      }

      const days = parseInt(req.query.days || "7", 10);
      const summary = await meshAuditLogs.getSecuritySummary(groupId, Math.min(days, 90));

      res.json({ summary, groupId, days });
    } catch (err) {
      console.error("Get org security summary error:", err);
      res.status(500).json({ error: "Failed to get security summary" });
    }
  },
);

// ─────────────────────────────────────────────────────────────────────────────
// System Admin Audit Endpoints
// ─────────────────────────────────────────────────────────────────────────────

// Query mesh audit logs with filtering (system admin only)
router.get("/admin/mesh", requireUser, detectTenant, requireSystemAdmin, async (req, res) => {
  try {
    // Validate and parse query params
    const parseResult = meshAuditQuerySchema.safeParse(req.query);
    if (!parseResult.success) {
      return res.status(400).json({
        error: "Invalid query parameters",
        details: parseResult.error.issues,
      });
    }

    const result = await meshAuditLogs.query(parseResult.data);

    res.json({
      logs: result.logs,
      total: result.total,
      limit: result.limit,
      offset: result.offset,
      hasMore: result.offset + result.logs.length < result.total,
    });
  } catch (err) {
    console.error("Query mesh audit logs error:", err);
    res.status(500).json({ error: "Failed to query audit logs" });
  }
});

// Get recent mesh audit logs (system admin only)
router.get(
  "/admin/mesh/recent",
  requireUser,
  detectTenant,
  requireSystemAdmin,
  async (req, res) => {
    try {
      const limit = Math.min(parseInt(req.query.limit || "100", 10), 500);
      const logs = await meshAuditLogs.getRecent(limit);

      res.json({ logs, total: logs.length });
    } catch (err) {
      console.error("Get recent mesh audit logs error:", err);
      res.status(500).json({ error: "Failed to get recent audit logs" });
    }
  },
);

// Get available event types (for filtering UI)
router.get("/admin/event-types", requireUser, detectTenant, requireSystemAdmin, (req, res) => {
  res.json({
    eventTypes: Object.values(MESH_AUDIT_EVENTS),
    categories: {
      capability: Object.entries(MESH_AUDIT_EVENTS)
        .filter(([k]) => k.startsWith("CAPABILITY_"))
        .map(([, v]) => v),
      vault: Object.entries(MESH_AUDIT_EVENTS)
        .filter(([k]) => k.startsWith("VAULT_") || k.startsWith("ORG_VAULT_"))
        .map(([, v]) => v),
      sharing: Object.entries(MESH_AUDIT_EVENTS)
        .filter(([k]) => k.startsWith("SHARE_"))
        .map(([, v]) => v),
      auth: Object.entries(MESH_AUDIT_EVENTS)
        .filter(([k]) => k.startsWith("AUTH_"))
        .map(([, v]) => v),
      relay: Object.entries(MESH_AUDIT_EVENTS)
        .filter(([k]) => k.startsWith("RELAY_"))
        .map(([, v]) => v),
      integration: Object.entries(MESH_AUDIT_EVENTS)
        .filter(([k]) => k.startsWith("INTEGRATION_"))
        .map(([, v]) => v),
    },
  });
});

// Export audit logs for compliance (system admin only)
router.get("/admin/export", requireUser, detectTenant, requireSystemAdmin, async (req, res) => {
  try {
    const { groupId, startTime, endTime } = req.query;

    if (!startTime || !endTime) {
      return res.status(400).json({
        error: "Both startTime and endTime are required for export",
      });
    }

    const start = new Date(startTime);
    const end = new Date(endTime);

    if (isNaN(start.getTime()) || isNaN(end.getTime())) {
      return res.status(400).json({ error: "Invalid date format" });
    }

    // Limit export range to 90 days
    const maxRangeMs = 90 * 24 * 60 * 60 * 1000;
    if (end.getTime() - start.getTime() > maxRangeMs) {
      return res.status(400).json({
        error: "Export range cannot exceed 90 days",
      });
    }

    const logs = await meshAuditLogs.exportForCompliance({
      groupId,
      startTime: start,
      endTime: end,
    });

    // Set content type for JSON download
    res.setHeader("Content-Type", "application/json");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="audit-export-${start.toISOString().slice(0, 10)}-${end.toISOString().slice(0, 10)}.json"`,
    );

    res.json({
      exportedAt: new Date().toISOString(),
      startTime: start.toISOString(),
      endTime: end.toISOString(),
      groupId: groupId || "all",
      recordCount: logs.length,
      logs,
    });
  } catch (err) {
    console.error("Export audit logs error:", err);
    res.status(500).json({ error: "Failed to export audit logs" });
  }
});

// Cleanup old audit logs (system admin only)
router.post("/admin/cleanup", requireUser, detectTenant, requireSystemAdmin, async (req, res) => {
  try {
    const daysToKeep = parseInt(req.body.daysToKeep || "365", 10);

    if (daysToKeep < 90) {
      return res.status(400).json({
        error: "Minimum retention period is 90 days",
      });
    }

    const deletedCount = await meshAuditLogs.cleanup(daysToKeep);

    // Log this cleanup action
    await meshAuditLogs.log({
      eventType: "admin.audit_cleanup",
      actorId: req.user.id,
      ipAddress: req.ip,
      success: true,
      details: { daysToKeep, deletedCount },
    });

    res.json({
      success: true,
      deletedCount,
      daysKept: daysToKeep,
    });
  } catch (err) {
    console.error("Cleanup audit logs error:", err);
    res.status(500).json({ error: "Failed to cleanup audit logs" });
  }
});

export default router;
