/**
 * SLA Monitoring Routes
 * Wave 5.7 - Multi-tenant SaaS Enterprise Features
 *
 * Provides API endpoints for SLA monitoring:
 * - GET /api/tenants/:id/sla - Get SLA status for a tenant
 * - GET /api/tenants/:id/sla/report - Generate SLA report
 * - GET /api/tenants/:id/sla/history - Historical SLA data
 * - POST /api/tenants/:id/sla/alerts - Configure SLA alerts
 * - GET /api/tenants/:id/sla/credits - Get credit history
 * - POST /api/tenants/:id/sla/credits/apply - Apply credits
 *
 * Also provides platform admin endpoints:
 * - GET /api/admin/sla/overview - Platform-wide SLA overview
 * - GET /api/admin/sla/breaches - List SLA breaches
 */

import { Router } from "express";
import { z } from "zod";
import { tenants, subscriptions, audit } from "../db/index.js";
import {
  getSLAStatus,
  getSLADefinition,
  generateSLAReport,
  getSLAHistory,
  calculateCredits,
  applyCredits,
  getCreditHistory,
  setSLAAlertThreshold,
  getSLAAlertThresholds,
  calculateUptime,
  calculateLatencyP99,
  isSLAMet,
} from "../lib/sla-monitor.js";
import { requireUser } from "../middleware/auth.js";
import {
  detectTenant,
  requireTenant,
  requireTenantOwnerRole,
} from "../middleware/tenant-context.js";

const router = Router();

// ============================================================
// VALIDATION SCHEMAS
// ============================================================

const uuidSchema = z.string().uuid();

const periodSchema = z.object({
  period: z.enum(["hour", "day", "week", "month"]).optional().default("month"),
});

const historySchema = z.object({
  days: z.coerce.number().int().min(1).max(90).optional().default(30),
});

const alertThresholdSchema = z.object({
  metric: z.enum(["uptime", "latency", "errorRate", "supportResponse"]),
  threshold: z.number().min(0).max(100),
});

// ============================================================
// PLATFORM ADMIN MIDDLEWARE
// ============================================================

/**
 * Check if user is a platform admin
 */
function isPlatformAdmin(user) {
  return user?.is_platform_admin === true;
}

/**
 * Middleware to require platform admin access
 */
function requirePlatformAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({
      error: "Authentication required",
      code: "AUTH_REQUIRED",
    });
  }

  if (!isPlatformAdmin(req.user)) {
    return res.status(403).json({
      error: "Platform admin access required",
      code: "PLATFORM_ADMIN_REQUIRED",
    });
  }

  next();
}

// ============================================================
// TENANT SLA ROUTES
// ============================================================

/**
 * GET /api/tenants/:id/sla
 * Get current SLA status for a tenant
 *
 * Accessible to:
 * - Tenant members (their own tenant)
 * - Platform admins (any tenant)
 */
router.get("/tenants/:id/sla", requireUser, async (req, res) => {
  try {
    const parseResult = uuidSchema.safeParse(req.params.id);
    if (!parseResult.success) {
      return res.status(400).json({ error: "Invalid tenant ID" });
    }

    const tenantId = parseResult.data;
    const tenant = await tenants.findById(tenantId);

    if (!tenant) {
      return res.status(404).json({ error: "Tenant not found" });
    }

    // Check authorization
    const isAdmin = isPlatformAdmin(req.user);
    const isTenantMember = req.user.tenant_id === tenantId;

    if (!isAdmin && !isTenantMember) {
      return res.status(403).json({
        error: "Access denied",
        code: "TENANT_ACCESS_DENIED",
      });
    }

    const slaStatus = await getSLAStatus(tenantId);

    res.json(slaStatus);
  } catch (err) {
    console.error("[sla-routes] Error getting SLA status:", err);
    res.status(500).json({ error: "Failed to get SLA status" });
  }
});

/**
 * GET /api/tenants/:id/sla/report
 * Generate comprehensive SLA report
 *
 * Query params:
 * - period: "day" | "week" | "month" (default: month)
 * - format: "json" | "pdf" (default: json, pdf not yet implemented)
 */
router.get("/tenants/:id/sla/report", requireUser, async (req, res) => {
  try {
    const parseResult = uuidSchema.safeParse(req.params.id);
    if (!parseResult.success) {
      return res.status(400).json({ error: "Invalid tenant ID" });
    }

    const periodResult = periodSchema.safeParse(req.query);
    if (!periodResult.success) {
      return res.status(400).json({
        error: "Invalid query parameters",
        details: periodResult.error.issues,
      });
    }

    const tenantId = parseResult.data;
    const { period } = periodResult.data;
    const format = req.query.format || "json";

    const tenant = await tenants.findById(tenantId);
    if (!tenant) {
      return res.status(404).json({ error: "Tenant not found" });
    }

    // Check authorization
    const isAdmin = isPlatformAdmin(req.user);
    const isTenantMember = req.user.tenant_id === tenantId;

    if (!isAdmin && !isTenantMember) {
      return res.status(403).json({
        error: "Access denied",
        code: "TENANT_ACCESS_DENIED",
      });
    }

    const report = await generateSLAReport(tenantId, period);

    if (format === "pdf") {
      // PDF export not yet implemented
      return res.status(501).json({
        error: "PDF export not yet implemented",
        code: "PDF_NOT_IMPLEMENTED",
        report, // Return JSON for now
      });
    }

    // Audit log
    await audit.log(req.user.id, "sla.report.generated", { tenantId, period }, req.ip);

    res.json(report);
  } catch (err) {
    console.error("[sla-routes] Error generating SLA report:", err);
    res.status(500).json({ error: "Failed to generate SLA report" });
  }
});

/**
 * GET /api/tenants/:id/sla/history
 * Get historical SLA data
 *
 * Query params:
 * - days: number 1-90 (default: 30)
 */
router.get("/tenants/:id/sla/history", requireUser, async (req, res) => {
  try {
    const parseResult = uuidSchema.safeParse(req.params.id);
    if (!parseResult.success) {
      return res.status(400).json({ error: "Invalid tenant ID" });
    }

    const historyResult = historySchema.safeParse(req.query);
    if (!historyResult.success) {
      return res.status(400).json({
        error: "Invalid query parameters",
        details: historyResult.error.issues,
      });
    }

    const tenantId = parseResult.data;
    const { days } = historyResult.data;

    const tenant = await tenants.findById(tenantId);
    if (!tenant) {
      return res.status(404).json({ error: "Tenant not found" });
    }

    // Check authorization
    const isAdmin = isPlatformAdmin(req.user);
    const isTenantMember = req.user.tenant_id === tenantId;

    if (!isAdmin && !isTenantMember) {
      return res.status(403).json({
        error: "Access denied",
        code: "TENANT_ACCESS_DENIED",
      });
    }

    const history = await getSLAHistory(tenantId, days);

    res.json(history);
  } catch (err) {
    console.error("[sla-routes] Error getting SLA history:", err);
    res.status(500).json({ error: "Failed to get SLA history" });
  }
});

/**
 * POST /api/tenants/:id/sla/alerts
 * Configure SLA alert thresholds
 *
 * Body:
 * - metric: "uptime" | "latency" | "errorRate" | "supportResponse"
 * - threshold: number (percentage of SLA to trigger alert)
 */
router.post(
  "/tenants/:id/sla/alerts",
  requireUser,
  detectTenant,
  requireTenantOwnerRole,
  async (req, res) => {
    try {
      const parseResult = uuidSchema.safeParse(req.params.id);
      if (!parseResult.success) {
        return res.status(400).json({ error: "Invalid tenant ID" });
      }

      const bodyResult = alertThresholdSchema.safeParse(req.body);
      if (!bodyResult.success) {
        return res.status(400).json({
          error: "Invalid request body",
          details: bodyResult.error.issues,
        });
      }

      const tenantId = parseResult.data;
      const { metric, threshold } = bodyResult.data;

      // Verify tenant ownership
      if (req.tenantId !== tenantId && !isPlatformAdmin(req.user)) {
        return res.status(403).json({
          error: "Access denied",
          code: "TENANT_ACCESS_DENIED",
        });
      }

      setSLAAlertThreshold(tenantId, metric, threshold);

      await audit.log(req.user.id, "sla.alert.configured", { tenantId, metric, threshold }, req.ip);

      const thresholds = getSLAAlertThresholds(tenantId);

      res.json({
        success: true,
        thresholds,
      });
    } catch (err) {
      console.error("[sla-routes] Error configuring SLA alerts:", err);
      res.status(500).json({ error: "Failed to configure SLA alerts" });
    }
  },
);

/**
 * GET /api/tenants/:id/sla/alerts
 * Get current SLA alert thresholds
 */
router.get("/tenants/:id/sla/alerts", requireUser, async (req, res) => {
  try {
    const parseResult = uuidSchema.safeParse(req.params.id);
    if (!parseResult.success) {
      return res.status(400).json({ error: "Invalid tenant ID" });
    }

    const tenantId = parseResult.data;

    // Check authorization
    const isAdmin = isPlatformAdmin(req.user);
    const isTenantMember = req.user.tenant_id === tenantId;

    if (!isAdmin && !isTenantMember) {
      return res.status(403).json({
        error: "Access denied",
        code: "TENANT_ACCESS_DENIED",
      });
    }

    const thresholds = getSLAAlertThresholds(tenantId);

    res.json({ thresholds });
  } catch (err) {
    console.error("[sla-routes] Error getting SLA alert thresholds:", err);
    res.status(500).json({ error: "Failed to get SLA alert thresholds" });
  }
});

/**
 * GET /api/tenants/:id/sla/credits
 * Get credit history for a tenant
 */
router.get("/tenants/:id/sla/credits", requireUser, async (req, res) => {
  try {
    const parseResult = uuidSchema.safeParse(req.params.id);
    if (!parseResult.success) {
      return res.status(400).json({ error: "Invalid tenant ID" });
    }

    const tenantId = parseResult.data;

    const tenant = await tenants.findById(tenantId);
    if (!tenant) {
      return res.status(404).json({ error: "Tenant not found" });
    }

    // Check authorization
    const isAdmin = isPlatformAdmin(req.user);
    const isTenantMember = req.user.tenant_id === tenantId;

    if (!isAdmin && !isTenantMember) {
      return res.status(403).json({
        error: "Access denied",
        code: "TENANT_ACCESS_DENIED",
      });
    }

    // Get current credit calculation
    const currentCredits = await calculateCredits(tenantId, "month");
    const creditHistory = getCreditHistory(tenantId);

    res.json({
      current: currentCredits,
      history: creditHistory,
    });
  } catch (err) {
    console.error("[sla-routes] Error getting SLA credits:", err);
    res.status(500).json({ error: "Failed to get SLA credits" });
  }
});

/**
 * POST /api/tenants/:id/sla/credits/apply
 * Apply SLA credits to billing (platform admin only)
 */
router.post(
  "/tenants/:id/sla/credits/apply",
  requireUser,
  requirePlatformAdmin,
  async (req, res) => {
    try {
      const parseResult = uuidSchema.safeParse(req.params.id);
      if (!parseResult.success) {
        return res.status(400).json({ error: "Invalid tenant ID" });
      }

      const tenantId = parseResult.data;
      const period = req.body.period || new Date().toISOString().slice(0, 7); // YYYY-MM

      const tenant = await tenants.findById(tenantId);
      if (!tenant) {
        return res.status(404).json({ error: "Tenant not found" });
      }

      // Calculate credits for the period
      const credits = await calculateCredits(tenantId, "month");

      if (!credits.enabled || credits.creditAmount === 0) {
        return res.json({
          success: false,
          message: "No credits to apply",
          credits,
        });
      }

      // Apply credits
      const result = await applyCredits(tenantId, period, credits);

      await audit.log(
        req.user.id,
        "sla.credits.applied",
        {
          tenantId,
          period,
          creditAmount: credits.creditAmount,
        },
        req.ip,
      );

      res.json({
        success: true,
        ...result,
        credits,
      });
    } catch (err) {
      console.error("[sla-routes] Error applying SLA credits:", err);
      res.status(500).json({ error: "Failed to apply SLA credits" });
    }
  },
);

// ============================================================
// PLATFORM ADMIN SLA ROUTES
// ============================================================

/**
 * GET /api/admin/sla/overview
 * Get platform-wide SLA overview (admin only)
 */
router.get("/admin/sla/overview", requireUser, requirePlatformAdmin, async (req, res) => {
  try {
    // Get all active tenants
    const allTenants = await tenants.list({ status: "active", limit: 1000 });

    const summary = {
      total: allTenants.length,
      compliant: 0,
      breach: 0,
      byPlan: {
        free: { total: 0, compliant: 0, breach: 0 },
        pro: { total: 0, compliant: 0, breach: 0 },
        enterprise: { total: 0, compliant: 0, breach: 0 },
      },
      breaches: [],
    };

    // Check SLA status for each tenant
    for (const tenant of allTenants) {
      try {
        const subscription = await subscriptions.findByTenantId(tenant.id);
        const planName = subscription?.plan || "free";
        const slaStatus = await getSLAStatus(tenant.id);

        summary.byPlan[planName].total++;

        if (slaStatus.overallStatus === "compliant") {
          summary.compliant++;
          summary.byPlan[planName].compliant++;
        } else {
          summary.breach++;
          summary.byPlan[planName].breach++;
          summary.breaches.push({
            tenantId: tenant.id,
            tenantName: tenant.name,
            plan: planName,
            metrics: slaStatus.metrics,
          });
        }
      } catch (err) {
        console.warn(`[sla-routes] Error checking SLA for tenant ${tenant.id}:`, err.message);
      }
    }

    // Sort breaches by severity (enterprise first, then pro)
    summary.breaches.sort((a, b) => {
      const planOrder = { enterprise: 0, pro: 1, free: 2 };
      return (planOrder[a.plan] || 2) - (planOrder[b.plan] || 2);
    });

    // Limit to top 20 breaches
    summary.breaches = summary.breaches.slice(0, 20);

    await audit.log(req.user.id, "sla.overview.viewed", {}, req.ip);

    res.json({
      summary,
      generatedAt: new Date().toISOString(),
    });
  } catch (err) {
    console.error("[sla-routes] Error getting SLA overview:", err);
    res.status(500).json({ error: "Failed to get SLA overview" });
  }
});

/**
 * GET /api/admin/sla/breaches
 * List all current SLA breaches (admin only)
 */
router.get("/admin/sla/breaches", requireUser, requirePlatformAdmin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const offset = parseInt(req.query.offset) || 0;
    const planFilter = req.query.plan;

    // Get all active tenants
    const allTenants = await tenants.list({ status: "active", limit: 1000 });

    const breaches = [];

    for (const tenant of allTenants) {
      try {
        const subscription = await subscriptions.findByTenantId(tenant.id);
        const planName = subscription?.plan || "free";

        // Apply plan filter if specified
        if (planFilter && planName !== planFilter) continue;

        const slaStatus = await getSLAStatus(tenant.id);

        if (slaStatus.overallStatus === "breach") {
          // Identify which metrics are breaching
          const breachingMetrics = [];
          for (const [metric, data] of Object.entries(slaStatus.metrics)) {
            if (!data.met && !data.noSLA) {
              breachingMetrics.push({
                metric,
                current: data.current,
                required: data.required,
                unit: data.unit,
              });
            }
          }

          breaches.push({
            tenantId: tenant.id,
            tenantName: tenant.name,
            tenantSlug: tenant.slug,
            plan: planName,
            breachingMetrics,
            slaDefinition: getSLADefinition(planName),
            creditsEligible: slaStatus.slaDefinition.credits?.enabled || false,
          });
        }
      } catch (err) {
        console.warn(`[sla-routes] Error checking SLA for tenant ${tenant.id}:`, err.message);
      }
    }

    // Sort by plan priority (enterprise first)
    breaches.sort((a, b) => {
      const planOrder = { enterprise: 0, pro: 1, free: 2 };
      return (planOrder[a.plan] || 2) - (planOrder[b.plan] || 2);
    });

    // Apply pagination
    const paginatedBreaches = breaches.slice(offset, offset + limit);

    await audit.log(req.user.id, "sla.breaches.viewed", { limit, offset, planFilter }, req.ip);

    res.json({
      breaches: paginatedBreaches,
      total: breaches.length,
      limit,
      offset,
    });
  } catch (err) {
    console.error("[sla-routes] Error listing SLA breaches:", err);
    res.status(500).json({ error: "Failed to list SLA breaches" });
  }
});

/**
 * GET /api/admin/sla/definitions
 * Get all SLA definitions (admin only)
 */
router.get("/admin/sla/definitions", requireUser, requirePlatformAdmin, async (req, res) => {
  try {
    res.json({
      definitions: {
        free: getSLADefinition("free"),
        pro: getSLADefinition("pro"),
        enterprise: getSLADefinition("enterprise"),
      },
    });
  } catch (err) {
    console.error("[sla-routes] Error getting SLA definitions:", err);
    res.status(500).json({ error: "Failed to get SLA definitions" });
  }
});

export default router;
