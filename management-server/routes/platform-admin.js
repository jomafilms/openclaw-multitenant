/**
 * Platform Admin Dashboard Backend Routes
 * Wave 4.5 - Multi-tenant SaaS administration
 *
 * Provides endpoints for platform-wide administration:
 * - Tenant management (list, view, suspend, delete)
 * - User management across tenants
 * - Platform-wide statistics
 * - Container management
 *
 * All routes require platform admin authentication
 */

import axios from "axios";
import crypto from "crypto";
import { Router } from "express";
import { z } from "zod";
import {
  users,
  audit,
  tenants,
  tenantMemberships,
  subscriptions,
  usage,
  groups,
  sessions,
  query,
} from "../db/index.js";
import { AGENT_SERVER_URL, AGENT_SERVER_TOKEN } from "../lib/context.js";
import { requireUser } from "../middleware/auth.js";

const router = Router();

// ============================================================
// PLATFORM ADMIN MIDDLEWARE
// ============================================================

/**
 * Check if user is a platform admin
 * Platform admins are identified by the is_platform_admin flag in the users table
 */
function isPlatformAdmin(user) {
  return user?.is_platform_admin === true;
}

/**
 * Middleware to require platform admin access
 * Must be used after requireUser middleware
 */
function requirePlatformAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({
      error: "Authentication required",
      code: "AUTH_REQUIRED",
    });
  }

  if (!isPlatformAdmin(req.user)) {
    // Log unauthorized access attempt
    audit
      .log(
        req.user.id,
        "platform_admin.access_denied",
        {
          route: req.path,
          method: req.method,
        },
        req.ip,
      )
      .catch(console.error);

    return res.status(403).json({
      error: "Platform admin access required",
      code: "PLATFORM_ADMIN_REQUIRED",
    });
  }

  next();
}

/**
 * Log admin action for audit trail
 */
async function logAdminAction(adminId, action, details, ipAddress) {
  try {
    await audit.log(adminId, `platform_admin.${action}`, details, ipAddress);
  } catch (err) {
    console.error(`[platform-admin] Failed to log action: ${err.message}`);
  }
}

// ============================================================
// VALIDATION SCHEMAS
// ============================================================

const uuidSchema = z.string().uuid();

const paginationSchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

const tenantFilterSchema = paginationSchema.extend({
  status: z.enum(["active", "suspended", "deleted"]).optional(),
  search: z.string().max(100).optional(),
});

const userFilterSchema = paginationSchema.extend({
  status: z.enum(["active", "pending", "suspended", "deleted"]).optional(),
  tenantId: z.string().uuid().optional(),
  search: z.string().max(100).optional(),
});

// ============================================================
// TENANT MANAGEMENT
// ============================================================

/**
 * GET /api/admin/tenants
 * List all tenants with stats (user count, group count, subscription status)
 */
router.get("/tenants", requireUser, requirePlatformAdmin, async (req, res) => {
  try {
    const parseResult = tenantFilterSchema.safeParse(req.query);
    if (!parseResult.success) {
      return res.status(400).json({
        error: "Invalid query parameters",
        details: parseResult.error.issues,
      });
    }

    const { limit, offset, status, search } = parseResult.data;

    // Build query with filters
    const conditions = [];
    const params = [];
    let paramIndex = 1;

    if (status) {
      conditions.push(`t.status = $${paramIndex}`);
      params.push(status);
      paramIndex++;
    }

    if (search) {
      conditions.push(`(t.name ILIKE $${paramIndex} OR t.slug ILIKE $${paramIndex})`);
      params.push(`%${search}%`);
      paramIndex++;
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

    // Main query with aggregations
    const tenantsResult = await query(
      `SELECT
         t.*,
         COUNT(DISTINCT u.id)::int as user_count,
         COUNT(DISTINCT g.id)::int as group_count,
         s.plan as subscription_plan,
         s.status as subscription_status
       FROM tenants t
       LEFT JOIN users u ON u.tenant_id = t.id
       LEFT JOIN groups g ON g.tenant_id = t.id
       LEFT JOIN subscriptions s ON s.tenant_id = t.id
       ${whereClause}
       GROUP BY t.id, s.plan, s.status
       ORDER BY t.created_at DESC
       LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`,
      [...params, limit, offset],
    );

    // Get total count for pagination
    const countResult = await query(
      `SELECT COUNT(DISTINCT t.id)::int as total
       FROM tenants t
       ${whereClause}`,
      params,
    );

    await logAdminAction(req.user.id, "tenants.list", { limit, offset, status, search }, req.ip);

    res.json({
      tenants: tenantsResult.rows,
      total: countResult.rows[0]?.total || 0,
      limit,
      offset,
    });
  } catch (err) {
    console.error("[platform-admin] List tenants error:", err);
    res.status(500).json({ error: "Failed to list tenants" });
  }
});

/**
 * GET /api/admin/tenants/:id
 * Get detailed tenant info
 */
router.get("/tenants/:id", requireUser, requirePlatformAdmin, async (req, res) => {
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

    // Get additional details
    const [members, subscription, groupsResult, ownerResult] = await Promise.all([
      tenantMemberships.getMembers(tenantId),
      subscriptions.findByTenantId(tenantId),
      query("SELECT COUNT(*)::int as count FROM groups WHERE tenant_id = $1", [tenantId]),
      tenant.owner_id ? users.findById(tenant.owner_id) : null,
    ]);

    await logAdminAction(req.user.id, "tenants.view", { tenantId }, req.ip);

    res.json({
      ...tenant,
      owner: ownerResult
        ? {
            id: ownerResult.id,
            name: ownerResult.name,
            email: ownerResult.email,
          }
        : null,
      subscription,
      memberCount: members.length,
      groupCount: groupsResult.rows[0]?.count || 0,
      members: members.slice(0, 10), // First 10 members only
    });
  } catch (err) {
    console.error("[platform-admin] Get tenant error:", err);
    res.status(500).json({ error: "Failed to get tenant details" });
  }
});

/**
 * GET /api/admin/tenants/:id/usage
 * Get usage metrics for a tenant
 */
router.get("/tenants/:id/usage", requireUser, requirePlatformAdmin, async (req, res) => {
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

    const days = parseInt(req.query.days || "30", 10);

    // Get usage aggregated by tenant
    const usageResult = await query(
      `SELECT
         DATE(date) as date,
         SUM(input_tokens)::bigint as input_tokens,
         SUM(output_tokens)::bigint as output_tokens,
         SUM(api_calls)::int as api_calls
       FROM usage u
       JOIN users usr ON u.user_id = usr.id
       WHERE usr.tenant_id = $1
         AND u.date > NOW() - ($2 * INTERVAL '1 day')
       GROUP BY DATE(date)
       ORDER BY date DESC`,
      [tenantId, days],
    );

    // Get totals
    const totalsResult = await query(
      `SELECT
         SUM(input_tokens)::bigint as total_input_tokens,
         SUM(output_tokens)::bigint as total_output_tokens,
         SUM(api_calls)::int as total_api_calls
       FROM usage u
       JOIN users usr ON u.user_id = usr.id
       WHERE usr.tenant_id = $1
         AND u.date > NOW() - ($2 * INTERVAL '1 day')`,
      [tenantId, days],
    );

    await logAdminAction(req.user.id, "tenants.usage", { tenantId, days }, req.ip);

    res.json({
      tenantId,
      days,
      daily: usageResult.rows,
      totals: totalsResult.rows[0] || {
        total_input_tokens: 0,
        total_output_tokens: 0,
        total_api_calls: 0,
      },
    });
  } catch (err) {
    console.error("[platform-admin] Get tenant usage error:", err);
    res.status(500).json({ error: "Failed to get tenant usage" });
  }
});

/**
 * POST /api/admin/tenants/:id/suspend
 * Suspend a tenant
 */
router.post("/tenants/:id/suspend", requireUser, requirePlatformAdmin, async (req, res) => {
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

    if (tenant.status === "suspended") {
      return res.status(400).json({ error: "Tenant is already suspended" });
    }

    const { reason } = req.body || {};

    const updated = await tenants.setStatus(tenantId, "suspended");

    await logAdminAction(
      req.user.id,
      "tenants.suspend",
      {
        tenantId,
        tenantName: tenant.name,
        reason,
      },
      req.ip,
    );

    res.json({
      success: true,
      tenant: updated,
      message: `Tenant "${tenant.name}" has been suspended`,
    });
  } catch (err) {
    console.error("[platform-admin] Suspend tenant error:", err);
    res.status(500).json({ error: "Failed to suspend tenant" });
  }
});

/**
 * POST /api/admin/tenants/:id/unsuspend
 * Unsuspend (reactivate) a tenant
 */
router.post("/tenants/:id/unsuspend", requireUser, requirePlatformAdmin, async (req, res) => {
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

    if (tenant.status !== "suspended") {
      return res.status(400).json({ error: "Tenant is not suspended" });
    }

    const updated = await tenants.setStatus(tenantId, "active");

    await logAdminAction(
      req.user.id,
      "tenants.unsuspend",
      {
        tenantId,
        tenantName: tenant.name,
      },
      req.ip,
    );

    res.json({
      success: true,
      tenant: updated,
      message: `Tenant "${tenant.name}" has been reactivated`,
    });
  } catch (err) {
    console.error("[platform-admin] Unsuspend tenant error:", err);
    res.status(500).json({ error: "Failed to unsuspend tenant" });
  }
});

/**
 * DELETE /api/admin/tenants/:id
 * Soft delete a tenant
 */
router.delete("/tenants/:id", requireUser, requirePlatformAdmin, async (req, res) => {
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

    if (tenant.status === "deleted") {
      return res.status(400).json({ error: "Tenant is already deleted" });
    }

    // Soft delete by setting status
    const updated = await tenants.delete(tenantId);

    await logAdminAction(
      req.user.id,
      "tenants.delete",
      {
        tenantId,
        tenantName: tenant.name,
      },
      req.ip,
    );

    res.json({
      success: true,
      tenant: updated,
      message: `Tenant "${tenant.name}" has been deleted`,
    });
  } catch (err) {
    console.error("[platform-admin] Delete tenant error:", err);
    res.status(500).json({ error: "Failed to delete tenant" });
  }
});

// ============================================================
// USER MANAGEMENT
// ============================================================

/**
 * GET /api/admin/users
 * List all users with tenant info
 */
router.get("/users", requireUser, requirePlatformAdmin, async (req, res) => {
  try {
    const parseResult = userFilterSchema.safeParse(req.query);
    if (!parseResult.success) {
      return res.status(400).json({
        error: "Invalid query parameters",
        details: parseResult.error.issues,
      });
    }

    const { limit, offset, status, tenantId, search } = parseResult.data;

    // Build query with filters
    const conditions = [];
    const params = [];
    let paramIndex = 1;

    if (status) {
      conditions.push(`u.status = $${paramIndex}`);
      params.push(status);
      paramIndex++;
    }

    if (tenantId) {
      conditions.push(`u.tenant_id = $${paramIndex}`);
      params.push(tenantId);
      paramIndex++;
    }

    if (search) {
      conditions.push(`(u.name ILIKE $${paramIndex} OR u.email ILIKE $${paramIndex})`);
      params.push(`%${search}%`);
      paramIndex++;
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

    const usersResult = await query(
      `SELECT
         u.id,
         u.name,
         u.email,
         u.status,
         u.tenant_id,
         u.is_platform_admin,
         u.created_at,
         u.updated_at,
         t.name as tenant_name,
         t.slug as tenant_slug
       FROM users u
       LEFT JOIN tenants t ON u.tenant_id = t.id
       ${whereClause}
       ORDER BY u.created_at DESC
       LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`,
      [...params, limit, offset],
    );

    const countResult = await query(
      `SELECT COUNT(*)::int as total FROM users u ${whereClause}`,
      params,
    );

    await logAdminAction(
      req.user.id,
      "users.list",
      { limit, offset, status, tenantId, search },
      req.ip,
    );

    res.json({
      users: usersResult.rows,
      total: countResult.rows[0]?.total || 0,
      limit,
      offset,
    });
  } catch (err) {
    console.error("[platform-admin] List users error:", err);
    res.status(500).json({ error: "Failed to list users" });
  }
});

/**
 * GET /api/admin/users/:id
 * Get user details
 */
router.get("/users/:id", requireUser, requirePlatformAdmin, async (req, res) => {
  try {
    const parseResult = uuidSchema.safeParse(req.params.id);
    if (!parseResult.success) {
      return res.status(400).json({ error: "Invalid user ID" });
    }

    const userId = parseResult.data;

    const userResult = await query(
      `SELECT
         u.id,
         u.name,
         u.email,
         u.status,
         u.tenant_id,
         u.is_platform_admin,
         u.container_id,
         u.container_port,
         u.created_at,
         u.updated_at,
         t.name as tenant_name,
         t.slug as tenant_slug
       FROM users u
       LEFT JOIN tenants t ON u.tenant_id = t.id
       WHERE u.id = $1`,
      [userId],
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = userResult.rows[0];

    // Get additional info
    const [sessionsResult, usageResult, groupsResult] = await Promise.all([
      query(
        `SELECT COUNT(*)::int as active_sessions
         FROM sessions
         WHERE user_id = $1 AND expires_at > NOW()`,
        [userId],
      ),
      query(
        `SELECT
           SUM(api_calls)::int as total_api_calls,
           SUM(input_tokens)::bigint as total_input_tokens,
           SUM(output_tokens)::bigint as total_output_tokens
         FROM usage
         WHERE user_id = $1
           AND date > NOW() - INTERVAL '30 days'`,
        [userId],
      ),
      query(
        `SELECT gm.role, g.name, g.slug
         FROM group_memberships gm
         JOIN groups g ON gm.group_id = g.id
         WHERE gm.user_id = $1`,
        [userId],
      ),
    ]);

    await logAdminAction(req.user.id, "users.view", { userId }, req.ip);

    res.json({
      ...user,
      activeSessions: sessionsResult.rows[0]?.active_sessions || 0,
      usage30Days: usageResult.rows[0] || {
        total_api_calls: 0,
        total_input_tokens: 0,
        total_output_tokens: 0,
      },
      groups: groupsResult.rows,
    });
  } catch (err) {
    console.error("[platform-admin] Get user error:", err);
    res.status(500).json({ error: "Failed to get user details" });
  }
});

/**
 * POST /api/admin/users/:id/impersonate
 * Generate an impersonation session for a user
 * Returns a temporary session token that allows admin to act as the user
 */
router.post("/users/:id/impersonate", requireUser, requirePlatformAdmin, async (req, res) => {
  try {
    const parseResult = uuidSchema.safeParse(req.params.id);
    if (!parseResult.success) {
      return res.status(400).json({ error: "Invalid user ID" });
    }

    const userId = parseResult.data;
    const targetUser = await users.findById(userId);

    if (!targetUser) {
      return res.status(404).json({ error: "User not found" });
    }

    // Cannot impersonate other platform admins
    if (targetUser.is_platform_admin) {
      return res.status(403).json({
        error: "Cannot impersonate platform admins",
        code: "IMPERSONATE_ADMIN_DENIED",
      });
    }

    // Generate a short-lived impersonation session (1 hour)
    const sessionToken = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    await sessions.create(userId, sessionToken, expiresAt, {
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"],
      impersonatedBy: req.user.id,
      isImpersonation: true,
    });

    await logAdminAction(
      req.user.id,
      "users.impersonate",
      {
        targetUserId: userId,
        targetUserEmail: targetUser.email,
        expiresAt: expiresAt.toISOString(),
      },
      req.ip,
    );

    res.json({
      success: true,
      sessionToken,
      expiresAt: expiresAt.toISOString(),
      user: {
        id: targetUser.id,
        name: targetUser.name,
        email: targetUser.email,
      },
      warning: "This session will expire in 1 hour. All actions will be logged.",
    });
  } catch (err) {
    console.error("[platform-admin] Impersonate user error:", err);
    res.status(500).json({ error: "Failed to create impersonation session" });
  }
});

/**
 * POST /api/admin/users/:id/disable
 * Disable a user account
 */
router.post("/users/:id/disable", requireUser, requirePlatformAdmin, async (req, res) => {
  try {
    const parseResult = uuidSchema.safeParse(req.params.id);
    if (!parseResult.success) {
      return res.status(400).json({ error: "Invalid user ID" });
    }

    const userId = parseResult.data;
    const targetUser = await users.findById(userId);

    if (!targetUser) {
      return res.status(404).json({ error: "User not found" });
    }

    // Cannot disable platform admins
    if (targetUser.is_platform_admin) {
      return res.status(403).json({
        error: "Cannot disable platform admin accounts",
        code: "DISABLE_ADMIN_DENIED",
      });
    }

    if (targetUser.status === "suspended") {
      return res.status(400).json({ error: "User is already disabled" });
    }

    const { reason } = req.body || {};

    const updated = await users.updateStatus(userId, "suspended");

    // Revoke all active sessions
    await query("DELETE FROM sessions WHERE user_id = $1", [userId]);

    await logAdminAction(
      req.user.id,
      "users.disable",
      {
        userId,
        userEmail: targetUser.email,
        reason,
      },
      req.ip,
    );

    res.json({
      success: true,
      user: {
        id: updated.id,
        email: updated.email,
        status: updated.status,
      },
      message: `User "${targetUser.email}" has been disabled`,
    });
  } catch (err) {
    console.error("[platform-admin] Disable user error:", err);
    res.status(500).json({ error: "Failed to disable user" });
  }
});

/**
 * POST /api/admin/users/:id/enable
 * Enable a disabled user account
 */
router.post("/users/:id/enable", requireUser, requirePlatformAdmin, async (req, res) => {
  try {
    const parseResult = uuidSchema.safeParse(req.params.id);
    if (!parseResult.success) {
      return res.status(400).json({ error: "Invalid user ID" });
    }

    const userId = parseResult.data;
    const targetUser = await users.findById(userId);

    if (!targetUser) {
      return res.status(404).json({ error: "User not found" });
    }

    if (targetUser.status !== "suspended") {
      return res.status(400).json({ error: "User is not disabled" });
    }

    const updated = await users.updateStatus(userId, "active");

    await logAdminAction(
      req.user.id,
      "users.enable",
      {
        userId,
        userEmail: targetUser.email,
      },
      req.ip,
    );

    res.json({
      success: true,
      user: {
        id: updated.id,
        email: updated.email,
        status: updated.status,
      },
      message: `User "${targetUser.email}" has been enabled`,
    });
  } catch (err) {
    console.error("[platform-admin] Enable user error:", err);
    res.status(500).json({ error: "Failed to enable user" });
  }
});

// ============================================================
// PLATFORM STATS
// ============================================================

/**
 * GET /api/admin/stats
 * Get platform-wide statistics
 */
router.get("/stats", requireUser, requirePlatformAdmin, async (req, res) => {
  try {
    const [tenantStats, userStats, groupStats, usageStats] = await Promise.all([
      // Tenant counts by status
      query(`
        SELECT
          COUNT(*)::int as total,
          COUNT(*) FILTER (WHERE status = 'active')::int as active,
          COUNT(*) FILTER (WHERE status = 'suspended')::int as suspended,
          COUNT(*) FILTER (WHERE status = 'deleted')::int as deleted
        FROM tenants
      `),
      // User counts by status
      query(`
        SELECT
          COUNT(*)::int as total,
          COUNT(*) FILTER (WHERE status = 'active')::int as active,
          COUNT(*) FILTER (WHERE status = 'pending')::int as pending,
          COUNT(*) FILTER (WHERE status = 'suspended')::int as suspended,
          COUNT(*) FILTER (WHERE container_id IS NOT NULL)::int as with_container
        FROM users
      `),
      // Group count
      query(`SELECT COUNT(*)::int as total FROM groups`),
      // Usage in last 30 days
      query(`
        SELECT
          SUM(api_calls)::bigint as total_api_calls,
          SUM(input_tokens)::bigint as total_input_tokens,
          SUM(output_tokens)::bigint as total_output_tokens
        FROM usage
        WHERE date > NOW() - INTERVAL '30 days'
      `),
    ]);

    await logAdminAction(req.user.id, "stats.view", {}, req.ip);

    res.json({
      tenants: tenantStats.rows[0],
      users: userStats.rows[0],
      groups: { total: groupStats.rows[0]?.total || 0 },
      usage30Days: usageStats.rows[0] || {
        total_api_calls: 0,
        total_input_tokens: 0,
        total_output_tokens: 0,
      },
      generatedAt: new Date().toISOString(),
    });
  } catch (err) {
    console.error("[platform-admin] Get stats error:", err);
    res.status(500).json({ error: "Failed to get platform stats" });
  }
});

/**
 * GET /api/admin/stats/subscriptions
 * Subscription counts by plan
 */
router.get("/stats/subscriptions", requireUser, requirePlatformAdmin, async (req, res) => {
  try {
    const metrics = await subscriptions.getMetrics();

    await logAdminAction(req.user.id, "stats.subscriptions", {}, req.ip);

    res.json({
      ...metrics,
      generatedAt: new Date().toISOString(),
    });
  } catch (err) {
    console.error("[platform-admin] Get subscription stats error:", err);
    res.status(500).json({ error: "Failed to get subscription stats" });
  }
});

/**
 * GET /api/admin/stats/usage
 * Platform-wide usage metrics
 */
router.get("/stats/usage", requireUser, requirePlatformAdmin, async (req, res) => {
  try {
    const days = parseInt(req.query.days || "30", 10);

    // Daily usage breakdown
    const dailyResult = await query(
      `SELECT
         DATE(date) as date,
         COUNT(DISTINCT user_id)::int as active_users,
         SUM(api_calls)::bigint as api_calls,
         SUM(input_tokens)::bigint as input_tokens,
         SUM(output_tokens)::bigint as output_tokens
       FROM usage
       WHERE date > NOW() - ($1 * INTERVAL '1 day')
       GROUP BY DATE(date)
       ORDER BY date DESC`,
      [days],
    );

    // Top users by API calls
    const topUsersResult = await query(
      `SELECT
         u.id,
         u.name,
         u.email,
         t.name as tenant_name,
         SUM(us.api_calls)::int as total_api_calls
       FROM usage us
       JOIN users u ON us.user_id = u.id
       LEFT JOIN tenants t ON u.tenant_id = t.id
       WHERE us.date > NOW() - ($1 * INTERVAL '1 day')
       GROUP BY u.id, u.name, u.email, t.name
       ORDER BY total_api_calls DESC
       LIMIT 10`,
      [days],
    );

    // Top tenants by API calls
    const topTenantsResult = await query(
      `SELECT
         t.id,
         t.name,
         t.slug,
         SUM(us.api_calls)::int as total_api_calls,
         COUNT(DISTINCT u.id)::int as active_users
       FROM usage us
       JOIN users u ON us.user_id = u.id
       JOIN tenants t ON u.tenant_id = t.id
       WHERE us.date > NOW() - ($1 * INTERVAL '1 day')
       GROUP BY t.id, t.name, t.slug
       ORDER BY total_api_calls DESC
       LIMIT 10`,
      [days],
    );

    await logAdminAction(req.user.id, "stats.usage", { days }, req.ip);

    res.json({
      days,
      daily: dailyResult.rows,
      topUsers: topUsersResult.rows,
      topTenants: topTenantsResult.rows,
      generatedAt: new Date().toISOString(),
    });
  } catch (err) {
    console.error("[platform-admin] Get usage stats error:", err);
    res.status(500).json({ error: "Failed to get usage stats" });
  }
});

// ============================================================
// CONTAINER MANAGEMENT
// ============================================================

/**
 * GET /api/admin/containers
 * List all containers with status
 */
router.get("/containers", requireUser, requirePlatformAdmin, async (req, res) => {
  try {
    const parseResult = paginationSchema.safeParse(req.query);
    if (!parseResult.success) {
      return res.status(400).json({
        error: "Invalid query parameters",
        details: parseResult.error.issues,
      });
    }

    const { limit, offset } = parseResult.data;

    // Get users with containers
    const usersResult = await query(
      `SELECT
         u.id as user_id,
         u.name,
         u.email,
         u.container_id,
         u.container_port,
         u.status as user_status,
         t.name as tenant_name,
         t.slug as tenant_slug
       FROM users u
       LEFT JOIN tenants t ON u.tenant_id = t.id
       WHERE u.container_id IS NOT NULL
       ORDER BY u.created_at DESC
       LIMIT $1 OFFSET $2`,
      [limit, offset],
    );

    const countResult = await query(
      `SELECT COUNT(*)::int as total FROM users WHERE container_id IS NOT NULL`,
    );

    // Try to get container statuses from agent server
    const containers = [];
    for (const user of usersResult.rows) {
      let containerStatus = { status: "unknown" };

      try {
        const response = await axios.get(
          `${AGENT_SERVER_URL}/api/containers/${user.user_id}/status/quick`,
          {
            headers: { "x-auth-token": AGENT_SERVER_TOKEN },
            timeout: 2000,
          },
        );
        containerStatus = response.data;
      } catch (err) {
        // Container status unavailable, use unknown
        containerStatus = { status: "unreachable", error: err.message };
      }

      containers.push({
        ...user,
        containerStatus,
      });
    }

    await logAdminAction(req.user.id, "containers.list", { limit, offset }, req.ip);

    res.json({
      containers,
      total: countResult.rows[0]?.total || 0,
      limit,
      offset,
    });
  } catch (err) {
    console.error("[platform-admin] List containers error:", err);
    res.status(500).json({ error: "Failed to list containers" });
  }
});

/**
 * POST /api/admin/containers/:id/restart
 * Restart a container
 */
router.post("/containers/:id/restart", requireUser, requirePlatformAdmin, async (req, res) => {
  try {
    const parseResult = uuidSchema.safeParse(req.params.id);
    if (!parseResult.success) {
      return res.status(400).json({ error: "Invalid user/container ID" });
    }

    const userId = parseResult.data;
    const user = await users.findById(userId);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    if (!user.container_id) {
      return res.status(400).json({ error: "User does not have a container" });
    }

    // Send restart command to agent server
    const response = await axios.post(
      `${AGENT_SERVER_URL}/api/containers/${userId}/restart`,
      {},
      {
        headers: { "x-auth-token": AGENT_SERVER_TOKEN },
        timeout: 30000,
      },
    );

    await logAdminAction(
      req.user.id,
      "containers.restart",
      {
        userId,
        userEmail: user.email,
        containerId: user.container_id,
      },
      req.ip,
    );

    res.json({
      success: true,
      message: `Container for user "${user.email}" is restarting`,
      result: response.data,
    });
  } catch (err) {
    console.error("[platform-admin] Restart container error:", err);

    if (err.response?.status === 404) {
      return res.status(404).json({ error: "Container not found on agent server" });
    }

    res.status(503).json({
      error: "Failed to restart container",
      details: err.message,
    });
  }
});

/**
 * POST /api/admin/containers/:id/stop
 * Stop a container
 */
router.post("/containers/:id/stop", requireUser, requirePlatformAdmin, async (req, res) => {
  try {
    const parseResult = uuidSchema.safeParse(req.params.id);
    if (!parseResult.success) {
      return res.status(400).json({ error: "Invalid user/container ID" });
    }

    const userId = parseResult.data;
    const user = await users.findById(userId);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    if (!user.container_id) {
      return res.status(400).json({ error: "User does not have a container" });
    }

    // Send stop command to agent server
    const response = await axios.post(
      `${AGENT_SERVER_URL}/api/containers/${userId}/stop`,
      {},
      {
        headers: { "x-auth-token": AGENT_SERVER_TOKEN },
        timeout: 30000,
      },
    );

    await logAdminAction(
      req.user.id,
      "containers.stop",
      {
        userId,
        userEmail: user.email,
        containerId: user.container_id,
      },
      req.ip,
    );

    res.json({
      success: true,
      message: `Container for user "${user.email}" has been stopped`,
      result: response.data,
    });
  } catch (err) {
    console.error("[platform-admin] Stop container error:", err);

    if (err.response?.status === 404) {
      return res.status(404).json({ error: "Container not found on agent server" });
    }

    res.status(503).json({
      error: "Failed to stop container",
      details: err.message,
    });
  }
});

export default router;
