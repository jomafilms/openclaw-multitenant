import crypto from "crypto";
/**
 * Admin Security Routes
 *
 * API endpoints for managing admin security settings:
 * - IP allowlist management
 * - Security settings configuration
 * - Emergency access token management
 */
import { Router } from "express";
import { adminIpAllowlist, adminSecuritySettings, emergencyAccessTokens } from "../db/admin.js";
import { audit } from "../db/index.js";
import { validateCidr, getLocalIps, getClientIpSecure, KNOWN_VPN_RANGES } from "../lib/ip-utils.js";
import {
  requireAdminIpAllowlist,
  requireAdminSession,
  requireConfirmation,
} from "../middleware/admin-security.js";

const router = Router();

// ============================================================
// MIDDLEWARE
// ============================================================

// Apply IP allowlist check to all routes in this router
router.use(requireAdminIpAllowlist);

// Require admin session for all routes
router.use(requireAdminSession);

// ============================================================
// IP ALLOWLIST ROUTES
// ============================================================

/**
 * GET /api/admin/security/ip-allowlist
 *
 * Get current IP allowlist configuration
 */
router.get("/ip-allowlist", async (req, res) => {
  try {
    const [entries, enabled, settings] = await Promise.all([
      adminIpAllowlist.list(),
      adminIpAllowlist.isAllowlistEnabled(),
      adminSecuritySettings.getAll(),
    ]);

    const localIps = await getLocalIps();
    const clientIp = getClientIpSecure(req);

    res.json({
      enabled,
      entries: entries.map((e) => ({
        id: e.id,
        ipRange: e.ip_range,
        description: e.description,
        createdBy: e.created_by_email,
        createdAt: e.created_at,
        expiresAt: e.expires_at,
        lastUsedAt: e.last_used_at,
        hitCount: e.hit_count,
      })),
      settings: {
        sessionTimeoutMs: parseInt(process.env.ADMIN_SESSION_TIMEOUT_MS, 10) || 3600000,
        inactivityTimeoutMs: parseInt(process.env.ADMIN_INACTIVITY_TIMEOUT_MS, 10) || 900000,
        ...settings,
      },
      knownVpnRanges: KNOWN_VPN_RANGES,
      localIps,
      clientIp,
    });
  } catch (err) {
    console.error("Get IP allowlist error:", err);
    res.status(500).json({ error: "Failed to get IP allowlist" });
  }
});

/**
 * POST /api/admin/security/ip-allowlist
 *
 * Add a new IP range to the allowlist
 */
router.post("/ip-allowlist", async (req, res) => {
  try {
    const { ipRange, description, expiresInHours } = req.body;

    if (!ipRange) {
      return res.status(400).json({ error: "ipRange is required" });
    }

    // Validate CIDR notation
    const validation = validateCidr(ipRange);
    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }

    // Calculate expiration
    const expiresAt = expiresInHours
      ? new Date(Date.now() + expiresInHours * 60 * 60 * 1000)
      : null;

    const entry = await adminIpAllowlist.add({
      ipRange,
      description: description || null,
      createdBy: req.user.id,
      expiresAt,
    });

    const clientIp = getClientIpSecure(req);
    await audit.log(
      req.user.id,
      "admin.ip_added",
      { ipRange, description, expiresAt: expiresAt?.toISOString() },
      clientIp,
    );

    res.status(201).json({
      success: true,
      entry: {
        id: entry.id,
        ipRange: entry.ip_range,
        description: entry.description,
        createdAt: entry.created_at,
        expiresAt: entry.expires_at,
      },
    });
  } catch (err) {
    console.error("Add IP allowlist error:", err);
    // Handle duplicate CIDR
    if (err.code === "23505") {
      return res.status(409).json({ error: "IP range already in allowlist" });
    }
    res.status(500).json({ error: "Failed to add IP range" });
  }
});

/**
 * DELETE /api/admin/security/ip-allowlist/:id
 *
 * Remove an IP range from the allowlist
 */
router.delete("/ip-allowlist/:id", async (req, res) => {
  try {
    const { id } = req.params;

    // Validate UUID format
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
      return res.status(400).json({ error: "Invalid ID format" });
    }

    const removed = await adminIpAllowlist.remove(id);

    if (!removed) {
      return res.status(404).json({ error: "Entry not found" });
    }

    const clientIp = getClientIpSecure(req);
    await audit.log(
      req.user.id,
      "admin.ip_removed",
      { entryId: id, ipRange: removed.ip_range },
      clientIp,
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Remove IP allowlist error:", err);
    res.status(500).json({ error: "Failed to remove IP range" });
  }
});

/**
 * POST /api/admin/security/ip-allowlist/toggle
 *
 * Enable or disable the IP allowlist feature
 * Requires confirmation when disabling
 */
router.post(
  "/ip-allowlist/toggle",
  requireConfirmation("ip_allowlist.disable"),
  async (req, res) => {
    try {
      const { enabled } = req.body;

      if (typeof enabled !== "boolean") {
        return res.status(400).json({ error: "enabled must be a boolean" });
      }

      await adminIpAllowlist.setAllowlistEnabled(enabled, req.user.id);

      const clientIp = getClientIpSecure(req);
      await audit.log(req.user.id, "admin.allowlist_toggled", { enabled }, clientIp);

      res.json({ success: true, enabled });
    } catch (err) {
      console.error("Toggle IP allowlist error:", err);
      res.status(500).json({ error: "Failed to toggle IP allowlist" });
    }
  },
);

/**
 * POST /api/admin/security/ip-allowlist/add-current
 *
 * Convenience endpoint to add the current request IP to allowlist
 */
router.post("/ip-allowlist/add-current", async (req, res) => {
  try {
    const clientIp = getClientIpSecure(req);
    const { description, expiresInHours } = req.body;

    if (!clientIp || clientIp === "unknown") {
      return res.status(400).json({ error: "Could not determine client IP" });
    }

    // Add as single IP (/32 for IPv4, /128 for IPv6)
    const isV6 = clientIp.includes(":");
    const cidr = `${clientIp}/${isV6 ? 128 : 32}`;

    const expiresAt = expiresInHours
      ? new Date(Date.now() + expiresInHours * 60 * 60 * 1000)
      : null;

    const entry = await adminIpAllowlist.add({
      ipRange: cidr,
      description: description || `Added via add-current by ${req.user.email}`,
      createdBy: req.user.id,
      expiresAt,
    });

    await audit.log(
      req.user.id,
      "admin.ip_added",
      { ipRange: cidr, description: entry.description, method: "add-current" },
      clientIp,
    );

    res.status(201).json({
      success: true,
      entry: {
        id: entry.id,
        ipRange: entry.ip_range,
        description: entry.description,
        createdAt: entry.created_at,
        expiresAt: entry.expires_at,
      },
    });
  } catch (err) {
    console.error("Add current IP error:", err);
    if (err.code === "23505") {
      return res.status(409).json({ error: "IP already in allowlist" });
    }
    res.status(500).json({ error: "Failed to add current IP" });
  }
});

// ============================================================
// SECURITY SETTINGS ROUTES
// ============================================================

/**
 * GET /api/admin/security/settings
 *
 * Get all admin security settings
 */
router.get("/settings", async (req, res) => {
  try {
    const settings = await adminSecuritySettings.getAll();

    // Include environment-based settings (read-only)
    const envSettings = {
      sessionTimeoutMs: parseInt(process.env.ADMIN_SESSION_TIMEOUT_MS, 10) || 3600000,
      inactivityTimeoutMs: parseInt(process.env.ADMIN_INACTIVITY_TIMEOUT_MS, 10) || 900000,
      reauthIntervalMs: parseInt(process.env.ADMIN_REAUTH_INTERVAL_MS, 10) || 300000,
    };

    res.json({
      settings,
      envSettings,
    });
  } catch (err) {
    console.error("Get security settings error:", err);
    res.status(500).json({ error: "Failed to get settings" });
  }
});

/**
 * PUT /api/admin/security/settings/:key
 *
 * Update a single security setting
 * Requires confirmation for system config changes
 */
router.put("/settings/:key", requireConfirmation("system.config.change"), async (req, res) => {
  try {
    const { key } = req.params;
    const { value } = req.body;

    // Validate key format (alphanumeric + underscores only)
    if (!/^[a-z0-9_]+$/i.test(key)) {
      return res.status(400).json({ error: "Invalid setting key format" });
    }

    await adminSecuritySettings.set(key, value, req.user.id);

    const clientIp = getClientIpSecure(req);
    await audit.log(req.user.id, "admin.settings_changed", { key, value }, clientIp);

    res.json({ success: true, key, value });
  } catch (err) {
    console.error("Update security setting error:", err);
    res.status(500).json({ error: "Failed to update setting" });
  }
});

/**
 * DELETE /api/admin/security/settings/:key
 *
 * Delete a security setting
 */
router.delete("/settings/:key", async (req, res) => {
  try {
    const { key } = req.params;

    await adminSecuritySettings.delete(key);

    const clientIp = getClientIpSecure(req);
    await audit.log(req.user.id, "admin.settings_deleted", { key }, clientIp);

    res.json({ success: true });
  } catch (err) {
    console.error("Delete security setting error:", err);
    res.status(500).json({ error: "Failed to delete setting" });
  }
});

// ============================================================
// EMERGENCY ACCESS TOKEN ROUTES
// ============================================================

/**
 * GET /api/admin/security/emergency-tokens
 *
 * List emergency access tokens
 */
router.get("/emergency-tokens", async (req, res) => {
  try {
    const includeUsed = req.query.includeUsed === "true";
    const tokens = await emergencyAccessTokens.list(includeUsed);

    res.json({
      tokens: tokens.map((t) => ({
        id: t.id,
        reason: t.reason,
        createdAt: t.created_at,
        expiresAt: t.expires_at,
        usedAt: t.used_at,
        usedByIp: t.used_by_ip,
        singleUse: t.single_use,
      })),
    });
  } catch (err) {
    console.error("List emergency tokens error:", err);
    res.status(500).json({ error: "Failed to list emergency tokens" });
  }
});

/**
 * POST /api/admin/security/emergency-tokens
 *
 * Create a new emergency access token
 * Requires confirmation
 */
router.post(
  "/emergency-tokens",
  requireConfirmation("emergency_token.create"),
  async (req, res) => {
    try {
      const { reason, expiresInHours = 24, singleUse = true } = req.body;

      if (!reason || typeof reason !== "string") {
        return res.status(400).json({ error: "reason is required" });
      }

      // Generate a secure token
      const token = crypto.randomBytes(32).toString("base64url");
      const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
      const expiresAt = new Date(Date.now() + expiresInHours * 60 * 60 * 1000);

      const record = await emergencyAccessTokens.create({
        tokenHash,
        reason,
        expiresAt,
        singleUse,
      });

      const clientIp = getClientIpSecure(req);
      await audit.log(
        req.user.id,
        "admin.emergency_token_created",
        {
          tokenId: record.id,
          reason,
          expiresAt: expiresAt.toISOString(),
          singleUse,
        },
        clientIp,
      );

      // Return the token only once - it cannot be retrieved later
      res.status(201).json({
        success: true,
        token, // Only shown once!
        tokenId: record.id,
        expiresAt: record.expires_at,
        singleUse,
        warning: "Save this token securely. It will only be shown once.",
      });
    } catch (err) {
      console.error("Create emergency token error:", err);
      res.status(500).json({ error: "Failed to create emergency token" });
    }
  },
);

/**
 * DELETE /api/admin/security/emergency-tokens/:id
 *
 * Revoke an emergency access token
 */
router.delete("/emergency-tokens/:id", async (req, res) => {
  try {
    const { id } = req.params;

    // Validate UUID format
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
      return res.status(400).json({ error: "Invalid ID format" });
    }

    const revoked = await emergencyAccessTokens.revoke(id);

    if (!revoked) {
      return res.status(404).json({ error: "Token not found" });
    }

    const clientIp = getClientIpSecure(req);
    await audit.log(req.user.id, "admin.emergency_token_revoked", { tokenId: id }, clientIp);

    res.json({ success: true });
  } catch (err) {
    console.error("Revoke emergency token error:", err);
    res.status(500).json({ error: "Failed to revoke token" });
  }
});

// ============================================================
// ADMIN SESSION INFO
// ============================================================

/**
 * GET /api/admin/security/session
 *
 * Get current admin session information
 */
router.get("/session", async (req, res) => {
  try {
    const clientIp = getClientIpSecure(req);

    res.json({
      user: {
        id: req.user.id,
        email: req.user.email,
        name: req.user.name,
      },
      session: {
        id: req.sessionId,
        isAdmin: req.isAdmin,
        emergencyAccess: req.emergencyAccess || false,
      },
      security: {
        clientIp,
        sessionTimeoutMs: parseInt(process.env.ADMIN_SESSION_TIMEOUT_MS, 10) || 3600000,
        inactivityTimeoutMs: parseInt(process.env.ADMIN_INACTIVITY_TIMEOUT_MS, 10) || 900000,
      },
    });
  } catch (err) {
    console.error("Get session info error:", err);
    res.status(500).json({ error: "Failed to get session info" });
  }
});

// ============================================================
// KNOWN VPN RANGES
// ============================================================

/**
 * GET /api/admin/security/vpn-ranges
 *
 * Get list of known VPN/corporate network ranges for quick selection
 */
router.get("/vpn-ranges", async (req, res) => {
  res.json({
    ranges: Object.entries(KNOWN_VPN_RANGES).map(([name, cidr]) => ({
      name,
      cidr,
      description: getVpnRangeDescription(name),
    })),
  });
});

function getVpnRangeDescription(name) {
  const descriptions = {
    tailscale: "Tailscale VPN",
    cloudflareWarp: "Cloudflare WARP",
    privateNetworkA: "Private Network Class A (10.x.x.x)",
    privateNetworkB: "Private Network Class B (172.16-31.x.x)",
    privateNetworkC: "Private Network Class C (192.168.x.x)",
    localhost4: "IPv4 Localhost",
    localhost6: "IPv6 Localhost",
  };
  return descriptions[name] || name;
}

export default router;
