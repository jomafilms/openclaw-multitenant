# Security Plan 07: Admin Security Hardening

## Overview

This plan addresses comprehensive admin security improvements for OCMT:

1. IP allowlisting for admin routes (CIDR notation)
2. Admin session timeout (shorter than regular users)
3. Enhanced audit logging for admin actions
4. Dangerous operation confirmation flow
5. Emergency access procedures
6. Admin security management UI
7. VPN/Zero-trust integration

---

## 1. Database Schema

### Migration

Add to `management-server/db/migrate.js`:

```javascript
// Admin IP Allowlist
`CREATE TABLE IF NOT EXISTS admin_ip_allowlist (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ip_range CIDR NOT NULL,
  description TEXT,
  created_by UUID REFERENCES users(id),
  created_at TIMESTAMP DEFAULT NOW(),
  expires_at TIMESTAMP,
  last_used_at TIMESTAMP,
  hit_count INTEGER DEFAULT 0,
  enabled BOOLEAN DEFAULT true
)`,

`CREATE INDEX IF NOT EXISTS idx_admin_ip_allowlist_enabled ON admin_ip_allowlist(enabled) WHERE enabled = true`,

// Admin Security Settings
`CREATE TABLE IF NOT EXISTS admin_security_settings (
  key VARCHAR(100) PRIMARY KEY,
  value JSONB NOT NULL,
  updated_by UUID REFERENCES users(id),
  updated_at TIMESTAMP DEFAULT NOW()
)`,

// Action Confirmations
`CREATE TABLE IF NOT EXISTS admin_action_confirmations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  admin_id UUID NOT NULL REFERENCES users(id),
  action_type VARCHAR(100) NOT NULL,
  action_details JSONB NOT NULL,
  token VARCHAR(64) NOT NULL UNIQUE,
  created_at TIMESTAMP DEFAULT NOW(),
  expires_at TIMESTAMP NOT NULL,
  confirmed_at TIMESTAMP,
  ip_address INET
)`,

`CREATE INDEX IF NOT EXISTS idx_admin_confirmations_token ON admin_action_confirmations(token) WHERE confirmed_at IS NULL`,

// Emergency Access Tokens
`CREATE TABLE IF NOT EXISTS emergency_access_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash VARCHAR(64) NOT NULL UNIQUE,
  reason TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  expires_at TIMESTAMP NOT NULL,
  used_at TIMESTAMP,
  used_by_ip INET,
  single_use BOOLEAN DEFAULT true
)`,
```

---

## 2. IP Utilities Library

### Create `management-server/lib/ip-utils.js`

```javascript
import { isIP } from "net";

/**
 * Known VPN/Corporate ranges for quick presets
 */
export const KNOWN_VPN_RANGES = {
  tailscale: "100.64.0.0/10",
  cloudflareWarp: "172.16.0.0/12",
  privateNetworkA: "10.0.0.0/8",
  privateNetworkB: "172.16.0.0/12",
  privateNetworkC: "192.168.0.0/16",
};

/**
 * Parse CIDR notation into base IP and prefix length
 */
export function parseCidr(cidr) {
  const [ip, prefix] = cidr.split("/");
  if (!isIP(ip)) {
    return null;
  }

  const prefixLength = prefix ? parseInt(prefix, 10) : ip.includes(":") ? 128 : 32;

  if (isNaN(prefixLength) || prefixLength < 0) {
    return null;
  }

  const isV6 = ip.includes(":");
  if ((isV6 && prefixLength > 128) || (!isV6 && prefixLength > 32)) {
    return null;
  }

  return { ip, prefixLength, isV6 };
}

/**
 * Convert IPv4 to 32-bit integer
 */
function ipv4ToInt(ip) {
  return ip.split(".").reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

/**
 * Check if an IP is within a CIDR range
 */
export function ipInCidr(ip, cidr) {
  const parsed = parseCidr(cidr);
  if (!parsed) return false;

  const testIpVersion = ip.includes(":") ? 6 : 4;
  const cidrVersion = parsed.isV6 ? 6 : 4;

  if (testIpVersion !== cidrVersion) return false;

  if (testIpVersion === 4) {
    const ipInt = ipv4ToInt(ip);
    const baseInt = ipv4ToInt(parsed.ip);
    const mask = parsed.prefixLength === 0 ? 0 : (~0 << (32 - parsed.prefixLength)) >>> 0;
    return (ipInt & mask) === (baseInt & mask);
  }

  // IPv6 comparison (simplified - use a library for production)
  return ip === parsed.ip;
}

/**
 * Validate CIDR notation
 */
export function validateCidr(cidr) {
  const parsed = parseCidr(cidr);
  if (!parsed) {
    return { valid: false, error: "Invalid CIDR notation" };
  }
  return { valid: true, parsed };
}

/**
 * Get client IP with trust proxy awareness
 */
export function getClientIpSecure(req) {
  // If Express trust proxy is configured, use req.ip
  if (req.app.get("trust proxy")) {
    return req.ip || req.socket?.remoteAddress || "unknown";
  }

  // Fallback to socket address
  return req.socket?.remoteAddress || "unknown";
}

/**
 * Get local network IPs for self-add convenience
 */
export function getLocalIps() {
  const { networkInterfaces } = require("os");
  const interfaces = networkInterfaces();
  const ips = [];

  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === "IPv4" && !iface.internal) {
        ips.push(iface.address);
      }
    }
  }

  return ips;
}
```

---

## 3. IP Allowlist Database Operations

### Add to `management-server/db/index.js`

```javascript
export const adminIpAllowlist = {
  async list() {
    const res = await query(
      `SELECT a.*, u.email as created_by_email
       FROM admin_ip_allowlist a
       LEFT JOIN users u ON a.created_by = u.id
       WHERE a.enabled = true
         AND (a.expires_at IS NULL OR a.expires_at > NOW())
       ORDER BY a.created_at DESC`,
    );
    return res.rows;
  },

  async add({ ipRange, description, createdBy, expiresAt }) {
    const res = await query(
      `INSERT INTO admin_ip_allowlist (ip_range, description, created_by, expires_at)
       VALUES ($1::cidr, $2, $3, $4)
       RETURNING *`,
      [ipRange, description, createdBy, expiresAt],
    );
    return res.rows[0];
  },

  async remove(id) {
    const res = await query(`DELETE FROM admin_ip_allowlist WHERE id = $1 RETURNING *`, [id]);
    return res.rows[0];
  },

  async checkIp(ip) {
    const res = await query(
      `UPDATE admin_ip_allowlist
       SET hit_count = hit_count + 1, last_used_at = NOW()
       WHERE enabled = true
         AND (expires_at IS NULL OR expires_at > NOW())
         AND $1::inet <<= ip_range
       RETURNING id`,
      [ip],
    );
    return res.rows.length > 0;
  },

  async isAllowlistEnabled() {
    const res = await query(
      `SELECT value FROM admin_security_settings WHERE key = 'ip_allowlist_enabled'`,
    );
    return res.rows[0]?.value === true;
  },

  async setAllowlistEnabled(enabled, updatedBy) {
    await query(
      `INSERT INTO admin_security_settings (key, value, updated_by, updated_at)
       VALUES ('ip_allowlist_enabled', $1, $2, NOW())
       ON CONFLICT (key) DO UPDATE SET value = $1, updated_by = $2, updated_at = NOW()`,
      [enabled, updatedBy],
    );
  },
};

export const adminSecuritySettings = {
  async get(key) {
    const res = await query(`SELECT value FROM admin_security_settings WHERE key = $1`, [key]);
    return res.rows[0]?.value;
  },

  async set(key, value, updatedBy) {
    await query(
      `INSERT INTO admin_security_settings (key, value, updated_by, updated_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (key) DO UPDATE SET value = $2, updated_by = $3, updated_at = NOW()`,
      [key, JSON.stringify(value), updatedBy],
    );
  },

  async getAll() {
    const res = await query(`SELECT key, value FROM admin_security_settings`);
    return Object.fromEntries(res.rows.map((r) => [r.key, r.value]));
  },
};

export const adminActionConfirmations = {
  async create({ adminId, actionType, actionDetails, token, expiresAt, ipAddress }) {
    const res = await query(
      `INSERT INTO admin_action_confirmations
       (admin_id, action_type, action_details, token, expires_at, ip_address)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [adminId, actionType, JSON.stringify(actionDetails), token, expiresAt, ipAddress],
    );
    return res.rows[0];
  },

  async findByToken(token) {
    const res = await query(
      `SELECT * FROM admin_action_confirmations
       WHERE token = $1
         AND expires_at > NOW()
         AND confirmed_at IS NULL`,
      [token],
    );
    return res.rows[0];
  },

  async confirm(id) {
    await query(`UPDATE admin_action_confirmations SET confirmed_at = NOW() WHERE id = $1`, [id]);
  },
};

export const emergencyAccessTokens = {
  async create({ tokenHash, reason, expiresAt, singleUse }) {
    const res = await query(
      `INSERT INTO emergency_access_tokens (token_hash, reason, expires_at, single_use)
       VALUES ($1, $2, $3, $4)
       RETURNING id, created_at, expires_at`,
      [tokenHash, reason, expiresAt, singleUse],
    );
    return res.rows[0];
  },

  async validate(tokenHash) {
    const res = await query(
      `SELECT * FROM emergency_access_tokens
       WHERE token_hash = $1
         AND expires_at > NOW()
         AND (single_use = false OR used_at IS NULL)`,
      [tokenHash],
    );
    return res.rows[0];
  },

  async markUsed(id, ip) {
    await query(
      `UPDATE emergency_access_tokens
       SET used_at = NOW(), used_by_ip = $2
       WHERE id = $1`,
      [id, ip],
    );
  },
};
```

---

## 4. IP Allowlist Middleware

### Create `management-server/middleware/admin-ip.js`

```javascript
import crypto from "crypto";
import { adminIpAllowlist, emergencyAccessTokens, audit } from "../db/index.js";
import { getClientIpSecure } from "../lib/ip-utils.js";

/**
 * Middleware to enforce IP allowlist for admin routes
 */
export async function requireAdminIpAllowlist(req, res, next) {
  try {
    // Check if allowlist is enabled
    const enabled = await adminIpAllowlist.isAllowlistEnabled();
    if (!enabled) {
      return next();
    }

    const clientIp = getClientIpSecure(req);

    // Check for emergency access token
    const emergencyToken = req.headers["x-emergency-access-token"];
    if (emergencyToken) {
      const tokenHash = crypto.createHash("sha256").update(emergencyToken).digest("hex");
      const validToken = await emergencyAccessTokens.validate(tokenHash);

      if (validToken) {
        await emergencyAccessTokens.markUsed(validToken.id, clientIp);
        await audit.log(
          null,
          "admin.emergency_access",
          {
            ip: clientIp,
            tokenId: validToken.id,
            reason: validToken.reason,
          },
          clientIp,
        );

        req.emergencyAccess = true;
        return next();
      }
    }

    // Check IP against allowlist
    const allowed = await adminIpAllowlist.checkIp(clientIp);

    if (!allowed) {
      await audit.log(
        req.user?.id || null,
        "admin.ip_blocked",
        { ip: clientIp, path: req.path },
        clientIp,
      );

      return res.status(403).json({
        error: "Access denied: IP not in admin allowlist",
        code: "ADMIN_IP_NOT_ALLOWED",
      });
    }

    next();
  } catch (err) {
    console.error("Admin IP allowlist check error:", err);
    // Fail closed - deny access on error
    res.status(500).json({ error: "Access verification failed" });
  }
}
```

---

## 5. Admin Session Hardening

### Update `management-server/middleware/auth.js`

```javascript
// Configurable admin session timeout (default: 1 hour)
const ADMIN_SESSION_TIMEOUT_MS = parseInt(process.env.ADMIN_SESSION_TIMEOUT_MS) || 60 * 60 * 1000;

// Inactivity timeout (default: 15 minutes)
const ADMIN_INACTIVITY_TIMEOUT_MS =
  parseInt(process.env.ADMIN_INACTIVITY_TIMEOUT_MS) || 15 * 60 * 1000;

export function requireAdmin(req, res, next) {
  const token = req.cookies?.[SESSION_COOKIE] || req.headers["x-session-token"];

  if (!token) {
    return res.status(401).json({ error: "Authentication required" });
  }

  sessions
    .findByToken(token)
    .then((session) => {
      if (!session) {
        return res.status(401).json({ error: "Invalid or expired session" });
      }

      // Check admin status
      const adminEmails =
        process.env.ADMIN_EMAILS?.split(",").map((e) => e.trim().toLowerCase()) || [];
      if (!adminEmails.includes(session.email.toLowerCase())) {
        return res.status(403).json({ error: "Admin access required" });
      }

      // Check admin session age
      const sessionAge = Date.now() - new Date(session.created_at).getTime();
      if (sessionAge > ADMIN_SESSION_TIMEOUT_MS) {
        return res.status(401).json({
          error: "Admin session expired",
          code: "ADMIN_SESSION_EXPIRED",
        });
      }

      // Check inactivity timeout
      if (session.last_activity_at) {
        const inactiveTime = Date.now() - new Date(session.last_activity_at).getTime();
        if (inactiveTime > ADMIN_INACTIVITY_TIMEOUT_MS) {
          return res.status(401).json({
            error: "Session inactive",
            code: "ADMIN_SESSION_INACTIVE",
          });
        }
      }

      // Update last activity
      sessions.updateLastActivity(session.id, getClientIpSecure(req)).catch(console.error);

      req.user = {
        id: session.user_id,
        email: session.email,
        name: session.name,
        status: session.status,
        containerId: session.container_id,
        containerPort: session.container_port,
        gatewayToken: session.gateway_token,
      };
      req.sessionId = session.id;
      req.isAdmin = true;

      next();
    })
    .catch((err) => {
      console.error("Admin auth error:", err);
      res.status(500).json({ error: "Authentication failed" });
    });
}
```

---

## 6. Admin Audit Logging

### Create `management-server/lib/admin-audit.js`

```javascript
import { meshAuditLogs, audit } from "../db/index.js";
import { getClientIpSecure } from "./ip-utils.js";

export const ADMIN_AUDIT_EVENTS = {
  ADMIN_ACCESS: "admin.access",
  ADMIN_LOGIN: "admin.login",
  ADMIN_LOGOUT: "admin.logout",
  ADMIN_LOGIN_FAILED: "admin.login_failed",
  ADMIN_IP_BLOCKED: "admin.ip_blocked",
  ADMIN_IP_ADDED: "admin.ip_added",
  ADMIN_IP_REMOVED: "admin.ip_removed",
  ADMIN_EMERGENCY_ACCESS: "admin.emergency_access",
  ADMIN_SETTINGS_CHANGED: "admin.settings_changed",
  ADMIN_ALLOWLIST_TOGGLED: "admin.allowlist_toggled",
  ADMIN_USER_DELETED: "admin.user_deleted",
  ADMIN_ORG_DELETED: "admin.org_deleted",
  ADMIN_SYSTEM_CONFIG: "admin.system_config",
  ADMIN_CONFIRMATION_REQUESTED: "admin.confirmation_requested",
  ADMIN_CONFIRMATION_APPROVED: "admin.confirmation_approved",
  ADMIN_CONFIRMATION_EXPIRED: "admin.confirmation_expired",
};

/**
 * Log an admin action with full context
 */
export async function logAdminAction(req, eventType, details = {}) {
  const ip = getClientIpSecure(req);
  const adminId = req.user?.id || "unknown";

  await meshAuditLogs.log({
    eventType,
    actorId: adminId,
    ipAddress: ip,
    success: details.success !== false,
    details: {
      ...details,
      userAgent: req.headers["user-agent"],
      path: req.path,
      method: req.method,
    },
  });

  await audit.log(adminId === "unknown" ? null : adminId, eventType, details, ip);
}

/**
 * Audit trail decorator for admin routes
 */
export function auditAdminRoute(eventType) {
  return (req, res, next) => {
    const originalEnd = res.end;
    const startTime = Date.now();

    res.end = function (...args) {
      const duration = Date.now() - startTime;
      const success = res.statusCode < 400;

      logAdminAction(req, eventType, {
        success,
        statusCode: res.statusCode,
        duration,
        requestBody: req.body ? Object.keys(req.body) : [],
      }).catch((err) => {
        console.error("Failed to log admin action:", err);
      });

      return originalEnd.apply(this, args);
    };

    next();
  };
}
```

---

## 7. Dangerous Operation Confirmation

### Create `management-server/lib/admin-confirmation.js`

```javascript
import crypto from "crypto";
import { adminActionConfirmations, adminSecuritySettings } from "../db/index.js";
import { getClientIpSecure } from "./ip-utils.js";

const CONFIRMATION_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes

const DANGEROUS_ACTIONS = [
  "user.delete",
  "group.delete",
  "admin.revoke",
  "system.config.change",
  "ip_allowlist.disable",
  "emergency_token.create",
];

export async function requiresConfirmation(actionType) {
  const configuredActions = await adminSecuritySettings.get("require_confirmation_for");
  const actions = configuredActions || DANGEROUS_ACTIONS;
  return actions.includes(actionType);
}

export async function createConfirmation(req, actionType, actionDetails) {
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + CONFIRMATION_EXPIRY_MS);

  const confirmation = await adminActionConfirmations.create({
    adminId: req.user.id,
    actionType,
    actionDetails,
    token,
    expiresAt,
    ipAddress: getClientIpSecure(req),
  });

  return {
    confirmationRequired: true,
    confirmationId: confirmation.id,
    token,
    expiresAt: expiresAt.toISOString(),
    action: actionType,
    details: actionDetails,
  };
}

export async function verifyConfirmation(token, expectedAction) {
  const confirmation = await adminActionConfirmations.findByToken(token);

  if (!confirmation) {
    return { valid: false, error: "Invalid or expired confirmation token" };
  }

  if (confirmation.action_type !== expectedAction) {
    return { valid: false, error: "Confirmation action mismatch" };
  }

  await adminActionConfirmations.confirm(confirmation.id);

  return {
    valid: true,
    adminId: confirmation.admin_id,
    actionType: confirmation.action_type,
    actionDetails: confirmation.action_details,
  };
}

/**
 * Middleware to require confirmation for dangerous actions
 */
export function requireConfirmation(actionType) {
  return async (req, res, next) => {
    const confirmationToken = req.headers["x-confirmation-token"];

    const needsConfirmation = await requiresConfirmation(actionType);
    if (!needsConfirmation) {
      return next();
    }

    if (confirmationToken) {
      const result = await verifyConfirmation(confirmationToken, actionType);

      if (!result.valid) {
        return res.status(400).json({
          error: result.error,
          code: "CONFIRMATION_INVALID",
        });
      }

      req.confirmedAction = result;
      return next();
    }

    // No token - create confirmation request
    const confirmation = await createConfirmation(req, actionType, {
      path: req.path,
      method: req.method,
      params: req.params,
      body: sanitizeBody(req.body),
    });

    return res.status(202).json(confirmation);
  };
}

function sanitizeBody(body) {
  if (!body) return {};

  const sanitized = { ...body };
  const sensitiveFields = ["password", "token", "secret", "key", "apiKey"];

  for (const field of sensitiveFields) {
    if (field in sanitized) {
      sanitized[field] = "[REDACTED]";
    }
  }

  return sanitized;
}
```

---

## 8. Emergency Access CLI Tool

### Create `management-server/scripts/generate-emergency-token.js`

```javascript
#!/usr/bin/env node
/**
 * Generate an emergency access token for admin lockout recovery
 *
 * Usage: node generate-emergency-token.js --reason "Locked out during IP migration" --hours 24
 */

import crypto from "crypto";
import { emergencyAccessTokens } from "../db/index.js";
import dotenv from "dotenv";

dotenv.config();

async function main() {
  const args = process.argv.slice(2);
  const reasonIdx = args.indexOf("--reason");
  const hoursIdx = args.indexOf("--hours");

  const reason = reasonIdx >= 0 ? args[reasonIdx + 1] : "Emergency access recovery";
  const hours = hoursIdx >= 0 ? parseInt(args[hoursIdx + 1], 10) : 24;

  if (!reason) {
    console.error('Usage: node generate-emergency-token.js --reason "Reason" [--hours N]');
    process.exit(1);
  }

  const token = crypto.randomBytes(32).toString("base64url");
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  const expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000);

  try {
    await emergencyAccessTokens.create({
      tokenHash,
      reason,
      expiresAt,
      singleUse: true,
    });

    console.log("\n========================================");
    console.log("EMERGENCY ACCESS TOKEN GENERATED");
    console.log("========================================\n");
    console.log("Token (save this - shown only once):");
    console.log(`  ${token}\n`);
    console.log("Details:");
    console.log(`  Reason: ${reason}`);
    console.log(`  Expires: ${expiresAt.toISOString()}`);
    console.log(`  Single use: Yes\n`);
    console.log("Usage:");
    console.log("  Add header: X-Emergency-Access-Token: <token>\n");
    console.log("========================================\n");

    process.exit(0);
  } catch (err) {
    console.error("Failed to generate token:", err);
    process.exit(1);
  }
}

main();
```

---

## 9. Admin Security Routes

### Add to `management-server/routes/admin.js`

```javascript
import { adminIpAllowlist, adminSecuritySettings } from "../db/index.js";
import { validateCidr, getLocalIps, KNOWN_VPN_RANGES } from "../lib/ip-utils.js";
import { requireConfirmation } from "../lib/admin-confirmation.js";
import { logAdminAction } from "../lib/admin-audit.js";
import { requireAdminIpAllowlist } from "../middleware/admin-ip.js";

// Apply IP allowlist to all admin routes
router.use(requireAdminIpAllowlist);

// GET /admin/security/ip-allowlist
router.get("/security/ip-allowlist", requireAdmin, async (req, res) => {
  try {
    const [entries, enabled, settings] = await Promise.all([
      adminIpAllowlist.list(),
      adminIpAllowlist.isAllowlistEnabled(),
      adminSecuritySettings.getAll(),
    ]);

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
      settings,
      knownVpnRanges: KNOWN_VPN_RANGES,
      localIps: getLocalIps(),
    });
  } catch (err) {
    console.error("Get IP allowlist error:", err);
    res.status(500).json({ error: "Failed to get IP allowlist" });
  }
});

// POST /admin/security/ip-allowlist
router.post("/security/ip-allowlist", requireAdmin, async (req, res) => {
  try {
    const { ipRange, description, expiresInHours } = req.body;

    const validation = validateCidr(ipRange);
    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }

    const expiresAt = expiresInHours
      ? new Date(Date.now() + expiresInHours * 60 * 60 * 1000)
      : null;

    const entry = await adminIpAllowlist.add({
      ipRange,
      description,
      createdBy: req.user.id,
      expiresAt,
    });

    await logAdminAction(req, "admin.ip_added", { ipRange, description, expiresAt });

    res.json({
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
    res.status(500).json({ error: "Failed to add IP range" });
  }
});

// DELETE /admin/security/ip-allowlist/:id
router.delete("/security/ip-allowlist/:id", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const removed = await adminIpAllowlist.remove(id);
    if (!removed) {
      return res.status(404).json({ error: "Entry not found" });
    }

    await logAdminAction(req, "admin.ip_removed", { entryId: id, ipRange: removed.ip_range });

    res.json({ success: true });
  } catch (err) {
    console.error("Remove IP allowlist error:", err);
    res.status(500).json({ error: "Failed to remove IP range" });
  }
});

// POST /admin/security/ip-allowlist/toggle
router.post(
  "/security/ip-allowlist/toggle",
  requireAdmin,
  requireConfirmation("ip_allowlist.disable"),
  async (req, res) => {
    try {
      const { enabled } = req.body;

      await adminIpAllowlist.setAllowlistEnabled(enabled, req.user.id);
      await logAdminAction(req, "admin.allowlist_toggled", { enabled });

      res.json({ success: true, enabled });
    } catch (err) {
      console.error("Toggle IP allowlist error:", err);
      res.status(500).json({ error: "Failed to toggle IP allowlist" });
    }
  },
);

// GET /admin/security/settings
router.get("/security/settings", requireAdmin, async (req, res) => {
  try {
    const settings = await adminSecuritySettings.getAll();
    res.json({ settings });
  } catch (err) {
    console.error("Get security settings error:", err);
    res.status(500).json({ error: "Failed to get settings" });
  }
});

// PUT /admin/security/settings/:key
router.put(
  "/security/settings/:key",
  requireAdmin,
  requireConfirmation("system.config.change"),
  async (req, res) => {
    try {
      const { key } = req.params;
      const { value } = req.body;

      await adminSecuritySettings.set(key, value, req.user.id);
      await logAdminAction(req, "admin.settings_changed", { key, value });

      res.json({ success: true, key, value });
    } catch (err) {
      console.error("Update security setting error:", err);
      res.status(500).json({ error: "Failed to update setting" });
    }
  },
);
```

---

## 10. VPN/Zero-Trust Integration

### Environment Variables

```bash
# Trust proxy headers (required behind reverse proxy/VPN)
TRUST_PROXY=true

# Pre-configured VPN CIDR ranges (comma-separated)
VPN_CIDR_RANGES=100.64.0.0/10,10.0.0.0/8

# Cloudflare Access integration
CLOUDFLARE_ACCESS_AUD=<your-access-audience-tag>
CLOUDFLARE_ACCESS_TEAM=<your-team-name>
```

### Cloudflare Access Verification

Create `management-server/lib/cloudflare-access.js`:

```javascript
import jwt from "jsonwebtoken";

let cfPublicKeys = null;
let cfKeysExpiry = 0;

async function getCfPublicKeys(teamName) {
  if (cfPublicKeys && Date.now() < cfKeysExpiry) {
    return cfPublicKeys;
  }

  const res = await fetch(`https://${teamName}.cloudflareaccess.com/cdn-cgi/access/certs`);
  const data = await res.json();

  cfPublicKeys = data.keys;
  cfKeysExpiry = Date.now() + 60 * 60 * 1000; // Cache 1 hour

  return cfPublicKeys;
}

export async function verifyCfAccessToken(token, audience, teamName) {
  try {
    const keys = await getCfPublicKeys(teamName);
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded) return null;

    const key = keys.find((k) => k.kid === decoded.header.kid);
    if (!key) return null;

    const payload = jwt.verify(token, key, {
      algorithms: ["RS256"],
      audience,
    });

    return {
      email: payload.email,
      identity_nonce: payload.identity_nonce,
      exp: payload.exp,
    };
  } catch (err) {
    console.error("CF Access verification failed:", err);
    return null;
  }
}

export function requireCfAccess(req, res, next) {
  const cfToken = req.headers["cf-access-jwt-assertion"];
  const audience = process.env.CLOUDFLARE_ACCESS_AUD;
  const team = process.env.CLOUDFLARE_ACCESS_TEAM;

  if (!audience || !team) {
    return next(); // CF Access not configured
  }

  if (!cfToken) {
    return res.status(401).json({ error: "Cloudflare Access required" });
  }

  verifyCfAccessToken(cfToken, audience, team)
    .then((identity) => {
      if (!identity) {
        return res.status(401).json({ error: "Invalid Cloudflare Access token" });
      }
      req.cfAccessIdentity = identity;
      next();
    })
    .catch(() => {
      res.status(500).json({ error: "Access verification failed" });
    });
}
```

---

## Files to Modify

| File                 | Changes                                |
| -------------------- | -------------------------------------- |
| `db/migrate.js`      | Add admin security tables              |
| `db/index.js`        | Add admin security CRUD operations     |
| `middleware/auth.js` | Add session timeout, inactivity checks |
| `routes/admin.js`    | Add security settings routes           |
| `server.js`          | Register new middleware and routes     |

## Files to Create

| File                                  | Purpose                          |
| ------------------------------------- | -------------------------------- |
| `lib/ip-utils.js`                     | CIDR validation, IP utilities    |
| `lib/admin-audit.js`                  | Admin action audit logging       |
| `lib/admin-confirmation.js`           | Dangerous operation confirmation |
| `lib/cloudflare-access.js`            | CF Access integration            |
| `middleware/admin-ip.js`              | IP allowlist enforcement         |
| `scripts/generate-emergency-token.js` | Emergency access CLI             |

---

## Implementation Sequence

### Week 1: Foundation

1. Database migrations for new tables
2. IP utilities library with CIDR validation
3. Database operations for IP allowlist
4. IP allowlist middleware

### Week 2: Session Hardening

5. Configurable admin session timeout
6. Session activity tracking
7. Inactivity timeout

### Week 3: Audit & Confirmation

8. Enhanced audit logging for admin actions
9. Confirmation flow for dangerous operations
10. Confirmation middleware

### Week 4: Recovery & UI

11. Emergency token generation script
12. Admin security settings UI
13. IP management API routes

### Week 5: VPN Integration & Testing

14. Cloudflare Access verification
15. VPN CIDR range presets
16. Comprehensive testing

---

## Security Considerations

1. **Fail Closed**: IP allowlist middleware denies access on any error
2. **Rate Limiting**: Apply strict rate limiting to admin login attempts
3. **Token Hashing**: Emergency tokens stored as SHA-256 hashes
4. **Timing-Safe**: Use constant-time comparison for tokens
5. **Audit Trail**: All admin actions logged with IP, timestamp, context
6. **Session Binding**: Consider binding admin sessions to IP address
7. **HTTPS Required**: Admin routes should only be accessible over HTTPS

---

## Lockout Recovery Procedure

1. **SSH Access Required**: Emergency tokens must be generated from server console
2. **Generate Token**: `node scripts/generate-emergency-token.js --reason "Description" --hours 4`
3. **Use Token**: Add `X-Emergency-Access-Token: <token>` header to admin requests
4. **Add Your IP**: Use emergency access to add your IP to the allowlist
5. **Token Auto-Expires**: Single-use token invalidated after first use

---

## Priority

**High** - Protects admin functionality from unauthorized access.

## Estimated Effort

- Phase 1-2 (Foundation): 4 hours
- Phase 3 (Session Hardening): 3 hours
- Phase 4 (Audit & Confirmation): 4 hours
- Phase 5 (Recovery & UI): 4 hours
- Phase 6 (VPN Integration): 3 hours
- Testing: 4 hours

**Total: ~2-3 days**
