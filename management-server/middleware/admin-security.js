/**
 * Admin Security Middleware
 *
 * Provides security controls for admin routes:
 * - IP allowlist enforcement
 * - Reduced session timeout for admin (1 hour vs 7 days)
 * - Re-authentication for sensitive operations
 * - Emergency access token support
 */
import crypto from "crypto";
import {
  adminIpAllowlist,
  emergencyAccessTokens,
  adminSecuritySettings,
  adminSessions,
} from "../db/admin.js";
import { sessions } from "../db/index.js";
import { audit } from "../db/index.js";
import { getClientIpSecure } from "../lib/ip-utils.js";

// ============================================================
// CONFIGURATION
// ============================================================

// Admin session timeout: 1 hour (configurable via env)
const ADMIN_SESSION_TIMEOUT_MS =
  parseInt(process.env.ADMIN_SESSION_TIMEOUT_MS, 10) || 60 * 60 * 1000;

// Inactivity timeout: 15 minutes (configurable via env)
const ADMIN_INACTIVITY_TIMEOUT_MS =
  parseInt(process.env.ADMIN_INACTIVITY_TIMEOUT_MS, 10) || 15 * 60 * 1000;

// Re-authentication interval for sensitive operations: 5 minutes
const REAUTH_INTERVAL_MS = parseInt(process.env.ADMIN_REAUTH_INTERVAL_MS, 10) || 5 * 60 * 1000;

// Session cookie name (matches auth.js)
const SESSION_COOKIE = "ocmt_session";

// ============================================================
// ADMIN IP ALLOWLIST MIDDLEWARE
// ============================================================

/**
 * Middleware to enforce IP allowlist for admin routes
 *
 * Features:
 * - Checks if allowlist is enabled before enforcing
 * - Supports emergency access tokens to bypass allowlist
 * - Logs all access attempts (allowed and blocked)
 * - Fails closed on errors (denies access)
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
          req.user?.id || null,
          "admin.emergency_access",
          {
            ip: clientIp,
            tokenId: validToken.id,
            reason: validToken.reason,
          },
          clientIp,
        );

        // Mark request as using emergency access
        req.emergencyAccess = true;
        return next();
      }
    }

    // Check IP against allowlist (this also updates hit count)
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

// ============================================================
// ADMIN SESSION TIMEOUT MIDDLEWARE
// ============================================================

/**
 * Check if user email is in the admin list
 */
function isSystemAdmin(user) {
  const adminEmails = (process.env.ADMIN_EMAILS || "")
    .split(",")
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean);
  return adminEmails.includes(user?.email?.toLowerCase());
}

/**
 * Enhanced admin authentication middleware with:
 * - Shorter session timeout (1 hour)
 * - Inactivity timeout (15 minutes)
 * - Session activity tracking
 */
export async function requireAdminSession(req, res, next) {
  // Support token from: cookie, header, or query param (for SSE)
  const token = req.cookies?.[SESSION_COOKIE] || req.headers["x-session-token"] || req.query.token;

  if (!token) {
    return res.status(401).json({ error: "Authentication required" });
  }

  try {
    const session = await sessions.findByToken(token);

    if (!session) {
      return res.status(401).json({ error: "Invalid or expired session" });
    }

    // Check admin status
    if (!isSystemAdmin({ email: session.email })) {
      return res.status(403).json({ error: "Admin access required" });
    }

    // Check admin session age (stricter than regular user)
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

    // Update last activity (fire and forget)
    const clientIp = getClientIpSecure(req);
    adminSessions.updateActivity(session.id, clientIp).catch((err) => {
      console.error("Failed to update session activity:", err);
    });

    // Set user on request
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
    req.sessionToken = token;
    req.isAdmin = true;

    next();
  } catch (err) {
    console.error("Admin auth error:", err);
    res.status(500).json({ error: "Authentication failed" });
  }
}

// ============================================================
// RE-AUTHENTICATION FOR SENSITIVE OPERATIONS
// ============================================================

/**
 * Middleware factory to require recent authentication for sensitive operations
 *
 * @param {Object} [options]
 * @param {number} [options.maxAge] - Maximum age of last auth in milliseconds
 * @returns {Function} Express middleware
 */
export function requireRecentAuth(options = {}) {
  const maxAge = options.maxAge || REAUTH_INTERVAL_MS;

  return async (req, res, next) => {
    // Check if user has authenticated recently
    const lastAuthAt = req.session?.lastPasswordAuthAt || req.cookies?.last_password_auth;

    if (!lastAuthAt) {
      return res.status(401).json({
        error: "Password confirmation required",
        code: "REAUTH_REQUIRED",
        requiresPassword: true,
      });
    }

    const authAge = Date.now() - new Date(lastAuthAt).getTime();
    if (authAge > maxAge) {
      return res.status(401).json({
        error: "Password confirmation required",
        code: "REAUTH_REQUIRED",
        requiresPassword: true,
      });
    }

    next();
  };
}

/**
 * Record that user has confirmed their password
 * Call this after successful password verification
 */
export function recordPasswordAuth(res) {
  const now = new Date().toISOString();
  res.cookie("last_password_auth", now, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: REAUTH_INTERVAL_MS,
    path: "/api/admin",
  });
}

// ============================================================
// DANGEROUS OPERATION CONFIRMATION
// ============================================================

/**
 * List of action types that require confirmation
 */
const DANGEROUS_ACTIONS = [
  "user.delete",
  "group.delete",
  "admin.revoke",
  "system.config.change",
  "ip_allowlist.disable",
  "emergency_token.create",
  "vault.delete",
  "all_sessions.revoke",
];

/**
 * Check if an action requires confirmation
 * @param {string} actionType
 * @returns {Promise<boolean>}
 */
export async function requiresConfirmation(actionType) {
  // Check for custom configured actions
  const customActions = await adminSecuritySettings.get("require_confirmation_for");
  const actions = customActions || DANGEROUS_ACTIONS;
  return actions.includes(actionType);
}

/**
 * Middleware factory for dangerous operation confirmation
 *
 * If no confirmation token is provided:
 * - Creates a confirmation request
 * - Returns 202 Accepted with confirmation details
 *
 * If confirmation token is provided:
 * - Validates the token
 * - Allows the request to proceed
 *
 * @param {string} actionType - Type of action requiring confirmation
 * @returns {Function} Express middleware
 */
export function requireConfirmation(actionType) {
  return async (req, res, next) => {
    const { adminActionConfirmations } = await import("../db/admin.js");

    // Check if this action type requires confirmation
    const needsConfirmation = await requiresConfirmation(actionType);
    if (!needsConfirmation) {
      return next();
    }

    // Check for confirmation token
    const confirmationToken = req.headers["x-confirmation-token"];

    if (confirmationToken) {
      // Validate the token
      const confirmation = await adminActionConfirmations.findByToken(confirmationToken);

      if (!confirmation) {
        return res.status(400).json({
          error: "Invalid or expired confirmation token",
          code: "CONFIRMATION_INVALID",
        });
      }

      if (confirmation.action_type !== actionType) {
        return res.status(400).json({
          error: "Confirmation action mismatch",
          code: "CONFIRMATION_MISMATCH",
        });
      }

      // Mark as confirmed
      await adminActionConfirmations.confirm(confirmation.id);

      // Attach confirmation details to request
      req.confirmedAction = {
        id: confirmation.id,
        adminId: confirmation.admin_id,
        actionType: confirmation.action_type,
        actionDetails: confirmation.action_details,
      };

      return next();
    }

    // No token - create confirmation request
    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes
    const clientIp = getClientIpSecure(req);

    const confirmation = await adminActionConfirmations.create({
      adminId: req.user.id,
      actionType,
      actionDetails: sanitizeActionDetails(req),
      token,
      expiresAt,
      ipAddress: clientIp,
    });

    // Log the confirmation request
    await audit.log(
      req.user.id,
      "admin.confirmation_requested",
      {
        actionType,
        confirmationId: confirmation.id,
        expiresAt: expiresAt.toISOString(),
      },
      clientIp,
    );

    return res.status(202).json({
      confirmationRequired: true,
      confirmationId: confirmation.id,
      token,
      expiresAt: expiresAt.toISOString(),
      action: actionType,
      message: "Please confirm this action by resubmitting with the X-Confirmation-Token header",
    });
  };
}

/**
 * Sanitize request details for confirmation storage
 * Removes sensitive fields like passwords and tokens
 */
function sanitizeActionDetails(req) {
  const details = {
    path: req.path,
    method: req.method,
    params: req.params,
  };

  if (req.body) {
    const sanitized = { ...req.body };
    const sensitiveFields = ["password", "token", "secret", "key", "apiKey", "accessToken"];

    for (const field of sensitiveFields) {
      if (field in sanitized) {
        sanitized[field] = "[REDACTED]";
      }
    }
    details.body = sanitized;
  }

  return details;
}

// ============================================================
// COMBINED ADMIN SECURITY MIDDLEWARE
// ============================================================

/**
 * Combined admin security middleware that applies all protections:
 * 1. IP allowlist check
 * 2. Admin session validation with reduced timeout
 *
 * Use this for all admin routes.
 */
export async function requireSecureAdmin(req, res, next) {
  try {
    // First check IP allowlist
    await new Promise((resolve, reject) => {
      requireAdminIpAllowlist(req, res, (err) => {
        if (err) {
          reject(err);
        } else if (res.headersSent) {
          reject(new Error("Response sent"));
        } else {
          resolve();
        }
      });
    });

    // Then check admin session
    await new Promise((resolve, reject) => {
      requireAdminSession(req, res, (err) => {
        if (err) {
          reject(err);
        } else if (res.headersSent) {
          reject(new Error("Response sent"));
        } else {
          resolve();
        }
      });
    });

    next();
  } catch (err) {
    // Response already sent by inner middleware
    if (!res.headersSent) {
      console.error("Secure admin middleware error:", err);
      res.status(500).json({ error: "Security check failed" });
    }
  }
}

// ============================================================
// EXPORTS
// ============================================================

export default {
  // IP allowlist
  requireAdminIpAllowlist,

  // Session security
  requireAdminSession,

  // Re-authentication
  requireRecentAuth,
  recordPasswordAuth,

  // Dangerous operations
  requireConfirmation,
  requiresConfirmation,

  // Combined
  requireSecureAdmin,
};
