// Session management routes
// List, revoke individual sessions, and sign out everywhere

import { Router } from "express";
import { sessions, audit } from "../db/index.js";
import { getClientIp, createRateLimiter } from "../lib/rate-limit.js";
import { requireUser } from "../middleware/auth.js";
import { detectTenant } from "../middleware/tenant-context.js";

const router = Router();

// Rate limiter for session management (20 requests per 15 minutes)
const sessionMgmtLimiter = createRateLimiter({
  name: "session-management",
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxRequests: 20,
  message: "Too many session management requests. Please try again later.",
});

router.use(sessionMgmtLimiter);

/**
 * Parse user agent into device info
 */
function parseUserAgent(userAgent) {
  if (!userAgent) {
    return { type: "unknown", name: "Unknown Device" };
  }

  const ua = userAgent.toLowerCase();

  // Detect device type
  let type = "desktop";
  if (ua.includes("mobile") || ua.includes("android") || ua.includes("iphone")) {
    type = "mobile";
  } else if (ua.includes("tablet") || ua.includes("ipad")) {
    type = "tablet";
  }

  // Detect browser
  let browser = "Unknown";
  if (ua.includes("firefox")) {
    browser = "Firefox";
  } else if (ua.includes("edg/") || ua.includes("edge")) {
    browser = "Edge";
  } else if (ua.includes("chrome") && !ua.includes("chromium")) {
    browser = "Chrome";
  } else if (ua.includes("safari") && !ua.includes("chrome")) {
    browser = "Safari";
  } else if (ua.includes("opera") || ua.includes("opr/")) {
    browser = "Opera";
  }

  // Detect OS
  let os = "Unknown";
  if (ua.includes("windows")) {
    os = "Windows";
  } else if (ua.includes("mac os") || ua.includes("macos")) {
    os = "macOS";
  } else if (ua.includes("linux") && !ua.includes("android")) {
    os = "Linux";
  } else if (ua.includes("android")) {
    os = "Android";
  } else if (ua.includes("iphone") || ua.includes("ipad") || ua.includes("ios")) {
    os = "iOS";
  }

  const name = `${browser} on ${os}`;

  return { type, name, browser, os };
}

/**
 * GET /api/auth/sessions - List active sessions
 */
router.get("/", requireUser, detectTenant, async (req, res) => {
  try {
    const activeSessions = await sessions.listActiveForUser(req.user.id);

    const sessionsWithCurrent = activeSessions.map((session) => {
      // Parse device info from stored data or user agent
      let deviceInfo = session.device_info || {};
      if (typeof deviceInfo === "string") {
        try {
          deviceInfo = JSON.parse(deviceInfo);
        } catch {
          deviceInfo = {};
        }
      }

      // If no device info stored, parse from user agent
      if (!deviceInfo.type || !deviceInfo.name) {
        deviceInfo = parseUserAgent(session.user_agent);
      }

      return {
        id: session.id,
        createdAt: session.created_at,
        expiresAt: session.expires_at,
        lastActivityAt: session.last_activity_at,
        ipAddress: session.ip_address,
        userAgent: session.user_agent,
        deviceInfo,
        isCurrent: session.id === req.sessionId,
      };
    });

    res.json({ sessions: sessionsWithCurrent, count: sessionsWithCurrent.length });
  } catch (err) {
    console.error("List sessions error:", err);
    res.status(500).json({ error: "Failed to list sessions" });
  }
});

/**
 * DELETE /api/auth/sessions/:id - Revoke specific session
 */
router.delete("/:id", requireUser, detectTenant, async (req, res) => {
  try {
    const { id } = req.params;

    // Validate UUID format
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
      return res.status(400).json({ error: "Invalid session ID format" });
    }

    const session = await sessions.findById(id);
    if (!session || session.user_id !== req.user.id) {
      return res.status(404).json({ error: "Session not found" });
    }

    if (id === req.sessionId) {
      return res.status(400).json({
        error: "Cannot revoke current session. Use logout instead.",
        code: "CANNOT_REVOKE_CURRENT",
      });
    }

    await sessions.revokeById(id, "user_revoked");
    await audit.log(req.user.id, "session.revoked", { sessionId: id }, getClientIp(req));

    res.json({ success: true, message: "Session revoked" });
  } catch (err) {
    console.error("Revoke session error:", err);
    res.status(500).json({ error: "Failed to revoke session" });
  }
});

/**
 * DELETE /api/auth/sessions - Sign out everywhere (except current)
 */
router.delete("/", requireUser, detectTenant, async (req, res) => {
  try {
    const revokedCount = await sessions.revokeAllForUser(
      req.user.id,
      req.sessionId,
      "sign_out_everywhere",
    );

    await audit.log(
      req.user.id,
      "session.revoked_all",
      {
        count: revokedCount,
        exceptCurrent: true,
      },
      getClientIp(req),
    );

    res.json({
      success: true,
      message: `Revoked ${revokedCount} session(s)`,
      revokedCount,
    });
  } catch (err) {
    console.error("Revoke all sessions error:", err);
    res.status(500).json({ error: "Failed to revoke sessions" });
  }
});

export default router;
