import crypto from "crypto";
import { sessions, users, magicLinks, audit } from "../db/index.js";
import { generatePermanentToken, encryptGatewayToken } from "../lib/gateway-tokens.js";
import { getClientIp } from "../lib/rate-limit.js";

// Session cookie configuration
const SESSION_COOKIE = "ocmt_session";
const SESSION_MAX_AGE = 7 * 24 * 60 * 60 * 1000; // 7 days

// Configurable session timeout for regular users
const USER_SESSION_TIMEOUT_MS =
  parseInt(process.env.USER_SESSION_TIMEOUT_MS) || 7 * 24 * 60 * 60 * 1000; // 7 days default

// Magic link configuration
const MAGIC_LINK_EXPIRY = 15 * 60 * 1000; // 15 minutes

/**
 * Check if user email is in the admin list
 */
function isSystemAdmin(user) {
  const adminEmails = (process.env.ADMIN_EMAILS || "")
    .split(",")
    .map((e) => e.trim().toLowerCase());
  return adminEmails.includes(user?.email?.toLowerCase());
}

/**
 * Middleware to require authenticated user session
 * Sets req.user if valid session exists
 *
 * SECURITY: Never accept tokens from query params
 * SSE endpoints must use requireUserSSE middleware instead
 */
export function requireUser(req, res, next) {
  // SECURITY: Only accept tokens from cookies or headers, never query params
  // Query param tokens can leak to server logs, browser history, referrer headers
  const token = req.cookies?.[SESSION_COOKIE] || req.headers["x-session-token"];

  if (!token) {
    return res.status(401).json({ error: "Authentication required" });
  }

  sessions
    .findByToken(token)
    .then(async (session) => {
      if (!session) {
        return res.status(401).json({ error: "Invalid or expired session" });
      }

      // Check session age against timeout
      const sessionAge = Date.now() - new Date(session.created_at).getTime();
      if (sessionAge > USER_SESSION_TIMEOUT_MS) {
        return res.status(401).json({
          error: "Session expired",
          code: "SESSION_EXPIRED",
        });
      }

      // Session includes joined user data
      req.user = {
        id: session.user_id,
        email: session.email,
        name: session.name,
        status: session.status,
        containerId: session.container_id,
        containerPort: session.container_port,
        gatewayToken: session.gateway_token,
        tenant_id: session.tenant_id,
        is_platform_admin: session.is_platform_admin,
      };
      req.sessionId = session.id;
      req.sessionToken = token;

      // Update last activity asynchronously (don't block request)
      const clientIp = getClientIp(req);
      sessions.updateLastActivity(session.id, clientIp).catch((err) => {
        console.error("Failed to update session activity:", err);
      });

      next();
    })
    .catch((err) => {
      console.error("Auth error:", err);
      res.status(500).json({ error: "Authentication failed" });
    });
}

/**
 * Middleware to require system admin
 * Must be used after requireUser
 */
export function requireAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: "Authentication required" });
  }
  if (!isSystemAdmin(req.user)) {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
}

/**
 * Optional auth - sets req.user if session exists, but doesn't require it
 */
export function optionalUser(req, res, next) {
  const token = req.cookies?.[SESSION_COOKIE] || req.headers["x-session-token"];

  if (!token) {
    return next();
  }

  sessions
    .findByToken(token)
    .then((session) => {
      if (session) {
        req.user = {
          id: session.user_id,
          email: session.email,
          name: session.name,
          status: session.status,
          containerId: session.container_id,
          containerPort: session.container_port,
          gatewayToken: session.gateway_token,
          tenant_id: session.tenant_id,
          is_platform_admin: session.is_platform_admin,
        };
        req.sessionId = session.id;
        req.sessionToken = token;
      }
      next();
    })
    .catch(() => next());
}

/**
 * Generate a magic link token for passwordless login
 */
export async function generateMagicLink(email) {
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + MAGIC_LINK_EXPIRY);

  await magicLinks.create(email, token, expiresAt);

  return token;
}

/**
 * Verify a magic link token and create a session
 * @param {string} token - Magic link token
 * @param {string} ipAddress - Client IP address
 * @param {string} [userAgent] - User agent string for session tracking
 */
export async function verifyMagicLink(token, ipAddress, userAgent = null) {
  // Atomically find and mark as used to prevent TOCTOU race condition
  const link = await magicLinks.findAndMarkUsed(token);

  if (!link) {
    return { success: false, error: "Invalid or expired magic link" };
  }

  // Find or create user
  let user = await users.findByEmail(link.email);

  if (!user) {
    // Create new user with encrypted gateway token
    const rawToken = generatePermanentToken();
    const encryptedToken = encryptGatewayToken(rawToken);
    user = await users.create({
      name: link.email.split("@")[0], // Use email prefix as initial name
      email: link.email,
      gatewayToken: encryptedToken,
    });

    await audit.log(user.id, "user.created", { email: link.email }, ipAddress);
  }

  // Create session with metadata
  const sessionToken = crypto.randomBytes(32).toString("hex");
  const sessionExpiresAt = new Date(Date.now() + SESSION_MAX_AGE);

  await sessions.create(user.id, sessionToken, sessionExpiresAt, {
    ipAddress,
    userAgent,
  });
  await audit.log(user.id, "user.login", { method: "magic_link" }, ipAddress);

  return {
    success: true,
    user,
    sessionToken,
    sessionExpiresAt,
  };
}

/**
 * Set session cookie on response
 */
export function setSessionCookie(res, token, expiresAt) {
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    expires: expiresAt,
    path: "/",
  });
}

/**
 * Clear session cookie
 */
export function clearSessionCookie(res) {
  res.clearCookie(SESSION_COOKIE, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
  });
}

/**
 * Logout - delete session and clear cookie
 */
export async function logout(req, res) {
  const token = req.cookies?.[SESSION_COOKIE] || req.headers["x-session-token"];

  if (token) {
    await sessions.delete(token);
  }

  clearSessionCookie(res);
}

export default {
  requireUser,
  requireAdmin,
  optionalUser,
  generateMagicLink,
  verifyMagicLink,
  setSessionCookie,
  clearSessionCookie,
  logout,
};
