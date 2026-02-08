// CSRF protection middleware
// Implements double-submit cookie pattern with Origin/Referer validation

import { audit } from "../db/index.js";
import { validateCsrfToken, getCsrfTokenFromRequest, generateCsrfToken } from "../lib/csrf.js";

// Methods that require CSRF protection
const PROTECTED_METHODS = ["POST", "PUT", "PATCH", "DELETE"];

// Paths exempt from CSRF (webhooks use signature validation, health checks are read-only)
const EXEMPT_PATHS = [/^\/api\/webhooks\//, /^\/api\/callbacks\//, /^\/health$/, /^\/api\/health$/];

/**
 * CSRF protection middleware
 * Validates CSRF token and Origin/Referer headers for state-changing requests
 */
export function csrfProtection(req, res, next) {
  // Skip safe methods (GET, HEAD, OPTIONS)
  if (!PROTECTED_METHODS.includes(req.method)) {
    return next();
  }

  // Skip exempt paths
  if (EXEMPT_PATHS.some((pattern) => pattern.test(req.path))) {
    return next();
  }

  // Skip if using API key authentication (not cookie-based, so not vulnerable to CSRF)
  if (req.headers["x-api-key"]) {
    return next();
  }

  // Skip if using Bearer token authentication (not cookie-based)
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    return next();
  }

  // Validate Origin/Referer header
  const originResult = validateOrigin(req);
  if (!originResult.valid) {
    logCsrfFailure(req, originResult.error);
    return res.status(403).json({
      error: "CSRF validation failed",
      code: "CSRF_ORIGIN_INVALID",
    });
  }

  // Get session token (used as session ID for CSRF binding)
  const sessionId = req.sessionToken;

  if (!sessionId) {
    // No session = no CSRF token needed (request will fail auth anyway)
    return next();
  }

  // Validate CSRF token
  const token = getCsrfTokenFromRequest(req);
  const result = validateCsrfToken(token, sessionId);

  if (!result.valid) {
    logCsrfFailure(req, result.error);
    return res.status(403).json({
      error: "CSRF validation failed",
      code: "CSRF_INVALID",
    });
  }

  next();
}

/**
 * Validate Origin or Referer header matches expected origin
 * @param {Request} req - Express request object
 * @returns {{ valid: boolean, error?: string }}
 */
function validateOrigin(req) {
  const origin = req.headers.origin;
  const referer = req.headers.referer;

  // If neither header is present, this is likely a same-origin request
  // CSRF attacks from other origins include these headers
  if (!origin && !referer) {
    return { valid: true };
  }

  const allowedOrigins = getAllowedOrigins();

  // Check Origin header
  if (origin) {
    if (allowedOrigins.includes(origin)) {
      return { valid: true };
    }
    return { valid: false, error: `Origin not allowed: ${origin}` };
  }

  // Check Referer header
  if (referer) {
    try {
      const refererUrl = new URL(referer);
      const refererOrigin = refererUrl.origin;
      if (allowedOrigins.includes(refererOrigin)) {
        return { valid: true };
      }
      return { valid: false, error: `Referer origin not allowed: ${refererOrigin}` };
    } catch {
      return { valid: false, error: "Invalid Referer header" };
    }
  }

  return { valid: false, error: "No Origin or Referer header" };
}

/**
 * Get allowed origins from environment
 * @returns {string[]} Array of allowed origin URLs
 */
function getAllowedOrigins() {
  const origins =
    process.env.ALLOWED_ORIGINS?.split(",")
      .map((o) => o.trim())
      .filter(Boolean) || [];

  // Always allow the app's own origin
  const appUrl = process.env.APP_URL || "http://localhost:3000";
  if (!origins.includes(appUrl)) {
    origins.push(appUrl);
  }

  // In development, also allow localhost variants
  if (process.env.NODE_ENV !== "production") {
    const devOrigins = [
      "http://localhost:3000",
      "http://localhost:5173", // Vite dev server
      "http://127.0.0.1:3000",
      "http://127.0.0.1:5173",
    ];
    for (const devOrigin of devOrigins) {
      if (!origins.includes(devOrigin)) {
        origins.push(devOrigin);
      }
    }
  }

  return origins;
}

/**
 * Log CSRF failures for security monitoring
 * @param {Request} req - Express request object
 * @param {string} reason - Failure reason
 */
async function logCsrfFailure(req, reason) {
  console.warn("CSRF validation failed:", {
    path: req.path,
    method: req.method,
    ip: req.ip,
    reason,
    origin: req.headers.origin,
    referer: req.headers.referer,
  });

  // Log to audit trail
  await audit
    .log(req.user?.id || null, "security.csrf_failed", { path: req.path, reason }, req.ip)
    .catch(console.error);
}

/**
 * Middleware to attach CSRF token to response
 * Should be called after session authentication middleware
 */
export function attachCsrfToken(req, res, next) {
  // Only attach token if there's a valid session
  if (req.sessionToken) {
    const token = generateCsrfToken(req.sessionToken);

    // Set as cookie for JavaScript access (not httpOnly so frontend can read it)
    res.cookie("XSRF-TOKEN", token, {
      httpOnly: false, // JavaScript needs to read this
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      path: "/",
    });

    // Also expose in header for API responses
    res.setHeader("X-CSRF-Token", token);

    // Attach to request for template rendering
    req.csrfToken = token;
  }

  next();
}

/**
 * Middleware to inject CSRF token into rendered pages
 * Makes token available as res.locals.csrfToken for templates
 */
export function injectCsrfToken(req, res, next) {
  if (req.csrfToken) {
    res.locals.csrfToken = req.csrfToken;
  }
  next();
}

export default {
  csrfProtection,
  attachCsrfToken,
  injectCsrfToken,
};
