// CSRF token generation and validation
// Uses HMAC-signed tokens bound to session for stateless protection

import crypto from "crypto";

// CSRF secret - MUST be set via environment variable in production
// Without this, tokens are invalidated on server restart
const CSRF_SECRET = process.env.CSRF_SECRET;
if (!CSRF_SECRET) {
  throw new Error("CSRF_SECRET environment variable is required");
}
const TOKEN_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Generate CSRF token bound to session
 * Uses HMAC to bind token to session without server-side storage
 * @param {string} sessionId - The session token/ID to bind to
 * @returns {string} Base64url-encoded CSRF token
 */
export function generateCsrfToken(sessionId) {
  if (!sessionId) {
    throw new Error("Session ID required for CSRF token generation");
  }

  const timestamp = Date.now();
  const random = crypto.randomBytes(16).toString("hex");
  const payload = `${sessionId}:${timestamp}:${random}`;

  const signature = crypto.createHmac("sha256", CSRF_SECRET).update(payload).digest("hex");

  // Token format: payload.signature (payload base64url encoded, signature as hex)
  const token = Buffer.from(payload).toString("base64url") + "." + signature;

  return token;
}

/**
 * Validate CSRF token
 * Uses timing-safe comparison to prevent timing attacks
 * @param {string} token - The CSRF token to validate
 * @param {string} sessionId - The session token/ID to validate against
 * @returns {{ valid: boolean, error?: string }}
 */
export function validateCsrfToken(token, sessionId) {
  if (!token) {
    return { valid: false, error: "CSRF token missing" };
  }

  if (!sessionId) {
    return { valid: false, error: "Session ID required for CSRF validation" };
  }

  const parts = token.split(".");
  if (parts.length !== 2) {
    return { valid: false, error: "Invalid CSRF token format" };
  }

  try {
    const payload = Buffer.from(parts[0], "base64url").toString("utf8");
    const providedSignature = parts[1]; // Already hex string

    // Verify signature using HMAC
    const expectedSignature = crypto
      .createHmac("sha256", CSRF_SECRET)
      .update(payload)
      .digest("hex");

    // Timing-safe comparison to prevent timing attacks
    const providedBuffer = Buffer.from(providedSignature, "hex");
    const expectedBuffer = Buffer.from(expectedSignature, "hex");

    // Buffers must be same length for timingSafeEqual
    if (providedBuffer.length !== expectedBuffer.length) {
      return { valid: false, error: "Invalid CSRF token signature" };
    }

    if (!crypto.timingSafeEqual(providedBuffer, expectedBuffer)) {
      return { valid: false, error: "Invalid CSRF token signature" };
    }

    // Parse payload
    const payloadParts = payload.split(":");
    if (payloadParts.length < 3) {
      return { valid: false, error: "Invalid CSRF token payload" };
    }

    const tokenSessionId = payloadParts[0];
    const timestamp = parseInt(payloadParts[1], 10);

    // Timing-safe session binding verification
    const sessionBuffer = Buffer.from(sessionId);
    const tokenSessionBuffer = Buffer.from(tokenSessionId);

    // Lengths must match for timing-safe comparison
    if (sessionBuffer.length !== tokenSessionBuffer.length) {
      return { valid: false, error: "CSRF token session mismatch" };
    }

    if (!crypto.timingSafeEqual(sessionBuffer, tokenSessionBuffer)) {
      return { valid: false, error: "CSRF token session mismatch" };
    }

    // Check expiry
    const tokenAge = Date.now() - timestamp;
    if (tokenAge > TOKEN_EXPIRY_MS) {
      return { valid: false, error: "CSRF token expired" };
    }

    // Reject tokens from the future (clock skew tolerance: 5 minutes)
    if (tokenAge < -5 * 60 * 1000) {
      return { valid: false, error: "CSRF token timestamp invalid" };
    }

    return { valid: true };
  } catch (err) {
    return { valid: false, error: "CSRF token validation failed" };
  }
}

/**
 * Get CSRF token from request
 * Checks header first (X-CSRF-Token, X-XSRF-Token), then body (_csrf)
 * @param {Request} req - Express request object
 * @returns {string|null} CSRF token or null if not found
 */
export function getCsrfTokenFromRequest(req) {
  // Header takes precedence (X-CSRF-Token or X-XSRF-Token)
  const headerToken = req.headers["x-csrf-token"] || req.headers["x-xsrf-token"];
  if (headerToken) {
    return headerToken;
  }

  // Fall back to body field
  if (req.body && req.body._csrf) {
    return req.body._csrf;
  }

  // Check query parameter as last resort (for forms that use GET-like POST)
  if (req.query && req.query._csrf) {
    return req.query._csrf;
  }

  return null;
}

export default {
  generateCsrfToken,
  validateCsrfToken,
  getCsrfTokenFromRequest,
};
