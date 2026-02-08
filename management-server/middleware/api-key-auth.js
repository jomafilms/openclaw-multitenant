// API Key Authentication Middleware
// Handles authentication via API keys for multi-tenant access
import { apiKeys, users } from "../db/index.js";

/**
 * Extract API key from request headers
 * Supports: x-api-key header or Authorization: Bearer opw_live_...
 * @param {import('express').Request} req
 * @returns {string|null}
 */
function extractApiKey(req) {
  // Priority 1: x-api-key header
  const xApiKey = req.headers["x-api-key"];
  if (xApiKey) {
    return xApiKey;
  }

  // Priority 2: Authorization Bearer header with API key format
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith("Bearer opw_live_")) {
    return authHeader.slice(7); // Remove "Bearer " prefix
  }

  return null;
}

/**
 * API Key Authentication Middleware
 *
 * Validates API keys and sets request context:
 * - req.apiKey: Key metadata (id, name, scopes, rateLimitOverride, etc.)
 * - req.tenant: Tenant info from the key
 * - req.user: User info if key has associated user_id
 * - req.authMethod: 'api_key' when authenticated via API key
 *
 * Passes through if no API key present (allows session auth fallback).
 * Returns 401 on invalid/expired/revoked keys.
 */
export async function apiKeyAuth(req, res, next) {
  const rawKey = extractApiKey(req);

  // No API key present - pass through for session auth fallback
  if (!rawKey) {
    return next();
  }

  try {
    const keyData = await apiKeys.validateKey(rawKey);

    if (!keyData) {
      return res.status(401).json({
        error: "Invalid API key",
        code: "INVALID_API_KEY",
      });
    }

    // Set request context
    req.apiKey = {
      id: keyData.id,
      name: keyData.name,
      keyPrefix: keyData.keyPrefix,
      scopes: keyData.scopes,
      rateLimitOverride: keyData.rateLimitOverride,
      expiresAt: keyData.expiresAt,
      createdAt: keyData.createdAt,
    };

    req.tenant = keyData.tenant;
    req.authMethod = "api_key";

    // If key has associated user, fetch and set user context
    if (keyData.userId) {
      const user = await users.findById(keyData.userId);
      if (user) {
        req.user = {
          id: user.id,
          email: user.email,
          name: user.name,
          status: user.status,
          containerId: user.container_id,
          containerPort: user.container_port,
          gatewayToken: user.gateway_token,
        };
      }
    }

    next();
  } catch (err) {
    console.error("API key auth error:", err);
    return res.status(500).json({
      error: "Authentication failed",
      code: "AUTH_ERROR",
    });
  }
}

/**
 * Require API Key Authentication
 *
 * Use after apiKeyAuth middleware to require API key authentication.
 * Returns 401 if request was not authenticated via API key.
 * For API-only endpoints that don't support session auth.
 */
export function requireApiKey(req, res, next) {
  if (req.authMethod !== "api_key" || !req.apiKey) {
    return res.status(401).json({
      error: "API key required",
      code: "API_KEY_REQUIRED",
    });
  }
  next();
}

/**
 * Require Specific Scope
 *
 * Factory function that returns middleware checking for a required scope.
 * Uses scope hierarchy: admin > write > read, with '*' granting all.
 * Returns 403 if scope not allowed.
 *
 * @param {string} scope - Required scope ('read', 'write', 'admin', or custom)
 * @returns {import('express').RequestHandler}
 *
 * @example
 * router.get('/data', apiKeyAuth, requireScope('read'), handler);
 * router.post('/data', apiKeyAuth, requireScope('write'), handler);
 * router.delete('/tenant', apiKeyAuth, requireScope('admin'), handler);
 */
export function requireScope(scope) {
  return (req, res, next) => {
    // Must have API key auth
    if (!req.apiKey) {
      return res.status(401).json({
        error: "API key required for scope check",
        code: "API_KEY_REQUIRED",
      });
    }

    // Check if key has required scope
    if (!apiKeys.checkScope(req.apiKey, scope)) {
      return res.status(403).json({
        error: `Scope '${scope}' required`,
        code: "INSUFFICIENT_SCOPE",
        required: scope,
        available: req.apiKey.scopes,
      });
    }

    next();
  };
}

/**
 * Require Multiple Scopes
 *
 * Factory function that returns middleware checking for ALL required scopes.
 * For endpoints needing multiple permissions.
 * Returns 403 if any scope is not allowed.
 *
 * @param {string[]} scopes - Array of required scopes
 * @returns {import('express').RequestHandler}
 *
 * @example
 * router.post('/admin/action', apiKeyAuth, requireScopes(['write', 'admin']), handler);
 */
export function requireScopes(scopes) {
  return (req, res, next) => {
    // Must have API key auth
    if (!req.apiKey) {
      return res.status(401).json({
        error: "API key required for scope check",
        code: "API_KEY_REQUIRED",
      });
    }

    // Check all required scopes
    const missingScopes = scopes.filter((scope) => !apiKeys.checkScope(req.apiKey, scope));

    if (missingScopes.length > 0) {
      return res.status(403).json({
        error: `Missing required scopes: ${missingScopes.join(", ")}`,
        code: "INSUFFICIENT_SCOPES",
        required: scopes,
        missing: missingScopes,
        available: req.apiKey.scopes,
      });
    }

    next();
  };
}

/**
 * Get Rate Limit for Request
 *
 * Helper to get the effective rate limit for a request.
 * Uses API key's rate_limit_override if set, otherwise returns null
 * for the rate limiter to use its default.
 *
 * @param {import('express').Request} req
 * @returns {number|null} Rate limit override or null for default
 */
export function getRateLimitOverride(req) {
  return req.apiKey?.rateLimitOverride ?? null;
}

export default {
  apiKeyAuth,
  requireApiKey,
  requireScope,
  requireScopes,
  getRateLimitOverride,
};
