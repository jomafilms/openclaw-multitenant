// Rate limiting middleware for group-vault server
// Uses in-memory store (consider Redis for distributed deployments)

/**
 * Rate limiter configuration
 * Key format: `${prefix}:${identifier}`
 */
const stores = new Map();

/**
 * Create a rate limiter with specified configuration
 * @param {Object} options
 * @param {string} options.name - Limiter name for logging/debugging
 * @param {number} options.windowMs - Time window in milliseconds
 * @param {number} options.maxRequests - Max requests per window
 * @param {string} [options.keyPrefix] - Prefix for rate limit keys
 * @param {Function} [options.keyGenerator] - Custom key generator (req) => string
 * @param {string} [options.message] - Custom error message
 * @returns {Function} Express middleware
 */
export function createRateLimiter(options) {
  const {
    name,
    windowMs,
    maxRequests,
    keyPrefix = "rl",
    keyGenerator = (req) => getClientIp(req),
    message = "Too many requests, please try again later",
    onLimitReached = null,
  } = options;

  const storeKey = `${keyPrefix}:${name}`;
  if (!stores.has(storeKey)) {
    stores.set(storeKey, new Map());
  }
  const store = stores.get(storeKey);

  // Periodic cleanup of expired entries
  const cleanupInterval = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of store.entries()) {
      if (now - entry.windowStart > windowMs * 2) {
        store.delete(key);
      }
    }
  }, windowMs);
  cleanupInterval.unref();

  return async function rateLimitMiddleware(req, res, next) {
    try {
      const key = keyGenerator(req);
      const now = Date.now();

      let entry = store.get(key);

      if (!entry || now - entry.windowStart > windowMs) {
        entry = { count: 0, windowStart: now };
        store.set(key, entry);
      }

      const remaining = Math.max(0, maxRequests - entry.count);
      const resetAt = entry.windowStart + windowMs;
      const retryAfterSeconds = Math.ceil((resetAt - now) / 1000);

      res.setHeader("RateLimit-Limit", maxRequests);
      res.setHeader("RateLimit-Remaining", remaining);
      res.setHeader("RateLimit-Reset", Math.ceil(resetAt / 1000));

      if (entry.count >= maxRequests) {
        res.setHeader("Retry-After", retryAfterSeconds);

        if (onLimitReached) {
          await onLimitReached(req, key);
        }

        console.warn(`[rate-limit] ${name}: limit exceeded for ${key}`);

        return res.status(429).json({
          error: message,
          code: "RATE_LIMIT_EXCEEDED",
          retryAfter: retryAfterSeconds,
        });
      }

      entry.count++;
      next();
    } catch (err) {
      console.error(`[rate-limit] ${name}: error in middleware:`, err);
      next();
    }
  };
}

/**
 * Extract client IP from request
 */
export function getClientIp(req) {
  const forwardedFor = req.headers["x-forwarded-for"];
  if (forwardedFor) {
    return forwardedFor.split(",")[0].trim();
  }
  const realIp = req.headers["x-real-ip"];
  if (realIp) {
    return realIp;
  }
  return req.ip || req.socket?.remoteAddress || "unknown";
}

// Vault unlock limiter: 5 attempts per 15 minutes
export const vaultUnlockLimiter = createRateLimiter({
  name: "vault-unlock",
  windowMs: 15 * 60 * 1000,
  maxRequests: 5,
  message: "Too many vault unlock attempts. Please try again in 15 minutes.",
  onLimitReached: async (req, key) => {
    console.warn(`[security] Group vault unlock rate limit reached for IP: ${key}`);
  },
});

// Token issuance limiter: 100 tokens per hour per user
export const tokenIssuanceLimiter = createRateLimiter({
  name: "token-issuance",
  windowMs: 60 * 60 * 1000,
  maxRequests: 100,
  keyGenerator: (req) => req.body?.userId || getClientIp(req),
  message: "Too many token requests. Please try again later.",
});

export default {
  createRateLimiter,
  getClientIp,
  vaultUnlockLimiter,
  tokenIssuanceLimiter,
};
