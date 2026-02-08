import { PLANS, getPlan } from "./quotas.js";
// Rate limiting middleware with Redis support and in-memory fallback
// Uses Redis for distributed deployments, falls back to in-memory when unavailable
// Supports tenant-scoped rate limiting with plan-based limits
import { getRedisClient, isRedisConnected } from "./redis.js";

// In-memory fallback stores
const memoryStores = new Map();

// Service identifier for Redis key namespacing
const SERVICE_NAME = process.env.SERVICE_NAME || "management";

/**
 * Redis key format:
 * ocmt:ratelimit:{service}:{limiterName}:{identifier}
 */
function buildRedisKey(limiterName, identifier) {
  return `ocmt:ratelimit:${SERVICE_NAME}:${limiterName}:${identifier}`;
}

/**
 * Trusted proxy IP ranges (private networks by default)
 */
const DEFAULT_TRUSTED_PROXY_RANGES = [
  "127.0.0.0/8",
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "::1/128",
  "fc00::/7",
];

/**
 * Check if an IP is within a CIDR range (simplified check)
 */
function isInCIDR(ip, cidr) {
  // Simple prefix match for common cases
  const [range, bits] = cidr.split("/");
  if (!bits) {
    return ip === range;
  }

  // For IPv4 with /8, /16, /24
  if (ip.includes(".") && range.includes(".")) {
    const ipParts = ip.split(".");
    const rangeParts = range.split(".");
    const prefixOctets = Math.floor(parseInt(bits, 10) / 8);

    for (let i = 0; i < prefixOctets; i++) {
      if (ipParts[i] !== rangeParts[i]) {
        return false;
      }
    }
    return true;
  }

  // For IPv6 or complex cases, do a simple prefix check
  return ip.startsWith(range.replace(/0+$/, ""));
}

/**
 * Check if socket IP is from a trusted proxy
 */
function isTrustedProxy(socketIp) {
  if (!socketIp) {
    return false;
  }

  const trustedEnv = process.env.TRUSTED_PROXIES;
  const trustedRanges = trustedEnv
    ? trustedEnv.split(",").map((s) => s.trim())
    : DEFAULT_TRUSTED_PROXY_RANGES;

  return trustedRanges.some((range) => isInCIDR(socketIp, range));
}

/**
 * Extract client IP from request
 * Uses Express trust proxy if configured, otherwise validates proxy headers
 *
 * SECURITY: Only trusts X-Forwarded-For/X-Real-IP from trusted proxy IPs
 */
export function getClientIp(req) {
  // If Express trust proxy is configured, use req.ip (Express handles validation)
  if (req.app?.get?.("trust proxy")) {
    return req.ip || req.socket?.remoteAddress || "unknown";
  }

  const socketIp = req.socket?.remoteAddress;

  // Only process forwarded headers if from trusted proxy
  if (socketIp && isTrustedProxy(socketIp)) {
    const forwardedFor = req.headers["x-forwarded-for"];
    if (forwardedFor) {
      // Take the first IP (original client)
      const firstIp = forwardedFor.split(",")[0].trim();
      // Basic validation: must look like an IP
      if (firstIp && (firstIp.includes(".") || firstIp.includes(":"))) {
        return firstIp;
      }
    }

    const realIp = req.headers["x-real-ip"];
    if (realIp && (realIp.includes(".") || realIp.includes(":"))) {
      return realIp;
    }
  }

  return socketIp || "unknown";
}

/**
 * Get entry from Redis
 */
async function getRedisEntry(limiterName, identifier, windowMs, ttlSeconds) {
  const redis = getRedisClient();
  if (!redis) {
    return null;
  }

  try {
    const key = buildRedisKey(limiterName, identifier);
    const data = await redis.get(key);

    if (!data) {
      const now = Date.now();
      const entry = { count: 0, windowStart: now };
      await redis.set(key, JSON.stringify(entry), "EX", ttlSeconds);
      return entry;
    }

    const entry = JSON.parse(data);
    const now = Date.now();

    // Reset window if expired
    if (now - entry.windowStart > windowMs) {
      const newEntry = { count: 0, windowStart: now };
      await redis.set(key, JSON.stringify(newEntry), "EX", ttlSeconds);
      return newEntry;
    }

    return entry;
  } catch (err) {
    console.error(`[rate-limit] Redis get error:`, err.message);
    return null;
  }
}

/**
 * Increment Redis entry counter
 */
async function incrementRedisEntry(limiterName, identifier, ttlSeconds) {
  const redis = getRedisClient();
  if (!redis) {
    return;
  }

  try {
    const key = buildRedisKey(limiterName, identifier);
    const data = await redis.get(key);

    if (data) {
      const entry = JSON.parse(data);
      entry.count++;
      await redis.set(key, JSON.stringify(entry), "EX", ttlSeconds);
    }
  } catch (err) {
    console.error(`[rate-limit] Redis increment error:`, err.message);
  }
}

/**
 * Decrement Redis entry counter (for skipFailedRequests)
 */
async function decrementRedisEntry(limiterName, identifier) {
  const redis = getRedisClient();
  if (!redis) {
    return;
  }

  try {
    const key = buildRedisKey(limiterName, identifier);
    const data = await redis.get(key);

    if (data) {
      const entry = JSON.parse(data);
      entry.count = Math.max(0, entry.count - 1);
      await redis.set(key, JSON.stringify(entry), "KEEPTTL");
    }
  } catch (err) {
    console.error(`[rate-limit] Redis decrement error:`, err.message);
  }
}

/**
 * Get or create memory entry
 */
function getMemoryEntry(store, identifier, now, windowMs) {
  let entry = store.get(identifier);

  if (!entry || now - entry.windowStart > windowMs) {
    entry = { count: 0, windowStart: now };
    store.set(identifier, entry);
  }

  return entry;
}

/**
 * Create a rate limiter with Redis support and in-memory fallback
 * @param {Object} options
 * @param {string} options.name - Limiter name for logging/debugging
 * @param {number} options.windowMs - Time window in milliseconds
 * @param {number} options.maxRequests - Max requests per window
 * @param {string} [options.keyPrefix] - Prefix for rate limit keys
 * @param {Function} [options.keyGenerator] - Custom key generator (req) => string
 * @param {string} [options.message] - Custom error message
 * @param {boolean} [options.skipFailedRequests] - Don't count failed requests
 * @param {Function} [options.onLimitReached] - Callback when limit is reached
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
    skipFailedRequests = false,
    onLimitReached = null,
  } = options;

  // Setup in-memory fallback store
  const storeKey = `${keyPrefix}:${name}`;
  if (!memoryStores.has(storeKey)) {
    memoryStores.set(storeKey, new Map());
  }
  const memoryStore = memoryStores.get(storeKey);

  // Periodic cleanup of expired entries in memory store
  const cleanupInterval = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of memoryStore.entries()) {
      if (now - entry.windowStart > windowMs * 2) {
        memoryStore.delete(key);
      }
    }
  }, windowMs);
  cleanupInterval.unref(); // Don't prevent process exit

  // Redis TTL (2x window to allow for clock skew)
  const redisTtlSeconds = Math.ceil((windowMs * 2) / 1000);

  return async function rateLimitMiddleware(req, res, next) {
    try {
      const identifier = keyGenerator(req);
      const now = Date.now();

      let entry;
      let useRedis = isRedisConnected();

      // Try Redis first if connected
      if (useRedis) {
        entry = await getRedisEntry(name, identifier, windowMs, redisTtlSeconds);
      }

      // Fallback to memory if Redis failed or unavailable
      if (!entry) {
        entry = getMemoryEntry(memoryStore, identifier, now, windowMs);
        useRedis = false;
      }

      // Calculate remaining requests and reset time
      const remaining = Math.max(0, maxRequests - entry.count);
      const resetAt = entry.windowStart + windowMs;
      const retryAfterSeconds = Math.ceil((resetAt - now) / 1000);

      // Set rate limit headers (draft IETF standard)
      res.setHeader("RateLimit-Limit", maxRequests);
      res.setHeader("RateLimit-Remaining", remaining);
      res.setHeader("RateLimit-Reset", Math.ceil(resetAt / 1000));

      // Check if limit exceeded
      if (entry.count >= maxRequests) {
        res.setHeader("Retry-After", retryAfterSeconds);

        if (onLimitReached) {
          await onLimitReached(req, identifier);
        }

        console.warn(
          `[rate-limit] ${name}: limit exceeded for ${identifier} (${useRedis ? "redis" : "memory"})`,
        );

        return res.status(429).json({
          error: message,
          code: "RATE_LIMIT_EXCEEDED",
          retryAfter: retryAfterSeconds,
        });
      }

      // Increment counter
      if (useRedis) {
        await incrementRedisEntry(name, identifier, redisTtlSeconds);
      } else {
        entry.count++;
      }

      // If skipFailedRequests is true, decrement on error response
      if (skipFailedRequests) {
        const originalEnd = res.end;
        res.end = function (...args) {
          if (res.statusCode >= 400) {
            if (useRedis) {
              decrementRedisEntry(name, identifier).catch(() => {});
            } else {
              entry.count = Math.max(0, entry.count - 1);
            }
          }
          return originalEnd.apply(this, args);
        };
      }

      next();
    } catch (err) {
      console.error(`[rate-limit] ${name}: error in middleware:`, err);
      // On error, allow the request through (fail open)
      next();
    }
  };
}

/**
 * Pre-configured rate limiters for common use cases
 */

// Strict limiter for authentication endpoints
// 5 attempts per 15 minutes per IP
export const strictAuthLimiter = createRateLimiter({
  name: "strict-auth",
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxRequests: 5,
  message: "Too many authentication attempts. Please try again in 15 minutes.",
  skipFailedRequests: false, // Count all attempts including failed
  onLimitReached: async (req, key) => {
    // Could log to audit, send alert, etc.
    console.warn(`[security] Auth rate limit reached for IP: ${key}`);
  },
});

// Limiter for vault unlock - critical security endpoint
// 5 attempts per 15 minutes per IP
export const vaultUnlockLimiter = createRateLimiter({
  name: "vault-unlock",
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxRequests: 5,
  message: "Too many vault unlock attempts. Please try again in 15 minutes.",
  skipFailedRequests: false,
  onLimitReached: async (req, key) => {
    console.warn(`[security] Vault unlock rate limit reached for IP: ${key}`);
  },
});

// Limiter for password recovery endpoints
// 3 attempts per 30 minutes per IP
export const recoveryLimiter = createRateLimiter({
  name: "recovery",
  windowMs: 30 * 60 * 1000, // 30 minutes
  maxRequests: 3,
  message: "Too many recovery attempts. Please try again in 30 minutes.",
  skipFailedRequests: false,
});

// Moderate limiter for token issuance
// 100 tokens per hour per user
export const tokenIssuanceLimiter = createRateLimiter({
  name: "token-issuance",
  windowMs: 60 * 60 * 1000, // 1 hour
  maxRequests: 100,
  keyGenerator: (req) => {
    // Key by user ID if available, otherwise IP
    return req.user?.id || req.body?.userId || getClientIp(req);
  },
  message: "Too many token requests. Please try again later.",
});

// General API limiter
// 1000 requests per hour per IP
export const generalApiLimiter = createRateLimiter({
  name: "general-api",
  windowMs: 60 * 60 * 1000, // 1 hour
  maxRequests: 1000,
  message: "API rate limit exceeded. Please slow down.",
  skipFailedRequests: true, // Don't count failed requests against limit
});

// Limiter for login/magic link requests
// 10 per 15 minutes per IP (slightly more lenient to allow retries)
export const loginLimiter = createRateLimiter({
  name: "login",
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxRequests: 10,
  message: "Too many login attempts. Please try again in 15 minutes.",
});

// Limiter for organization invites (prevent spam)
// 50 invites per hour per user
export const inviteLimiter = createRateLimiter({
  name: "org-invite",
  windowMs: 60 * 60 * 1000, // 1 hour
  maxRequests: 50,
  keyGenerator: (req) => req.user?.id || getClientIp(req),
  message: "Too many invite requests. Please try again later.",
});

// Relay message rate limiter
// 100 messages per minute per container
export const relayMessageLimiter = createRateLimiter({
  name: "relay-message",
  windowMs: 60 * 1000, // 1 minute
  maxRequests: 100,
  keyGenerator: (req) => req.container?.userId || getClientIp(req),
  message: "Message rate limit exceeded. Please slow down.",
});

/**
 * NEW: Invite/Share specific rate limiters for groups
 * Added as part of Wave 2.1 security plan
 */

// Limiter for accepting invites
// 10 per 15 minutes per user - prevents spam accept attempts
export const inviteAcceptLimiter = createRateLimiter({
  name: "invite-accept",
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxRequests: 10,
  keyGenerator: (req) => req.user?.id || getClientIp(req),
  message: "Too many invite actions. Please wait before trying again.",
});

// Limiter for declining invites
// 10 per 15 minutes per user - prevents spam decline attempts
export const inviteDeclineLimiter = createRateLimiter({
  name: "invite-decline",
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxRequests: 10,
  keyGenerator: (req) => req.user?.id || getClientIp(req),
  message: "Too many invite actions. Please wait before trying again.",
});

// Limiter for creating/sending invites
// 20 per hour per user - prevents invite spam
export const inviteCreateLimiter = createRateLimiter({
  name: "invite-create",
  windowMs: 60 * 60 * 1000, // 1 hour
  maxRequests: 20,
  keyGenerator: (req) => req.user?.id || getClientIp(req),
  message: "Too many invites sent. Please wait before sending more.",
});

// Limiter for creating shares
// 50 per hour per user - prevents share spam
export const shareCreateLimiter = createRateLimiter({
  name: "share-create",
  windowMs: 60 * 60 * 1000, // 1 hour
  maxRequests: 50,
  keyGenerator: (req) => req.user?.id || getClientIp(req),
  message: "Too many shares created. Please wait before creating more.",
});

// Limiter for deleting shares
// 30 per 15 minutes per user - prevents mass deletion
export const shareDeleteLimiter = createRateLimiter({
  name: "share-delete",
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxRequests: 30,
  keyGenerator: (req) => req.user?.id || getClientIp(req),
  message: "Too many share deletions. Please wait before deleting more.",
});

/**
 * Utility: Get rate limit status for a key
 */
export function getRateLimitStatus(limiterName, key) {
  const storeKey = `rl:${limiterName}`;
  const store = memoryStores.get(storeKey);
  if (!store) {
    return null;
  }

  const entry = store.get(key);
  if (!entry) {
    return null;
  }

  return {
    count: entry.count,
    windowStart: entry.windowStart,
  };
}

/**
 * Utility: Reset rate limit for a key (for admin use)
 */
export function resetRateLimit(limiterName, key) {
  const storeKey = `rl:${limiterName}`;
  const store = memoryStores.get(storeKey);
  if (!store) {
    return false;
  }

  return store.delete(key);
}

/**
 * Utility: Get all active rate limit entries (for monitoring)
 */
export function getAllRateLimitEntries(limiterName) {
  const storeKey = `rl:${limiterName}`;
  const store = memoryStores.get(storeKey);
  if (!store) {
    return [];
  }

  return Array.from(store.entries()).map(([key, entry]) => ({
    key,
    ...entry,
  }));
}

// ============================================================
// TENANT-SCOPED RATE LIMITING
// ============================================================

/**
 * Default plan-based rate limits (requests per minute)
 * These can be overridden via options when creating the limiter
 */
export const DEFAULT_PLAN_RATE_LIMITS = {
  free: 100, // 100 requests/minute
  pro: 500, // 500 requests/minute
  enterprise: 2000, // 2000 requests/minute (effectively unlimited for most uses)
};

/**
 * Get the rate limit key for a request
 * Uses tenant_id if available, otherwise falls back to client IP
 *
 * @param {object} req - Express request object
 * @returns {string} Rate limit key (tenant ID or IP)
 */
export function getTenantRateLimitKey(req) {
  // Priority 1: Use tenant ID if available
  if (req.tenant?.id) {
    return `tenant:${req.tenant.id}`;
  }

  // Priority 2: Use tenant ID from context
  if (req.tenantId) {
    return `tenant:${req.tenantId}`;
  }

  // Fallback: Use client IP for unauthenticated requests
  return `ip:${getClientIp(req)}`;
}

/**
 * Get the rate limit for a request based on plan and overrides
 *
 * Priority:
 * 1. API key rate_limit_override (if set)
 * 2. Plan-based limit
 * 3. Default limit
 *
 * @param {object} req - Express request object
 * @param {object} planLimits - Plan-based limits override
 * @param {number} defaultLimit - Default limit for unknown plans
 * @returns {number} Rate limit for this request (-1 means unlimited)
 */
export function getTenantRateLimit(req, planLimits = DEFAULT_PLAN_RATE_LIMITS, defaultLimit = 100) {
  // Priority 1: Check API key override
  if (req.apiKey?.rate_limit_override != null) {
    const override = req.apiKey.rate_limit_override;
    // -1 or 0 means unlimited
    if (override <= 0) {
      return -1;
    }
    return override;
  }

  // Priority 2: Get plan from subscription
  const planName = req.subscription?.plan || req.tenant?.subscription?.plan || "free";
  const planLimit = planLimits[planName.toLowerCase()];

  if (planLimit != null) {
    // -1 means unlimited
    if (planLimit === -1) {
      return -1;
    }
    return planLimit;
  }

  // Fallback: Use default limit
  return defaultLimit;
}

/**
 * Create a tenant-aware rate limiter with plan-based limits
 *
 * Features:
 * - Rate limits are per-tenant, not per-IP (IP fallback for unauthenticated)
 * - Plan-based limits (free/pro/enterprise)
 * - API key override support
 * - Standard rate limit headers
 * - Redis support with in-memory fallback
 *
 * @param {Object} options
 * @param {string} options.name - Limiter name for logging/debugging
 * @param {number} [options.windowMs=60000] - Time window in milliseconds (default: 1 minute)
 * @param {number} [options.defaultLimit=100] - Default limit for unauthenticated/unknown plans
 * @param {Object} [options.planLimits] - Plan-based limits override { free, pro, enterprise }
 * @param {string} [options.message] - Custom error message
 * @param {boolean} [options.skipFailedRequests=false] - Don't count failed requests
 * @param {Function} [options.onLimitReached] - Callback when limit is reached
 * @param {boolean} [options.useXHeaders=true] - Use X-RateLimit-* headers (legacy)
 * @returns {Function} Express middleware
 */
export function createTenantRateLimiter(options = {}) {
  const {
    name = "tenant-api",
    windowMs = 60 * 1000, // 1 minute default
    defaultLimit = 100,
    planLimits = DEFAULT_PLAN_RATE_LIMITS,
    message = "Rate limit exceeded. Please try again later.",
    skipFailedRequests = false,
    onLimitReached = null,
    useXHeaders = true,
  } = options;

  // Setup in-memory fallback store
  const storeKey = `tenant-rl:${name}`;
  if (!memoryStores.has(storeKey)) {
    memoryStores.set(storeKey, new Map());
  }
  const memoryStore = memoryStores.get(storeKey);

  // Periodic cleanup of expired entries in memory store
  const cleanupInterval = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of memoryStore.entries()) {
      if (now - entry.windowStart > windowMs * 2) {
        memoryStore.delete(key);
      }
    }
  }, windowMs);
  cleanupInterval.unref(); // Don't prevent process exit

  // Redis TTL (2x window to allow for clock skew)
  const redisTtlSeconds = Math.ceil((windowMs * 2) / 1000);

  return async function tenantRateLimitMiddleware(req, res, next) {
    try {
      const identifier = getTenantRateLimitKey(req);
      const maxRequests = getTenantRateLimit(req, planLimits, defaultLimit);
      const now = Date.now();

      // If unlimited (-1), skip rate limiting
      if (maxRequests === -1) {
        // Set headers indicating unlimited
        if (useXHeaders) {
          res.setHeader("X-RateLimit-Limit", "unlimited");
          res.setHeader("X-RateLimit-Remaining", "unlimited");
        }
        res.setHeader("RateLimit-Limit", "unlimited");
        res.setHeader("RateLimit-Remaining", "unlimited");
        return next();
      }

      let entry;
      let useRedis = isRedisConnected();

      // Try Redis first if connected
      if (useRedis) {
        entry = await getRedisEntry(name, identifier, windowMs, redisTtlSeconds);
      }

      // Fallback to memory if Redis failed or unavailable
      if (!entry) {
        entry = getMemoryEntry(memoryStore, identifier, now, windowMs);
        useRedis = false;
      }

      // Calculate remaining requests and reset time
      const remaining = Math.max(0, maxRequests - entry.count);
      const resetAt = entry.windowStart + windowMs;
      const resetTimestamp = Math.ceil(resetAt / 1000);
      const retryAfterSeconds = Math.ceil((resetAt - now) / 1000);

      // Set rate limit headers
      // IETF draft standard headers
      res.setHeader("RateLimit-Limit", maxRequests);
      res.setHeader("RateLimit-Remaining", remaining);
      res.setHeader("RateLimit-Reset", resetTimestamp);

      // Legacy X-prefixed headers (widely used)
      if (useXHeaders) {
        res.setHeader("X-RateLimit-Limit", maxRequests);
        res.setHeader("X-RateLimit-Remaining", remaining);
        res.setHeader("X-RateLimit-Reset", resetTimestamp);
      }

      // Check if limit exceeded
      if (entry.count >= maxRequests) {
        res.setHeader("Retry-After", retryAfterSeconds);

        if (onLimitReached) {
          await onLimitReached(req, identifier, {
            limit: maxRequests,
            count: entry.count,
            tenantId: req.tenant?.id || req.tenantId,
            plan: req.subscription?.plan || req.tenant?.subscription?.plan || "unknown",
          });
        }

        const tenantInfo = req.tenant?.id ? ` tenant=${req.tenant.id}` : "";
        console.warn(
          `[rate-limit] ${name}: limit exceeded for ${identifier}${tenantInfo} ` +
            `(${entry.count}/${maxRequests}, ${useRedis ? "redis" : "memory"})`,
        );

        return res.status(429).json({
          error: message,
          code: "RATE_LIMIT_EXCEEDED",
          retryAfter: retryAfterSeconds,
          limit: maxRequests,
          reset: resetTimestamp,
        });
      }

      // Increment counter
      if (useRedis) {
        await incrementRedisEntry(name, identifier, redisTtlSeconds);
      } else {
        entry.count++;
      }

      // If skipFailedRequests is true, decrement on error response
      if (skipFailedRequests) {
        const originalEnd = res.end;
        res.end = function (...args) {
          if (res.statusCode >= 400) {
            if (useRedis) {
              decrementRedisEntry(name, identifier).catch(() => {});
            } else {
              entry.count = Math.max(0, entry.count - 1);
            }
          }
          return originalEnd.apply(this, args);
        };
      }

      next();
    } catch (err) {
      console.error(`[rate-limit] ${name}: error in tenant middleware:`, err);
      // On error, allow the request through (fail open)
      next();
    }
  };
}

/**
 * Pre-configured tenant rate limiter for general API usage
 * Uses plan-based limits: free=100, pro=500, enterprise=2000 requests/minute
 */
export const tenantApiLimiter = createTenantRateLimiter({
  name: "tenant-api",
  windowMs: 60 * 1000, // 1 minute
  defaultLimit: 100,
  planLimits: DEFAULT_PLAN_RATE_LIMITS,
  message: "API rate limit exceeded. Please try again later or upgrade your plan.",
  skipFailedRequests: true,
  onLimitReached: async (req, identifier, info) => {
    console.warn(
      `[security] Tenant API rate limit reached: ${identifier} ` +
        `(plan=${info.plan}, limit=${info.limit})`,
    );
  },
});

/**
 * Stricter tenant rate limiter for sensitive operations
 * Lower limits across all plans
 */
export const tenantSensitiveLimiter = createTenantRateLimiter({
  name: "tenant-sensitive",
  windowMs: 60 * 1000, // 1 minute
  defaultLimit: 20,
  planLimits: {
    free: 20,
    pro: 50,
    enterprise: 100,
  },
  message: "Rate limit exceeded for sensitive operation. Please wait before retrying.",
  skipFailedRequests: false,
  onLimitReached: async (req, identifier, info) => {
    console.warn(
      `[security] Tenant sensitive operation rate limit reached: ${identifier} ` +
        `(plan=${info.plan}, limit=${info.limit})`,
    );
  },
});

/**
 * Reset tenant rate limit (for admin use)
 * @param {string} limiterName - Name of the limiter
 * @param {string} tenantId - Tenant ID to reset
 * @returns {boolean} True if reset was successful
 */
export async function resetTenantRateLimit(limiterName, tenantId) {
  const key = `tenant:${tenantId}`;

  // Reset in memory
  const memoryResult = resetRateLimit(limiterName, key);

  // Reset in Redis if connected
  if (isRedisConnected()) {
    const redis = getRedisClient();
    if (redis) {
      try {
        const redisKey = buildRedisKey(limiterName, key);
        await redis.del(redisKey);
      } catch (err) {
        console.error(`[rate-limit] Redis reset error for ${key}:`, err.message);
      }
    }
  }

  return memoryResult;
}

/**
 * Get tenant rate limit status
 * @param {string} limiterName - Name of the limiter
 * @param {string} tenantId - Tenant ID to check
 * @returns {object|null} Status object or null if not found
 */
export async function getTenantRateLimitStatus(limiterName, tenantId) {
  const key = `tenant:${tenantId}`;

  // Try Redis first if connected
  if (isRedisConnected()) {
    const redis = getRedisClient();
    if (redis) {
      try {
        const redisKey = buildRedisKey(limiterName, key);
        const data = await redis.get(redisKey);
        if (data) {
          return JSON.parse(data);
        }
      } catch (err) {
        console.error(`[rate-limit] Redis status error for ${key}:`, err.message);
      }
    }
  }

  // Fallback to memory
  return getRateLimitStatus(limiterName, key);
}

export default {
  createRateLimiter,
  getClientIp,
  strictAuthLimiter,
  vaultUnlockLimiter,
  recoveryLimiter,
  tokenIssuanceLimiter,
  generalApiLimiter,
  loginLimiter,
  inviteLimiter,
  relayMessageLimiter,
  // New invite/share limiters
  inviteAcceptLimiter,
  inviteDeclineLimiter,
  inviteCreateLimiter,
  shareCreateLimiter,
  shareDeleteLimiter,
  // Tenant-scoped rate limiting
  createTenantRateLimiter,
  tenantApiLimiter,
  tenantSensitiveLimiter,
  getTenantRateLimitKey,
  getTenantRateLimit,
  DEFAULT_PLAN_RATE_LIMITS,
  resetTenantRateLimit,
  getTenantRateLimitStatus,
  // Utilities
  getRateLimitStatus,
  resetRateLimit,
  getAllRateLimitEntries,
};
