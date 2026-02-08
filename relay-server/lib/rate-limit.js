// Rate limiting middleware with Redis support and in-memory fallback
// Uses Redis for distributed deployments, falls back to in-memory when unavailable
import { getRedisClient, isRedisConnected } from "./redis.js";

// In-memory fallback stores
const memoryStores = new Map();

// Service identifier for Redis key namespacing
const SERVICE_NAME = process.env.SERVICE_NAME || "relay";

/**
 * Redis key format:
 * ocmt:ratelimit:{service}:{limiterName}:{identifier}
 */
function buildRedisKey(limiterName, identifier) {
  return `ocmt:ratelimit:${SERVICE_NAME}:${limiterName}:${identifier}`;
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
export async function resetRateLimit(limiterName, key) {
  const storeKey = `rl:${limiterName}`;
  const store = memoryStores.get(storeKey);

  // Reset in memory
  const memoryResult = store ? store.delete(key) : false;

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

// General API limiter: 1000 requests per hour per IP
export const generalApiLimiter = createRateLimiter({
  name: "general-api",
  windowMs: 60 * 60 * 1000,
  maxRequests: 1000,
  message: "API rate limit exceeded. Please slow down.",
  skipFailedRequests: true,
});

// Message send limiter: 100 messages per minute per container
// This is applied in addition to the database-backed rate limit
export const messageSendLimiter = createRateLimiter({
  name: "message-send",
  windowMs: 60 * 1000,
  maxRequests: 100,
  keyGenerator: (req) => req.container?.userId || getClientIp(req),
  message: "Message rate limit exceeded. Please slow down.",
});

// Revocation check limiter: 500 requests per minute per IP
// (used for checking if tokens are revoked)
export const revocationCheckLimiter = createRateLimiter({
  name: "revocation-check",
  windowMs: 60 * 1000,
  maxRequests: 500,
  message: "Too many revocation checks. Please slow down.",
});

export default {
  createRateLimiter,
  getClientIp,
  generalApiLimiter,
  messageSendLimiter,
  revocationCheckLimiter,
  getRateLimitStatus,
  resetRateLimit,
  getAllRateLimitEntries,
};
