# Security Plan 02: Redis Rate Limiting Migration

## Overview

Migrate rate limiting from in-memory `Map()` stores to Redis for distributed deployment support, with graceful fallback to in-memory when Redis is unavailable.

## Current State

Three independent rate-limit.js files with in-memory implementations:

| Service           | File                | Limiters   |
| ----------------- | ------------------- | ---------- |
| management-server | `lib/rate-limit.js` | 8 limiters |
| relay-server      | `lib/rate-limit.js` | 3 limiters |
| group-vault       | `lib/rate-limit.js` | 2 limiters |

**Problem**: In-memory stores don't coordinate across multiple instances, and limits reset on server restart.

---

## Implementation Plan

### Phase 1: Redis Client Setup

#### 1.1 Add Dependencies

Add to each service's `package.json`:

```json
{
  "dependencies": {
    "ioredis": "^5.4.1"
  }
}
```

#### 1.2 Create Redis Client Module

Create `management-server/lib/redis.js`:

```javascript
// Redis client with connection management
import Redis from "ioredis";

let redisClient = null;
let isConnected = false;

/**
 * Get or create Redis client
 * Returns null if Redis is not configured
 */
export function getRedisClient() {
  if (redisClient) return redisClient;

  const redisUrl = process.env.REDIS_URL;
  if (!redisUrl) {
    console.log("[redis] REDIS_URL not configured, using in-memory fallback");
    return null;
  }

  redisClient = new Redis(redisUrl, {
    maxRetriesPerRequest: 3,
    retryStrategy: (times) => {
      if (times > 10) {
        console.error("[redis] Max retry attempts reached");
        return null;
      }
      return Math.min(times * 100, 3000);
    },
    lazyConnect: true,
    enableReadyCheck: true,
    connectTimeout: 5000,
  });

  redisClient.on("connect", () => {
    console.log("[redis] Connected to Redis");
    isConnected = true;
  });

  redisClient.on("error", (err) => {
    console.error("[redis] Redis error:", err.message);
    isConnected = false;
  });

  redisClient.on("close", () => {
    console.log("[redis] Redis connection closed");
    isConnected = false;
  });

  redisClient.connect().catch((err) => {
    console.warn("[redis] Initial connection failed:", err.message);
  });

  return redisClient;
}

/**
 * Check if Redis is currently connected
 */
export function isRedisConnected() {
  return isConnected && redisClient?.status === "ready";
}

/**
 * Gracefully close Redis connection
 */
export async function closeRedis() {
  if (redisClient) {
    await redisClient.quit();
    redisClient = null;
    isConnected = false;
  }
}

export default { getRedisClient, isRedisConnected, closeRedis };
```

---

### Phase 2: Refactor Rate Limiter

Refactor `management-server/lib/rate-limit.js`:

```javascript
// Rate limiting middleware with Redis support and in-memory fallback
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

  // Setup in-memory fallback
  const storeKey = `${keyPrefix}:${name}`;
  if (!memoryStores.has(storeKey)) {
    memoryStores.set(storeKey, new Map());
  }
  const memoryStore = memoryStores.get(storeKey);

  // Cleanup interval for memory store
  const cleanupInterval = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of memoryStore.entries()) {
      if (now - entry.windowStart > windowMs * 2) {
        memoryStore.delete(key);
      }
    }
  }, windowMs);
  cleanupInterval.unref();

  const redisTtlSeconds = Math.ceil((windowMs * 2) / 1000);

  return async function rateLimitMiddleware(req, res, next) {
    try {
      const identifier = keyGenerator(req);
      const now = Date.now();

      let entry;
      let useRedis = isRedisConnected();

      if (useRedis) {
        entry = await getRedisEntry(name, identifier, windowMs, redisTtlSeconds);
      }

      // Fallback to memory if Redis failed or unavailable
      if (!entry) {
        entry = getMemoryEntry(memoryStore, identifier, now, windowMs);
        useRedis = false;
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

      // Handle skipFailedRequests
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
      next(); // Fail open
    }
  };
}

async function getRedisEntry(limiterName, identifier, windowMs, ttlSeconds) {
  const redis = getRedisClient();
  if (!redis) return null;

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

async function incrementRedisEntry(limiterName, identifier, ttlSeconds) {
  const redis = getRedisClient();
  if (!redis) return;

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

async function decrementRedisEntry(limiterName, identifier) {
  const redis = getRedisClient();
  if (!redis) return;

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

function getMemoryEntry(store, identifier, now, windowMs) {
  let entry = store.get(identifier);

  if (!entry || now - entry.windowStart > windowMs) {
    entry = { count: 0, windowStart: now };
    store.set(identifier, entry);
  }

  return entry;
}

// ... rest of pre-configured limiters unchanged ...
```

---

### Phase 3: Redis Key Naming Strategy

```
Format: ocmt:ratelimit:{service}:{limiter}:{identifier}

Examples:
- ocmt:ratelimit:management:strict-auth:192.168.1.1
- ocmt:ratelimit:management:vault-unlock:user-abc123
- ocmt:ratelimit:relay:message-send:container-xyz
- ocmt:ratelimit:group-vault:vault-unlock:10.0.0.50
```

**Benefits**:

- Namespaced to avoid collisions
- Service-scoped for multi-service deployments
- Easy to monitor with `redis-cli KEYS ocmt:ratelimit:*`

---

### Phase 3.5: Rate Limiting for Groups/Invites/Shares Endpoints

**CRITICAL**: The Groups + Shares refactor added new endpoints that require rate limiting to prevent spam and brute force attacks.

#### New Limiters Required

| Endpoint                              | Limiter Name     | Window | Max Requests | Reason                        |
| ------------------------------------- | ---------------- | ------ | ------------ | ----------------------------- |
| `POST /api/group-invites/:id/accept`  | `invite-accept`  | 15 min | 10           | Prevent spam accept attempts  |
| `POST /api/group-invites/:id/decline` | `invite-decline` | 15 min | 10           | Prevent spam decline attempts |
| `POST /api/groups/:id/invites`        | `invite-send`    | 1 hour | 20           | Prevent invite spam           |
| `POST /api/shares`                    | `share-create`   | 15 min | 30           | Prevent share spam            |
| `DELETE /api/shares/:id`              | `share-delete`   | 15 min | 30           | Prevent mass deletion         |

#### Implementation

**Add to `management-server/routes/group-invites.js`:**

```javascript
import { createRateLimiter } from '../lib/rate-limit.js';

const inviteAcceptLimiter = createRateLimiter({
  name: 'invite-accept',
  windowMs: 15 * 60 * 1000,
  maxRequests: 10,
  keyGenerator: (req) => req.user.id,
  message: 'Too many invite actions. Please wait before trying again.',
});

const inviteDeclineLimiter = createRateLimiter({
  name: 'invite-decline',
  windowMs: 15 * 60 * 1000,
  maxRequests: 10,
  keyGenerator: (req) => req.user.id,
  message: 'Too many invite actions. Please wait before trying again.',
});

const inviteSendLimiter = createRateLimiter({
  name: 'invite-send',
  windowMs: 60 * 60 * 1000, // 1 hour
  maxRequests: 20,
  keyGenerator: (req) => req.user.id,
  message: 'Too many invites sent. Please wait before sending more.',
});

// Apply to routes
router.post('/:id/accept', requireUser, inviteAcceptLimiter, validate({ params: idParamSchema }), async (req, res) => { ... });
router.post('/:id/decline', requireUser, inviteDeclineLimiter, validate({ params: idParamSchema }), async (req, res) => { ... });
```

**Add to `management-server/routes/shares.js`:**

```javascript
import { createRateLimiter } from '../lib/rate-limit.js';

const shareCreateLimiter = createRateLimiter({
  name: 'share-create',
  windowMs: 15 * 60 * 1000,
  maxRequests: 30,
  keyGenerator: (req) => req.user.id,
  message: 'Too many shares created. Please wait before creating more.',
});

const shareDeleteLimiter = createRateLimiter({
  name: 'share-delete',
  windowMs: 15 * 60 * 1000,
  maxRequests: 30,
  keyGenerator: (req) => req.user.id,
});

router.post('/', requireUser, shareCreateLimiter, async (req, res) => { ... });
router.delete('/:id', requireUser, shareDeleteLimiter, async (req, res) => { ... });
```

---

### Phase 4: Docker Configuration

#### 4.1 Development `docker-compose.yml`

```yaml
services:
  redis:
    image: redis:7-alpine
    container_name: ocmt-redis
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    command: redis-server --appendonly yes --maxmemory 100mb --maxmemory-policy volatile-lru
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 3
    deploy:
      resources:
        limits:
          memory: 128M

volumes:
  redis-data:
```

#### 4.2 Production Configuration

```yaml
services:
  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data
    command: >
      redis-server
      --appendonly yes
      --maxmemory 256mb
      --maxmemory-policy volatile-lru
      --requirepass ${REDIS_PASSWORD:-}
    networks:
      - internal

  management-server:
    environment:
      - REDIS_URL=redis://:${REDIS_PASSWORD:-}@redis:6379
      - SERVICE_NAME=management

  relay-server:
    environment:
      - REDIS_URL=redis://:${REDIS_PASSWORD:-}@redis:6379
      - SERVICE_NAME=relay
```

---

### Phase 5: Environment Variables

Add to `.env.example` files:

```bash
# Redis (optional - falls back to in-memory if not set)
REDIS_URL=redis://localhost:6379

# Service name for rate limit key namespacing
SERVICE_NAME=management
```

---

### Phase 6: Graceful Fallback Logic

```
Fallback decision tree:
1. REDIS_URL configured?
   - No → use in-memory only
2. Redis client connected?
   - No → use in-memory fallback
3. Redis operation succeeds?
   - Yes → use Redis result
   - No → log warning, use in-memory fallback
4. On any error → fail open (allow request)
```

---

### Phase 7: Migration Strategy (Zero Downtime)

1. **Deploy Redis** (ahead of time):

   ```bash
   docker-compose up -d redis
   ```

2. **Deploy updated services without REDIS_URL**:
   - Services continue using in-memory
   - New code deployed but not using Redis yet

3. **Enable Redis incrementally**:

   ```bash
   # Start with management-server
   REDIS_URL=redis://localhost:6379 docker-compose up -d management-server

   # Monitor logs
   docker-compose logs -f management-server | grep redis
   ```

4. **Enable for remaining services**

5. **Verify**:
   ```bash
   redis-cli KEYS "ocmt:ratelimit:*"
   ```

**Rollback**: Remove `REDIS_URL` and restart services.

---

### Phase 8: Health Check Update

Update `management-server/server.js`:

```javascript
import { isRedisConnected } from "./lib/redis.js";

app.get("/health", (req, res) => {
  const relayStatus = getRelayStatus();
  res.json({
    status: "ok",
    relay: {
      healthy: relayStatus.healthy,
      url: relayStatus.url,
    },
    redis: {
      connected: isRedisConnected(),
      fallbackActive: !isRedisConnected(),
    },
  });
});
```

---

### Phase 9: Testing

#### Unit Tests

```javascript
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createRateLimiter } from "./rate-limit.js";

vi.mock("./redis.js", () => ({
  getRedisClient: vi.fn(),
  isRedisConnected: vi.fn(),
}));

import { getRedisClient, isRedisConnected } from "./redis.js";

describe("rate-limit with Redis", () => {
  let mockRedis;

  beforeEach(() => {
    mockRedis = {
      get: vi.fn(),
      set: vi.fn(),
    };
  });

  it("should use Redis when connected", async () => {
    isRedisConnected.mockReturnValue(true);
    getRedisClient.mockReturnValue(mockRedis);
    mockRedis.get.mockResolvedValue(null);
    mockRedis.set.mockResolvedValue("OK");

    const limiter = createRateLimiter({
      name: "test-redis",
      windowMs: 60000,
      maxRequests: 5,
    });

    const mockReq = { headers: {}, ip: "1.2.3.4" };
    const mockRes = { setHeader: vi.fn() };
    const mockNext = vi.fn();

    await limiter(mockReq, mockRes, mockNext);

    expect(mockRedis.get).toHaveBeenCalled();
    expect(mockNext).toHaveBeenCalled();
  });

  it("should fall back to memory when Redis unavailable", async () => {
    isRedisConnected.mockReturnValue(false);

    const limiter = createRateLimiter({
      name: "test-fallback",
      windowMs: 60000,
      maxRequests: 5,
    });

    const mockReq = { headers: {}, ip: "1.2.3.4" };
    const mockRes = { setHeader: vi.fn() };
    const mockNext = vi.fn();

    await limiter(mockReq, mockRes, mockNext);

    expect(mockNext).toHaveBeenCalled();
  });
});
```

#### Integration Test Script

```bash
#!/bin/bash
# scripts/test-redis-ratelimit.sh
set -e

docker run -d --name test-redis -p 6379:6379 redis:7-alpine
trap "docker stop test-redis && docker rm test-redis" EXIT

sleep 2

REDIS_URL=redis://localhost:6379 pnpm test -- rate-limit

echo "Redis keys created:"
docker exec test-redis redis-cli KEYS "ocmt:ratelimit:*"
```

---

## Files to Modify

| File                                       | Changes             |
| ------------------------------------------ | ------------------- |
| `management-server/package.json`           | Add ioredis         |
| `management-server/lib/rate-limit.js`      | Add Redis support   |
| `management-server/lib/rate-limit.test.js` | Add Redis tests     |
| `management-server/server.js`              | Update health check |
| `management-server/.env.example`           | Add REDIS_URL       |
| `relay-server/lib/rate-limit.js`           | Add Redis support   |
| `relay-server/package.json`                | Add ioredis         |
| `group-vault/lib/rate-limit.js`            | Add Redis support   |
| `docker-compose.yml`                       | Add Redis service   |

## Files to Create

| File                              | Purpose                 |
| --------------------------------- | ----------------------- |
| `management-server/lib/redis.js`  | Redis client module     |
| `relay-server/lib/redis.js`       | Redis client module     |
| `group-vault/lib/redis.js`        | Redis client module     |
| `scripts/test-redis-ratelimit.sh` | Integration test script |

---

## Open Questions

1. Should we create a shared `@ocmt/rate-limit` package?
2. Should Redis be required for production?
3. Should we implement sliding window instead of fixed window?

---

## Priority

**High** - Critical for production multi-instance deployments.

## Estimated Effort

- Phase 1-2: 3-4 hours
- Phase 3-5: 2 hours
- Phase 6-7: 2 hours
- Phase 8-9: 2-3 hours

**Total: ~1-1.5 days**
