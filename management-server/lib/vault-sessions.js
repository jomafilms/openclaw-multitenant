// Vault session store - uses Redis when available, falls back to in-memory
import crypto from "crypto";
import { getRedisClient, isRedisConnected } from "./redis.js";

export const VAULT_SESSION_TIMEOUT_MS = 60 * 60 * 1000; // 1 hour
export const VAULT_SESSION_TIMEOUT_SEC = 60 * 60;

// In-memory fallback when Redis is unavailable
const memoryStore = new Map();

// Redis key prefix for vault sessions
const REDIS_PREFIX = "vault:session:";

// Clean up expired sessions from memory store periodically
setInterval(() => {
  const now = Date.now();
  for (const [token, session] of memoryStore) {
    if (session.expiresAt < now) {
      memoryStore.delete(token);
    }
  }
}, 60000);

/**
 * Create a vault session after unlock
 * Uses Redis if available, otherwise in-memory
 */
export async function createVaultSession(userId, vaultKey) {
  const token = crypto.randomBytes(32).toString("hex");
  const session = {
    userId,
    vaultKey,
    expiresAt: Date.now() + VAULT_SESSION_TIMEOUT_MS,
    createdAt: Date.now(),
  };

  const redis = getRedisClient();
  if (redis && isRedisConnected()) {
    try {
      await redis.setex(REDIS_PREFIX + token, VAULT_SESSION_TIMEOUT_SEC, JSON.stringify(session));
      return token;
    } catch (err) {
      console.warn("[vault-sessions] Redis write failed, using memory:", err.message);
    }
  }

  // Fallback to memory
  memoryStore.set(token, session);
  return token;
}

/**
 * Get vault session by token
 * Checks Redis first, then memory fallback
 */
export async function getVaultSession(token) {
  if (!token) {
    return null;
  }

  const redis = getRedisClient();
  if (redis && isRedisConnected()) {
    try {
      const data = await redis.get(REDIS_PREFIX + token);
      if (data) {
        const session = JSON.parse(data);
        if (session.expiresAt > Date.now()) {
          return session;
        }
        // Expired - clean up
        await redis.del(REDIS_PREFIX + token);
        return null;
      }
    } catch (err) {
      console.warn("[vault-sessions] Redis read failed, checking memory:", err.message);
    }
  }

  // Fallback to memory
  const session = memoryStore.get(token);
  if (!session) {
    return null;
  }
  if (session.expiresAt < Date.now()) {
    memoryStore.delete(token);
    return null;
  }
  return session;
}

/**
 * Extend vault session
 */
export async function extendVaultSession(token) {
  if (!token) {
    return false;
  }

  const redis = getRedisClient();
  if (redis && isRedisConnected()) {
    try {
      const data = await redis.get(REDIS_PREFIX + token);
      if (data) {
        const session = JSON.parse(data);
        if (session.expiresAt > Date.now()) {
          session.expiresAt = Date.now() + VAULT_SESSION_TIMEOUT_MS;
          await redis.setex(
            REDIS_PREFIX + token,
            VAULT_SESSION_TIMEOUT_SEC,
            JSON.stringify(session),
          );
          return true;
        }
      }
      return false;
    } catch (err) {
      console.warn("[vault-sessions] Redis extend failed, trying memory:", err.message);
    }
  }

  // Fallback to memory
  const session = memoryStore.get(token);
  if (session && session.expiresAt > Date.now()) {
    session.expiresAt = Date.now() + VAULT_SESSION_TIMEOUT_MS;
    return true;
  }
  return false;
}

/**
 * Delete vault session (lock)
 */
export async function deleteVaultSession(token) {
  if (!token) {
    return;
  }

  const redis = getRedisClient();
  if (redis && isRedisConnected()) {
    try {
      await redis.del(REDIS_PREFIX + token);
    } catch (err) {
      console.warn("[vault-sessions] Redis delete failed:", err.message);
    }
  }

  // Always clean from memory too
  memoryStore.delete(token);
}

/**
 * Legacy sync interface for compatibility
 * @deprecated Use async versions instead
 */
export const vaultSessions = {
  get(token) {
    // Sync fallback - only checks memory
    const session = memoryStore.get(token);
    if (!session) {
      return undefined;
    }
    if (session.expiresAt < Date.now()) {
      memoryStore.delete(token);
      return undefined;
    }
    return session;
  },
  set(token, session) {
    memoryStore.set(token, session);
    // Also try to write to Redis async (fire and forget)
    const redis = getRedisClient();
    if (redis && isRedisConnected()) {
      redis
        .setex(REDIS_PREFIX + token, VAULT_SESSION_TIMEOUT_SEC, JSON.stringify(session))
        .catch(() => {});
    }
  },
  has(token) {
    return memoryStore.has(token);
  },
  delete(token) {
    memoryStore.delete(token);
    const redis = getRedisClient();
    if (redis && isRedisConnected()) {
      redis.del(REDIS_PREFIX + token).catch(() => {});
    }
  },
};
