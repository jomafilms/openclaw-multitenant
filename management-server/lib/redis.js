// Redis client with connection management for distributed rate limiting
// Provides graceful fallback to in-memory when Redis is unavailable
import Redis from "ioredis";

let redisClient = null;
let isConnected = false;

/**
 * Get or create Redis client
 * Returns null if Redis is not configured (REDIS_URL not set)
 * @returns {Redis|null} Redis client instance or null
 */
export function getRedisClient() {
  if (redisClient) return redisClient;

  const redisUrl = process.env.REDIS_URL;
  if (!redisUrl) {
    console.log("[redis] REDIS_URL not configured, using in-memory fallback");
    return null;
  }

  redisClient = new Redis(redisUrl, {
    // Connection pool settings
    maxRetriesPerRequest: 3,

    // Reconnection strategy with exponential backoff
    retryStrategy: (times) => {
      if (times > 10) {
        console.error("[redis] Max retry attempts reached, giving up");
        return null; // Stop retrying
      }
      // Exponential backoff: 100ms, 200ms, 300ms... up to 3s
      const delay = Math.min(times * 100, 3000);
      console.log(`[redis] Retrying connection in ${delay}ms (attempt ${times})`);
      return delay;
    },

    // Don't connect immediately - wait for first use
    lazyConnect: true,

    // Verify connection is ready before use
    enableReadyCheck: true,

    // Connection timeout
    connectTimeout: 5000,

    // Keep connection alive
    keepAlive: 10000,
  });

  // Connection event handlers
  redisClient.on("connect", () => {
    console.log("[redis] Connected to Redis");
    isConnected = true;
  });

  redisClient.on("ready", () => {
    console.log("[redis] Redis client ready");
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

  redisClient.on("reconnecting", () => {
    console.log("[redis] Reconnecting to Redis...");
  });

  redisClient.on("end", () => {
    console.log("[redis] Redis connection ended");
    isConnected = false;
  });

  // Attempt initial connection
  redisClient.connect().catch((err) => {
    console.warn("[redis] Initial connection failed:", err.message);
    // Don't throw - allow fallback to in-memory
  });

  return redisClient;
}

/**
 * Check if Redis is currently connected and ready
 * @returns {boolean} True if Redis is connected and ready
 */
export function isRedisConnected() {
  return isConnected && redisClient?.status === "ready";
}

/**
 * Gracefully close Redis connection
 * Call this during server shutdown for clean cleanup
 */
export async function closeRedis() {
  if (redisClient) {
    try {
      await redisClient.quit();
      console.log("[redis] Redis connection closed gracefully");
    } catch (err) {
      console.warn("[redis] Error closing Redis connection:", err.message);
      // Force disconnect if quit fails
      redisClient.disconnect();
    }
    redisClient = null;
    isConnected = false;
  }
}

/**
 * Get Redis connection status for health checks
 * @returns {Object} Connection status info
 */
export function getRedisStatus() {
  return {
    connected: isRedisConnected(),
    status: redisClient?.status || "not-initialized",
    fallbackActive: !isRedisConnected(),
  };
}

export default {
  getRedisClient,
  isRedisConnected,
  closeRedis,
  getRedisStatus,
};
