// Wake-on-request service
// Automatically wakes hibernated containers when their resources are accessed
import axios from 'axios';
import { AGENT_SERVER_URL, AGENT_SERVER_TOKEN } from './context.js';

// Wake request configuration
const WAKE_TIMEOUT_MS = 30000; // 30 seconds max wait
const QUICK_CHECK_TIMEOUT_MS = 2000; // 2 seconds for quick status check

// Metrics
const metrics = {
  wakeRequests: 0,
  alreadyRunning: 0,
  successfulWakes: 0,
  failedWakes: 0,
  timeouts: 0,
  totalLatencyMs: 0,
};

/**
 * Quick check if a container is running
 * Uses the fast cached status endpoint
 */
export async function isContainerRunning(userId) {
  try {
    const response = await axios.get(
      `${AGENT_SERVER_URL}/api/containers/${userId}/status/quick`,
      {
        headers: { 'x-auth-token': AGENT_SERVER_TOKEN },
        timeout: QUICK_CHECK_TIMEOUT_MS,
      }
    );
    return response.data.ready === true;
  } catch (err) {
    if (err.response?.status === 404) {
      return false; // Container doesn't exist
    }
    console.warn(`[wake-on-request] Quick check failed for ${userId.slice(0, 8)}:`, err.message);
    return false;
  }
}

/**
 * Wake a container if hibernated
 * Returns wake result with status and timing
 */
export async function wakeContainerIfNeeded(userId, reason = 'on-request') {
  const startTime = Date.now();
  metrics.wakeRequests++;

  // Quick check first
  const isRunning = await isContainerRunning(userId);
  if (isRunning) {
    metrics.alreadyRunning++;
    return {
      success: true,
      status: 'already-running',
      wakeTime: 0,
    };
  }

  console.log(`[wake-on-request] Waking container for ${userId.slice(0, 8)}... (reason: ${reason})`);

  try {
    const response = await axios.post(
      `${AGENT_SERVER_URL}/api/containers/${userId}/wake`,
      { reason, timeout: WAKE_TIMEOUT_MS },
      {
        headers: { 'x-auth-token': AGENT_SERVER_TOKEN },
        timeout: WAKE_TIMEOUT_MS + 5000, // Add buffer for network
      }
    );

    const wakeTime = Date.now() - startTime;
    metrics.successfulWakes++;
    metrics.totalLatencyMs += wakeTime;

    console.log(`[wake-on-request] Container ${userId.slice(0, 8)} awoke in ${wakeTime}ms`);

    return {
      success: true,
      status: response.data.status,
      wakeTime,
      queued: response.data.queued,
    };

  } catch (err) {
    const wakeTime = Date.now() - startTime;

    if (err.code === 'ECONNABORTED' || err.response?.status === 504) {
      metrics.timeouts++;
      console.error(`[wake-on-request] Timeout waking container ${userId.slice(0, 8)} after ${wakeTime}ms`);
      return {
        success: false,
        status: 'timeout',
        wakeTime,
        error: 'Container took too long to wake',
      };
    }

    metrics.failedWakes++;
    console.error(`[wake-on-request] Failed to wake container ${userId.slice(0, 8)}:`, err.message);

    return {
      success: false,
      status: 'failed',
      wakeTime,
      error: err.response?.data?.error || err.message,
    };
  }
}

/**
 * Wake multiple containers in parallel
 * Useful for operations that need multiple peer containers
 */
export async function wakeContainers(userIds, reason = 'on-request') {
  const results = await Promise.allSettled(
    userIds.map(userId => wakeContainerIfNeeded(userId, reason))
  );

  return userIds.map((userId, idx) => {
    const result = results[idx];
    if (result.status === 'fulfilled') {
      return { userId, ...result.value };
    }
    return {
      userId,
      success: false,
      status: 'error',
      error: result.reason?.message || 'Unknown error',
    };
  });
}

/**
 * Get wake-on-request metrics
 */
export function getWakeOnRequestMetrics() {
  const avgLatency = metrics.successfulWakes > 0
    ? Math.round(metrics.totalLatencyMs / metrics.successfulWakes)
    : 0;

  return {
    totalRequests: metrics.wakeRequests,
    alreadyRunning: metrics.alreadyRunning,
    successfulWakes: metrics.successfulWakes,
    failedWakes: metrics.failedWakes,
    timeouts: metrics.timeouts,
    avgWakeLatencyMs: avgLatency,
  };
}

/**
 * Express middleware factory for wake-on-request
 * Wakes the target container before proceeding with the request
 */
export function createWakeMiddleware(getTargetUserId) {
  return async (req, res, next) => {
    try {
      const targetUserId = await getTargetUserId(req);
      if (!targetUserId) {
        return next(); // No target, skip wake
      }

      const result = await wakeContainerIfNeeded(targetUserId, 'on-request');

      if (!result.success) {
        // Store error info for downstream handlers
        req.wakeError = result;

        if (result.status === 'timeout') {
          return res.status(503).json({
            error: 'Target container unavailable',
            message: 'The target user\'s container is hibernated and taking too long to wake',
            wakeStatus: 'timeout',
          });
        }

        // For other failures, let the request proceed but with error info
      }

      // Store wake info for downstream use
      req.wakeResult = result;
      next();

    } catch (err) {
      console.error('[wake-middleware] Error:', err);
      next(); // Continue anyway, let the actual endpoint handle errors
    }
  };
}
