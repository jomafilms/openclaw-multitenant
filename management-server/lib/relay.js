/**
 * Relay Service Client
 *
 * Connects management server to the relay for:
 * - Health checks
 * - Revocation status queries
 * - Snapshot management
 */
import axios from 'axios';

const RELAY_URL = process.env.RELAY_URL || 'http://localhost:5000';
const RELAY_TIMEOUT = parseInt(process.env.RELAY_TIMEOUT || '5000', 10);

let relayHealthy = false;
let lastHealthCheck = 0;
const HEALTH_CHECK_INTERVAL = 30000; // 30 seconds

/**
 * Get the relay service URL
 */
export function getRelayUrl() {
  return RELAY_URL;
}

/**
 * Check relay health
 */
export async function checkRelayHealth() {
  try {
    const response = await axios.get(`${RELAY_URL}/health`, {
      timeout: RELAY_TIMEOUT
    });

    relayHealthy = response.data?.status === 'ok';
    lastHealthCheck = Date.now();

    return {
      healthy: relayHealthy,
      service: response.data?.service,
      connections: response.data?.connections ?? 0,
      revocations: response.data?.revocations ?? 0,
      snapshots: response.data?.snapshots ?? 0
    };
  } catch (err) {
    relayHealthy = false;
    lastHealthCheck = Date.now();

    return {
      healthy: false,
      error: err.message,
      connections: 0,
      revocations: 0,
      snapshots: 0
    };
  }
}

/**
 * Get cached relay health status
 */
export function getRelayStatus() {
  return {
    healthy: relayHealthy,
    lastCheck: lastHealthCheck,
    url: RELAY_URL
  };
}

/**
 * Check if a capability is revoked at the relay
 */
export async function checkRevocation(capabilityId) {
  try {
    const response = await axios.get(
      `${RELAY_URL}/relay/revocation/${encodeURIComponent(capabilityId)}`,
      { timeout: RELAY_TIMEOUT }
    );

    return {
      success: true,
      ...response.data
    };
  } catch (err) {
    return {
      success: false,
      error: err.message,
      revoked: false
    };
  }
}

/**
 * Batch check revocations
 */
export async function checkRevocations(capabilityIds) {
  try {
    const response = await axios.post(
      `${RELAY_URL}/relay/check-revocations`,
      { capabilityIds },
      { timeout: RELAY_TIMEOUT }
    );

    return {
      success: true,
      results: response.data?.results ?? {}
    };
  } catch (err) {
    return {
      success: false,
      error: err.message,
      results: {}
    };
  }
}

/**
 * Get revocation statistics
 */
export async function getRevocationStats() {
  try {
    const response = await axios.get(
      `${RELAY_URL}/relay/revocation-stats`,
      { timeout: RELAY_TIMEOUT }
    );

    return {
      success: true,
      ...response.data
    };
  } catch (err) {
    return {
      success: false,
      error: err.message,
      totalRevocations: 0,
      totalSnapshots: 0
    };
  }
}

/**
 * Fetch a cached snapshot from the relay
 */
export async function getSnapshot(capabilityId) {
  try {
    const response = await axios.get(
      `${RELAY_URL}/relay/snapshots/${encodeURIComponent(capabilityId)}`,
      { timeout: RELAY_TIMEOUT }
    );

    return {
      success: true,
      snapshot: response.data
    };
  } catch (err) {
    if (err.response?.status === 404) {
      return {
        success: false,
        error: 'Snapshot not found'
      };
    }
    return {
      success: false,
      error: err.message
    };
  }
}

// Start periodic health checks
setInterval(async () => {
  await checkRelayHealth();
}, HEALTH_CHECK_INTERVAL);

// Initial health check
checkRelayHealth().catch(() => {
  console.warn('[relay] Initial health check failed');
});

/**
 * Get snapshot statistics
 */
export async function getSnapshotStats() {
  try {
    const response = await axios.get(
      `${RELAY_URL}/relay/revocation-stats`,
      { timeout: RELAY_TIMEOUT }
    );

    return {
      success: true,
      totalSnapshots: response.data?.totalSnapshots ?? 0
    };
  } catch (err) {
    return {
      success: false,
      error: err.message,
      totalSnapshots: 0
    };
  }
}

/**
 * Trigger snapshot refresh on a container via the agent server
 */
export async function triggerSnapshotRefresh(userId) {
  const AGENT_SERVER_URL = process.env.AGENT_SERVER_URL || 'http://localhost:3001';
  const AGENT_SERVER_TOKEN = process.env.AGENT_SERVER_TOKEN;

  try {
    const response = await axios.post(
      `${AGENT_SERVER_URL}/api/containers/${userId}/snapshots/sync`,
      {},
      {
        headers: { 'x-auth-token': AGENT_SERVER_TOKEN },
        timeout: 30000
      }
    );

    return {
      success: true,
      ...response.data
    };
  } catch (err) {
    return {
      success: false,
      error: err.response?.data?.error || err.message
    };
  }
}

export default {
  getRelayUrl,
  checkRelayHealth,
  getRelayStatus,
  checkRevocation,
  checkRevocations,
  getRevocationStats,
  getSnapshot,
  getSnapshotStats,
  triggerSnapshotRefresh
};
