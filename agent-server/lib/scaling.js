// Container auto-scaling module
// Handles resource limits by plan, hibernation decisions, and scaling daemon

import { containers, docker, pauseContainer, stopContainer, ensureAwake } from "./containers.js";

// ============================================================
// PLAN-BASED RESOURCE LIMITS
// ============================================================

const RESOURCE_LIMITS = {
  free: {
    memory: 512 * 1024 * 1024, // 512MB
    memorySwap: 768 * 1024 * 1024, // 768MB (memory + swap)
    cpuShares: 256, // 0.25 CPU (relative weight)
    cpuQuota: 50000, // 0.5 CPU (50% of 100000 period)
    cpuPeriod: 100000, // Standard period
    pidsLimit: 100, // Process limit
  },
  pro: {
    memory: 2 * 1024 * 1024 * 1024, // 2GB
    memorySwap: 3 * 1024 * 1024 * 1024, // 3GB
    cpuShares: 1024, // 1 CPU (relative weight)
    cpuQuota: 200000, // 2 CPU
    cpuPeriod: 100000,
    pidsLimit: 500,
  },
  enterprise: {
    memory: 4 * 1024 * 1024 * 1024, // 4GB
    memorySwap: 6 * 1024 * 1024 * 1024, // 6GB
    cpuShares: 2048, // 2 CPU (relative weight)
    cpuQuota: 400000, // 4 CPU
    cpuPeriod: 100000,
    pidsLimit: 1000,
  },
};

// Hibernation thresholds
const HIBERNATION_CONFIG = {
  pauseAfterMs: 30 * 60 * 1000, // 30 minutes idle -> pause
  stopAfterMs: 4 * 60 * 60 * 1000, // 4 hours total -> stop
  checkIntervalMs: 60 * 1000, // Check every minute
};

// Pre-warmed container pool configuration
const POOL_CONFIG = {
  enabled: false, // Disabled by default
  targetSize: 2, // Target number of pre-warmed containers
  maxSize: 5, // Maximum pool size
  warmPlan: "free", // Plan for pre-warmed containers
  idleTimeoutMs: 10 * 60 * 1000, // Remove from pool after 10 min unused
};

// ============================================================
// METRICS TRACKING
// ============================================================

const scalingMetrics = {
  // Container lifecycle
  totalHibernations: 0,
  totalWakes: 0,
  pauseCount: 0,
  stopCount: 0,

  // Resource adjustments
  resourceAdjustments: 0,
  adjustmentsByPlan: new Map(),

  // Cost tracking (per tenant, per hour)
  containerRuntime: new Map(), // userId -> { startTime, totalRuntimeMs, plan }

  // Pool metrics
  poolHits: 0,
  poolMisses: 0,

  // Timestamps
  lastCheck: null,
  startTime: Date.now(),
};

// ============================================================
// RESOURCE MANAGEMENT
// ============================================================

/**
 * Get resource limits for a given plan
 * @param {string} plan - Plan name: 'free', 'pro', or 'enterprise'
 * @returns {object} Resource limits configuration
 */
export function getContainerResources(plan) {
  const limits = RESOURCE_LIMITS[plan] || RESOURCE_LIMITS.free;
  return {
    plan,
    memory: limits.memory,
    memorySwap: limits.memorySwap,
    memoryMB: Math.round(limits.memory / (1024 * 1024)),
    cpuShares: limits.cpuShares,
    cpuQuota: limits.cpuQuota,
    cpuPeriod: limits.cpuPeriod,
    cpuCores: limits.cpuQuota / limits.cpuPeriod,
    pidsLimit: limits.pidsLimit,
  };
}

/**
 * Adjust container resources based on plan
 * Updates memory, CPU, and process limits for an existing container
 * @param {string} containerId - Docker container ID
 * @param {string} plan - Plan name
 * @returns {Promise<object>} Result of the adjustment
 */
export async function adjustContainerResources(containerId, plan) {
  const limits = RESOURCE_LIMITS[plan] || RESOURCE_LIMITS.free;

  try {
    const container = docker.getContainer(containerId);
    const inspection = await container.inspect();

    // Check if container is running (can only update running containers)
    if (!inspection.State.Running) {
      return {
        success: false,
        error: "Container must be running to adjust resources",
        containerId,
        plan,
      };
    }

    // Update container resources
    await container.update({
      Memory: limits.memory,
      MemorySwap: limits.memorySwap,
      CpuShares: limits.cpuShares,
      CpuQuota: limits.cpuQuota,
      CpuPeriod: limits.cpuPeriod,
      PidsLimit: limits.pidsLimit,
    });

    // Update metrics
    scalingMetrics.resourceAdjustments++;
    const planCount = scalingMetrics.adjustmentsByPlan.get(plan) || 0;
    scalingMetrics.adjustmentsByPlan.set(plan, planCount + 1);

    console.log(
      `[scaling] Adjusted ${containerId.slice(0, 12)} to ${plan} plan:`,
      `${Math.round(limits.memory / 1024 / 1024)}MB RAM,`,
      `${limits.cpuQuota / limits.cpuPeriod} CPU`,
    );

    return {
      success: true,
      containerId,
      plan,
      resources: getContainerResources(plan),
    };
  } catch (error) {
    console.error(`[scaling] Failed to adjust resources:`, error.message);
    return {
      success: false,
      error: error.message,
      containerId,
      plan,
    };
  }
}

/**
 * Get current resource usage for a container
 * @param {string} containerId - Docker container ID
 * @returns {Promise<object>} Current resource usage stats
 */
export async function getContainerStats(containerId) {
  try {
    const container = docker.getContainer(containerId);
    const stats = await container.stats({ stream: false });

    // Calculate CPU usage percentage
    const cpuDelta =
      stats.cpu_stats.cpu_usage.total_usage - (stats.precpu_stats.cpu_usage?.total_usage || 0);
    const systemDelta =
      stats.cpu_stats.system_cpu_usage - (stats.precpu_stats.system_cpu_usage || 0);
    const numCpus = stats.cpu_stats.online_cpus || 1;
    const cpuPercent = systemDelta > 0 ? (cpuDelta / systemDelta) * numCpus * 100 : 0;

    // Memory usage
    const memoryUsage = stats.memory_stats.usage || 0;
    const memoryLimit = stats.memory_stats.limit || 1;
    const memoryPercent = (memoryUsage / memoryLimit) * 100;

    return {
      containerId,
      cpu: {
        percent: Math.round(cpuPercent * 100) / 100,
        throttled: stats.cpu_stats.throttling_data?.throttled_time || 0,
      },
      memory: {
        used: memoryUsage,
        limit: memoryLimit,
        percent: Math.round(memoryPercent * 100) / 100,
        usedMB: Math.round(memoryUsage / (1024 * 1024)),
        limitMB: Math.round(memoryLimit / (1024 * 1024)),
      },
      network: {
        rxBytes: stats.networks?.eth0?.rx_bytes || 0,
        txBytes: stats.networks?.eth0?.tx_bytes || 0,
      },
      pids: stats.pids_stats?.current || 0,
      timestamp: new Date().toISOString(),
    };
  } catch (error) {
    return {
      containerId,
      error: error.message,
      timestamp: new Date().toISOString(),
    };
  }
}

// ============================================================
// HIBERNATION DECISIONS
// ============================================================

/**
 * Check if a container should be hibernated (paused or stopped)
 * @param {string} userId - User ID associated with container
 * @returns {object} Hibernation decision
 */
export function shouldHibernate(userId) {
  const info = containers.get(userId);
  if (!info) {
    return { shouldHibernate: false, reason: "not_found" };
  }

  const now = Date.now();
  const idleTime = now - (info.lastActivity || now);
  const pausedTime = info.pausedAt ? now - info.pausedAt : 0;

  // Already stopped - no action needed
  if (info.hibernationState === "stopped") {
    return { shouldHibernate: false, reason: "already_stopped" };
  }

  // If paused, check if should be stopped
  if (info.hibernationState === "paused") {
    const totalIdleTime = idleTime + pausedTime;
    if (totalIdleTime > HIBERNATION_CONFIG.stopAfterMs) {
      return {
        shouldHibernate: true,
        action: "stop",
        reason: "paused_too_long",
        idleMs: totalIdleTime,
        thresholdMs: HIBERNATION_CONFIG.stopAfterMs,
      };
    }
    return { shouldHibernate: false, reason: "waiting_in_paused_state" };
  }

  // If running, check if should be paused
  if (info.hibernationState === "running") {
    if (idleTime > HIBERNATION_CONFIG.pauseAfterMs) {
      return {
        shouldHibernate: true,
        action: "pause",
        reason: "idle_too_long",
        idleMs: idleTime,
        thresholdMs: HIBERNATION_CONFIG.pauseAfterMs,
      };
    }
  }

  return {
    shouldHibernate: false,
    reason: "active",
    idleMs: idleTime,
  };
}

/**
 * Hibernate a container (pause it to preserve memory, instant wake)
 * @param {string} userId - User ID associated with container
 * @returns {Promise<object>} Result of hibernation
 */
export async function hibernateContainer(userId) {
  const info = containers.get(userId);
  if (!info) {
    return { success: false, error: "Container not found" };
  }

  try {
    const success = await pauseContainer(userId);
    if (success) {
      scalingMetrics.totalHibernations++;
      scalingMetrics.pauseCount++;
      updateContainerRuntime(userId, "pause");
    }
    return {
      success,
      userId,
      action: "pause",
      hibernationState: info.hibernationState,
    };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

/**
 * Wake a container from hibernation
 * @param {string} userId - User ID associated with container
 * @returns {Promise<object>} Result of waking
 */
export async function wakeContainer(userId) {
  const info = containers.get(userId);
  if (!info) {
    return { success: false, error: "Container not found" };
  }

  try {
    const success = await ensureAwake(userId);
    if (success) {
      scalingMetrics.totalWakes++;
      updateContainerRuntime(userId, "wake");
    }
    return {
      success,
      userId,
      hibernationState: info.hibernationState,
    };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

/**
 * Fully stop a container (release all resources, slower wake)
 * @param {string} userId - User ID associated with container
 * @returns {Promise<object>} Result of stopping
 */
export async function fullStopContainer(userId) {
  const info = containers.get(userId);
  if (!info) {
    return { success: false, error: "Container not found" };
  }

  try {
    const success = await stopContainer(userId);
    if (success) {
      scalingMetrics.totalHibernations++;
      scalingMetrics.stopCount++;
      updateContainerRuntime(userId, "stop");
    }
    return {
      success,
      userId,
      action: "stop",
      hibernationState: info.hibernationState,
    };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

// ============================================================
// COST TRACKING
// ============================================================

/**
 * Update container runtime tracking for cost calculation
 */
function updateContainerRuntime(userId, event) {
  const now = Date.now();
  let tracking = scalingMetrics.containerRuntime.get(userId);

  if (!tracking) {
    tracking = {
      userId,
      totalRuntimeMs: 0,
      currentSessionStart: null,
      plan: "free",
      sessions: [],
    };
    scalingMetrics.containerRuntime.set(userId, tracking);
  }

  if (event === "wake" || event === "start") {
    tracking.currentSessionStart = now;
  } else if ((event === "pause" || event === "stop") && tracking.currentSessionStart) {
    const sessionDuration = now - tracking.currentSessionStart;
    tracking.totalRuntimeMs += sessionDuration;
    tracking.sessions.push({
      start: tracking.currentSessionStart,
      end: now,
      durationMs: sessionDuration,
    });
    tracking.currentSessionStart = null;
  }
}

/**
 * Calculate cost for a tenant based on their container runtime
 * @param {string} userId - User ID
 * @param {string} plan - Plan name for pricing
 * @returns {object} Cost calculation
 */
export function calculateTenantCost(userId, plan = "free") {
  const tracking = scalingMetrics.containerRuntime.get(userId);
  if (!tracking) {
    return {
      userId,
      plan,
      totalRuntimeMs: 0,
      totalRuntimeHours: 0,
      estimatedCost: 0,
    };
  }

  // Include current session if running
  let totalMs = tracking.totalRuntimeMs;
  if (tracking.currentSessionStart) {
    totalMs += Date.now() - tracking.currentSessionStart;
  }

  const hours = totalMs / (1000 * 60 * 60);

  // Pricing per hour (example rates)
  const hourlyRates = {
    free: 0, // Free tier
    pro: 0.05, // $0.05/hour
    enterprise: 0.1, // $0.10/hour
  };

  const rate = hourlyRates[plan] || 0;
  const cost = hours * rate;

  return {
    userId,
    plan,
    totalRuntimeMs: totalMs,
    totalRuntimeHours: Math.round(hours * 100) / 100,
    hourlyRate: rate,
    estimatedCost: Math.round(cost * 100) / 100,
    sessions: tracking.sessions.length,
  };
}

// ============================================================
// AUTO-SCALING DAEMON
// ============================================================

let scalingInterval = null;

/**
 * Start the auto-scaling monitor daemon
 * Periodically checks containers and makes scaling decisions
 * @param {number} intervalMs - Check interval in milliseconds (default: 60000)
 */
export function startScalingMonitor(intervalMs = HIBERNATION_CONFIG.checkIntervalMs) {
  if (scalingInterval) {
    console.log("[scaling] Monitor already running");
    return;
  }

  console.log(`[scaling] Starting monitor, interval: ${intervalMs / 1000}s`);
  scalingInterval = setInterval(() => runScalingCheck(), intervalMs);

  // Run initial check
  runScalingCheck();
}

/**
 * Stop the auto-scaling monitor daemon
 */
export function stopScalingMonitor() {
  if (scalingInterval) {
    clearInterval(scalingInterval);
    scalingInterval = null;
    console.log("[scaling] Monitor stopped");
  }
}

/**
 * Run a single scaling check across all containers
 */
async function runScalingCheck() {
  scalingMetrics.lastCheck = Date.now();
  const results = {
    checked: 0,
    paused: 0,
    stopped: 0,
    errors: 0,
  };

  for (const [userId, info] of containers) {
    results.checked++;

    try {
      const decision = shouldHibernate(userId);

      if (decision.shouldHibernate) {
        if (decision.action === "pause") {
          const result = await hibernateContainer(userId);
          if (result.success) {
            results.paused++;
            console.log(
              `[scaling] Paused ${info.containerName} after ${Math.round(decision.idleMs / 60000)}min idle`,
            );
          }
        } else if (decision.action === "stop") {
          const result = await fullStopContainer(userId);
          if (result.success) {
            results.stopped++;
            console.log(`[scaling] Stopped ${info.containerName} after being paused`);
          }
        }
      }
    } catch (error) {
      results.errors++;
      console.error(`[scaling] Error checking ${userId.slice(0, 8)}:`, error.message);
    }
  }

  if (results.paused > 0 || results.stopped > 0) {
    console.log(
      `[scaling] Check complete: ${results.checked} containers, ${results.paused} paused, ${results.stopped} stopped`,
    );
  }

  return results;
}

// ============================================================
// METRICS & STATUS
// ============================================================

/**
 * Get current scaling metrics
 * @returns {object} Scaling metrics
 */
export function getScalingMetrics() {
  const uptimeMs = Date.now() - scalingMetrics.startTime;

  // Calculate total cost across all tenants
  let totalCost = 0;
  let totalRuntimeHours = 0;
  for (const [userId] of scalingMetrics.containerRuntime) {
    const cost = calculateTenantCost(userId);
    totalCost += cost.estimatedCost;
    totalRuntimeHours += cost.totalRuntimeHours;
  }

  return {
    uptime: {
      ms: uptimeMs,
      hours: Math.round((uptimeMs / (1000 * 60 * 60)) * 100) / 100,
    },
    hibernations: {
      total: scalingMetrics.totalHibernations,
      paused: scalingMetrics.pauseCount,
      stopped: scalingMetrics.stopCount,
    },
    wakes: scalingMetrics.totalWakes,
    resourceAdjustments: {
      total: scalingMetrics.resourceAdjustments,
      byPlan: Object.fromEntries(scalingMetrics.adjustmentsByPlan),
    },
    containers: {
      total: containers.size,
      byState: getContainersByState(),
    },
    cost: {
      totalRuntimeHours,
      estimatedTotalCost: Math.round(totalCost * 100) / 100,
      trackedTenants: scalingMetrics.containerRuntime.size,
    },
    pool: {
      enabled: POOL_CONFIG.enabled,
      hits: scalingMetrics.poolHits,
      misses: scalingMetrics.poolMisses,
    },
    lastCheck: scalingMetrics.lastCheck ? new Date(scalingMetrics.lastCheck).toISOString() : null,
    monitorRunning: scalingInterval !== null,
  };
}

/**
 * Get containers grouped by hibernation state
 */
function getContainersByState() {
  const states = { running: 0, paused: 0, stopped: 0, unknown: 0 };
  for (const info of containers.values()) {
    const state = info.hibernationState || "unknown";
    states[state] = (states[state] || 0) + 1;
  }
  return states;
}

/**
 * Get detailed status for all containers including resource usage
 * @returns {Promise<Array>} Container statuses with resource info
 */
export async function getAllContainerStatus() {
  const statuses = [];

  for (const [userId, info] of containers) {
    const baseStatus = {
      userId,
      containerId: info.containerId,
      containerName: info.containerName,
      port: info.port,
      hibernationState: info.hibernationState,
      lastActivity: info.lastActivity,
      idleMinutes: info.lastActivity ? Math.round((Date.now() - info.lastActivity) / 60000) : null,
    };

    // Only get stats for running containers
    if (info.hibernationState === "running") {
      try {
        const stats = await getContainerStats(info.containerId);
        statuses.push({ ...baseStatus, stats });
      } catch {
        statuses.push({ ...baseStatus, stats: null });
      }
    } else {
      statuses.push({ ...baseStatus, stats: null });
    }
  }

  return statuses;
}

// ============================================================
// PRE-WARMED CONTAINER POOL (Optional)
// ============================================================

const containerPool = new Map(); // poolId -> { containerId, createdAt, assignedTo }

/**
 * Initialize the pre-warmed container pool
 * Creates containers ahead of time for faster provisioning
 */
export async function initializePool() {
  if (!POOL_CONFIG.enabled) {
    console.log("[scaling] Container pool disabled");
    return;
  }

  console.log(`[scaling] Initializing pool with ${POOL_CONFIG.targetSize} containers`);

  for (let i = 0; i < POOL_CONFIG.targetSize; i++) {
    try {
      await addToPool();
    } catch (error) {
      console.error("[scaling] Failed to add container to pool:", error.message);
    }
  }
}

/**
 * Add a pre-warmed container to the pool
 */
async function addToPool() {
  if (containerPool.size >= POOL_CONFIG.maxSize) {
    return null;
  }

  const poolId = `pool-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const limits = RESOURCE_LIMITS[POOL_CONFIG.warmPlan];

  // Create a minimal container that can be assigned to a user later
  // This is a placeholder - actual implementation would need to create
  // the container with the base image and wait for user assignment
  console.log(`[scaling] Adding pre-warmed container to pool: ${poolId}`);

  containerPool.set(poolId, {
    poolId,
    createdAt: Date.now(),
    plan: POOL_CONFIG.warmPlan,
    assignedTo: null,
  });

  return poolId;
}

/**
 * Get a container from the pool for immediate assignment
 * @returns {object|null} Pool container or null if none available
 */
export function getFromPool() {
  if (!POOL_CONFIG.enabled || containerPool.size === 0) {
    scalingMetrics.poolMisses++;
    return null;
  }

  // Get oldest available container
  for (const [poolId, entry] of containerPool) {
    if (!entry.assignedTo) {
      scalingMetrics.poolHits++;
      return entry;
    }
  }

  scalingMetrics.poolMisses++;
  return null;
}

/**
 * Update pool configuration
 * @param {object} config - New configuration values
 */
export function updatePoolConfig(config) {
  Object.assign(POOL_CONFIG, config);
  console.log("[scaling] Pool config updated:", POOL_CONFIG);
}

// ============================================================
// EXPORTS
// ============================================================

export { RESOURCE_LIMITS, HIBERNATION_CONFIG, POOL_CONFIG };
