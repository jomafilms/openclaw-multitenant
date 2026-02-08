// Container state and Docker operations
import Docker from "dockerode";
import { ensureContainerSetup, readGatewayToken } from "./setup.js";

const docker = new Docker({ socketPath: "/var/run/docker.sock" });

// In-memory container state with activity timestamps
const containers = new Map();

// Hibernation configuration
const PAUSE_AFTER_MS = 30 * 60 * 1000; // 30 minutes -> pause
const STOP_AFTER_MS = 4 * 60 * 60 * 1000; // 4 hours paused -> stop

/**
 * Update activity timestamp for a container
 */
export function touchActivity(userId) {
  const info = containers.get(userId);
  if (info) {
    info.lastActivity = Date.now();
    info.hibernationState = "running";
  }
}

/**
 * Ensure container is awake before operations
 */
export async function ensureAwake(userId) {
  const info = containers.get(userId);
  if (!info) {
    return false;
  }

  const container = docker.getContainer(info.containerId);

  try {
    const inspection = await container.inspect();
    const state = inspection.State;

    if (state.Running && !state.Paused) {
      touchActivity(userId);
      return true;
    }

    if (state.Paused) {
      console.log(`[hibernate] Unpausing ${info.containerName}...`);
      const start = Date.now();
      await container.unpause();
      console.log(`[hibernate] Unpaused in ${Date.now() - start}ms`);
      touchActivity(userId);
      return true;
    }

    if (!state.Running) {
      console.log(`[hibernate] Starting ${info.containerName}...`);
      const start = Date.now();
      await container.start();
      await new Promise((resolve) => setTimeout(resolve, 2000));
      console.log(`[hibernate] Started in ${Date.now() - start}ms`);
      touchActivity(userId);
      return true;
    }

    return true;
  } catch (error) {
    console.error(`[hibernate] Failed to wake ${info.containerName}:`, error.message);
    return false;
  }
}

/**
 * Pause a container (keeps memory, instant wake)
 */
export async function pauseContainer(userId) {
  const info = containers.get(userId);
  if (!info) {
    return false;
  }

  try {
    const container = docker.getContainer(info.containerId);
    const inspection = await container.inspect();

    if (inspection.State.Running && !inspection.State.Paused) {
      await container.pause();
      info.hibernationState = "paused";
      info.pausedAt = Date.now();
      console.log(`[hibernate] Paused ${info.containerName}`);
      return true;
    }
  } catch (error) {
    console.error(`[hibernate] Failed to pause:`, error.message);
  }
  return false;
}

/**
 * Stop a container (full hibernation, slower wake)
 */
export async function stopContainer(userId) {
  const info = containers.get(userId);
  if (!info) {
    return false;
  }

  try {
    const container = docker.getContainer(info.containerId);
    const inspection = await container.inspect();

    if (inspection.State.Running || inspection.State.Paused) {
      if (inspection.State.Paused) {
        await container.unpause();
      }
      await container.stop({ t: 10 });
      info.hibernationState = "stopped";
      info.stoppedAt = Date.now();
      console.log(`[hibernate] Stopped ${info.containerName}`);
      return true;
    }
  } catch (error) {
    console.error(`[hibernate] Failed to stop:`, error.message);
  }
  return false;
}

/**
 * Check all containers for hibernation
 */
export async function checkHibernation() {
  const now = Date.now();

  for (const [userId, info] of containers) {
    try {
      const container = docker.getContainer(info.containerId);
      const inspection = await container.inspect();
      const state = inspection.State;

      if (!state.Running && !state.Paused) {
        info.hibernationState = "stopped";
        continue;
      }

      if (state.Paused) {
        info.hibernationState = "paused";
        const pausedDuration = now - (info.pausedAt || now);
        if (pausedDuration > STOP_AFTER_MS - PAUSE_AFTER_MS) {
          console.log(`[hibernate] ${info.containerName} paused too long, stopping...`);
          await stopContainer(userId);
        }
        continue;
      }

      const idleTime = now - (info.lastActivity || now);
      if (idleTime > PAUSE_AFTER_MS) {
        console.log(
          `[hibernate] ${info.containerName} idle ${Math.round(idleTime / 60000)}min, pausing...`,
        );
        await pauseContainer(userId);
      }
    } catch (error) {
      if (error.statusCode === 404) {
        containers.delete(userId);
      }
    }
  }
}

/**
 * Execute command in container with timeout
 */
export async function execInContainer(containerId, cmd, timeoutMs = 30000) {
  const container = docker.getContainer(containerId);
  const exec = await container.exec({
    Cmd: cmd,
    AttachStdout: true,
    AttachStderr: true,
  });

  const stream = await exec.start({ hijack: true, stdin: false });

  return new Promise((resolve, reject) => {
    let output = "";
    let error = "";

    const timeout = setTimeout(() => {
      reject(new Error("Command timeout"));
    }, timeoutMs);

    stream.on("data", (chunk) => {
      if (chunk.length > 8) {
        const data = chunk.slice(8).toString();
        const streamType = chunk[0];
        if (streamType === 2) {
          error += data;
        } else {
          output += data;
        }
      }
    });

    stream.on("end", () => {
      clearTimeout(timeout);
      resolve({ output: output.trim(), error: error.trim() });
    });

    stream.on("error", (err) => {
      clearTimeout(timeout);
      reject(err);
    });
  });
}

/**
 * Scan for existing containers on startup
 */
export async function scanExistingContainers() {
  try {
    const allContainers = await docker.listContainers({ all: true });
    const ocmtContainers = allContainers.filter((c) => c.Names.some((n) => n.startsWith("/ocmt-")));

    console.log("Scanning for existing containers...");
    console.log("Found", ocmtContainers.length, "container(s)");

    for (const c of ocmtContainers) {
      const port = c.Ports.find((p) => p.PrivatePort === 18789)?.PublicPort;
      if (!port) {
        continue;
      }

      const container = docker.getContainer(c.Id);
      const inspection = await container.inspect();
      const labels = inspection.Config.Labels || {};

      const userId = labels["ocmt.userId"] || c.Names[0].replace("/ocmt-", "");

      // Repair container setup (creates missing dirs, fixes config)
      ensureContainerSetup(userId);

      // Read gateway token from config (authoritative source, never from labels for security)
      let gatewayToken = readGatewayToken(userId) || "unknown";

      let hibernationState = "stopped";
      if (inspection.State.Running) {
        hibernationState = inspection.State.Paused ? "paused" : "running";
      }

      containers.set(userId, {
        containerId: c.Id,
        containerName: c.Names[0].slice(1),
        port,
        hibernationState,
        lastActivity: Date.now(),
        gatewayToken,
      });

      console.log(`  Restored: ${userId.slice(0, 12)}... port ${port} (${hibernationState})`);
    }
  } catch (error) {
    console.error("Scan error:", error);
  }
}

// Wake request queue for deduplication
// Key: userId -> { promise, waiters, startedAt }
const wakeQueue = new Map();

// Wake metrics
const wakeMetrics = {
  totalWakes: 0,
  successfulWakes: 0,
  failedWakes: 0,
  timeouts: 0,
  totalLatencyMs: 0,
  wakesByReason: new Map(), // 'on-request' | 'direct' | 'reconnect'
};

/**
 * Get quick container status (no Docker inspection for running containers)
 * Returns cached state for fast checks
 */
export function getQuickStatus(userId) {
  const info = containers.get(userId);
  if (!info) {
    return { exists: false };
  }

  return {
    exists: true,
    containerId: info.containerId,
    containerName: info.containerName,
    port: info.port,
    hibernationState: info.hibernationState || "unknown",
    lastActivity: info.lastActivity,
    idleMs: info.lastActivity ? Date.now() - info.lastActivity : null,
  };
}

/**
 * Check if container is ready to receive requests
 */
export function isContainerReady(userId) {
  const info = containers.get(userId);
  return info?.hibernationState === "running";
}

/**
 * Wake container with deduplication and queuing
 * Multiple callers waiting on same wake get same result
 */
export async function wakeContainerWithQueue(userId, options = {}) {
  const { reason = "direct", timeout = 30000 } = options;
  const startTime = Date.now();

  // Check if already running
  if (isContainerReady(userId)) {
    touchActivity(userId);
    return { status: "already-running", wakeTime: 0 };
  }

  // Check if already waking
  const existingWake = wakeQueue.get(userId);
  if (existingWake) {
    console.log(`[wake-queue] Joining existing wake for ${userId.slice(0, 8)}...`);
    existingWake.waiters++;
    const result = await existingWake.promise;
    return { ...result, queued: true };
  }

  // Start new wake operation
  let resolveWake, rejectWake;
  const wakePromise = new Promise((resolve, reject) => {
    resolveWake = resolve;
    rejectWake = reject;
  });

  const wakeEntry = {
    promise: wakePromise,
    waiters: 1,
    startedAt: startTime,
    reason,
  };
  wakeQueue.set(userId, wakeEntry);

  console.log(`[wake-queue] Starting wake for ${userId.slice(0, 8)}... (reason: ${reason})`);

  try {
    // Set up timeout
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error("Wake timeout")), timeout);
    });

    // Race wake vs timeout
    const wakeResult = await Promise.race([
      (async () => {
        const awoke = await ensureAwake(userId);
        if (!awoke) {
          throw new Error("Container failed to wake");
        }

        // Wait for gateway to be ready (healthcheck)
        const info = containers.get(userId);
        if (info) {
          await waitForGatewayReady(info.port, 5000);
        }

        const wakeTime = Date.now() - startTime;
        return { status: "awoke", wakeTime, reason };
      })(),
      timeoutPromise,
    ]);

    // Update metrics
    wakeMetrics.totalWakes++;
    wakeMetrics.successfulWakes++;
    wakeMetrics.totalLatencyMs += wakeResult.wakeTime;
    const reasonCount = wakeMetrics.wakesByReason.get(reason) || 0;
    wakeMetrics.wakesByReason.set(reason, reasonCount + 1);

    console.log(
      `[wake-queue] Wake complete for ${userId.slice(0, 8)} in ${wakeResult.wakeTime}ms (${wakeEntry.waiters} waiter(s))`,
    );
    resolveWake(wakeResult);
    return wakeResult;
  } catch (err) {
    wakeMetrics.totalWakes++;
    wakeMetrics.failedWakes++;
    if (err.message === "Wake timeout") {
      wakeMetrics.timeouts++;
    }

    console.error(`[wake-queue] Wake failed for ${userId.slice(0, 8)}:`, err.message);
    rejectWake(err);
    throw err;
  } finally {
    wakeQueue.delete(userId);
  }
}

/**
 * Wait for gateway to respond to health check
 */
async function waitForGatewayReady(port, timeout = 5000) {
  const startTime = Date.now();
  const checkInterval = 200;

  while (Date.now() - startTime < timeout) {
    try {
      const response = await fetch(`http://localhost:${port}/health`, {
        signal: AbortSignal.timeout(500),
      });
      if (response.ok) {
        return true;
      }
    } catch {
      // Gateway not ready yet
    }
    await new Promise((r) => setTimeout(r, checkInterval));
  }

  // Timeout, but container might still work
  console.warn(`[wake-queue] Gateway health check timed out on port ${port}`);
  return false;
}

/**
 * Get wake metrics
 */
export function getWakeMetrics() {
  const avgLatency =
    wakeMetrics.successfulWakes > 0
      ? Math.round(wakeMetrics.totalLatencyMs / wakeMetrics.successfulWakes)
      : 0;

  return {
    total: wakeMetrics.totalWakes,
    successful: wakeMetrics.successfulWakes,
    failed: wakeMetrics.failedWakes,
    timeouts: wakeMetrics.timeouts,
    avgLatencyMs: avgLatency,
    byReason: Object.fromEntries(wakeMetrics.wakesByReason),
    currentlyWaking: wakeQueue.size,
  };
}

// Export state and docker instance
export { containers, docker, PAUSE_AFTER_MS, STOP_AFTER_MS, wakeQueue };
