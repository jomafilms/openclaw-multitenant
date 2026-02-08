import { randomBytes } from "crypto";
// Container CRUD and management routes
import { Router } from "express";
import fs from "fs";
import path from "path";
import {
  containers,
  docker,
  ensureAwake,
  touchActivity,
  pauseContainer,
  stopContainer,
  execInContainer,
  getQuickStatus,
  isContainerReady,
  wakeContainerWithQueue,
  getWakeMetrics,
} from "../lib/containers.js";
import { ensureContainerSetup, writeGatewayConfig, DATA_DIR } from "../lib/setup.js";

const router = Router();
const IMAGE_NAME = process.env.OPENCLAW_IMAGE || "openclaw:local";
const BASE_PORT = 19000;

// List all containers
router.get("/", async (req, res) => {
  const list = [];
  for (const [userId, info] of containers) {
    list.push({
      userId,
      ...info,
      idleMinutes: info.lastActivity ? Math.round((Date.now() - info.lastActivity) / 60000) : null,
    });
  }
  res.json(list);
});

// Provision a new container
router.post("/provision", async (req, res) => {
  const { userId, userName, anthropicApiKey, anthropicSetupToken, openaiApiKey } = req.body;

  if (!userId) {
    return res.status(400).json({ error: "userId required" });
  }

  if (!anthropicApiKey && !anthropicSetupToken) {
    return res.status(400).json({ error: "anthropicApiKey or anthropicSetupToken required" });
  }

  // Check if already exists
  if (containers.has(userId)) {
    await ensureAwake(userId);
    return res.json({ status: "exists", ...containers.get(userId) });
  }

  try {
    // Find available port
    const usedPorts = new Set([...containers.values()].map((c) => c.port));
    let port = BASE_PORT;
    while (usedPorts.has(port)) {
      port++;
    }

    // Create directories and config
    ensureContainerSetup(userId);

    // Generate and write gateway token
    const gatewayToken = randomBytes(32).toString("hex");
    writeGatewayConfig(userId, gatewayToken);

    const containerName = "ocmt-" + userId.slice(0, 12);
    console.log("Creating container", containerName, "on port", port);

    // Build environment variables
    const env = [
      "HOME=/home/node",
      "NODE_OPTIONS=--max-old-space-size=1536",
      "OPENCLAW_GATEWAY_TOKEN=" + gatewayToken,
      "OCMT_USER_ID=" + userId,
      "OCMT_USER_NAME=" + (userName || "User"),
    ];

    if (anthropicSetupToken) {
      env.push("ANTHROPIC_SETUP_TOKEN=" + anthropicSetupToken);
      console.log("  Using setup-token auth");
    } else if (anthropicApiKey) {
      env.push("ANTHROPIC_API_KEY=" + anthropicApiKey);
      console.log("  Using API key auth");
    }

    if (openaiApiKey) {
      env.push("OPENAI_API_KEY=" + openaiApiKey);
      console.log("  OpenAI key configured");
    }

    const userDataDir = path.join(DATA_DIR, userId);
    const container = await docker.createContainer({
      Image: IMAGE_NAME,
      name: containerName,
      Env: env,
      Labels: { "ocmt.userId": userId },
      ExposedPorts: { "18789/tcp": {} },
      Cmd: ["node", "dist/index.js", "gateway", "--bind", "lan", "--port", "18789"],
      HostConfig: {
        PortBindings: { "18789/tcp": [{ HostPort: String(port) }] },
        Binds: [userDataDir + ":/home/node/.openclaw:rw", "/opt/ocmt/skills:/opt/ocmt/skills:ro"],
        Memory: 2048 * 1024 * 1024,
        MemorySwap: 3072 * 1024 * 1024,
        CpuShares: 512,
        RestartPolicy: { Name: "unless-stopped" },
        NetworkMode: "ocmt-isolated",
      },
    });

    await container.start();

    const info = {
      containerId: container.id,
      containerName,
      port,
      gatewayToken,
      hibernationState: "running",
      lastActivity: Date.now(),
      createdAt: new Date().toISOString(),
    };

    containers.set(userId, info);
    console.log("Container started:", containerName);

    res.json({ status: "created", ...info });
  } catch (error) {
    console.error("Provision error:", error);
    res.status(500).json({ error: error.message });
  }
});

// Delete a container
router.delete("/:userId", async (req, res) => {
  const { userId } = req.params;
  const info = containers.get(userId);

  if (!info) {
    return res.status(404).json({ error: "Container not found" });
  }

  try {
    const container = docker.getContainer(info.containerId);
    try {
      const inspection = await container.inspect();
      if (inspection.State.Paused) {
        await container.unpause();
      }
    } catch (e) {
      /* ignore */
    }
    await container.stop().catch(() => {});
    await container.remove();
    containers.delete(userId);

    console.log("Container removed:", info.containerName);
    res.json({ status: "removed" });
  } catch (error) {
    console.error("Deprovision error:", error);
    res.status(500).json({ error: error.message });
  }
});

// Get container status
router.get("/:userId/status", async (req, res) => {
  const { userId } = req.params;
  const info = containers.get(userId);

  if (!info) {
    return res.status(404).json({ error: "Container not found" });
  }

  try {
    const container = docker.getContainer(info.containerId);
    const inspection = await container.inspect();
    res.json({
      ...info,
      running: inspection.State.Running,
      paused: inspection.State.Paused,
      startedAt: inspection.State.StartedAt,
      idleMinutes: info.lastActivity ? Math.round((Date.now() - info.lastActivity) / 60000) : null,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Quick status check (no Docker inspection, uses cached state)
// Fast endpoint for wake-on-request checks
router.get("/:userId/status/quick", async (req, res) => {
  const { userId } = req.params;
  const status = getQuickStatus(userId);

  if (!status.exists) {
    return res.status(404).json({ error: "Container not found", exists: false });
  }

  res.json({
    ...status,
    ready: status.hibernationState === "running",
  });
});

// Check if container is ready to receive requests
router.get("/:userId/ready", async (req, res) => {
  const { userId } = req.params;
  const ready = isContainerReady(userId);
  res.json({ ready, userId });
});

// Get wake metrics
router.get("/metrics/wake", async (req, res) => {
  res.json(getWakeMetrics());
});

// Wake container (with deduplication and queuing)
router.post("/:userId/wake", async (req, res) => {
  const { userId } = req.params;
  const { reason = "direct", timeout = 30000 } = req.body || {};
  const info = containers.get(userId);

  if (!info) {
    return res.status(404).json({ error: "Container not found" });
  }

  try {
    const result = await wakeContainerWithQueue(userId, { reason, timeout });
    res.json({
      status: result.status,
      wakeTime: result.wakeTime,
      hibernationState: containers.get(userId)?.hibernationState,
      queued: result.queued || false,
      reason: result.reason,
    });
  } catch (err) {
    if (err.message === "Wake timeout") {
      return res.status(504).json({
        error: "Wake timeout",
        message: "Container took too long to wake",
      });
    }
    res.status(503).json({
      error: "Failed to wake container",
      message: err.message,
    });
  }
});

// Hibernate container
router.post("/:userId/hibernate", async (req, res) => {
  const { userId } = req.params;
  const { mode } = req.body;
  const info = containers.get(userId);

  if (!info) {
    return res.status(404).json({ error: "Container not found" });
  }

  if (mode === "stop") {
    await stopContainer(userId);
  } else {
    await pauseContainer(userId);
  }

  res.json({ status: "hibernating", hibernationState: info.hibernationState });
});

// Repair container (internal - called automatically)
// Also updates MCP config for existing containers
router.post("/:userId/repair", async (req, res) => {
  const { userId } = req.params;
  const info = containers.get(userId);

  if (!info) {
    return res.status(404).json({ error: "Container not found" });
  }

  try {
    // Ensure directory structure and base config
    ensureContainerSetup(userId);

    // Update gateway config including MCP servers (uses existing gatewayToken)
    const config = writeGatewayConfig(userId, info.gatewayToken);

    res.json({
      status: "repaired",
      sandboxMode: config.agents?.defaults?.sandbox?.mode || "unknown",
      workspace: config.agents?.defaults?.workspace || "unknown",
      mcpConfigured: !!config.mcpServers?.ocmt,
    });
  } catch (error) {
    console.error("Repair error:", error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// SNAPSHOT SYNC (CACHED tier sharing)
// ============================================================

// Trigger snapshot sync on the container
// This refreshes due snapshots and pushes them to the relay
router.post("/:userId/snapshots/sync", async (req, res) => {
  const { userId } = req.params;
  const info = containers.get(userId);

  if (!info) {
    return res.status(404).json({ error: "Container not found" });
  }

  const awoke = await ensureAwake(userId);
  if (!awoke) {
    return res.status(503).json({ error: "Container failed to wake" });
  }

  try {
    // Call the container's snapshot sync endpoint
    const containerUrl = `http://localhost:${info.port}`;
    const response = await fetch(`${containerUrl}/v1/secrets/snapshots/sync`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${info.gatewayToken}`,
      },
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: "Unknown error" }));
      return res.status(response.status).json(error);
    }

    const result = await response.json();
    touchActivity(userId);
    res.json(result);
  } catch (error) {
    console.error("Snapshot sync error:", error);
    res.status(502).json({ error: "Container communication failed: " + error.message });
  }
});

// Get snapshot status for the container
router.get("/:userId/snapshots/status", async (req, res) => {
  const { userId } = req.params;
  const info = containers.get(userId);

  if (!info) {
    return res.status(404).json({ error: "Container not found" });
  }

  const awoke = await ensureAwake(userId);
  if (!awoke) {
    return res.status(503).json({ error: "Container failed to wake" });
  }

  try {
    const containerUrl = `http://localhost:${info.port}`;
    const response = await fetch(`${containerUrl}/v1/secrets/snapshots/status`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${info.gatewayToken}`,
      },
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: "Unknown error" }));
      return res.status(response.status).json(error);
    }

    const result = await response.json();
    res.json(result);
  } catch (error) {
    console.error("Snapshot status error:", error);
    res.status(502).json({ error: "Container communication failed: " + error.message });
  }
});

// ============================================================
// AUTH PROFILES (credential sync)
// ============================================================

// Get auth profiles from container
router.get("/:userId/auth-profiles", async (req, res) => {
  const { userId } = req.params;
  const authProfilesPath = path.join(
    DATA_DIR,
    userId,
    "agents",
    "main",
    "agent",
    "auth-profiles.json",
  );

  try {
    if (!fs.existsSync(authProfilesPath)) {
      return res.json({ profiles: {}, version: 2 });
    }
    const data = JSON.parse(fs.readFileSync(authProfilesPath, "utf-8"));
    res.json(data);
  } catch (error) {
    console.error("Read auth-profiles error:", error);
    res.status(500).json({ error: error.message });
  }
});

// Write auth profiles to container
router.post("/:userId/auth-profiles", async (req, res) => {
  const { userId } = req.params;
  const { profiles } = req.body;

  if (!profiles) {
    return res.status(400).json({ error: "profiles required" });
  }

  const agentDir = path.join(DATA_DIR, userId, "agents", "main", "agent");
  const authProfilesPath = path.join(agentDir, "auth-profiles.json");

  try {
    // Ensure directory exists
    if (!fs.existsSync(agentDir)) {
      fs.mkdirSync(agentDir, { recursive: true });
      fs.chownSync(agentDir, 1000, 1000);
    }

    const authStore = { version: 2, profiles };
    fs.writeFileSync(authProfilesPath, JSON.stringify(authStore, null, 2));
    fs.chownSync(authProfilesPath, 1000, 1000);
    fs.chmodSync(authProfilesPath, 0o600);

    console.log(`[containers] Wrote auth-profiles for user ${userId.slice(0, 8)}`);
    res.json({ success: true, count: Object.keys(profiles).length });
  } catch (error) {
    console.error("Write auth-profiles error:", error);
    res.status(500).json({ error: error.message });
  }
});

// Chat proxy
router.post("/:userId/chat", async (req, res) => {
  const { userId } = req.params;
  const { message } = req.body;
  const info = containers.get(userId);

  if (!info) {
    return res.status(404).json({ error: "Container not found" });
  }

  if (!message) {
    return res.status(400).json({ error: "Message required" });
  }

  const awoke = await ensureAwake(userId);
  if (!awoke) {
    return res.status(503).json({ error: "Container failed to wake" });
  }

  try {
    const result = await execInContainer(
      info.containerId,
      ["openclaw", "agent", "--agent", "main", "--message", message, "--local"],
      120000,
    );

    touchActivity(userId);
    console.log("Chat response for", userId.slice(0, 8), ":", result.output.slice(0, 100));
    res.json({ response: result.output });
  } catch (error) {
    console.error("Chat exec error:", error);
    res.status(502).json({ error: "Container communication failed: " + error.message });
  }
});

export default router;
