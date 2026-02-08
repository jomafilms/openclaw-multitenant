// Group vault container management routes for agent server
// Handles container provisioning and lifecycle

import { randomBytes } from "crypto";
import { Router } from "express";
import fs from "fs";
import path from "path";
import { docker, containers } from "../lib/containers.js";

const router = Router();
const IMAGE_NAME = process.env.OCMT_GROUP_VAULT_IMAGE || "ocmt-group-vault:local";
const BASE_PORT = 18800; // Different port range from user containers

// In-memory tracking of group vault containers
const groupVaultContainers = new Map();

// Data directory for group vaults
const DATA_DIR = process.env.GROUP_VAULT_DATA_DIR || "/data/group-vaults";

/**
 * Ensure group vault data directory exists
 */
function ensureGroupVaultDir(groupId) {
  const groupDir = path.join(DATA_DIR, groupId);
  if (!fs.existsSync(groupDir)) {
    fs.mkdirSync(groupDir, { recursive: true });
  }
  return groupDir;
}

/**
 * POST /api/group-vaults/provision
 * Provision a new group vault container
 */
router.post("/provision", async (req, res) => {
  const { groupId, groupSlug, authToken } = req.body;

  if (!groupId) {
    return res.status(400).json({ error: "groupId required" });
  }

  if (!authToken) {
    return res.status(400).json({ error: "authToken required" });
  }

  // Check if already exists
  if (groupVaultContainers.has(groupId)) {
    const existing = groupVaultContainers.get(groupId);
    return res.json({ status: "exists", ...existing });
  }

  try {
    // Find available port
    const usedPorts = new Set([...groupVaultContainers.values()].map((c) => c.port));
    let port = BASE_PORT;
    while (usedPorts.has(port)) {
      port++;
    }

    // Ensure data directory
    const groupDir = ensureGroupVaultDir(groupId);

    const containerName = `ocmt-group-vault-${(groupSlug || groupId).slice(0, 20)}`;
    console.log("Creating group vault container", containerName, "on port", port);

    // Generate signing key for capability tokens
    const signingKey = randomBytes(32).toString("hex");

    // Build environment variables
    const env = [
      `PORT=${port}`,
      `GROUP_ID=${groupId}`,
      `AUTH_TOKEN=${authToken}`,
      `SIGNING_KEY=${signingKey}`,
    ];

    const container = await docker.createContainer({
      Image: IMAGE_NAME,
      name: containerName,
      Env: env,
      Labels: {
        "ocmt.type": "group-vault",
        "ocmt.groupId": groupId,
        "ocmt.groupSlug": groupSlug || "",
      },
      ExposedPorts: { [`${port}/tcp`]: {} },
      HostConfig: {
        PortBindings: { [`${port}/tcp`]: [{ HostPort: String(port) }] },
        Binds: [`${groupDir}:/app/data:rw`],
        Memory: 256 * 1024 * 1024, // 256MB - group vault is lightweight
        MemorySwap: 512 * 1024 * 1024,
        CpuShares: 256,
        RestartPolicy: { Name: "unless-stopped" },
        NetworkMode: "ocmt-isolated",
      },
    });

    await container.start();

    const info = {
      containerId: container.id,
      containerName,
      port,
      groupId,
      createdAt: new Date().toISOString(),
    };

    groupVaultContainers.set(groupId, info);
    console.log("Group vault container started:", containerName);

    // Wait a moment for the container to be ready
    await new Promise((resolve) => setTimeout(resolve, 2000));

    res.json({ status: "created", ...info });
  } catch (error) {
    console.error("Group vault provision error:", error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /api/group-vaults
 * List all group vault containers
 */
router.get("/", async (req, res) => {
  const list = [];
  for (const [groupId, info] of groupVaultContainers) {
    try {
      const container = docker.getContainer(info.containerId);
      const inspection = await container.inspect();
      list.push({
        groupId,
        ...info,
        running: inspection.State.Running,
        paused: inspection.State.Paused,
      });
    } catch {
      list.push({
        groupId,
        ...info,
        running: false,
        error: "Container not found",
      });
    }
  }
  res.json(list);
});

/**
 * GET /api/group-vaults/:groupId/status
 * Get status of a specific group vault container
 */
router.get("/:groupId/status", async (req, res) => {
  const { groupId } = req.params;
  const info = groupVaultContainers.get(groupId);

  if (!info) {
    return res.status(404).json({ error: "Group vault container not found" });
  }

  try {
    const container = docker.getContainer(info.containerId);
    const inspection = await container.inspect();
    res.json({
      ...info,
      running: inspection.State.Running,
      paused: inspection.State.Paused,
      startedAt: inspection.State.StartedAt,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * DELETE /api/group-vaults/:groupId
 * Delete an group vault container
 */
router.delete("/:groupId", async (req, res) => {
  const { groupId } = req.params;
  const info = groupVaultContainers.get(groupId);

  if (!info) {
    return res.status(404).json({ error: "Group vault container not found" });
  }

  try {
    const container = docker.getContainer(info.containerId);
    try {
      await container.stop();
    } catch {
      // Ignore if already stopped
    }
    await container.remove();
    groupVaultContainers.delete(groupId);

    console.log("Group vault container removed:", info.containerName);
    res.json({ status: "removed" });
  } catch (error) {
    console.error("Group vault delete error:", error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /api/group-vaults/:groupId/restart
 * Restart an group vault container
 */
router.post("/:groupId/restart", async (req, res) => {
  const { groupId } = req.params;
  const info = groupVaultContainers.get(groupId);

  if (!info) {
    return res.status(404).json({ error: "Group vault container not found" });
  }

  try {
    const container = docker.getContainer(info.containerId);
    await container.restart();
    console.log("Group vault container restarted:", info.containerName);
    res.json({ status: "restarted" });
  } catch (error) {
    console.error("Group vault restart error:", error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * Scan for existing group vault containers on startup
 */
export async function scanExistingGroupVaultContainers() {
  try {
    const allContainers = await docker.listContainers({ all: true });
    const orgVaultCntrs = allContainers.filter((c) =>
      c.Names.some((n) => n.startsWith("/ocmt-group-vault-")),
    );

    console.log("Scanning for existing group vault containers...");
    console.log("Found", orgVaultCntrs.length, "group vault container(s)");

    for (const c of orgVaultCntrs) {
      const container = docker.getContainer(c.Id);
      const inspection = await container.inspect();
      const labels = inspection.Config.Labels || {};

      const groupId = labels["ocmt.groupId"];
      if (!groupId) {
        continue;
      }

      const port = c.Ports.find((p) => p.PrivatePort >= BASE_PORT)?.PublicPort;
      if (!port) {
        continue;
      }

      groupVaultContainers.set(groupId, {
        containerId: c.Id,
        containerName: c.Names[0].slice(1),
        port,
        groupId,
      });

      console.log(`  Restored: ${groupId.slice(0, 12)}... port ${port}`);
    }
  } catch (error) {
    console.error("Group vault scan error:", error);
  }
}

export { groupVaultContainers };
export default router;
