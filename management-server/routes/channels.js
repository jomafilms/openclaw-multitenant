import axios from "axios";
// Channel management routes (proxy to agent server)
import { Router } from "express";
import { users } from "../db/index.js";
import { AGENT_SERVER_URL, AGENT_SERVER_TOKEN } from "../lib/context.js";
import { requireUser } from "../middleware/auth.js";
import { detectTenant } from "../middleware/tenant-context.js";

const router = Router();

// Get channel status from DB (no secrets stored, just enabled flags)
router.get("/status", requireUser, detectTenant, async (req, res) => {
  try {
    const settings = await users.getSettings(req.user.id);
    const enabledChannels = settings.channels || {};

    // Build channel list from DB flags
    const channels = [];
    const knownChannels = ["telegram", "discord", "slack", "signal", "whatsapp"];

    for (const ch of knownChannels) {
      const chStatus = enabledChannels[ch];
      if (chStatus?.enabled) {
        channels.push({
          id: ch,
          name: ch.charAt(0).toUpperCase() + ch.slice(1),
          status: "connected",
          connectedAt: chStatus.connectedAt,
        });
      }
    }

    res.json({ channels });
  } catch (err) {
    console.warn("Channel status error:", err.message);
    res.json({ channels: [], error: "Failed to get channel status" });
  }
});

// Connect a messaging channel
router.post("/:channel/connect", requireUser, detectTenant, async (req, res) => {
  if (!req.user.containerId) {
    return res.status(400).json({ error: "Container not provisioned" });
  }

  const channel = req.params.channel;

  try {
    // Send token to agent server (writes to container config)
    const response = await axios.post(
      `${AGENT_SERVER_URL}/api/containers/${req.user.id}/channels/${channel}/connect`,
      req.body,
      { headers: { "x-auth-token": AGENT_SERVER_TOKEN }, timeout: 30000 },
    );

    // Save enabled flag in DB (no secrets, just status)
    const settings = await users.getSettings(req.user.id);
    settings.channels = settings.channels || {};
    settings.channels[channel] = {
      enabled: true,
      connectedAt: new Date().toISOString(),
    };
    await users.updateSettings(req.user.id, { channels: settings.channels });

    res.json(response.data);
  } catch (err) {
    console.error("Channel connect error:", err.message);
    res.status(err.response?.status || 500).json({
      error: err.response?.data?.error || "Failed to connect channel",
    });
  }
});

// Disconnect a messaging channel
router.post("/:channel/disconnect", requireUser, detectTenant, async (req, res) => {
  if (!req.user.containerId) {
    return res.status(400).json({ error: "Container not provisioned" });
  }

  const channel = req.params.channel;

  try {
    // Remove from container config
    const response = await axios.post(
      `${AGENT_SERVER_URL}/api/containers/${req.user.id}/channels/${channel}/disconnect`,
      {},
      { headers: { "x-auth-token": AGENT_SERVER_TOKEN }, timeout: 15000 },
    );

    // Clear enabled flag in DB
    const settings = await users.getSettings(req.user.id);
    if (settings.channels?.[channel]) {
      settings.channels[channel] = { enabled: false };
      await users.updateSettings(req.user.id, { channels: settings.channels });
    }

    res.json(response.data);
  } catch (err) {
    console.error("Channel disconnect error:", err.message);
    res.status(err.response?.status || 500).json({
      error: err.response?.data?.error || "Failed to disconnect channel",
    });
  }
});

// Set agent config value
router.post("/config", requireUser, detectTenant, async (req, res) => {
  if (!req.user.containerId) {
    return res.status(400).json({ error: "Container not provisioned" });
  }

  const { key, value } = req.body;
  if (!key) {
    return res.status(400).json({ error: "Config key required" });
  }

  try {
    const response = await axios.post(
      `${AGENT_SERVER_URL}/api/containers/${req.user.id}/config`,
      { key, value },
      { headers: { "x-auth-token": AGENT_SERVER_TOKEN }, timeout: 15000 },
    );
    res.json(response.data);
  } catch (err) {
    console.error("Agent config error:", err.message);
    res.status(err.response?.status || 500).json({
      error: err.response?.data?.error || "Failed to set config",
    });
  }
});

// Get agent config value
router.get("/config/:key", requireUser, detectTenant, async (req, res) => {
  if (!req.user.containerId) {
    return res.status(400).json({ error: "Container not provisioned" });
  }

  try {
    const response = await axios.get(
      `${AGENT_SERVER_URL}/api/containers/${req.user.id}/config/${encodeURIComponent(req.params.key)}`,
      { headers: { "x-auth-token": AGENT_SERVER_TOKEN }, timeout: 15000 },
    );
    res.json(response.data);
  } catch (err) {
    res.status(err.response?.status || 500).json({
      error: err.response?.data?.error || "Failed to get config",
    });
  }
});

// Write to agent workspace
router.post("/workspace/write", requireUser, detectTenant, async (req, res) => {
  if (!req.user.containerId) {
    return res.status(400).json({ error: "Container not provisioned" });
  }

  const { filePath, content } = req.body;
  if (!filePath || content === undefined) {
    return res.status(400).json({ error: "filePath and content required" });
  }

  try {
    const response = await axios.post(
      `${AGENT_SERVER_URL}/api/containers/${req.user.id}/workspace/write`,
      { filePath, content },
      { headers: { "x-auth-token": AGENT_SERVER_TOKEN }, timeout: 15000 },
    );
    res.json(response.data);
  } catch (err) {
    res.status(err.response?.status || 500).json({
      error: err.response?.data?.error || "Failed to write file",
    });
  }
});

// Refresh agent context
router.post("/context/refresh", requireUser, detectTenant, async (req, res) => {
  if (!req.user.containerId) {
    return res.status(400).json({ error: "Container not provisioned" });
  }

  try {
    const { updateAgentContext } = await import("../lib/context.js");
    await updateAgentContext(req.user.id);
    res.json({ success: true, message: "Agent context refreshed" });
  } catch (err) {
    console.error("Context refresh error:", err.message);
    res.status(500).json({ error: "Failed to refresh context" });
  }
});

export default router;
