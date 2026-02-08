// Channel configuration routes
import { Router } from "express";
import fs from "fs";
import path from "path";
import {
  containers,
  ensureAwake,
  touchActivity,
} from "../lib/containers.js";
import { DATA_DIR } from "../lib/setup.js";

const router = Router();

/**
 * Read and parse openclaw.json config for a user
 */
function readConfig(userId) {
  const configPath = path.join(DATA_DIR, userId, "openclaw.json");
  try {
    if (fs.existsSync(configPath)) {
      return JSON.parse(fs.readFileSync(configPath, "utf-8"));
    }
  } catch (e) {
    console.warn(`[channels] Error reading config for ${userId}:`, e.message);
  }
  return {};
}

/**
 * Write openclaw.json config for a user
 */
function writeConfig(userId, config) {
  const configPath = path.join(DATA_DIR, userId, "openclaw.json");
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
  fs.chownSync(configPath, 1000, 1000);
  fs.chmodSync(configPath, 0o644);
}

// Get channel status - reads from config file
router.get("/:userId/channels", async (req, res) => {
  const { userId } = req.params;
  const info = containers.get(userId);

  if (!info) {
    return res.status(404).json({ error: "Container not found" });
  }

  try {
    const config = readConfig(userId);
    const configuredChannels = config.channels || {};

    // Build channel status from config
    const channels = [];
    const knownChannels = ["telegram", "discord", "slack", "signal", "whatsapp"];

    for (const channel of knownChannels) {
      const channelConfig = configuredChannels[channel];
      if (channelConfig) {
        channels.push({
          id: channel,
          name: channel.charAt(0).toUpperCase() + channel.slice(1),
          status: "configured",
          hasToken: !!(channelConfig.token || channelConfig.phone || channelConfig.botToken)
        });
      }
    }

    res.json({ channels });
  } catch (error) {
    console.warn(`[channels] Status check failed: ${error.message}`);
    res.json({ channels: [], error: error.message });
  }
});

// Connect a channel - writes directly to config file
router.post("/:userId/channels/:channel/connect", async (req, res) => {
  const { userId, channel } = req.params;
  const { token, phone, appToken, botToken } = req.body;
  const info = containers.get(userId);

  if (!info) {
    return res.status(404).json({ error: "Container not found" });
  }

  try {
    const config = readConfig(userId);

    switch (channel) {
      case "telegram":
        if (!token) {
          return res.status(400).json({ error: "Bot token required" });
        }
        config.channels = config.channels || {};
        config.channels.telegram = {
          botToken: token,
          dmPolicy: "open"  // Allow DMs without pairing for personal bots
        };
        break;

      case "discord":
        if (!token) {
          return res.status(400).json({ error: "Bot token required" });
        }
        config.channels = config.channels || {};
        config.channels.discord = {
          botToken: token,
          dmPolicy: "open"
        };
        break;

      case "slack":
        if (!appToken || !botToken) {
          return res.status(400).json({ error: "App token and bot token required" });
        }
        config.channels = config.channels || {};
        config.channels.slack = { appToken, botToken };
        break;

      case "signal":
        if (!phone) {
          return res.status(400).json({ error: "Phone number required" });
        }
        config.channels = config.channels || {};
        config.channels.signal = { phone };
        break;

      case "whatsapp":
        return res.status(501).json({ error: "WhatsApp requires QR flow" });

      default:
        return res.status(400).json({ error: `Unknown channel: ${channel}` });
    }

    writeConfig(userId, config);
    touchActivity(userId);

    console.log(`[channels] ${userId.slice(0, 8)}: Connected ${channel}`);
    res.json({ status: "configured", channel, message: "Channel configured" });
  } catch (error) {
    console.error(`[channels] Error connecting ${channel}:`, error.message);
    res.status(500).json({ error: error.message });
  }
});

// Disconnect a channel - removes from config file
router.post("/:userId/channels/:channel/disconnect", async (req, res) => {
  const { userId, channel } = req.params;
  const info = containers.get(userId);

  if (!info) {
    return res.status(404).json({ error: "Container not found" });
  }

  try {
    const config = readConfig(userId);

    if (config.channels && config.channels[channel]) {
      delete config.channels[channel];
      writeConfig(userId, config);
    }

    touchActivity(userId);
    console.log(`[channels] ${userId.slice(0, 8)}: Disconnected ${channel}`);
    res.json({ status: "disconnected", channel });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Set config value - writes directly to config file
router.post("/:userId/config", async (req, res) => {
  const { userId } = req.params;
  const { key, value } = req.body;
  const info = containers.get(userId);

  if (!info) {
    return res.status(404).json({ error: "Container not found" });
  }

  if (!key) {
    return res.status(400).json({ error: "Config key required" });
  }

  try {
    const config = readConfig(userId);

    // Support dot-notation keys like "channels.telegram.token"
    const parts = key.split(".");
    let current = config;

    for (let i = 0; i < parts.length - 1; i++) {
      if (!current[parts[i]]) {
        current[parts[i]] = {};
      }
      current = current[parts[i]];
    }

    const lastKey = parts[parts.length - 1];
    if (value === null || value === undefined) {
      delete current[lastKey];
    } else {
      current[lastKey] = value;
    }

    writeConfig(userId, config);
    touchActivity(userId);

    console.log(`[config] ${userId.slice(0, 8)}: ${key} = ${value ? "***" : "(unset)"}`);
    res.json({ status: "ok", key });
  } catch (error) {
    console.error(`[config] Error:`, error.message);
    res.status(500).json({ error: error.message });
  }
});

// Get config value - reads from config file
router.get("/:userId/config/:key", async (req, res) => {
  const { userId, key } = req.params;
  const info = containers.get(userId);

  if (!info) {
    return res.status(404).json({ error: "Container not found" });
  }

  try {
    const config = readConfig(userId);

    // Support dot-notation keys
    const parts = key.split(".");
    let current = config;

    for (const part of parts) {
      if (current && typeof current === "object") {
        current = current[part];
      } else {
        current = undefined;
        break;
      }
    }

    res.json({ key, value: current ?? null });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

export default router;
