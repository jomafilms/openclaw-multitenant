/**
 * HTTP routes for direct browser-to-container vault unlock
 *
 * These routes proxy vault operations directly to the user's container,
 * bypassing the management server. The password is derived in the browser
 * and never passes through this server.
 *
 * This is an HTTP fallback for environments where WebSocket is not available.
 * The WebSocket proxy in lib/unlock-proxy.js is preferred when possible.
 */

import { Router } from "express";
import { proxyToContainer } from "../lib/unlock-proxy.js";

const router = Router();

// Get vault status
router.get("/:userId/vault/status", async (req, res) => {
  const { userId } = req.params;
  const result = await proxyToContainer(userId, "GET", "/vault/status");

  if (result.error) {
    return res.status(result.error === "Container not found" ? 404 : 503).json(result);
  }

  res.json(result);
});

// Get unlock challenge
// Browser will use this challenge to derive a response from the password
router.post("/:userId/vault/challenge", async (req, res) => {
  const { userId } = req.params;
  const result = await proxyToContainer(userId, "POST", "/vault/unlock/challenge");

  if (result.error) {
    return res.status(result.error === "Container not found" ? 404 : 503).json(result);
  }

  res.json(result);
});

// Verify unlock response
// Browser sends: { challengeId, response (HMAC), derivedKey }
// The password NEVER reaches this server - only the derived key proof
router.post("/:userId/vault/verify", async (req, res) => {
  const { userId } = req.params;
  const { challengeId, response, derivedKey } = req.body;

  if (!challengeId || !response || !derivedKey) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const result = await proxyToContainer(userId, "POST", "/vault/unlock/verify", {
    challengeId,
    response,
    derivedKey,
  });

  if (result.error) {
    return res.status(result.error === "Container not found" ? 404 : 503).json(result);
  }

  res.json(result);
});

// Lock vault
router.post("/:userId/vault/lock", async (req, res) => {
  const { userId } = req.params;
  const result = await proxyToContainer(userId, "POST", "/vault/lock");

  if (result.error) {
    return res.status(result.error === "Container not found" ? 404 : 503).json(result);
  }

  res.json(result);
});

// Extend vault session
router.post("/:userId/vault/extend", async (req, res) => {
  const { userId } = req.params;
  const result = await proxyToContainer(userId, "POST", "/vault/extend");

  if (result.error) {
    return res.status(result.error === "Container not found" ? 404 : 503).json(result);
  }

  res.json(result);
});

// ─────────────────────────────────────────────────────────────────────────────
// Session Vault Routes (encrypted session storage)
// The derived key goes directly to the container, never through management server
// ─────────────────────────────────────────────────────────────────────────────

// Get session vault status
router.get("/:userId/vault/session/status", async (req, res) => {
  const { userId } = req.params;
  const result = await proxyToContainer(userId, "GET", "/vault/session/status");

  if (result.error) {
    return res.status(result.error === "Container not found" ? 404 : 503).json(result);
  }

  res.json(result);
});

// Get session challenge (salt + KDF params)
// Browser uses these to derive the encryption key locally
router.get("/:userId/vault/session/challenge", async (req, res) => {
  const { userId } = req.params;
  const result = await proxyToContainer(userId, "GET", "/vault/session/challenge");

  if (result.error) {
    return res.status(result.error === "Container not found" ? 404 : 503).json(result);
  }

  res.json(result);
});

// Unlock session vault with derived key
// The password NEVER reaches this server - only the derived key
router.post("/:userId/vault/session/unlock", async (req, res) => {
  const { userId } = req.params;
  const { derivedKey } = req.body;

  if (!derivedKey) {
    return res.status(400).json({ error: "derivedKey required" });
  }

  const result = await proxyToContainer(userId, "POST", "/vault/session/unlock", {
    derivedKey,
  });

  if (result.error) {
    return res.status(result.error === "Container not found" ? 404 : 503).json(result);
  }

  res.json(result);
});

// Lock session vault
router.post("/:userId/vault/session/lock", async (req, res) => {
  const { userId } = req.params;
  const result = await proxyToContainer(userId, "POST", "/vault/session/lock");

  if (result.error) {
    return res.status(result.error === "Container not found" ? 404 : 503).json(result);
  }

  res.json(result);
});

// Extend session vault timeout
router.post("/:userId/vault/session/extend", async (req, res) => {
  const { userId } = req.params;
  const result = await proxyToContainer(userId, "POST", "/vault/session/extend");

  if (result.error) {
    return res.status(result.error === "Container not found" ? 404 : 503).json(result);
  }

  res.json(result);
});

// Migrate unencrypted sessions to encrypted format
router.post("/:userId/vault/session/migrate", async (req, res) => {
  const { userId } = req.params;
  const result = await proxyToContainer(userId, "POST", "/vault/session/migrate");

  if (result.error) {
    return res.status(result.error === "Container not found" ? 404 : 503).json(result);
  }

  res.json(result);
});

// ─────────────────────────────────────────────────────────────────────────────
// Biometric Routes (device-based vault unlock)
// Allows users to unlock vault using FaceID/TouchID instead of password
// ─────────────────────────────────────────────────────────────────────────────

// Enable biometric unlock for a device (requires vault to be unlocked)
router.post("/:userId/vault/biometrics/enable", async (req, res) => {
  const { userId } = req.params;
  const { fingerprint, name } = req.body;

  if (!fingerprint || !name) {
    return res.status(400).json({ error: "fingerprint and name required" });
  }

  const result = await proxyToContainer(userId, "POST", "/vault/biometrics/enable", {
    fingerprint,
    name,
  });

  if (result.error) {
    return res.status(result.error === "Container not found" ? 404 : 503).json(result);
  }

  res.json(result);
});

// Unlock vault using device key (biometric unlock)
router.post("/:userId/vault/biometrics/unlock", async (req, res) => {
  const { userId } = req.params;
  const { fingerprint, deviceKey } = req.body;

  if (!fingerprint || !deviceKey) {
    return res.status(400).json({ error: "fingerprint and deviceKey required" });
  }

  const result = await proxyToContainer(userId, "POST", "/vault/biometrics/unlock", {
    fingerprint,
    deviceKey,
  });

  if (result.error) {
    return res.status(result.error === "Container not found" ? 404 : 503).json(result);
  }

  res.json(result);
});

// List registered biometric devices (requires vault to be unlocked)
router.get("/:userId/vault/biometrics/devices", async (req, res) => {
  const { userId } = req.params;
  const result = await proxyToContainer(userId, "GET", "/vault/biometrics/devices");

  if (result.error) {
    return res.status(result.error === "Container not found" ? 404 : 503).json(result);
  }

  res.json(result);
});

// Remove a biometric device (requires vault to be unlocked)
router.delete("/:userId/vault/biometrics/devices/:fingerprint", async (req, res) => {
  const { userId, fingerprint } = req.params;
  const result = await proxyToContainer(
    userId,
    "DELETE",
    `/vault/biometrics/devices/${fingerprint}`,
  );

  if (result.error) {
    return res.status(result.error === "Container not found" ? 404 : 503).json(result);
  }

  res.json(result);
});

// ─────────────────────────────────────────────────────────────────────────────
// API Key Routes (zero-knowledge API key storage)
// Keys are stored in container vault, never touch management server
// ─────────────────────────────────────────────────────────────────────────────

// Store an API key in container vault (requires vault to be unlocked)
router.post("/:userId/vault/apikeys/:provider", async (req, res) => {
  const { userId, provider } = req.params;
  const { apiKey, metadata } = req.body;

  if (!apiKey) {
    return res.status(400).json({ error: "apiKey required" });
  }

  const result = await proxyToContainer(userId, "POST", `/apikeys/${provider}`, {
    apiKey,
    metadata,
  });

  if (result.error) {
    return res.status(result.error === "Container not found" ? 404 : 503).json(result);
  }

  res.json(result);
});

// Get an API key from container vault (requires vault to be unlocked)
router.get("/:userId/vault/apikeys/:provider", async (req, res) => {
  const { userId, provider } = req.params;
  const result = await proxyToContainer(userId, "GET", `/apikeys/${provider}`);

  if (result.error) {
    return res.status(result.error === "Container not found" ? 404 : 503).json(result);
  }

  res.json(result);
});

// List all API keys in container vault (requires vault to be unlocked)
router.get("/:userId/vault/apikeys", async (req, res) => {
  const { userId } = req.params;
  const result = await proxyToContainer(userId, "GET", "/apikeys");

  if (result.error) {
    return res.status(result.error === "Container not found" ? 404 : 503).json(result);
  }

  res.json(result);
});

// Check if an API key exists (requires vault to be unlocked)
router.get("/:userId/vault/apikeys/:provider/exists", async (req, res) => {
  const { userId, provider } = req.params;
  const result = await proxyToContainer(userId, "GET", `/apikeys/${provider}/exists`);

  if (result.error) {
    return res.status(result.error === "Container not found" ? 404 : 503).json(result);
  }

  res.json(result);
});

// Delete an API key from container vault (requires vault to be unlocked)
router.delete("/:userId/vault/apikeys/:provider", async (req, res) => {
  const { userId, provider } = req.params;
  const result = await proxyToContainer(userId, "DELETE", `/apikeys/${provider}`);

  if (result.error) {
    return res.status(result.error === "Container not found" ? 404 : 503).json(result);
  }

  res.json(result);
});

export default router;
