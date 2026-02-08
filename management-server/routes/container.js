import axios from "axios";
// Container management routes (wake, status, etc)
import { Router } from "express";
import { AGENT_SERVER_URL, AGENT_SERVER_TOKEN } from "../lib/context.js";
import { requireUser } from "../middleware/auth.js";
import { detectTenant } from "../middleware/tenant-context.js";

const router = Router();

// Wake container from hibernation
router.post("/wake", requireUser, detectTenant, async (req, res) => {
  if (!req.user.containerId) {
    return res.status(400).json({ error: "No container provisioned" });
  }

  try {
    const { reason = "user-request", timeout = 30000 } = req.body || {};
    const response = await axios.post(
      `${AGENT_SERVER_URL}/api/containers/${req.user.id}/wake`,
      { reason, timeout },
      { headers: { "x-auth-token": AGENT_SERVER_TOKEN }, timeout: timeout + 5000 },
    );
    res.json(response.data);
  } catch (err) {
    if (err.code === "ECONNABORTED" || err.response?.status === 504) {
      return res.status(504).json({
        error: "Wake timeout",
        message: "Container took too long to wake",
      });
    }
    console.error("Wake container error:", err.message);
    res.status(503).json({ error: "Failed to wake container" });
  }
});

// Get quick container status (cached, no Docker inspection)
router.get("/status", requireUser, detectTenant, async (req, res) => {
  if (!req.user.containerId) {
    return res.json({ exists: false, ready: false, hibernationState: "none" });
  }

  try {
    const response = await axios.get(
      `${AGENT_SERVER_URL}/api/containers/${req.user.id}/status/quick`,
      { headers: { "x-auth-token": AGENT_SERVER_TOKEN }, timeout: 5000 },
    );
    res.json(response.data);
  } catch (err) {
    if (err.response?.status === 404) {
      return res.json({ exists: false, ready: false, hibernationState: "none" });
    }
    console.error("Container status error:", err.message);
    res.status(503).json({ error: "Failed to get container status" });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Container Unlock Info (connection metadata only, no tokens)
// ─────────────────────────────────────────────────────────────────────────────

// Get unlock connection info for vault operations
// SECURITY: No longer returns AGENT_SERVER_TOKEN - use proxy endpoints instead
router.get("/unlock-info", requireUser, detectTenant, async (req, res) => {
  if (!req.user.containerId) {
    return res.status(404).json({ error: "No container provisioned" });
  }

  try {
    // Wake container if needed
    await axios.post(
      `${AGENT_SERVER_URL}/api/containers/${req.user.id}/wake`,
      { reason: "unlock", timeout: 10000 },
      { headers: { "x-auth-token": AGENT_SERVER_TOKEN }, timeout: 15000 },
    );

    // Return connection info - use management server proxy paths
    // SECURITY FIX: authToken is no longer exposed to client
    // All vault operations go through /api/container/vault/* proxy endpoints
    res.json({
      userId: req.user.id,
      // Use management server proxy paths instead of direct agent server
      proxyEnabled: true,
      vaultProxyPath: "/api/container/vault",
      // Legacy fields for backward compatibility (deprecated)
      agentServerUrl: null, // No longer exposed
      wsPath: null, // WebSocket now goes through management server
      httpPathPrefix: "/api/container/vault",
    });
  } catch (err) {
    if (err.code === "ECONNABORTED" || err.response?.status === 504) {
      return res.status(504).json({
        error: "Wake timeout",
        message: "Container took too long to wake for unlock",
      });
    }
    console.error("Get unlock info error:", err.message);
    res.status(503).json({ error: "Failed to prepare container for unlock" });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Vault Proxy Endpoints
// These endpoints proxy vault operations to the agent server, keeping the
// AGENT_SERVER_TOKEN server-side. The browser never sees the infrastructure token.
// ─────────────────────────────────────────────────────────────────────────────

// Proxy helper function
async function proxyVaultRequest(req, res, method, subpath, body = null) {
  const userId = req.user.id;
  const url = `${AGENT_SERVER_URL}/api/containers/${userId}/vault${subpath}`;

  try {
    const config = {
      method,
      url,
      headers: { "x-auth-token": AGENT_SERVER_TOKEN },
      timeout: 30000,
    };

    if (body) {
      config.data = body;
      config.headers["Content-Type"] = "application/json";
    }

    const response = await axios(config);
    res.json(response.data);
  } catch (err) {
    if (err.response) {
      // Forward error response from agent server
      res.status(err.response.status).json(err.response.data);
    } else if (err.code === "ECONNABORTED") {
      res.status(504).json({ error: "Request timeout" });
    } else {
      console.error("Vault proxy error:", err.message);
      res.status(503).json({ error: "Failed to communicate with container" });
    }
  }
}

// GET /api/container/vault/status - Get vault status
router.get("/vault/status", requireUser, detectTenant, async (req, res) => {
  if (!req.user.containerId) {
    return res.status(404).json({ error: "No container provisioned" });
  }
  await proxyVaultRequest(req, res, "GET", "/status");
});

// POST /api/container/vault/challenge - Get unlock challenge
router.post("/vault/challenge", requireUser, detectTenant, async (req, res) => {
  if (!req.user.containerId) {
    return res.status(404).json({ error: "No container provisioned" });
  }
  await proxyVaultRequest(req, res, "POST", "/challenge");
});

// POST /api/container/vault/verify - Verify unlock response
router.post("/vault/verify", requireUser, detectTenant, async (req, res) => {
  if (!req.user.containerId) {
    return res.status(404).json({ error: "No container provisioned" });
  }
  await proxyVaultRequest(req, res, "POST", "/verify", req.body);
});

// POST /api/container/vault/lock - Lock the vault
router.post("/vault/lock", requireUser, detectTenant, async (req, res) => {
  if (!req.user.containerId) {
    return res.status(404).json({ error: "No container provisioned" });
  }
  await proxyVaultRequest(req, res, "POST", "/lock");
});

// POST /api/container/vault/extend - Extend vault session
router.post("/vault/extend", requireUser, detectTenant, async (req, res) => {
  if (!req.user.containerId) {
    return res.status(404).json({ error: "No container provisioned" });
  }
  await proxyVaultRequest(req, res, "POST", "/extend");
});

// ─────────────────────────────────────────────────────────────────────────────
// Session Vault Proxy Endpoints (encrypted session storage)
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/container/vault/session/status - Get session vault status
router.get("/vault/session/status", requireUser, detectTenant, async (req, res) => {
  if (!req.user.containerId) {
    return res.status(404).json({ error: "No container provisioned" });
  }
  await proxyVaultRequest(req, res, "GET", "/session/status");
});

// GET /api/container/vault/session/challenge - Get session challenge
router.get("/vault/session/challenge", requireUser, detectTenant, async (req, res) => {
  if (!req.user.containerId) {
    return res.status(404).json({ error: "No container provisioned" });
  }
  await proxyVaultRequest(req, res, "GET", "/session/challenge");
});

// POST /api/container/vault/session/unlock - Unlock session vault
router.post("/vault/session/unlock", requireUser, detectTenant, async (req, res) => {
  if (!req.user.containerId) {
    return res.status(404).json({ error: "No container provisioned" });
  }
  await proxyVaultRequest(req, res, "POST", "/session/unlock", req.body);
});

// POST /api/container/vault/session/lock - Lock session vault
router.post("/vault/session/lock", requireUser, detectTenant, async (req, res) => {
  if (!req.user.containerId) {
    return res.status(404).json({ error: "No container provisioned" });
  }
  await proxyVaultRequest(req, res, "POST", "/session/lock");
});

// POST /api/container/vault/session/extend - Extend session vault
router.post("/vault/session/extend", requireUser, detectTenant, async (req, res) => {
  if (!req.user.containerId) {
    return res.status(404).json({ error: "No container provisioned" });
  }
  await proxyVaultRequest(req, res, "POST", "/session/extend");
});

// POST /api/container/vault/session/migrate - Migrate sessions to encrypted
router.post("/vault/session/migrate", requireUser, detectTenant, async (req, res) => {
  if (!req.user.containerId) {
    return res.status(404).json({ error: "No container provisioned" });
  }
  await proxyVaultRequest(req, res, "POST", "/session/migrate");
});

// ─────────────────────────────────────────────────────────────────────────────
// API Key Vault Proxy Endpoints (for zero-knowledge API key storage)
// ─────────────────────────────────────────────────────────────────────────────

// POST /api/container/vault/apikeys/:provider - Store API key
router.post("/vault/apikeys/:provider", requireUser, detectTenant, async (req, res) => {
  if (!req.user.containerId) {
    return res.status(404).json({ error: "No container provisioned" });
  }
  await proxyVaultRequest(req, res, "POST", `/apikeys/${req.params.provider}`, req.body);
});

// DELETE /api/container/vault/apikeys/:provider - Delete API key
router.delete("/vault/apikeys/:provider", requireUser, detectTenant, async (req, res) => {
  if (!req.user.containerId) {
    return res.status(404).json({ error: "No container provisioned" });
  }
  await proxyVaultRequest(req, res, "DELETE", `/apikeys/${req.params.provider}`);
});

export default router;
