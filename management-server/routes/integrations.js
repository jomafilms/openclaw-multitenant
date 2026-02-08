// Integration routes - API keys, OAuth status
import { Router } from "express";
import { users, audit, integrations } from "../db/index.js";
import { updateAgentContext } from "../lib/context.js";
import { requireUser } from "../middleware/auth.js";
import { detectTenant } from "../middleware/tenant-context.js";

const router = Router();

// List user's integrations (without secrets)
router.get("/", requireUser, detectTenant, async (req, res) => {
  try {
    const userIntegrations = await integrations.listForUser(req.user.id);
    res.json({ integrations: userIntegrations });
  } catch (err) {
    console.error("List integrations error:", err);
    res.status(500).json({ error: "Failed to list integrations" });
  }
});

// Add API key integration
router.post("/api-key", requireUser, detectTenant, async (req, res) => {
  try {
    const { provider, apiKey, metadata } = req.body;

    if (!provider || !apiKey) {
      return res.status(400).json({ error: "Provider and API key required" });
    }

    const validProviders = ["openai", "anthropic", "google", "github", "custom"];
    if (!validProviders.includes(provider)) {
      return res
        .status(400)
        .json({ error: `Invalid provider. Must be one of: ${validProviders.join(", ")}` });
    }

    const integration = await integrations.create({
      userId: req.user.id,
      provider,
      integrationType: "api_key",
      apiKey,
      metadata,
    });

    await audit.log(req.user.id, "integration.api_key_added", { provider }, req.ip);

    updateAgentContext(req.user.id).catch((err) => {
      console.error("Failed to update agent context:", err.message);
    });

    res.json({
      success: true,
      integration: {
        id: integration.id,
        provider: integration.provider,
        integration_type: integration.integration_type,
        status: integration.status,
        created_at: integration.created_at,
      },
    });
  } catch (err) {
    console.error("Add API key error:", err);
    res.status(500).json({ error: "Failed to add API key" });
  }
});

// Notify that a zero-knowledge API key was added (doesn't store the actual key)
router.post("/api-key/notify", requireUser, detectTenant, async (req, res) => {
  try {
    const { provider, zeroKnowledge } = req.body;

    if (!provider) {
      return res.status(400).json({ error: "Provider required" });
    }

    const validProviders = ["openai", "anthropic", "google", "github", "custom"];
    if (!validProviders.includes(provider)) {
      return res
        .status(400)
        .json({ error: `Invalid provider. Must be one of: ${validProviders.join(", ")}` });
    }

    // Create a metadata-only record (no actual API key stored)
    // This allows listing integrations without knowing the key value
    const integration = await integrations.create({
      userId: req.user.id,
      provider,
      integrationType: "api_key",
      apiKey: null, // No key stored - it's in the container vault
      metadata: { zeroKnowledge: true },
    });

    await audit.log(
      req.user.id,
      "integration.api_key_added_zk",
      { provider, zeroKnowledge: true },
      req.ip,
    );

    res.json({
      success: true,
      integration: {
        id: integration.id,
        provider: integration.provider,
        integration_type: integration.integration_type,
        status: integration.status,
        created_at: integration.created_at,
        zeroKnowledge: true,
      },
    });
  } catch (err) {
    console.error("API key notify error:", err);
    res.status(500).json({ error: "Failed to record API key notification" });
  }
});

// Delete integration
router.delete("/:provider", requireUser, detectTenant, async (req, res) => {
  try {
    const { provider } = req.params;

    await integrations.delete(req.user.id, provider);
    await audit.log(req.user.id, "integration.removed", { provider }, req.ip);

    updateAgentContext(req.user.id).catch((err) => {
      console.error("Failed to update agent context:", err.message);
    });

    res.json({ success: true });
  } catch (err) {
    console.error("Delete integration error:", err);
    res.status(500).json({ error: "Failed to delete integration" });
  }
});

// Get AI status (check if any AI keys configured)
router.get("/ai-status", requireUser, detectTenant, async (req, res) => {
  try {
    const anthropicKey = await integrations.getDecryptedTokens(req.user.id, "anthropic");
    const openaiKey = await integrations.getDecryptedTokens(req.user.id, "openai");

    res.json({
      anthropic: {
        hasKey: !!anthropicKey?.apiKey,
        source: anthropicKey?.apiKey ? "user" : process.env.ANTHROPIC_API_KEY ? "business" : null,
      },
      openai: {
        hasKey: !!openaiKey?.apiKey,
        source: openaiKey?.apiKey ? "user" : process.env.OPENAI_API_KEY ? "business" : null,
      },
    });
  } catch (err) {
    console.error("AI status error:", err);
    res.status(500).json({ error: "Failed to get AI status" });
  }
});

export default router;
