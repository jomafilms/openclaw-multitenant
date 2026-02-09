// MCP Protocol endpoint for agent containers
import { Router } from "express";
import { users } from "../db/index.js";
import { decryptGatewayToken, generateEphemeralToken } from "../lib/gateway-tokens.js";
import { MCP_TOOLS, handleMcpToolCall, requireContainerAuth } from "../lib/mcp.js";

const router = Router();

/**
 * MCP Protocol Handler
 * Implements MCP JSON-RPC style protocol over HTTP
 */
router.post("/", requireContainerAuth, async (req, res) => {
  try {
    // Debug logging for MCP calls (method only - never log params to protect user privacy)
    if (process.env.DEBUG_MCP) {
      console.log("[mcp] method:", req.body?.method);
    }

    const { method, params, id } = req.body;
    const userId = req.userId;

    // SECURITY: Vault session tokens MUST be explicitly provided via header.
    // Never auto-discover sessions - this would bypass the explicit unlock requirement.
    // Tools requiring vault access will return appropriate errors if no token is provided.
    const vaultSessionToken = req.headers["x-vault-session"] || null;

    // Handle different MCP methods
    if (method === "initialize") {
      return res.json({
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2024-11-05",
          serverInfo: { name: "ocmt", version: "1.0.0" },
          capabilities: { tools: {} },
        },
      });
    }

    if (method === "tools/list") {
      return res.json({
        jsonrpc: "2.0",
        id,
        result: { tools: MCP_TOOLS },
      });
    }

    if (method === "tools/call") {
      const { name, arguments: args } = params || {};
      if (!name) {
        return res.json({
          jsonrpc: "2.0",
          id,
          error: { code: -32602, message: "Tool name required" },
        });
      }

      try {
        const result = await handleMcpToolCall(name, args, userId, vaultSessionToken);
        return res.json({
          jsonrpc: "2.0",
          id,
          result: { content: [{ type: "text", text: JSON.stringify(result) }] },
        });
      } catch (toolErr) {
        return res.json({
          jsonrpc: "2.0",
          id,
          error: { code: -32000, message: toolErr.message },
        });
      }
    }

    res.json({
      jsonrpc: "2.0",
      id,
      error: { code: -32601, message: `Method not found: ${method}` },
    });
  } catch (err) {
    console.error("MCP handler error:", err);
    res.json({
      jsonrpc: "2.0",
      id: req.body?.id,
      error: { code: -32603, message: "Internal error" },
    });
  }
});

/**
 * Token Refresh Endpoint
 * Allows containers to refresh their ephemeral gateway tokens
 *
 * Requires valid (but possibly near-expiring) token to get a new one.
 * This prevents needing to store the permanent token in the container.
 */
router.post("/refresh-token", requireContainerAuth, async (req, res) => {
  try {
    const userId = req.userId;

    // Get user to access stored permanent token
    const user = await users.findById(userId);
    if (!user || !user.gateway_token) {
      return res.status(403).json({ error: "User not found or no gateway token" });
    }

    // Decrypt the permanent token
    let permanentToken;
    try {
      permanentToken = decryptGatewayToken(user.gateway_token);
    } catch {
      // Legacy unencrypted token
      permanentToken = user.gateway_token;
    }

    // Generate new ephemeral token (1 hour validity)
    const newToken = generateEphemeralToken(userId, permanentToken, 3600);

    res.json({
      success: true,
      token: newToken,
      expiresIn: 3600,
      message: "Token refreshed successfully",
    });
  } catch (err) {
    console.error("[mcp] Token refresh error:", err.message);
    res.status(500).json({ error: "Token refresh failed" });
  }
});

export default router;
