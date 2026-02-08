/**
 * OCMT MCP Endpoint
 * Add this to your management-server/server.js
 *
 * Provides vault and integration tools to OpenClaw containers via HTTP MCP
 */

// =============================================================================
// MCP Tool Definitions
// =============================================================================

const MCP_TOOLS = [
  {
    name: "ocmt_vault_status",
    description: "Check if the user's vault is currently unlocked",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "ocmt_unlock_link",
    description: "Generate a magic link for the user to unlock their vault",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "ocmt_integrations",
    description: "List all connected integrations and their status",
    inputSchema: {
      type: "object",
      properties: {
        provider: {
          type: "string",
          description: "Optional: filter by provider (google, microsoft, etc)",
        },
      },
      required: [],
    },
  },
  {
    name: "ocmt_extend_session",
    description: "Extend the vault session during active conversation",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
];

// =============================================================================
// Tool Handlers
// =============================================================================

async function handleToolCall(toolName, params, userId, db) {
  switch (toolName) {
    case "ocmt_vault_status": {
      const session = await db.getVaultSession(userId);
      if (!session || !session.unlockedAt) {
        return { locked: true, expiresIn: null };
      }
      const expiresAt = new Date(session.expiresAt);
      const now = new Date();
      if (expiresAt <= now) {
        return { locked: true, expiresIn: null };
      }
      return {
        locked: false,
        expiresIn: Math.floor((expiresAt - now) / 1000),
      };
    }

    case "ocmt_unlock_link": {
      const token = await db.createUnlockToken(userId, {
        expiresIn: "15m",
        purpose: "vault-unlock",
      });
      // Use your actual domain here
      const baseUrl = process.env.OCMT_BASE_URL || "https://YOUR_DOMAIN";
      return {
        url: `${baseUrl}/unlock?t=${token}`,
        expiresIn: 900, // 15 minutes
      };
    }

    case "ocmt_integrations": {
      const integrations = await db.getUserIntegrations(userId);
      const { provider } = params || {};

      let results = integrations.map((int) => ({
        provider: int.provider,
        status: int.status, // 'connected' | 'expired' | 'error'
        needsReauth: int.status !== "connected",
        reconnectUrl:
          int.status !== "connected"
            ? `${process.env.OCMT_BASE_URL}/connect/${int.provider}?userId=${userId}`
            : null,
        lastSync: int.lastSyncAt,
        scopes: int.scopes,
      }));

      if (provider) {
        results = results.filter((r) => r.provider === provider);
      }

      return { integrations: results };
    }

    case "ocmt_extend_session": {
      const session = await db.getVaultSession(userId);
      if (!session || session.locked) {
        return {
          success: false,
          error: "Vault is locked",
          needsUnlock: true,
        };
      }

      // Extend by 30 minutes
      const newExpiry = new Date(Date.now() + 30 * 60 * 1000);
      await db.updateVaultSession(userId, { expiresAt: newExpiry });

      return {
        success: true,
        expiresIn: 1800, // 30 minutes
      };
    }

    default:
      throw new Error(`Unknown tool: ${toolName}`);
  }
}

// =============================================================================
// MCP HTTP Endpoint
// =============================================================================

/**
 * Express middleware for internal auth
 * Validates container tokens
 */
function requireInternalAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  const userId = req.headers["x-user-id"];

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing authorization" });
  }

  const token = authHeader.slice(7);

  // Validate container token against your database
  // This token was generated at container provisioning time
  const isValid = validateContainerToken(token, userId);

  if (!isValid) {
    return res.status(403).json({ error: "Invalid container token" });
  }

  req.userId = userId;
  next();
}

/**
 * MCP Protocol Handler
 *
 * Implements the MCP JSON-RPC style protocol over HTTP
 *
 * Usage in Express:
 *   app.post('/api/mcp', requireInternalAuth, mcpHandler(db));
 */
function mcpHandler(db) {
  return async (req, res) => {
    try {
      const { method, params, id } = req.body;
      const userId = req.userId;

      let result;

      switch (method) {
        case "tools/list":
          result = { tools: MCP_TOOLS };
          break;

        case "tools/call":
          const { name, arguments: args } = params;
          if (!name) {
            return res.status(400).json({
              jsonrpc: "2.0",
              id,
              error: { code: -32602, message: "Missing tool name" },
            });
          }
          result = await handleToolCall(name, args || {}, userId, db);
          break;

        case "initialize":
          result = {
            protocolVersion: "2024-11-05",
            serverInfo: {
              name: "ocmt-vault",
              version: "1.0.0",
            },
            capabilities: {
              tools: {},
            },
          };
          break;

        default:
          return res.status(400).json({
            jsonrpc: "2.0",
            id,
            error: { code: -32601, message: `Unknown method: ${method}` },
          });
      }

      res.json({
        jsonrpc: "2.0",
        id,
        result,
      });
    } catch (error) {
      console.error("MCP error:", error);
      res.status(500).json({
        jsonrpc: "2.0",
        id: req.body?.id,
        error: {
          code: -32603,
          message: error.message,
        },
      });
    }
  };
}

// =============================================================================
// Express Setup Example
// =============================================================================

/*
// In your management-server/server.js:

const express = require('express');
const app = express();

app.use(express.json());

// Your database/services
const db = require('./db');

// Mount the MCP endpoint
app.post('/api/mcp', requireInternalAuth, mcpHandler(db));

// Unlock link handler (user clicks this)
app.get('/unlock', async (req, res) => {
  const { t: token } = req.query;

  try {
    const { userId } = await db.validateUnlockToken(token);
    await db.unlockVault(userId, { expiresIn: '2h' });

    // Redirect to success page or back to chat
    res.redirect('/unlocked');
  } catch (err) {
    res.status(400).send('Invalid or expired link');
  }
});
*/

// =============================================================================
// Exports
// =============================================================================

module.exports = {
  MCP_TOOLS,
  handleToolCall,
  requireInternalAuth,
  mcpHandler,
};
