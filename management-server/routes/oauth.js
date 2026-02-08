import axios from "axios";
import crypto from "crypto";
// OAuth routes - Google OAuth flow with zero-knowledge PKCE
// Tokens NEVER pass through this server - container exchanges directly
import { Router } from "express";
import { users, audit, integrations, meshAuditLogs, MESH_AUDIT_EVENTS } from "../db/index.js";
import { updateAgentContext, AGENT_SERVER_URL, AGENT_SERVER_TOKEN } from "../lib/context.js";
import { getRedisClient, isRedisConnected } from "../lib/redis.js";
import { vaultSessions } from "../lib/vault-sessions.js";
import { requireUser } from "../middleware/auth.js";
import { detectTenant } from "../middleware/tenant-context.js";

const router = Router();

const USER_UI_URL = process.env.USER_UI_URL || "http://localhost:5173";
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_REDIRECT_URI = `${process.env.BASE_URL || "http://localhost:3000"}/api/oauth/google/callback`;

// Google Drive scope levels - user can choose their permission level
const DRIVE_SCOPE_LEVELS = {
  minimal: {
    name: "Minimal",
    description: "Read-only access to files you select",
    scopes: ["https://www.googleapis.com/auth/drive.file"],
    capabilities: ["Read files you explicitly open", "Cannot browse or search Drive"],
  },
  standard: {
    name: "Standard",
    description: "Read and write access to Drive files",
    scopes: [
      "https://www.googleapis.com/auth/drive.file",
      "https://www.googleapis.com/auth/drive.readonly",
    ],
    capabilities: ["Read all files", "Create and edit files you create", "Search Drive"],
  },
  full: {
    name: "Full",
    description: "Full access to all Drive operations",
    scopes: ["https://www.googleapis.com/auth/drive"],
    capabilities: [
      "Read all files",
      "Create, edit, and delete any file",
      "Manage permissions",
      "Full Drive access",
    ],
  },
};

// PKCE flow storage with Redis fallback to in-memory for local development
const PKCE_TTL_SECONDS = 600; // 10 minutes
const PKCE_FLOW_PREFIX = "oauth:pkce:";

// In-memory fallback when Redis is not configured
const memoryPkceFlows = new Map();

// Cleanup expired flows (only needed for in-memory fallback)
setInterval(() => {
  if (isRedisConnected()) {
    return;
  } // Redis handles expiry via TTL
  const now = Date.now();
  for (const [state, data] of memoryPkceFlows.entries()) {
    if (now - data.createdAt > PKCE_TTL_SECONDS * 1000) {
      memoryPkceFlows.delete(state);
    }
  }
}, 60_000);

/**
 * Store PKCE flow data in Redis or memory
 */
async function setPkceFlow(state, data) {
  const redis = getRedisClient();
  if (redis && isRedisConnected()) {
    try {
      await redis.setex(`${PKCE_FLOW_PREFIX}${state}`, PKCE_TTL_SECONDS, JSON.stringify(data));
      return;
    } catch (err) {
      console.warn("[oauth] Redis setex failed, falling back to memory:", err.message);
    }
  }
  // Fallback to in-memory
  memoryPkceFlows.set(state, {
    ...data,
    createdAt: Date.now(),
  });
}

/**
 * Get and delete PKCE flow data (consume the token)
 */
async function getAndDeletePkceFlow(state) {
  const redis = getRedisClient();
  if (redis && isRedisConnected()) {
    try {
      const key = `${PKCE_FLOW_PREFIX}${state}`;
      // Use GETDEL for atomic get-and-delete (Redis 6.2+)
      // Fall back to GET + DEL for older versions
      let dataStr;
      try {
        dataStr = await redis.getdel(key);
      } catch {
        // GETDEL not available, use GET + DEL
        dataStr = await redis.get(key);
        if (dataStr) {
          await redis.del(key);
        }
      }
      if (dataStr) {
        return JSON.parse(dataStr);
      }
      return null;
    } catch (err) {
      console.warn("[oauth] Redis get failed, checking memory fallback:", err.message);
    }
  }
  // Fallback to in-memory
  const data = memoryPkceFlows.get(state);
  if (!data) {
    return null;
  }
  memoryPkceFlows.delete(state);
  // Check expiry for in-memory data
  if (Date.now() - data.createdAt > PKCE_TTL_SECONDS * 1000) {
    return null;
  }
  return data;
}

// Get available Drive scope options (for UI)
router.get("/google/drive/scope-options", requireUser, detectTenant, (req, res) => {
  const options = Object.entries(DRIVE_SCOPE_LEVELS).map(([level, config]) => ({
    level,
    name: config.name,
    description: config.description,
    capabilities: config.capabilities,
  }));
  res.json({ options });
});

// Start Google OAuth flow with PKCE
router.get("/google/start", requireUser, detectTenant, async (req, res) => {
  if (!GOOGLE_CLIENT_ID) {
    return res.status(503).json({ error: "Google OAuth not configured" });
  }

  const userId = req.user.id;

  const hasVault = await users.hasVault(userId);
  if (!hasVault) {
    return res.redirect(`${USER_UI_URL}/vault/setup?reason=oauth&next=/connections`);
  }

  const vaultSessionToken = req.cookies?.ocmt_vault_session || req.headers["x-vault-session"];
  const vaultSession = vaultSessionToken ? vaultSessions.get(vaultSessionToken) : null;
  if (!vaultSession || vaultSession.userId !== userId || vaultSession.expiresAt <= Date.now()) {
    return res.redirect(`${USER_UI_URL}/connections?needsUnlock=google`);
  }

  const { scope, scopeLevel } = req.query;

  // Determine provider name for the integration
  const provider =
    scope === "calendar"
      ? "google_calendar"
      : scope === "gmail"
        ? "google_gmail"
        : scope === "drive"
          ? "google_drive"
          : "google";

  // Determine scope level for drive
  const driveScopeLevel =
    scope === "drive"
      ? scopeLevel && DRIVE_SCOPE_LEVELS[scopeLevel]
        ? scopeLevel
        : "minimal"
      : null;

  try {
    // Initialize PKCE with agent-server - container generates the verifier
    const pkceResponse = await axios.post(
      `${AGENT_SERVER_URL}/api/containers/${userId}/oauth/pkce/init`,
      {
        provider,
        scope: scope || "profile",
        scopeLevel: driveScopeLevel,
      },
      {
        headers: { "x-auth-token": AGENT_SERVER_TOKEN },
        timeout: 10000,
      },
    );

    const { stateToken: pkceStateToken, codeChallenge, codeChallengeMethod } = pkceResponse.data;

    // Generate our own state token for the callback
    const ourState = crypto.randomBytes(16).toString("hex");

    // Store mapping
    await setPkceFlow(ourState, {
      userId,
      pkceStateToken,
      scope: scope || "profile",
      scopeLevel: driveScopeLevel,
      provider,
      vaultSessionToken,
      createdAt: Date.now(),
    });

    // Build scopes
    let scopes = ["openid", "email", "profile"];
    if (scope === "calendar") {
      scopes.push("https://www.googleapis.com/auth/calendar");
    } else if (scope === "gmail") {
      scopes.push("https://www.googleapis.com/auth/gmail.modify");
    } else if (scope === "drive") {
      const level = driveScopeLevel || "minimal";
      scopes.push(...DRIVE_SCOPE_LEVELS[level].scopes);
    }

    // Build auth URL with PKCE code_challenge
    const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    authUrl.searchParams.set("client_id", GOOGLE_CLIENT_ID);
    authUrl.searchParams.set("redirect_uri", GOOGLE_REDIRECT_URI);
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("scope", scopes.join(" "));
    authUrl.searchParams.set("access_type", "offline");
    authUrl.searchParams.set("prompt", "consent");
    authUrl.searchParams.set("state", ourState);
    // PKCE parameters
    authUrl.searchParams.set("code_challenge", codeChallenge);
    authUrl.searchParams.set("code_challenge_method", codeChallengeMethod);

    console.log(`[oauth] Started PKCE flow for user ${userId.slice(0, 8)}, provider: ${provider}`);

    res.redirect(authUrl.toString());
  } catch (err) {
    console.error("Failed to initialize PKCE:", err.message);
    return res.redirect(`${USER_UI_URL}/connections?error=pkce_init_failed`);
  }
});

// Google OAuth callback - forwards auth code to container (NEVER exchanges tokens)
router.get("/google/callback", async (req, res) => {
  try {
    const { code, state, error } = req.query;

    if (error) {
      return res.redirect(`${USER_UI_URL}/connections?error=${encodeURIComponent(error)}`);
    }

    if (!code || !state) {
      return res.redirect(`${USER_UI_URL}/connections?error=missing_params`);
    }

    // Get our pending PKCE flow
    const flowData = await getAndDeletePkceFlow(state);
    if (!flowData) {
      return res.redirect(`${USER_UI_URL}/connections?error=invalid_state`);
    }

    const { userId, pkceStateToken, scope, scopeLevel, provider, vaultSessionToken } = flowData;

    // Verify vault session is still valid
    const vaultSession = vaultSessionToken ? vaultSessions.get(vaultSessionToken) : null;
    if (!vaultSession || vaultSession.userId !== userId || vaultSession.expiresAt <= Date.now()) {
      return res.redirect(`${USER_UI_URL}/connections?error=vault_locked`);
    }

    // Forward auth code to agent-server for token exchange
    // TOKENS NEVER TOUCH THIS SERVER - container exchanges directly with Google
    let exchangeResult;
    try {
      const exchangeResponse = await axios.post(
        `${AGENT_SERVER_URL}/api/containers/${userId}/oauth/pkce/exchange`,
        {
          stateToken: pkceStateToken,
          authCode: code,
          redirectUri: GOOGLE_REDIRECT_URI,
        },
        {
          headers: { "x-auth-token": AGENT_SERVER_TOKEN },
          timeout: 30000,
        },
      );
      exchangeResult = exchangeResponse.data;
    } catch (exchangeErr) {
      console.error(
        "PKCE token exchange failed:",
        exchangeErr.response?.data || exchangeErr.message,
      );
      return res.redirect(`${USER_UI_URL}/connections?error=token_exchange_failed`);
    }

    const { email: providerEmail } = exchangeResult;

    // Store metadata only in integrations table (NO tokens - they're in container)
    const metadata = {
      scope,
      storedInVault: true,
      zeroKnowledge: true,
      pkceExchange: true,
    };
    if (scopeLevel) {
      metadata.scopeLevel = scopeLevel;
      metadata.scopeLevelName = DRIVE_SCOPE_LEVELS[scopeLevel]?.name || scopeLevel;
    }

    await integrations.create({
      userId,
      provider,
      integrationType: "oauth",
      accessToken: null, // Never stored here
      refreshToken: null, // Never stored here
      tokenExpiresAt: null, // Container manages expiry
      providerEmail,
      metadata,
    });

    await audit.log(
      userId,
      "integration.oauth_connected",
      { provider, email: providerEmail, zeroKnowledge: true, pkce: true },
      req.ip,
    );

    // Log to mesh audit
    await meshAuditLogs.log({
      eventType: MESH_AUDIT_EVENTS.INTEGRATION_CONNECTED,
      actorId: userId,
      ipAddress: req.ip,
      success: true,
      details: {
        provider,
        providerEmail,
        scope,
        scopeLevel: scopeLevel || null,
        zeroKnowledge: true,
        pkce: true,
      },
    });

    // Update agent context (metadata only)
    updateAgentContext(userId).catch((err) => {
      console.error("Failed to update agent context:", err.message);
    });

    console.log(
      `[oauth] PKCE flow complete for user ${userId.slice(0, 8)}, provider: ${provider} - tokens never touched this server`,
    );

    res.redirect(`${USER_UI_URL}/connections?success=${provider}`);
  } catch (err) {
    console.error("Google OAuth callback error:", err);
    res.redirect(`${USER_UI_URL}/connections?error=oauth_failed`);
  }
});

export default router;
