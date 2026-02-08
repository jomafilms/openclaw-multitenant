// agent-server/routes/oauth-pkce.js
// Zero-knowledge OAuth with PKCE - tokens never touch management server
// Container generates PKCE verifier, exchanges auth code directly with provider

import axios from "axios";
import crypto from "crypto";
import { Router } from "express";
import { containers } from "../lib/containers.js";

const router = Router();

// In-memory PKCE state storage per container
// Key: stateToken, Value: { userId, codeVerifier, provider, scope, createdAt }
const pkceStates = new Map();
const PKCE_STATE_EXPIRY = 10 * 60 * 1000; // 10 minutes

// Cleanup expired PKCE states
setInterval(() => {
  const now = Date.now();
  for (const [state, data] of pkceStates.entries()) {
    if (now - data.createdAt > PKCE_STATE_EXPIRY) {
      pkceStates.delete(state);
    }
  }
}, 60_000);

/**
 * Generate PKCE code_verifier and code_challenge
 * Uses SHA-256 for the challenge (S256 method)
 */
function generatePKCE() {
  // code_verifier: 43-128 character random string
  const codeVerifier = crypto.randomBytes(32).toString("base64url");

  // code_challenge: SHA-256 hash of verifier, base64url encoded
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

  return { codeVerifier, codeChallenge };
}

/**
 * POST /:userId/oauth/pkce/init
 * Initialize PKCE OAuth flow - container generates verifier
 * Returns code_challenge for management server to include in auth URL
 */
router.post("/:userId/oauth/pkce/init", async (req, res) => {
  const { userId } = req.params;
  const { provider, scope, scopeLevel } = req.body;

  if (!provider) {
    return res.status(400).json({ error: "Provider required" });
  }

  // Verify container exists
  const container = containers.get(userId);
  if (!container) {
    return res.status(404).json({ error: "Container not found" });
  }

  // Generate PKCE parameters
  const { codeVerifier, codeChallenge } = generatePKCE();

  // Generate state token
  const stateToken = crypto.randomBytes(32).toString("hex");

  // Store PKCE state
  pkceStates.set(stateToken, {
    userId,
    codeVerifier,
    provider,
    scope: scope || "profile",
    scopeLevel: scopeLevel || null,
    createdAt: Date.now(),
  });

  console.log(
    `[oauth-pkce] Initialized PKCE for user ${userId.slice(0, 8)}, provider: ${provider}`,
  );

  res.json({
    stateToken,
    codeChallenge,
    codeChallengeMethod: "S256",
  });
});

/**
 * POST /:userId/oauth/pkce/exchange
 * Exchange auth code for tokens - done directly by container
 * Management server only forwards the auth_code, never sees tokens
 */
router.post("/:userId/oauth/pkce/exchange", async (req, res) => {
  const { userId } = req.params;
  const { stateToken, authCode, redirectUri } = req.body;

  if (!stateToken || !authCode) {
    return res.status(400).json({ error: "stateToken and authCode required" });
  }

  // Get and consume PKCE state
  const pkceState = pkceStates.get(stateToken);
  if (!pkceState) {
    return res.status(400).json({ error: "Invalid or expired state token" });
  }
  pkceStates.delete(stateToken);

  // Verify state belongs to this user
  if (pkceState.userId !== userId) {
    return res.status(403).json({ error: "State token user mismatch" });
  }

  const { codeVerifier, provider, scope, scopeLevel } = pkceState;

  try {
    let tokens;
    let providerEmail = null;

    if (provider.startsWith("google")) {
      tokens = await exchangeGoogleToken(authCode, codeVerifier, redirectUri);
      providerEmail = await getGoogleUserEmail(tokens.access_token);
    } else {
      return res.status(400).json({ error: `Unsupported provider: ${provider}` });
    }

    // Store tokens in container's vault
    const container = containers.get(userId);
    if (!container) {
      return res.status(404).json({ error: "Container not found" });
    }

    // Write tokens to container's secrets file
    // The container will encrypt these with the user's vault key
    const credentialData = {
      provider,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      expiresAt: new Date(Date.now() + (tokens.expires_in || 3600) * 1000).toISOString(),
      email: providerEmail,
      scope,
      scopeLevel,
      connectedAt: new Date().toISOString(),
      zeroKnowledge: true,
    };

    // Store credential in container (will be vault-encrypted)
    await storeCredentialInContainer(container, provider, credentialData);

    console.log(
      `[oauth-pkce] Token exchange complete for user ${userId.slice(0, 8)}, provider: ${provider}`,
    );

    res.json({
      success: true,
      provider,
      email: providerEmail,
      scope,
      scopeLevel,
    });
  } catch (err) {
    console.error(`[oauth-pkce] Token exchange failed:`, err.message);
    res.status(500).json({
      error: "Token exchange failed",
      message: err.response?.data?.error_description || err.message,
    });
  }
});

/**
 * Exchange Google OAuth code for tokens using PKCE
 */
async function exchangeGoogleToken(code, codeVerifier, redirectUri) {
  // Google OAuth token endpoint supports PKCE
  const response = await axios.post(
    "https://oauth2.googleapis.com/token",
    {
      code,
      code_verifier: codeVerifier,
      redirect_uri: redirectUri,
      grant_type: "authorization_code",
      // Note: client_id is still needed but client_secret is NOT needed with PKCE
      // However, for web apps Google still requires client_secret even with PKCE
      // We'll use a minimal client_id that's safe to embed
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
    },
    {
      timeout: 10000,
    },
  );

  return response.data;
}

/**
 * Get Google user's email from access token
 */
async function getGoogleUserEmail(accessToken) {
  try {
    const response = await axios.get("https://www.googleapis.com/oauth2/v2/userinfo", {
      headers: { Authorization: `Bearer ${accessToken}` },
      timeout: 10000,
    });
    return response.data.email;
  } catch (err) {
    console.error(`[oauth-pkce] Failed to get user email:`, err.message);
    return null;
  }
}

/**
 * Store OAuth credential in container's vault
 */
async function storeCredentialInContainer(container, provider, credentialData) {
  const axios = (await import("axios")).default;

  // Call container's internal credential storage endpoint
  // This writes to the container's encrypted secrets store
  await axios.post(
    `http://localhost:${container.port}/internal/credentials`,
    {
      provider,
      credential: credentialData,
    },
    {
      timeout: 10000,
      headers: { "x-internal-token": container.internalToken },
    },
  );
}

/**
 * POST /:userId/oauth/pkce/refresh
 * Refresh an OAuth token - done directly by container
 */
router.post("/:userId/oauth/pkce/refresh", async (req, res) => {
  const { userId } = req.params;
  const { provider, refreshToken } = req.body;

  if (!provider || !refreshToken) {
    return res.status(400).json({ error: "provider and refreshToken required" });
  }

  try {
    let tokens;

    if (provider.startsWith("google")) {
      tokens = await refreshGoogleToken(refreshToken);
    } else {
      return res.status(400).json({ error: `Unsupported provider: ${provider}` });
    }

    console.log(
      `[oauth-pkce] Token refresh complete for user ${userId.slice(0, 8)}, provider: ${provider}`,
    );

    res.json({
      success: true,
      accessToken: tokens.access_token,
      expiresIn: tokens.expires_in,
      expiresAt: new Date(Date.now() + (tokens.expires_in || 3600) * 1000).toISOString(),
    });
  } catch (err) {
    console.error(`[oauth-pkce] Token refresh failed:`, err.message);
    res.status(500).json({
      error: "Token refresh failed",
      message: err.response?.data?.error_description || err.message,
    });
  }
});

/**
 * Refresh Google OAuth token
 */
async function refreshGoogleToken(refreshToken) {
  const response = await axios.post(
    "https://oauth2.googleapis.com/token",
    {
      refresh_token: refreshToken,
      grant_type: "refresh_token",
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
    },
    {
      timeout: 10000,
    },
  );

  return response.data;
}

export default router;
export { pkceStates };
