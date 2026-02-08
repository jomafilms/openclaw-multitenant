// group-vault/server.js
// Minimal HTTP API for group vault operations
// No agent, no chat capability - just secure secret storage

import crypto from "crypto";
import express from "express";
import audit from "./lib/audit.js";
import {
  initAuth,
  issueCapabilityToken,
  verifyCapabilityToken,
  checkAccess,
  revokeToken,
  revokeUserTokens,
} from "./lib/auth.js";
import { vaultUnlockLimiter, tokenIssuanceLimiter } from "./lib/rate-limit.js";
import {
  validate,
  initGroupVaultSchema,
  unlockGroupVaultSchema,
  lockVaultSchema,
  issueTokenSchema,
  revokeTokenSchema,
  storeSecretSchema,
  secretKeyParamSchema,
  tokenIdParamSchema,
  userIdParamSchema,
} from "./lib/schemas.js";
import {
  createGroupVault,
  unlockGroupVault,
  updateGroupVault,
  isValidGroupVault,
  createVaultSession,
  getVaultSession,
  deleteVaultSession,
  extendVaultSession,
  VAULT_SESSION_TIMEOUT_MS,
} from "./lib/vault.js";

const app = express();
app.use(express.json());

// Configuration
const PORT = process.env.PORT || 18790;
const GROUP_ID = process.env.GROUP_ID;
const AUTH_TOKEN = process.env.AUTH_TOKEN; // For management API auth
const SIGNING_KEY = process.env.SIGNING_KEY || crypto.randomBytes(32).toString("hex");

if (!GROUP_ID) {
  console.error("GROUP_ID environment variable is required");
  process.exit(1);
}

if (!AUTH_TOKEN) {
  console.error("AUTH_TOKEN environment variable is required");
  process.exit(1);
}

// Initialize auth with org ID for persistent revocations
// Note: initAuth is now async - we handle startup initialization
let authInitialized = false;

async function initializeAuth() {
  try {
    await initAuth(SIGNING_KEY, GROUP_ID);
    authInitialized = true;
    console.log("Auth initialized with persistent revocations");
  } catch (err) {
    console.error("Warning: Failed to initialize persistent revocations:", err.message);
    console.error("Falling back to in-memory revocation tracking");
    // Fall back to sync initialization without persistence
    await initAuth(SIGNING_KEY);
    authInitialized = true;
  }
}

// Start auth initialization (non-blocking)
initializeAuth();

// Initialize audit logging database connection
audit.initDb();

// In-memory vault storage (in production, backed by database)
let vaultData = null;
let vaultKey = null;

// Middleware: verify management API token - timing-safe comparison
function requireManagementAuth(req, res, next) {
  const token = req.headers["x-auth-token"];
  if (!token || typeof token !== "string") {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const tokenBuf = Buffer.from(token);
  const authBuf = Buffer.from(AUTH_TOKEN);
  if (tokenBuf.length !== authBuf.length || !crypto.timingSafeEqual(tokenBuf, authBuf)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// Middleware: verify capability token for secret access
function requireCapability(permission) {
  return (req, res, next) => {
    const tokenString = req.headers["x-capability-token"];
    if (!tokenString) {
      return res.status(401).json({ error: "Capability token required" });
    }

    const token = verifyCapabilityToken(tokenString);
    if (!token) {
      return res.status(401).json({ error: "Invalid or expired capability token" });
    }

    if (token.groupId !== GROUP_ID) {
      return res.status(403).json({ error: "Token not valid for this org" });
    }

    req.capability = token;
    req.requiredPermission = permission;
    next();
  };
}

// Middleware: check vault is unlocked
function requireVaultUnlocked(req, res, next) {
  const session = getVaultSession(GROUP_ID);
  if (!session) {
    return res.status(423).json({ error: "Vault is locked", code: "VAULT_LOCKED" });
  }
  req.vaultKey = session.key;
  next();
}

// Health check
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    groupId: GROUP_ID,
    vaultInitialized: !!vaultData,
    vaultUnlocked: !!getVaultSession(GROUP_ID),
  });
});

// Initialize vault (management API)
app.post(
  "/init",
  requireManagementAuth,
  validate({ body: initGroupVaultSchema }),
  async (req, res) => {
    if (vaultData) {
      return res.status(400).json({ error: "Vault already initialized" });
    }

    const { password } = req.validatedBody;

    try {
      const { vault } = await createGroupVault(password);
      vaultData = vault;

      await audit.log(GROUP_ID, {
        action: "vault.initialized",
        userId: "system",
        success: true,
      });

      res.json({ success: true, message: "Org vault initialized" });
    } catch (err) {
      console.error("Init error:", err);
      res.status(500).json({ error: "Failed to initialize vault" });
    }
  },
);

// Import existing vault (management API)
app.post("/import", requireManagementAuth, async (req, res) => {
  if (vaultData) {
    return res.status(400).json({ error: "Vault already initialized" });
  }

  const { vault } = req.body;
  if (!isValidGroupVault(vault)) {
    return res.status(400).json({ error: "Invalid vault format" });
  }

  vaultData = vault;

  await audit.log(GROUP_ID, {
    action: "vault.imported",
    userId: "system",
    success: true,
  });

  res.json({ success: true, message: "Vault imported" });
});

// Export vault (management API)
app.get("/export", requireManagementAuth, async (req, res) => {
  if (!vaultData) {
    return res.status(400).json({ error: "Vault not initialized" });
  }

  await audit.log(GROUP_ID, {
    action: "vault.exported",
    userId: "system",
    success: true,
  });

  res.json({ vault: vaultData });
});

// Unlock vault (management API - requires threshold approval in future)
// Rate limited: 5 attempts per 15 minutes per IP to prevent brute force
app.post(
  "/unlock",
  vaultUnlockLimiter,
  requireManagementAuth,
  validate({ body: unlockGroupVaultSchema }),
  async (req, res) => {
    if (!vaultData) {
      return res.status(400).json({ error: "Vault not initialized" });
    }

    const { password, userId } = req.validatedBody;

    try {
      const { data, key } = await unlockGroupVault(vaultData, password);
      vaultKey = key;
      createVaultSession(GROUP_ID, key);

      await audit.log(GROUP_ID, {
        action: "vault.unlocked",
        userId: userId || "system",
        success: true,
      });

      res.json({
        success: true,
        expiresIn: VAULT_SESSION_TIMEOUT_MS / 1000,
        secretCount: Object.keys(data.secrets || {}).length,
      });
    } catch (err) {
      await audit.log(GROUP_ID, {
        action: "vault.unlock_failed",
        userId: userId || "system",
        success: false,
        error: err.message,
      });

      if (err.message === "Invalid password") {
        return res.status(401).json({ error: "Invalid password" });
      }
      console.error("Unlock error:", err);
      res.status(500).json({ error: "Failed to unlock vault" });
    }
  },
);

// Lock vault (management API)
app.post("/lock", requireManagementAuth, validate({ body: lockVaultSchema }), async (req, res) => {
  const { userId } = req.validatedBody || {};
  deleteVaultSession(GROUP_ID);
  vaultKey = null;

  await audit.log(GROUP_ID, {
    action: "vault.locked",
    userId: userId || "system",
    success: true,
  });

  res.json({ success: true });
});

// Extend vault session (management API)
app.post("/extend", requireManagementAuth, (req, res) => {
  if (extendVaultSession(GROUP_ID)) {
    res.json({ success: true, expiresIn: VAULT_SESSION_TIMEOUT_MS / 1000 });
  } else {
    res.status(423).json({ error: "Vault is locked" });
  }
});

// Issue capability token (management API)
// Rate limited: 100 tokens per hour per user to prevent abuse
app.post(
  "/tokens",
  tokenIssuanceLimiter,
  requireManagementAuth,
  validate({ body: issueTokenSchema }),
  requireVaultUnlocked,
  async (req, res) => {
    const { userId, allowedSecrets, permissions, ttlSeconds } = req.validatedBody;

    try {
      const token = issueCapabilityToken({
        groupId: GROUP_ID,
        userId,
        allowedSecrets: allowedSecrets || ["*"],
        permissions: permissions || ["read"],
        ttlSeconds: ttlSeconds || 3600,
      });

      await audit.log(GROUP_ID, {
        action: "token.issued",
        userId,
        success: true,
      });

      res.json({ token, expiresIn: ttlSeconds || 3600 });
    } catch (err) {
      console.error("Token issue error:", err);
      res.status(500).json({ error: "Failed to issue token" });
    }
  },
);

// Revoke capability token (management API)
app.delete(
  "/tokens/:tokenId",
  requireManagementAuth,
  validate({ params: tokenIdParamSchema, body: revokeTokenSchema }),
  async (req, res) => {
    const { revokedBy, reason } = req.validatedBody || {};
    const { tokenId } = req.validatedParams;

    try {
      await revokeToken(tokenId, { revokedBy, reason });

      await audit.log(GROUP_ID, {
        action: "token.revoked",
        userId: revokedBy || "system",
        success: true,
      });

      res.json({ success: true });
    } catch (err) {
      console.error("Token revoke error:", err);
      res.status(500).json({ error: "Failed to revoke token" });
    }
  },
);

// Revoke all tokens for a user (management API)
app.delete(
  "/tokens/user/:userId",
  requireManagementAuth,
  validate({ params: userIdParamSchema, body: revokeTokenSchema }),
  async (req, res) => {
    const { revokedBy, reason } = req.validatedBody || {};
    const { userId } = req.validatedParams;

    try {
      const result = await revokeUserTokens(GROUP_ID, userId, { revokedBy, reason });

      await audit.log(GROUP_ID, {
        action: "tokens.revoked.user",
        userId: revokedBy || "system",
        targetUserId: userId,
        success: true,
      });

      res.json({ success: true, revokedCount: result });
    } catch (err) {
      console.error("User tokens revoke error:", err);
      res.status(500).json({ error: "Failed to revoke user tokens" });
    }
  },
);

// Get vault status
app.get("/status", requireManagementAuth, (req, res) => {
  const session = getVaultSession(GROUP_ID);
  res.json({
    initialized: !!vaultData,
    unlocked: !!session,
    expiresIn: session ? Math.floor((session.expiresAt - Date.now()) / 1000) : 0,
  });
});

// Get a secret (capability token required)
app.get(
  "/secrets/:key",
  validate({ params: secretKeyParamSchema }),
  requireCapability("read"),
  requireVaultUnlocked,
  async (req, res) => {
    const { key } = req.validatedParams;

    if (!checkAccess(req.capability, key, "read")) {
      await audit.log(GROUP_ID, {
        action: "secret.read.denied",
        userId: req.capability.userId,
        secretKey: key,
        success: false,
        error: "Access denied",
      });
      return res.status(403).json({ error: "Access denied for this secret" });
    }

    try {
      const { data } = await unlockGroupVault(vaultData, null, req.vaultKey);
      const secret = data.secrets?.[key];

      if (!secret) {
        return res.status(404).json({ error: "Secret not found" });
      }

      await audit.log(GROUP_ID, {
        action: "secret.read",
        userId: req.capability.userId,
        secretKey: key,
        success: true,
      });

      res.json({ key, value: secret.value, metadata: secret.metadata });
    } catch (err) {
      console.error("Get secret error:", err);
      res.status(500).json({ error: "Failed to get secret" });
    }
  },
);

// List secrets (capability token required, returns keys only)
app.get("/secrets", requireCapability("read"), requireVaultUnlocked, async (req, res) => {
  try {
    // Re-unlock with cached key to get data
    const session = getVaultSession(GROUP_ID);
    if (!session) {
      return res.status(423).json({ error: "Vault is locked" });
    }

    // Decrypt vault to get secret keys
    const { data } = await unlockGroupVault(vaultData, null, session.key);
    const allKeys = Object.keys(data.secrets || {});

    // Filter by allowed secrets
    let keys;
    if (req.capability.allowedSecrets.includes("*")) {
      keys = allKeys;
    } else {
      keys = allKeys.filter((k) => req.capability.allowedSecrets.includes(k));
    }

    await audit.log(GROUP_ID, {
      action: "secrets.listed",
      userId: req.capability.userId,
      success: true,
    });

    res.json({
      keys: keys.map((k) => ({
        key: k,
        metadata: data.secrets[k].metadata,
      })),
    });
  } catch (err) {
    console.error("List secrets error:", err);
    res.status(500).json({ error: "Failed to list secrets" });
  }
});

// Store a secret (capability token required)
app.post(
  "/secrets/:key",
  validate({ params: secretKeyParamSchema, body: storeSecretSchema }),
  requireCapability("write"),
  requireVaultUnlocked,
  async (req, res) => {
    const { key } = req.validatedParams;
    const { value, metadata } = req.validatedBody;

    if (!checkAccess(req.capability, key, "write")) {
      await audit.log(GROUP_ID, {
        action: "secret.write.denied",
        userId: req.capability.userId,
        secretKey: key,
        success: false,
        error: "Access denied",
      });
      return res.status(403).json({ error: "Access denied for this secret" });
    }

    try {
      const session = getVaultSession(GROUP_ID);
      const { data } = await unlockGroupVault(vaultData, null, session.key);

      // Update secrets
      data.secrets = data.secrets || {};
      const isNew = !data.secrets[key];
      data.secrets[key] = {
        value,
        metadata: metadata || {},
        updatedAt: new Date().toISOString(),
        updatedBy: req.capability.userId,
      };

      // Re-encrypt vault
      vaultData = updateGroupVault(vaultData, session.key, data);

      await audit.log(GROUP_ID, {
        action: isNew ? "secret.created" : "secret.updated",
        userId: req.capability.userId,
        secretKey: key,
        success: true,
      });

      res.json({ success: true, created: isNew });
    } catch (err) {
      console.error("Store secret error:", err);
      res.status(500).json({ error: "Failed to store secret" });
    }
  },
);

// Delete a secret (capability token required)
app.delete(
  "/secrets/:key",
  validate({ params: secretKeyParamSchema }),
  requireCapability("delete"),
  requireVaultUnlocked,
  async (req, res) => {
    const { key } = req.validatedParams;

    if (!checkAccess(req.capability, key, "delete")) {
      await audit.log(GROUP_ID, {
        action: "secret.delete.denied",
        userId: req.capability.userId,
        secretKey: key,
        success: false,
        error: "Access denied",
      });
      return res.status(403).json({ error: "Access denied for this secret" });
    }

    try {
      const session = getVaultSession(GROUP_ID);
      const { data } = await unlockGroupVault(vaultData, null, session.key);

      if (!data.secrets?.[key]) {
        return res.status(404).json({ error: "Secret not found" });
      }

      delete data.secrets[key];

      // Re-encrypt vault
      vaultData = updateGroupVault(vaultData, session.key, data);

      await audit.log(GROUP_ID, {
        action: "secret.deleted",
        userId: req.capability.userId,
        secretKey: key,
        success: true,
      });

      res.json({ success: true });
    } catch (err) {
      console.error("Delete secret error:", err);
      res.status(500).json({ error: "Failed to delete secret" });
    }
  },
);

// Get audit logs (management API)
app.get("/audit", requireManagementAuth, (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  const logs = audit.getLogs(GROUP_ID, limit);
  res.json({ logs });
});

// Get audit logs for specific secret (management API)
app.get(
  "/audit/secret/:key",
  requireManagementAuth,
  validate({ params: secretKeyParamSchema }),
  (req, res) => {
    const limit = parseInt(req.query.limit) || 50;
    const logs = audit.getSecretLogs(GROUP_ID, req.validatedParams.key, limit);
    res.json({ logs });
  },
);

// Start server
app.listen(PORT, () => {
  console.log(`Org vault server running on port ${PORT}`);
  console.log(`Organization: ${GROUP_ID}`);
  console.log("Vault initialized:", !!vaultData);
});

export default app;
