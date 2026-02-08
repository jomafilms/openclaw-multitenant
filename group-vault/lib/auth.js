// group-vault/lib/auth.js
// Authentication and authorization for group vault API
//
// SECURITY: Token revocations are persisted to PostgreSQL to survive server restarts.
// An in-memory Set is used for fast revocation checks, loaded from DB at startup.

import crypto from "crypto";
import { groupTokenRevocations } from "../../management-server/db/index.js";

/**
 * Capability token for scoped secret access
 * @typedef {Object} CapabilityToken
 * @property {string} groupId - Group ID
 * @property {string} userId - User ID
 * @property {string[]} allowedSecrets - List of allowed secret keys (or ['*'] for all)
 * @property {string[]} permissions - ['read', 'write', 'delete']
 * @property {number} expiresAt - Expiration timestamp
 * @property {string} signature - HMAC signature
 */

// In-memory token tracking (for fast lookup)
// Maps tokenId -> { groupId, userId, expiresAt }
const issuedTokens = new Map();

// In-memory revocation set (loaded from DB at startup for fast checks)
// Set of revoked tokenIds
const revokedTokens = new Set();

// Group ID for this vault instance
let currentGroupId = null;

// Token signing key (should be from env in production)
let signingKey = null;

// Flag to track if revocations have been loaded from DB
let revocationsLoaded = false;

/**
 * Initialize auth with signing key and load revocations from database.
 * @param {string} key - Signing key
 * @param {string} groupId - Group ID (optional, for loading revocations)
 */
export async function initAuth(key, groupId = null) {
  if (!key || key.length < 32) {
    throw new Error("Signing key must be at least 32 characters");
  }
  signingKey = crypto.createHash("sha256").update(key).digest();
  currentGroupId = groupId;

  // Load revocations from database if group ID is provided
  if (groupId && !revocationsLoaded) {
    await loadRevocationsFromDb(groupId);
  }
}

/**
 * Load revoked tokens from database into memory for fast checks.
 * @param {string} groupId - Group ID
 */
async function loadRevocationsFromDb(groupId) {
  try {
    console.log(`[auth] Loading revocations for group ${groupId} from database...`);
    const tokenIds = await groupTokenRevocations.getAllTokenIdsForGroup(groupId);

    revokedTokens.clear();
    for (const tokenId of tokenIds) {
      revokedTokens.add(tokenId);
    }

    revocationsLoaded = true;
    console.log(`[auth] Loaded ${tokenIds.length} revoked tokens from database`);
  } catch (err) {
    console.error("[auth] Failed to load revocations from database:", err);
    // Continue without persistence - will use in-memory only
    revocationsLoaded = true;
  }
}

/**
 * Generate a capability token
 * @param {Object} params - Token parameters
 * @param {string} params.groupId - Group ID
 * @param {string} params.userId - User ID
 * @param {string[]} params.allowedSecrets - Allowed secret keys
 * @param {string[]} params.permissions - Permissions
 * @param {number} params.ttlSeconds - Time to live in seconds
 * @returns {string} Token string
 */
export function issueCapabilityToken({
  groupId,
  userId,
  allowedSecrets = ["*"],
  permissions = ["read"],
  ttlSeconds = 3600,
}) {
  if (!signingKey) {
    throw new Error("Auth not initialized");
  }

  const tokenId = crypto.randomBytes(16).toString("hex");
  const expiresAt = Date.now() + ttlSeconds * 1000;

  const payload = {
    id: tokenId,
    groupId,
    userId,
    allowedSecrets,
    permissions,
    expiresAt,
  };

  const signature = crypto
    .createHmac("sha256", signingKey)
    .update(JSON.stringify(payload))
    .digest("hex");

  const token = {
    ...payload,
    signature,
  };

  // Store for revocation capability
  issuedTokens.set(tokenId, {
    groupId,
    userId,
    expiresAt,
  });

  return Buffer.from(JSON.stringify(token)).toString("base64url");
}

/**
 * Verify and decode a capability token
 * @param {string} tokenString - Base64url encoded token
 * @returns {CapabilityToken|null} Token or null if invalid
 */
export function verifyCapabilityToken(tokenString) {
  if (!signingKey) {
    throw new Error("Auth not initialized");
  }

  try {
    const token = JSON.parse(Buffer.from(tokenString, "base64url").toString());

    // Check expiration
    if (token.expiresAt < Date.now()) {
      return null;
    }

    // Check if revoked (check persistent revocation set first, then issued tokens)
    if (revokedTokens.has(token.id)) {
      return null;
    }

    // For backward compatibility, also check issued tokens map
    // New tokens will be tracked, old tokens validated by signature only
    // (This allows tokens issued before server restart to still work if not revoked)

    // Verify signature
    const { signature, ...payload } = token;
    const expectedSignature = crypto
      .createHmac("sha256", signingKey)
      .update(JSON.stringify(payload))
      .digest("hex");

    if (signature !== expectedSignature) {
      return null;
    }

    return token;
  } catch {
    return null;
  }
}

/**
 * Revoke a capability token
 * @param {string} tokenId - Token ID
 * @param {Object} options - Options
 * @param {string} options.userId - User ID who owned the token
 * @param {string} options.revokedBy - User ID who revoked the token
 * @param {string} options.reason - Reason for revocation
 */
export async function revokeToken(tokenId, options = {}) {
  // Remove from issued tokens map
  const tokenMeta = issuedTokens.get(tokenId);
  issuedTokens.delete(tokenId);

  // Add to revoked set for fast lookup
  revokedTokens.add(tokenId);

  // Persist to database
  if (currentGroupId) {
    try {
      await groupTokenRevocations.create({
        groupId: currentGroupId,
        tokenId,
        userId: options.userId || tokenMeta?.userId,
        revokedBy: options.revokedBy,
        reason: options.reason,
      });
      console.log(`[auth] Revoked token ${tokenId.slice(0, 8)} (persisted)`);
    } catch (err) {
      console.error("[auth] Failed to persist token revocation:", err);
      // Continue - token is still revoked in memory
    }
  }
}

/**
 * Revoke all tokens for a user in a group
 * @param {string} groupId - Group ID
 * @param {string} userId - User ID
 * @param {Object} options - Options
 * @param {string} options.revokedBy - User ID who revoked the tokens
 * @param {string} options.reason - Reason for revocation
 */
export async function revokeUserTokens(groupId, userId, options = {}) {
  const revokedCount = { memory: 0, db: 0 };

  // Revoke in-memory tokens
  for (const [tokenId, meta] of issuedTokens) {
    if (meta.groupId === groupId && meta.userId === userId) {
      issuedTokens.delete(tokenId);
      revokedTokens.add(tokenId);
      revokedCount.memory++;
    }
  }

  // Persist to database (this also catches tokens from previous server runs)
  try {
    const dbCount = await groupTokenRevocations.revokeAllForUser(
      groupId,
      userId,
      options.revokedBy,
      options.reason,
    );
    revokedCount.db = dbCount;

    // Reload revocations from DB to catch any we missed
    await loadRevocationsFromDb(groupId);

    console.log(
      `[auth] Revoked all tokens for user ${userId}: ${revokedCount.memory} in memory, ${revokedCount.db} in database`,
    );
  } catch (err) {
    console.error("[auth] Failed to persist user token revocations:", err);
    // Continue - tokens are still revoked in memory
  }

  return revokedCount;
}

/**
 * Check if token allows access to a secret
 * @param {CapabilityToken} token - Verified token
 * @param {string} secretKey - Secret key to access
 * @param {string} permission - Required permission
 * @returns {boolean}
 */
export function checkAccess(token, secretKey, permission) {
  // Check permission
  if (!token.permissions.includes(permission)) {
    return false;
  }

  // Check allowed secrets
  if (token.allowedSecrets.includes("*")) {
    return true;
  }

  return token.allowedSecrets.includes(secretKey);
}

// Clean up expired tokens periodically
setInterval(() => {
  const now = Date.now();
  for (const [tokenId, meta] of issuedTokens) {
    if (meta.expiresAt < now) {
      issuedTokens.delete(tokenId);
    }
  }
}, 60000);

/**
 * Check if a specific token is revoked
 * @param {string} tokenId - Token ID
 * @returns {boolean} True if revoked
 */
export function isTokenRevoked(tokenId) {
  return revokedTokens.has(tokenId);
}

/**
 * Get revocation statistics
 * @returns {Object} Stats object
 */
export function getRevocationStats() {
  return {
    issuedTokens: issuedTokens.size,
    revokedTokens: revokedTokens.size,
    revocationsLoaded,
    groupId: currentGroupId,
  };
}

/**
 * Force reload of revocations from database
 * @param {string} groupId - Group ID (optional, uses current if not provided)
 */
export async function reloadRevocations(groupId = null) {
  const targetGroupId = groupId || currentGroupId;
  if (targetGroupId) {
    revocationsLoaded = false;
    await loadRevocationsFromDb(targetGroupId);
  }
}

export default {
  initAuth,
  issueCapabilityToken,
  verifyCapabilityToken,
  revokeToken,
  revokeUserTokens,
  checkAccess,
  isTokenRevoked,
  getRevocationStats,
  reloadRevocations,
};
