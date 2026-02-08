// Org vault session store (in-memory, replace with Redis in production)
// Tracks which groups have unlocked vaults and validates session keys
import crypto from "crypto";

// Default unlock duration: 8 hours
export const GROUP_VAULT_UNLOCK_DURATION_MS = 8 * 60 * 60 * 1000;
export const GROUP_VAULT_UNLOCK_DURATION_SEC = 8 * 60 * 60;

// In-memory store for active group vault sessions
// Key: groupId, Value: { sessionKey, expiresAt, unlockedAt, requestId, approvers }
const groupVaultSessions = new Map();

// Clean up expired sessions periodically
setInterval(() => {
  const now = Date.now();
  for (const [groupId, session] of groupVaultSessions) {
    if (session.expiresAt < now) {
      groupVaultSessions.delete(groupId);
    }
  }
}, 60000);

/**
 * Generate a secure session key for group vault access
 */
export function generateSessionKey() {
  return crypto.randomBytes(32).toString("hex");
}

/**
 * Create an group vault session after threshold is met
 * @param {string} groupId - Organization ID
 * @param {string} requestId - The unlock request ID
 * @param {string[]} approvers - List of approver user IDs
 * @returns {{ sessionKey: string, expiresAt: Date }}
 */
export function createGroupVaultSession(groupId, requestId, approvers) {
  const sessionKey = generateSessionKey();
  const expiresAt = Date.now() + GROUP_VAULT_UNLOCK_DURATION_MS;

  groupVaultSessions.set(groupId, {
    sessionKey,
    requestId,
    approvers,
    unlockedAt: Date.now(),
    expiresAt,
  });

  return {
    sessionKey,
    expiresAt: new Date(expiresAt),
  };
}

/**
 * Get group vault session by org ID
 * @param {string} groupId - Organization ID
 * @returns {Object|null} Session object or null if not found/expired
 */
export function getGroupVaultSession(groupId) {
  const session = groupVaultSessions.get(groupId);
  if (!session) return null;

  if (session.expiresAt < Date.now()) {
    groupVaultSessions.delete(groupId);
    return null;
  }

  return session;
}

/**
 * Validate a session key for an org
 * @param {string} groupId - Organization ID
 * @param {string} sessionKey - Session key to validate
 * @returns {boolean} True if valid
 */
export function validateGroupSessionKey(groupId, sessionKey) {
  const session = getGroupVaultSession(groupId);
  if (!session) return false;

  // Constant-time comparison to prevent timing attacks
  const expected = Buffer.from(session.sessionKey, "hex");
  const provided = Buffer.from(sessionKey, "hex");

  if (expected.length !== provided.length) return false;
  return crypto.timingSafeEqual(expected, provided);
}

/**
 * Lock an group vault (delete session)
 * @param {string} groupId - Organization ID
 * @returns {boolean} True if session existed
 */
export function lockGroupVault(groupId) {
  return groupVaultSessions.delete(groupId);
}

/**
 * Check if an group vault is currently unlocked
 * @param {string} groupId - Organization ID
 * @returns {boolean}
 */
export function isGroupVaultUnlocked(groupId) {
  return getGroupVaultSession(groupId) !== null;
}

/**
 * Get remaining time until group vault auto-locks
 * @param {string} groupId - Organization ID
 * @returns {number} Seconds until lock, or 0 if locked
 */
export function getGroupVaultTimeRemaining(groupId) {
  const session = getGroupVaultSession(groupId);
  if (!session) return 0;
  return Math.max(0, Math.floor((session.expiresAt - Date.now()) / 1000));
}

/**
 * Get all active group vault sessions (for admin/monitoring)
 * @returns {Array<{ groupId: string, expiresAt: Date, approvers: string[] }>}
 */
export function listActiveGroupVaultSessions() {
  const result = [];
  const now = Date.now();

  for (const [groupId, session] of groupVaultSessions) {
    if (session.expiresAt > now) {
      result.push({
        groupId,
        requestId: session.requestId,
        approvers: session.approvers,
        unlockedAt: new Date(session.unlockedAt),
        expiresAt: new Date(session.expiresAt),
        timeRemaining: Math.floor((session.expiresAt - now) / 1000),
      });
    }
  }

  return result;
}
