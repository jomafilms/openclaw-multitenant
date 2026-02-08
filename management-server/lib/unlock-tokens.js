// Vault unlock tokens (for agent-generated magic links)
import crypto from 'crypto';

const unlockTokens = new Map();

// Clean up expired unlock tokens periodically
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of unlockTokens) {
    if (data.expiresAt < now) {
      unlockTokens.delete(token);
    }
  }
}, 60000); // Every minute

/**
 * Create an unlock token for a user
 * Used by MCP tools when agent needs user to unlock vault
 * @param {string} userId - User ID
 * @param {number} expiresInMs - Token expiry time in milliseconds (default 15 minutes)
 * @returns {string} - The unlock token
 */
export function createUnlockToken(userId, expiresInMs = 15 * 60 * 1000) {
  const token = crypto.randomBytes(32).toString('hex');
  unlockTokens.set(token, {
    userId,
    expiresAt: Date.now() + expiresInMs,
    createdAt: Date.now()
  });
  return token;
}

/**
 * Validate and consume an unlock token (one-time use)
 * @param {string} token - Token to validate
 * @returns {{userId: string, expiresAt: number, createdAt: number} | null}
 */
export function validateUnlockToken(token) {
  const data = unlockTokens.get(token);
  if (!data) {
    return null;
  }
  if (data.expiresAt < Date.now()) {
    unlockTokens.delete(token);
    return null;
  }
  // Consume the token (one-time use)
  unlockTokens.delete(token);
  return data;
}

/**
 * Peek at an unlock token without consuming it
 * @param {string} token - Token to peek
 * @returns {{userId: string, expiresAt: number, createdAt: number} | null}
 */
export function peekUnlockToken(token) {
  return unlockTokens.get(token) || null;
}

// Export the Map for MCP handler access
export { unlockTokens };
