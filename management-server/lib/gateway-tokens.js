// Gateway Token Management
// Implements ephemeral tokens for secure container-to-management-server communication
//
// Architecture:
// - Permanent tokens (gateway_token) are stored encrypted in the database
// - Ephemeral tokens are signed, time-limited tokens derived from permanent tokens
// - Containers can request ephemeral tokens on startup or when tokens expire
// - This limits exposure if a token is compromised

import crypto from "crypto";
import { encrypt, decrypt } from "./encryption.js";

// Default expiration: 1 hour (in seconds)
const DEFAULT_EXPIRY_SECONDS = 3600;
// Maximum expiration: 24 hours
const MAX_EXPIRY_SECONDS = 86400;
// Minimum expiration: 5 minutes
const MIN_EXPIRY_SECONDS = 300;

/**
 * Generate a new permanent gateway token.
 * This token should be stored encrypted in the database.
 *
 * @returns {string} 64-character hex string (32 bytes)
 */
export function generatePermanentToken() {
  return crypto.randomBytes(32).toString("hex");
}

/**
 * Encrypt a gateway token for database storage.
 *
 * @param {string} rawToken - The raw gateway token
 * @returns {string} Encrypted token for database storage
 */
export function encryptGatewayToken(rawToken) {
  if (!rawToken) {
    return null;
  }
  return encrypt(rawToken);
}

/**
 * Decrypt a gateway token from database storage.
 *
 * @param {string} encryptedToken - The encrypted token from database
 * @returns {string|null} Raw token or null if empty
 */
export function decryptGatewayToken(encryptedToken) {
  if (!encryptedToken) {
    return null;
  }
  return decrypt(encryptedToken);
}

/**
 * Generate an ephemeral gateway token for container use.
 * This creates a short-lived, signed token that can be validated without database lookup.
 *
 * Token format: base64({ payload, signature })
 * Payload: { userId, exp, nonce }
 *
 * @param {string} userId - The user ID this token is for
 * @param {string} permanentToken - The permanent token used as HMAC key
 * @param {number} [expiresInSeconds=3600] - Token lifetime in seconds
 * @returns {string} Base64-encoded ephemeral token
 */
export function generateEphemeralToken(
  userId,
  permanentToken,
  expiresInSeconds = DEFAULT_EXPIRY_SECONDS,
) {
  if (!userId || !permanentToken) {
    throw new Error("userId and permanentToken are required");
  }

  // Clamp expiry to valid range
  const expiry = Math.min(Math.max(expiresInSeconds, MIN_EXPIRY_SECONDS), MAX_EXPIRY_SECONDS);

  const payload = {
    userId,
    exp: Math.floor(Date.now() / 1000) + expiry,
    nonce: crypto.randomBytes(8).toString("hex"),
  };

  const payloadStr = JSON.stringify(payload);
  const signature = crypto.createHmac("sha256", permanentToken).update(payloadStr).digest("hex");

  // Use URL-safe base64 encoding
  return Buffer.from(JSON.stringify({ payload, signature })).toString("base64url");
}

/**
 * Validate an ephemeral gateway token.
 * Returns the payload if valid, null if invalid or expired.
 *
 * @param {string} ephemeralToken - The ephemeral token to validate
 * @param {string} permanentToken - The permanent token used to verify signature
 * @returns {{ userId: string, exp: number, nonce: string } | null} Payload if valid, null otherwise
 */
export function validateEphemeralToken(ephemeralToken, permanentToken) {
  if (!ephemeralToken || !permanentToken) {
    return null;
  }

  try {
    // Try both URL-safe and standard base64
    let decoded;
    try {
      decoded = Buffer.from(ephemeralToken, "base64url").toString("utf8");
    } catch {
      decoded = Buffer.from(ephemeralToken, "base64").toString("utf8");
    }

    const { payload, signature } = JSON.parse(decoded);

    if (!payload || !signature) {
      return null;
    }

    // Verify signature using timing-safe comparison
    const expectedSig = crypto
      .createHmac("sha256", permanentToken)
      .update(JSON.stringify(payload))
      .digest("hex");

    const sigBuffer = Buffer.from(signature, "hex");
    const expectedBuffer = Buffer.from(expectedSig, "hex");

    if (sigBuffer.length !== expectedBuffer.length) {
      return null;
    }

    if (!crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
      return null;
    }

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) {
      return null; // Token expired
    }

    return payload;
  } catch {
    // Any parsing error means invalid token
    return null;
  }
}

/**
 * Check if a token looks like an ephemeral token (base64 JSON) or permanent token (hex).
 *
 * @param {string} token - Token to check
 * @returns {'ephemeral' | 'permanent' | 'unknown'} Token type
 */
export function detectTokenType(token) {
  if (!token) {
    return "unknown";
  }

  // Permanent tokens are 64 hex characters
  if (/^[0-9a-f]{64}$/i.test(token)) {
    return "permanent";
  }

  // Ephemeral tokens are base64-encoded JSON with signature
  try {
    let decoded;
    try {
      decoded = Buffer.from(token, "base64url").toString("utf8");
    } catch {
      decoded = Buffer.from(token, "base64").toString("utf8");
    }

    const parsed = JSON.parse(decoded);
    if (parsed.payload && parsed.signature) {
      return "ephemeral";
    }
  } catch {
    // Not valid base64 JSON
  }

  return "unknown";
}

/**
 * Get the expiration time remaining for an ephemeral token (without full validation).
 * Useful for deciding whether to refresh a token.
 *
 * @param {string} ephemeralToken - The ephemeral token
 * @returns {number} Seconds until expiration, or 0 if expired/invalid
 */
export function getTokenExpiry(ephemeralToken) {
  if (!ephemeralToken) {
    return 0;
  }

  try {
    let decoded;
    try {
      decoded = Buffer.from(ephemeralToken, "base64url").toString("utf8");
    } catch {
      decoded = Buffer.from(ephemeralToken, "base64").toString("utf8");
    }

    const { payload } = JSON.parse(decoded);
    if (!payload?.exp) {
      return 0;
    }

    const now = Math.floor(Date.now() / 1000);
    const remaining = payload.exp - now;

    return remaining > 0 ? remaining : 0;
  } catch {
    return 0;
  }
}

/**
 * Check if a token needs refresh (less than 5 minutes remaining).
 *
 * @param {string} ephemeralToken - The ephemeral token to check
 * @param {number} [thresholdSeconds=300] - Refresh threshold in seconds
 * @returns {boolean} True if token should be refreshed
 */
export function needsRefresh(ephemeralToken, thresholdSeconds = 300) {
  const remaining = getTokenExpiry(ephemeralToken);
  return remaining < thresholdSeconds;
}

export default {
  generatePermanentToken,
  encryptGatewayToken,
  decryptGatewayToken,
  generateEphemeralToken,
  validateEphemeralToken,
  detectTokenType,
  getTokenExpiry,
  needsRefresh,
};
