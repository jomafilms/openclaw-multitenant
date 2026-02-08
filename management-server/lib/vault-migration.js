/**
 * Vault Migration Service
 *
 * Migrates vault encryption from management server to container.
 * After migration, the management server no longer has access to the vault key,
 * and all session encryption happens in the container.
 */

import axios from "axios";
import { AGENT_SERVER_URL, AGENT_SERVER_TOKEN } from "./context.js";

/**
 * Check if a user's container has vault migration available
 */
export async function checkMigrationStatus(userId) {
  try {
    const response = await axios.get(
      `${AGENT_SERVER_URL}/api/containers/${userId}/vault/session/status`,
      { headers: { "x-auth-token": AGENT_SERVER_TOKEN }, timeout: 10000 },
    );

    const status = response.data?.status;
    if (!status) {
      return { available: false, reason: "Could not get session vault status" };
    }

    return {
      available: true,
      initialized: status.initialized,
      locked: status.locked,
      sessionsEncrypted: status.sessionsEncrypted,
    };
  } catch (err) {
    if (err.response?.status === 404) {
      return { available: false, reason: "Container not found" };
    }
    console.error("Check migration status error:", err.message);
    return { available: false, reason: "Failed to check migration status" };
  }
}

/**
 * Migrate a user's vault to container-side encryption.
 *
 * This should be called when:
 * 1. User has an existing vault in management server
 * 2. Container supports session encryption
 * 3. User has unlocked their vault (we have the derived key)
 *
 * After migration:
 * - Container handles all session encryption
 * - Management server vault remains for integrations/capabilities
 * - Session files are encrypted with user's vault key
 *
 * @param {string} userId - User ID
 * @param {Buffer} derivedKey - User's derived vault key (from password)
 * @param {object} options - Migration options
 * @returns {Promise<{success: boolean, migrated?: number, failed?: string[], error?: string}>}
 */
export async function migrateVaultToContainer(userId, derivedKey, options = {}) {
  const { migrateExistingSessions = true, timeout = 60000 } = options;

  try {
    // Wake container first
    await axios.post(
      `${AGENT_SERVER_URL}/api/containers/${userId}/wake`,
      { reason: "vault-migration", timeout: 30000 },
      { headers: { "x-auth-token": AGENT_SERVER_TOKEN }, timeout: 35000 },
    );

    // Unlock session vault with the derived key
    const unlockResponse = await axios.post(
      `${AGENT_SERVER_URL}/api/containers/${userId}/vault/session/unlock`,
      { derivedKey: derivedKey.toString("base64") },
      { headers: { "x-auth-token": AGENT_SERVER_TOKEN }, timeout: 15000 },
    );

    if (!unlockResponse.data?.success) {
      return {
        success: false,
        error: unlockResponse.data?.error || "Failed to unlock session vault",
      };
    }

    // Migrate existing sessions if requested
    if (migrateExistingSessions) {
      const migrateResponse = await axios.post(
        `${AGENT_SERVER_URL}/api/containers/${userId}/vault/session/migrate`,
        {},
        { headers: { "x-auth-token": AGENT_SERVER_TOKEN }, timeout },
      );

      return {
        success: true,
        migrated: migrateResponse.data?.migrated || 0,
        failed: migrateResponse.data?.failed || [],
        expiresIn: unlockResponse.data?.expiresIn,
      };
    }

    return {
      success: true,
      migrated: 0,
      failed: [],
      expiresIn: unlockResponse.data?.expiresIn,
    };
  } catch (err) {
    console.error("Migrate vault to container error:", err.message);
    return {
      success: false,
      error: err.response?.data?.error || err.message,
    };
  }
}

/**
 * Initialize container vault during user onboarding.
 * Called when a new user creates their vault password.
 *
 * @param {string} userId - User ID
 * @param {Buffer} derivedKey - User's derived vault key (from password)
 * @returns {Promise<{success: boolean, salt?: string, error?: string}>}
 */
export async function initializeContainerVault(userId, derivedKey) {
  try {
    // Wake container first
    await axios.post(
      `${AGENT_SERVER_URL}/api/containers/${userId}/wake`,
      { reason: "vault-init", timeout: 30000 },
      { headers: { "x-auth-token": AGENT_SERVER_TOKEN }, timeout: 35000 },
    );

    // Get or create salt
    const challengeResponse = await axios.get(
      `${AGENT_SERVER_URL}/api/containers/${userId}/vault/session/challenge`,
      { headers: { "x-auth-token": AGENT_SERVER_TOKEN }, timeout: 10000 },
    );

    if (!challengeResponse.data?.success || !challengeResponse.data?.challenge) {
      return {
        success: false,
        error: challengeResponse.data?.error || "Failed to get vault challenge",
      };
    }

    // Unlock with derived key
    const unlockResponse = await axios.post(
      `${AGENT_SERVER_URL}/api/containers/${userId}/vault/session/unlock`,
      { derivedKey: derivedKey.toString("base64") },
      { headers: { "x-auth-token": AGENT_SERVER_TOKEN }, timeout: 15000 },
    );

    if (!unlockResponse.data?.success) {
      return {
        success: false,
        error: unlockResponse.data?.error || "Failed to unlock session vault",
      };
    }

    return {
      success: true,
      salt: challengeResponse.data.challenge.salt,
      expiresIn: unlockResponse.data.expiresIn,
    };
  } catch (err) {
    console.error("Initialize container vault error:", err.message);
    return {
      success: false,
      error: err.response?.data?.error || err.message,
    };
  }
}
