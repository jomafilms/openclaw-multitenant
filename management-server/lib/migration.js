/**
 * User Vault Migration
 *
 * Migrates user secrets from the centralized management server vault
 * to the user's container-side secret store.
 *
 * The migration process:
 * 1. Reads the user's vault data (requires vault to be unlocked)
 * 2. Wakes the user's container if hibernating
 * 3. Initializes the container's secret store (if not already initialized)
 * 4. Imports integrations to the container vault
 * 5. Tracks migration status in user settings
 */

import axios from "axios";
import { users, audit } from "../db/index.js";
import { AGENT_SERVER_URL, AGENT_SERVER_TOKEN } from "./context.js";
import { getVaultSession } from "./vault-sessions.js";
import { unlockVaultWithKey } from "./vault.js";

// Migration status values
export const MIGRATION_STATUS = {
  NOT_STARTED: "not_started",
  IN_PROGRESS: "in_progress",
  COMPLETED: "completed",
  FAILED: "failed",
  PARTIAL: "partial", // Some integrations migrated, some failed
};

/**
 * Get container gateway URL for a user
 */
function getContainerUrl(user) {
  // Container runs on host, accessible via localhost port
  return `http://localhost:${user.container_port}`;
}

/**
 * Wake container and wait for it to be ready
 */
async function ensureContainerAwake(userId) {
  try {
    const response = await axios.post(
      `${AGENT_SERVER_URL}/api/containers/${userId}/wake`,
      { reason: "migration", timeout: 30000 },
      {
        headers: { "x-auth-token": AGENT_SERVER_TOKEN },
        timeout: 35000,
      },
    );
    return { success: true, wakeTime: response.data.wakeTime };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * Check if container's secret store is initialized
 */
async function checkContainerVaultStatus(user) {
  const containerUrl = getContainerUrl(user);
  try {
    const response = await axios.get(`${containerUrl}/v1/secrets/status`, {
      headers: { Authorization: `Bearer ${user.gateway_token}` },
      timeout: 10000,
    });
    return response.data;
  } catch (err) {
    return { initialized: false, error: err.message };
  }
}

/**
 * Initialize container's secret store with a password
 */
async function initializeContainerVault(user, password) {
  const containerUrl = getContainerUrl(user);
  try {
    const response = await axios.post(
      `${containerUrl}/v1/secrets/initialize`,
      { password },
      {
        headers: {
          Authorization: `Bearer ${user.gateway_token}`,
          "Content-Type": "application/json",
        },
        timeout: 30000,
      },
    );
    return response.data;
  } catch (err) {
    return { success: false, error: err.response?.data?.error || err.message };
  }
}

/**
 * Unlock container's secret store
 */
async function unlockContainerVault(user, password) {
  const containerUrl = getContainerUrl(user);
  try {
    const response = await axios.post(
      `${containerUrl}/v1/secrets/unlock`,
      { password },
      {
        headers: {
          Authorization: `Bearer ${user.gateway_token}`,
          "Content-Type": "application/json",
        },
        timeout: 30000,
      },
    );
    return response.data;
  } catch (err) {
    return { success: false, error: err.response?.data?.error || err.message };
  }
}

/**
 * Import an integration to container's secret store
 */
async function importIntegrationToContainer(user, provider, integration) {
  const containerUrl = getContainerUrl(user);
  try {
    const response = await axios.put(
      `${containerUrl}/v1/secrets/integrations/${encodeURIComponent(provider)}`,
      integration,
      {
        headers: {
          Authorization: `Bearer ${user.gateway_token}`,
          "Content-Type": "application/json",
        },
        timeout: 15000,
      },
    );
    return response.data;
  } catch (err) {
    return { success: false, error: err.response?.data?.error || err.message };
  }
}

/**
 * Update migration status in user settings
 */
async function updateMigrationStatus(userId, status, details = {}) {
  const migrationInfo = {
    status,
    lastAttempt: new Date().toISOString(),
    ...details,
  };

  await users.updateSettings(userId, {
    containerVaultMigration: migrationInfo,
  });

  return migrationInfo;
}

/**
 * Get current migration status for a user
 */
export async function getMigrationStatus(userId) {
  const settings = await users.getSettings(userId);
  return settings?.containerVaultMigration || { status: MIGRATION_STATUS.NOT_STARTED };
}

/**
 * Migrate a user's vault to their container
 *
 * @param {string} userId - User ID to migrate
 * @param {object} options - Migration options
 * @param {string} options.vaultSessionToken - Vault session token (vault must be unlocked)
 * @param {string} options.containerPassword - Password for the container vault (defaults to same as management vault derivation)
 * @param {boolean} options.force - Force re-migration even if already completed
 * @param {string} options.adminUserId - ID of admin performing the migration (for audit)
 * @param {string} options.ipAddress - IP address for audit logging
 * @returns {Promise<object>} Migration result
 */
export async function migrateUserToContainerVault(userId, options = {}) {
  const { vaultSessionToken, containerPassword, force = false, adminUserId, ipAddress } = options;

  // Check existing migration status
  const currentStatus = await getMigrationStatus(userId);
  if (currentStatus.status === MIGRATION_STATUS.COMPLETED && !force) {
    return {
      success: false,
      error: "Migration already completed. Use force=true to re-migrate.",
      status: currentStatus,
    };
  }

  // Get user data
  const user = await users.findById(userId);
  if (!user) {
    return { success: false, error: "User not found" };
  }

  if (!user.container_id || !user.container_port) {
    return { success: false, error: "User does not have a provisioned container" };
  }

  if (!user.vault) {
    return { success: false, error: "User does not have a management vault" };
  }

  // Validate vault session
  const vaultSession = vaultSessionToken ? await getVaultSession(vaultSessionToken) : null;
  if (!vaultSession || vaultSession.userId !== userId) {
    return { success: false, error: "Valid vault session required. Vault must be unlocked." };
  }

  // Mark migration in progress
  await updateMigrationStatus(userId, MIGRATION_STATUS.IN_PROGRESS);

  const result = {
    success: true,
    userId,
    startedAt: new Date().toISOString(),
    integrationsMigrated: [],
    integrationsFailed: [],
    errors: [],
  };

  try {
    // Step 1: Unlock management vault to get data
    let vaultData;
    try {
      vaultData = unlockVaultWithKey(user.vault, vaultSession.vaultKey);
    } catch (err) {
      result.success = false;
      result.errors.push(`Failed to unlock management vault: ${err.message}`);
      await updateMigrationStatus(userId, MIGRATION_STATUS.FAILED, {
        error: "Failed to unlock management vault",
      });
      return result;
    }

    // Step 2: Wake container
    const wakeResult = await ensureContainerAwake(userId);
    if (!wakeResult.success) {
      result.success = false;
      result.errors.push(`Failed to wake container: ${wakeResult.error}`);
      await updateMigrationStatus(userId, MIGRATION_STATUS.FAILED, {
        error: "Failed to wake container",
      });
      return result;
    }
    result.containerWakeTime = wakeResult.wakeTime;

    // Step 3: Check/initialize container vault
    const vaultStatus = await checkContainerVaultStatus(user);

    // Use provided password or generate a deterministic one based on vault key
    // In production, you'd want the user to provide a new password
    const password =
      containerPassword || Buffer.from(vaultSession.vaultKey).toString("base64").slice(0, 32);

    if (!vaultStatus.initialized) {
      // Initialize new container vault
      const initResult = await initializeContainerVault(user, password);
      if (!initResult.success) {
        result.success = false;
        result.errors.push(`Failed to initialize container vault: ${initResult.error}`);
        await updateMigrationStatus(userId, MIGRATION_STATUS.FAILED, {
          error: "Failed to initialize container vault",
        });
        return result;
      }
      result.containerVaultInitialized = true;
    } else if (vaultStatus.locked) {
      // Unlock existing container vault
      const unlockResult = await unlockContainerVault(user, password);
      if (!unlockResult.success) {
        result.success = false;
        result.errors.push(`Failed to unlock container vault: ${unlockResult.error}`);
        await updateMigrationStatus(userId, MIGRATION_STATUS.FAILED, {
          error: "Failed to unlock container vault",
        });
        return result;
      }
      result.containerVaultUnlocked = true;
    }

    // Step 4: Migrate integrations
    const integrations = vaultData.integrations || {};
    const integrationEntries = Object.entries(integrations);

    if (integrationEntries.length === 0) {
      result.message = "No integrations to migrate";
    } else {
      for (const [provider, integration] of integrationEntries) {
        try {
          const importResult = await importIntegrationToContainer(user, provider, integration);
          if (importResult.success) {
            result.integrationsMigrated.push(provider);
          } else {
            result.integrationsFailed.push({ provider, error: importResult.error });
          }
        } catch (err) {
          result.integrationsFailed.push({ provider, error: err.message });
        }
      }
    }

    // Determine final status
    result.completedAt = new Date().toISOString();

    if (result.integrationsFailed.length === 0) {
      await updateMigrationStatus(userId, MIGRATION_STATUS.COMPLETED, {
        completedAt: result.completedAt,
        integrationsMigrated: result.integrationsMigrated.length,
      });
    } else if (result.integrationsMigrated.length > 0) {
      // Partial success
      await updateMigrationStatus(userId, MIGRATION_STATUS.PARTIAL, {
        completedAt: result.completedAt,
        integrationsMigrated: result.integrationsMigrated.length,
        integrationsFailed: result.integrationsFailed.length,
      });
      result.success = true;
      result.partial = true;
    } else {
      await updateMigrationStatus(userId, MIGRATION_STATUS.FAILED, {
        error: "All integrations failed to migrate",
        failedIntegrations: result.integrationsFailed.length,
      });
      result.success = false;
    }

    // Audit log
    if (adminUserId) {
      await audit.log(
        adminUserId,
        "vault.migration",
        {
          targetUserId: userId,
          status: result.success ? (result.partial ? "partial" : "completed") : "failed",
          integrationsMigrated: result.integrationsMigrated.length,
          integrationsFailed: result.integrationsFailed.length,
        },
        ipAddress,
        userId,
      );
    }

    return result;
  } catch (err) {
    result.success = false;
    result.errors.push(`Unexpected error: ${err.message}`);
    await updateMigrationStatus(userId, MIGRATION_STATUS.FAILED, {
      error: err.message,
    });
    return result;
  }
}

/**
 * Check if a user is eligible for migration
 */
export async function checkMigrationEligibility(userId) {
  const user = await users.findById(userId);
  if (!user) {
    return { eligible: false, reason: "User not found" };
  }

  const checks = {
    hasContainer: !!(user.container_id && user.container_port),
    hasVault: !!user.vault,
    containerActive: user.status === "active",
  };

  const eligible = checks.hasContainer && checks.hasVault;

  return {
    eligible,
    checks,
    reason: !eligible
      ? !checks.hasContainer
        ? "No container provisioned"
        : "No vault configured"
      : null,
  };
}

/**
 * List users eligible for migration
 */
export async function listMigrationCandidates() {
  const allUsers = await users.list();
  const candidates = [];

  for (const user of allUsers) {
    const eligibility = await checkMigrationEligibility(user.id);
    const status = await getMigrationStatus(user.id);

    if (eligibility.eligible) {
      candidates.push({
        userId: user.id,
        email: user.email,
        name: user.name,
        migrationStatus: status.status,
        lastAttempt: status.lastAttempt,
      });
    }
  }

  return candidates;
}
