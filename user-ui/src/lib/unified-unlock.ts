/**
 * Unified unlock flow for vault operations.
 *
 * Provides a single entry point for unlocking both the legacy vault
 * (for integrations/capabilities) and the session vault (for encrypted sessions).
 *
 * Security model:
 * - Password derivation happens entirely in the browser
 * - Derived keys go directly to the container
 * - Management server never sees the password or derived keys
 */

import { api, type ApiResult } from "./api.js";
import {
  createContainerUnlockProxyClient,
  createContainerUnlockClient,
  createContainerUnlockHttpClient,
  type IContainerUnlockClient,
} from "./container-unlock.js";

// ============================================================================
// Types
// ============================================================================

export interface UnlockResult {
  success: boolean;
  expiresIn?: number;
  error?: string;
  /** Whether the legacy vault was unlocked */
  legacyVaultUnlocked?: boolean;
  /** Whether the session vault was unlocked */
  sessionVaultUnlocked?: boolean;
}

export interface VaultStatus {
  /** Legacy vault status */
  legacyVault: {
    initialized: boolean;
    locked: boolean;
    expiresIn: number;
  };
  /** Session vault status (encrypted sessions) */
  sessionVault: {
    initialized: boolean;
    locked: boolean;
    expiresIn: number | null;
    sessionsEncrypted: boolean;
  };
}

export interface UnlockOptions {
  /** Unlock legacy vault (integrations, capabilities) */
  unlockLegacy?: boolean;
  /** Unlock session vault (encrypted sessions) */
  unlockSession?: boolean;
  /** Migrate existing sessions to encrypted format */
  migrateExistingSessions?: boolean;
}

// ============================================================================
// Unified Unlock Client
// ============================================================================

/**
 * Unified unlock client that handles both legacy and session vault operations.
 */
export class UnifiedUnlockClient {
  private client: IContainerUnlockClient | null = null;
  private proxyEnabled: boolean;
  private vaultProxyPath: string;
  // Legacy fields (deprecated)
  private agentServerUrl: string | null;
  private userId: string;
  private authToken?: string;

  constructor(
    private containerInfo: {
      userId: string;
      proxyEnabled?: boolean;
      vaultProxyPath?: string;
      // Legacy fields (deprecated - will be null when proxyEnabled is true)
      agentServerUrl?: string | null;
      authToken?: string;
    },
  ) {
    this.proxyEnabled = containerInfo.proxyEnabled ?? true;
    this.vaultProxyPath = containerInfo.vaultProxyPath ?? "/api/container/vault";
    this.userId = containerInfo.userId;
    // Legacy fields
    this.agentServerUrl = containerInfo.agentServerUrl ?? null;
    this.authToken = containerInfo.authToken;
  }

  /**
   * Get or create the underlying container unlock client.
   * SECURITY: Uses proxy client by default - no authToken exposed to browser.
   */
  private async getClient(): Promise<IContainerUnlockClient> {
    if (this.client) {
      return this.client;
    }

    // Use proxy client (preferred - no authToken exposure)
    if (this.proxyEnabled || !this.agentServerUrl) {
      this.client = createContainerUnlockProxyClient(this.vaultProxyPath);
      return this.client;
    }

    // Legacy path: direct connection (deprecated)
    console.warn("[UnifiedUnlockClient] Using legacy direct connection - this is deprecated");
    try {
      this.client = createContainerUnlockClient(this.agentServerUrl, this.userId, this.authToken);
      return this.client;
    } catch {
      // WebSocket failed, use HTTP
      if (!this.authToken) {
        throw new Error("Auth token required for HTTP fallback");
      }
      this.client = createContainerUnlockHttpClient(
        this.agentServerUrl,
        this.userId,
        this.authToken,
      );
      return this.client;
    }
  }

  /**
   * Get status of both vault systems.
   */
  async getStatus(): Promise<VaultStatus> {
    const client = await this.getClient();

    const [legacyStatus, sessionStatus] = await Promise.all([
      client.getVaultStatus().catch(() => ({
        initialized: false,
        locked: true,
        expiresIn: 0,
        publicKey: null,
      })),
      client.getSessionVaultStatus().catch(() => ({
        success: false,
        status: {
          initialized: false,
          locked: true,
          expiresIn: null,
          sessionsEncrypted: false,
        },
      })),
    ]);

    return {
      legacyVault: {
        initialized: legacyStatus.initialized,
        locked: legacyStatus.locked,
        expiresIn: legacyStatus.expiresIn,
      },
      sessionVault: sessionStatus.status || {
        initialized: false,
        locked: true,
        expiresIn: null,
        sessionsEncrypted: false,
      },
    };
  }

  /**
   * Unlock vaults with password.
   * By default unlocks both legacy and session vaults.
   */
  async unlock(password: string, options: UnlockOptions = {}): Promise<UnlockResult> {
    const { unlockLegacy = true, unlockSession = true, migrateExistingSessions = true } = options;

    const client = await this.getClient();
    const result: UnlockResult = { success: true };

    // Unlock legacy vault
    if (unlockLegacy) {
      try {
        const legacyResult = await client.unlock(password);
        result.legacyVaultUnlocked = legacyResult.success;
        if (legacyResult.expiresIn) {
          result.expiresIn = legacyResult.expiresIn;
        }
        if (!legacyResult.success) {
          result.success = false;
          result.error = legacyResult.error;
        }
      } catch (err) {
        result.legacyVaultUnlocked = false;
        result.success = false;
        result.error = (err as Error).message;
      }
    }

    // Unlock session vault
    if (unlockSession) {
      try {
        const sessionResult = await client.unlockSessionVault(password);
        result.sessionVaultUnlocked = sessionResult.success;
        if (
          sessionResult.expiresIn &&
          (!result.expiresIn || sessionResult.expiresIn < result.expiresIn)
        ) {
          result.expiresIn = sessionResult.expiresIn;
        }
        if (!sessionResult.success) {
          // Session unlock failure is not fatal if legacy succeeded
          if (!result.legacyVaultUnlocked) {
            result.success = false;
            result.error = sessionResult.error;
          }
        }

        // Migrate existing sessions if requested and session vault is unlocked
        if (sessionResult.success && migrateExistingSessions) {
          try {
            await client.migrateSessionsToEncrypted();
          } catch {
            // Migration failure is not fatal
            console.warn("Failed to migrate sessions to encrypted format");
          }
        }
      } catch (err) {
        result.sessionVaultUnlocked = false;
        // Session unlock failure is not fatal if legacy succeeded
        if (!result.legacyVaultUnlocked) {
          result.success = false;
          result.error = (err as Error).message;
        }
      }
    }

    return result;
  }

  /**
   * Lock both vaults.
   */
  async lock(): Promise<{ success: boolean }> {
    const client = await this.getClient();

    await Promise.all([
      client.lock().catch(() => ({})),
      client.lockSessionVault().catch(() => ({})),
    ]);

    return { success: true };
  }

  /**
   * Extend both vault sessions.
   */
  async extend(): Promise<{ success: boolean; expiresIn?: number }> {
    const client = await this.getClient();

    const [legacyResult, sessionResult] = await Promise.all([
      client.extendSession().catch(() => ({ success: false, expiresIn: 0 })),
      client.extendSessionVault().catch(() => ({ success: false, expiresIn: 0 })),
    ]);

    // Return the shorter expiration time
    const expiresIn = Math.min(
      legacyResult.expiresIn || Infinity,
      sessionResult.expiresIn || Infinity,
    );

    return {
      success: legacyResult.success || sessionResult.success,
      expiresIn: expiresIn === Infinity ? undefined : expiresIn,
    };
  }

  /**
   * Close the connection.
   */
  close(): void {
    if (this.client) {
      this.client.close();
      this.client = null;
    }
  }
}

// ============================================================================
// High-Level API Functions
// ============================================================================

/**
 * Create a unified unlock client for the current user.
 * SECURITY: Uses proxy endpoints by default - authToken is never exposed to browser.
 */
export async function createUnifiedUnlockClient(): Promise<UnifiedUnlockClient | null> {
  try {
    // Get container unlock info from management server
    const result = await api.getContainerUnlockInfo();
    if (!result.success) {
      console.error("Failed to get container unlock info:", result.error);
      return null;
    }

    const data = result.data;

    // New API: proxyEnabled=true, uses management server proxy endpoints
    // Legacy API: agentServerUrl and authToken provided (deprecated)
    return new UnifiedUnlockClient({
      userId: data.userId,
      proxyEnabled: data.proxyEnabled ?? !data.authToken,
      vaultProxyPath: data.vaultProxyPath ?? data.httpPathPrefix ?? "/api/container/vault",
      // Legacy fields (will be null/undefined when using proxy)
      agentServerUrl: data.agentServerUrl,
      authToken: data.authToken,
    });
  } catch (err) {
    console.error("Failed to create unlock client:", err);
    return null;
  }
}

/**
 * Unlock vault with password using the unified flow.
 * This is the main entry point for vault unlock operations.
 */
export async function unlockVault(
  password: string,
  options: UnlockOptions = {},
): Promise<UnlockResult> {
  const client = await createUnifiedUnlockClient();
  if (!client) {
    return { success: false, error: "Failed to connect to container" };
  }

  try {
    return await client.unlock(password, options);
  } finally {
    client.close();
  }
}

/**
 * Get vault status using the unified flow.
 */
export async function getVaultStatus(): Promise<VaultStatus | null> {
  const client = await createUnifiedUnlockClient();
  if (!client) {
    return null;
  }

  try {
    return await client.getStatus();
  } finally {
    client.close();
  }
}

/**
 * Lock vault using the unified flow.
 */
export async function lockVault(): Promise<{ success: boolean }> {
  const client = await createUnifiedUnlockClient();
  if (!client) {
    return { success: false };
  }

  try {
    return await client.lock();
  } finally {
    client.close();
  }
}
