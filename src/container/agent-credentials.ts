/**
 * Agent Credentials Provider
 *
 * Provides an interface for agents to access credentials from the local
 * secret store instead of calling the management server. All credentials
 * are stored locally in the container and never leave in plaintext.
 */

import { createSubsystemLogger } from "../logging/subsystem.js";
import { getSecretStore, type Integration } from "./secret-store.js";

const log = createSubsystemLogger("container/credentials");

export interface AgentCredential {
  provider: string;
  accessToken: string;
  refreshToken?: string;
  expiresAt: Date;
  email?: string;
  scopes?: string[];
}

export interface CredentialProvider {
  /**
   * Get credentials for a specific provider (e.g., "google", "github", "slack")
   * Returns null if credentials are not available or vault is locked
   */
  getCredential(provider: string): AgentCredential | null;

  /**
   * List available integrations (without exposing tokens)
   */
  listProviders(): Array<{ provider: string; email?: string; expiresAt: Date }>;

  /**
   * Check if the secret store is unlocked and ready
   */
  isReady(): boolean;

  /**
   * Check if credentials exist for a provider (even if vault is locked)
   * This can be used to prompt user to unlock
   */
  hasCredential(provider: string): boolean;
}

/**
 * Create a credential provider backed by the local secret store
 */
export function createLocalCredentialProvider(): CredentialProvider {
  const store = getSecretStore();

  return {
    getCredential(provider: string): AgentCredential | null {
      if (!store.isUnlocked()) {
        log.warn(`cannot get credential for ${provider}: vault is locked`);
        return null;
      }

      const integration = store.getIntegration(provider);
      if (!integration) {
        return null;
      }

      return {
        provider,
        accessToken: integration.accessToken,
        refreshToken: integration.refreshToken,
        expiresAt: new Date(integration.expiresAt),
        email: integration.email,
        scopes: integration.scopes,
      };
    },

    listProviders(): Array<{ provider: string; email?: string; expiresAt: Date }> {
      if (!store.isUnlocked()) {
        log.warn("cannot list providers: vault is locked");
        return [];
      }

      return store.listIntegrations().map((int) => ({
        provider: int.provider,
        email: int.email,
        expiresAt: new Date(int.expiresAt),
      }));
    },

    isReady(): boolean {
      return store.isUnlocked();
    },

    hasCredential(provider: string): boolean {
      if (!store.isUnlocked()) {
        // Can't check without unlocking
        return false;
      }
      return store.getIntegration(provider) !== null;
    },
  };
}

// Singleton instance
let credentialProvider: CredentialProvider | null = null;

/**
 * Get the shared credential provider instance
 */
export function getCredentialProvider(): CredentialProvider {
  if (!credentialProvider) {
    credentialProvider = createLocalCredentialProvider();
  }
  return credentialProvider;
}

/**
 * Store credentials in the local secret store
 * This is called when OAuth flow completes or credentials are refreshed
 */
export async function storeCredential(
  provider: string,
  credential: {
    accessToken: string;
    refreshToken?: string;
    expiresAt: Date;
    email?: string;
    scopes?: string[];
  },
): Promise<boolean> {
  const store = getSecretStore();

  if (!store.isUnlocked()) {
    log.warn(`cannot store credential for ${provider}: vault is locked`);
    return false;
  }

  try {
    await store.setIntegration(provider, {
      accessToken: credential.accessToken,
      refreshToken: credential.refreshToken,
      expiresAt: credential.expiresAt.toISOString(),
      email: credential.email,
      scopes: credential.scopes,
    });
    log.info(`stored credential for ${provider}`);
    return true;
  } catch (err) {
    log.error(`failed to store credential for ${provider}: ${String(err)}`);
    return false;
  }
}

/**
 * Remove credentials from the local secret store
 */
export async function removeCredential(provider: string): Promise<boolean> {
  const store = getSecretStore();

  if (!store.isUnlocked()) {
    log.warn(`cannot remove credential for ${provider}: vault is locked`);
    return false;
  }

  try {
    await store.removeIntegration(provider);
    log.info(`removed credential for ${provider}`);
    return true;
  } catch (err) {
    log.error(`failed to remove credential for ${provider}: ${String(err)}`);
    return false;
  }
}

/**
 * Check if credentials are expired or about to expire
 */
export function isCredentialExpired(
  credential: AgentCredential,
  bufferMs = 5 * 60 * 1000,
): boolean {
  return credential.expiresAt.getTime() - bufferMs < Date.now();
}

/**
 * Adapter to convert local credentials to the format expected by external APIs
 */
export function toOAuthCredentials(credential: AgentCredential): {
  access_token: string;
  refresh_token?: string;
  expires_at: number;
} {
  return {
    access_token: credential.accessToken,
    refresh_token: credential.refreshToken,
    expires_at: Math.floor(credential.expiresAt.getTime() / 1000),
  };
}
