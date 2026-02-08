/**
 * Secret Store Gateway Runtime Integration
 *
 * Initializes and manages the container-side secret store within the gateway.
 * This ensures the vault is available when the gateway starts and provides
 * runtime access to credentials for MCP tools and other gateway components.
 */

import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { OpenClawConfig } from "../config/config.js";
import {
  getCredentialProvider,
  type CredentialProvider,
  type AgentCredential,
} from "../container/agent-credentials.js";
import {
  getSecretStore,
  resetSecretStore,
  type SecretStore,
  type SecretStoreOptions,
} from "../container/secret-store.js";
import { createSubsystemLogger } from "../logging/subsystem.js";

const log = createSubsystemLogger("gateway/secret-store");

export interface SecretStoreRuntimeConfig {
  /** Base directory for secret storage (default: ~/.ocmt) */
  baseDir?: string;
  /** Auto-unlock vault on startup if password is provided via env */
  autoUnlockFromEnv?: boolean;
  /** Environment variable name for auto-unlock password */
  passwordEnvVar?: string;
  /** Relay URL for capability revocation notifications */
  relayUrl?: string;
}

export interface SecretStoreRuntimeState {
  /** The singleton secret store instance */
  store: SecretStore;
  /** Credential provider for agents/MCP tools */
  credentialProvider: CredentialProvider;
  /** Whether the vault is initialized (file exists) */
  initialized: boolean;
  /** Whether the vault is currently unlocked */
  unlocked: boolean;
  /** Stop the runtime (cleanup timers, etc.) */
  stop: () => void;
}

/**
 * Default password environment variable for auto-unlock.
 * Set OCMT_VAULT_PASSWORD to auto-unlock on gateway start.
 */
const DEFAULT_PASSWORD_ENV_VAR = "OCMT_VAULT_PASSWORD";

/**
 * Default base directory for secret storage.
 */
const DEFAULT_BASE_DIR = join(homedir(), ".ocmt");

/**
 * Interval for session keep-alive when vault is unlocked (every 10 minutes).
 */
const SESSION_KEEPALIVE_INTERVAL_MS = 10 * 60 * 1000;

/**
 * Initialize the secret store runtime for the gateway.
 *
 * This should be called during gateway startup to ensure the secret store
 * is available for credential access. If auto-unlock is enabled and the
 * vault password is provided via environment variable, it will attempt
 * to unlock automatically.
 *
 * @param cfg - OpenClaw configuration (optional, for future config-driven options)
 * @param runtimeConfig - Secret store runtime configuration
 * @returns Secret store runtime state
 */
export async function initSecretStoreRuntime(
  cfg?: OpenClawConfig,
  runtimeConfig?: SecretStoreRuntimeConfig,
): Promise<SecretStoreRuntimeState> {
  const baseDir = runtimeConfig?.baseDir ?? DEFAULT_BASE_DIR;
  const autoUnlockFromEnv = runtimeConfig?.autoUnlockFromEnv ?? true;
  const passwordEnvVar = runtimeConfig?.passwordEnvVar ?? DEFAULT_PASSWORD_ENV_VAR;
  const relayUrl = runtimeConfig?.relayUrl;

  const storeOptions: SecretStoreOptions = {
    baseDir,
    relayUrl,
  };

  // Get or create the singleton store instance
  const store = getSecretStore(storeOptions);
  const credentialProvider = getCredentialProvider();

  // Check if vault is initialized
  const secretsPath = join(baseDir, "secrets.enc");
  const initialized = existsSync(secretsPath);

  let unlocked = store.isUnlocked();
  let keepaliveTimer: NodeJS.Timeout | null = null;

  // Attempt auto-unlock if configured
  if (initialized && !unlocked && autoUnlockFromEnv) {
    const password = process.env[passwordEnvVar];
    if (password) {
      try {
        const success = await store.unlock(password);
        if (success) {
          unlocked = true;
          log.info("vault auto-unlocked from environment");
        } else {
          log.warn("vault auto-unlock failed: invalid password");
        }
      } catch (err) {
        log.warn(`vault auto-unlock failed: ${String(err)}`);
      }
    } else {
      log.info("vault not auto-unlocked (no password in environment)");
    }
  }

  // Start session keepalive timer if unlocked
  if (unlocked) {
    keepaliveTimer = setInterval(() => {
      if (store.isUnlocked()) {
        try {
          store.extendSession();
          log.debug("vault session extended");
        } catch (err) {
          log.warn(`failed to extend vault session: ${String(err)}`);
        }
      }
    }, SESSION_KEEPALIVE_INTERVAL_MS);
  }

  const stop = () => {
    if (keepaliveTimer) {
      clearInterval(keepaliveTimer);
      keepaliveTimer = null;
    }
  };

  return {
    store,
    credentialProvider,
    initialized,
    unlocked,
    stop,
  };
}

/**
 * Get the vault status for diagnostic/health checks.
 */
export function getSecretStoreStatus(): {
  initialized: boolean;
  locked: boolean;
  sessionTimeRemaining: number;
  publicKey: string | null;
} {
  const store = getSecretStore();
  const secretsPath = join(DEFAULT_BASE_DIR, "secrets.enc");

  return {
    initialized: existsSync(secretsPath),
    locked: !store.isUnlocked(),
    sessionTimeRemaining: store.getSessionTimeRemaining(),
    publicKey: store.getPublicKey(),
  };
}

/**
 * Get credentials for a provider from the local secret store.
 * Returns null if vault is locked or credential doesn't exist.
 *
 * This is the primary interface for MCP tools to retrieve credentials.
 */
export function getCredentialFromStore(provider: string): AgentCredential | null {
  const credentialProvider = getCredentialProvider();
  return credentialProvider.getCredential(provider);
}

/**
 * Check if the vault is ready for credential access.
 */
export function isVaultReady(): boolean {
  const credentialProvider = getCredentialProvider();
  return credentialProvider.isReady();
}

/**
 * List available credential providers.
 */
export function listCredentialProviders(): Array<{
  provider: string;
  email?: string;
  expiresAt: Date;
}> {
  const credentialProvider = getCredentialProvider();
  return credentialProvider.listProviders();
}

/**
 * Reset the secret store runtime (for testing).
 */
export function resetSecretStoreRuntime(): void {
  resetSecretStore();
}
