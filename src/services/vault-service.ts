/**
 * Container-side vault service.
 * Handles vault state, session encryption key lifecycle, and KDF parameters.
 *
 * Security model:
 * - Salt stored on disk, never transmitted except for key derivation challenge
 * - Derived key held in memory during unlock, securely erased on lock/timeout
 * - All encryption/decryption happens in the SecureSessionStore
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { SecureSessionStore } from "../config/sessions/encrypted-store.js";

// ============================================================================
// Types
// ============================================================================

export interface VaultConfig {
  sessionDir: string;
  kdfMemory?: number; // Default: 65536 (64 MB)
  kdfIterations?: number; // Default: 3
  kdfParallelism?: number; // Default: 4
}

export interface VaultStatus {
  initialized: boolean;
  locked: boolean;
  expiresIn: number | null;
  sessionsEncrypted: boolean;
}

export interface VaultChallenge {
  salt: string; // Base64 encoded
  kdf: {
    algorithm: "argon2id";
    memory: number;
    iterations: number;
    parallelism: number;
  };
}

// ============================================================================
// ContainerVaultService Implementation
// ============================================================================

export class ContainerVaultService {
  private sessionStore: SecureSessionStore;
  private salt: Uint8Array | null = null;
  private config: Required<VaultConfig>;

  private static readonly SALT_FILE = ".vault-salt";
  private static readonly SALT_SIZE = 16; // 128-bit salt
  private static readonly DEFAULT_CONFIG = {
    kdfMemory: 65536, // 64 MB
    kdfIterations: 3,
    kdfParallelism: 4,
  };

  constructor(config: VaultConfig) {
    this.config = {
      sessionDir: config.sessionDir,
      kdfMemory: config.kdfMemory ?? ContainerVaultService.DEFAULT_CONFIG.kdfMemory,
      kdfIterations: config.kdfIterations ?? ContainerVaultService.DEFAULT_CONFIG.kdfIterations,
      kdfParallelism: config.kdfParallelism ?? ContainerVaultService.DEFAULT_CONFIG.kdfParallelism,
    };
    this.sessionStore = new SecureSessionStore(config.sessionDir);
  }

  /**
   * Initialize the vault. Creates a new salt if one doesn't exist.
   * @returns The salt (base64) and whether it was newly created
   */
  async initialize(): Promise<{ salt: string; isNew: boolean }> {
    const saltPath = this.getSaltPath();

    // Ensure directory exists
    await fs.promises.mkdir(this.config.sessionDir, { recursive: true });

    if (fs.existsSync(saltPath)) {
      // Load existing salt
      const saltBuffer = await fs.promises.readFile(saltPath);
      this.salt = new Uint8Array(saltBuffer);
      return { salt: Buffer.from(this.salt).toString("base64"), isNew: false };
    }

    // Generate new salt
    this.salt = crypto.randomBytes(ContainerVaultService.SALT_SIZE);
    await fs.promises.writeFile(saltPath, Buffer.from(this.salt), { mode: 0o600 });
    return { salt: Buffer.from(this.salt).toString("base64"), isNew: true };
  }

  /**
   * Check if the vault has been initialized (salt exists).
   */
  isInitialized(): boolean {
    return this.salt !== null;
  }

  /**
   * Get the challenge for client-side key derivation.
   * Contains salt and KDF parameters.
   */
  getChallenge(): VaultChallenge {
    if (!this.salt) {
      throw new Error("Vault not initialized");
    }

    return {
      salt: Buffer.from(this.salt).toString("base64"),
      kdf: {
        algorithm: "argon2id",
        memory: this.config.kdfMemory,
        iterations: this.config.kdfIterations,
        parallelism: this.config.kdfParallelism,
      },
    };
  }

  /**
   * Unlock the vault with a derived key.
   * @param derivedKey - 32-byte key derived from password via Argon2id
   * @returns Time until auto-lock in seconds
   */
  async unlock(derivedKey: Buffer): Promise<{ expiresIn: number }> {
    await this.sessionStore.unlock(derivedKey);

    const expiresAt = this.sessionStore.getExpiresAt();
    return {
      expiresIn: expiresAt ? Math.floor((expiresAt - Date.now()) / 1000) : 0,
    };
  }

  /**
   * Lock the vault and securely erase the key.
   */
  lock(): void {
    this.sessionStore.lock();
  }

  /**
   * Extend the vault session timeout.
   * @returns Time until auto-lock in seconds
   */
  extend(): { expiresIn: number } {
    this.sessionStore.extend();

    const expiresAt = this.sessionStore.getExpiresAt();
    return {
      expiresIn: expiresAt ? Math.floor((expiresAt - Date.now()) / 1000) : 0,
    };
  }

  /**
   * Get the current vault status.
   */
  getStatus(): VaultStatus {
    const expiresAt = this.sessionStore.getExpiresAt();
    return {
      initialized: this.salt !== null,
      locked: !this.sessionStore.isUnlocked(),
      expiresIn: expiresAt ? Math.floor((expiresAt - Date.now()) / 1000) : null,
      sessionsEncrypted: true,
    };
  }

  /**
   * Get the underlying session store for direct session operations.
   */
  getSessionStore(): SecureSessionStore {
    return this.sessionStore;
  }

  /**
   * Get the current unlock key (for biometric enrollment).
   * Returns null if vault is locked.
   */
  getUnlockKey(): Buffer | null {
    return this.sessionStore.getUnlockKey();
  }

  /**
   * Migrate existing unencrypted sessions to encrypted format.
   * Vault must be unlocked.
   */
  async migrateExistingSessions(): Promise<{ migrated: number; failed: string[] }> {
    return this.sessionStore.migrateUnencryptedSessions();
  }

  /**
   * Initialize and unlock in one operation (for migration from old vault).
   * @param derivedKey - 32-byte key
   * @param migrateExisting - Whether to migrate existing plaintext sessions
   */
  async migrateAndUnlock(
    derivedKey: Buffer,
    migrateExisting: boolean = true,
  ): Promise<{ expiresIn: number; migrated?: number; failed?: string[] }> {
    // Initialize if needed
    if (!this.isInitialized()) {
      await this.initialize();
    }

    // Unlock
    const unlockResult = await this.unlock(derivedKey);

    // Optionally migrate
    if (migrateExisting) {
      const migrationResult = await this.migrateExistingSessions();
      return {
        ...unlockResult,
        migrated: migrationResult.migrated,
        failed: migrationResult.failed,
      };
    }

    return unlockResult;
  }

  // ============================================================================
  // Private Helpers
  // ============================================================================

  private getSaltPath(): string {
    return path.join(this.config.sessionDir, ContainerVaultService.SALT_FILE);
  }
}

// ============================================================================
// Singleton Instance Management
// ============================================================================

let globalVaultService: ContainerVaultService | null = null;

/**
 * Get the global ContainerVaultService instance.
 */
export function getVaultService(): ContainerVaultService | null {
  return globalVaultService;
}

/**
 * Initialize the global ContainerVaultService with configuration.
 */
export async function initVaultService(config: VaultConfig): Promise<ContainerVaultService> {
  globalVaultService = new ContainerVaultService(config);
  await globalVaultService.initialize();
  return globalVaultService;
}

/**
 * Clear the global ContainerVaultService instance.
 * Primarily for testing.
 */
export function clearVaultService(): void {
  if (globalVaultService) {
    globalVaultService.lock();
  }
  globalVaultService = null;
}
