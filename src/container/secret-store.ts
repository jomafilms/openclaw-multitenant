/**
 * Container-Side Secret Store
 *
 * Encrypted local storage for user secrets. Secrets never leave the container
 * in plaintext. The management server cannot decrypt this data.
 */

import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  scryptSync,
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
  KeyObject,
  diffieHellman,
  createHash,
} from "crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";
import { homedir } from "os";
import { join, dirname } from "path";
import { createSubsystemLogger } from "../logging/subsystem.js";
import { type RelayClient, type RelayClientConfig } from "../relay/client.js";

const log = createSubsystemLogger("secret-store");

// Use XChaCha20-Poly1305 via libsodium when available, fallback to AES-256-GCM
const ALGORITHM = "aes-256-gcm";
const KEY_LENGTH = 32;
const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;
const SCRYPT_N = 2 ** 16;
const SCRYPT_R = 8;
const SCRYPT_P = 1;

// Session timeout: 30 minutes
const SESSION_TIMEOUT_MS = 30 * 60 * 1000;

// Ed25519 SPKI prefix for DER-encoded public keys (12 bytes header + 32 bytes key)
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
// X25519 SPKI prefix for DER-encoded public keys (12 bytes header + 32 bytes key)
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

/**
 * Sharing tier determines how capabilities can be accessed when issuer is offline.
 * - LIVE: Real-time access only, issuer must be online (current model)
 * - CACHED: Periodic encrypted snapshots pushed to relay, accessible offline
 * - DELEGATED: Direct token delegation (future, most dangerous)
 */
export type SharingTier = "LIVE" | "CACHED" | "DELEGATED";

/**
 * Generate an Ed25519 keypair for signing and X25519 keypair for encryption.
 */
function generateIdentityKeypairs(): Identity {
  // Ed25519 for signing
  const { publicKey: ed25519Pub, privateKey: ed25519Priv } = generateKeyPairSync("ed25519");

  const publicKeyPem = ed25519Pub.export({ type: "spki", format: "pem" }).toString();
  const privateKeyPem = ed25519Priv.export({ type: "pkcs8", format: "pem" }).toString();

  // Extract raw 32-byte public key from SPKI encoding
  const spkiDer = ed25519Pub.export({ type: "spki", format: "der" }) as Buffer;
  const rawPublicKey = spkiDer.subarray(ED25519_SPKI_PREFIX.length);

  // X25519 for encryption (ECDH key exchange)
  const { publicKey: x25519Pub, privateKey: x25519Priv } = generateKeyPairSync("x25519");

  const encryptionPublicKeyPem = x25519Pub.export({ type: "spki", format: "pem" }).toString();
  const encryptionPrivateKeyPem = x25519Priv.export({ type: "pkcs8", format: "pem" }).toString();

  const x25519SpkiDer = x25519Pub.export({ type: "spki", format: "der" }) as Buffer;
  const rawEncryptionPublicKey = x25519SpkiDer.subarray(X25519_SPKI_PREFIX.length);

  return {
    publicKey: rawPublicKey.toString("base64"),
    privateKeyPem,
    publicKeyPem,
    encryptionPublicKey: rawEncryptionPublicKey.toString("base64"),
    encryptionPrivateKeyPem,
    encryptionPublicKeyPem,
    algorithm: "Ed25519",
  };
}

/**
 * Create a KeyObject from a base64-encoded raw Ed25519 public key.
 */
function publicKeyFromBase64(publicKeyBase64: string): KeyObject {
  const rawKey = Buffer.from(publicKeyBase64, "base64");
  if (rawKey.length !== 32) {
    throw new Error(`Invalid Ed25519 public key length: expected 32 bytes, got ${rawKey.length}`);
  }
  // Reconstruct SPKI-encoded DER format
  const spkiDer = Buffer.concat([ED25519_SPKI_PREFIX, rawKey]);
  return createPublicKey({ key: spkiDer, type: "spki", format: "der" });
}

/**
 * Create an X25519 KeyObject from a base64-encoded raw public key.
 */
function x25519PublicKeyFromBase64(publicKeyBase64: string): KeyObject {
  const rawKey = Buffer.from(publicKeyBase64, "base64");
  if (rawKey.length !== 32) {
    throw new Error(`Invalid X25519 public key length: expected 32 bytes, got ${rawKey.length}`);
  }
  // Reconstruct SPKI-encoded DER format
  const spkiDer = Buffer.concat([X25519_SPKI_PREFIX, rawKey]);
  return createPublicKey({ key: spkiDer, type: "spki", format: "der" });
}

export interface Integration {
  accessToken: string;
  refreshToken?: string;
  expiresAt: string;
  email?: string;
  scopes?: string[];
  metadata?: Record<string, unknown>;
}

export interface Identity {
  /** Base64-encoded raw 32-byte Ed25519 public key (for signing) */
  publicKey: string;
  /** PEM-encoded Ed25519 private key (stored encrypted in vault) */
  privateKeyPem: string;
  /** PEM-encoded Ed25519 public key for easy KeyObject creation */
  publicKeyPem: string;
  /** Base64-encoded raw 32-byte X25519 public key (for encryption) */
  encryptionPublicKey?: string;
  /** PEM-encoded X25519 private key (stored encrypted in vault) */
  encryptionPrivateKeyPem?: string;
  /** PEM-encoded X25519 public key */
  encryptionPublicKeyPem?: string;
  algorithm: "Ed25519";
}

export interface CapabilityGrant {
  id: string;
  subject: string; // Ed25519 public key of grantee (for verification)
  subjectEncryptionKey?: string; // X25519 public key of grantee (for CACHED snapshots)
  resource: string;
  scope: string[];
  expires: string;
  maxCalls?: number;
  callCount: number;
  revoked: boolean;
  issuedAt: string;
  /** Sharing tier: LIVE (default), CACHED, or DELEGATED */
  tier: SharingTier;
  /** For CACHED tier: refresh interval in seconds (default: 3600 = 1 hour) */
  cacheRefreshInterval?: number;
  /** For CACHED tier: last snapshot timestamp */
  lastSnapshotAt?: string;
}

/**
 * Encrypted snapshot for CACHED tier sharing.
 * Stored on relay for offline access.
 */
export interface CachedSnapshot {
  /** Capability ID this snapshot belongs to */
  capabilityId: string;
  /** Encrypted resource data (AES-256-GCM, key from X25519 ECDH) */
  encryptedData: string;
  /** Ephemeral X25519 public key used for ECDH */
  ephemeralPublicKey: string;
  /** Nonce for AES-256-GCM */
  nonce: string;
  /** Auth tag for AES-256-GCM */
  tag: string;
  /** Signature of (capabilityId + encryptedData + ephemeralPublicKey) by issuer */
  signature: string;
  /** Issuer's Ed25519 public key for verification */
  issuerPublicKey: string;
  /** Recipient's X25519 public key (for relay to filter by recipient) */
  recipientPublicKey: string;
  /** When this snapshot was created */
  createdAt: string;
  /** When this snapshot expires (same as capability expiry) */
  expiresAt: string;
}

export interface ReceivedCapability {
  id: string;
  issuer: string; // Ed25519 public key of issuer
  issuerEncryptionKey?: string; // X25519 public key of issuer (for CACHED snapshots)
  issuerContainerId: string;
  resource: string;
  scope: string[];
  expires: string;
  token: string; // Signed capability token
  /** Sharing tier: LIVE (default), CACHED, or DELEGATED */
  tier: SharingTier;
  /** For CACHED tier: last known snapshot data */
  cachedSnapshot?: {
    data: string; // Decrypted resource data
    updatedAt: string;
  };
}

/**
 * Pending capability approval for human-in-the-loop.
 * When an agent requests to share access with another user,
 * the approval must be confirmed by the human owner.
 */
export interface PendingCapabilityApproval {
  id: string;
  subjectPublicKey: string;
  subjectEmail?: string;
  resource: string;
  scope: string[];
  expiresInSeconds: number;
  maxCalls?: number;
  reason?: string;
  agentContext?: Record<string, unknown>;
  status: "pending" | "approved" | "denied" | "expired";
  createdAt: string;
  decidedAt?: string;
  approvalToken?: string;
}

/**
 * Result of requesting a capability approval.
 */
export interface ApprovalRequestResult {
  approvalId: string;
  approvalToken: string;
  status: "pending";
  expiresAt: string;
}

/**
 * Options for the approval-aware capability issuance.
 */
export interface ApprovalAwareIssueOptions {
  maxCalls?: number;
  tier?: SharingTier;
  subjectEncryptionKey?: string;
  cacheRefreshInterval?: number;
  /** Email of the subject (for display in approval UI) */
  subjectEmail?: string;
  /** Reason for sharing (shown to user in approval request) */
  reason?: string;
  /** Additional context from the agent */
  agentContext?: Record<string, unknown>;
  /** Skip human approval (only for automated system operations) */
  skipApproval?: boolean;
  /** Pre-approved approval ID (if user already approved via management server) */
  approvalId?: string;
}

// Re-export ceiling types from the dedicated module
export {
  PERMISSION_LEVELS,
  DEFAULT_AGENT_CEILING,
  CEILING_ROLES,
  isValidPermission,
  getPermissionOrder,
  isWithinCeiling,
  partitionPermissions,
  getCeilingForRole,
  CeilingExceededError,
  InsufficientPermissionsError,
  CeilingManager,
  createEmptyCeilingStoreData,
  type PermissionLevel,
  type CeilingRole,
  type AgentCeilingConfig,
  type EscalationRequest,
  type CeilingStoreData,
  type UserPermissionConfig,
} from "./capability-ceiling.js";

import {
  CeilingManager,
  CeilingExceededError,
  createEmptyCeilingStoreData,
  type CeilingStoreData,
} from "./capability-ceiling.js";
import {
  KeyRotationManager,
  KeyRotationState,
  KeyRotationResult,
  createInitialRotationState,
  createFreshRotationState,
  rotateVaultKey,
  identifyCapabilitiesNeedingReissue,
  type VersionedIdentity,
  type ArchivedKey,
  type KeyRotationNotification,
} from "./key-rotation.js";

// Re-export key rotation types
export {
  KeyRotationManager,
  type KeyRotationState,
  type KeyRotationResult,
  type VersionedIdentity,
  type ArchivedKey,
  type KeyRotationNotification,
} from "./key-rotation.js";

export interface SecretStoreData {
  version: number;
  integrations: Record<string, Integration>;
  identity?: Identity;
  grants: Record<string, CapabilityGrant>;
  capabilities: Record<string, ReceivedCapability>;
  /** Pending cached snapshots to be pushed to relay */
  pendingSnapshots?: Record<string, CachedSnapshot>;
  /** Agent ceiling configurations and escalation requests */
  ceilingData?: CeilingStoreData;
  /** Key rotation state for versioned identity management */
  keyRotationState?: KeyRotationState;
  /** Map of capability ID to signer key version (for tracking which key signed each capability) */
  capabilityKeyVersions?: Record<string, number>;
}

interface EncryptedStore {
  version: number;
  algorithm: string;
  kdf: {
    algorithm: string;
    salt: string;
    n: number;
    r: number;
    p: number;
  };
  nonce: string;
  ciphertext: string;
  tag: string;
}

export interface SecretStoreOptions {
  baseDir?: string;
  /** Relay client for notifying revocations. If not provided, revocations are local only. */
  relayClient?: RelayClient;
  /** Relay URL for creating a default client. Ignored if relayClient is provided. */
  relayUrl?: string;
  /**
   * Scrypt N parameter for key derivation. Default is 2^16 (65536) for production.
   * Use a lower value like 2^14 (16384) for testing to avoid memory issues.
   * WARNING: Only use lower values in test environments!
   */
  scryptN?: number;
}

export class SecretStore {
  private storePath: string;
  private vaultKey: Buffer | null = null;
  private expiresAt = 0;
  private lockTimeout: NodeJS.Timeout | null = null;
  private data: SecretStoreData | null = null;
  private relayClient: RelayClient | null = null;
  private relayUrl: string | null = null;
  private scryptN: number;

  constructor(options?: SecretStoreOptions | string) {
    // Support both old string baseDir and new options object
    const opts: SecretStoreOptions =
      typeof options === "string" ? { baseDir: options } : (options ?? {});

    const base = opts.baseDir || join(homedir(), ".ocmt");
    this.storePath = join(base, "secrets.enc");

    // Store relay config for lazy client creation
    this.relayClient = opts.relayClient ?? null;
    this.relayUrl = opts.relayUrl ?? null;

    // Scrypt N parameter (lower for tests)
    this.scryptN = opts.scryptN ?? SCRYPT_N;

    // Ensure directory exists
    const dir = dirname(this.storePath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
  }

  /**
   * Configure the relay client for instant revocation notifications.
   * Call this after construction to enable relay notifications.
   */
  setRelayClient(client: RelayClient): void {
    this.relayClient = client;
  }

  /**
   * Get or create the relay client.
   * Returns null if no relay is configured.
   */
  private async getOrCreateRelayClient(): Promise<RelayClient | null> {
    if (this.relayClient) {
      return this.relayClient;
    }

    if (this.relayUrl) {
      // Lazy import to avoid circular dependencies
      const { RelayClient } = await import("../relay/client.js");
      this.relayClient = new RelayClient({ relayUrl: this.relayUrl });
      return this.relayClient;
    }

    return null;
  }

  /**
   * Check if vault is currently unlocked
   */
  isUnlocked(): boolean {
    return this.vaultKey !== null && Date.now() < this.expiresAt;
  }

  /**
   * Get remaining session time in seconds
   */
  getSessionTimeRemaining(): number {
    if (!this.isUnlocked()) {
      return 0;
    }
    return Math.floor((this.expiresAt - Date.now()) / 1000);
  }

  /**
   * Initialize a new secret store with a password
   */
  async initialize(password: string): Promise<void> {
    if (existsSync(this.storePath)) {
      throw new Error("Secret store already exists");
    }

    const salt = randomBytes(32);
    const key = this.deriveKey(password, salt);

    const initialData: SecretStoreData = {
      version: 2,
      integrations: {},
      grants: {},
      capabilities: {},
      pendingSnapshots: {},
    };

    // Generate Ed25519 (signing) and X25519 (encryption) identity keypairs
    initialData.identity = generateIdentityKeypairs();

    await this.encrypt(initialData, key, salt);
    this.vaultKey = key;
    this.data = initialData;
    this.startSession();
  }

  /**
   * Unlock the secret store with a password
   */
  async unlock(password: string): Promise<boolean> {
    if (!existsSync(this.storePath)) {
      throw new Error("Secret store not initialized");
    }

    const encrypted = JSON.parse(readFileSync(this.storePath, "utf-8")) as EncryptedStore;
    const salt = Buffer.from(encrypted.kdf.salt, "base64");
    const key = this.deriveKey(password, salt);

    try {
      this.data = await this.decrypt(encrypted, key);
      this.vaultKey = key;
      this.startSession();
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Unlock with a pre-derived key (for challenge-response auth)
   */
  async unlockWithKey(derivedKey: Buffer): Promise<boolean> {
    if (!existsSync(this.storePath)) {
      throw new Error("Secret store not initialized");
    }

    const encrypted = JSON.parse(readFileSync(this.storePath, "utf-8")) as EncryptedStore;

    try {
      this.data = await this.decrypt(encrypted, derivedKey);
      this.vaultKey = derivedKey;
      this.startSession();
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Lock the secret store
   */
  lock(): void {
    if (this.lockTimeout) {
      clearTimeout(this.lockTimeout);
      this.lockTimeout = null;
    }

    // Securely zero the key
    if (this.vaultKey) {
      randomBytes(this.vaultKey.length).copy(this.vaultKey);
      this.vaultKey = null;
    }

    this.data = null;
    this.expiresAt = 0;
  }

  /**
   * Extend the session
   */
  extendSession(): void {
    if (!this.isUnlocked()) {
      throw new Error("Vault is locked");
    }

    if (this.lockTimeout) {
      clearTimeout(this.lockTimeout);
    }

    this.expiresAt = Date.now() + SESSION_TIMEOUT_MS;
    this.lockTimeout = setTimeout(() => this.lock(), SESSION_TIMEOUT_MS);
  }

  /**
   * Get the KDF salt for challenge-response auth
   */
  getSalt(): string | null {
    if (!existsSync(this.storePath)) {
      return null;
    }

    const encrypted = JSON.parse(readFileSync(this.storePath, "utf-8")) as EncryptedStore;
    return encrypted.kdf.salt;
  }

  /**
   * Get user's Ed25519 signing public key
   */
  getPublicKey(): string | null {
    if (!this.isUnlocked() || !this.data?.identity) {
      return null;
    }
    return this.data.identity.publicKey;
  }

  /**
   * Get user's X25519 encryption public key
   */
  getEncryptionPublicKey(): string | null {
    if (!this.isUnlocked() || !this.data?.identity) {
      return null;
    }
    return this.data.identity.encryptionPublicKey ?? null;
  }

  /**
   * Get both public keys for sharing with other users
   */
  getPublicKeys(): { signingKey: string; encryptionKey: string } | null {
    if (!this.isUnlocked() || !this.data?.identity) {
      return null;
    }
    if (!this.data.identity.encryptionPublicKey) {
      return null;
    }
    return {
      signingKey: this.data.identity.publicKey,
      encryptionKey: this.data.identity.encryptionPublicKey,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Integration Management
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Store an integration credential
   */
  async setIntegration(provider: string, integration: Integration): Promise<void> {
    this.ensureUnlocked();

    this.data!.integrations[provider] = integration;
    await this.save();
  }

  /**
   * Get an integration credential
   */
  getIntegration(provider: string): Integration | null {
    this.ensureUnlocked();
    return this.data!.integrations[provider] || null;
  }

  /**
   * List all integrations (without exposing tokens)
   */
  listIntegrations(): Array<{ provider: string; email?: string; expiresAt: string }> {
    this.ensureUnlocked();

    return Object.entries(this.data!.integrations).map(([provider, int]) => ({
      provider,
      email: int.email,
      expiresAt: int.expiresAt,
    }));
  }

  /**
   * Remove an integration
   */
  async removeIntegration(provider: string): Promise<void> {
    this.ensureUnlocked();

    delete this.data!.integrations[provider];
    await this.save();
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Capability Management
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Issue a capability token to another user
   * @param subjectPublicKey - Ed25519 public key of the recipient (for verification)
   * @param resource - The integration/resource to share
   * @param scope - Allowed operations
   * @param expiresInSeconds - Token lifetime
   * @param options - Additional options including tier, maxCalls, encryption key
   */
  async issueCapability(
    subjectPublicKey: string,
    resource: string,
    scope: string[],
    expiresInSeconds: number,
    options?: {
      maxCalls?: number;
      tier?: SharingTier;
      subjectEncryptionKey?: string;
      cacheRefreshInterval?: number;
    },
  ): Promise<{ id: string; token: string; snapshot?: CachedSnapshot }> {
    this.ensureUnlocked();

    if (!this.data!.integrations[resource]) {
      throw new Error(`No integration for resource: ${resource}`);
    }

    const tier = options?.tier ?? "LIVE";
    const maxCalls = options?.maxCalls;
    const subjectEncryptionKey = options?.subjectEncryptionKey;
    const cacheRefreshInterval = options?.cacheRefreshInterval ?? 3600; // Default: 1 hour

    // CACHED tier requires encryption key
    if (tier === "CACHED" && !subjectEncryptionKey) {
      throw new Error("CACHED tier requires subjectEncryptionKey for encrypted snapshots");
    }

    const id = randomBytes(16).toString("hex");
    const now = Math.floor(Date.now() / 1000);
    const exp = now + expiresInSeconds;

    // Get current key version for tracking
    let keyVersion = 1;
    let keyId: string | undefined;
    if (this.data!.keyRotationState) {
      keyVersion = this.data!.keyRotationState.current.version;
      keyId = this.data!.keyRotationState.current.keyId;
    }

    // Build capability token
    const claims = {
      v: 1,
      id,
      iss: this.data!.identity!.publicKey,
      issEnc: this.data!.identity!.encryptionPublicKey,
      sub: subjectPublicKey,
      subEnc: subjectEncryptionKey,
      resource,
      scope,
      tier,
      iat: now,
      exp,
      constraints: maxCalls ? { maxCalls } : undefined,
      keyVersion, // Track which key version signed this capability
      keyId, // Key fingerprint for verification
    };

    // Sign token with Ed25519
    const tokenData = JSON.stringify(claims);
    const signature = this.sign(tokenData);
    const token = Buffer.from(JSON.stringify({ ...claims, sig: signature })).toString("base64url");

    // Store grant record
    this.data!.grants[id] = {
      id,
      subject: subjectPublicKey,
      subjectEncryptionKey,
      resource,
      scope,
      expires: new Date(exp * 1000).toISOString(),
      maxCalls,
      callCount: 0,
      revoked: false,
      issuedAt: new Date().toISOString(),
      tier,
      cacheRefreshInterval: tier === "CACHED" ? cacheRefreshInterval : undefined,
    };

    // Track key version for this capability
    if (!this.data!.capabilityKeyVersions) {
      this.data!.capabilityKeyVersions = {};
    }
    this.data!.capabilityKeyVersions[id] = keyVersion;

    await this.save();

    // For CACHED tier, generate initial snapshot
    let snapshot: CachedSnapshot | undefined;
    if (tier === "CACHED" && subjectEncryptionKey) {
      snapshot = await this.createCachedSnapshot(id);
    }

    return { id, token, snapshot };
  }

  /**
   * Issue a capability with human-in-the-loop approval.
   *
   * This is the recommended method for agent-initiated sharing.
   * It requires explicit human approval before the container signs
   * and issues the capability token.
   *
   * Flow:
   * 1. Agent requests capability issuance
   * 2. Request is stored as pending in the management server
   * 3. User is notified via UI/push notification
   * 4. User approves or denies
   * 5. If approved, container signs and issues the token
   *
   * @param subjectPublicKey - Ed25519 public key of the recipient
   * @param resource - The integration/resource to share
   * @param scope - Allowed operations
   * @param expiresInSeconds - Token lifetime
   * @param options - Additional options including approval settings
   * @param checkApproval - Function to check approval status from management server
   * @returns Issued capability if approved, or throws if denied/pending
   */
  async issueCapabilityWithApproval(
    subjectPublicKey: string,
    resource: string,
    scope: string[],
    expiresInSeconds: number,
    options: ApprovalAwareIssueOptions,
    checkApproval: (approvalId: string) => Promise<{ status: string; decidedAt?: string }>,
  ): Promise<{ id: string; token: string; snapshot?: CachedSnapshot }> {
    this.ensureUnlocked();

    // If skipApproval is set, just issue directly (for system operations)
    if (options.skipApproval) {
      return this.issueCapability(subjectPublicKey, resource, scope, expiresInSeconds, {
        maxCalls: options.maxCalls,
        tier: options.tier,
        subjectEncryptionKey: options.subjectEncryptionKey,
        cacheRefreshInterval: options.cacheRefreshInterval,
      });
    }

    // Must have an approvalId to proceed
    if (!options.approvalId) {
      throw new Error(
        "Capability issuance requires human approval. " +
          "Request approval via the management server first.",
      );
    }

    // Check the approval status
    const approval = await checkApproval(options.approvalId);

    if (approval.status === "pending") {
      throw new Error("Capability approval is still pending. Waiting for user decision.");
    }

    if (approval.status === "denied") {
      throw new Error("Capability approval was denied by the user.");
    }

    if (approval.status === "expired") {
      throw new Error("Capability approval has expired. Please request a new approval.");
    }

    if (approval.status !== "approved") {
      throw new Error(`Invalid approval status: ${approval.status}`);
    }

    // Approval is confirmed, issue the capability
    return this.issueCapability(subjectPublicKey, resource, scope, expiresInSeconds, {
      maxCalls: options.maxCalls,
      tier: options.tier,
      subjectEncryptionKey: options.subjectEncryptionKey,
      cacheRefreshInterval: options.cacheRefreshInterval,
    });
  }

  /**
   * Revoke a capability.
   * Also notifies the relay for instant network-wide enforcement.
   *
   * @param id - The capability ID to revoke
   * @param options - Revocation options
   * @returns Result including relay notification status
   */
  async revokeCapability(
    id: string,
    options?: { reason?: string; skipRelayNotification?: boolean },
  ): Promise<{
    revoked: boolean;
    relayNotified: boolean;
    relayError?: string;
  }> {
    this.ensureUnlocked();

    const grant = this.data!.grants[id];
    if (!grant) {
      throw new Error("Capability not found");
    }

    // Mark as revoked locally
    grant.revoked = true;
    await this.save();

    // Notify relay for instant enforcement (unless skipped)
    let relayNotified = false;
    let relayError: string | undefined;

    if (!options?.skipRelayNotification) {
      const result = await this.notifyRevocation(id, {
        reason: options?.reason,
        originalExpiry: grant.expires,
      });
      relayNotified = result.success;
      relayError = result.error;
    }

    return { revoked: true, relayNotified, relayError };
  }

  /**
   * Notify the relay about a capability revocation.
   * This enables instant enforcement across the mesh network.
   *
   * The relay cannot forge revocations because:
   * 1. Revocations must be signed by the capability issuer
   * 2. The relay only stores the revocation record
   * 3. Other nodes can verify the signature
   *
   * @param capabilityId - The capability ID being revoked
   * @param options - Additional revocation details
   */
  async notifyRevocation(
    capabilityId: string,
    options?: { reason?: string; originalExpiry?: string },
  ): Promise<{ success: boolean; error?: string; relayReachable: boolean }> {
    this.ensureUnlocked();

    const relayClient = await this.getOrCreateRelayClient();
    if (!relayClient) {
      return {
        success: false,
        error: "No relay client configured",
        relayReachable: false,
      };
    }

    const identity = this.data!.identity;
    if (!identity) {
      return {
        success: false,
        error: "No identity available for signing",
        relayReachable: false,
      };
    }

    try {
      const result = await relayClient.notifyRevocation({
        capabilityId,
        publicKey: identity.publicKey,
        privateKeyPem: identity.privateKeyPem,
        reason: options?.reason,
        originalExpiry: options?.originalExpiry,
      });

      if (!result.relayReachable) {
        log.warn(`Relay unreachable for revocation of ${capabilityId}`, { error: result.error });
      } else if (!result.success) {
        log.warn(`Relay rejected revocation of ${capabilityId}`, { error: result.error });
      }

      return result;
    } catch (err) {
      const error = (err as Error).message;
      log.error(`Failed to notify relay of revocation`, { error });
      return { success: false, error, relayReachable: false };
    }
  }

  /**
   * Check if a capability is revoked at the relay.
   * Useful for verifying revocation status before executing a capability.
   */
  async checkRelayRevocation(capabilityId: string): Promise<{
    revoked: boolean;
    revokedAt?: string;
    reason?: string;
    error?: string;
    relayReachable: boolean;
  }> {
    const relayClient = await this.getOrCreateRelayClient();
    if (!relayClient) {
      return {
        revoked: false,
        error: "No relay client configured",
        relayReachable: false,
      };
    }

    return relayClient.checkRevocation(capabilityId);
  }

  /**
   * List issued capabilities
   */
  listIssuedCapabilities(): CapabilityGrant[] {
    this.ensureUnlocked();
    return Object.values(this.data!.grants);
  }

  /**
   * Store a received capability
   */
  async storeReceivedCapability(token: string, issuerContainerId: string): Promise<string> {
    this.ensureUnlocked();

    // Decode and verify token
    const decoded = JSON.parse(Buffer.from(token, "base64url").toString());
    const { id, iss, issEnc, resource, scope, tier, exp, sig } = decoded;

    // Verify Ed25519 signature
    const claims = { ...decoded };
    delete claims.sig;
    if (!this.verify(JSON.stringify(claims), sig, iss)) {
      throw new Error("Invalid capability signature");
    }

    // Check not expired
    if (exp < Date.now() / 1000) {
      throw new Error("Capability expired");
    }

    this.data!.capabilities[id] = {
      id,
      issuer: iss,
      issuerEncryptionKey: issEnc,
      issuerContainerId,
      resource,
      scope,
      expires: new Date(exp * 1000).toISOString(),
      token,
      tier: tier ?? "LIVE",
    };

    await this.save();
    return id;
  }

  /**
   * Get a received capability
   */
  getReceivedCapability(id: string): ReceivedCapability | null {
    this.ensureUnlocked();
    return this.data!.capabilities[id] || null;
  }

  /**
   * List received capabilities
   */
  listReceivedCapabilities(): ReceivedCapability[] {
    this.ensureUnlocked();
    return Object.values(this.data!.capabilities);
  }

  /**
   * Execute a capability request (called on issuer's container)
   */
  async executeCapability(
    token: string,
    operation: string,
    params: Record<string, unknown>,
  ): Promise<unknown> {
    this.ensureUnlocked();

    // Decode token
    const decoded = JSON.parse(Buffer.from(token, "base64url").toString());
    const { id, iss, resource, scope, exp, sig, constraints } = decoded;

    // Verify signature
    const claims = { ...decoded };
    delete claims.sig;
    if (!this.verify(JSON.stringify(claims), sig, iss)) {
      throw new Error("Invalid capability signature");
    }

    // Check expiry
    if (exp < Date.now() / 1000) {
      throw new Error("Capability expired");
    }

    // Check scope
    if (!scope.includes(operation) && !scope.includes("*")) {
      throw new Error(`Operation '${operation}' not in capability scope`);
    }

    // Check revocation
    const grant = this.data!.grants[id];
    if (grant?.revoked) {
      throw new Error("Capability has been revoked");
    }

    // Check call count
    if (constraints?.maxCalls && grant) {
      if (grant.callCount >= constraints.maxCalls) {
        throw new Error("Capability call limit exceeded");
      }
      grant.callCount++;
      await this.save();
    }

    // Get the actual credential
    const integration = this.data!.integrations[resource];
    if (!integration) {
      throw new Error(`Resource '${resource}' not connected`);
    }

    // Return credential for the caller to use
    // In practice, this would make the API call and return the result
    return {
      accessToken: integration.accessToken,
      operation,
      params,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Agent Capability Ceiling Management
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Get the CeilingManager for managing agent permission ceilings.
   * The ceiling manager controls what permissions agents can grant without human approval.
   *
   * By default, agents can only grant read and list permissions.
   * Higher permissions (write, delete, admin, share-further) require human approval.
   */
  getCeilingManager(): CeilingManager {
    this.ensureUnlocked();

    // Initialize ceiling data if not present
    if (!this.data!.ceilingData) {
      this.data!.ceilingData = createEmptyCeilingStoreData();
    }

    return new CeilingManager(this.data!.ceilingData, async () => {
      await this.save();
    });
  }

  /**
   * Issue a capability token with agent ceiling validation.
   * If the agent tries to grant permissions above their ceiling, this will throw
   * a CeilingExceededError or create an escalation request.
   *
   * @param agentId - The agent issuing the capability
   * @param subjectPublicKey - Ed25519 public key of the recipient
   * @param resource - The integration/resource to share
   * @param scope - Requested permissions
   * @param expiresInSeconds - Token lifetime
   * @param options - Additional options
   */
  async issueCapabilityAsAgent(
    agentId: string,
    subjectPublicKey: string,
    resource: string,
    scope: string[],
    expiresInSeconds: number,
    options?: {
      maxCalls?: number;
      tier?: SharingTier;
      subjectEncryptionKey?: string;
      cacheRefreshInterval?: number;
      /** If true, create escalation request instead of throwing for permissions above ceiling */
      requestEscalation?: boolean;
    },
  ): Promise<{
    id?: string;
    token?: string;
    snapshot?: CachedSnapshot;
    escalationRequest?: import("./capability-ceiling.js").EscalationRequest;
    requiresApproval: boolean;
  }> {
    this.ensureUnlocked();

    const ceilingManager = this.getCeilingManager();

    // Check if agent can grant these permissions
    try {
      ceilingManager.validateAgentPermissions(agentId, scope);
    } catch (err) {
      if (err instanceof CeilingExceededError) {
        if (options?.requestEscalation) {
          // Create escalation request instead of throwing
          const escalationRequest = await ceilingManager.createEscalationRequest(
            agentId,
            resource,
            scope,
            subjectPublicKey,
            expiresInSeconds,
            options?.maxCalls,
          );
          return {
            escalationRequest,
            requiresApproval: true,
          };
        }
        throw err;
      }
      throw err;
    }

    // Agent can grant these permissions, proceed with issuance
    const result = await this.issueCapability(subjectPublicKey, resource, scope, expiresInSeconds, {
      maxCalls: options?.maxCalls,
      tier: options?.tier,
      subjectEncryptionKey: options?.subjectEncryptionKey,
      cacheRefreshInterval: options?.cacheRefreshInterval,
    });

    return {
      ...result,
      requiresApproval: false,
    };
  }

  /**
   * Approve a pending escalation request and issue the capability.
   * This must be called by a human (verified by the approverPublicKey).
   */
  async approveEscalationAndIssue(
    escalationRequestId: string,
    approverPublicKey: string,
    options?: {
      tier?: SharingTier;
      subjectEncryptionKey?: string;
      cacheRefreshInterval?: number;
    },
  ): Promise<{ id: string; token: string; snapshot?: CachedSnapshot }> {
    this.ensureUnlocked();

    const ceilingManager = this.getCeilingManager();

    // Get and approve the escalation request
    const request = ceilingManager.getEscalationRequest(escalationRequestId);
    if (!request) {
      throw new Error("Escalation request not found");
    }

    const approvedScope = await ceilingManager.approveEscalationRequest(
      escalationRequestId,
      approverPublicKey,
    );

    // Issue the capability with approved scope
    return this.issueCapability(
      request.subjectPublicKey,
      request.resource,
      approvedScope,
      request.expiresInSeconds,
      {
        maxCalls: request.maxCalls,
        tier: options?.tier,
        subjectEncryptionKey: options?.subjectEncryptionKey,
        cacheRefreshInterval: options?.cacheRefreshInterval,
      },
    );
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Key Rotation Management
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Get the KeyRotationManager for managing signing key rotation.
   * The manager handles transition periods, key archival, and verification.
   */
  getKeyRotationManager(): KeyRotationManager {
    this.ensureUnlocked();

    // Initialize key rotation state if not present
    if (!this.data!.keyRotationState) {
      if (this.data!.identity) {
        // Migrate existing identity to versioned format
        this.data!.keyRotationState = createInitialRotationState(this.data!.identity);
      } else {
        // Create fresh rotation state
        this.data!.keyRotationState = createFreshRotationState();
        // Also update legacy identity field for backward compatibility
        const current = this.data!.keyRotationState.current;
        this.data!.identity = {
          publicKey: current.publicKey,
          privateKeyPem: current.privateKeyPem,
          publicKeyPem: current.publicKeyPem,
          encryptionPublicKey: current.encryptionPublicKey,
          encryptionPrivateKeyPem: current.encryptionPrivateKeyPem,
          encryptionPublicKeyPem: current.encryptionPublicKeyPem,
          algorithm: "Ed25519",
        };
      }
    }

    return new KeyRotationManager(this.data!.keyRotationState, async () => {
      // Also update legacy identity field to match current key
      const current = this.data!.keyRotationState!.current;
      this.data!.identity = {
        publicKey: current.publicKey,
        privateKeyPem: current.privateKeyPem,
        publicKeyPem: current.publicKeyPem,
        encryptionPublicKey: current.encryptionPublicKey,
        encryptionPrivateKeyPem: current.encryptionPrivateKeyPem,
        encryptionPublicKeyPem: current.encryptionPublicKeyPem,
        algorithm: "Ed25519",
      };
      await this.save();
    });
  }

  /**
   * Rotate the signing key with a configurable transition period.
   *
   * During the transition period:
   * - Both old and new keys are valid for signature verification
   * - New capabilities are signed with the new key
   * - Old capabilities remain valid (can be re-issued if desired)
   * - The relay is notified of the key change
   *
   * @param options - Rotation options
   * @returns Rotation result with old/new key IDs and transition end time
   */
  async rotateSigningKey(options?: {
    /** Transition period in hours (default: 24) */
    transitionHours?: number;
    /** Reason for rotation (for audit log) */
    reason?: string;
    /** Auth headers for relay notification */
    authHeaders?: { authorization: string; containerId: string };
  }): Promise<KeyRotationResult> {
    this.ensureUnlocked();

    const transitionHours = options?.transitionHours ?? 24;
    const reason = options?.reason ?? "Manual rotation";

    const manager = this.getKeyRotationManager();
    const result = await manager.rotateSigningKey(transitionHours, reason);

    // Notify relay of key rotation if configured
    if (options?.authHeaders) {
      const relayClient = await this.getOrCreateRelayClient();
      if (relayClient) {
        const current = manager.getCurrentIdentity();
        try {
          await relayClient.notifyKeyRotation(
            {
              oldPublicKey: manager.getPreviousIdentity()!.publicKey,
              newPublicKey: current.publicKey,
              newEncryptionPublicKey: current.encryptionPublicKey,
              transitionEndsAt: result.transitionEndsAt,
              newPrivateKeyPem: current.privateKeyPem,
              keyVersion: current.version,
            },
            options.authHeaders,
          );
        } catch (err) {
          log.warn(`Failed to notify relay of key rotation`, { error: (err as Error).message });
        }
      }
    }

    return result;
  }

  /**
   * Complete an active key rotation transition early.
   * After this, the old key will no longer be valid for verification.
   */
  async completeKeyRotation(): Promise<void> {
    this.ensureUnlocked();
    const manager = this.getKeyRotationManager();
    await manager.completeTransition();
  }

  /**
   * Check if currently in a key rotation transition period.
   */
  isInKeyRotationTransition(): boolean {
    this.ensureUnlocked();
    const manager = this.getKeyRotationManager();
    return manager.isInTransition();
  }

  /**
   * Get the current key version number.
   */
  getCurrentKeyVersion(): number {
    this.ensureUnlocked();
    const manager = this.getKeyRotationManager();
    return manager.getCurrentIdentity().version;
  }

  /**
   * Get all archived keys (for audit purposes).
   */
  getArchivedKeys(): ArchivedKey[] {
    this.ensureUnlocked();
    const manager = this.getKeyRotationManager();
    return manager.getArchivedKeys();
  }

  /**
   * Verify a signature using any valid key (current or previous during transition).
   */
  verifyWithValidKey(
    data: string,
    signature: string,
    signerPublicKey: string,
  ): { valid: boolean; keyVersion?: number } {
    this.ensureUnlocked();
    const manager = this.getKeyRotationManager();
    return manager.verifyWithAnyValidKey(data, signature, signerPublicKey);
  }

  /**
   * Get capabilities that were signed with a key that has been rotated out.
   * These can optionally be re-issued with the new key, or let expire naturally.
   */
  getCapabilitiesNeedingReissue(): Array<{
    id: string;
    resource: string;
    subject: string;
    expires: string;
    signerKeyVersion: number;
  }> {
    this.ensureUnlocked();

    if (!this.data!.keyRotationState || !this.data!.capabilityKeyVersions) {
      return [];
    }

    const currentVersion = this.data!.keyRotationState.current.version;
    const grants = this.data!.grants;
    const keyVersions = this.data!.capabilityKeyVersions;

    const results: Array<{
      id: string;
      resource: string;
      subject: string;
      expires: string;
      signerKeyVersion: number;
    }> = [];

    for (const [id, grant] of Object.entries(grants)) {
      if (grant.revoked) {
        continue;
      }
      if (new Date(grant.expires).getTime() < Date.now()) {
        continue;
      }

      const version = keyVersions[id];
      if (version !== undefined && version < currentVersion) {
        results.push({
          id,
          resource: grant.resource,
          subject: grant.subject,
          expires: grant.expires,
          signerKeyVersion: version,
        });
      }
    }

    return results;
  }

  /**
   * Re-issue a capability with the current signing key.
   * The old capability remains valid during the transition period.
   */
  async reissueCapability(
    capabilityId: string,
    options?: {
      /** Whether to revoke the old capability after re-issue */
      revokeOld?: boolean;
    },
  ): Promise<{ id: string; token: string; snapshot?: CachedSnapshot }> {
    this.ensureUnlocked();

    const oldGrant = this.data!.grants[capabilityId];
    if (!oldGrant) {
      throw new Error("Capability not found");
    }

    if (oldGrant.revoked) {
      throw new Error("Cannot re-issue revoked capability");
    }

    const remainingSeconds = Math.max(
      0,
      Math.floor((new Date(oldGrant.expires).getTime() - Date.now()) / 1000),
    );

    if (remainingSeconds === 0) {
      throw new Error("Cannot re-issue expired capability");
    }

    // Issue new capability with same parameters
    const result = await this.issueCapability(
      oldGrant.subject,
      oldGrant.resource,
      oldGrant.scope,
      remainingSeconds,
      {
        maxCalls: oldGrant.maxCalls,
        tier: oldGrant.tier,
        subjectEncryptionKey: oldGrant.subjectEncryptionKey,
        cacheRefreshInterval: oldGrant.cacheRefreshInterval,
      },
    );

    // Optionally revoke old capability
    if (options?.revokeOld) {
      await this.revokeCapability(capabilityId, {
        reason: "Re-issued with new key",
        skipRelayNotification: false,
      });
    }

    return result;
  }

  /**
   * Re-issue all capabilities signed with old keys.
   * Useful after a key rotation to ensure all active capabilities use the new key.
   */
  async reissueAllOldCapabilities(options?: {
    /** Whether to revoke old capabilities after re-issue */
    revokeOld?: boolean;
  }): Promise<{
    reissued: number;
    failed: number;
    errors: string[];
  }> {
    this.ensureUnlocked();

    const needReissue = this.getCapabilitiesNeedingReissue();
    let reissued = 0;
    let failed = 0;
    const errors: string[] = [];

    for (const cap of needReissue) {
      try {
        await this.reissueCapability(cap.id, options);
        reissued++;
      } catch (err) {
        failed++;
        errors.push(`${cap.id}: ${(err as Error).message}`);
      }
    }

    return { reissued, failed, errors };
  }

  /**
   * Create a key rotation notification to send to capability recipients.
   * Recipients should update their stored issuer public keys.
   */
  createKeyRotationNotification(affectedCapabilityIds?: string[]): KeyRotationNotification {
    this.ensureUnlocked();

    const manager = this.getKeyRotationManager();

    // If no specific IDs provided, use all non-expired, non-revoked grants
    const capIds =
      affectedCapabilityIds ??
      Object.values(this.data!.grants)
        .filter((g) => !g.revoked && new Date(g.expires).getTime() > Date.now())
        .map((g) => g.id);

    return manager.createRotationNotification(capIds);
  }

  /**
   * Rotate the vault encryption key (re-encrypt with new password).
   *
   * This changes the password used to encrypt the vault.
   * All data is re-encrypted with a new salt and derived key.
   *
   * @param currentPassword - Current vault password
   * @param newPassword - New vault password
   */
  async rotateEncryptionKey(currentPassword: string, newPassword: string): Promise<void> {
    this.ensureUnlocked();

    // Read current encrypted store
    const encrypted = JSON.parse(readFileSync(this.storePath, "utf-8")) as {
      version: number;
      algorithm: string;
      kdf: { algorithm: string; salt: string; n: number; r: number; p: number };
      nonce: string;
      ciphertext: string;
      tag: string;
    };

    const currentSalt = Buffer.from(encrypted.kdf.salt, "base64");
    const currentNonce = Buffer.from(encrypted.nonce, "base64");
    const currentTag = Buffer.from(encrypted.tag, "base64");
    const currentCiphertext = Buffer.from(encrypted.ciphertext, "base64");

    // Verify current password
    const currentKey = this.deriveKey(currentPassword, currentSalt);

    // Re-encrypt with new password
    const result = rotateVaultKey({
      encryptedData: currentCiphertext,
      currentSalt,
      currentKey,
      currentNonce,
      currentTag,
      newPassword,
      scryptN: this.scryptN,
    });

    // Write new encrypted store
    const newEncrypted = {
      version: 2,
      algorithm: ALGORITHM,
      kdf: {
        algorithm: "scrypt",
        salt: result.newSalt.toString("base64"),
        n: this.scryptN,
        r: SCRYPT_R,
        p: SCRYPT_P,
      },
      nonce: result.newNonce.toString("base64"),
      ciphertext: result.encryptedData.toString("base64"),
      tag: result.newTag.toString("base64"),
    };

    writeFileSync(this.storePath, JSON.stringify(newEncrypted, null, 2), {
      mode: 0o600,
    });

    // Update in-memory key
    this.vaultKey = result.newKey;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Private Methods
  // ─────────────────────────────────────────────────────────────────────────

  private ensureUnlocked(): void {
    if (!this.isUnlocked()) {
      throw new Error("Vault is locked");
    }
  }

  private startSession(): void {
    this.expiresAt = Date.now() + SESSION_TIMEOUT_MS;
    this.lockTimeout = setTimeout(() => this.lock(), SESSION_TIMEOUT_MS);
  }

  private deriveKey(password: string, salt: Buffer): Buffer {
    return scryptSync(password, salt, KEY_LENGTH, {
      N: this.scryptN,
      r: SCRYPT_R,
      p: SCRYPT_P,
    });
  }

  private async encrypt(data: SecretStoreData, key: Buffer, salt: Buffer): Promise<void> {
    const nonce = randomBytes(NONCE_LENGTH);
    const cipher = createCipheriv(ALGORITHM, key, nonce);

    const plaintext = JSON.stringify(data);
    const ciphertext = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()]);

    const tag = cipher.getAuthTag();

    const encrypted: EncryptedStore = {
      version: 2,
      algorithm: ALGORITHM,
      kdf: {
        algorithm: "scrypt",
        salt: salt.toString("base64"),
        n: this.scryptN,
        r: SCRYPT_R,
        p: SCRYPT_P,
      },
      nonce: nonce.toString("base64"),
      ciphertext: ciphertext.toString("base64"),
      tag: tag.toString("base64"),
    };

    writeFileSync(this.storePath, JSON.stringify(encrypted, null, 2), {
      mode: 0o600,
    });
  }

  private async decrypt(encrypted: EncryptedStore, key: Buffer): Promise<SecretStoreData> {
    const nonce = Buffer.from(encrypted.nonce, "base64");
    const ciphertext = Buffer.from(encrypted.ciphertext, "base64");
    const tag = Buffer.from(encrypted.tag, "base64");

    const decipher = createDecipheriv(ALGORITHM, key, nonce);
    decipher.setAuthTag(tag);

    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString(
      "utf-8",
    );

    return JSON.parse(plaintext);
  }

  private async save(): Promise<void> {
    this.ensureUnlocked();

    const encrypted = JSON.parse(readFileSync(this.storePath, "utf-8")) as EncryptedStore;
    const salt = Buffer.from(encrypted.kdf.salt, "base64");

    await this.encrypt(this.data!, this.vaultKey!, salt);
  }

  /**
   * Sign data with the vault's Ed25519 private key.
   * Returns a base64-encoded signature.
   */
  private sign(data: string): string {
    if (!this.data?.identity?.privateKeyPem) {
      throw new Error("No identity keypair available for signing");
    }

    const privateKey = createPrivateKey(this.data.identity.privateKeyPem);
    const signature = cryptoSign(null, Buffer.from(data, "utf-8"), privateKey);
    return signature.toString("base64");
  }

  /**
   * Verify an Ed25519 signature against data and a public key.
   * @param data - The original data that was signed
   * @param signature - Base64-encoded signature
   * @param publicKeyBase64 - Base64-encoded raw 32-byte Ed25519 public key
   */
  private verify(data: string, signature: string, publicKeyBase64: string): boolean {
    try {
      const publicKey = publicKeyFromBase64(publicKeyBase64);
      const signatureBuffer = Buffer.from(signature, "base64");

      // Ed25519 signatures are always 64 bytes
      if (signatureBuffer.length !== 64) {
        return false;
      }

      return cryptoVerify(null, Buffer.from(data, "utf-8"), publicKey, signatureBuffer);
    } catch {
      // Invalid key format or signature
      return false;
    }
  }

  /**
   * Encrypt data for a specific recipient using X25519 ECDH.
   * Uses an ephemeral keypair so each encryption is unique.
   */
  private encryptForRecipient(
    plaintext: string,
    recipientPublicKeyBase64: string,
  ): {
    ciphertext: string;
    ephemeralPublicKey: string;
    nonce: string;
    tag: string;
  } {
    // Generate ephemeral X25519 keypair
    const { publicKey: ephemeralPub, privateKey: ephemeralPriv } = generateKeyPairSync("x25519");

    // Get recipient's public key
    const recipientPubKey = x25519PublicKeyFromBase64(recipientPublicKeyBase64);

    // Perform ECDH to get shared secret
    const sharedSecret = diffieHellman({
      privateKey: ephemeralPriv,
      publicKey: recipientPubKey,
    });

    // Derive AES-256-GCM key from shared secret using HKDF-like construction
    const derivedKey = createHash("sha256")
      .update(Buffer.concat([sharedSecret, Buffer.from("ocmt-cached-snapshot-v1")]))
      .digest();

    // Encrypt with AES-256-GCM
    const nonce = randomBytes(NONCE_LENGTH);
    const cipher = createCipheriv(ALGORITHM, derivedKey, nonce);
    const ciphertext = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()]);
    const tag = cipher.getAuthTag();

    // Export ephemeral public key as raw bytes
    const ephemeralDer = ephemeralPub.export({ type: "spki", format: "der" }) as Buffer;
    const ephemeralRaw = ephemeralDer.subarray(X25519_SPKI_PREFIX.length);

    return {
      ciphertext: ciphertext.toString("base64"),
      ephemeralPublicKey: ephemeralRaw.toString("base64"),
      nonce: nonce.toString("base64"),
      tag: tag.toString("base64"),
    };
  }

  /**
   * Decrypt data from a sender using our X25519 private key.
   */
  private decryptFromSender(
    ciphertextBase64: string,
    senderEphemeralPublicKeyBase64: string,
    nonceBase64: string,
    tagBase64: string,
  ): string {
    if (!this.data?.identity?.encryptionPrivateKeyPem) {
      throw new Error("No encryption keypair available");
    }

    // Get sender's ephemeral public key
    const senderPubKey = x25519PublicKeyFromBase64(senderEphemeralPublicKeyBase64);

    // Get our private key
    const ourPrivKey = createPrivateKey(this.data.identity.encryptionPrivateKeyPem);

    // Perform ECDH to get shared secret
    const sharedSecret = diffieHellman({
      privateKey: ourPrivKey,
      publicKey: senderPubKey,
    });

    // Derive AES-256-GCM key (same as encryption)
    const derivedKey = createHash("sha256")
      .update(Buffer.concat([sharedSecret, Buffer.from("ocmt-cached-snapshot-v1")]))
      .digest();

    // Decrypt
    const nonce = Buffer.from(nonceBase64, "base64");
    const ciphertext = Buffer.from(ciphertextBase64, "base64");
    const tag = Buffer.from(tagBase64, "base64");

    const decipher = createDecipheriv(ALGORITHM, derivedKey, nonce);
    decipher.setAuthTag(tag);

    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf-8");
  }

  /**
   * Create an encrypted cached snapshot for CACHED tier sharing.
   * Uses X25519 ECDH to derive a shared secret, then AES-256-GCM for encryption.
   */
  async createCachedSnapshot(capabilityId: string): Promise<CachedSnapshot> {
    this.ensureUnlocked();

    const grant = this.data!.grants[capabilityId];
    if (!grant) {
      throw new Error("Capability not found");
    }

    if (grant.tier !== "CACHED") {
      throw new Error("Capability is not CACHED tier");
    }

    if (!grant.subjectEncryptionKey) {
      throw new Error("No recipient encryption key available");
    }

    if (grant.revoked) {
      throw new Error("Capability has been revoked");
    }

    // Get the resource data to snapshot
    const integration = this.data!.integrations[grant.resource];
    if (!integration) {
      throw new Error(`Resource '${grant.resource}' not connected`);
    }

    // Prepare resource data for snapshot
    const resourceData = {
      resource: grant.resource,
      scope: grant.scope,
      accessToken: integration.accessToken,
      refreshToken: integration.refreshToken,
      expiresAt: integration.expiresAt,
      email: integration.email,
      scopes: integration.scopes,
      metadata: integration.metadata,
      snapshotAt: new Date().toISOString(),
    };

    // Encrypt to recipient using X25519 ECDH
    const encryptedPayload = this.encryptForRecipient(
      JSON.stringify(resourceData),
      grant.subjectEncryptionKey,
    );

    // Create snapshot with signature
    const signatureData = `${capabilityId}:${encryptedPayload.ciphertext}:${encryptedPayload.ephemeralPublicKey}`;
    const signature = this.sign(signatureData);

    const snapshot: CachedSnapshot = {
      capabilityId,
      encryptedData: encryptedPayload.ciphertext,
      ephemeralPublicKey: encryptedPayload.ephemeralPublicKey,
      nonce: encryptedPayload.nonce,
      tag: encryptedPayload.tag,
      signature,
      issuerPublicKey: this.data!.identity!.publicKey,
      recipientPublicKey: grant.subjectEncryptionKey,
      createdAt: new Date().toISOString(),
      expiresAt: grant.expires,
    };

    // Update grant with last snapshot time
    grant.lastSnapshotAt = snapshot.createdAt;

    // Store in pending snapshots for relay push
    if (!this.data!.pendingSnapshots) {
      this.data!.pendingSnapshots = {};
    }
    this.data!.pendingSnapshots[capabilityId] = snapshot;

    await this.save();

    return snapshot;
  }

  /**
   * Get all capabilities that need snapshot refresh.
   */
  getCapabilitiesNeedingRefresh(): CapabilityGrant[] {
    this.ensureUnlocked();

    const now = Date.now();
    return Object.values(this.data!.grants).filter((grant) => {
      if (grant.tier !== "CACHED" || grant.revoked) {
        return false;
      }
      if (new Date(grant.expires).getTime() < now) {
        return false;
      }

      const refreshInterval = (grant.cacheRefreshInterval ?? 3600) * 1000;
      const lastSnapshot = grant.lastSnapshotAt ? new Date(grant.lastSnapshotAt).getTime() : 0;

      return now - lastSnapshot >= refreshInterval;
    });
  }

  /**
   * Refresh all CACHED tier snapshots that are due.
   */
  async refreshCachedSnapshots(): Promise<CachedSnapshot[]> {
    this.ensureUnlocked();

    const needsRefresh = this.getCapabilitiesNeedingRefresh();
    const snapshots: CachedSnapshot[] = [];

    for (const grant of needsRefresh) {
      try {
        const snapshot = await this.createCachedSnapshot(grant.id);
        snapshots.push(snapshot);
      } catch {
        log.warn(`Failed to refresh snapshot for capability`, { capabilityId: grant.id });
      }
    }

    return snapshots;
  }

  /**
   * Get pending snapshots that need to be pushed to relay.
   */
  getPendingSnapshots(): CachedSnapshot[] {
    this.ensureUnlocked();
    return Object.values(this.data!.pendingSnapshots ?? {});
  }

  /**
   * Mark snapshots as pushed to relay.
   */
  async markSnapshotsPushed(capabilityIds: string[]): Promise<void> {
    this.ensureUnlocked();

    if (!this.data!.pendingSnapshots) {
      return;
    }

    for (const id of capabilityIds) {
      delete this.data!.pendingSnapshots[id];
    }

    await this.save();
  }

  /**
   * Push pending snapshots to the relay for storage.
   */
  async pushSnapshotsToRelay(): Promise<{
    pushed: number;
    failed: number;
    errors: string[];
  }> {
    this.ensureUnlocked();

    const relayClient = await this.getOrCreateRelayClient();
    if (!relayClient) {
      return { pushed: 0, failed: 0, errors: ["No relay client configured"] };
    }

    const pending = this.getPendingSnapshots();
    if (pending.length === 0) {
      return { pushed: 0, failed: 0, errors: [] };
    }

    let pushed = 0;
    let failed = 0;
    const errors: string[] = [];
    const pushedIds: string[] = [];

    for (const snapshot of pending) {
      try {
        const result = await relayClient.storeSnapshot(snapshot);
        if (result.success) {
          pushed++;
          pushedIds.push(snapshot.capabilityId);
        } else {
          failed++;
          errors.push(`${snapshot.capabilityId}: ${result.error}`);
        }
      } catch (err) {
        failed++;
        errors.push(`${snapshot.capabilityId}: ${(err as Error).message}`);
      }
    }

    if (pushedIds.length > 0) {
      await this.markSnapshotsPushed(pushedIds);
    }

    return { pushed, failed, errors };
  }

  /**
   * Fetch a cached snapshot from the relay.
   */
  async fetchSnapshotFromRelay(capabilityId: string): Promise<CachedSnapshot | null> {
    const relayClient = await this.getOrCreateRelayClient();
    if (!relayClient) {
      return null;
    }

    const result = await relayClient.getSnapshot(capabilityId);
    if (!result.success || !result.snapshot) {
      return null;
    }

    return result.snapshot;
  }

  /**
   * Decrypt a cached snapshot using our X25519 private key.
   */
  decryptCachedSnapshot(snapshot: CachedSnapshot): {
    data: Record<string, unknown>;
    updatedAt: string;
    staleness: number;
  } {
    this.ensureUnlocked();

    // Verify the signature first
    const signatureData = `${snapshot.capabilityId}:${snapshot.encryptedData}:${snapshot.ephemeralPublicKey}`;
    if (!this.verify(signatureData, snapshot.signature, snapshot.issuerPublicKey)) {
      throw new Error("Invalid snapshot signature");
    }

    // Check expiry
    if (new Date(snapshot.expiresAt).getTime() < Date.now()) {
      throw new Error("Snapshot has expired");
    }

    // Decrypt using our private key
    const decrypted = this.decryptFromSender(
      snapshot.encryptedData,
      snapshot.ephemeralPublicKey,
      snapshot.nonce,
      snapshot.tag,
    );

    const staleness = Date.now() - new Date(snapshot.createdAt).getTime();

    return {
      data: JSON.parse(decrypted),
      updatedAt: snapshot.createdAt,
      staleness,
    };
  }

  /**
   * Store decrypted snapshot data in received capability.
   */
  async updateCachedSnapshotData(capabilityId: string, snapshot: CachedSnapshot): Promise<void> {
    this.ensureUnlocked();

    const capability = this.data!.capabilities[capabilityId];
    if (!capability) {
      throw new Error("Capability not found");
    }

    const decrypted = this.decryptCachedSnapshot(snapshot);

    capability.cachedSnapshot = {
      data: JSON.stringify(decrypted.data),
      updatedAt: decrypted.updatedAt,
    };

    await this.save();
  }

  /**
   * Get cached data for a received capability (for offline access).
   */
  getCachedData(capabilityId: string): {
    data: Record<string, unknown>;
    updatedAt: string;
    staleness: number;
  } | null {
    this.ensureUnlocked();

    const capability = this.data!.capabilities[capabilityId];
    if (!capability?.cachedSnapshot) {
      return null;
    }

    const staleness = Date.now() - new Date(capability.cachedSnapshot.updatedAt).getTime();

    return {
      data: JSON.parse(capability.cachedSnapshot.data),
      updatedAt: capability.cachedSnapshot.updatedAt,
      staleness,
    };
  }

  /**
   * Access a CACHED capability's data, trying relay first then falling back to local cache.
   */
  async accessCachedCapability(capabilityId: string): Promise<{
    data: Record<string, unknown>;
    source: "live" | "cache";
    updatedAt: string;
    staleness: number;
  } | null> {
    this.ensureUnlocked();

    const capability = this.data!.capabilities[capabilityId];
    if (!capability) {
      return null;
    }

    // First try to get fresh data from relay
    try {
      const snapshot = await this.fetchSnapshotFromRelay(capabilityId);
      if (snapshot) {
        await this.updateCachedSnapshotData(capabilityId, snapshot);
        const cached = this.getCachedData(capabilityId);
        if (cached) {
          return { ...cached, source: "live" };
        }
      }
    } catch {
      // Relay fetch failed, try local cache
    }

    // Fall back to local cached data
    const cached = this.getCachedData(capabilityId);
    if (cached) {
      return { ...cached, source: "cache" };
    }

    return null;
  }

  /**
   * Fetch all available snapshots from the relay for this user.
   * Used to sync CACHED tier capabilities when coming online.
   */
  async fetchAllAvailableSnapshots(): Promise<{
    fetched: number;
    errors: string[];
  }> {
    this.ensureUnlocked();

    const relayClient = await this.getOrCreateRelayClient();
    if (!relayClient) {
      return { fetched: 0, errors: ["No relay client configured"] };
    }

    const identity = this.data!.identity;
    if (!identity?.encryptionPublicKey || !identity?.encryptionPrivateKeyPem) {
      return { fetched: 0, errors: ["No encryption identity available"] };
    }

    try {
      const result = await relayClient.listSnapshots({
        recipientPublicKey: identity.encryptionPublicKey,
        privateKeyPem: identity.encryptionPrivateKeyPem,
      });

      if (!result.success || !result.snapshots) {
        return { fetched: 0, errors: [result.error ?? "Failed to list snapshots"] };
      }

      let fetched = 0;
      const errors: string[] = [];

      for (const snapshot of result.snapshots) {
        try {
          // Check if we have the corresponding received capability
          const capability = this.data!.capabilities[snapshot.capabilityId];
          if (capability && capability.tier === "CACHED") {
            await this.updateCachedSnapshotData(snapshot.capabilityId, snapshot);
            fetched++;
          }
        } catch (err) {
          errors.push(`${snapshot.capabilityId}: ${(err as Error).message}`);
        }
      }

      return { fetched, errors };
    } catch (err) {
      return { fetched: 0, errors: [(err as Error).message] };
    }
  }

  /**
   * Start a background refresh loop for CACHED tier snapshots.
   * Should be called when the container starts.
   *
   * @param intervalMs - Refresh interval in milliseconds (default: 5 minutes)
   * @returns A function to stop the refresh loop
   */
  startSnapshotRefreshLoop(intervalMs = 5 * 60 * 1000): () => void {
    let running = true;

    const runRefresh = async () => {
      if (!running) {
        return;
      }
      if (!this.isUnlocked()) {
        // Vault is locked, skip this iteration
        return;
      }

      try {
        // Refresh snapshots that are due
        const snapshots = await this.refreshCachedSnapshots();
        if (snapshots.length > 0) {
          log.debug(`Refreshed cached snapshots`, { count: snapshots.length });

          // Push to relay
          const pushResult = await this.pushSnapshotsToRelay();
          if (pushResult.pushed > 0) {
            log.debug(`Pushed snapshots to relay`, { count: pushResult.pushed });
          }
          if (pushResult.failed > 0) {
            log.warn(`Failed to push some snapshots`, { failedCount: pushResult.failed });
          }
        }
      } catch (err) {
        log.error(`Snapshot refresh failed`, { error: (err as Error).message });
      }
    };

    // Run initial refresh
    runRefresh();

    // Schedule periodic refresh
    const interval = setInterval(runRefresh, intervalMs);

    // Return cleanup function
    return () => {
      running = false;
      clearInterval(interval);
    };
  }

  /**
   * Push all pending snapshots to the relay and optionally refresh due snapshots.
   * This is a convenience method for explicit user-triggered refresh.
   */
  async syncSnapshots(): Promise<{
    refreshed: number;
    pushed: number;
    failed: number;
    errors: string[];
  }> {
    this.ensureUnlocked();

    // Refresh due snapshots
    const refreshed = await this.refreshCachedSnapshots();

    // Push to relay
    const pushResult = await this.pushSnapshotsToRelay();

    return {
      refreshed: refreshed.length,
      pushed: pushResult.pushed,
      failed: pushResult.failed,
      errors: pushResult.errors,
    };
  }
}

// Singleton instance
let instance: SecretStore | null = null;

/**
 * Get or create the singleton SecretStore instance.
 * @param options - Configuration options (only used on first call)
 */
export function getSecretStore(options?: SecretStoreOptions | string): SecretStore {
  if (!instance) {
    instance = new SecretStore(options);
  }
  return instance;
}

/**
 * Reset the singleton instance (for testing).
 */
export function resetSecretStore(): void {
  if (instance) {
    instance.lock();
    instance = null;
  }
}
