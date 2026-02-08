/**
 * Key Rotation for Mesh Security
 *
 * Implements secure key rotation for Ed25519 signing keys and encryption keys.
 * Supports transition periods where both old and new keys are valid.
 *
 * Security considerations:
 * - Old keys are archived, not deleted (for audit)
 * - Transition period allows gradual migration
 * - Capabilities signed with old keys remain valid until expiry or re-issuance
 * - Relay is notified of key changes for discovery
 */

import {
  randomBytes,
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
  KeyObject,
  scryptSync,
  createCipheriv,
  createDecipheriv,
  createHash,
} from "crypto";

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

// Default transition period: 24 hours
const DEFAULT_TRANSITION_HOURS = 24;

// Ed25519 SPKI prefix for DER-encoded public keys (12 bytes header + 32 bytes key)
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
// X25519 SPKI prefix for DER-encoded public keys (12 bytes header + 32 bytes key)
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Identity keypair with version tracking
 */
export interface VersionedIdentity {
  /** Version number (incrementing) */
  version: number;
  /** Unique key ID (fingerprint of public key) */
  keyId: string;
  /** Base64-encoded raw 32-byte Ed25519 public key (for signing) */
  publicKey: string;
  /** PEM-encoded Ed25519 private key */
  privateKeyPem: string;
  /** PEM-encoded Ed25519 public key */
  publicKeyPem: string;
  /** Base64-encoded raw 32-byte X25519 public key (for encryption) */
  encryptionPublicKey: string;
  /** PEM-encoded X25519 private key */
  encryptionPrivateKeyPem: string;
  /** PEM-encoded X25519 public key */
  encryptionPublicKeyPem: string;
  /** When this key was generated */
  createdAt: string;
  /** Algorithm identifier */
  algorithm: "Ed25519";
}

/**
 * Archived key record for audit trail
 */
export interface ArchivedKey {
  /** Key ID */
  keyId: string;
  /** Version number */
  version: number;
  /** Base64-encoded Ed25519 public key */
  publicKey: string;
  /** Base64-encoded X25519 encryption public key */
  encryptionPublicKey: string;
  /** When this key was created */
  createdAt: string;
  /** When this key was archived (rotated out) */
  archivedAt: string;
  /** Reason for archival */
  reason: string;
  /** Whether this key is still valid for verification during transition */
  transitionActive: boolean;
  /** When the transition period ends */
  transitionEndsAt?: string;
}

/**
 * Key rotation state
 */
export interface KeyRotationState {
  /** Current active identity */
  current: VersionedIdentity;
  /** Previous identity (if in transition) */
  previous?: VersionedIdentity;
  /** When the transition started */
  transitionStartedAt?: string;
  /** When the transition ends */
  transitionEndsAt?: string;
  /** Archived keys for audit */
  archivedKeys: ArchivedKey[];
}

/**
 * Result of a key rotation operation
 */
export interface KeyRotationResult {
  /** ID of the old key */
  oldKeyId: string;
  /** ID of the new key */
  newKeyId: string;
  /** When the transition period ends */
  transitionEndsAt: string;
  /** New public key (for relay registration) */
  newPublicKey: string;
  /** New encryption public key */
  newEncryptionPublicKey: string;
}

/**
 * Capability with key version tracking
 */
export interface VersionedCapability {
  /** Capability ID */
  id: string;
  /** Key version that signed this capability */
  signerKeyVersion: number;
  /** Key ID that signed this capability */
  signerKeyId: string;
  /** Whether this needs re-issuance (signed with old key) */
  needsReissue: boolean;
}

/**
 * Notification to send to capability recipients about key rotation
 */
export interface KeyRotationNotification {
  /** Type of notification */
  type: "key_rotation";
  /** Old key ID */
  oldKeyId: string;
  /** New key ID */
  newKeyId: string;
  /** New public key */
  newPublicKey: string;
  /** New encryption public key */
  newEncryptionPublicKey: string;
  /** Transition end time */
  transitionEndsAt: string;
  /** Affected capability IDs */
  affectedCapabilityIds: string[];
  /** Signature of this notification (signed with new key) */
  signature: string;
  /** Timestamp */
  timestamp: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Key Generation Utilities
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generate a key ID (fingerprint) from a public key
 */
export function generateKeyId(publicKeyBase64: string): string {
  const hash = createHash("sha256").update(Buffer.from(publicKeyBase64, "base64")).digest();
  // Use first 16 bytes as hex (32 chars)
  return hash.subarray(0, 16).toString("hex");
}

/**
 * Generate a new versioned identity keypair
 */
export function generateVersionedIdentity(version: number): VersionedIdentity {
  // Ed25519 for signing
  const { publicKey: ed25519Pub, privateKey: ed25519Priv } = generateKeyPairSync("ed25519");

  const publicKeyPem = ed25519Pub.export({ type: "spki", format: "pem" }).toString();
  const privateKeyPem = ed25519Priv.export({ type: "pkcs8", format: "pem" }).toString();

  // Extract raw 32-byte public key from SPKI encoding
  const spkiDer = ed25519Pub.export({ type: "spki", format: "der" }) as Buffer;
  const rawPublicKey = spkiDer.subarray(ED25519_SPKI_PREFIX.length);
  const publicKey = rawPublicKey.toString("base64");

  // X25519 for encryption (ECDH key exchange)
  const { publicKey: x25519Pub, privateKey: x25519Priv } = generateKeyPairSync("x25519");

  const encryptionPublicKeyPem = x25519Pub.export({ type: "spki", format: "pem" }).toString();
  const encryptionPrivateKeyPem = x25519Priv.export({ type: "pkcs8", format: "pem" }).toString();

  const x25519SpkiDer = x25519Pub.export({ type: "spki", format: "der" }) as Buffer;
  const rawEncryptionPublicKey = x25519SpkiDer.subarray(X25519_SPKI_PREFIX.length);
  const encryptionPublicKey = rawEncryptionPublicKey.toString("base64");

  const keyId = generateKeyId(publicKey);

  return {
    version,
    keyId,
    publicKey,
    privateKeyPem,
    publicKeyPem,
    encryptionPublicKey,
    encryptionPrivateKeyPem,
    encryptionPublicKeyPem,
    createdAt: new Date().toISOString(),
    algorithm: "Ed25519",
  };
}

/**
 * Create a KeyObject from a base64-encoded raw Ed25519 public key
 */
export function publicKeyFromBase64(publicKeyBase64: string): KeyObject {
  const rawKey = Buffer.from(publicKeyBase64, "base64");
  if (rawKey.length !== 32) {
    throw new Error(`Invalid Ed25519 public key length: expected 32 bytes, got ${rawKey.length}`);
  }
  const spkiDer = Buffer.concat([ED25519_SPKI_PREFIX, rawKey]);
  return createPublicKey({ key: spkiDer, type: "spki", format: "der" });
}

// ─────────────────────────────────────────────────────────────────────────────
// Key Rotation Manager
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Manages key rotation for a secret store
 */
export class KeyRotationManager {
  private state: KeyRotationState;
  private onSave: () => Promise<void>;

  constructor(state: KeyRotationState, onSave: () => Promise<void>) {
    this.state = state;
    this.onSave = onSave;
  }

  /**
   * Get the current key rotation state
   */
  getState(): KeyRotationState {
    return this.state;
  }

  /**
   * Get the current active identity
   */
  getCurrentIdentity(): VersionedIdentity {
    return this.state.current;
  }

  /**
   * Get the previous identity (if in transition period)
   */
  getPreviousIdentity(): VersionedIdentity | undefined {
    return this.state.previous;
  }

  /**
   * Check if currently in a transition period
   */
  isInTransition(): boolean {
    if (!this.state.transitionEndsAt) {
      return false;
    }
    return new Date(this.state.transitionEndsAt).getTime() > Date.now();
  }

  /**
   * Get the transition end time (if in transition)
   */
  getTransitionEndTime(): Date | null {
    if (!this.state.transitionEndsAt) {
      return null;
    }
    return new Date(this.state.transitionEndsAt);
  }

  /**
   * Rotate the signing key
   *
   * This generates a new Ed25519 keypair and starts a transition period.
   * During transition, both old and new keys are valid for verification.
   *
   * @param transitionHours - Duration of transition period in hours (default: 24)
   * @param reason - Reason for rotation (for audit log)
   */
  async rotateSigningKey(
    transitionHours: number = DEFAULT_TRANSITION_HOURS,
    reason: string = "Scheduled rotation",
  ): Promise<KeyRotationResult> {
    const oldIdentity = this.state.current;
    const newVersion = oldIdentity.version + 1;

    // Generate new keypair
    const newIdentity = generateVersionedIdentity(newVersion);

    // Calculate transition end time
    const transitionEndsAt = new Date(Date.now() + transitionHours * 60 * 60 * 1000).toISOString();

    // Archive the old key
    const archivedKey: ArchivedKey = {
      keyId: oldIdentity.keyId,
      version: oldIdentity.version,
      publicKey: oldIdentity.publicKey,
      encryptionPublicKey: oldIdentity.encryptionPublicKey,
      createdAt: oldIdentity.createdAt,
      archivedAt: new Date().toISOString(),
      reason,
      transitionActive: true,
      transitionEndsAt,
    };

    // Update state
    this.state.previous = oldIdentity;
    this.state.current = newIdentity;
    this.state.transitionStartedAt = new Date().toISOString();
    this.state.transitionEndsAt = transitionEndsAt;
    this.state.archivedKeys.push(archivedKey);

    await this.onSave();

    return {
      oldKeyId: oldIdentity.keyId,
      newKeyId: newIdentity.keyId,
      transitionEndsAt,
      newPublicKey: newIdentity.publicKey,
      newEncryptionPublicKey: newIdentity.encryptionPublicKey,
    };
  }

  /**
   * Complete the transition and revoke the old key
   *
   * Call this after the transition period ends or to force immediate revocation.
   */
  async completeTransition(): Promise<void> {
    if (!this.state.previous) {
      throw new Error("No transition in progress");
    }

    // Mark the archived key as no longer in transition
    const archived = this.state.archivedKeys.find((k) => k.keyId === this.state.previous?.keyId);
    if (archived) {
      archived.transitionActive = false;
    }

    // Clear transition state
    this.state.previous = undefined;
    this.state.transitionStartedAt = undefined;
    this.state.transitionEndsAt = undefined;

    await this.onSave();
  }

  /**
   * Verify a signature using any valid key (current or previous during transition)
   *
   * @param data - The data that was signed
   * @param signature - Base64-encoded signature
   * @param signerPublicKey - Base64-encoded public key of claimed signer
   * @returns Object with verification result and key version used
   */
  verifyWithAnyValidKey(
    data: string,
    signature: string,
    signerPublicKey: string,
  ): { valid: boolean; keyVersion?: number; keyId?: string } {
    // Try current key first
    if (signerPublicKey === this.state.current.publicKey) {
      const valid = this.verifySignature(data, signature, signerPublicKey);
      if (valid) {
        return {
          valid: true,
          keyVersion: this.state.current.version,
          keyId: this.state.current.keyId,
        };
      }
    }

    // Try previous key if in transition
    if (
      this.isInTransition() &&
      this.state.previous &&
      signerPublicKey === this.state.previous.publicKey
    ) {
      const valid = this.verifySignature(data, signature, signerPublicKey);
      if (valid) {
        return {
          valid: true,
          keyVersion: this.state.previous.version,
          keyId: this.state.previous.keyId,
        };
      }
    }

    return { valid: false };
  }

  /**
   * Sign data with the current key
   */
  signWithCurrentKey(data: string): { signature: string; keyVersion: number; keyId: string } {
    const privateKey = createPrivateKey(this.state.current.privateKeyPem);
    const signature = cryptoSign(null, Buffer.from(data, "utf-8"), privateKey);
    return {
      signature: signature.toString("base64"),
      keyVersion: this.state.current.version,
      keyId: this.state.current.keyId,
    };
  }

  /**
   * Verify a signature against a specific public key
   */
  private verifySignature(data: string, signature: string, publicKeyBase64: string): boolean {
    try {
      const publicKey = publicKeyFromBase64(publicKeyBase64);
      const signatureBuffer = Buffer.from(signature, "base64");

      if (signatureBuffer.length !== 64) {
        return false;
      }

      return cryptoVerify(null, Buffer.from(data, "utf-8"), publicKey, signatureBuffer);
    } catch {
      return false;
    }
  }

  /**
   * Get all archived keys (for audit)
   */
  getArchivedKeys(): ArchivedKey[] {
    return [...this.state.archivedKeys];
  }

  /**
   * Get the key ID for a given version
   */
  getKeyIdForVersion(version: number): string | null {
    if (this.state.current.version === version) {
      return this.state.current.keyId;
    }
    if (this.state.previous?.version === version) {
      return this.state.previous.keyId;
    }
    const archived = this.state.archivedKeys.find((k) => k.version === version);
    return archived?.keyId ?? null;
  }

  /**
   * Check if a key ID is currently valid (current or in-transition previous)
   */
  isKeyValid(keyId: string): boolean {
    if (this.state.current.keyId === keyId) {
      return true;
    }
    if (this.isInTransition() && this.state.previous?.keyId === keyId) {
      return true;
    }
    return false;
  }

  /**
   * Create a key rotation notification for capability recipients
   */
  createRotationNotification(affectedCapabilityIds: string[]): KeyRotationNotification {
    if (!this.state.previous || !this.state.transitionEndsAt) {
      throw new Error("No transition in progress");
    }

    const timestamp = new Date().toISOString();
    const notificationData = {
      type: "key_rotation" as const,
      oldKeyId: this.state.previous.keyId,
      newKeyId: this.state.current.keyId,
      newPublicKey: this.state.current.publicKey,
      newEncryptionPublicKey: this.state.current.encryptionPublicKey,
      transitionEndsAt: this.state.transitionEndsAt,
      affectedCapabilityIds,
      timestamp,
    };

    // Sign with new key
    const dataToSign = JSON.stringify(notificationData);
    const { signature } = this.signWithCurrentKey(dataToSign);

    return {
      ...notificationData,
      signature,
    };
  }

  /**
   * Verify a key rotation notification from another user
   */
  static verifyRotationNotification(notification: KeyRotationNotification): boolean {
    const { signature, ...dataWithoutSig } = notification;
    const dataToVerify = JSON.stringify(dataWithoutSig);

    try {
      const publicKey = publicKeyFromBase64(notification.newPublicKey);
      const signatureBuffer = Buffer.from(signature, "base64");

      if (signatureBuffer.length !== 64) {
        return false;
      }

      return cryptoVerify(null, Buffer.from(dataToVerify, "utf-8"), publicKey, signatureBuffer);
    } catch {
      return false;
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Vault Key Rotation (Encryption Key for Vault Storage)
// ─────────────────────────────────────────────────────────────────────────────

export interface VaultKeyRotationParams {
  /** Current encrypted vault data */
  encryptedData: Buffer;
  /** Current KDF salt */
  currentSalt: Buffer;
  /** Current derived key (from password) */
  currentKey: Buffer;
  /** Current nonce */
  currentNonce: Buffer;
  /** Current auth tag */
  currentTag: Buffer;
  /** New password (or same password for salt rotation) */
  newPassword: string;
  /** Scrypt N parameter */
  scryptN: number;
}

export interface VaultKeyRotationResult {
  /** New encrypted data */
  encryptedData: Buffer;
  /** New KDF salt */
  newSalt: Buffer;
  /** New nonce */
  newNonce: Buffer;
  /** New auth tag */
  newTag: Buffer;
  /** New derived key */
  newKey: Buffer;
}

/**
 * Rotate the vault encryption key
 *
 * This re-encrypts the vault with a new derived key.
 * Can be used to:
 * - Change password
 * - Rotate the salt (same password, new salt)
 * - Increase KDF parameters
 */
export function rotateVaultKey(params: VaultKeyRotationParams): VaultKeyRotationResult {
  const { encryptedData, currentKey, currentNonce, currentTag, newPassword, scryptN } = params;

  // Decrypt with current key
  const decipher = createDecipheriv("aes-256-gcm", currentKey, currentNonce);
  decipher.setAuthTag(currentTag);
  const plaintext = Buffer.concat([decipher.update(encryptedData), decipher.final()]);

  // Generate new salt and derive new key
  const newSalt = randomBytes(32);
  const newKey = scryptSync(newPassword, newSalt, 32, {
    N: scryptN,
    r: 8,
    p: 1,
  });

  // Encrypt with new key
  const newNonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", newKey, newNonce);
  const newEncryptedData = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const newTag = cipher.getAuthTag();

  return {
    encryptedData: newEncryptedData,
    newSalt,
    newNonce,
    newTag,
    newKey,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Capability Re-issuance Tracking
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Identify capabilities that need re-issuance after key rotation
 */
export function identifyCapabilitiesNeedingReissue(
  grants: Record<string, { id: string; expires: string; revoked: boolean }>,
  oldKeyVersion: number,
  currentCapabilityVersions: Map<string, number>,
): VersionedCapability[] {
  const needsReissue: VersionedCapability[] = [];

  for (const [id, grant] of Object.entries(grants)) {
    // Skip revoked or expired
    if (grant.revoked) {
      continue;
    }
    if (new Date(grant.expires).getTime() < Date.now()) {
      continue;
    }

    // Check if this capability was signed with old key
    const capVersion = currentCapabilityVersions.get(id);
    if (capVersion !== undefined && capVersion <= oldKeyVersion) {
      needsReissue.push({
        id,
        signerKeyVersion: capVersion,
        signerKeyId: "", // Would be filled in by caller
        needsReissue: true,
      });
    }
  }

  return needsReissue;
}

// ─────────────────────────────────────────────────────────────────────────────
// Initialization Helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Create initial key rotation state from an existing identity
 */
export function createInitialRotationState(identity: {
  publicKey: string;
  privateKeyPem: string;
  publicKeyPem?: string;
  encryptionPublicKey?: string;
  encryptionPrivateKeyPem?: string;
  encryptionPublicKeyPem?: string;
}): KeyRotationState {
  const keyId = generateKeyId(identity.publicKey);

  // Generate encryption keys if not present (for migration)
  let encryptionPublicKey = identity.encryptionPublicKey ?? "";
  let encryptionPrivateKeyPem = identity.encryptionPrivateKeyPem ?? "";
  let encryptionPublicKeyPem = identity.encryptionPublicKeyPem ?? "";

  if (!encryptionPublicKey) {
    const { publicKey: x25519Pub, privateKey: x25519Priv } = generateKeyPairSync("x25519");
    encryptionPublicKeyPem = x25519Pub.export({ type: "spki", format: "pem" }).toString();
    encryptionPrivateKeyPem = x25519Priv.export({ type: "pkcs8", format: "pem" }).toString();
    const x25519SpkiDer = x25519Pub.export({ type: "spki", format: "der" }) as Buffer;
    encryptionPublicKey = x25519SpkiDer.subarray(X25519_SPKI_PREFIX.length).toString("base64");
  }

  const versionedIdentity: VersionedIdentity = {
    version: 1,
    keyId,
    publicKey: identity.publicKey,
    privateKeyPem: identity.privateKeyPem,
    publicKeyPem: identity.publicKeyPem ?? "",
    encryptionPublicKey,
    encryptionPrivateKeyPem,
    encryptionPublicKeyPem,
    createdAt: new Date().toISOString(),
    algorithm: "Ed25519",
  };

  return {
    current: versionedIdentity,
    archivedKeys: [],
  };
}

/**
 * Create a fresh key rotation state with new keys
 */
export function createFreshRotationState(): KeyRotationState {
  const identity = generateVersionedIdentity(1);
  return {
    current: identity,
    archivedKeys: [],
  };
}
