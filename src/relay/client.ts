/**
 * Relay Client
 *
 * Client for communicating with the relay service from containers.
 * Used for notifying the relay about capability revocations.
 */

import { sign as cryptoSign, createPrivateKey } from "crypto";

// Type for cached snapshots (avoiding circular import with secret-store)
interface CachedSnapshot {
  capabilityId: string;
  encryptedData: string;
  ephemeralPublicKey: string;
  nonce: string;
  tag: string;
  signature: string;
  issuerPublicKey: string;
  recipientPublicKey: string;
  createdAt: string;
  expiresAt: string;
}

export interface RelayClientConfig {
  /** Relay service URL (e.g., "https://relay.example.com") */
  relayUrl: string;
  /** Request timeout in milliseconds (default: 5000) */
  timeout?: number;
  /** Retry count for failed requests (default: 2) */
  retries?: number;
}

export interface NotifyRevocationParams {
  /** The capability ID being revoked */
  capabilityId: string;
  /** Public key of the issuer (revoker) - base64 encoded */
  publicKey: string;
  /** PEM-encoded private key for signing */
  privateKeyPem: string;
  /** Optional reason for revocation */
  reason?: string;
  /** Original capability expiry time (ISO string) */
  originalExpiry?: string;
}

export interface NotifyRevocationResult {
  success: boolean;
  error?: string;
  /** Whether the relay was reachable */
  relayReachable: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// Container Registration Types
// ─────────────────────────────────────────────────────────────────────────────

export interface RegisterContainerParams {
  /** Ed25519 public key (base64) */
  publicKey: string;
  /** X25519 encryption public key (base64, optional) */
  encryptionPublicKey?: string;
  /** Callback URL for message delivery (HTTPS) */
  callbackUrl?: string;
  /** PEM-encoded private key for signing the challenge */
  privateKeyPem: string;
}

export interface ContainerRegistration {
  containerId: string;
  publicKey: string;
  publicKeyHash: string;
  encryptionPublicKey?: string;
  hasCallback: boolean;
  registeredAt: string;
  updatedAt?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Message Relay Types
// ─────────────────────────────────────────────────────────────────────────────

export interface SendMessageParams {
  /** Target container ID (UUID) */
  targetContainerId: string;
  /** Capability token for authorization */
  capabilityToken: string;
  /** Encrypted message payload (the relay cannot decrypt this) */
  encryptedPayload: string;
  /** Nonce used for encryption (base64, optional) */
  nonce?: string;
  /** Signature of the envelope (base64, optional) */
  signature?: string;
}

export interface SendMessageResult {
  success: boolean;
  messageId?: string;
  capabilityId?: string;
  status?: "delivered" | "queued";
  deliveryMethod?: "websocket" | "callback" | "pending";
  wakeTriggered?: boolean;
  error?: string;
  relayReachable: boolean;
}

export interface PendingMessage {
  id: string;
  from: string;
  payload: string;
  size: number;
  timestamp: string;
}

export interface ContainerLookupResult {
  containerId: string;
  publicKey: string;
  encryptionPublicKey?: string;
  registeredAt: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Key Rotation Types
// ─────────────────────────────────────────────────────────────────────────────

export interface NotifyKeyRotationParams {
  /** Old public key being rotated out */
  oldPublicKey: string;
  /** New public key being rotated in */
  newPublicKey: string;
  /** New encryption public key */
  newEncryptionPublicKey: string;
  /** When the transition period ends */
  transitionEndsAt: string;
  /** PEM-encoded new private key for signing the rotation notice */
  newPrivateKeyPem: string;
  /** Key version (incrementing) */
  keyVersion: number;
}

export interface KeyRotationResult {
  success: boolean;
  error?: string;
  relayReachable: boolean;
}

export class RelayClient {
  private readonly config: Required<RelayClientConfig>;

  constructor(config: RelayClientConfig) {
    this.config = {
      relayUrl: config.relayUrl.replace(/\/$/, ""), // Remove trailing slash
      timeout: config.timeout ?? 5000,
      retries: config.retries ?? 2,
    };
  }

  /**
   * Notify the relay that a capability has been revoked.
   * The revocation is signed by the issuer to prove authorization.
   */
  async notifyRevocation(params: NotifyRevocationParams): Promise<NotifyRevocationResult> {
    const { capabilityId, publicKey, privateKeyPem, reason, originalExpiry } = params;

    const timestamp = new Date().toISOString();

    // Build the payload to sign
    const signPayload = JSON.stringify({
      action: "revoke",
      capabilityId,
      revokedBy: publicKey,
      reason,
      originalExpiry,
      timestamp,
    });

    // Sign with issuer's private key
    const privateKey = createPrivateKey(privateKeyPem);
    const signature = cryptoSign(null, Buffer.from(signPayload, "utf-8"), privateKey);

    // Build the request body
    const body = {
      capabilityId,
      revokedBy: publicKey,
      signature: signature.toString("base64"),
      reason,
      originalExpiry,
      timestamp,
    };

    // Send to relay with retries
    let lastError: Error | null = null;
    for (let attempt = 0; attempt <= this.config.retries; attempt++) {
      try {
        const response = await this.fetchWithTimeout(
          `${this.config.relayUrl}/relay/revoke`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
          },
          this.config.timeout,
        );

        const result = (await response.json()) as { success: boolean; error?: string };

        if (response.ok && result.success) {
          return { success: true, relayReachable: true };
        }

        return {
          success: false,
          error: result.error ?? `HTTP ${response.status}`,
          relayReachable: true,
        };
      } catch (err) {
        lastError = err as Error;
        // Retry on network errors
        if (attempt < this.config.retries) {
          await this.sleep(100 * Math.pow(2, attempt)); // Exponential backoff
        }
      }
    }

    // All retries failed
    return {
      success: false,
      error: lastError?.message ?? "Unknown error",
      relayReachable: false,
    };
  }

  /**
   * Check if a capability is revoked at the relay.
   */
  async checkRevocation(capabilityId: string): Promise<{
    revoked: boolean;
    revokedAt?: string;
    revokedBy?: string;
    reason?: string;
    error?: string;
    relayReachable: boolean;
  }> {
    try {
      const response = await this.fetchWithTimeout(
        `${this.config.relayUrl}/relay/revocation/${encodeURIComponent(capabilityId)}`,
        { method: "GET" },
        this.config.timeout,
      );

      if (!response.ok) {
        return {
          revoked: false,
          error: `HTTP ${response.status}`,
          relayReachable: true,
        };
      }

      const result = (await response.json()) as {
        revoked: boolean;
        revokedAt?: string;
        revokedBy?: string;
        reason?: string;
      };

      return { ...result, relayReachable: true };
    } catch (err) {
      return {
        revoked: false,
        error: (err as Error).message,
        relayReachable: false,
      };
    }
  }

  /**
   * Batch check revocations for multiple capabilities.
   */
  async checkRevocations(capabilityIds: string[]): Promise<{
    results: Record<string, { revoked: boolean; revokedAt?: string; reason?: string }>;
    error?: string;
    relayReachable: boolean;
  }> {
    try {
      const response = await this.fetchWithTimeout(
        `${this.config.relayUrl}/relay/check-revocations`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ capabilityIds }),
        },
        this.config.timeout,
      );

      if (!response.ok) {
        return {
          results: {},
          error: `HTTP ${response.status}`,
          relayReachable: true,
        };
      }

      const data = (await response.json()) as {
        results: Record<string, { revoked: boolean; revokedAt?: string; reason?: string }>;
      };

      return { ...data, relayReachable: true };
    } catch (err) {
      return {
        results: {},
        error: (err as Error).message,
        relayReachable: false,
      };
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Cached Snapshot Storage (CACHED tier)
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Store a cached snapshot on the relay for offline access.
   * The snapshot is already encrypted and signed by the issuer.
   */
  async storeSnapshot(snapshot: CachedSnapshot): Promise<{
    success: boolean;
    error?: string;
    relayReachable: boolean;
  }> {
    let lastError: Error | null = null;
    for (let attempt = 0; attempt <= this.config.retries; attempt++) {
      try {
        const response = await this.fetchWithTimeout(
          `${this.config.relayUrl}/relay/snapshots`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(snapshot),
          },
          this.config.timeout,
        );

        const result = (await response.json()) as { success: boolean; error?: string };

        if (response.ok && result.success) {
          return { success: true, relayReachable: true };
        }

        return {
          success: false,
          error: result.error ?? `HTTP ${response.status}`,
          relayReachable: true,
        };
      } catch (err) {
        lastError = err as Error;
        if (attempt < this.config.retries) {
          await this.sleep(100 * Math.pow(2, attempt));
        }
      }
    }

    return {
      success: false,
      error: lastError?.message ?? "Unknown error",
      relayReachable: false,
    };
  }

  /**
   * Retrieve a cached snapshot from the relay.
   */
  async getSnapshot(capabilityId: string): Promise<{
    success: boolean;
    snapshot?: CachedSnapshot;
    error?: string;
    relayReachable: boolean;
  }> {
    try {
      const response = await this.fetchWithTimeout(
        `${this.config.relayUrl}/relay/snapshots/${encodeURIComponent(capabilityId)}`,
        { method: "GET" },
        this.config.timeout,
      );

      if (!response.ok) {
        if (response.status === 404) {
          return { success: false, error: "Snapshot not found", relayReachable: true };
        }
        return {
          success: false,
          error: `HTTP ${response.status}`,
          relayReachable: true,
        };
      }

      const snapshot = (await response.json()) as CachedSnapshot;
      return { success: true, snapshot, relayReachable: true };
    } catch (err) {
      return {
        success: false,
        error: (err as Error).message,
        relayReachable: false,
      };
    }
  }

  /**
   * Delete a cached snapshot from the relay.
   * Called when a capability is revoked.
   */
  async deleteSnapshot(capabilityId: string): Promise<{
    success: boolean;
    error?: string;
    relayReachable: boolean;
  }> {
    try {
      const response = await this.fetchWithTimeout(
        `${this.config.relayUrl}/relay/snapshots/${encodeURIComponent(capabilityId)}`,
        { method: "DELETE" },
        this.config.timeout,
      );

      if (!response.ok && response.status !== 404) {
        return {
          success: false,
          error: `HTTP ${response.status}`,
          relayReachable: true,
        };
      }

      return { success: true, relayReachable: true };
    } catch (err) {
      return {
        success: false,
        error: (err as Error).message,
        relayReachable: false,
      };
    }
  }

  /**
   * List available snapshots for a recipient.
   * Requires signing the request to prove ownership of the recipient public key.
   */
  async listSnapshots(params: { recipientPublicKey: string; privateKeyPem: string }): Promise<{
    success: boolean;
    snapshots?: CachedSnapshot[];
    error?: string;
    relayReachable: boolean;
  }> {
    const { recipientPublicKey, privateKeyPem } = params;
    const timestamp = new Date().toISOString();

    // Build and sign the request payload
    const signPayload = JSON.stringify({
      action: "list-snapshots",
      recipientPublicKey,
      timestamp,
    });

    const privateKey = createPrivateKey(privateKeyPem);
    const signature = cryptoSign(null, Buffer.from(signPayload, "utf-8"), privateKey);

    const body = {
      recipientPublicKey,
      signature: signature.toString("base64"),
      timestamp,
    };

    try {
      const response = await this.fetchWithTimeout(
        `${this.config.relayUrl}/relay/snapshots/list`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        },
        this.config.timeout,
      );

      if (!response.ok) {
        const result = (await response.json()) as { error?: string };
        return {
          success: false,
          error: result.error ?? `HTTP ${response.status}`,
          relayReachable: true,
        };
      }

      const result = (await response.json()) as { success: boolean; snapshots: CachedSnapshot[] };
      return {
        success: true,
        snapshots: result.snapshots,
        relayReachable: true,
      };
    } catch (err) {
      return {
        success: false,
        error: (err as Error).message,
        relayReachable: false,
      };
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Container Registration
  // ─────────────────────────────────────────────────────────────────────────────

  /**
   * Register a container with the relay.
   * This enables message forwarding via callback URL and discovery by public key.
   *
   * @param params - Registration parameters including public key and optional callback URL
   * @param authHeaders - Authentication headers (Authorization and X-Container-Id)
   */
  async registerContainer(
    params: RegisterContainerParams,
    authHeaders: { authorization: string; containerId: string },
  ): Promise<{
    success: boolean;
    registration?: ContainerRegistration;
    error?: string;
    relayReachable: boolean;
  }> {
    const { publicKey, encryptionPublicKey, callbackUrl, privateKeyPem } = params;

    // Generate a random challenge and sign it to prove key ownership
    const challenge = `ocmt-register:${Date.now()}:${Math.random().toString(36).slice(2)}`;
    const privateKey = createPrivateKey(privateKeyPem);
    const signature = cryptoSign(null, Buffer.from(challenge, "utf-8"), privateKey);

    const body = {
      publicKey,
      encryptionPublicKey,
      callbackUrl,
      challenge,
      signature: signature.toString("base64"),
    };

    let lastError: Error | null = null;
    for (let attempt = 0; attempt <= this.config.retries; attempt++) {
      try {
        const response = await this.fetchWithTimeout(
          `${this.config.relayUrl}/relay/registry/register`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: authHeaders.authorization,
              "X-Container-Id": authHeaders.containerId,
            },
            body: JSON.stringify(body),
          },
          this.config.timeout,
        );

        const result = (await response.json()) as {
          success: boolean;
          containerId?: string;
          publicKeyHash?: string;
          hasCallback?: boolean;
          error?: string;
        };

        if (response.ok && result.success) {
          return {
            success: true,
            registration: {
              containerId: result.containerId!,
              publicKey,
              publicKeyHash: result.publicKeyHash!,
              encryptionPublicKey,
              hasCallback: result.hasCallback ?? false,
              registeredAt: new Date().toISOString(),
            },
            relayReachable: true,
          };
        }

        return {
          success: false,
          error: result.error ?? `HTTP ${response.status}`,
          relayReachable: true,
        };
      } catch (err) {
        lastError = err as Error;
        if (attempt < this.config.retries) {
          await this.sleep(100 * Math.pow(2, attempt));
        }
      }
    }

    return {
      success: false,
      error: lastError?.message ?? "Unknown error",
      relayReachable: false,
    };
  }

  /**
   * Update container registration (callback URL or encryption key).
   */
  async updateRegistration(
    updates: { callbackUrl?: string | null; encryptionPublicKey?: string | null },
    authHeaders: { authorization: string; containerId: string },
  ): Promise<{
    success: boolean;
    error?: string;
    relayReachable: boolean;
  }> {
    try {
      const response = await this.fetchWithTimeout(
        `${this.config.relayUrl}/relay/registry/update`,
        {
          method: "PATCH",
          headers: {
            "Content-Type": "application/json",
            Authorization: authHeaders.authorization,
            "X-Container-Id": authHeaders.containerId,
          },
          body: JSON.stringify(updates),
        },
        this.config.timeout,
      );

      const result = (await response.json()) as { success: boolean; error?: string };

      if (response.ok && result.success) {
        return { success: true, relayReachable: true };
      }

      return {
        success: false,
        error: result.error ?? `HTTP ${response.status}`,
        relayReachable: true,
      };
    } catch (err) {
      return {
        success: false,
        error: (err as Error).message,
        relayReachable: false,
      };
    }
  }

  /**
   * Get current container's registration.
   */
  async getRegistration(authHeaders: { authorization: string; containerId: string }): Promise<{
    success: boolean;
    registration?: ContainerRegistration;
    error?: string;
    relayReachable: boolean;
  }> {
    try {
      const response = await this.fetchWithTimeout(
        `${this.config.relayUrl}/relay/registry`,
        {
          method: "GET",
          headers: {
            Authorization: authHeaders.authorization,
            "X-Container-Id": authHeaders.containerId,
          },
        },
        this.config.timeout,
      );

      if (!response.ok) {
        if (response.status === 404) {
          return { success: false, error: "Container not registered", relayReachable: true };
        }
        return {
          success: false,
          error: `HTTP ${response.status}`,
          relayReachable: true,
        };
      }

      const data = (await response.json()) as ContainerRegistration;
      return { success: true, registration: data, relayReachable: true };
    } catch (err) {
      return {
        success: false,
        error: (err as Error).message,
        relayReachable: false,
      };
    }
  }

  /**
   * Unregister a container.
   */
  async unregister(authHeaders: { authorization: string; containerId: string }): Promise<{
    success: boolean;
    error?: string;
    relayReachable: boolean;
  }> {
    try {
      const response = await this.fetchWithTimeout(
        `${this.config.relayUrl}/relay/registry`,
        {
          method: "DELETE",
          headers: {
            Authorization: authHeaders.authorization,
            "X-Container-Id": authHeaders.containerId,
          },
        },
        this.config.timeout,
      );

      const result = (await response.json()) as { success: boolean; error?: string };

      if (response.ok && result.success) {
        return { success: true, relayReachable: true };
      }

      return {
        success: false,
        error: result.error ?? `HTTP ${response.status}`,
        relayReachable: true,
      };
    } catch (err) {
      return {
        success: false,
        error: (err as Error).message,
        relayReachable: false,
      };
    }
  }

  /**
   * Look up a container by public key.
   * This enables discovering container IDs from public keys.
   */
  async lookupByPublicKey(publicKey: string): Promise<{
    success: boolean;
    container?: ContainerLookupResult;
    error?: string;
    relayReachable: boolean;
  }> {
    try {
      const response = await this.fetchWithTimeout(
        `${this.config.relayUrl}/relay/registry/lookup`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ publicKey }),
        },
        this.config.timeout,
      );

      if (!response.ok) {
        if (response.status === 404) {
          return { success: false, error: "Container not found", relayReachable: true };
        }
        const result = (await response.json()) as { error?: string };
        return {
          success: false,
          error: result.error ?? `HTTP ${response.status}`,
          relayReachable: true,
        };
      }

      const data = (await response.json()) as ContainerLookupResult;
      return { success: true, container: data, relayReachable: true };
    } catch (err) {
      return {
        success: false,
        error: (err as Error).message,
        relayReachable: false,
      };
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Key Rotation
  // ─────────────────────────────────────────────────────────────────────────────

  /**
   * Notify the relay about a key rotation.
   * This updates the container's public key registration and allows the relay
   * to maintain a mapping of old->new keys during the transition period.
   *
   * The notification is signed with the NEW key to prove ownership.
   *
   * @param params - Key rotation parameters
   * @param authHeaders - Authentication headers for the container
   */
  async notifyKeyRotation(
    params: NotifyKeyRotationParams,
    authHeaders: { authorization: string; containerId: string },
  ): Promise<KeyRotationResult> {
    const {
      oldPublicKey,
      newPublicKey,
      newEncryptionPublicKey,
      transitionEndsAt,
      newPrivateKeyPem,
      keyVersion,
    } = params;

    const timestamp = new Date().toISOString();

    // Build the payload to sign
    const signPayload = JSON.stringify({
      action: "key_rotation",
      oldPublicKey,
      newPublicKey,
      newEncryptionPublicKey,
      transitionEndsAt,
      keyVersion,
      timestamp,
    });

    // Sign with new private key to prove ownership
    const privateKey = createPrivateKey(newPrivateKeyPem);
    const signature = cryptoSign(null, Buffer.from(signPayload, "utf-8"), privateKey);

    const body = {
      oldPublicKey,
      newPublicKey,
      newEncryptionPublicKey,
      transitionEndsAt,
      keyVersion,
      signature: signature.toString("base64"),
      timestamp,
    };

    let lastError: Error | null = null;
    for (let attempt = 0; attempt <= this.config.retries; attempt++) {
      try {
        const response = await this.fetchWithTimeout(
          `${this.config.relayUrl}/relay/registry/rotate-key`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: authHeaders.authorization,
              "X-Container-Id": authHeaders.containerId,
            },
            body: JSON.stringify(body),
          },
          this.config.timeout,
        );

        const result = (await response.json()) as { success: boolean; error?: string };

        if (response.ok && result.success) {
          return { success: true, relayReachable: true };
        }

        return {
          success: false,
          error: result.error ?? `HTTP ${response.status}`,
          relayReachable: true,
        };
      } catch (err) {
        lastError = err as Error;
        if (attempt < this.config.retries) {
          await this.sleep(100 * Math.pow(2, attempt));
        }
      }
    }

    return {
      success: false,
      error: lastError?.message ?? "Unknown error",
      relayReachable: false,
    };
  }

  /**
   * Get key rotation history for a container.
   * Useful for verifying old signatures during transition periods.
   */
  async getKeyRotationHistory(containerId: string): Promise<{
    success: boolean;
    history?: Array<{
      publicKey: string;
      encryptionPublicKey?: string;
      keyVersion: number;
      rotatedAt: string;
      transitionEndsAt?: string;
      isActive: boolean;
    }>;
    error?: string;
    relayReachable: boolean;
  }> {
    try {
      const response = await this.fetchWithTimeout(
        `${this.config.relayUrl}/relay/registry/${encodeURIComponent(containerId)}/key-history`,
        { method: "GET" },
        this.config.timeout,
      );

      if (!response.ok) {
        if (response.status === 404) {
          return { success: false, error: "Container not found", relayReachable: true };
        }
        return {
          success: false,
          error: `HTTP ${response.status}`,
          relayReachable: true,
        };
      }

      const data = (await response.json()) as {
        history: Array<{
          publicKey: string;
          encryptionPublicKey?: string;
          keyVersion: number;
          rotatedAt: string;
          transitionEndsAt?: string;
          isActive: boolean;
        }>;
      };

      return { success: true, history: data.history, relayReachable: true };
    } catch (err) {
      return {
        success: false,
        error: (err as Error).message,
        relayReachable: false,
      };
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Message Relay (with Capability Verification)
  // ─────────────────────────────────────────────────────────────────────────────

  /**
   * Send an encrypted message to another container with capability verification.
   *
   * This is the main method for container-to-container communication.
   * The capability token proves authorization to access the target resource.
   *
   * The relay is ZERO-KNOWLEDGE:
   * - The encryptedPayload is never decrypted by the relay
   * - Only metadata (who->whom, timestamp, size) is logged
   * - The capability token is verified but content remains encrypted
   *
   * @param params - Message parameters including target, capability token, and encrypted payload
   * @param authHeaders - Authentication headers for the sending container
   */
  async sendMessage(
    params: SendMessageParams,
    authHeaders: { authorization: string; containerId: string },
  ): Promise<SendMessageResult> {
    const { targetContainerId, capabilityToken, encryptedPayload, nonce, signature } = params;

    const body = {
      toContainerId: targetContainerId,
      capabilityToken,
      encryptedPayload,
      nonce,
      signature,
    };

    let lastError: Error | null = null;
    for (let attempt = 0; attempt <= this.config.retries; attempt++) {
      try {
        const response = await this.fetchWithTimeout(
          `${this.config.relayUrl}/relay/forward`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: authHeaders.authorization,
              "X-Container-Id": authHeaders.containerId,
            },
            body: JSON.stringify(body),
          },
          this.config.timeout,
        );

        const result = (await response.json()) as {
          messageId?: string;
          capabilityId?: string;
          status?: "delivered" | "queued";
          deliveryMethod?: "websocket" | "callback" | "pending";
          wakeTriggered?: boolean;
          error?: string;
        };

        if (response.ok && result.messageId) {
          return {
            success: true,
            messageId: result.messageId,
            capabilityId: result.capabilityId,
            status: result.status,
            deliveryMethod: result.deliveryMethod,
            wakeTriggered: result.wakeTriggered,
            relayReachable: true,
          };
        }

        // Don't retry on 4xx (authorization errors)
        if (response.status >= 400 && response.status < 500) {
          return {
            success: false,
            error: result.error ?? `HTTP ${response.status}`,
            relayReachable: true,
          };
        }

        lastError = new Error(result.error ?? `HTTP ${response.status}`);
      } catch (err) {
        lastError = err as Error;
      }

      if (attempt < this.config.retries) {
        await this.sleep(100 * Math.pow(2, attempt));
      }
    }

    return {
      success: false,
      error: lastError?.message ?? "Unknown error",
      relayReachable: false,
    };
  }

  /**
   * Send a simple encrypted message without capability verification.
   * Use this when both containers already have a trust relationship.
   *
   * For capability-based access control, use sendMessage() instead.
   */
  async sendSimpleMessage(
    targetContainerId: string,
    payload: string,
    authHeaders: { authorization: string; containerId: string },
  ): Promise<SendMessageResult> {
    const body = {
      toContainerId: targetContainerId,
      payload,
    };

    let lastError: Error | null = null;
    for (let attempt = 0; attempt <= this.config.retries; attempt++) {
      try {
        const response = await this.fetchWithTimeout(
          `${this.config.relayUrl}/relay/send`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: authHeaders.authorization,
              "X-Container-Id": authHeaders.containerId,
            },
            body: JSON.stringify(body),
          },
          this.config.timeout,
        );

        const result = (await response.json()) as {
          messageId?: string;
          status?: "delivered" | "queued";
          deliveryMethod?: "websocket" | "callback" | "pending";
          wakeTriggered?: boolean;
          error?: string;
        };

        if (response.ok && result.messageId) {
          return {
            success: true,
            messageId: result.messageId,
            status: result.status,
            deliveryMethod: result.deliveryMethod,
            wakeTriggered: result.wakeTriggered,
            relayReachable: true,
          };
        }

        return {
          success: false,
          error: result.error ?? `HTTP ${response.status}`,
          relayReachable: true,
        };
      } catch (err) {
        lastError = err as Error;
        if (attempt < this.config.retries) {
          await this.sleep(100 * Math.pow(2, attempt));
        }
      }
    }

    return {
      success: false,
      error: lastError?.message ?? "Unknown error",
      relayReachable: false,
    };
  }

  /**
   * Get pending messages for the authenticated container.
   */
  async getPendingMessages(
    authHeaders: { authorization: string; containerId: string },
    options?: { limit?: number; acknowledgeIds?: string[] },
  ): Promise<{
    success: boolean;
    messages?: PendingMessage[];
    count?: number;
    error?: string;
    relayReachable: boolean;
  }> {
    try {
      let url = `${this.config.relayUrl}/relay/messages/pending`;
      const params = new URLSearchParams();

      if (options?.limit) {
        params.set("limit", String(options.limit));
      }
      if (options?.acknowledgeIds?.length) {
        params.set("ack", options.acknowledgeIds.join(","));
      }

      if (params.toString()) {
        url += `?${params.toString()}`;
      }

      const response = await this.fetchWithTimeout(
        url,
        {
          method: "GET",
          headers: {
            Authorization: authHeaders.authorization,
            "X-Container-Id": authHeaders.containerId,
          },
        },
        this.config.timeout,
      );

      if (!response.ok) {
        return {
          success: false,
          error: `HTTP ${response.status}`,
          relayReachable: true,
        };
      }

      const data = (await response.json()) as {
        count: number;
        messages: PendingMessage[];
      };

      return {
        success: true,
        messages: data.messages,
        count: data.count,
        relayReachable: true,
      };
    } catch (err) {
      return {
        success: false,
        error: (err as Error).message,
        relayReachable: false,
      };
    }
  }

  /**
   * Acknowledge messages as delivered.
   */
  async acknowledgeMessages(
    messageIds: string[],
    authHeaders: { authorization: string; containerId: string },
  ): Promise<{
    success: boolean;
    acknowledged?: number;
    error?: string;
    relayReachable: boolean;
  }> {
    try {
      const response = await this.fetchWithTimeout(
        `${this.config.relayUrl}/relay/messages/ack`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: authHeaders.authorization,
            "X-Container-Id": authHeaders.containerId,
          },
          body: JSON.stringify({ messageIds }),
        },
        this.config.timeout,
      );

      if (!response.ok) {
        return {
          success: false,
          error: `HTTP ${response.status}`,
          relayReachable: true,
        };
      }

      const data = (await response.json()) as {
        acknowledged: number;
        messageIds: string[];
      };

      return {
        success: true,
        acknowledged: data.acknowledged,
        relayReachable: true,
      };
    } catch (err) {
      return {
        success: false,
        error: (err as Error).message,
        relayReachable: false,
      };
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Private Helpers
  // ─────────────────────────────────────────────────────────────────────────────

  /**
   * Fetch with timeout support.
   */
  private async fetchWithTimeout(
    url: string,
    options: RequestInit,
    timeoutMs: number,
  ): Promise<Response> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      return await fetch(url, {
        ...options,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Sleep helper.
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

// Default relay URL (can be overridden via config)
const DEFAULT_RELAY_URL = "http://localhost:18790";

let clientInstance: RelayClient | null = null;

/**
 * Get or create the relay client singleton.
 */
export function getRelayClient(config?: RelayClientConfig): RelayClient {
  if (!clientInstance || config) {
    clientInstance = new RelayClient(config ?? { relayUrl: DEFAULT_RELAY_URL });
  }
  return clientInstance;
}

/**
 * Reset the client singleton (for testing).
 */
export function resetRelayClient(): void {
  clientInstance = null;
}
