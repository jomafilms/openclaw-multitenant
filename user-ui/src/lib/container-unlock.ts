/**
 * Direct browser-to-container unlock client
 *
 * Connects directly to the user's container via WebSocket proxy,
 * bypassing the management server for vault unlock operations.
 * Password derivation happens entirely in the browser.
 *
 * Supports both WebSocket (preferred) and HTTP (fallback) transports.
 */

import {
  createUnlockResponse,
  createSessionUnlockPayload,
  type SessionKdfParams,
} from "./vault-crypto.js";

interface UnlockChallengeResponse {
  challengeId: string;
  challenge: string;
  salt: string | null;
}

interface UnlockVerifyResponse {
  success: boolean;
  expiresIn?: number;
  error?: string;
}

interface VaultStatus {
  initialized: boolean;
  locked: boolean;
  expiresIn: number;
  publicKey: string | null;
}

// Session vault types (for encrypted session storage)
interface SessionVaultStatus {
  initialized: boolean;
  locked: boolean;
  expiresIn: number | null;
  sessionsEncrypted: boolean;
}

interface SessionChallengeResponse {
  success: boolean;
  challenge?: {
    salt: string;
    kdf: {
      algorithm: "argon2id";
      memory: number;
      iterations: number;
      parallelism: number;
    };
  };
  error?: string;
}

type MessageHandler = (data: unknown) => void;

/**
 * Abstract interface for container unlock client
 */
export interface IContainerUnlockClient {
  // Original vault operations (integrations, capabilities)
  getVaultStatus(): Promise<VaultStatus>;
  getChallenge(): Promise<UnlockChallengeResponse>;
  submitUnlockResponse(
    challengeId: string,
    response: string,
    derivedKey: string,
  ): Promise<UnlockVerifyResponse>;
  unlock(password: string): Promise<{ success: boolean; expiresIn?: number; error?: string }>;
  lock(): Promise<{ success: boolean }>;
  extendSession(): Promise<{ success: boolean; expiresIn: number }>;
  close(): void;

  // Session vault operations (encrypted session storage)
  getSessionVaultStatus(): Promise<{
    success: boolean;
    status?: SessionVaultStatus;
    error?: string;
  }>;
  getSessionChallenge(): Promise<SessionChallengeResponse>;
  unlockSessionVault(
    password: string,
  ): Promise<{ success: boolean; expiresIn?: number; error?: string }>;
  lockSessionVault(): Promise<{ success: boolean }>;
  extendSessionVault(): Promise<{ success: boolean; expiresIn?: number; error?: string }>;
  migrateSessionsToEncrypted(): Promise<{
    success: boolean;
    migrated?: number;
    failed?: string[];
    error?: string;
  }>;
}

/**
 * WebSocket-based client for direct container communication
 */
export class ContainerUnlockClient implements IContainerUnlockClient {
  private ws: WebSocket | null = null;
  private messageHandlers = new Map<string, MessageHandler>();
  private messageIdCounter = 0;
  private connectionPromise: Promise<void> | null = null;

  constructor(private wsUrl: string) {}

  /**
   * Connect to the container's unlock WebSocket endpoint
   */
  async connect(): Promise<void> {
    if (this.ws?.readyState === WebSocket.OPEN) {
      return;
    }

    if (this.connectionPromise) {
      return this.connectionPromise;
    }

    this.connectionPromise = new Promise((resolve, reject) => {
      const ws = new WebSocket(this.wsUrl);

      const timeout = setTimeout(() => {
        ws.close();
        reject(new Error("Connection timeout"));
      }, 10000);

      ws.onopen = () => {
        clearTimeout(timeout);
        this.ws = ws;
        this.connectionPromise = null;
        resolve();
      };

      ws.onerror = () => {
        clearTimeout(timeout);
        this.connectionPromise = null;
        reject(new Error("Failed to connect to container"));
      };

      ws.onclose = () => {
        this.ws = null;
        this.connectionPromise = null;
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          const handler = this.messageHandlers.get(data.id);
          if (handler) {
            this.messageHandlers.delete(data.id);
            handler(data);
          }
        } catch {
          console.error("Failed to parse WebSocket message");
        }
      };
    });

    return this.connectionPromise;
  }

  /**
   * Send a message and wait for response
   */
  private async sendMessage<T>(type: string, payload: Record<string, unknown> = {}): Promise<T> {
    await this.connect();

    if (!this.ws) {
      throw new Error("Not connected");
    }

    const id = String(++this.messageIdCounter);

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.messageHandlers.delete(id);
        reject(new Error("Request timeout"));
      }, 30000);

      this.messageHandlers.set(id, (data: unknown) => {
        clearTimeout(timeout);
        const response = data as { error?: string } & T;
        if (response.error) {
          reject(new Error(response.error));
        } else {
          resolve(response as T);
        }
      });

      this.ws!.send(JSON.stringify({ id, type, ...payload }));
    });
  }

  /**
   * Get vault status from container
   */
  async getVaultStatus(): Promise<VaultStatus> {
    return this.sendMessage<VaultStatus>("vault:status");
  }

  /**
   * Request an unlock challenge from the container
   */
  async getChallenge(): Promise<UnlockChallengeResponse> {
    return this.sendMessage<UnlockChallengeResponse>("vault:challenge");
  }

  /**
   * Submit unlock response to the container
   */
  async submitUnlockResponse(
    challengeId: string,
    response: string,
    derivedKey: string,
  ): Promise<UnlockVerifyResponse> {
    return this.sendMessage<UnlockVerifyResponse>("vault:verify", {
      challengeId,
      response,
      derivedKey,
    });
  }

  /**
   * Complete unlock flow with password
   * Password derivation happens entirely in browser
   */
  async unlock(
    password: string,
  ): Promise<{ success: boolean; expiresIn?: number; error?: string }> {
    // Step 1: Get challenge from container
    const challenge = await this.getChallenge();

    if (!challenge.salt) {
      return { success: false, error: "Vault not initialized" };
    }

    // Step 2: Derive key and sign challenge in browser
    // Password NEVER leaves the browser
    const { response, derivedKey } = await createUnlockResponse(
      password,
      challenge.salt,
      challenge.challenge,
    );

    // Step 3: Submit response to container
    const result = await this.submitUnlockResponse(challenge.challengeId, response, derivedKey);

    return result;
  }

  /**
   * Lock the vault
   */
  async lock(): Promise<{ success: boolean }> {
    return this.sendMessage<{ success: boolean }>("vault:lock");
  }

  /**
   * Extend vault session
   */
  async extendSession(): Promise<{ success: boolean; expiresIn: number }> {
    return this.sendMessage<{ success: boolean; expiresIn: number }>("vault:extend");
  }

  /**
   * Close the connection
   */
  close(): void {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Session Vault Operations (encrypted session storage)
  // ─────────────────────────────────────────────────────────────────────────────

  /**
   * Get session vault status
   */
  async getSessionVaultStatus(): Promise<{
    success: boolean;
    status?: SessionVaultStatus;
    error?: string;
  }> {
    return this.sendMessage<{ success: boolean; status?: SessionVaultStatus; error?: string }>(
      "session:status",
    );
  }

  /**
   * Get session challenge (salt + KDF params) for key derivation
   */
  async getSessionChallenge(): Promise<SessionChallengeResponse> {
    return this.sendMessage<SessionChallengeResponse>("session:challenge");
  }

  /**
   * Unlock session vault with password
   * Key derivation happens entirely in browser
   */
  async unlockSessionVault(
    password: string,
  ): Promise<{ success: boolean; expiresIn?: number; error?: string }> {
    // Step 1: Get KDF params from container
    const challengeResponse = await this.getSessionChallenge();

    if (!challengeResponse.success || !challengeResponse.challenge) {
      return { success: false, error: challengeResponse.error || "Failed to get challenge" };
    }

    // Step 2: Derive key in browser using Argon2id
    const { derivedKey } = await createSessionUnlockPayload(password, {
      salt: challengeResponse.challenge.salt,
      memory: challengeResponse.challenge.kdf.memory,
      iterations: challengeResponse.challenge.kdf.iterations,
      parallelism: challengeResponse.challenge.kdf.parallelism,
    });

    // Step 3: Send derived key directly to container
    return this.sendMessage<{ success: boolean; expiresIn?: number; error?: string }>(
      "session:unlock",
      {
        derivedKey,
      },
    );
  }

  /**
   * Lock session vault
   */
  async lockSessionVault(): Promise<{ success: boolean }> {
    return this.sendMessage<{ success: boolean }>("session:lock");
  }

  /**
   * Extend session vault timeout
   */
  async extendSessionVault(): Promise<{ success: boolean; expiresIn?: number; error?: string }> {
    return this.sendMessage<{ success: boolean; expiresIn?: number; error?: string }>(
      "session:extend",
    );
  }

  /**
   * Migrate unencrypted sessions to encrypted format
   */
  async migrateSessionsToEncrypted(): Promise<{
    success: boolean;
    migrated?: number;
    failed?: string[];
    error?: string;
  }> {
    return this.sendMessage<{
      success: boolean;
      migrated?: number;
      failed?: string[];
      error?: string;
    }>("session:migrate");
  }
}

/**
 * HTTP client that uses management server proxy endpoints.
 * SECURITY: This client does NOT require authToken - authentication is handled
 * by the management server session, and the AGENT_SERVER_TOKEN is added server-side.
 */
export class ContainerUnlockProxyClient implements IContainerUnlockClient {
  constructor(private proxyBasePath: string = "/api/container/vault") {}

  private async request<T>(
    method: string,
    path: string,
    body?: Record<string, unknown>,
  ): Promise<T> {
    const url = `${this.proxyBasePath}${path}`;

    const response = await fetch(url, {
      method,
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include", // Include session cookies
      body: body ? JSON.stringify(body) : undefined,
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: "Request failed" }));
      throw new Error(error.error || `HTTP ${response.status}`);
    }

    return response.json();
  }

  async getVaultStatus(): Promise<VaultStatus> {
    return this.request("GET", "/status");
  }

  async getChallenge(): Promise<UnlockChallengeResponse> {
    return this.request("POST", "/challenge");
  }

  async submitUnlockResponse(
    challengeId: string,
    response: string,
    derivedKey: string,
  ): Promise<UnlockVerifyResponse> {
    return this.request("POST", "/verify", { challengeId, response, derivedKey });
  }

  async unlock(
    password: string,
  ): Promise<{ success: boolean; expiresIn?: number; error?: string }> {
    // Step 1: Get challenge from container (via proxy)
    const challenge = await this.getChallenge();

    if (!challenge.salt) {
      return { success: false, error: "Vault not initialized" };
    }

    // Step 2: Derive key and sign challenge in browser
    // Password NEVER leaves the browser
    const { response, derivedKey } = await createUnlockResponse(
      password,
      challenge.salt,
      challenge.challenge,
    );

    // Step 3: Submit response to container (via proxy)
    const result = await this.submitUnlockResponse(challenge.challengeId, response, derivedKey);

    return result;
  }

  async lock(): Promise<{ success: boolean }> {
    return this.request("POST", "/lock");
  }

  async extendSession(): Promise<{ success: boolean; expiresIn: number }> {
    return this.request("POST", "/extend");
  }

  close(): void {
    // No-op for HTTP client
  }

  // Session vault operations

  async getSessionVaultStatus(): Promise<{
    success: boolean;
    status?: SessionVaultStatus;
    error?: string;
  }> {
    return this.request("GET", "/session/status");
  }

  async getSessionChallenge(): Promise<SessionChallengeResponse> {
    return this.request("GET", "/session/challenge");
  }

  async unlockSessionVault(
    password: string,
  ): Promise<{ success: boolean; expiresIn?: number; error?: string }> {
    const challengeResponse = await this.getSessionChallenge();

    if (!challengeResponse.success || !challengeResponse.challenge) {
      return { success: false, error: challengeResponse.error || "Failed to get challenge" };
    }

    const { derivedKey } = await createSessionUnlockPayload(password, {
      salt: challengeResponse.challenge.salt,
      memory: challengeResponse.challenge.kdf.memory,
      iterations: challengeResponse.challenge.kdf.iterations,
      parallelism: challengeResponse.challenge.kdf.parallelism,
    });

    return this.request("POST", "/session/unlock", { derivedKey });
  }

  async lockSessionVault(): Promise<{ success: boolean }> {
    return this.request("POST", "/session/lock");
  }

  async extendSessionVault(): Promise<{ success: boolean; expiresIn?: number; error?: string }> {
    return this.request("POST", "/session/extend");
  }

  async migrateSessionsToEncrypted(): Promise<{
    success: boolean;
    migrated?: number;
    failed?: string[];
    error?: string;
  }> {
    return this.request("POST", "/session/migrate");
  }
}

/**
 * HTTP-based client for direct container communication
 * @deprecated Use ContainerUnlockProxyClient instead - this client exposes authToken to browser
 */
export class ContainerUnlockHttpClient implements IContainerUnlockClient {
  constructor(
    private baseUrl: string,
    private userId: string,
    private authToken: string,
  ) {
    console.warn(
      "[DEPRECATED] ContainerUnlockHttpClient exposes authToken to browser. Use ContainerUnlockProxyClient instead.",
    );
  }

  private async request<T>(
    method: string,
    path: string,
    body?: Record<string, unknown>,
  ): Promise<T> {
    const url = `${this.baseUrl}/api/containers/${this.userId}/vault${path}`;

    const response = await fetch(url, {
      method,
      headers: {
        "Content-Type": "application/json",
        "X-Auth-Token": this.authToken,
      },
      body: body ? JSON.stringify(body) : undefined,
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: "Request failed" }));
      throw new Error(error.error || `HTTP ${response.status}`);
    }

    return response.json();
  }

  async getVaultStatus(): Promise<VaultStatus> {
    return this.request("GET", "/status");
  }

  async getChallenge(): Promise<UnlockChallengeResponse> {
    return this.request("POST", "/challenge");
  }

  async submitUnlockResponse(
    challengeId: string,
    response: string,
    derivedKey: string,
  ): Promise<UnlockVerifyResponse> {
    return this.request("POST", "/verify", { challengeId, response, derivedKey });
  }

  async unlock(
    password: string,
  ): Promise<{ success: boolean; expiresIn?: number; error?: string }> {
    // Step 1: Get challenge from container
    const challenge = await this.getChallenge();

    if (!challenge.salt) {
      return { success: false, error: "Vault not initialized" };
    }

    // Step 2: Derive key and sign challenge in browser
    // Password NEVER leaves the browser
    const { response, derivedKey } = await createUnlockResponse(
      password,
      challenge.salt,
      challenge.challenge,
    );

    // Step 3: Submit response to container
    const result = await this.submitUnlockResponse(challenge.challengeId, response, derivedKey);

    return result;
  }

  async lock(): Promise<{ success: boolean }> {
    return this.request("POST", "/lock");
  }

  async extendSession(): Promise<{ success: boolean; expiresIn: number }> {
    return this.request("POST", "/extend");
  }

  close(): void {
    // No-op for HTTP client
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Session Vault Operations (encrypted session storage)
  // ─────────────────────────────────────────────────────────────────────────────

  async getSessionVaultStatus(): Promise<{
    success: boolean;
    status?: SessionVaultStatus;
    error?: string;
  }> {
    return this.request("GET", "/session/status");
  }

  async getSessionChallenge(): Promise<SessionChallengeResponse> {
    return this.request("GET", "/session/challenge");
  }

  async unlockSessionVault(
    password: string,
  ): Promise<{ success: boolean; expiresIn?: number; error?: string }> {
    // Step 1: Get KDF params from container
    const challengeResponse = await this.getSessionChallenge();

    if (!challengeResponse.success || !challengeResponse.challenge) {
      return { success: false, error: challengeResponse.error || "Failed to get challenge" };
    }

    // Step 2: Derive key in browser using Argon2id
    const { derivedKey } = await createSessionUnlockPayload(password, {
      salt: challengeResponse.challenge.salt,
      memory: challengeResponse.challenge.kdf.memory,
      iterations: challengeResponse.challenge.kdf.iterations,
      parallelism: challengeResponse.challenge.kdf.parallelism,
    });

    // Step 3: Send derived key directly to container
    return this.request("POST", "/session/unlock", { derivedKey });
  }

  async lockSessionVault(): Promise<{ success: boolean }> {
    return this.request("POST", "/session/lock");
  }

  async extendSessionVault(): Promise<{ success: boolean; expiresIn?: number; error?: string }> {
    return this.request("POST", "/session/extend");
  }

  async migrateSessionsToEncrypted(): Promise<{
    success: boolean;
    migrated?: number;
    failed?: string[];
    error?: string;
  }> {
    return this.request("POST", "/session/migrate");
  }
}

/**
 * Create unlock client using management server proxy.
 * SECURITY: This is the preferred method - no authToken is exposed to the browser.
 * The management server handles authentication and adds the AGENT_SERVER_TOKEN server-side.
 */
export function createContainerUnlockProxyClient(
  proxyBasePath: string = "/api/container/vault",
): IContainerUnlockClient {
  return new ContainerUnlockProxyClient(proxyBasePath);
}

/**
 * Create unlock client for a user's container
 * @deprecated This function may expose authToken to browser. Use createContainerUnlockProxyClient instead.
 */
export function createContainerUnlockClient(
  agentServerUrl: string,
  userId: string,
  authToken?: string,
): IContainerUnlockClient {
  // If no agentServerUrl provided (null from new API), use proxy client
  if (!agentServerUrl) {
    return new ContainerUnlockProxyClient();
  }

  // Legacy path: Convert HTTP URL to WebSocket URL
  const wsProtocol = agentServerUrl.startsWith("https") ? "wss" : "ws";
  const baseUrl = agentServerUrl.replace(/^https?/, wsProtocol);
  const tokenParam = authToken ? `?token=${encodeURIComponent(authToken)}` : "";
  const wsUrl = `${baseUrl}/api/containers/${userId}/unlock${tokenParam}`;

  return new ContainerUnlockClient(wsUrl);
}

/**
 * Create HTTP-based unlock client
 * @deprecated This function exposes authToken to browser. Use createContainerUnlockProxyClient instead.
 */
export function createContainerUnlockHttpClient(
  agentServerUrl: string,
  userId: string,
  authToken: string,
): IContainerUnlockClient {
  return new ContainerUnlockHttpClient(agentServerUrl, userId, authToken);
}
