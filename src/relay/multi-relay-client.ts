/**
 * Multi-Relay Client with Failover Support
 *
 * Provides high availability for relay communication through:
 * - Multiple relay endpoints
 * - Health checking with circuit breaker pattern
 * - Configurable selection strategies (primary, round-robin, latency)
 * - Graceful degradation when all relays fail
 *
 * @module relay/multi-relay-client
 */

import {
  RelayClient,
  type NotifyRevocationParams,
  type NotifyRevocationResult,
  type RegisterContainerParams,
  type ContainerRegistration,
  type SendMessageParams,
  type SendMessageResult,
  type PendingMessage,
  type ContainerLookupResult,
} from "./client.js";

// ─────────────────────────────────────────────────────────────────────────────
// Configuration Types
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Selection strategy for choosing relays
 */
export type RelaySelectionStrategy = "primary" | "round-robin" | "latency";

/**
 * Configuration for the multi-relay client
 */
export interface MultiRelayConfig {
  /** List of relay URLs (first is primary for 'primary' strategy) */
  urls: string[];
  /** Strategy for selecting relays */
  strategy: RelaySelectionStrategy;
  /** Interval for health checks in milliseconds (default: 30000) */
  healthCheckIntervalMs?: number;
  /** Number of consecutive failures before circuit opens (default: 3) */
  circuitBreakerThreshold?: number;
  /** Time in ms before attempting to reset an open circuit (default: 60000) */
  circuitBreakerResetMs?: number;
  /** Request timeout in milliseconds (default: 5000) */
  timeout?: number;
  /** Number of retries per relay before trying next (default: 1) */
  retriesPerRelay?: number;
  /** Enable graceful degradation mode (default: true) */
  gracefulDegradation?: boolean;
}

/**
 * Health status for a relay
 */
export interface RelayHealth {
  url: string;
  healthy: boolean;
  latencyMs: number | null;
  lastChecked: Date | null;
  consecutiveFailures: number;
  circuitOpen: boolean;
  circuitOpenedAt: Date | null;
}

/**
 * Result from operations that can fall back to degraded mode
 */
export interface MultiRelayResult<T> {
  success: boolean;
  data?: T;
  error?: string;
  /** Which relay handled the request (null if all failed) */
  relayUsed: string | null;
  /** Whether result came from degraded mode (e.g., cached/expired data) */
  degradedMode: boolean;
  /** All relays that were attempted */
  relaysAttempted: string[];
}

// ─────────────────────────────────────────────────────────────────────────────
// Circuit Breaker Implementation
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Circuit breaker state for a single relay
 */
interface CircuitBreakerState {
  failures: number;
  circuitOpen: boolean;
  openedAt: number | null;
  lastAttempt: number;
  latencyMs: number | null;
}

/**
 * Circuit breaker for managing relay health
 */
class CircuitBreaker {
  private readonly threshold: number;
  private readonly resetMs: number;
  private states: Map<string, CircuitBreakerState> = new Map();

  constructor(threshold: number, resetMs: number) {
    this.threshold = threshold;
    this.resetMs = resetMs;
  }

  /**
   * Check if a relay is available (circuit not open or ready to retry)
   */
  isAvailable(url: string): boolean {
    const state = this.getState(url);

    if (!state.circuitOpen) {
      return true;
    }

    // Check if enough time has passed to attempt a reset
    const now = Date.now();
    if (state.openedAt && now - state.openedAt >= this.resetMs) {
      return true; // Half-open state - allow one attempt
    }

    return false;
  }

  /**
   * Record a successful request
   */
  recordSuccess(url: string, latencyMs: number): void {
    const state = this.getState(url);
    state.failures = 0;
    state.circuitOpen = false;
    state.openedAt = null;
    state.lastAttempt = Date.now();
    state.latencyMs = latencyMs;
  }

  /**
   * Record a failed request
   */
  recordFailure(url: string): void {
    const state = this.getState(url);
    state.failures++;
    state.lastAttempt = Date.now();

    if (state.failures >= this.threshold) {
      state.circuitOpen = true;
      state.openedAt = Date.now();
    }
  }

  /**
   * Get health info for a relay
   */
  getHealth(url: string): RelayHealth {
    const state = this.getState(url);
    return {
      url,
      healthy: !state.circuitOpen && state.failures < this.threshold,
      latencyMs: state.latencyMs,
      lastChecked: state.lastAttempt ? new Date(state.lastAttempt) : null,
      consecutiveFailures: state.failures,
      circuitOpen: state.circuitOpen,
      circuitOpenedAt: state.openedAt ? new Date(state.openedAt) : null,
    };
  }

  /**
   * Get all known relay health states
   */
  getAllHealth(): RelayHealth[] {
    return Array.from(this.states.keys()).map((url) => this.getHealth(url));
  }

  /**
   * Force reset a circuit (for testing or manual recovery)
   */
  resetCircuit(url: string): void {
    const state = this.getState(url);
    state.failures = 0;
    state.circuitOpen = false;
    state.openedAt = null;
  }

  private getState(url: string): CircuitBreakerState {
    if (!this.states.has(url)) {
      this.states.set(url, {
        failures: 0,
        circuitOpen: false,
        openedAt: null,
        lastAttempt: 0,
        latencyMs: null,
      });
    }
    return this.states.get(url)!;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Multi-Relay Client
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Multi-relay client with failover support
 */
export class MultiRelayClient {
  private readonly config: Required<MultiRelayConfig>;
  private readonly clients: Map<string, RelayClient> = new Map();
  private readonly circuitBreaker: CircuitBreaker;
  private roundRobinIndex = 0;
  private healthCheckInterval: ReturnType<typeof setInterval> | null = null;

  constructor(config: MultiRelayConfig) {
    if (config.urls.length === 0) {
      throw new Error("At least one relay URL is required");
    }

    this.config = {
      urls: config.urls.map((url) => url.replace(/\/$/, "")),
      strategy: config.strategy,
      healthCheckIntervalMs: config.healthCheckIntervalMs ?? 30000,
      circuitBreakerThreshold: config.circuitBreakerThreshold ?? 3,
      circuitBreakerResetMs: config.circuitBreakerResetMs ?? 60000,
      timeout: config.timeout ?? 5000,
      retriesPerRelay: config.retriesPerRelay ?? 1,
      gracefulDegradation: config.gracefulDegradation ?? true,
    };

    this.circuitBreaker = new CircuitBreaker(
      this.config.circuitBreakerThreshold,
      this.config.circuitBreakerResetMs,
    );

    // Create clients for each relay
    for (const url of this.config.urls) {
      this.clients.set(
        url,
        new RelayClient({
          relayUrl: url,
          timeout: this.config.timeout,
          retries: this.config.retriesPerRelay,
        }),
      );
    }
  }

  /**
   * Start periodic health checks
   */
  startHealthChecks(): void {
    if (this.healthCheckInterval) {
      return; // Already running
    }

    // Run initial health check
    this.runHealthChecks();

    // Schedule periodic checks
    this.healthCheckInterval = setInterval(
      () => this.runHealthChecks(),
      this.config.healthCheckIntervalMs,
    );
  }

  /**
   * Stop periodic health checks
   */
  stopHealthChecks(): void {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = null;
    }
  }

  /**
   * Run health checks on all relays
   */
  async runHealthChecks(): Promise<RelayHealth[]> {
    const results: RelayHealth[] = [];

    await Promise.all(
      this.config.urls.map(async (url) => {
        const startTime = Date.now();
        try {
          const response = await fetch(`${url}/health`, {
            method: "GET",
            signal: AbortSignal.timeout(this.config.timeout),
          });

          const latencyMs = Date.now() - startTime;

          if (response.ok) {
            this.circuitBreaker.recordSuccess(url, latencyMs);
          } else {
            this.circuitBreaker.recordFailure(url);
          }
        } catch {
          this.circuitBreaker.recordFailure(url);
        }

        results.push(this.circuitBreaker.getHealth(url));
      }),
    );

    return results;
  }

  /**
   * Get current health status of all relays
   */
  getHealthStatus(): RelayHealth[] {
    return this.config.urls.map((url) => this.circuitBreaker.getHealth(url));
  }

  /**
   * Get available relays (circuit not open)
   */
  getAvailableRelays(): string[] {
    return this.config.urls.filter((url) => this.circuitBreaker.isAvailable(url));
  }

  /**
   * Select the next relay based on the configured strategy
   */
  private selectRelay(excludeUrls: Set<string> = new Set()): string | null {
    const available = this.config.urls.filter(
      (url) => this.circuitBreaker.isAvailable(url) && !excludeUrls.has(url),
    );

    if (available.length === 0) {
      // If graceful degradation is enabled, try any relay even with open circuit
      if (this.config.gracefulDegradation) {
        const notExcluded = this.config.urls.filter((url) => !excludeUrls.has(url));
        return notExcluded[0] ?? null;
      }
      return null;
    }

    switch (this.config.strategy) {
      case "primary":
        // Always prefer the first available relay (primary)
        return available[0];

      case "round-robin": {
        // Cycle through available relays
        const index = this.roundRobinIndex % available.length;
        this.roundRobinIndex++;
        return available[index];
      }

      case "latency": {
        // Select relay with lowest latency
        const withLatency = available
          .map((url) => ({ url, health: this.circuitBreaker.getHealth(url) }))
          .filter((r) => r.health.latencyMs !== null)
          .sort((a, b) => (a.health.latencyMs ?? Infinity) - (b.health.latencyMs ?? Infinity));

        return withLatency[0]?.url ?? available[0];
      }

      default:
        return available[0];
    }
  }

  /**
   * Execute an operation with failover across relays
   *
   * @param operation - The operation to execute on a relay client
   * @param operationName - Name of the operation for error messages
   * @param isSuccess - Optional custom function to determine if result is successful
   *                    (defaults to checking result.success if present, otherwise relayReachable && !error)
   */
  private async executeWithFailover<T extends { relayReachable: boolean; error?: string }>(
    operation: (client: RelayClient, url: string) => Promise<T>,
    operationName: string,
    isSuccess?: (result: T) => boolean,
  ): Promise<MultiRelayResult<Omit<T, "relayReachable" | "error">>> {
    const attempted: string[] = [];
    const excluded = new Set<string>();
    let lastError: string | undefined;

    // Default success check: has success field and it's true, or no error and relay reachable
    const checkSuccess =
      isSuccess ??
      ((result: T) => {
        if (
          "success" in result &&
          typeof (result as unknown as { success: boolean }).success === "boolean"
        ) {
          return (result as unknown as { success: boolean }).success;
        }
        // For methods like checkRevocation that don't have success field
        return result.relayReachable && !result.error;
      });

    while (true) {
      const relayUrl = this.selectRelay(excluded);

      if (!relayUrl) {
        // All relays exhausted
        return {
          success: false,
          error: lastError ?? `All relays failed for ${operationName}`,
          relayUsed: null,
          degradedMode: false,
          relaysAttempted: attempted,
        };
      }

      const client = this.clients.get(relayUrl)!;
      attempted.push(relayUrl);
      excluded.add(relayUrl);

      const startTime = Date.now();

      try {
        const result = await operation(client, relayUrl);
        const latencyMs = Date.now() - startTime;

        if (result.relayReachable) {
          this.circuitBreaker.recordSuccess(relayUrl, latencyMs);

          if (checkSuccess(result)) {
            // Extract data properties (everything except error, relayReachable)
            const { error, relayReachable, ...data } = result;
            return {
              success: true,
              data: data as Omit<T, "relayReachable" | "error">,
              relayUsed: relayUrl,
              degradedMode: false,
              relaysAttempted: attempted,
            };
          }
        } else {
          this.circuitBreaker.recordFailure(relayUrl);
        }

        lastError = result.error;
      } catch (err) {
        this.circuitBreaker.recordFailure(relayUrl);
        lastError = err instanceof Error ? err.message : String(err);
      }

      // Check if we should continue trying
      const remainingAvailable = this.config.urls.filter(
        (url) => this.circuitBreaker.isAvailable(url) && !excluded.has(url),
      );

      if (remainingAvailable.length === 0 && !this.config.gracefulDegradation) {
        break;
      }

      // Check if we've tried all relays
      if (excluded.size >= this.config.urls.length) {
        break;
      }
    }

    return {
      success: false,
      error: lastError ?? `All relays failed for ${operationName}`,
      relayUsed: null,
      degradedMode: false,
      relaysAttempted: attempted,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Public API - Wrapping RelayClient methods with failover
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Notify relays that a capability has been revoked
   */
  async notifyRevocation(
    params: NotifyRevocationParams,
  ): Promise<MultiRelayResult<Omit<NotifyRevocationResult, "relayReachable" | "error">>> {
    return this.executeWithFailover(
      async (client) => client.notifyRevocation(params),
      "notifyRevocation",
      (result) => result.success,
    );
  }

  /**
   * Check if a capability is revoked
   */
  async checkRevocation(capabilityId: string): Promise<
    MultiRelayResult<{
      revoked: boolean;
      revokedAt?: string;
      revokedBy?: string;
      reason?: string;
    }>
  > {
    return this.executeWithFailover(
      async (client) => client.checkRevocation(capabilityId),
      "checkRevocation",
      // For checkRevocation, success means relay was reachable and no error
      (result) => result.relayReachable && !result.error,
    );
  }

  /**
   * Batch check revocations for multiple capabilities
   */
  async checkRevocations(capabilityIds: string[]): Promise<
    MultiRelayResult<{
      results: Record<string, { revoked: boolean; revokedAt?: string; reason?: string }>;
    }>
  > {
    return this.executeWithFailover(
      async (client) => client.checkRevocations(capabilityIds),
      "checkRevocations",
      // For checkRevocations, success means relay was reachable and no error
      (result) => result.relayReachable && !result.error,
    );
  }

  /**
   * Register a container with the relay network
   */
  async registerContainer(
    params: RegisterContainerParams,
    authHeaders: { authorization: string; containerId: string },
  ): Promise<MultiRelayResult<{ registration?: ContainerRegistration }>> {
    // For registration, we should try to register with all healthy relays
    // to ensure the container is reachable from any relay
    const results = await Promise.all(
      this.config.urls
        .filter((url) => this.circuitBreaker.isAvailable(url))
        .map(async (url) => {
          const client = this.clients.get(url)!;
          const startTime = Date.now();
          try {
            const result = await client.registerContainer(params, authHeaders);
            const latencyMs = Date.now() - startTime;
            if (result.relayReachable) {
              this.circuitBreaker.recordSuccess(url, latencyMs);
            } else {
              this.circuitBreaker.recordFailure(url);
            }
            return { url, result };
          } catch (err) {
            this.circuitBreaker.recordFailure(url);
            return {
              url,
              result: {
                success: false,
                error: err instanceof Error ? err.message : String(err),
                relayReachable: false,
              },
            };
          }
        }),
    );

    // Find first successful registration
    const successfulResult = results.find((r) => r.result.success);
    if (successfulResult) {
      return {
        success: true,
        data: { registration: successfulResult.result.registration },
        relayUsed: successfulResult.url,
        degradedMode: false,
        relaysAttempted: results.map((r) => r.url),
      };
    }

    // Return error from first relay
    return {
      success: false,
      error: results[0]?.result.error ?? "No relays available",
      relayUsed: null,
      degradedMode: false,
      relaysAttempted: results.map((r) => r.url),
    };
  }

  /**
   * Update container registration
   */
  async updateRegistration(
    updates: { callbackUrl?: string | null; encryptionPublicKey?: string | null },
    authHeaders: { authorization: string; containerId: string },
  ): Promise<MultiRelayResult<Record<string, never>>> {
    // Update on all healthy relays
    const results = await Promise.all(
      this.config.urls
        .filter((url) => this.circuitBreaker.isAvailable(url))
        .map(async (url) => {
          const client = this.clients.get(url)!;
          const startTime = Date.now();
          try {
            const result = await client.updateRegistration(updates, authHeaders);
            const latencyMs = Date.now() - startTime;
            if (result.relayReachable) {
              this.circuitBreaker.recordSuccess(url, latencyMs);
            } else {
              this.circuitBreaker.recordFailure(url);
            }
            return { url, result };
          } catch (err) {
            this.circuitBreaker.recordFailure(url);
            return {
              url,
              result: {
                success: false,
                error: err instanceof Error ? err.message : String(err),
                relayReachable: false,
              },
            };
          }
        }),
    );

    const successfulResult = results.find((r) => r.result.success);
    if (successfulResult) {
      return {
        success: true,
        data: {},
        relayUsed: successfulResult.url,
        degradedMode: false,
        relaysAttempted: results.map((r) => r.url),
      };
    }

    return {
      success: false,
      error: results[0]?.result.error ?? "No relays available",
      relayUsed: null,
      degradedMode: false,
      relaysAttempted: results.map((r) => r.url),
    };
  }

  /**
   * Get current container's registration
   */
  async getRegistration(authHeaders: {
    authorization: string;
    containerId: string;
  }): Promise<MultiRelayResult<{ registration?: ContainerRegistration }>> {
    return this.executeWithFailover(
      async (client) => client.getRegistration(authHeaders),
      "getRegistration",
      (result) => result.success,
    );
  }

  /**
   * Unregister a container from all relays
   */
  async unregister(authHeaders: {
    authorization: string;
    containerId: string;
  }): Promise<MultiRelayResult<Record<string, never>>> {
    // Unregister from all relays
    const results = await Promise.all(
      this.config.urls.map(async (url) => {
        const client = this.clients.get(url)!;
        const startTime = Date.now();
        try {
          const result = await client.unregister(authHeaders);
          const latencyMs = Date.now() - startTime;
          if (result.relayReachable) {
            this.circuitBreaker.recordSuccess(url, latencyMs);
          } else {
            this.circuitBreaker.recordFailure(url);
          }
          return { url, result };
        } catch (err) {
          this.circuitBreaker.recordFailure(url);
          return {
            url,
            result: {
              success: false,
              error: err instanceof Error ? err.message : String(err),
              relayReachable: false,
            },
          };
        }
      }),
    );

    const successfulResult = results.find((r) => r.result.success);
    if (successfulResult) {
      return {
        success: true,
        data: {},
        relayUsed: successfulResult.url,
        degradedMode: false,
        relaysAttempted: results.map((r) => r.url),
      };
    }

    return {
      success: false,
      error: results[0]?.result.error ?? "No relays available",
      relayUsed: null,
      degradedMode: false,
      relaysAttempted: results.map((r) => r.url),
    };
  }

  /**
   * Look up a container by public key
   */
  async lookupByPublicKey(
    publicKey: string,
  ): Promise<MultiRelayResult<{ container?: ContainerLookupResult }>> {
    return this.executeWithFailover(
      async (client) => client.lookupByPublicKey(publicKey),
      "lookupByPublicKey",
      (result) => result.success,
    );
  }

  /**
   * Send an encrypted message with capability verification
   */
  async sendMessage(
    params: SendMessageParams,
    authHeaders: { authorization: string; containerId: string },
  ): Promise<MultiRelayResult<Omit<SendMessageResult, "relayReachable" | "error">>> {
    return this.executeWithFailover(
      async (client) => client.sendMessage(params, authHeaders),
      "sendMessage",
      (result) => result.success,
    );
  }

  /**
   * Send a simple encrypted message without capability verification
   */
  async sendSimpleMessage(
    targetContainerId: string,
    payload: string,
    authHeaders: { authorization: string; containerId: string },
  ): Promise<MultiRelayResult<Omit<SendMessageResult, "relayReachable" | "error">>> {
    return this.executeWithFailover(
      async (client) => client.sendSimpleMessage(targetContainerId, payload, authHeaders),
      "sendSimpleMessage",
      (result) => result.success,
    );
  }

  /**
   * Get pending messages
   */
  async getPendingMessages(
    authHeaders: { authorization: string; containerId: string },
    options?: { limit?: number; acknowledgeIds?: string[] },
  ): Promise<
    MultiRelayResult<{
      messages?: PendingMessage[];
      count?: number;
    }>
  > {
    return this.executeWithFailover(
      async (client) => client.getPendingMessages(authHeaders, options),
      "getPendingMessages",
      (result) => result.success,
    );
  }

  /**
   * Acknowledge messages
   */
  async acknowledgeMessages(
    messageIds: string[],
    authHeaders: { authorization: string; containerId: string },
  ): Promise<MultiRelayResult<{ acknowledged?: number }>> {
    return this.executeWithFailover(
      async (client) => client.acknowledgeMessages(messageIds, authHeaders),
      "acknowledgeMessages",
      (result) => result.success,
    );
  }

  /**
   * Store a cached snapshot on the relay
   */
  async storeSnapshot(snapshot: {
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
  }): Promise<MultiRelayResult<Record<string, never>>> {
    // Store on all healthy relays for redundancy
    const results = await Promise.all(
      this.config.urls
        .filter((url) => this.circuitBreaker.isAvailable(url))
        .map(async (url) => {
          const client = this.clients.get(url)!;
          const startTime = Date.now();
          try {
            const result = await client.storeSnapshot(snapshot);
            const latencyMs = Date.now() - startTime;
            if (result.relayReachable) {
              this.circuitBreaker.recordSuccess(url, latencyMs);
            } else {
              this.circuitBreaker.recordFailure(url);
            }
            return { url, result };
          } catch (err) {
            this.circuitBreaker.recordFailure(url);
            return {
              url,
              result: {
                success: false,
                error: err instanceof Error ? err.message : String(err),
                relayReachable: false,
              },
            };
          }
        }),
    );

    const successfulResult = results.find((r) => r.result.success);
    if (successfulResult) {
      return {
        success: true,
        data: {},
        relayUsed: successfulResult.url,
        degradedMode: false,
        relaysAttempted: results.map((r) => r.url),
      };
    }

    return {
      success: false,
      error: results[0]?.result.error ?? "No relays available",
      relayUsed: null,
      degradedMode: false,
      relaysAttempted: results.map((r) => r.url),
    };
  }

  /**
   * Get a cached snapshot from the relay
   */
  async getSnapshot(capabilityId: string): Promise<
    MultiRelayResult<{
      snapshot?: {
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
      };
    }>
  > {
    return this.executeWithFailover(
      async (client) => client.getSnapshot(capabilityId),
      "getSnapshot",
      (result) => result.success,
    );
  }

  /**
   * Delete a cached snapshot
   */
  async deleteSnapshot(capabilityId: string): Promise<MultiRelayResult<Record<string, never>>> {
    // Delete from all relays
    const results = await Promise.all(
      this.config.urls.map(async (url) => {
        const client = this.clients.get(url)!;
        const startTime = Date.now();
        try {
          const result = await client.deleteSnapshot(capabilityId);
          const latencyMs = Date.now() - startTime;
          if (result.relayReachable) {
            this.circuitBreaker.recordSuccess(url, latencyMs);
          } else {
            this.circuitBreaker.recordFailure(url);
          }
          return { url, result };
        } catch (err) {
          this.circuitBreaker.recordFailure(url);
          return {
            url,
            result: {
              success: false,
              error: err instanceof Error ? err.message : String(err),
              relayReachable: false,
            },
          };
        }
      }),
    );

    const successfulResult = results.find((r) => r.result.success);
    if (successfulResult) {
      return {
        success: true,
        data: {},
        relayUsed: successfulResult.url,
        degradedMode: false,
        relaysAttempted: results.map((r) => r.url),
      };
    }

    return {
      success: false,
      error: results[0]?.result.error ?? "No relays available",
      relayUsed: null,
      degradedMode: false,
      relaysAttempted: results.map((r) => r.url),
    };
  }

  /**
   * List available snapshots for a recipient
   */
  async listSnapshots(params: { recipientPublicKey: string; privateKeyPem: string }): Promise<
    MultiRelayResult<{
      snapshots?: Array<{
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
      }>;
    }>
  > {
    return this.executeWithFailover(
      async (client) => client.listSnapshots(params),
      "listSnapshots",
      (result) => result.success,
    );
  }

  /**
   * Force reset circuit breaker for a specific relay (for testing/recovery)
   */
  resetCircuitBreaker(url: string): void {
    this.circuitBreaker.resetCircuit(url);
  }

  /**
   * Force reset all circuit breakers (for testing/recovery)
   */
  resetAllCircuitBreakers(): void {
    for (const url of this.config.urls) {
      this.circuitBreaker.resetCircuit(url);
    }
  }

  /**
   * Get configuration
   */
  getConfig(): Readonly<Required<MultiRelayConfig>> {
    return { ...this.config };
  }

  /**
   * Dispose the client (stop health checks)
   */
  dispose(): void {
    this.stopHealthChecks();
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Singleton Management
// ─────────────────────────────────────────────────────────────────────────────

let multiRelayClientInstance: MultiRelayClient | null = null;

/**
 * Get or create the multi-relay client singleton
 */
export function getMultiRelayClient(config?: MultiRelayConfig): MultiRelayClient {
  if (!multiRelayClientInstance || config) {
    if (multiRelayClientInstance) {
      multiRelayClientInstance.dispose();
    }
    multiRelayClientInstance = new MultiRelayClient(
      config ?? {
        urls: ["http://localhost:18790"],
        strategy: "primary",
      },
    );
  }
  return multiRelayClientInstance;
}

/**
 * Reset the multi-relay client singleton (for testing)
 */
export function resetMultiRelayClient(): void {
  if (multiRelayClientInstance) {
    multiRelayClientInstance.dispose();
    multiRelayClientInstance = null;
  }
}
