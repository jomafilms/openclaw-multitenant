/**
 * Tests for Multi-Relay Client with Failover Support
 *
 * Tests failover scenarios including:
 * - Primary relay failure with fallback to secondary
 * - Circuit breaker behavior
 * - Selection strategies (primary, round-robin, latency)
 * - Graceful degradation when all relays fail
 * - Health check functionality
 */

import { generateKeyPairSync, sign as cryptoSign, createPrivateKey, randomBytes } from "crypto";
import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import {
  MultiRelayClient,
  type MultiRelayConfig,
  type RelayHealth,
  getMultiRelayClient,
  resetMultiRelayClient,
} from "./multi-relay-client.js";

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

// Ed25519 SPKI prefix for DER-encoded public keys
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/**
 * Generate an Ed25519 keypair for testing
 */
function generateTestKeypair(): {
  publicKey: string;
  privateKeyPem: string;
} {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const spkiDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const rawPublicKey = spkiDer.subarray(ED25519_SPKI_PREFIX.length);

  return {
    publicKey: rawPublicKey.toString("base64"),
    privateKeyPem,
  };
}

describe("MultiRelayClient", () => {
  const relay1 = "http://relay1.example.com";
  const relay2 = "http://relay2.example.com";
  const relay3 = "http://relay3.example.com";

  beforeEach(() => {
    mockFetch.mockReset();
    resetMultiRelayClient();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("Configuration", () => {
    it("should require at least one relay URL", () => {
      expect(() => {
        new MultiRelayClient({ urls: [], strategy: "primary" });
      }).toThrow("At least one relay URL is required");
    });

    it("should normalize relay URLs by removing trailing slashes", () => {
      const client = new MultiRelayClient({
        urls: ["http://relay1.example.com/", "http://relay2.example.com/"],
        strategy: "primary",
      });

      const config = client.getConfig();
      expect(config.urls).toEqual(["http://relay1.example.com", "http://relay2.example.com"]);
    });

    it("should use default values for optional config", () => {
      const client = new MultiRelayClient({
        urls: [relay1],
        strategy: "primary",
      });

      const config = client.getConfig();
      expect(config.healthCheckIntervalMs).toBe(30000);
      expect(config.circuitBreakerThreshold).toBe(3);
      expect(config.circuitBreakerResetMs).toBe(60000);
      expect(config.timeout).toBe(5000);
      expect(config.retriesPerRelay).toBe(1);
      expect(config.gracefulDegradation).toBe(true);
    });
  });

  describe("Selection Strategy - Primary", () => {
    it("should always prefer primary relay when healthy", async () => {
      const client = new MultiRelayClient({
        urls: [relay1, relay2],
        strategy: "primary",
      });

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          revoked: false,
        }),
      });

      // Multiple calls should all go to primary
      for (let i = 0; i < 5; i++) {
        await client.checkRevocation("cap-123");
      }

      // All calls should go to relay1
      const calls = mockFetch.mock.calls;
      expect(calls.every((call) => (call[0] as string).startsWith(relay1))).toBe(true);
    });

    it("should fallback to secondary when primary fails", async () => {
      const client = new MultiRelayClient({
        urls: [relay1, relay2],
        strategy: "primary",
        circuitBreakerThreshold: 1, // Open circuit after 1 failure
      });

      // Primary fails
      mockFetch.mockImplementation((url: string) => {
        if (url.startsWith(relay1)) {
          return Promise.reject(new Error("Connection refused"));
        }
        return Promise.resolve({
          ok: true,
          json: async () => ({ revoked: false }),
        });
      });

      const result = await client.checkRevocation("cap-123");

      expect(result.success).toBe(true);
      expect(result.relayUsed).toBe(relay2);
      expect(result.relaysAttempted).toContain(relay1);
      expect(result.relaysAttempted).toContain(relay2);
    });
  });

  describe("Selection Strategy - Round Robin", () => {
    it("should cycle through relays", async () => {
      const client = new MultiRelayClient({
        urls: [relay1, relay2, relay3],
        strategy: "round-robin",
      });

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ revoked: false }),
      });

      const usedRelays: string[] = [];
      for (let i = 0; i < 6; i++) {
        const result = await client.checkRevocation(`cap-${i}`);
        usedRelays.push(result.relayUsed!);
      }

      // Should cycle through all relays twice
      expect(usedRelays[0]).toBe(relay1);
      expect(usedRelays[1]).toBe(relay2);
      expect(usedRelays[2]).toBe(relay3);
      expect(usedRelays[3]).toBe(relay1);
      expect(usedRelays[4]).toBe(relay2);
      expect(usedRelays[5]).toBe(relay3);
    });

    it("should skip unhealthy relays in rotation", async () => {
      const client = new MultiRelayClient({
        urls: [relay1, relay2, relay3],
        strategy: "round-robin",
        circuitBreakerThreshold: 1,
      });

      // relay2 is unhealthy
      mockFetch.mockImplementation((url: string) => {
        if (url.startsWith(relay2)) {
          return Promise.reject(new Error("Connection refused"));
        }
        return Promise.resolve({
          ok: true,
          json: async () => ({ revoked: false }),
        });
      });

      // First call - round-robin starts at relay1, succeeds
      const result1 = await client.checkRevocation("cap-1");
      expect(result1.relayUsed).toBe(relay1);

      // Second call - round-robin moves to relay2, fails, falls through to relay3
      // The round-robin index advances, so next available after relay2 would be relay3
      const result2 = await client.checkRevocation("cap-2");
      // relay2 fails and falls back, circuit opens for relay2
      expect(result2.relaysAttempted).toContain(relay2);
      expect(result2.success).toBe(true);

      // Third call - relay2 circuit is now open, round-robin should skip it
      // Available relays are [relay1, relay3], round-robin continues
      const result3 = await client.checkRevocation("cap-3");
      expect(result3.relaysAttempted).not.toContain(relay2);
      expect(result3.success).toBe(true);
    });
  });

  describe("Selection Strategy - Latency", () => {
    it("should prefer lowest latency relay", async () => {
      const client = new MultiRelayClient({
        urls: [relay1, relay2, relay3],
        strategy: "latency",
      });

      // Set up different latencies through health checks
      let healthCheckCount = 0;
      mockFetch.mockImplementation(async (url: string) => {
        healthCheckCount++;
        // Simulate different latencies for health checks
        if (url.includes("/health")) {
          if (url.startsWith(relay1)) {
            await new Promise((r) => setTimeout(r, 100)); // 100ms
          } else if (url.startsWith(relay2)) {
            await new Promise((r) => setTimeout(r, 10)); // 10ms - fastest
          } else if (url.startsWith(relay3)) {
            await new Promise((r) => setTimeout(r, 50)); // 50ms
          }
        }
        return {
          ok: true,
          json: async () => ({ revoked: false }),
        };
      });

      // Run health checks to establish latency
      await client.runHealthChecks();

      // Reset mock to just return success
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ revoked: false }),
      });

      // Should prefer relay2 (lowest latency)
      const result = await client.checkRevocation("cap-123");
      expect(result.relayUsed).toBe(relay2);
    });
  });

  describe("Circuit Breaker", () => {
    it("should open circuit after consecutive failures", async () => {
      const client = new MultiRelayClient({
        urls: [relay1, relay2],
        strategy: "primary",
        circuitBreakerThreshold: 3,
      });

      // relay1 always fails
      mockFetch.mockImplementation((url: string) => {
        if (url.startsWith(relay1)) {
          return Promise.reject(new Error("Connection refused"));
        }
        return Promise.resolve({
          ok: true,
          json: async () => ({ revoked: false }),
        });
      });

      // First 3 calls will try relay1 first, then fallback
      for (let i = 0; i < 3; i++) {
        await client.checkRevocation(`cap-${i}`);
      }

      // After 3 failures, circuit should be open for relay1
      const health = client.getHealthStatus();
      const relay1Health = health.find((h) => h.url === relay1);
      expect(relay1Health?.circuitOpen).toBe(true);
      expect(relay1Health?.consecutiveFailures).toBe(3);

      // Reset mock call count
      mockFetch.mockClear();

      // Next call should skip relay1 entirely
      const result = await client.checkRevocation("cap-4");
      expect(result.relayUsed).toBe(relay2);

      // relay1 should not have been called
      const calls = mockFetch.mock.calls;
      expect(calls.some((call) => (call[0] as string).startsWith(relay1))).toBe(false);
    });

    it("should reset circuit after success", async () => {
      const client = new MultiRelayClient({
        urls: [relay1],
        strategy: "primary",
        circuitBreakerThreshold: 3,
      });

      // First, fail 2 times (not enough to open circuit)
      mockFetch.mockRejectedValue(new Error("Connection refused"));

      await client.checkRevocation("cap-1");
      await client.checkRevocation("cap-2");

      let health = client.getHealthStatus();
      expect(health[0].consecutiveFailures).toBe(2);
      expect(health[0].circuitOpen).toBe(false);

      // Now succeed
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ revoked: false }),
      });

      await client.checkRevocation("cap-3");

      health = client.getHealthStatus();
      expect(health[0].consecutiveFailures).toBe(0);
      expect(health[0].healthy).toBe(true);
    });

    it("should allow retry after reset period", async () => {
      vi.useFakeTimers();

      const client = new MultiRelayClient({
        urls: [relay1, relay2],
        strategy: "primary",
        circuitBreakerThreshold: 1,
        circuitBreakerResetMs: 1000, // 1 second reset
      });

      // relay1 fails initially
      mockFetch.mockImplementation((url: string) => {
        if (url.startsWith(relay1)) {
          return Promise.reject(new Error("Connection refused"));
        }
        return Promise.resolve({
          ok: true,
          json: async () => ({ revoked: false }),
        });
      });

      // This opens the circuit for relay1
      await client.checkRevocation("cap-1");

      let health = client.getHealthStatus();
      expect(health.find((h) => h.url === relay1)?.circuitOpen).toBe(true);

      // Advance time past reset period
      vi.advanceTimersByTime(1500);

      // Now relay1 is back up
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ revoked: false }),
      });

      // Should try relay1 again (half-open state)
      const result = await client.checkRevocation("cap-2");
      expect(result.relayUsed).toBe(relay1);

      // Circuit should be closed now
      health = client.getHealthStatus();
      expect(health.find((h) => h.url === relay1)?.circuitOpen).toBe(false);

      vi.useRealTimers();
    });

    it("should support manual circuit reset", () => {
      const client = new MultiRelayClient({
        urls: [relay1, relay2],
        strategy: "primary",
        circuitBreakerThreshold: 1,
      });

      // Manually trigger failure state
      mockFetch.mockRejectedValue(new Error("fail"));

      // This will fail and trigger circuit open
      client.checkRevocation("cap-1").catch(() => {});

      // Force reset
      client.resetCircuitBreaker(relay1);

      const health = client.getHealthStatus();
      expect(health.find((h) => h.url === relay1)?.circuitOpen).toBe(false);
    });
  });

  describe("Graceful Degradation", () => {
    it("should return error when all relays fail and degradation disabled", async () => {
      const client = new MultiRelayClient({
        urls: [relay1, relay2],
        strategy: "primary",
        circuitBreakerThreshold: 1,
        gracefulDegradation: false,
      });

      mockFetch.mockRejectedValue(new Error("Connection refused"));

      const result = await client.checkRevocation("cap-123");

      expect(result.success).toBe(false);
      expect(result.relayUsed).toBeNull();
      expect(result.relaysAttempted).toContain(relay1);
      expect(result.relaysAttempted).toContain(relay2);
      expect(result.error).toContain("Connection refused");
    });

    it("should attempt all relays when degradation enabled even with open circuits", async () => {
      const client = new MultiRelayClient({
        urls: [relay1, relay2],
        strategy: "primary",
        circuitBreakerThreshold: 1,
        gracefulDegradation: true,
      });

      // Both fail initially
      mockFetch.mockRejectedValue(new Error("Connection refused"));

      // Open circuits for both
      await client.checkRevocation("cap-1");
      await client.checkRevocation("cap-2");

      // Reset mock - relay2 now works
      mockFetch.mockImplementation((url: string) => {
        if (url.startsWith(relay1)) {
          return Promise.reject(new Error("Still down"));
        }
        return Promise.resolve({
          ok: true,
          json: async () => ({ revoked: false }),
        });
      });

      // With graceful degradation, should still try relays
      const result = await client.checkRevocation("cap-3");
      expect(result.success).toBe(true);
      expect(result.relayUsed).toBe(relay2);
    });
  });

  describe("Health Checks", () => {
    it("should update health status after health check", async () => {
      const client = new MultiRelayClient({
        urls: [relay1, relay2],
        strategy: "primary",
      });

      mockFetch.mockResolvedValue({ ok: true });

      await client.runHealthChecks();

      const health = client.getHealthStatus();
      expect(health).toHaveLength(2);
      expect(health[0].healthy).toBe(true);
      expect(health[0].lastChecked).not.toBeNull();
      expect(health[0].latencyMs).not.toBeNull();
    });

    it("should detect unhealthy relays", async () => {
      const client = new MultiRelayClient({
        urls: [relay1, relay2],
        strategy: "primary",
      });

      mockFetch.mockImplementation((url: string) => {
        if (url.startsWith(relay1)) {
          return Promise.reject(new Error("Connection refused"));
        }
        return Promise.resolve({ ok: true });
      });

      await client.runHealthChecks();

      const health = client.getHealthStatus();
      const relay1Health = health.find((h) => h.url === relay1);
      const relay2Health = health.find((h) => h.url === relay2);

      expect(relay1Health?.healthy).toBe(true); // Not unhealthy yet (1 failure < threshold)
      expect(relay1Health?.consecutiveFailures).toBe(1);
      expect(relay2Health?.healthy).toBe(true);
    });

    it("should return available relays", async () => {
      const client = new MultiRelayClient({
        urls: [relay1, relay2, relay3],
        strategy: "primary",
        circuitBreakerThreshold: 1,
      });

      // relay2 fails
      mockFetch.mockImplementation((url: string) => {
        if (url.startsWith(relay2)) {
          return Promise.reject(new Error("Down"));
        }
        return Promise.resolve({ ok: true });
      });

      await client.runHealthChecks();

      const available = client.getAvailableRelays();
      expect(available).toContain(relay1);
      expect(available).not.toContain(relay2);
      expect(available).toContain(relay3);
    });

    it("should start and stop periodic health checks", async () => {
      vi.useFakeTimers();

      const client = new MultiRelayClient({
        urls: [relay1],
        strategy: "primary",
        healthCheckIntervalMs: 100,
      });

      mockFetch.mockResolvedValue({ ok: true });

      client.startHealthChecks();

      // Initial check runs immediately
      expect(mockFetch).toHaveBeenCalledTimes(1);

      // Advance time and check periodic execution
      vi.advanceTimersByTime(100);
      expect(mockFetch).toHaveBeenCalledTimes(2);

      vi.advanceTimersByTime(100);
      expect(mockFetch).toHaveBeenCalledTimes(3);

      client.stopHealthChecks();

      vi.advanceTimersByTime(200);
      // No more calls after stopping
      expect(mockFetch).toHaveBeenCalledTimes(3);

      vi.useRealTimers();
    });
  });

  describe("Multi-Relay Operations", () => {
    it("should register container on all healthy relays", async () => {
      const client = new MultiRelayClient({
        urls: [relay1, relay2, relay3],
        strategy: "primary",
        circuitBreakerThreshold: 1,
      });

      const keypair = generateTestKeypair();
      const containerId = "test-container-123";

      // relay2 is down
      mockFetch.mockImplementation((url: string) => {
        if (url.startsWith(relay2)) {
          return Promise.reject(new Error("Down"));
        }
        return Promise.resolve({
          ok: true,
          json: async () => ({
            success: true,
            containerId,
            publicKeyHash: "hash123",
            hasCallback: true,
          }),
        });
      });

      const result = await client.registerContainer(
        {
          publicKey: keypair.publicKey,
          callbackUrl: "https://callback.example.com",
          privateKeyPem: keypair.privateKeyPem,
        },
        {
          authorization: "Bearer token",
          containerId,
        },
      );

      expect(result.success).toBe(true);
      expect(result.data?.registration?.containerId).toBe(containerId);
      // Should have attempted relay1 and relay3 (relay2 skipped due to circuit)
      expect(result.relaysAttempted.length).toBeGreaterThanOrEqual(2);
    });

    it("should unregister container from all relays", async () => {
      const client = new MultiRelayClient({
        urls: [relay1, relay2],
        strategy: "primary",
      });

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ success: true }),
      });

      const result = await client.unregister({
        authorization: "Bearer token",
        containerId: "container-123",
      });

      expect(result.success).toBe(true);
      // Should have called both relays
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it("should store snapshot on multiple relays for redundancy", async () => {
      const client = new MultiRelayClient({
        urls: [relay1, relay2],
        strategy: "primary",
      });

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ success: true }),
      });

      const snapshot = {
        capabilityId: "cap-123",
        encryptedData: "encrypted",
        ephemeralPublicKey: "key",
        nonce: "nonce",
        tag: "tag",
        signature: "sig",
        issuerPublicKey: "issuer",
        recipientPublicKey: "recipient",
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      };

      const result = await client.storeSnapshot(snapshot);

      expect(result.success).toBe(true);
      // Should store on both relays
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it("should delete snapshot from all relays", async () => {
      const client = new MultiRelayClient({
        urls: [relay1, relay2, relay3],
        strategy: "primary",
      });

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ success: true }),
      });

      const result = await client.deleteSnapshot("cap-123");

      expect(result.success).toBe(true);
      expect(mockFetch).toHaveBeenCalledTimes(3); // All relays
    });
  });

  describe("Message Operations with Failover", () => {
    it("should send message with failover on relay failure", async () => {
      const client = new MultiRelayClient({
        urls: [relay1, relay2],
        strategy: "primary",
        circuitBreakerThreshold: 1,
      });

      // relay1 fails, relay2 succeeds
      mockFetch.mockImplementation((url: string) => {
        if (url.startsWith(relay1)) {
          return Promise.reject(new Error("Connection refused"));
        }
        return Promise.resolve({
          ok: true,
          json: async () => ({
            messageId: "msg-123",
            status: "delivered",
            deliveryMethod: "websocket",
          }),
        });
      });

      const result = await client.sendMessage(
        {
          targetContainerId: "target-container",
          capabilityToken: "token",
          encryptedPayload: "payload",
        },
        {
          authorization: "Bearer token",
          containerId: "sender-container",
        },
      );

      expect(result.success).toBe(true);
      expect(result.relayUsed).toBe(relay2);
      expect(result.data?.messageId).toBe("msg-123");
    });

    it("should get pending messages with failover", async () => {
      const client = new MultiRelayClient({
        urls: [relay1, relay2],
        strategy: "round-robin",
      });

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          count: 2,
          messages: [
            {
              id: "msg-1",
              from: "container-a",
              payload: "p1",
              size: 100,
              timestamp: "2024-01-01T00:00:00Z",
            },
            {
              id: "msg-2",
              from: "container-b",
              payload: "p2",
              size: 200,
              timestamp: "2024-01-01T01:00:00Z",
            },
          ],
        }),
      });

      const result = await client.getPendingMessages(
        {
          authorization: "Bearer token",
          containerId: "my-container",
        },
        { limit: 10 },
      );

      expect(result.success).toBe(true);
      expect(result.data?.count).toBe(2);
      expect(result.data?.messages).toHaveLength(2);
    });

    it("should acknowledge messages", async () => {
      const client = new MultiRelayClient({
        urls: [relay1],
        strategy: "primary",
      });

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          acknowledged: 3,
          messageIds: ["msg-1", "msg-2", "msg-3"],
        }),
      });

      const result = await client.acknowledgeMessages(["msg-1", "msg-2", "msg-3"], {
        authorization: "Bearer token",
        containerId: "my-container",
      });

      expect(result.success).toBe(true);
      expect(result.data?.acknowledged).toBe(3);
    });
  });

  describe("Revocation Operations", () => {
    it("should notify revocation with failover", async () => {
      const keypair = generateTestKeypair();
      const client = new MultiRelayClient({
        urls: [relay1, relay2],
        strategy: "primary",
        circuitBreakerThreshold: 1,
      });

      // First relay fails
      mockFetch.mockImplementation((url: string) => {
        if (url.startsWith(relay1)) {
          return Promise.reject(new Error("Down"));
        }
        return Promise.resolve({
          ok: true,
          json: async () => ({ success: true }),
        });
      });

      const result = await client.notifyRevocation({
        capabilityId: "cap-123",
        publicKey: keypair.publicKey,
        privateKeyPem: keypair.privateKeyPem,
        reason: "User requested",
      });

      expect(result.success).toBe(true);
      expect(result.relayUsed).toBe(relay2);
    });

    it("should check revocations batch with failover", async () => {
      const client = new MultiRelayClient({
        urls: [relay1, relay2],
        strategy: "latency",
      });

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          results: {
            "cap-1": { revoked: false },
            "cap-2": { revoked: true, revokedAt: "2024-01-01T00:00:00Z" },
          },
        }),
      });

      const result = await client.checkRevocations(["cap-1", "cap-2"]);

      expect(result.success).toBe(true);
      expect(result.data?.results["cap-1"].revoked).toBe(false);
      expect(result.data?.results["cap-2"].revoked).toBe(true);
    });
  });

  describe("Container Lookup", () => {
    it("should lookup container by public key with failover", async () => {
      const client = new MultiRelayClient({
        urls: [relay1, relay2],
        strategy: "primary",
        circuitBreakerThreshold: 1,
      });

      // relay1 returns 404, relay2 finds it
      mockFetch.mockImplementation((url: string) => {
        if (url.startsWith(relay1)) {
          return Promise.resolve({
            ok: false,
            status: 404,
            json: async () => ({ error: "Container not found" }),
          });
        }
        return Promise.resolve({
          ok: true,
          json: async () => ({
            containerId: "container-123",
            publicKey: "pub-key",
            registeredAt: "2024-01-01T00:00:00Z",
          }),
        });
      });

      // First call goes to relay1, fails with 404
      const result = await client.lookupByPublicKey("pub-key");

      // Should have fallen through to relay2
      expect(result.success).toBe(true);
      expect(result.data?.container?.containerId).toBe("container-123");
    });
  });

  describe("Singleton Management", () => {
    it("should return same instance when config not changed", () => {
      const config: MultiRelayConfig = {
        urls: [relay1, relay2],
        strategy: "primary",
      };

      const client1 = getMultiRelayClient(config);
      const client2 = getMultiRelayClient();

      expect(client1).toBe(client2);
    });

    it("should create new instance when config provided", () => {
      const config1: MultiRelayConfig = {
        urls: [relay1],
        strategy: "primary",
      };
      const config2: MultiRelayConfig = {
        urls: [relay1, relay2],
        strategy: "round-robin",
      };

      const client1 = getMultiRelayClient(config1);
      const client2 = getMultiRelayClient(config2);

      expect(client1).not.toBe(client2);
    });

    it("should reset singleton", () => {
      const config: MultiRelayConfig = {
        urls: [relay1],
        strategy: "primary",
      };

      const client1 = getMultiRelayClient(config);
      resetMultiRelayClient();
      const client2 = getMultiRelayClient(config);

      expect(client1).not.toBe(client2);
    });
  });

  describe("Dispose", () => {
    it("should stop health checks on dispose", () => {
      vi.useFakeTimers();

      const client = new MultiRelayClient({
        urls: [relay1],
        strategy: "primary",
        healthCheckIntervalMs: 100,
      });

      mockFetch.mockResolvedValue({ ok: true });

      client.startHealthChecks();
      client.dispose();

      const callCountAfterDispose = mockFetch.mock.calls.length;

      vi.advanceTimersByTime(500);

      // No additional calls after dispose
      expect(mockFetch.mock.calls.length).toBe(callCountAfterDispose);

      vi.useRealTimers();
    });
  });
});
