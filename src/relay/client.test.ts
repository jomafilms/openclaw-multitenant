/**
 * Tests for Relay Client
 *
 * Tests the message relay flow including:
 * - Container registration
 * - Message forwarding with capability verification
 * - Container discovery by public key
 */

import { generateKeyPairSync, sign as cryptoSign, createPrivateKey, randomBytes } from "crypto";
import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import { RelayClient, type SendMessageParams, type RegisterContainerParams } from "./client.js";

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

  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

  // Extract raw 32-byte public key from SPKI encoding
  const spkiDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const rawPublicKey = spkiDer.subarray(ED25519_SPKI_PREFIX.length);

  return {
    publicKey: rawPublicKey.toString("base64"),
    privateKeyPem,
  };
}

/**
 * Generate a mock capability token
 */
function generateMockCapabilityToken(params: {
  issuerPublicKey: string;
  issuerPrivateKeyPem: string;
  subjectPublicKey: string;
  resource: string;
  scope: string[];
  expiresInSeconds: number;
}): string {
  const id = randomBytes(16).toString("hex");
  const now = Math.floor(Date.now() / 1000);
  const exp = now + params.expiresInSeconds;

  const claims = {
    v: 1,
    id,
    iss: params.issuerPublicKey,
    sub: params.subjectPublicKey,
    resource: params.resource,
    scope: params.scope,
    iat: now,
    exp,
  };

  const privateKey = createPrivateKey(params.issuerPrivateKeyPem);
  const signature = cryptoSign(null, Buffer.from(JSON.stringify(claims), "utf-8"), privateKey);
  const token = { ...claims, sig: signature.toString("base64") };

  return Buffer.from(JSON.stringify(token)).toString("base64url");
}

describe("RelayClient", () => {
  let client: RelayClient;
  const testRelayUrl = "http://localhost:18790";

  beforeEach(() => {
    client = new RelayClient({ relayUrl: testRelayUrl, timeout: 5000, retries: 1 });
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("Container Registration", () => {
    it("should register a container with public key and callback URL", async () => {
      const keypair = generateTestKeypair();
      const containerId = "550e8400-e29b-41d4-a716-446655440000";

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          success: true,
          containerId,
          publicKeyHash: "abc123",
          hasCallback: true,
        }),
      });

      const result = await client.registerContainer(
        {
          publicKey: keypair.publicKey,
          callbackUrl: "https://example.com/webhook",
          privateKeyPem: keypair.privateKeyPem,
        },
        {
          authorization: "Bearer test-token",
          containerId,
        },
      );

      expect(result.success).toBe(true);
      expect(result.registration?.containerId).toBe(containerId);
      expect(result.registration?.publicKey).toBe(keypair.publicKey);
      expect(result.registration?.hasCallback).toBe(true);
      expect(result.relayReachable).toBe(true);

      // Verify the request was made correctly
      expect(mockFetch).toHaveBeenCalledWith(
        `${testRelayUrl}/relay/registry/register`,
        expect.objectContaining({
          method: "POST",
          headers: expect.objectContaining({
            "Content-Type": "application/json",
            Authorization: "Bearer test-token",
            "X-Container-Id": containerId,
          }),
        }),
      );

      // Verify the body contains required fields
      const callArgs = mockFetch.mock.calls[0] as unknown[];
      const requestInit = callArgs[1] as RequestInit;
      const body = JSON.parse(requestInit.body as string);
      expect(body.publicKey).toBe(keypair.publicKey);
      expect(body.callbackUrl).toBe("https://example.com/webhook");
      expect(body.challenge).toBeDefined();
      expect(body.signature).toBeDefined();
    });

    it("should handle registration without callback URL", async () => {
      const keypair = generateTestKeypair();
      const containerId = "550e8400-e29b-41d4-a716-446655440001";

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          success: true,
          containerId,
          publicKeyHash: "def456",
          hasCallback: false,
        }),
      });

      const result = await client.registerContainer(
        {
          publicKey: keypair.publicKey,
          privateKeyPem: keypair.privateKeyPem,
        },
        {
          authorization: "Bearer test-token",
          containerId,
        },
      );

      expect(result.success).toBe(true);
      expect(result.registration?.hasCallback).toBe(false);
    });

    it("should handle registration failure", async () => {
      const keypair = generateTestKeypair();

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 403,
        json: async () => ({
          success: false,
          error: "Public key ownership verification failed",
        }),
      });

      const result = await client.registerContainer(
        {
          publicKey: keypair.publicKey,
          privateKeyPem: keypair.privateKeyPem,
        },
        {
          authorization: "Bearer test-token",
          containerId: "test-id",
        },
      );

      expect(result.success).toBe(false);
      expect(result.error).toBe("Public key ownership verification failed");
      expect(result.relayReachable).toBe(true);
    });

    it("should handle network failure with retries", async () => {
      const keypair = generateTestKeypair();

      mockFetch.mockRejectedValue(new Error("Network error"));

      const result = await client.registerContainer(
        {
          publicKey: keypair.publicKey,
          privateKeyPem: keypair.privateKeyPem,
        },
        {
          authorization: "Bearer test-token",
          containerId: "test-id",
        },
      );

      expect(result.success).toBe(false);
      expect(result.error).toBe("Network error");
      expect(result.relayReachable).toBe(false);

      // Should have retried
      expect(mockFetch).toHaveBeenCalledTimes(2); // Initial + 1 retry
    });
  });

  describe("Container Lookup", () => {
    it("should lookup container by public key", async () => {
      const keypair = generateTestKeypair();
      const containerId = "550e8400-e29b-41d4-a716-446655440002";

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          containerId,
          publicKey: keypair.publicKey,
          encryptionPublicKey: "enc-key-base64",
          registeredAt: "2024-01-01T00:00:00Z",
        }),
      });

      const result = await client.lookupByPublicKey(keypair.publicKey);

      expect(result.success).toBe(true);
      expect(result.container?.containerId).toBe(containerId);
      expect(result.container?.publicKey).toBe(keypair.publicKey);
      expect(result.relayReachable).toBe(true);
    });

    it("should handle container not found", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        json: async () => ({ error: "Container not found" }),
      });

      const result = await client.lookupByPublicKey("nonexistent-key");

      expect(result.success).toBe(false);
      expect(result.error).toBe("Container not found");
    });
  });

  describe("Message Forwarding with Capability", () => {
    it("should send message with capability token", async () => {
      const issuerKeypair = generateTestKeypair();
      const recipientKeypair = generateTestKeypair();
      const senderContainerId = "550e8400-e29b-41d4-a716-446655440003";
      const targetContainerId = "550e8400-e29b-41d4-a716-446655440004";

      const capabilityToken = generateMockCapabilityToken({
        issuerPublicKey: issuerKeypair.publicKey,
        issuerPrivateKeyPem: issuerKeypair.privateKeyPem,
        subjectPublicKey: recipientKeypair.publicKey,
        resource: "google",
        scope: ["read", "list"],
        expiresInSeconds: 3600,
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          messageId: "msg-123",
          capabilityId: "cap-456",
          status: "delivered",
          deliveryMethod: "websocket",
          wakeTriggered: false,
        }),
      });

      const result = await client.sendMessage(
        {
          targetContainerId,
          capabilityToken,
          encryptedPayload: "encrypted-data-base64",
          nonce: "nonce-base64",
        },
        {
          authorization: "Bearer test-token",
          containerId: senderContainerId,
        },
      );

      expect(result.success).toBe(true);
      expect(result.messageId).toBe("msg-123");
      expect(result.capabilityId).toBe("cap-456");
      expect(result.status).toBe("delivered");
      expect(result.deliveryMethod).toBe("websocket");
      expect(result.relayReachable).toBe(true);

      // Verify the request
      expect(mockFetch).toHaveBeenCalledWith(
        `${testRelayUrl}/relay/forward`,
        expect.objectContaining({
          method: "POST",
          headers: expect.objectContaining({
            "Content-Type": "application/json",
            Authorization: "Bearer test-token",
            "X-Container-Id": senderContainerId,
          }),
        }),
      );
    });

    it("should handle invalid capability token", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 403,
        json: async () => ({
          error: "Invalid or expired capability token",
        }),
      });

      const result = await client.sendMessage(
        {
          targetContainerId: "target-id",
          capabilityToken: "invalid-token",
          encryptedPayload: "encrypted-data",
        },
        {
          authorization: "Bearer test-token",
          containerId: "sender-id",
        },
      );

      expect(result.success).toBe(false);
      expect(result.error).toBe("Invalid or expired capability token");
      expect(result.relayReachable).toBe(true);

      // Should not retry on 4xx errors
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it("should queue message when target is offline", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          messageId: "msg-789",
          capabilityId: "cap-012",
          status: "queued",
          deliveryMethod: "pending",
          wakeTriggered: true,
        }),
      });

      const result = await client.sendMessage(
        {
          targetContainerId: "offline-container",
          capabilityToken: "valid-token",
          encryptedPayload: "encrypted-data",
        },
        {
          authorization: "Bearer test-token",
          containerId: "sender-id",
        },
      );

      expect(result.success).toBe(true);
      expect(result.status).toBe("queued");
      expect(result.wakeTriggered).toBe(true);
    });
  });

  describe("Simple Message Sending", () => {
    it("should send simple message without capability verification", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          messageId: "msg-simple-123",
          status: "delivered",
          deliveryMethod: "websocket",
        }),
      });

      const result = await client.sendSimpleMessage(
        "target-container-id",
        "encrypted-payload-content",
        {
          authorization: "Bearer test-token",
          containerId: "sender-id",
        },
      );

      expect(result.success).toBe(true);
      expect(result.messageId).toBe("msg-simple-123");
      expect(result.status).toBe("delivered");

      // Verify it uses the /send endpoint
      expect(mockFetch).toHaveBeenCalledWith(`${testRelayUrl}/relay/send`, expect.anything());
    });
  });

  describe("Pending Messages", () => {
    it("should retrieve pending messages", async () => {
      const mockMessages = [
        {
          id: "msg-1",
          from: "container-a",
          payload: "encrypted-payload-1",
          size: 100,
          timestamp: "2024-01-01T00:00:00Z",
        },
        {
          id: "msg-2",
          from: "container-b",
          payload: "encrypted-payload-2",
          size: 200,
          timestamp: "2024-01-01T01:00:00Z",
        },
      ];

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          count: 2,
          messages: mockMessages,
        }),
      });

      const result = await client.getPendingMessages(
        {
          authorization: "Bearer test-token",
          containerId: "my-container",
        },
        { limit: 50 },
      );

      expect(result.success).toBe(true);
      expect(result.count).toBe(2);
      expect(result.messages).toHaveLength(2);
      expect(result.messages![0].id).toBe("msg-1");
    });

    it("should acknowledge messages while retrieving", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          count: 0,
          messages: [],
        }),
      });

      await client.getPendingMessages(
        {
          authorization: "Bearer test-token",
          containerId: "my-container",
        },
        { acknowledgeIds: ["msg-1", "msg-2"] },
      );

      // Verify ack IDs are in query params
      const callArgs = mockFetch.mock.calls[0] as unknown[];
      const url = callArgs[0] as string;
      expect(url).toContain("ack=msg-1%2Cmsg-2");
    });
  });

  describe("Message Acknowledgement", () => {
    it("should acknowledge messages", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          acknowledged: 3,
          messageIds: ["msg-1", "msg-2", "msg-3"],
        }),
      });

      const result = await client.acknowledgeMessages(["msg-1", "msg-2", "msg-3"], {
        authorization: "Bearer test-token",
        containerId: "my-container",
      });

      expect(result.success).toBe(true);
      expect(result.acknowledged).toBe(3);

      // Verify the request
      expect(mockFetch).toHaveBeenCalledWith(
        `${testRelayUrl}/relay/messages/ack`,
        expect.objectContaining({
          method: "POST",
        }),
      );
    });
  });

  describe("Registration Management", () => {
    it("should get current registration", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          containerId: "my-container",
          publicKey: "my-public-key",
          publicKeyHash: "hash123",
          hasCallback: true,
          registeredAt: "2024-01-01T00:00:00Z",
          updatedAt: "2024-01-02T00:00:00Z",
        }),
      });

      const result = await client.getRegistration({
        authorization: "Bearer test-token",
        containerId: "my-container",
      });

      expect(result.success).toBe(true);
      expect(result.registration?.containerId).toBe("my-container");
      expect(result.registration?.hasCallback).toBe(true);
    });

    it("should update registration callback URL", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ success: true }),
      });

      const result = await client.updateRegistration(
        { callbackUrl: "https://new-callback.example.com/webhook" },
        {
          authorization: "Bearer test-token",
          containerId: "my-container",
        },
      );

      expect(result.success).toBe(true);

      // Verify the request
      expect(mockFetch).toHaveBeenCalledWith(
        `${testRelayUrl}/relay/registry/update`,
        expect.objectContaining({
          method: "PATCH",
        }),
      );
    });

    it("should unregister container", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ success: true }),
      });

      const result = await client.unregister({
        authorization: "Bearer test-token",
        containerId: "my-container",
      });

      expect(result.success).toBe(true);

      // Verify the request
      expect(mockFetch).toHaveBeenCalledWith(
        `${testRelayUrl}/relay/registry`,
        expect.objectContaining({
          method: "DELETE",
        }),
      );
    });
  });
});
