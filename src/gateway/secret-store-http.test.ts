/**
 * Tests for Secret Store HTTP Handler
 *
 * Tests the HTTP endpoints for vault management and secret operations.
 * Uses mock functions to avoid SecretStore initialization overhead.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import type { ResolvedGatewayAuth } from "./auth.js";
import { handleSecretStoreHttpRequest } from "./secret-store-http.js";

// Mock dependencies
vi.mock("./auth.js", () => ({
  authorizeGatewayConnect: vi.fn().mockResolvedValue({ ok: true }),
}));

vi.mock("../config/config.js", () => ({
  loadConfig: vi.fn().mockReturnValue({ gateway: { trustedProxies: [] } }),
}));

// Mock the secret-api functions
const mockVaultStatus = vi.fn();
const mockGenerateChallenge = vi.fn();
const mockVerifyChallenge = vi.fn();
const mockLockVault = vi.fn();
const mockExtendSession = vi.fn();
const mockListIntegrations = vi.fn();
const mockGetIntegration = vi.fn();
const mockSetIntegration = vi.fn();
const mockListCapabilities = vi.fn();
const mockIssueCapability = vi.fn();
const mockRevokeCapability = vi.fn();
const mockExecuteCapability = vi.fn();

vi.mock("../container/secret-api.js", () => ({
  getVaultStatus: () => mockVaultStatus(),
  generateUnlockChallenge: () => mockGenerateChallenge(),
  verifyUnlockChallenge: (req: unknown) => mockVerifyChallenge(req),
  lockVault: () => mockLockVault(),
  extendSession: () => mockExtendSession(),
  listIntegrations: () => mockListIntegrations(),
  getIntegration: (provider: string) => mockGetIntegration(provider),
  setIntegration: (provider: string, integration: unknown) =>
    mockSetIntegration(provider, integration),
  listCapabilities: (type: string) => mockListCapabilities(type),
  issueCapability: (req: unknown) => mockIssueCapability(req),
  revokeCapability: (id: string) => mockRevokeCapability(id),
  executeCapability: (req: unknown) => mockExecuteCapability(req),
}));

// Mock the secret store singleton
const mockSyncSnapshots = vi.fn();
const mockGetPendingSnapshots = vi.fn();
const mockGetCapabilitiesNeedingRefresh = vi.fn();
const mockFetchAllAvailableSnapshots = vi.fn();
const mockSecretStoreIsUnlocked = vi.fn().mockReturnValue(true);

vi.mock("../container/secret-store.js", () => ({
  getSecretStore: () => ({
    initialize: vi.fn().mockResolvedValue(undefined),
    unlock: vi.fn().mockResolvedValue(true),
    lock: vi.fn(),
    isUnlocked: mockSecretStoreIsUnlocked,
    getSessionTimeRemaining: vi.fn().mockReturnValue(1800),
    removeIntegration: vi.fn().mockResolvedValue(undefined),
    storeReceivedCapability: vi.fn().mockResolvedValue("test-cap-id"),
    listIntegrations: vi.fn().mockReturnValue([]),
    getIntegration: vi.fn().mockReturnValue(null),
    setIntegration: vi.fn().mockResolvedValue(undefined),
    syncSnapshots: mockSyncSnapshots,
    getPendingSnapshots: mockGetPendingSnapshots,
    getCapabilitiesNeedingRefresh: mockGetCapabilitiesNeedingRefresh,
    fetchAllAvailableSnapshots: mockFetchAllAvailableSnapshots,
  }),
}));

function createMockRequest(method: string, url: string, body?: unknown): IncomingMessage {
  let bodyEmitted = false;
  const req = {
    method,
    url,
    headers: { host: "localhost:18789" },
    on: vi.fn((event: string, handler: (data?: unknown) => void) => {
      if (event === "data" && body && !bodyEmitted) {
        bodyEmitted = true;
        handler(Buffer.from(JSON.stringify(body)));
      }
      if (event === "end") {
        process.nextTick(() => handler());
      }
      return req;
    }),
  } as unknown as IncomingMessage;
  return req;
}

function createMockResponse(): ServerResponse & { _data: string; _statusCode: number } {
  let data = "";
  let statusCode = 200;
  const res = {
    get statusCode() {
      return statusCode;
    },
    set statusCode(code: number) {
      statusCode = code;
    },
    get _statusCode() {
      return statusCode;
    },
    _data: "",
    setHeader: vi.fn(),
    end: vi.fn((chunk?: string) => {
      if (chunk) {
        data += chunk;
      }
      res._data = data;
    }),
    write: vi.fn((chunk: string) => {
      data += chunk;
    }),
    flushHeaders: vi.fn(),
  } as unknown as ServerResponse & { _data: string; _statusCode: number };
  return res;
}

const mockAuth: ResolvedGatewayAuth = {
  enabled: false,
  method: "none",
  password: null,
  sessionToken: null,
  maxFailedAttempts: 5,
  lockoutDurationMs: 300000,
};

describe("secret-store-http", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("path matching", () => {
    it("returns false for non-secret-store paths", async () => {
      const req = createMockRequest("GET", "/v1/other/path");
      const res = createMockResponse();

      const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

      expect(handled).toBe(false);
    });

    it("returns false for root path", async () => {
      const req = createMockRequest("GET", "/");
      const res = createMockResponse();

      const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

      expect(handled).toBe(false);
    });

    it("handles /v1/secrets/status path", async () => {
      mockVaultStatus.mockReturnValue({
        initialized: true,
        locked: false,
        expiresIn: 1800,
        publicKey: "abc",
      });
      const req = createMockRequest("GET", "/v1/secrets/status");
      const res = createMockResponse();

      const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

      expect(handled).toBe(true);
      expect(res._statusCode).toBe(200);
    });
  });

  describe("GET /v1/secrets/status", () => {
    it("returns vault status when not initialized", async () => {
      mockVaultStatus.mockReturnValue({
        initialized: false,
        locked: true,
        expiresIn: 0,
        publicKey: null,
      });
      const req = createMockRequest("GET", "/v1/secrets/status");
      const res = createMockResponse();

      const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

      expect(handled).toBe(true);
      expect(res._statusCode).toBe(200);
      const data = JSON.parse(res._data);
      expect(data.initialized).toBe(false);
      expect(data.locked).toBe(true);
    });

    it("returns initialized and unlocked status", async () => {
      mockVaultStatus.mockReturnValue({
        initialized: true,
        locked: false,
        expiresIn: 1800,
        publicKey: "test-key",
      });
      const req = createMockRequest("GET", "/v1/secrets/status");
      const res = createMockResponse();

      const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

      expect(handled).toBe(true);
      expect(res._statusCode).toBe(200);
      const data = JSON.parse(res._data);
      expect(data.initialized).toBe(true);
      expect(data.locked).toBe(false);
      expect(data.expiresIn).toBe(1800);
    });
  });

  describe("POST /v1/secrets/unlock/challenge", () => {
    it("generates an unlock challenge", async () => {
      mockGenerateChallenge.mockReturnValue({
        challengeId: "test-challenge-id",
        challenge: "test-challenge",
        salt: "test-salt",
      });
      const req = createMockRequest("POST", "/v1/secrets/unlock/challenge");
      const res = createMockResponse();

      const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

      expect(handled).toBe(true);
      expect(res._statusCode).toBe(200);
      const data = JSON.parse(res._data);
      expect(data.challengeId).toBe("test-challenge-id");
      expect(data.challenge).toBe("test-challenge");
    });
  });

  describe("POST /v1/secrets/unlock/verify", () => {
    it("verifies challenge and unlocks vault", async () => {
      mockVerifyChallenge.mockResolvedValue({ success: true, expiresIn: 1800 });
      const req = createMockRequest("POST", "/v1/secrets/unlock/verify", {
        challengeId: "test-id",
        response: "test-response",
        derivedKey: "test-key",
      });
      const res = createMockResponse();

      const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

      expect(handled).toBe(true);
      expect(res._statusCode).toBe(200);
      const data = JSON.parse(res._data);
      expect(data.success).toBe(true);
    });

    it("returns 401 on invalid challenge", async () => {
      mockVerifyChallenge.mockResolvedValue({ success: false, error: "Invalid response" });
      const req = createMockRequest("POST", "/v1/secrets/unlock/verify", {
        challengeId: "test-id",
        response: "wrong-response",
        derivedKey: "wrong-key",
      });
      const res = createMockResponse();

      const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

      expect(handled).toBe(true);
      expect(res._statusCode).toBe(401);
    });
  });

  describe("POST /v1/secrets/lock", () => {
    it("locks the vault", async () => {
      mockLockVault.mockReturnValue({ success: true });
      const req = createMockRequest("POST", "/v1/secrets/lock");
      const res = createMockResponse();

      const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

      expect(handled).toBe(true);
      expect(res._statusCode).toBe(200);
      const data = JSON.parse(res._data);
      expect(data.success).toBe(true);
    });
  });

  describe("integrations", () => {
    it("lists integrations", async () => {
      mockListIntegrations.mockReturnValue({
        success: true,
        integrations: [
          { provider: "google", email: "test@example.com", expiresAt: "2024-01-01" },
          { provider: "github", email: "user@example.com", expiresAt: "2024-06-01" },
        ],
      });
      const req = createMockRequest("GET", "/v1/secrets/integrations");
      const res = createMockResponse();

      const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

      expect(handled).toBe(true);
      expect(res._statusCode).toBe(200);
      const data = JSON.parse(res._data);
      expect(data.success).toBe(true);
      expect(data.integrations).toHaveLength(2);
    });

    it("gets specific integration", async () => {
      mockGetIntegration.mockReturnValue({
        success: true,
        integration: { accessToken: "test-token", email: "test@example.com" },
      });
      const req = createMockRequest("GET", "/v1/secrets/integrations/google");
      const res = createMockResponse();

      const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

      expect(handled).toBe(true);
      expect(res._statusCode).toBe(200);
      expect(mockGetIntegration).toHaveBeenCalledWith("google");
    });

    it("returns error when vault is locked", async () => {
      mockGetIntegration.mockReturnValue({ success: false, error: "Vault is locked" });
      const req = createMockRequest("GET", "/v1/secrets/integrations/google");
      const res = createMockResponse();

      const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

      expect(handled).toBe(true);
      expect(res._statusCode).toBe(400);
    });
  });

  describe("capabilities", () => {
    it("issues a capability", async () => {
      mockIssueCapability.mockResolvedValue({ success: true, id: "cap-id", token: "cap-token" });
      const req = createMockRequest("POST", "/v1/secrets/capabilities/issue", {
        subjectPublicKey: "test-key",
        resource: "google",
        scope: ["read"],
        expiresInSeconds: 3600,
      });
      const res = createMockResponse();

      const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

      expect(handled).toBe(true);
      expect(res._statusCode).toBe(200);
      const data = JSON.parse(res._data);
      expect(data.success).toBe(true);
      expect(data.id).toBe("cap-id");
    });

    it("revokes a capability", async () => {
      mockRevokeCapability.mockResolvedValue({ success: true });
      const req = createMockRequest("POST", "/v1/secrets/capabilities/test-cap-id/revoke");
      const res = createMockResponse();

      const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

      expect(handled).toBe(true);
      expect(res._statusCode).toBe(200);
      expect(mockRevokeCapability).toHaveBeenCalledWith("test-cap-id");
    });

    it("lists issued capabilities", async () => {
      mockListCapabilities.mockReturnValue({ success: true, capabilities: [] });
      const req = createMockRequest("GET", "/v1/secrets/capabilities/issued");
      const res = createMockResponse();

      const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

      expect(handled).toBe(true);
      expect(res._statusCode).toBe(200);
      expect(mockListCapabilities).toHaveBeenCalledWith("issued");
    });

    it("lists received capabilities", async () => {
      mockListCapabilities.mockReturnValue({ success: true, capabilities: [] });
      const req = createMockRequest("GET", "/v1/secrets/capabilities/received");
      const res = createMockResponse();

      const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

      expect(handled).toBe(true);
      expect(res._statusCode).toBe(200);
      expect(mockListCapabilities).toHaveBeenCalledWith("received");
    });

    it("executes a capability", async () => {
      mockExecuteCapability.mockResolvedValue({ success: true, result: { data: "test" } });
      const req = createMockRequest("POST", "/v1/secrets/capabilities/execute", {
        token: "cap-token",
        operation: "read",
        params: {},
      });
      const res = createMockResponse();

      const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

      expect(handled).toBe(true);
      expect(res._statusCode).toBe(200);
      const data = JSON.parse(res._data);
      expect(data.success).toBe(true);
    });
  });

  describe("method not allowed", () => {
    it("returns 405 for GET on /v1/secrets/lock", async () => {
      const req = createMockRequest("GET", "/v1/secrets/lock");
      const res = createMockResponse();

      const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

      expect(handled).toBe(true);
      expect(res._statusCode).toBe(405);
    });
  });

  describe("migration support", () => {
    describe("POST /v1/secrets/import", () => {
      it("bulk imports integrations", async () => {
        const req = createMockRequest("POST", "/v1/secrets/import", {
          integrations: {
            google: {
              accessToken: "google-token",
              expiresAt: "2025-01-01T00:00:00Z",
              email: "test@example.com",
            },
            github: {
              accessToken: "github-token",
              expiresAt: "2025-01-01T00:00:00Z",
            },
          },
        });
        const res = createMockResponse();

        const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

        expect(handled).toBe(true);
        expect(res._statusCode).toBe(200);
        const data = JSON.parse(res._data);
        expect(data.success).toBe(true);
        expect(data.imported).toContain("google");
        expect(data.imported).toContain("github");
        expect(data.failed).toHaveLength(0);
      });

      it("handles partial failures", async () => {
        const req = createMockRequest("POST", "/v1/secrets/import", {
          integrations: {
            google: {
              accessToken: "google-token",
              expiresAt: "2025-01-01T00:00:00Z",
            },
            invalid: {
              // Missing accessToken
              expiresAt: "2025-01-01T00:00:00Z",
            },
          },
        });
        const res = createMockResponse();

        const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

        expect(handled).toBe(true);
        expect(res._statusCode).toBe(200);
        const data = JSON.parse(res._data);
        expect(data.partial).toBe(true);
        expect(data.imported).toContain("google");
        expect(data.failed).toHaveLength(1);
        expect(data.failed[0].provider).toBe("invalid");
      });

      it("requires integrations object", async () => {
        const req = createMockRequest("POST", "/v1/secrets/import", {});
        const res = createMockResponse();

        const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

        expect(handled).toBe(true);
        expect(res._statusCode).toBe(400);
        const data = JSON.parse(res._data);
        expect(data.error.message).toContain("integrations");
      });
    });

    describe("GET /v1/secrets/export", () => {
      it("exports all integrations", async () => {
        mockListIntegrations.mockReturnValue({
          success: true,
          integrations: [
            { provider: "google", email: "test@example.com", expiresAt: "2025-01-01" },
          ],
        });
        mockGetIntegration.mockReturnValue({
          success: true,
          integration: {
            accessToken: "test-token",
            refreshToken: "refresh-token",
            expiresAt: "2025-01-01T00:00:00Z",
            email: "test@example.com",
          },
        });

        const req = createMockRequest("GET", "/v1/secrets/export");
        const res = createMockResponse();

        const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

        expect(handled).toBe(true);
        expect(res._statusCode).toBe(200);
        const data = JSON.parse(res._data);
        expect(data.success).toBe(true);
        expect(data.integrations).toBeDefined();
        expect(data.exportedAt).toBeDefined();
      });
    });
  });

  describe("snapshot management (CACHED tier)", () => {
    beforeEach(() => {
      mockSecretStoreIsUnlocked.mockReturnValue(true);
    });

    describe("POST /v1/secrets/snapshots/sync", () => {
      it("syncs CACHED tier snapshots", async () => {
        mockSyncSnapshots.mockResolvedValue({
          refreshed: 2,
          pushed: 2,
          failed: 0,
          errors: [],
        });

        const req = createMockRequest("POST", "/v1/secrets/snapshots/sync");
        const res = createMockResponse();

        const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

        expect(handled).toBe(true);
        expect(res._statusCode).toBe(200);
        const data = JSON.parse(res._data);
        expect(data.success).toBe(true);
        expect(data.refreshed).toBe(2);
        expect(data.pushed).toBe(2);
        expect(data.failed).toBe(0);
      });

      it("returns partial success when some pushes fail", async () => {
        mockSyncSnapshots.mockResolvedValue({
          refreshed: 3,
          pushed: 2,
          failed: 1,
          errors: ["cap-123: Relay unreachable"],
        });

        const req = createMockRequest("POST", "/v1/secrets/snapshots/sync");
        const res = createMockResponse();

        const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

        expect(handled).toBe(true);
        expect(res._statusCode).toBe(200);
        const data = JSON.parse(res._data);
        expect(data.success).toBe(true);
        expect(data.refreshed).toBe(3);
        expect(data.pushed).toBe(2);
        expect(data.failed).toBe(1);
        expect(data.errors).toContain("cap-123: Relay unreachable");
      });

      it("returns 400 when vault is locked", async () => {
        mockSecretStoreIsUnlocked.mockReturnValue(false);

        const req = createMockRequest("POST", "/v1/secrets/snapshots/sync");
        const res = createMockResponse();

        const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

        expect(handled).toBe(true);
        expect(res._statusCode).toBe(400);
        const data = JSON.parse(res._data);
        expect(data.success).toBe(false);
        expect(data.error).toContain("locked");
      });
    });

    describe("GET /v1/secrets/snapshots/status", () => {
      it("returns snapshot status", async () => {
        mockGetPendingSnapshots.mockReturnValue([
          { capabilityId: "cap-1" },
          { capabilityId: "cap-2" },
        ]);
        mockGetCapabilitiesNeedingRefresh.mockReturnValue([{ id: "cap-3" }]);

        const req = createMockRequest("GET", "/v1/secrets/snapshots/status");
        const res = createMockResponse();

        const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

        expect(handled).toBe(true);
        expect(res._statusCode).toBe(200);
        const data = JSON.parse(res._data);
        expect(data.success).toBe(true);
        expect(data.pendingCount).toBe(2);
        expect(data.needingRefreshCount).toBe(1);
        expect(data.pendingCapabilityIds).toContain("cap-1");
        expect(data.pendingCapabilityIds).toContain("cap-2");
        expect(data.needingRefreshCapabilityIds).toContain("cap-3");
      });

      it("returns empty counts when no snapshots pending", async () => {
        mockGetPendingSnapshots.mockReturnValue([]);
        mockGetCapabilitiesNeedingRefresh.mockReturnValue([]);

        const req = createMockRequest("GET", "/v1/secrets/snapshots/status");
        const res = createMockResponse();

        const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

        expect(handled).toBe(true);
        expect(res._statusCode).toBe(200);
        const data = JSON.parse(res._data);
        expect(data.success).toBe(true);
        expect(data.pendingCount).toBe(0);
        expect(data.needingRefreshCount).toBe(0);
      });

      it("returns 400 when vault is locked", async () => {
        mockSecretStoreIsUnlocked.mockReturnValue(false);

        const req = createMockRequest("GET", "/v1/secrets/snapshots/status");
        const res = createMockResponse();

        const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

        expect(handled).toBe(true);
        expect(res._statusCode).toBe(400);
        const data = JSON.parse(res._data);
        expect(data.success).toBe(false);
        expect(data.error).toContain("locked");
      });
    });

    describe("POST /v1/secrets/snapshots/fetch", () => {
      it("fetches all available snapshots from relay", async () => {
        mockFetchAllAvailableSnapshots.mockResolvedValue({
          fetched: 3,
          errors: [],
        });

        const req = createMockRequest("POST", "/v1/secrets/snapshots/fetch");
        const res = createMockResponse();

        const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

        expect(handled).toBe(true);
        expect(res._statusCode).toBe(200);
        const data = JSON.parse(res._data);
        expect(data.success).toBe(true);
        expect(data.fetched).toBe(3);
      });

      it("returns partial success with errors", async () => {
        mockFetchAllAvailableSnapshots.mockResolvedValue({
          fetched: 2,
          errors: ["cap-456: Decryption failed"],
        });

        const req = createMockRequest("POST", "/v1/secrets/snapshots/fetch");
        const res = createMockResponse();

        const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

        expect(handled).toBe(true);
        expect(res._statusCode).toBe(200);
        const data = JSON.parse(res._data);
        expect(data.success).toBe(false);
        expect(data.fetched).toBe(2);
        expect(data.errors).toContain("cap-456: Decryption failed");
      });

      it("returns 400 when vault is locked", async () => {
        mockSecretStoreIsUnlocked.mockReturnValue(false);

        const req = createMockRequest("POST", "/v1/secrets/snapshots/fetch");
        const res = createMockResponse();

        const handled = await handleSecretStoreHttpRequest(req, res, { auth: mockAuth });

        expect(handled).toBe(true);
        expect(res._statusCode).toBe(400);
        const data = JSON.parse(res._data);
        expect(data.success).toBe(false);
        expect(data.error).toContain("locked");
      });
    });
  });
});
