import { generateKeyPairSync, sign as cryptoSign, createPrivateKey } from "crypto";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  createRevocationService,
  createRevocationMiddleware,
  type RevocationRequest,
} from "./revocation-service.js";
import { RevocationStore, resetRevocationStore } from "./revocation-store.js";

describe("RevocationService", () => {
  let tempDir: string;
  let store: RevocationStore;
  let service: ReturnType<typeof createRevocationService>;

  // Generate a test keypair
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const rawPublicKey = (publicKey.export({ type: "spki", format: "der" }) as Buffer).subarray(12);
  const publicKeyBase64 = rawPublicKey.toString("base64");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

  function signRevocation(request: Omit<RevocationRequest, "signature">): string {
    const payload = JSON.stringify({
      action: "revoke",
      capabilityId: request.capabilityId,
      revokedBy: request.revokedBy,
      reason: request.reason,
      originalExpiry: request.originalExpiry,
      timestamp: request.timestamp,
    });

    const privKey = createPrivateKey(privateKeyPem);
    const signature = cryptoSign(null, Buffer.from(payload, "utf-8"), privKey);
    return signature.toString("base64");
  }

  beforeEach(() => {
    resetRevocationStore();
    tempDir = mkdtempSync(join(tmpdir(), "revocation-service-test-"));
    store = new RevocationStore(tempDir);
    service = createRevocationService(store);
  });

  afterEach(async () => {
    await store.close();
    rmSync(tempDir, { recursive: true, force: true });
  });

  describe("handleRevoke", () => {
    it("accepts valid revocation request", async () => {
      const timestamp = new Date().toISOString();
      const request: Omit<RevocationRequest, "signature"> = {
        capabilityId: "cap-123",
        revokedBy: publicKeyBase64,
        reason: "Compromised",
        timestamp,
      };

      const result = await service.handleRevoke({
        ...request,
        signature: signRevocation(request),
      });

      expect(result.success).toBe(true);
      expect(result.revocationId).toBe("cap-123");
    });

    it("rejects request with missing fields", async () => {
      const result = await service.handleRevoke({
        capabilityId: "cap-123",
        revokedBy: "",
        signature: "bad",
        timestamp: new Date().toISOString(),
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain("Missing required fields");
    });

    it("rejects request with old timestamp", async () => {
      const oldTimestamp = new Date(Date.now() - 10 * 60 * 1000).toISOString();
      const request: Omit<RevocationRequest, "signature"> = {
        capabilityId: "cap-123",
        revokedBy: publicKeyBase64,
        timestamp: oldTimestamp,
      };

      const result = await service.handleRevoke({
        ...request,
        signature: signRevocation(request),
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain("timestamp");
    });

    it("rejects request with invalid signature", async () => {
      const result = await service.handleRevoke({
        capabilityId: "cap-123",
        revokedBy: publicKeyBase64,
        signature: "invalid-signature",
        timestamp: new Date().toISOString(),
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain("Invalid signature");
    });

    it("rejects request signed by wrong key", async () => {
      // Generate a different keypair
      const { privateKey: otherPriv } = generateKeyPairSync("ed25519");
      const otherPrivPem = otherPriv.export({ type: "pkcs8", format: "pem" }).toString();

      const timestamp = new Date().toISOString();
      const payload = JSON.stringify({
        action: "revoke",
        capabilityId: "cap-123",
        revokedBy: publicKeyBase64,
        reason: undefined,
        originalExpiry: undefined,
        timestamp,
      });

      // Sign with wrong key
      const wrongSig = cryptoSign(
        null,
        Buffer.from(payload, "utf-8"),
        createPrivateKey(otherPrivPem),
      );

      const result = await service.handleRevoke({
        capabilityId: "cap-123",
        revokedBy: publicKeyBase64,
        signature: wrongSig.toString("base64"),
        timestamp,
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain("Invalid signature");
    });
  });

  describe("checkRevocation", () => {
    it("returns false for non-revoked capability", () => {
      const result = service.checkRevocation("unknown-cap");
      expect(result.revoked).toBe(false);
    });

    it("returns true with details for revoked capability", async () => {
      const timestamp = new Date().toISOString();
      const request: Omit<RevocationRequest, "signature"> = {
        capabilityId: "cap-123",
        revokedBy: publicKeyBase64,
        reason: "Security incident",
        timestamp,
      };

      await service.handleRevoke({
        ...request,
        signature: signRevocation(request),
      });

      const result = service.checkRevocation("cap-123");
      expect(result.revoked).toBe(true);
      expect(result.revokedBy).toBe(publicKeyBase64);
      expect(result.reason).toBe("Security incident");
      expect(result.revokedAt).toBeDefined();
    });
  });

  describe("getStats", () => {
    it("returns statistics", async () => {
      const timestamp = new Date().toISOString();
      const request: Omit<RevocationRequest, "signature"> = {
        capabilityId: "cap-123",
        revokedBy: publicKeyBase64,
        timestamp,
      };

      await service.handleRevoke({
        ...request,
        signature: signRevocation(request),
      });

      const stats = service.getStats();
      expect(stats.totalRevocations).toBe(1);
    });
  });
});

describe("RevocationMiddleware", () => {
  let tempDir: string;
  let store: RevocationStore;
  let service: ReturnType<typeof createRevocationService>;
  let middleware: ReturnType<typeof createRevocationMiddleware>;

  // Generate a test keypair
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const rawPublicKey = (publicKey.export({ type: "spki", format: "der" }) as Buffer).subarray(12);
  const publicKeyBase64 = rawPublicKey.toString("base64");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

  function signRevocation(request: Omit<RevocationRequest, "signature">): string {
    const payload = JSON.stringify({
      action: "revoke",
      capabilityId: request.capabilityId,
      revokedBy: request.revokedBy,
      reason: request.reason,
      originalExpiry: request.originalExpiry,
      timestamp: request.timestamp,
    });

    const privKey = createPrivateKey(privateKeyPem);
    const signature = cryptoSign(null, Buffer.from(payload, "utf-8"), privKey);
    return signature.toString("base64");
  }

  beforeEach(() => {
    resetRevocationStore();
    tempDir = mkdtempSync(join(tmpdir(), "revocation-middleware-test-"));
    store = new RevocationStore(tempDir);
    service = createRevocationService(store);
    middleware = createRevocationMiddleware(service);
  });

  afterEach(async () => {
    await store.close();
    rmSync(tempDir, { recursive: true, force: true });
  });

  describe("shouldBlock", () => {
    it("does not block non-revoked capability", () => {
      const result = middleware.shouldBlock("cap-valid");
      expect(result.blocked).toBe(false);
    });

    it("blocks revoked capability", async () => {
      const timestamp = new Date().toISOString();
      const request: Omit<RevocationRequest, "signature"> = {
        capabilityId: "cap-revoked",
        revokedBy: publicKeyBase64,
        reason: "Compromised",
        timestamp,
      };

      await service.handleRevoke({
        ...request,
        signature: signRevocation(request),
      });

      const result = middleware.shouldBlock("cap-revoked");
      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("Compromised");
    });
  });

  describe("shouldBlockAny", () => {
    it("returns false when no capabilities are revoked", () => {
      const result = middleware.shouldBlockAny(["cap-1", "cap-2", "cap-3"]);
      expect(result.blocked).toBe(false);
    });

    it("returns true when any capability is revoked", async () => {
      const timestamp = new Date().toISOString();
      const request: Omit<RevocationRequest, "signature"> = {
        capabilityId: "cap-2",
        revokedBy: publicKeyBase64,
        timestamp,
      };

      await service.handleRevoke({
        ...request,
        signature: signRevocation(request),
      });

      const result = middleware.shouldBlockAny(["cap-1", "cap-2", "cap-3"]);
      expect(result.blocked).toBe(true);
      expect(result.blockedId).toBe("cap-2");
    });
  });
});
