// group-vault/lib/auth.test.js
// Tests for group vault auth and capability tokens

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  initAuth,
  issueCapabilityToken,
  verifyCapabilityToken,
  checkAccess,
  revokeToken,
  revokeUserTokens,
} from "./auth.js";

describe("GroupVaultAuth", () => {
  const signingKey = "test-signing-key-that-is-at-least-32-characters";
  const groupId = "test-group-123";
  const userId = "test-user-456";

  beforeEach(async () => {
    await initAuth(signingKey);
  });

  describe("initAuth", () => {
    it("should initialize with valid key", async () => {
      await expect(initAuth(signingKey)).resolves.not.toThrow();
    });

    it("should reject short key", async () => {
      await expect(initAuth("short")).rejects.toThrow("Signing key must be at least 32 characters");
    });
  });

  describe("issueCapabilityToken", () => {
    it("should issue token with default permissions", () => {
      const token = issueCapabilityToken({
        groupId,
        userId,
      });

      expect(token).toBeTruthy();
      expect(typeof token).toBe("string");
    });

    it("should issue token with custom permissions", () => {
      const token = issueCapabilityToken({
        groupId,
        userId,
        allowedSecrets: ["api-key", "db-password"],
        permissions: ["read", "write"],
        ttlSeconds: 7200,
      });

      const verified = verifyCapabilityToken(token);
      expect(verified.allowedSecrets).toEqual(["api-key", "db-password"]);
      expect(verified.permissions).toEqual(["read", "write"]);
    });
  });

  describe("verifyCapabilityToken", () => {
    it("should verify valid token", () => {
      const token = issueCapabilityToken({ groupId, userId });
      const verified = verifyCapabilityToken(token);

      expect(verified).toBeTruthy();
      expect(verified.groupId).toBe(groupId);
      expect(verified.userId).toBe(userId);
    });

    it("should reject tampered token", () => {
      const token = issueCapabilityToken({ groupId, userId });
      const tamperedToken = token.slice(0, -5) + "xxxxx";

      const verified = verifyCapabilityToken(tamperedToken);
      expect(verified).toBeNull();
    });

    it("should reject expired token", () => {
      const token = issueCapabilityToken({
        groupId,
        userId,
        ttlSeconds: -1, // Already expired
      });

      const verified = verifyCapabilityToken(token);
      expect(verified).toBeNull();
    });

    it("should reject invalid base64", () => {
      const verified = verifyCapabilityToken("not-valid-base64!!!");
      expect(verified).toBeNull();
    });
  });

  describe("checkAccess", () => {
    it("should allow wildcard access", () => {
      const token = {
        allowedSecrets: ["*"],
        permissions: ["read", "write"],
      };

      expect(checkAccess(token, "any-secret", "read")).toBe(true);
      expect(checkAccess(token, "any-secret", "write")).toBe(true);
      expect(checkAccess(token, "any-secret", "delete")).toBe(false);
    });

    it("should check specific secrets", () => {
      const token = {
        allowedSecrets: ["api-key", "db-password"],
        permissions: ["read"],
      };

      expect(checkAccess(token, "api-key", "read")).toBe(true);
      expect(checkAccess(token, "db-password", "read")).toBe(true);
      expect(checkAccess(token, "other-secret", "read")).toBe(false);
    });

    it("should check permissions", () => {
      const token = {
        allowedSecrets: ["*"],
        permissions: ["read"],
      };

      expect(checkAccess(token, "secret", "read")).toBe(true);
      expect(checkAccess(token, "secret", "write")).toBe(false);
    });
  });

  describe("revokeToken", () => {
    it("should revoke token", () => {
      const token = issueCapabilityToken({ groupId, userId });
      const verified1 = verifyCapabilityToken(token);
      expect(verified1).toBeTruthy();

      revokeToken(verified1.id);

      const verified2 = verifyCapabilityToken(token);
      expect(verified2).toBeNull();
    });
  });

  describe("revokeUserTokens", () => {
    it("should revoke all tokens for user", () => {
      const token1 = issueCapabilityToken({ groupId, userId });
      const token2 = issueCapabilityToken({ groupId, userId });
      const otherToken = issueCapabilityToken({ groupId, userId: "other-user" });

      revokeUserTokens(groupId, userId);

      expect(verifyCapabilityToken(token1)).toBeNull();
      expect(verifyCapabilityToken(token2)).toBeNull();
      expect(verifyCapabilityToken(otherToken)).toBeTruthy();
    });
  });
});
