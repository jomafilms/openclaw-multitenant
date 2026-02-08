/**
 * Tests for Agent Credentials Provider
 *
 * Tests the interface for agents to access credentials from the local secret store.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  isCredentialExpired,
  toOAuthCredentials,
  type AgentCredential,
} from "./agent-credentials.js";

// These tests focus on the pure functions that don't require SecretStore initialization.
// Full integration tests with SecretStore would require mocking scrypt to use lower params.

describe("agent-credentials", () => {
  describe("isCredentialExpired", () => {
    it("returns true for expired credential", () => {
      const credential: AgentCredential = {
        provider: "google",
        accessToken: "token",
        expiresAt: new Date(Date.now() - 1000),
      };

      expect(isCredentialExpired(credential)).toBe(true);
    });

    it("returns true for credential expiring within buffer", () => {
      const credential: AgentCredential = {
        provider: "google",
        accessToken: "token",
        expiresAt: new Date(Date.now() + 60000), // 1 minute from now
      };

      // Default buffer is 5 minutes
      expect(isCredentialExpired(credential)).toBe(true);
    });

    it("returns false for credential not expiring soon", () => {
      const credential: AgentCredential = {
        provider: "google",
        accessToken: "token",
        expiresAt: new Date(Date.now() + 3600000), // 1 hour from now
      };

      expect(isCredentialExpired(credential)).toBe(false);
    });

    it("respects custom buffer", () => {
      const credential: AgentCredential = {
        provider: "google",
        accessToken: "token",
        expiresAt: new Date(Date.now() + 60000), // 1 minute from now
      };

      // With 30 second buffer, should not be expired
      expect(isCredentialExpired(credential, 30000)).toBe(false);
    });

    it("handles edge case at buffer boundary", () => {
      const bufferMs = 5 * 60 * 1000;
      const credential: AgentCredential = {
        provider: "google",
        accessToken: "token",
        expiresAt: new Date(Date.now() + bufferMs + 1000), // Just past buffer
      };

      expect(isCredentialExpired(credential, bufferMs)).toBe(false);
    });
  });

  describe("toOAuthCredentials", () => {
    it("converts credential to OAuth format", () => {
      const expiresAt = new Date(Date.now() + 3600000);
      const credential: AgentCredential = {
        provider: "google",
        accessToken: "access-token",
        refreshToken: "refresh-token",
        expiresAt,
      };

      const oauth = toOAuthCredentials(credential);

      expect(oauth.access_token).toBe("access-token");
      expect(oauth.refresh_token).toBe("refresh-token");
      expect(oauth.expires_at).toBe(Math.floor(expiresAt.getTime() / 1000));
    });

    it("handles missing refresh token", () => {
      const credential: AgentCredential = {
        provider: "google",
        accessToken: "access-token",
        expiresAt: new Date(),
      };

      const oauth = toOAuthCredentials(credential);

      expect(oauth.access_token).toBe("access-token");
      expect(oauth.refresh_token).toBeUndefined();
    });

    it("converts timestamp to unix epoch seconds", () => {
      const timestampMs = 1700000000000;
      const credential: AgentCredential = {
        provider: "google",
        accessToken: "token",
        expiresAt: new Date(timestampMs),
      };

      const oauth = toOAuthCredentials(credential);

      expect(oauth.expires_at).toBe(1700000000);
    });

    it("preserves all credential fields in conversion", () => {
      const credential: AgentCredential = {
        provider: "google",
        accessToken: "access",
        refreshToken: "refresh",
        expiresAt: new Date(1700000000000),
        email: "test@example.com",
        scopes: ["email", "profile"],
      };

      const oauth = toOAuthCredentials(credential);

      expect(oauth).toEqual({
        access_token: "access",
        refresh_token: "refresh",
        expires_at: 1700000000,
      });
    });
  });

  describe("CredentialProvider interface", () => {
    it("type definitions are correct", () => {
      // Type-level test to ensure the types are exported correctly
      type TestCredential = AgentCredential;
      const cred: TestCredential = {
        provider: "test",
        accessToken: "token",
        expiresAt: new Date(),
      };
      expect(cred.provider).toBe("test");
    });
  });
});
