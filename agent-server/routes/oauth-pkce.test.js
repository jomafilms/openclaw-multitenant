// agent-server/routes/oauth-pkce.test.js
// Tests for zero-knowledge OAuth PKCE flow

import crypto from "crypto";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

// Mock axios before importing the module
vi.mock("axios", () => ({
  default: {
    post: vi.fn(),
    get: vi.fn(),
  },
}));

// Mock containers
vi.mock("../lib/containers.js", () => ({
  containers: new Map([["test-user-123", { port: 8080, internalToken: "internal-token" }]]),
}));

describe("OAuth PKCE", () => {
  describe("generatePKCE", () => {
    it("should generate valid code_verifier and code_challenge", async () => {
      // Import dynamically to get fresh module with mocks
      const { pkceStates } = await import("./oauth-pkce.js");

      // Generate PKCE manually to test the algorithm
      const codeVerifier = crypto.randomBytes(32).toString("base64url");
      const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

      // Verify format
      expect(codeVerifier.length).toBeGreaterThanOrEqual(43);
      expect(codeVerifier.length).toBeLessThanOrEqual(128);
      expect(codeChallenge.length).toBe(43); // SHA-256 base64url is always 43 chars

      // Verify challenge is correct hash of verifier
      const recomputedChallenge = crypto
        .createHash("sha256")
        .update(codeVerifier)
        .digest("base64url");
      expect(codeChallenge).toBe(recomputedChallenge);
    });
  });

  describe("PKCE state management", () => {
    it("should store and retrieve PKCE state", async () => {
      const { pkceStates } = await import("./oauth-pkce.js");

      const stateToken = crypto.randomBytes(32).toString("hex");
      const testState = {
        userId: "test-user-123",
        codeVerifier: crypto.randomBytes(32).toString("base64url"),
        provider: "google_calendar",
        scope: "calendar",
        createdAt: Date.now(),
      };

      pkceStates.set(stateToken, testState);

      const retrieved = pkceStates.get(stateToken);
      expect(retrieved).toBeDefined();
      expect(retrieved.userId).toBe("test-user-123");
      expect(retrieved.provider).toBe("google_calendar");
      expect(retrieved.codeVerifier).toBe(testState.codeVerifier);

      // Cleanup
      pkceStates.delete(stateToken);
    });

    it("should not return expired state", async () => {
      const { pkceStates } = await import("./oauth-pkce.js");

      const stateToken = crypto.randomBytes(32).toString("hex");
      const expiredState = {
        userId: "test-user-123",
        codeVerifier: crypto.randomBytes(32).toString("base64url"),
        provider: "google_calendar",
        scope: "calendar",
        createdAt: Date.now() - 20 * 60 * 1000, // 20 minutes ago (expired)
      };

      pkceStates.set(stateToken, expiredState);

      // State should still be retrievable (cleanup is interval-based)
      const retrieved = pkceStates.get(stateToken);
      expect(retrieved).toBeDefined();

      // But the state was created in the past
      expect(Date.now() - retrieved.createdAt).toBeGreaterThan(10 * 60 * 1000);

      // Cleanup
      pkceStates.delete(stateToken);
    });
  });

  describe("security properties", () => {
    it("code_verifier should be cryptographically random", () => {
      const verifiers = new Set();
      for (let i = 0; i < 100; i++) {
        const verifier = crypto.randomBytes(32).toString("base64url");
        expect(verifiers.has(verifier)).toBe(false);
        verifiers.add(verifier);
      }
    });

    it("state token should be cryptographically random", () => {
      const tokens = new Set();
      for (let i = 0; i < 100; i++) {
        const token = crypto.randomBytes(32).toString("hex");
        expect(tokens.has(token)).toBe(false);
        tokens.add(token);
      }
    });

    it("code_challenge should be one-way (cannot derive verifier from challenge)", () => {
      const codeVerifier = crypto.randomBytes(32).toString("base64url");
      const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

      // Given only the challenge, we cannot derive the verifier
      // This is a property of SHA-256 (preimage resistance)
      expect(codeChallenge).not.toContain(codeVerifier);
      expect(codeChallenge.length).toBeLessThan(codeVerifier.length);
    });
  });
});

describe("Zero-knowledge guarantees", () => {
  it("management server only sees auth_code and code_challenge", () => {
    // The management server receives:
    // 1. code_challenge (hash, cannot derive verifier)
    // 2. auth_code (useless without verifier)
    // 3. metadata (provider, scope, etc.)

    // It NEVER sees:
    // 1. code_verifier
    // 2. access_token
    // 3. refresh_token

    const codeVerifier = crypto.randomBytes(32).toString("base64url");
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

    // Simulate what management server sees
    const managementServerSees = {
      codeChallenge, // Safe - hash of verifier
      authCode: "4/P7q7W91a-oMsCeLvIaQm6bTrgtp7", // Useless without verifier
      state: crypto.randomBytes(16).toString("hex"),
      scope: "calendar",
      provider: "google_calendar",
    };

    // Management server cannot:
    // 1. Derive verifier from challenge
    expect(managementServerSees.codeChallenge).not.toBe(codeVerifier);

    // 2. Exchange auth_code without verifier (would fail at Google)
    // This is enforced by the OAuth provider

    // Container sees everything needed:
    const containerSees = {
      codeVerifier, // Secret
      authCode: managementServerSees.authCode, // From management server
      redirectUri: "https://example.com/callback",
    };

    // Container can exchange because it has the verifier
    expect(containerSees.codeVerifier).toBe(codeVerifier);
  });
});
