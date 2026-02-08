import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

// Set a stable CSRF secret for testing before importing the module
process.env.CSRF_SECRET = "test-csrf-secret-for-unit-tests-0123456789abcdef";

import { generateCsrfToken, validateCsrfToken, getCsrfTokenFromRequest } from "./csrf.js";

describe("CSRF Token Library", () => {
  // Store the real Date.now to restore after tests that mock it
  const realDateNow = Date.now.bind(Date);

  afterEach(() => {
    // Always restore Date.now after each test
    Date.now = realDateNow;
    vi.restoreAllMocks();
  });

  describe("generateCsrfToken", () => {
    it("should generate a valid token for a session ID", () => {
      const sessionId = "test-session-12345";
      const token = generateCsrfToken(sessionId);

      expect(typeof token).toBe("string");
      expect(token.length).toBeGreaterThan(0);
      // Token format: base64url.base64url
      expect(token.split(".")).toHaveLength(2);
    });

    it("should generate different tokens for same session (random component)", () => {
      const sessionId = "test-session-12345";
      const token1 = generateCsrfToken(sessionId);
      const token2 = generateCsrfToken(sessionId);

      expect(token1).not.toBe(token2);
    });

    it("should throw error if session ID is missing", () => {
      expect(() => generateCsrfToken(null)).toThrow("Session ID required");
      expect(() => generateCsrfToken(undefined)).toThrow("Session ID required");
      expect(() => generateCsrfToken("")).toThrow("Session ID required");
    });
  });

  describe("validateCsrfToken", () => {
    it("should validate a valid token", () => {
      const sessionId = "test-session-12345";
      const token = generateCsrfToken(sessionId);
      const result = validateCsrfToken(token, sessionId);

      expect(result.valid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it("should reject token with different session ID", () => {
      const sessionId = "test-session-12345";
      const wrongSessionId = "wrong-session-67890";
      const token = generateCsrfToken(sessionId);
      const result = validateCsrfToken(token, wrongSessionId);

      expect(result.valid).toBe(false);
      expect(result.error).toBe("CSRF token session mismatch");
    });

    it("should reject missing token", () => {
      const result = validateCsrfToken(null, "session-123");

      expect(result.valid).toBe(false);
      expect(result.error).toBe("CSRF token missing");
    });

    it("should reject missing session ID", () => {
      const token = generateCsrfToken("session-123");
      const result = validateCsrfToken(token, null);

      expect(result.valid).toBe(false);
      expect(result.error).toBe("Session ID required for CSRF validation");
    });

    it("should reject invalid token format", () => {
      const result = validateCsrfToken("invalid-token-no-dot", "session-123");

      expect(result.valid).toBe(false);
      expect(result.error).toBe("Invalid CSRF token format");
    });

    it("should reject token with invalid signature", () => {
      const sessionId = "test-session-12345";
      const token = generateCsrfToken(sessionId);
      // Tamper with the signature
      const parts = token.split(".");
      const tamperedToken =
        parts[0] + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
      const result = validateCsrfToken(tamperedToken, sessionId);

      expect(result.valid).toBe(false);
      expect(result.error).toBe("Invalid CSRF token signature");
    });

    it("should reject tampered payload", () => {
      const sessionId = "test-session-12345";
      const token = generateCsrfToken(sessionId);
      // Tamper with the payload
      const parts = token.split(".");
      const tamperedPayload = Buffer.from("different-session:1234567890:random").toString(
        "base64url",
      );
      const tamperedToken = tamperedPayload + "." + parts[1];
      const result = validateCsrfToken(tamperedToken, sessionId);

      expect(result.valid).toBe(false);
      // Either signature or session mismatch
      expect(result.error).toMatch(/Invalid CSRF token|session mismatch/);
    });

    it("should reject expired tokens", async () => {
      const sessionId = "test-session-12345";

      // Mock Date.now to simulate time passage
      const realDateNow = Date.now;
      const now = realDateNow();

      // Create token at "now"
      Date.now = vi.fn(() => now);
      const token = generateCsrfToken(sessionId);

      // Validate token 25 hours later (past 24-hour expiry)
      Date.now = vi.fn(() => now + 25 * 60 * 60 * 1000);
      const result = validateCsrfToken(token, sessionId);

      // Restore Date.now
      Date.now = realDateNow;

      expect(result.valid).toBe(false);
      expect(result.error).toBe("CSRF token expired");
    });

    it("should reject tokens from the future", () => {
      const sessionId = "test-session-12345";

      const realDateNow = Date.now;
      const now = realDateNow();

      // Create token at "future"
      Date.now = vi.fn(() => now + 10 * 60 * 1000); // 10 minutes in future
      const token = generateCsrfToken(sessionId);

      // Validate token at "now" (token appears from the future)
      Date.now = vi.fn(() => now);
      const result = validateCsrfToken(token, sessionId);

      // Restore Date.now
      Date.now = realDateNow;

      expect(result.valid).toBe(false);
      expect(result.error).toBe("CSRF token timestamp invalid");
    });

    it("should allow tokens within clock skew tolerance", () => {
      const sessionId = "test-session-12345";

      const realDateNow = Date.now;
      const now = realDateNow();

      // Create token at "slight future" (within 5 minute tolerance)
      Date.now = vi.fn(() => now + 2 * 60 * 1000); // 2 minutes in future
      const token = generateCsrfToken(sessionId);

      // Validate token at "now"
      Date.now = vi.fn(() => now);
      const result = validateCsrfToken(token, sessionId);

      // Restore Date.now
      Date.now = realDateNow;

      expect(result.valid).toBe(true);
    });
  });

  describe("getCsrfTokenFromRequest", () => {
    it("should extract token from X-CSRF-Token header", () => {
      const req = {
        headers: { "x-csrf-token": "token-from-header" },
        body: {},
        query: {},
      };

      expect(getCsrfTokenFromRequest(req)).toBe("token-from-header");
    });

    it("should extract token from X-XSRF-Token header", () => {
      const req = {
        headers: { "x-xsrf-token": "token-from-xsrf-header" },
        body: {},
        query: {},
      };

      expect(getCsrfTokenFromRequest(req)).toBe("token-from-xsrf-header");
    });

    it("should prefer header over body", () => {
      const req = {
        headers: { "x-csrf-token": "header-token" },
        body: { _csrf: "body-token" },
        query: {},
      };

      expect(getCsrfTokenFromRequest(req)).toBe("header-token");
    });

    it("should extract token from body when no header", () => {
      const req = {
        headers: {},
        body: { _csrf: "body-token" },
        query: {},
      };

      expect(getCsrfTokenFromRequest(req)).toBe("body-token");
    });

    it("should extract token from query when no header or body", () => {
      const req = {
        headers: {},
        body: {},
        query: { _csrf: "query-token" },
      };

      expect(getCsrfTokenFromRequest(req)).toBe("query-token");
    });

    it("should return null when no token found", () => {
      const req = {
        headers: {},
        body: {},
        query: {},
      };

      expect(getCsrfTokenFromRequest(req)).toBeNull();
    });

    it("should handle missing body and query", () => {
      const req = {
        headers: {},
      };

      expect(getCsrfTokenFromRequest(req)).toBeNull();
    });
  });

  describe("timing-safe comparisons", () => {
    it("should not leak timing information through signature validation", () => {
      // This is a basic sanity check - proper timing analysis requires
      // statistical testing which is beyond unit test scope
      const sessionId = "test-session-12345";
      const validToken = generateCsrfToken(sessionId);

      // Both should take roughly the same time (timing-safe)
      const validResult = validateCsrfToken(validToken, sessionId);
      expect(validResult.valid).toBe(true);

      // Invalid signature should still go through timing-safe comparison
      const parts = validToken.split(".");
      const invalidSigToken =
        parts[0] + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
      const invalidResult = validateCsrfToken(invalidSigToken, sessionId);
      expect(invalidResult.valid).toBe(false);
    });
  });
});
