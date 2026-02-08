// Gateway Token Tests
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { clearKeyCache } from "./encryption.js";
import {
  generatePermanentToken,
  encryptGatewayToken,
  decryptGatewayToken,
  generateEphemeralToken,
  validateEphemeralToken,
  detectTokenType,
  getTokenExpiry,
  needsRefresh,
} from "./gateway-tokens.js";

// Set up encryption key for tests
beforeAll(() => {
  // Clear any cached keys first
  clearKeyCache();
  // Set a test encryption key (64 hex chars = 32 bytes)
  process.env.ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
});

describe("gateway-tokens", () => {
  describe("generatePermanentToken", () => {
    it("generates 64-character hex string", () => {
      const token = generatePermanentToken();
      expect(token).toMatch(/^[0-9a-f]{64}$/);
    });

    it("generates unique tokens", () => {
      const tokens = new Set();
      for (let i = 0; i < 100; i++) {
        tokens.add(generatePermanentToken());
      }
      expect(tokens.size).toBe(100);
    });
  });

  describe("encryptGatewayToken / decryptGatewayToken", () => {
    it("encrypts and decrypts token correctly", () => {
      const original = generatePermanentToken();
      const encrypted = encryptGatewayToken(original);

      expect(encrypted).not.toBe(original);
      expect(encrypted).toContain(":"); // Versioned format

      const decrypted = decryptGatewayToken(encrypted);
      expect(decrypted).toBe(original);
    });

    it("handles null/empty input", () => {
      expect(encryptGatewayToken(null)).toBeNull();
      expect(encryptGatewayToken("")).toBeNull();
      expect(decryptGatewayToken(null)).toBeNull();
      expect(decryptGatewayToken("")).toBeNull();
    });
  });

  describe("generateEphemeralToken", () => {
    const userId = "test-user-123";
    const permanentToken = generatePermanentToken();

    it("generates valid base64url token", () => {
      const token = generateEphemeralToken(userId, permanentToken);
      expect(token).toBeTruthy();

      // Should be valid base64url (no +, /, or = padding issues)
      const decoded = Buffer.from(token, "base64url").toString("utf8");
      const parsed = JSON.parse(decoded);

      expect(parsed.payload).toBeDefined();
      expect(parsed.signature).toBeDefined();
      expect(parsed.payload.userId).toBe(userId);
      expect(parsed.payload.exp).toBeGreaterThan(Date.now() / 1000);
      expect(parsed.payload.nonce).toMatch(/^[0-9a-f]{16}$/);
    });

    it("respects custom expiry", () => {
      const token = generateEphemeralToken(userId, permanentToken, 600); // 10 minutes
      const decoded = JSON.parse(Buffer.from(token, "base64url").toString("utf8"));

      const expectedExp = Math.floor(Date.now() / 1000) + 600;
      expect(decoded.payload.exp).toBeGreaterThanOrEqual(expectedExp - 1);
      expect(decoded.payload.exp).toBeLessThanOrEqual(expectedExp + 1);
    });

    it("clamps expiry to valid range", () => {
      // Too short - should be MIN_EXPIRY_SECONDS (300)
      const shortToken = generateEphemeralToken(userId, permanentToken, 60);
      const shortDecoded = JSON.parse(Buffer.from(shortToken, "base64url").toString("utf8"));
      const shortExpected = Math.floor(Date.now() / 1000) + 300;
      expect(shortDecoded.payload.exp).toBeGreaterThanOrEqual(shortExpected - 1);

      // Too long - should be MAX_EXPIRY_SECONDS (86400)
      const longToken = generateEphemeralToken(userId, permanentToken, 200000);
      const longDecoded = JSON.parse(Buffer.from(longToken, "base64url").toString("utf8"));
      const longExpected = Math.floor(Date.now() / 1000) + 86400;
      expect(longDecoded.payload.exp).toBeLessThanOrEqual(longExpected + 1);
    });

    it("throws on missing parameters", () => {
      expect(() => generateEphemeralToken(null, permanentToken)).toThrow();
      expect(() => generateEphemeralToken(userId, null)).toThrow();
    });

    it("generates unique tokens (different nonces)", () => {
      const tokens = new Set();
      for (let i = 0; i < 100; i++) {
        tokens.add(generateEphemeralToken(userId, permanentToken));
      }
      expect(tokens.size).toBe(100);
    });
  });

  describe("validateEphemeralToken", () => {
    const userId = "test-user-456";
    const permanentToken = generatePermanentToken();

    it("validates correct token", () => {
      const ephemeralToken = generateEphemeralToken(userId, permanentToken);
      const payload = validateEphemeralToken(ephemeralToken, permanentToken);

      expect(payload).not.toBeNull();
      expect(payload.userId).toBe(userId);
      expect(payload.nonce).toMatch(/^[0-9a-f]{16}$/);
    });

    it("rejects token with wrong permanent key", () => {
      const ephemeralToken = generateEphemeralToken(userId, permanentToken);
      const wrongKey = generatePermanentToken();

      const payload = validateEphemeralToken(ephemeralToken, wrongKey);
      expect(payload).toBeNull();
    });

    it("rejects expired token", () => {
      // Generate a token that's already expired by mocking time
      vi.useFakeTimers();
      const now = Date.now();
      vi.setSystemTime(now);

      const ephemeralToken = generateEphemeralToken(userId, permanentToken, 300);

      // Advance time past expiration
      vi.setSystemTime(now + 400 * 1000);

      const payload = validateEphemeralToken(ephemeralToken, permanentToken);
      expect(payload).toBeNull();

      vi.useRealTimers();
    });

    it("rejects tampered payload", () => {
      const ephemeralToken = generateEphemeralToken(userId, permanentToken);
      const decoded = JSON.parse(Buffer.from(ephemeralToken, "base64url").toString("utf8"));

      // Tamper with userId
      decoded.payload.userId = "different-user";
      const tampered = Buffer.from(JSON.stringify(decoded)).toString("base64url");

      const payload = validateEphemeralToken(tampered, permanentToken);
      expect(payload).toBeNull();
    });

    it("rejects invalid base64", () => {
      expect(validateEphemeralToken("not-valid-base64!!!", permanentToken)).toBeNull();
    });

    it("rejects null/empty inputs", () => {
      const ephemeralToken = generateEphemeralToken(userId, permanentToken);

      expect(validateEphemeralToken(null, permanentToken)).toBeNull();
      expect(validateEphemeralToken(ephemeralToken, null)).toBeNull();
      expect(validateEphemeralToken("", permanentToken)).toBeNull();
    });
  });

  describe("detectTokenType", () => {
    it("detects permanent tokens", () => {
      const permanent = generatePermanentToken();
      expect(detectTokenType(permanent)).toBe("permanent");
    });

    it("detects ephemeral tokens", () => {
      const permanent = generatePermanentToken();
      const ephemeral = generateEphemeralToken("user-id", permanent);
      expect(detectTokenType(ephemeral)).toBe("ephemeral");
    });

    it("returns unknown for invalid input", () => {
      expect(detectTokenType(null)).toBe("unknown");
      expect(detectTokenType("")).toBe("unknown");
      expect(detectTokenType("short")).toBe("unknown");
      expect(detectTokenType("not-hex-not-base64!!!")).toBe("unknown");
    });
  });

  describe("getTokenExpiry", () => {
    const userId = "test-user-789";
    const permanentToken = generatePermanentToken();

    it("returns remaining seconds for valid token", () => {
      const ephemeralToken = generateEphemeralToken(userId, permanentToken, 3600);
      const expiry = getTokenExpiry(ephemeralToken);

      // Should be close to 3600, allowing for some execution time
      expect(expiry).toBeGreaterThan(3595);
      expect(expiry).toBeLessThanOrEqual(3600);
    });

    it("returns 0 for expired token", () => {
      vi.useFakeTimers();
      const now = Date.now();
      vi.setSystemTime(now);

      const ephemeralToken = generateEphemeralToken(userId, permanentToken, 300);

      vi.setSystemTime(now + 400 * 1000);

      expect(getTokenExpiry(ephemeralToken)).toBe(0);

      vi.useRealTimers();
    });

    it("returns 0 for invalid token", () => {
      expect(getTokenExpiry(null)).toBe(0);
      expect(getTokenExpiry("")).toBe(0);
      expect(getTokenExpiry("invalid")).toBe(0);
    });
  });

  describe("needsRefresh", () => {
    const userId = "test-user-abc";
    const permanentToken = generatePermanentToken();

    it("returns false for fresh token", () => {
      const ephemeralToken = generateEphemeralToken(userId, permanentToken, 3600);
      expect(needsRefresh(ephemeralToken)).toBe(false);
    });

    it("returns true when near expiration", () => {
      vi.useFakeTimers();
      const now = Date.now();
      vi.setSystemTime(now);

      const ephemeralToken = generateEphemeralToken(userId, permanentToken, 600);

      // Advance to 4 minutes remaining (below 5 min threshold)
      vi.setSystemTime(now + 360 * 1000);

      expect(needsRefresh(ephemeralToken)).toBe(true);

      vi.useRealTimers();
    });

    it("respects custom threshold", () => {
      vi.useFakeTimers();
      const now = Date.now();
      vi.setSystemTime(now);

      const ephemeralToken = generateEphemeralToken(userId, permanentToken, 600);

      // 8 minutes remaining
      vi.setSystemTime(now + 120 * 1000);

      // Default threshold (5 min) - should not need refresh
      expect(needsRefresh(ephemeralToken)).toBe(false);

      // Custom threshold (10 min) - should need refresh
      expect(needsRefresh(ephemeralToken, 600)).toBe(true);

      vi.useRealTimers();
    });
  });
});
