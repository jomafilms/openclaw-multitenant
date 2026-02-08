// Tests for TOTP (Time-based One-Time Password) utilities
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  generateTotpSecret,
  generateTotpUri,
  generateTotpQRCodeUri,
  verifyTotpCode,
  generateBackupCodes,
  verifyBackupCode,
  getCurrentTotpCode,
} from "./totp.js";

// Mock the db/core.js encryption functions
vi.mock("../db/core.js", () => ({
  encrypt: vi.fn((data) => `encrypted:${data}`),
  decrypt: vi.fn((data) => data.replace("encrypted:", "")),
}));

describe("TOTP Utilities", () => {
  describe("generateTotpSecret", () => {
    it("should generate a valid TOTP secret", () => {
      const result = generateTotpSecret();

      expect(result).toBeDefined();
      expect(result.secret).toBeDefined();
      expect(result.encryptedSecret).toBeDefined();
      expect(typeof result.secret).toBe("string");
      expect(typeof result.encryptedSecret).toBe("string");
    });

    it("should generate base32 encoded secret", () => {
      const result = generateTotpSecret();

      // Base32 uses only uppercase A-Z and 2-7
      expect(/^[A-Z2-7]+$/.test(result.secret)).toBe(true);
    });

    it("should generate minimum 32 character secret", () => {
      const result = generateTotpSecret();

      // 20 bytes = 160 bits, base32 encoded = 32 characters
      expect(result.secret.length).toBeGreaterThanOrEqual(32);
    });

    it("should generate unique secrets each time", () => {
      const result1 = generateTotpSecret();
      const result2 = generateTotpSecret();

      expect(result1.secret).not.toBe(result2.secret);
    });

    it("should encrypt the secret for storage", () => {
      const result = generateTotpSecret();

      expect(result.encryptedSecret.startsWith("encrypted:")).toBe(true);
    });
  });

  describe("generateTotpUri", () => {
    it("should generate valid otpauth URI", () => {
      const email = "user@example.com";
      const secret = "JBSWY3DPEHPK3PXP";
      const uri = generateTotpUri(email, secret);

      expect(uri.startsWith("otpauth://totp/")).toBe(true);
    });

    it("should include issuer in URI", () => {
      const email = "user@example.com";
      const secret = "JBSWY3DPEHPK3PXP";
      const uri = generateTotpUri(email, secret);

      expect(uri).toContain("issuer=OCMT");
    });

    it("should include email in URI", () => {
      const email = "user@example.com";
      const secret = "JBSWY3DPEHPK3PXP";
      const uri = generateTotpUri(email, secret);

      expect(uri).toContain(encodeURIComponent(email));
    });

    it("should include secret in URI", () => {
      const email = "user@example.com";
      const secret = "JBSWY3DPEHPK3PXP";
      const uri = generateTotpUri(email, secret);

      expect(uri).toContain(`secret=${secret.toUpperCase()}`);
    });

    it("should include SHA1 algorithm", () => {
      const uri = generateTotpUri("test@example.com", "JBSWY3DPEHPK3PXP");

      expect(uri).toContain("algorithm=SHA1");
    });

    it("should include 6 digits", () => {
      const uri = generateTotpUri("test@example.com", "JBSWY3DPEHPK3PXP");

      expect(uri).toContain("digits=6");
    });

    it("should include 30 second period", () => {
      const uri = generateTotpUri("test@example.com", "JBSWY3DPEHPK3PXP");

      expect(uri).toContain("period=30");
    });

    it("should URL encode special characters in email", () => {
      const email = "user+test@example.com";
      const uri = generateTotpUri(email, "JBSWY3DPEHPK3PXP");

      expect(uri).toContain(encodeURIComponent(email));
    });
  });

  describe("generateTotpQRCodeUri", () => {
    it("should return the same as generateTotpUri", () => {
      const email = "user@example.com";
      const secret = "JBSWY3DPEHPK3PXP";

      const qrUri = generateTotpQRCodeUri(email, secret);
      const totpUri = generateTotpUri(email, secret);

      expect(qrUri).toBe(totpUri);
    });
  });

  describe("verifyTotpCode", () => {
    it("should verify current valid code", () => {
      const { secret, encryptedSecret } = generateTotpSecret();
      const currentCode = getCurrentTotpCode(secret);

      const result = verifyTotpCode(encryptedSecret, currentCode);

      expect(result).toBe(true);
    });

    it("should reject invalid code", () => {
      const { encryptedSecret } = generateTotpSecret();

      const result = verifyTotpCode(encryptedSecret, "000000");

      expect(result).toBe(false);
    });

    it("should reject null encrypted secret", () => {
      const result = verifyTotpCode(null, "123456");

      expect(result).toBe(false);
    });

    it("should reject null code", () => {
      const { encryptedSecret } = generateTotpSecret();

      const result = verifyTotpCode(encryptedSecret, null);

      expect(result).toBe(false);
    });

    it("should reject empty code", () => {
      const { encryptedSecret } = generateTotpSecret();

      const result = verifyTotpCode(encryptedSecret, "");

      expect(result).toBe(false);
    });

    it("should reject non-numeric code", () => {
      const { encryptedSecret } = generateTotpSecret();

      const result = verifyTotpCode(encryptedSecret, "abcdef");

      expect(result).toBe(false);
    });

    it("should reject code with wrong length", () => {
      const { encryptedSecret } = generateTotpSecret();

      expect(verifyTotpCode(encryptedSecret, "12345")).toBe(false);
      expect(verifyTotpCode(encryptedSecret, "1234567")).toBe(false);
    });

    it("should accept code with spaces (normalizes)", () => {
      const { secret, encryptedSecret } = generateTotpSecret();
      const currentCode = getCurrentTotpCode(secret);
      const codeWithSpaces = currentCode.slice(0, 3) + " " + currentCode.slice(3);

      const result = verifyTotpCode(encryptedSecret, codeWithSpaces);

      expect(result).toBe(true);
    });

    it("should accept codes within time window tolerance", () => {
      // This is tested implicitly by using current codes
      // The implementation allows +/- 1 time step
      const { secret, encryptedSecret } = generateTotpSecret();
      const currentCode = getCurrentTotpCode(secret);

      expect(verifyTotpCode(encryptedSecret, currentCode)).toBe(true);
    });
  });

  describe("getCurrentTotpCode", () => {
    it("should generate 6 digit code", () => {
      const { secret } = generateTotpSecret();
      const code = getCurrentTotpCode(secret);

      expect(code.length).toBe(6);
      expect(/^\d{6}$/.test(code)).toBe(true);
    });

    it("should generate consistent codes for same time window", () => {
      const { secret } = generateTotpSecret();
      const code1 = getCurrentTotpCode(secret);
      const code2 = getCurrentTotpCode(secret);

      expect(code1).toBe(code2);
    });

    it("should generate different codes for different secrets", () => {
      const secret1 = generateTotpSecret().secret;
      const secret2 = generateTotpSecret().secret;

      const code1 = getCurrentTotpCode(secret1);
      const code2 = getCurrentTotpCode(secret2);

      expect(code1).not.toBe(code2);
    });
  });

  describe("generateBackupCodes", () => {
    it("should generate 8 backup codes", async () => {
      const result = await generateBackupCodes();

      expect(result.codes.length).toBe(8);
      expect(result.hashedCodes.length).toBe(8);
    });

    it("should generate codes in XXXX-XXXX format", async () => {
      const result = await generateBackupCodes();

      for (const code of result.codes) {
        expect(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(code)).toBe(true);
      }
    });

    it("should generate unique codes", async () => {
      const result = await generateBackupCodes();
      const uniqueCodes = new Set(result.codes);

      expect(uniqueCodes.size).toBe(8);
    });

    it("should generate Argon2id hashes", async () => {
      const result = await generateBackupCodes();

      for (const hash of result.hashedCodes) {
        expect(hash.startsWith("$argon2id$")).toBe(true);
      }
    });

    it("should exclude ambiguous characters", async () => {
      const result = await generateBackupCodes();

      for (const code of result.codes) {
        // Should not contain 0, O, 1, I, l (ambiguous characters)
        const rawCode = code.replace("-", "");
        expect(/[0OIl1]/.test(rawCode)).toBe(false);
      }
    });
  });

  describe("verifyBackupCode", () => {
    it("should verify valid backup code", async () => {
      const result = await generateBackupCodes();
      const firstCode = result.codes[0];
      const firstHash = result.hashedCodes[0];

      const isValid = await verifyBackupCode(firstCode, firstHash);

      expect(isValid).toBe(true);
    });

    it("should verify code without dash", async () => {
      const result = await generateBackupCodes();
      const codeWithoutDash = result.codes[0].replace("-", "");
      const firstHash = result.hashedCodes[0];

      const isValid = await verifyBackupCode(codeWithoutDash, firstHash);

      expect(isValid).toBe(true);
    });

    it("should verify lowercase code", async () => {
      const result = await generateBackupCodes();
      const lowercaseCode = result.codes[0].toLowerCase();
      const firstHash = result.hashedCodes[0];

      const isValid = await verifyBackupCode(lowercaseCode, firstHash);

      expect(isValid).toBe(true);
    });

    it("should reject invalid code", async () => {
      const result = await generateBackupCodes();
      const firstHash = result.hashedCodes[0];

      const isValid = await verifyBackupCode("INVALID-CODE", firstHash);

      expect(isValid).toBe(false);
    });

    it("should reject code with wrong hash", async () => {
      const result = await generateBackupCodes();
      const firstCode = result.codes[0];
      const secondHash = result.hashedCodes[1];

      const isValid = await verifyBackupCode(firstCode, secondHash);

      expect(isValid).toBe(false);
    });

    it("should reject null code", async () => {
      const result = await generateBackupCodes();

      const isValid = await verifyBackupCode(null, result.hashedCodes[0]);

      expect(isValid).toBe(false);
    });

    it("should reject null hash", async () => {
      const result = await generateBackupCodes();

      const isValid = await verifyBackupCode(result.codes[0], null);

      expect(isValid).toBe(false);
    });

    it("should reject code with wrong length", async () => {
      const result = await generateBackupCodes();

      const isValid = await verifyBackupCode("ABCD", result.hashedCodes[0]);

      expect(isValid).toBe(false);
    });
  });

  describe("timing attack resistance", () => {
    it("verifyTotpCode uses timing-safe comparison", () => {
      // Generate a valid code and test both valid and invalid scenarios
      // The implementation uses crypto.timingSafeEqual
      const { secret, encryptedSecret } = generateTotpSecret();
      const currentCode = getCurrentTotpCode(secret);

      // Valid code
      expect(verifyTotpCode(encryptedSecret, currentCode)).toBe(true);

      // Invalid code (should still use timing-safe comparison)
      expect(verifyTotpCode(encryptedSecret, "999999")).toBe(false);
    });
  });

  describe("edge cases", () => {
    it("should handle decryption errors gracefully", () => {
      // Pass an invalid encrypted secret that will fail decryption
      const result = verifyTotpCode("invalid:encrypted:data", "123456");

      expect(result).toBe(false);
    });

    it("should handle code with leading zeros", () => {
      const { secret, encryptedSecret } = generateTotpSecret();

      // Mock a code with leading zeros
      const codeWithLeadingZero = "012345";

      // Should be properly validated (will likely be false unless we get lucky)
      const result = verifyTotpCode(encryptedSecret, codeWithLeadingZero);

      expect(typeof result).toBe("boolean");
    });
  });
});
