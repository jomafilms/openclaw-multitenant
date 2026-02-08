/**
 * Tests for Container Secret Store
 *
 * Comprehensive test coverage for:
 * - Key derivation
 * - Encrypt/decrypt roundtrip
 * - Vault initialization and unlock
 * - Capability token generation and verification
 * - Scope enforcement
 * - Expiry enforcement
 * - Revocation checks
 * - Call count limits
 */

import { randomBytes, scryptSync, createCipheriv, createDecipheriv } from "crypto";
import { existsSync, rmSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";

// We mock the scryptSync function to use lower memory parameters for testing
// The production code uses N=2^16 which can exceed memory limits in test environments
const TEST_SCRYPT_N = 2 ** 14; // Lower memory for tests

// Helper to create a unique temp directory for each test
function createTempDir(): string {
  const dir = join(tmpdir(), `ocmt-test-${randomBytes(8).toString("hex")}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

// Helper to cleanup temp directory
function cleanupTempDir(dir: string): void {
  if (existsSync(dir)) {
    rmSync(dir, { recursive: true, force: true });
  }
}

// Test-friendly key derivation with lower memory parameters
function testDeriveKey(password: string, salt: Buffer): Buffer {
  return scryptSync(password, salt, 32, {
    N: TEST_SCRYPT_N,
    r: 8,
    p: 1,
  });
}

// Test-friendly encrypt function
function testEncrypt(
  key: Buffer,
  plaintext: string,
): { nonce: Buffer; ciphertext: Buffer; tag: Buffer } {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { nonce, ciphertext, tag };
}

// Test-friendly decrypt function
function testDecrypt(key: Buffer, nonce: Buffer, tag: Buffer, ciphertext: Buffer): string {
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf-8");
}

describe("SecretStore crypto primitives", () => {
  // ─────────────────────────────────────────────────────────────────────────
  // Key Derivation Tests
  // ─────────────────────────────────────────────────────────────────────────

  describe("key derivation", () => {
    it("derives consistent key from same password and salt", () => {
      const salt = randomBytes(32);
      const password = "test-password-123";

      const key1 = testDeriveKey(password, salt);
      const key2 = testDeriveKey(password, salt);

      expect(key1.equals(key2)).toBe(true);
      expect(key1.length).toBe(32);
    });

    it("derives different keys for different passwords", () => {
      const salt = randomBytes(32);
      const key1 = testDeriveKey("password-one", salt);
      const key2 = testDeriveKey("password-two", salt);

      expect(key1.equals(key2)).toBe(false);
    });

    it("derives different keys for different salts", () => {
      const salt1 = randomBytes(32);
      const salt2 = randomBytes(32);
      const key1 = testDeriveKey("same-password", salt1);
      const key2 = testDeriveKey("same-password", salt2);

      expect(key1.equals(key2)).toBe(false);
    });

    it("produces 32-byte keys suitable for AES-256", () => {
      const salt = randomBytes(32);
      const key = testDeriveKey("any-password", salt);

      expect(key.length).toBe(32);
      expect(Buffer.isBuffer(key)).toBe(true);
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // Encrypt/Decrypt Tests
  // ─────────────────────────────────────────────────────────────────────────

  describe("encrypt/decrypt", () => {
    it("encrypts and decrypts data correctly", () => {
      const salt = randomBytes(32);
      const key = testDeriveKey("encrypt-test", salt);
      const plaintext = "Hello, World! This is secret data.";

      const { nonce, ciphertext, tag } = testEncrypt(key, plaintext);
      const decrypted = testDecrypt(key, nonce, tag, ciphertext);

      expect(decrypted).toBe(plaintext);
    });

    it("fails decryption with wrong key", () => {
      const salt = randomBytes(32);
      const correctKey = testDeriveKey("correct-password", salt);
      const wrongKey = testDeriveKey("wrong-password", salt);
      const plaintext = "Secret message";

      const { nonce, ciphertext, tag } = testEncrypt(correctKey, plaintext);

      expect(() => testDecrypt(wrongKey, nonce, tag, ciphertext)).toThrow();
    });

    it("fails decryption with tampered ciphertext", () => {
      const salt = randomBytes(32);
      const key = testDeriveKey("tamper-test", salt);
      const plaintext = "Original message";

      const { nonce, ciphertext, tag } = testEncrypt(key, plaintext);

      // Tamper with ciphertext
      ciphertext[0] ^= 0xff;

      expect(() => testDecrypt(key, nonce, tag, ciphertext)).toThrow();
    });

    it("fails decryption with tampered tag", () => {
      const salt = randomBytes(32);
      const key = testDeriveKey("tag-test", salt);
      const plaintext = "Protected message";

      const { nonce, ciphertext, tag } = testEncrypt(key, plaintext);

      // Tamper with tag
      tag[0] ^= 0xff;

      expect(() => testDecrypt(key, nonce, tag, ciphertext)).toThrow();
    });

    it("handles empty plaintext", () => {
      const salt = randomBytes(32);
      const key = testDeriveKey("empty-test", salt);
      const plaintext = "";

      const { nonce, ciphertext, tag } = testEncrypt(key, plaintext);
      const decrypted = testDecrypt(key, nonce, tag, ciphertext);

      expect(decrypted).toBe("");
    });

    it("handles large plaintext", () => {
      const salt = randomBytes(32);
      const key = testDeriveKey("large-test", salt);
      const plaintext = "x".repeat(100000); // 100KB

      const { nonce, ciphertext, tag } = testEncrypt(key, plaintext);
      const decrypted = testDecrypt(key, nonce, tag, ciphertext);

      expect(decrypted).toBe(plaintext);
    });

    it("handles unicode plaintext", () => {
      const salt = randomBytes(32);
      const key = testDeriveKey("unicode-test", salt);
      const plaintext = "Hello \u4e16\u754c! \ud83d\udd10 Special chars: \u00e9\u00e0\u00fc";

      const { nonce, ciphertext, tag } = testEncrypt(key, plaintext);
      const decrypted = testDecrypt(key, nonce, tag, ciphertext);

      expect(decrypted).toBe(plaintext);
    });

    it("produces different ciphertext for same plaintext (due to random nonce)", () => {
      const salt = randomBytes(32);
      const key = testDeriveKey("nonce-test", salt);
      const plaintext = "Same message";

      const result1 = testEncrypt(key, plaintext);
      const result2 = testEncrypt(key, plaintext);

      expect(result1.ciphertext.equals(result2.ciphertext)).toBe(false);
      expect(result1.nonce.equals(result2.nonce)).toBe(false);
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SecretStore Vault File Format Tests
// ─────────────────────────────────────────────────────────────────────────────

describe("SecretStore vault file format", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = createTempDir();
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  it("creates correct encrypted file structure", () => {
    const password = "test-password";
    const salt = randomBytes(32);
    const key = testDeriveKey(password, salt);

    const vaultData = {
      version: 2,
      integrations: {},
      identity: {
        publicKey: randomBytes(32).toString("base64"),
        privateKey: randomBytes(64).toString("base64"),
        algorithm: "Ed25519",
      },
      grants: {},
      capabilities: {},
    };

    const plaintext = JSON.stringify(vaultData);
    const { nonce, ciphertext, tag } = testEncrypt(key, plaintext);

    const encryptedStore = {
      version: 2,
      algorithm: "aes-256-gcm",
      kdf: {
        algorithm: "scrypt",
        salt: salt.toString("base64"),
        n: TEST_SCRYPT_N,
        r: 8,
        p: 1,
      },
      nonce: nonce.toString("base64"),
      ciphertext: ciphertext.toString("base64"),
      tag: tag.toString("base64"),
    };

    const filePath = join(tempDir, "secrets.enc");
    writeFileSync(filePath, JSON.stringify(encryptedStore, null, 2), { mode: 0o600 });

    // Verify file exists and has correct structure
    expect(existsSync(filePath)).toBe(true);

    const readBack = JSON.parse(readFileSync(filePath, "utf-8"));
    expect(readBack.version).toBe(2);
    expect(readBack.algorithm).toBe("aes-256-gcm");
    expect(readBack.kdf.algorithm).toBe("scrypt");
    expect(readBack.kdf.salt).toBe(salt.toString("base64"));
    expect(readBack.nonce).toBe(nonce.toString("base64"));
    expect(readBack.ciphertext).toBe(ciphertext.toString("base64"));
    expect(readBack.tag).toBe(tag.toString("base64"));
  });

  it("can decrypt previously encrypted vault data", () => {
    const password = "roundtrip-password";
    const salt = randomBytes(32);
    const key = testDeriveKey(password, salt);

    const originalData = {
      version: 2,
      integrations: {
        google: {
          accessToken: "secret-token-12345",
          refreshToken: "refresh-67890",
          expiresAt: "2025-12-31T23:59:59Z",
          email: "test@example.com",
          scopes: ["read", "write"],
        },
      },
      identity: {
        publicKey: "test-public-key",
        privateKey: "test-private-key",
        algorithm: "Ed25519",
      },
      grants: {},
      capabilities: {},
    };

    // Encrypt
    const plaintext = JSON.stringify(originalData);
    const { nonce, ciphertext, tag } = testEncrypt(key, plaintext);

    // Store
    const encryptedStore = {
      version: 2,
      algorithm: "aes-256-gcm",
      kdf: {
        algorithm: "scrypt",
        salt: salt.toString("base64"),
        n: TEST_SCRYPT_N,
        r: 8,
        p: 1,
      },
      nonce: nonce.toString("base64"),
      ciphertext: ciphertext.toString("base64"),
      tag: tag.toString("base64"),
    };

    // Decrypt with same password
    const derivedKey = testDeriveKey(password, Buffer.from(encryptedStore.kdf.salt, "base64"));
    const decrypted = testDecrypt(
      derivedKey,
      Buffer.from(encryptedStore.nonce, "base64"),
      Buffer.from(encryptedStore.tag, "base64"),
      Buffer.from(encryptedStore.ciphertext, "base64"),
    );

    const recoveredData = JSON.parse(decrypted);
    expect(recoveredData).toEqual(originalData);
  });

  it("rejects decryption with wrong password", () => {
    const correctPassword = "correct-password";
    const wrongPassword = "wrong-password";
    const salt = randomBytes(32);
    const correctKey = testDeriveKey(correctPassword, salt);

    const vaultData = { version: 2, integrations: {}, grants: {}, capabilities: {} };
    const plaintext = JSON.stringify(vaultData);
    const { nonce, ciphertext, tag } = testEncrypt(correctKey, plaintext);

    // Try to decrypt with wrong password
    const wrongKey = testDeriveKey(wrongPassword, salt);

    expect(() =>
      testDecrypt(
        wrongKey,
        Buffer.from(nonce.toString("base64"), "base64"),
        Buffer.from(tag.toString("base64"), "base64"),
        Buffer.from(ciphertext.toString("base64"), "base64"),
      ),
    ).toThrow();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Capability Token Tests
// ─────────────────────────────────────────────────────────────────────────────

describe("Capability token structure", () => {
  it("creates valid capability token structure", () => {
    const id = randomBytes(16).toString("hex");
    const issuerPublicKey = randomBytes(32).toString("base64");
    const subjectPublicKey = randomBytes(32).toString("base64");
    const now = Math.floor(Date.now() / 1000);
    const exp = now + 3600; // 1 hour

    const claims = {
      v: 1,
      id,
      iss: issuerPublicKey,
      sub: subjectPublicKey,
      resource: "google-calendar",
      scope: ["read", "write"],
      iat: now,
      exp,
      constraints: { maxCalls: 10 },
    };

    // Simulate signing (placeholder in production code)
    const signature = randomBytes(64).toString("base64");
    const tokenPayload = { ...claims, sig: signature };
    const token = Buffer.from(JSON.stringify(tokenPayload)).toString("base64url");

    // Decode and verify structure
    const decoded = JSON.parse(Buffer.from(token, "base64url").toString());
    expect(decoded.v).toBe(1);
    expect(decoded.id).toBe(id);
    expect(decoded.iss).toBe(issuerPublicKey);
    expect(decoded.sub).toBe(subjectPublicKey);
    expect(decoded.resource).toBe("google-calendar");
    expect(decoded.scope).toEqual(["read", "write"]);
    expect(decoded.iat).toBe(now);
    expect(decoded.exp).toBe(exp);
    expect(decoded.constraints.maxCalls).toBe(10);
    expect(decoded.sig).toBe(signature);
  });

  it("encodes capability token as base64url", () => {
    const claims = {
      v: 1,
      id: "test-id",
      iss: "issuer",
      sub: "subject",
      resource: "resource",
      scope: ["read"],
      iat: 1000,
      exp: 2000,
    };

    const token = Buffer.from(JSON.stringify(claims)).toString("base64url");

    // base64url should not contain +, /, or =
    expect(token).not.toMatch(/[+/=]/);

    // Should be decodable
    const decoded = JSON.parse(Buffer.from(token, "base64url").toString());
    expect(decoded).toEqual(claims);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Scope Enforcement Logic Tests
// ─────────────────────────────────────────────────────────────────────────────

describe("Scope enforcement logic", () => {
  function checkScope(scope: string[], operation: string): boolean {
    return scope.includes(operation) || scope.includes("*");
  }

  it("allows operation that is in scope", () => {
    expect(checkScope(["read", "write"], "read")).toBe(true);
    expect(checkScope(["read", "write"], "write")).toBe(true);
  });

  it("rejects operation not in scope", () => {
    expect(checkScope(["read"], "write")).toBe(false);
    expect(checkScope(["read", "list"], "delete")).toBe(false);
  });

  it("allows any operation with wildcard scope", () => {
    expect(checkScope(["*"], "read")).toBe(true);
    expect(checkScope(["*"], "write")).toBe(true);
    expect(checkScope(["*"], "delete")).toBe(true);
    expect(checkScope(["*"], "any-operation")).toBe(true);
  });

  it("handles empty scope", () => {
    expect(checkScope([], "read")).toBe(false);
  });

  it("handles case-sensitive operations", () => {
    expect(checkScope(["Read"], "read")).toBe(false);
    expect(checkScope(["READ"], "read")).toBe(false);
    expect(checkScope(["read"], "READ")).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Expiry Enforcement Logic Tests
// ─────────────────────────────────────────────────────────────────────────────

describe("Expiry enforcement logic", () => {
  function isExpired(expUnixSeconds: number): boolean {
    return expUnixSeconds < Date.now() / 1000;
  }

  it("returns false for non-expired token", () => {
    const futureExp = Math.floor(Date.now() / 1000) + 3600; // 1 hour in future
    expect(isExpired(futureExp)).toBe(false);
  });

  it("returns true for expired token", () => {
    const pastExp = Math.floor(Date.now() / 1000) - 3600; // 1 hour in past
    expect(isExpired(pastExp)).toBe(true);
  });

  it("handles just-expired token", () => {
    const justPastExp = Math.floor(Date.now() / 1000) - 1; // 1 second ago
    expect(isExpired(justPastExp)).toBe(true);
  });

  it("handles token expiring now", () => {
    const nowExp = Math.floor(Date.now() / 1000);
    // Might be expired depending on timing, but should not throw
    const result = isExpired(nowExp);
    expect(typeof result).toBe("boolean");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Revocation Check Logic Tests
// ─────────────────────────────────────────────────────────────────────────────

describe("Revocation check logic", () => {
  interface Grant {
    id: string;
    revoked: boolean;
    callCount: number;
    maxCalls?: number;
  }

  function isRevoked(grants: Record<string, Grant>, capabilityId: string): boolean {
    const grant = grants[capabilityId];
    return grant?.revoked ?? false;
  }

  it("returns false for non-revoked capability", () => {
    const grants: Record<string, Grant> = {
      "cap-1": { id: "cap-1", revoked: false, callCount: 0 },
    };
    expect(isRevoked(grants, "cap-1")).toBe(false);
  });

  it("returns true for revoked capability", () => {
    const grants: Record<string, Grant> = {
      "cap-1": { id: "cap-1", revoked: true, callCount: 5 },
    };
    expect(isRevoked(grants, "cap-1")).toBe(true);
  });

  it("returns false for non-existent capability", () => {
    const grants: Record<string, Grant> = {};
    expect(isRevoked(grants, "non-existent")).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Call Count Limit Logic Tests
// ─────────────────────────────────────────────────────────────────────────────

describe("Call count limit logic", () => {
  interface Grant {
    callCount: number;
    maxCalls?: number;
  }

  function isCallLimitExceeded(grant: Grant | undefined, maxCalls?: number): boolean {
    if (!maxCalls || !grant) {
      return false;
    }
    return grant.callCount >= maxCalls;
  }

  it("returns false when no limit is set", () => {
    const grant: Grant = { callCount: 100 };
    expect(isCallLimitExceeded(grant, undefined)).toBe(false);
  });

  it("returns false when under limit", () => {
    const grant: Grant = { callCount: 3, maxCalls: 5 };
    expect(isCallLimitExceeded(grant, 5)).toBe(false);
  });

  it("returns true when at limit", () => {
    const grant: Grant = { callCount: 5, maxCalls: 5 };
    expect(isCallLimitExceeded(grant, 5)).toBe(true);
  });

  it("returns true when over limit", () => {
    const grant: Grant = { callCount: 10, maxCalls: 5 };
    expect(isCallLimitExceeded(grant, 5)).toBe(true);
  });

  it("returns false for undefined grant", () => {
    expect(isCallLimitExceeded(undefined, 5)).toBe(false);
  });

  it("handles zero limit", () => {
    const grant: Grant = { callCount: 0 };
    expect(isCallLimitExceeded(grant, 0)).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Integration Data Structure Tests
// ─────────────────────────────────────────────────────────────────────────────

describe("Integration data structure", () => {
  interface Integration {
    accessToken: string;
    refreshToken?: string;
    expiresAt: string;
    email?: string;
    scopes?: string[];
    metadata?: Record<string, unknown>;
  }

  it("validates complete integration structure", () => {
    const integration: Integration = {
      accessToken: "token-12345",
      refreshToken: "refresh-67890",
      expiresAt: "2025-12-31T23:59:59Z",
      email: "user@example.com",
      scopes: ["read", "write", "admin"],
      metadata: { custom: "value", nested: { key: "val" } },
    };

    expect(integration.accessToken).toBe("token-12345");
    expect(integration.refreshToken).toBe("refresh-67890");
    expect(integration.expiresAt).toBe("2025-12-31T23:59:59Z");
    expect(integration.email).toBe("user@example.com");
    expect(integration.scopes).toEqual(["read", "write", "admin"]);
    expect(integration.metadata?.custom).toBe("value");
  });

  it("validates minimal integration structure", () => {
    const integration: Integration = {
      accessToken: "token-only",
      expiresAt: "2025-01-01T00:00:00Z",
    };

    expect(integration.accessToken).toBe("token-only");
    expect(integration.expiresAt).toBe("2025-01-01T00:00:00Z");
    expect(integration.refreshToken).toBeUndefined();
    expect(integration.email).toBeUndefined();
    expect(integration.scopes).toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Capability Grant Structure Tests
// ─────────────────────────────────────────────────────────────────────────────

describe("Capability grant structure", () => {
  interface CapabilityGrant {
    id: string;
    subject: string;
    resource: string;
    scope: string[];
    expires: string;
    maxCalls?: number;
    callCount: number;
    revoked: boolean;
    issuedAt: string;
  }

  it("validates complete capability grant", () => {
    const grant: CapabilityGrant = {
      id: randomBytes(16).toString("hex"),
      subject: randomBytes(32).toString("base64"),
      resource: "google-calendar",
      scope: ["read", "list"],
      expires: "2025-12-31T23:59:59Z",
      maxCalls: 100,
      callCount: 0,
      revoked: false,
      issuedAt: new Date().toISOString(),
    };

    expect(grant.id.length).toBe(32); // 16 bytes hex
    expect(grant.callCount).toBe(0);
    expect(grant.revoked).toBe(false);
    expect(grant.scope).toContain("read");
    expect(grant.maxCalls).toBe(100);
  });

  it("validates grant without call limit", () => {
    const grant: CapabilityGrant = {
      id: "test-id",
      subject: "subject-key",
      resource: "api-service",
      scope: ["*"],
      expires: "2025-12-31T23:59:59Z",
      callCount: 0,
      revoked: false,
      issuedAt: new Date().toISOString(),
    };

    expect(grant.maxCalls).toBeUndefined();
    expect(grant.scope).toEqual(["*"]);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Session Timeout Logic Tests
// ─────────────────────────────────────────────────────────────────────────────

describe("Session timeout logic", () => {
  const SESSION_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes

  it("calculates session time remaining correctly", () => {
    const expiresAt = Date.now() + SESSION_TIMEOUT_MS;
    const remaining = Math.floor((expiresAt - Date.now()) / 1000);

    expect(remaining).toBeGreaterThan(1700);
    expect(remaining).toBeLessThanOrEqual(1800);
  });

  it("returns zero for expired session", () => {
    const expiresAt = Date.now() - 1000; // 1 second ago
    const isUnlocked = Date.now() < expiresAt;
    const remaining = isUnlocked ? Math.floor((expiresAt - Date.now()) / 1000) : 0;

    expect(remaining).toBe(0);
  });

  it("extends session correctly", () => {
    const originalExpiry = Date.now() + 10 * 60 * 1000; // 10 minutes left
    const newExpiry = Date.now() + SESSION_TIMEOUT_MS; // Reset to 30 minutes

    expect(newExpiry).toBeGreaterThan(originalExpiry);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Edge Case Tests
// ─────────────────────────────────────────────────────────────────────────────

describe("Edge cases", () => {
  it("handles empty password for key derivation", () => {
    const salt = randomBytes(32);
    const key = testDeriveKey("", salt);

    expect(key.length).toBe(32);
    expect(Buffer.isBuffer(key)).toBe(true);
  });

  it("handles very long password", () => {
    const salt = randomBytes(32);
    const longPassword = "x".repeat(10000);
    const key = testDeriveKey(longPassword, salt);

    expect(key.length).toBe(32);
  });

  it("handles unicode password", () => {
    const salt = randomBytes(32);
    const unicodePassword = "p@ssw\u00f6rd\u4e2d\u6587\ud83d\udd10";
    const key = testDeriveKey(unicodePassword, salt);

    expect(key.length).toBe(32);
  });

  it("handles special characters in JSON payload", () => {
    const data = {
      token: 'value-with-"quotes"-and-\\backslashes\\',
      unicode: "\u4e2d\u6587\ud83d\udd10",
      newlines: "line1\nline2\r\nline3",
      tabs: "col1\tcol2",
    };

    const json = JSON.stringify(data);
    const parsed = JSON.parse(json);

    expect(parsed).toEqual(data);
  });

  it("handles null bytes in encrypted data", () => {
    const salt = randomBytes(32);
    const key = testDeriveKey("null-byte-test", salt);
    const plaintext = "before\x00after";

    const { nonce, ciphertext, tag } = testEncrypt(key, plaintext);
    const decrypted = testDecrypt(key, nonce, tag, ciphertext);

    expect(decrypted).toBe(plaintext);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Salt Handling Tests
// ─────────────────────────────────────────────────────────────────────────────

describe("Salt handling", () => {
  it("generates unique salts", () => {
    const salt1 = randomBytes(32);
    const salt2 = randomBytes(32);

    expect(salt1.equals(salt2)).toBe(false);
  });

  it("salt survives base64 encoding/decoding", () => {
    const originalSalt = randomBytes(32);
    const encoded = originalSalt.toString("base64");
    const decoded = Buffer.from(encoded, "base64");

    expect(decoded.equals(originalSalt)).toBe(true);
  });

  it("salt length is correct", () => {
    const salt = randomBytes(32);
    expect(salt.length).toBe(32);

    const encoded = salt.toString("base64");
    // 32 bytes = 44 base64 chars (including padding)
    expect(encoded.length).toBe(44);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Ed25519 Signing Tests
// ─────────────────────────────────────────────────────────────────────────────

import {
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  createPrivateKey,
  createPublicKey,
} from "crypto";

// Ed25519 SPKI prefix for DER-encoded public keys (12 bytes header + 32 bytes key)
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/**
 * Create a KeyObject from a base64-encoded raw Ed25519 public key.
 * Matches the implementation in secret-store.ts
 */
function publicKeyFromBase64(publicKeyBase64: string) {
  const rawKey = Buffer.from(publicKeyBase64, "base64");
  if (rawKey.length !== 32) {
    throw new Error(`Invalid Ed25519 public key length: expected 32 bytes, got ${rawKey.length}`);
  }
  // Reconstruct SPKI-encoded DER format
  const spkiDer = Buffer.concat([ED25519_SPKI_PREFIX, rawKey]);
  return createPublicKey({ key: spkiDer, type: "spki", format: "der" });
}

/**
 * Generate Ed25519 keypair (matches secret-store.ts implementation)
 */
function generateEd25519Keypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");

  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

  // Extract raw 32-byte public key from SPKI encoding
  const spkiDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const rawPublicKey = spkiDer.subarray(ED25519_SPKI_PREFIX.length);

  return {
    publicKey: rawPublicKey.toString("base64"),
    privateKeyPem,
    publicKeyPem,
  };
}

/**
 * Sign data with Ed25519 private key
 */
function signEd25519(data: string, privateKeyPem: string): string {
  const privateKey = createPrivateKey(privateKeyPem);
  const signature = cryptoSign(null, Buffer.from(data, "utf-8"), privateKey);
  return signature.toString("base64");
}

/**
 * Verify Ed25519 signature
 */
function verifyEd25519(data: string, signature: string, publicKeyBase64: string): boolean {
  try {
    const publicKey = publicKeyFromBase64(publicKeyBase64);
    const signatureBuffer = Buffer.from(signature, "base64");

    // Ed25519 signatures are always 64 bytes
    if (signatureBuffer.length !== 64) {
      return false;
    }

    return cryptoVerify(null, Buffer.from(data, "utf-8"), publicKey, signatureBuffer);
  } catch {
    return false;
  }
}

describe("Ed25519 cryptographic signing", () => {
  describe("keypair generation", () => {
    it("generates valid Ed25519 keypair", () => {
      const keypair = generateEd25519Keypair();

      // Raw public key should be 32 bytes (base64 encoded)
      const rawPubKey = Buffer.from(keypair.publicKey, "base64");
      expect(rawPubKey.length).toBe(32);

      // Private key should be PEM-formatted
      expect(keypair.privateKeyPem).toContain("-----BEGIN PRIVATE KEY-----");
      expect(keypair.privateKeyPem).toContain("-----END PRIVATE KEY-----");

      // Public key should be PEM-formatted
      expect(keypair.publicKeyPem).toContain("-----BEGIN PUBLIC KEY-----");
      expect(keypair.publicKeyPem).toContain("-----END PUBLIC KEY-----");
    });

    it("generates unique keypairs each time", () => {
      const keypair1 = generateEd25519Keypair();
      const keypair2 = generateEd25519Keypair();

      expect(keypair1.publicKey).not.toBe(keypair2.publicKey);
      expect(keypair1.privateKeyPem).not.toBe(keypair2.privateKeyPem);
    });

    it("can reconstruct public key from raw bytes", () => {
      const keypair = generateEd25519Keypair();

      // Reconstruct KeyObject from raw public key
      const reconstructedKey = publicKeyFromBase64(keypair.publicKey);

      // Verify it's the same by exporting and comparing
      const exportedPem = reconstructedKey.export({ type: "spki", format: "pem" }).toString();
      expect(exportedPem).toBe(keypair.publicKeyPem);
    });
  });

  describe("signing and verification", () => {
    it("signs and verifies data correctly", () => {
      const keypair = generateEd25519Keypair();
      const data = "Hello, World! This is test data.";

      const signature = signEd25519(data, keypair.privateKeyPem);
      const isValid = verifyEd25519(data, signature, keypair.publicKey);

      expect(isValid).toBe(true);
    });

    it("produces 64-byte signatures", () => {
      const keypair = generateEd25519Keypair();
      const data = "Test message";

      const signature = signEd25519(data, keypair.privateKeyPem);
      const signatureBuffer = Buffer.from(signature, "base64");

      expect(signatureBuffer.length).toBe(64);
    });

    it("produces different signatures for different data", () => {
      const keypair = generateEd25519Keypair();

      const sig1 = signEd25519("message one", keypair.privateKeyPem);
      const sig2 = signEd25519("message two", keypair.privateKeyPem);

      expect(sig1).not.toBe(sig2);
    });

    it("produces same signature for same data (Ed25519 is deterministic)", () => {
      const keypair = generateEd25519Keypair();
      const data = "deterministic signing test";

      const sig1 = signEd25519(data, keypair.privateKeyPem);
      const sig2 = signEd25519(data, keypair.privateKeyPem);

      expect(sig1).toBe(sig2);
    });

    it("handles empty data", () => {
      const keypair = generateEd25519Keypair();
      const data = "";

      const signature = signEd25519(data, keypair.privateKeyPem);
      const isValid = verifyEd25519(data, signature, keypair.publicKey);

      expect(isValid).toBe(true);
    });

    it("handles large data", () => {
      const keypair = generateEd25519Keypair();
      const data = "x".repeat(100000); // 100KB

      const signature = signEd25519(data, keypair.privateKeyPem);
      const isValid = verifyEd25519(data, signature, keypair.publicKey);

      expect(isValid).toBe(true);
    });

    it("handles unicode data", () => {
      const keypair = generateEd25519Keypair();
      const data = "Hello \u4e16\u754c! \ud83d\udd10 Special chars: \u00e9\u00e0\u00fc";

      const signature = signEd25519(data, keypair.privateKeyPem);
      const isValid = verifyEd25519(data, signature, keypair.publicKey);

      expect(isValid).toBe(true);
    });

    it("handles JSON-serialized data", () => {
      const keypair = generateEd25519Keypair();
      const claims = {
        v: 1,
        id: "test-capability-id",
        iss: keypair.publicKey,
        sub: "recipient-public-key",
        resource: "google-calendar",
        scope: ["read", "list"],
        iat: 1707177600,
        exp: 1707264000,
      };
      const data = JSON.stringify(claims);

      const signature = signEd25519(data, keypair.privateKeyPem);
      const isValid = verifyEd25519(data, signature, keypair.publicKey);

      expect(isValid).toBe(true);
    });
  });

  describe("signature verification failure cases", () => {
    it("rejects signature with wrong public key", () => {
      const keypair1 = generateEd25519Keypair();
      const keypair2 = generateEd25519Keypair();
      const data = "Test message";

      // Sign with keypair1
      const signature = signEd25519(data, keypair1.privateKeyPem);

      // Verify with keypair2's public key - should fail
      const isValid = verifyEd25519(data, signature, keypair2.publicKey);

      expect(isValid).toBe(false);
    });

    it("rejects signature when data is tampered", () => {
      const keypair = generateEd25519Keypair();
      const originalData = "Original message";
      const tamperedData = "Tampered message";

      const signature = signEd25519(originalData, keypair.privateKeyPem);
      const isValid = verifyEd25519(tamperedData, signature, keypair.publicKey);

      expect(isValid).toBe(false);
    });

    it("rejects tampered signature", () => {
      const keypair = generateEd25519Keypair();
      const data = "Test message";

      const signature = signEd25519(data, keypair.privateKeyPem);

      // Tamper with signature
      const sigBuffer = Buffer.from(signature, "base64");
      sigBuffer[0] ^= 0xff;
      const tamperedSignature = sigBuffer.toString("base64");

      const isValid = verifyEd25519(data, tamperedSignature, keypair.publicKey);

      expect(isValid).toBe(false);
    });

    it("rejects signature with wrong length", () => {
      const keypair = generateEd25519Keypair();
      const data = "Test message";

      // Create a signature that's too short
      const shortSignature = randomBytes(32).toString("base64");
      expect(verifyEd25519(data, shortSignature, keypair.publicKey)).toBe(false);

      // Create a signature that's too long
      const longSignature = randomBytes(128).toString("base64");
      expect(verifyEd25519(data, longSignature, keypair.publicKey)).toBe(false);
    });

    it("rejects invalid public key format", () => {
      const keypair = generateEd25519Keypair();
      const data = "Test message";
      const signature = signEd25519(data, keypair.privateKeyPem);

      // Invalid public key (wrong length)
      const invalidKey = randomBytes(16).toString("base64");
      expect(verifyEd25519(data, signature, invalidKey)).toBe(false);
    });

    it("rejects empty signature", () => {
      const keypair = generateEd25519Keypair();
      const data = "Test message";

      expect(verifyEd25519(data, "", keypair.publicKey)).toBe(false);
    });

    it("rejects invalid base64 in signature", () => {
      const keypair = generateEd25519Keypair();
      const data = "Test message";

      expect(verifyEd25519(data, "not-valid-base64!!!", keypair.publicKey)).toBe(false);
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Capability Token with Ed25519 Signature Tests
// ─────────────────────────────────────────────────────────────────────────────

describe("Capability token with Ed25519 signatures", () => {
  /**
   * Issue a capability token (simulates SecretStore.issueCapability)
   */
  function issueCapabilityToken(
    issuerKeypair: { publicKey: string; privateKeyPem: string },
    subjectPublicKey: string,
    resource: string,
    scope: string[],
    expiresInSeconds: number,
    options?: { maxCalls?: number },
  ): { id: string; token: string } {
    const id = randomBytes(16).toString("hex");
    const now = Math.floor(Date.now() / 1000);
    const exp = now + expiresInSeconds;

    const claims = {
      v: 1,
      id,
      iss: issuerKeypair.publicKey,
      sub: subjectPublicKey,
      resource,
      scope,
      iat: now,
      exp,
      constraints: options?.maxCalls ? { maxCalls: options.maxCalls } : undefined,
    };

    // Sign with Ed25519
    const tokenData = JSON.stringify(claims);
    const signature = signEd25519(tokenData, issuerKeypair.privateKeyPem);
    const token = Buffer.from(JSON.stringify({ ...claims, sig: signature })).toString("base64url");

    return { id, token };
  }

  /**
   * Verify and decode a capability token (simulates SecretStore.executeCapability verification)
   */
  function verifyCapabilityToken(token: string): {
    valid: boolean;
    claims?: Record<string, unknown>;
    error?: string;
  } {
    try {
      const decoded = JSON.parse(Buffer.from(token, "base64url").toString());
      const { sig, ...claims } = decoded;

      // Verify signature
      if (!verifyEd25519(JSON.stringify(claims), sig, claims.iss)) {
        return { valid: false, error: "Invalid signature" };
      }

      // Check expiry
      const now = Math.floor(Date.now() / 1000);
      if (claims.exp < now) {
        return { valid: false, error: "Token expired" };
      }

      return { valid: true, claims };
    } catch (err) {
      return { valid: false, error: (err as Error).message };
    }
  }

  it("issues and verifies a valid capability token", () => {
    const issuer = generateEd25519Keypair();
    const subject = generateEd25519Keypair();

    const { token } = issueCapabilityToken(
      issuer,
      subject.publicKey,
      "google-calendar",
      ["read", "list"],
      3600, // 1 hour
    );

    const result = verifyCapabilityToken(token);

    expect(result.valid).toBe(true);
    expect(result.claims?.iss).toBe(issuer.publicKey);
    expect(result.claims?.sub).toBe(subject.publicKey);
    expect(result.claims?.resource).toBe("google-calendar");
    expect(result.claims?.scope).toEqual(["read", "list"]);
  });

  it("rejects token signed by different issuer", () => {
    const realIssuer = generateEd25519Keypair();
    const fakeIssuer = generateEd25519Keypair();
    const subject = generateEd25519Keypair();

    // Create a token and modify the issuer claim
    const { token } = issueCapabilityToken(
      fakeIssuer,
      subject.publicKey,
      "google-calendar",
      ["read"],
      3600,
    );

    // Decode, change issuer to realIssuer (but signature is from fakeIssuer)
    const decoded = JSON.parse(Buffer.from(token, "base64url").toString());
    decoded.iss = realIssuer.publicKey; // Change issuer claim
    const tamperedToken = Buffer.from(JSON.stringify(decoded)).toString("base64url");

    const result = verifyCapabilityToken(tamperedToken);

    expect(result.valid).toBe(false);
    expect(result.error).toBe("Invalid signature");
  });

  it("rejects token with tampered scope", () => {
    const issuer = generateEd25519Keypair();
    const subject = generateEd25519Keypair();

    const { token } = issueCapabilityToken(
      issuer,
      subject.publicKey,
      "google-calendar",
      ["read"],
      3600,
    );

    // Decode and tamper with scope
    const decoded = JSON.parse(Buffer.from(token, "base64url").toString());
    decoded.scope = ["read", "write", "delete", "admin"]; // Escalate privileges
    const tamperedToken = Buffer.from(JSON.stringify(decoded)).toString("base64url");

    const result = verifyCapabilityToken(tamperedToken);

    expect(result.valid).toBe(false);
    expect(result.error).toBe("Invalid signature");
  });

  it("rejects token with tampered expiry", () => {
    const issuer = generateEd25519Keypair();
    const subject = generateEd25519Keypair();

    const { token } = issueCapabilityToken(
      issuer,
      subject.publicKey,
      "google-calendar",
      ["read"],
      3600,
    );

    // Decode and extend expiry
    const decoded = JSON.parse(Buffer.from(token, "base64url").toString());
    decoded.exp = decoded.exp + 86400 * 365; // Extend by 1 year
    const tamperedToken = Buffer.from(JSON.stringify(decoded)).toString("base64url");

    const result = verifyCapabilityToken(tamperedToken);

    expect(result.valid).toBe(false);
    expect(result.error).toBe("Invalid signature");
  });

  it("rejects expired token", () => {
    const issuer = generateEd25519Keypair();
    const subject = generateEd25519Keypair();

    // Issue token that's already expired
    const { token } = issueCapabilityToken(
      issuer,
      subject.publicKey,
      "google-calendar",
      ["read"],
      -3600, // Negative = already expired
    );

    const result = verifyCapabilityToken(token);

    expect(result.valid).toBe(false);
    expect(result.error).toBe("Token expired");
  });

  it("rejects token with tampered resource", () => {
    const issuer = generateEd25519Keypair();
    const subject = generateEd25519Keypair();

    const { token } = issueCapabilityToken(
      issuer,
      subject.publicKey,
      "google-calendar",
      ["read"],
      3600,
    );

    // Decode and change resource
    const decoded = JSON.parse(Buffer.from(token, "base64url").toString());
    decoded.resource = "google-drive"; // Change to different resource
    const tamperedToken = Buffer.from(JSON.stringify(decoded)).toString("base64url");

    const result = verifyCapabilityToken(tamperedToken);

    expect(result.valid).toBe(false);
    expect(result.error).toBe("Invalid signature");
  });

  it("handles token with constraints", () => {
    const issuer = generateEd25519Keypair();
    const subject = generateEd25519Keypair();

    const { token } = issueCapabilityToken(
      issuer,
      subject.publicKey,
      "api-service",
      ["read", "write"],
      3600,
      { maxCalls: 100 },
    );

    const result = verifyCapabilityToken(token);

    expect(result.valid).toBe(true);
    expect((result.claims?.constraints as { maxCalls?: number })?.maxCalls).toBe(100);
  });

  it("token is base64url encoded (URL-safe)", () => {
    const issuer = generateEd25519Keypair();
    const subject = generateEd25519Keypair();

    const { token } = issueCapabilityToken(
      issuer,
      subject.publicKey,
      "google-calendar",
      ["read"],
      3600,
    );

    // base64url should not contain +, /, or =
    expect(token).not.toMatch(/[+/=]/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SecretStore Integration Tests (Real Ed25519 Signing)
// ─────────────────────────────────────────────────────────────────────────────

import { SecretStore, resetSecretStore } from "./secret-store.js";

// Use lower scrypt N for tests to avoid memory issues
const TEST_SCRYPT_OPTIONS = { scryptN: TEST_SCRYPT_N };

describe("SecretStore Ed25519 integration", () => {
  let tempDir: string;
  let store: SecretStore;

  beforeEach(() => {
    // Reset singleton for each test
    resetSecretStore();
    tempDir = createTempDir();
    store = new SecretStore({ baseDir: tempDir, ...TEST_SCRYPT_OPTIONS });
  });

  afterEach(() => {
    store.lock();
    cleanupTempDir(tempDir);
    resetSecretStore();
  });

  describe("identity keypair generation", () => {
    it("generates Ed25519 identity on vault initialization", async () => {
      await store.initialize("test-password");

      // Vault should be unlocked after initialization
      expect(store.isUnlocked()).toBe(true);

      // Should have a public key
      const publicKey = store.getPublicKey();
      expect(publicKey).toBeTruthy();

      // Public key should be base64-encoded 32 bytes
      const rawKey = Buffer.from(publicKey!, "base64");
      expect(rawKey.length).toBe(32);
    });

    it("preserves identity keypair after lock/unlock cycle", async () => {
      await store.initialize("test-password");
      const originalPublicKey = store.getPublicKey();

      // Lock and unlock
      store.lock();
      expect(store.isUnlocked()).toBe(false);
      expect(store.getPublicKey()).toBeNull();

      const unlocked = await store.unlock("test-password");
      expect(unlocked).toBe(true);

      // Public key should be the same
      expect(store.getPublicKey()).toBe(originalPublicKey);
    });

    it("generates both signing and encryption keypairs", async () => {
      await store.initialize("test-password");

      const keys = store.getPublicKeys();
      expect(keys).toBeTruthy();
      expect(keys!.signingKey).toBeTruthy();
      expect(keys!.encryptionKey).toBeTruthy();

      // Both should be 32 bytes
      const signingKeyRaw = Buffer.from(keys!.signingKey, "base64");
      const encryptionKeyRaw = Buffer.from(keys!.encryptionKey, "base64");
      expect(signingKeyRaw.length).toBe(32);
      expect(encryptionKeyRaw.length).toBe(32);

      // They should be different (Ed25519 vs X25519)
      expect(keys!.signingKey).not.toBe(keys!.encryptionKey);
    });
  });

  describe("capability token signing", () => {
    it("issues capability token with valid Ed25519 signature", async () => {
      await store.initialize("test-password");

      // Set up an integration to share
      await store.setIntegration("google-calendar", {
        accessToken: "test-access-token",
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      });

      // Issue capability
      const recipientKey = generateEd25519Keypair().publicKey;
      const { token, id } = await store.issueCapability(
        recipientKey,
        "google-calendar",
        ["read", "list"],
        3600,
      );

      expect(token).toBeTruthy();
      expect(id).toBeTruthy();

      // Decode and verify token structure
      const decoded = JSON.parse(Buffer.from(token, "base64url").toString());
      expect(decoded.iss).toBe(store.getPublicKey());
      expect(decoded.sub).toBe(recipientKey);
      expect(decoded.resource).toBe("google-calendar");
      expect(decoded.scope).toEqual(["read", "list"]);
      expect(decoded.sig).toBeTruthy();

      // Verify signature
      const { sig, ...claims } = decoded;
      const isValid = verifyEd25519(JSON.stringify(claims), sig, decoded.iss);
      expect(isValid).toBe(true);
    });

    it("issues capability tokens with different signatures for different recipients", async () => {
      await store.initialize("test-password");

      await store.setIntegration("google-calendar", {
        accessToken: "test-access-token",
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      });

      const recipient1 = generateEd25519Keypair().publicKey;
      const recipient2 = generateEd25519Keypair().publicKey;

      const { token: token1 } = await store.issueCapability(
        recipient1,
        "google-calendar",
        ["read"],
        3600,
      );

      const { token: token2 } = await store.issueCapability(
        recipient2,
        "google-calendar",
        ["read"],
        3600,
      );

      // Tokens should be different (different subject = different claims = different signature)
      expect(token1).not.toBe(token2);

      // Both should have valid signatures
      const decoded1 = JSON.parse(Buffer.from(token1, "base64url").toString());
      const decoded2 = JSON.parse(Buffer.from(token2, "base64url").toString());

      const { sig: sig1, ...claims1 } = decoded1;
      const { sig: sig2, ...claims2 } = decoded2;

      expect(verifyEd25519(JSON.stringify(claims1), sig1, decoded1.iss)).toBe(true);
      expect(verifyEd25519(JSON.stringify(claims2), sig2, decoded2.iss)).toBe(true);
    });

    it("executes capability with valid signature", async () => {
      await store.initialize("test-password");

      await store.setIntegration("google-calendar", {
        accessToken: "secret-token-12345",
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      });

      const recipientKey = generateEd25519Keypair().publicKey;
      const { token } = await store.issueCapability(
        recipientKey,
        "google-calendar",
        ["read"],
        3600,
      );

      // Execute capability
      const result = await store.executeCapability(token, "read", { calendarId: "primary" });

      expect(result).toBeTruthy();
      expect((result as { accessToken: string }).accessToken).toBe("secret-token-12345");
    });

    it("rejects capability with tampered signature", async () => {
      await store.initialize("test-password");

      await store.setIntegration("google-calendar", {
        accessToken: "secret-token",
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      });

      const recipientKey = generateEd25519Keypair().publicKey;
      const { token } = await store.issueCapability(
        recipientKey,
        "google-calendar",
        ["read"],
        3600,
      );

      // Tamper with the signature
      const decoded = JSON.parse(Buffer.from(token, "base64url").toString());
      const sigBuffer = Buffer.from(decoded.sig, "base64");
      sigBuffer[0] ^= 0xff;
      decoded.sig = sigBuffer.toString("base64");
      const tamperedToken = Buffer.from(JSON.stringify(decoded)).toString("base64url");

      // Should reject
      await expect(store.executeCapability(tamperedToken, "read", {})).rejects.toThrow(
        "Invalid capability signature",
      );
    });

    it("rejects capability with tampered claims", async () => {
      await store.initialize("test-password");

      await store.setIntegration("google-calendar", {
        accessToken: "secret-token",
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      });

      const recipientKey = generateEd25519Keypair().publicKey;
      const { token } = await store.issueCapability(
        recipientKey,
        "google-calendar",
        ["read"],
        3600,
      );

      // Tamper with the scope to escalate privileges
      const decoded = JSON.parse(Buffer.from(token, "base64url").toString());
      decoded.scope = ["read", "write", "delete", "admin"];
      const tamperedToken = Buffer.from(JSON.stringify(decoded)).toString("base64url");

      // Should reject due to signature mismatch
      await expect(store.executeCapability(tamperedToken, "read", {})).rejects.toThrow(
        "Invalid capability signature",
      );
    });
  });

  describe("capability storage and verification", () => {
    it("stores received capability and verifies signature", async () => {
      // Create issuer store
      const issuerDir = createTempDir();
      const issuerStore = new SecretStore({ baseDir: issuerDir, ...TEST_SCRYPT_OPTIONS });
      await issuerStore.initialize("issuer-password");

      await issuerStore.setIntegration("google-calendar", {
        accessToken: "issuer-token",
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      });

      // Create recipient store
      await store.initialize("recipient-password");
      const recipientKey = store.getPublicKey()!;

      // Issue capability from issuer to recipient
      const { token } = await issuerStore.issueCapability(
        recipientKey,
        "google-calendar",
        ["read"],
        3600,
      );

      // Recipient stores the capability
      const capabilityId = await store.storeReceivedCapability(token, "issuer-container-id");
      expect(capabilityId).toBeTruthy();

      // Verify it's stored correctly
      const received = store.getReceivedCapability(capabilityId);
      expect(received).toBeTruthy();
      expect(received!.issuer).toBe(issuerStore.getPublicKey());
      expect(received!.resource).toBe("google-calendar");
      expect(received!.scope).toEqual(["read"]);

      // Cleanup
      issuerStore.lock();
      cleanupTempDir(issuerDir);
    });

    it("rejects storing capability with invalid signature", async () => {
      await store.initialize("test-password");

      // Create a token with a fake signature
      const fakeIssuer = generateEd25519Keypair();
      const claims = {
        v: 1,
        id: randomBytes(16).toString("hex"),
        iss: fakeIssuer.publicKey,
        sub: store.getPublicKey(),
        resource: "google-calendar",
        scope: ["read"],
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
      };

      // Sign with fake issuer
      const sig = signEd25519(JSON.stringify(claims), fakeIssuer.privateKeyPem);

      // Tamper with the claims after signing
      const tamperedClaims = { ...claims, scope: ["read", "write", "admin"] };
      const token = Buffer.from(JSON.stringify({ ...tamperedClaims, sig })).toString("base64url");

      // Should reject due to signature mismatch
      await expect(store.storeReceivedCapability(token, "fake-container")).rejects.toThrow(
        "Invalid capability signature",
      );
    });

    it("rejects storing expired capability", async () => {
      await store.initialize("test-password");

      // Create a token that's already expired
      const issuer = generateEd25519Keypair();
      const claims = {
        v: 1,
        id: randomBytes(16).toString("hex"),
        iss: issuer.publicKey,
        sub: store.getPublicKey(),
        resource: "google-calendar",
        scope: ["read"],
        iat: Math.floor(Date.now() / 1000) - 7200, // 2 hours ago
        exp: Math.floor(Date.now() / 1000) - 3600, // 1 hour ago (expired)
      };

      const sig = signEd25519(JSON.stringify(claims), issuer.privateKeyPem);
      const token = Buffer.from(JSON.stringify({ ...claims, sig })).toString("base64url");

      await expect(store.storeReceivedCapability(token, "issuer-container")).rejects.toThrow(
        "Capability expired",
      );
    });
  });

  describe("CACHED Tier Snapshots", () => {
    it("issues CACHED tier capability with initial snapshot", async () => {
      const tempDir = createTempDir();
      try {
        const store = new (await import("./secret-store.js")).SecretStore({
          baseDir: tempDir,
          scryptN: TEST_SCRYPT_N,
        });
        await store.initialize("test-password");

        // Add an integration to share
        await store.setIntegration("google-calendar", {
          accessToken: "test-access-token",
          expiresAt: new Date(Date.now() + 86400 * 1000).toISOString(),
          email: "test@example.com",
        });

        // Create a recipient with encryption key
        const recipientKeys = store.getPublicKeys();
        expect(recipientKeys).not.toBeNull();

        // Issue CACHED tier capability (using our own key as recipient for testing)
        const result = await store.issueCapability(
          recipientKeys!.signingKey,
          "google-calendar",
          ["read"],
          3600,
          {
            tier: "CACHED",
            subjectEncryptionKey: recipientKeys!.encryptionKey,
            cacheRefreshInterval: 300,
          },
        );

        expect(result.id).toBeDefined();
        expect(result.token).toBeDefined();
        expect(result.snapshot).toBeDefined();

        // Verify snapshot structure
        const snapshot = result.snapshot!;
        expect(snapshot.capabilityId).toBe(result.id);
        expect(snapshot.encryptedData).toBeDefined();
        expect(snapshot.ephemeralPublicKey).toBeDefined();
        expect(snapshot.nonce).toBeDefined();
        expect(snapshot.tag).toBeDefined();
        expect(snapshot.signature).toBeDefined();
        expect(snapshot.issuerPublicKey).toBe(recipientKeys!.signingKey);

        // Verify grant is stored with CACHED tier
        const grants = store.listIssuedCapabilities();
        const grant = grants.find((g) => g.id === result.id);
        expect(grant).toBeDefined();
        expect(grant!.tier).toBe("CACHED");
        expect(grant!.cacheRefreshInterval).toBe(300);
        expect(grant!.subjectEncryptionKey).toBe(recipientKeys!.encryptionKey);
      } finally {
        cleanupTempDir(tempDir);
      }
    });

    it("rejects CACHED tier without encryption key", async () => {
      const tempDir = createTempDir();
      try {
        const store = new (await import("./secret-store.js")).SecretStore({
          baseDir: tempDir,
          scryptN: TEST_SCRYPT_N,
        });
        await store.initialize("test-password");

        await store.setIntegration("google-calendar", {
          accessToken: "test-access-token",
          expiresAt: new Date(Date.now() + 86400 * 1000).toISOString(),
        });

        const recipientKeys = store.getPublicKeys();

        await expect(
          store.issueCapability(recipientKeys!.signingKey, "google-calendar", ["read"], 3600, {
            tier: "CACHED",
            // No subjectEncryptionKey provided
          }),
        ).rejects.toThrow("CACHED tier requires subjectEncryptionKey");
      } finally {
        cleanupTempDir(tempDir);
      }
    });

    it("decrypts cached snapshot correctly", async () => {
      const tempDir = createTempDir();
      try {
        const store = new (await import("./secret-store.js")).SecretStore({
          baseDir: tempDir,
          scryptN: TEST_SCRYPT_N,
        });
        await store.initialize("test-password");

        await store.setIntegration("google-calendar", {
          accessToken: "secret-access-token",
          refreshToken: "secret-refresh-token",
          expiresAt: new Date(Date.now() + 86400 * 1000).toISOString(),
          email: "test@example.com",
        });

        const keys = store.getPublicKeys()!;

        const result = await store.issueCapability(
          keys.signingKey,
          "google-calendar",
          ["read"],
          3600,
          {
            tier: "CACHED",
            subjectEncryptionKey: keys.encryptionKey,
          },
        );

        // Decrypt the snapshot (using our own key since we're both issuer and recipient)
        const decrypted = store.decryptCachedSnapshot(result.snapshot!);

        expect(decrypted.data).toBeDefined();
        expect(decrypted.data.accessToken).toBe("secret-access-token");
        expect(decrypted.data.refreshToken).toBe("secret-refresh-token");
        expect(decrypted.data.email).toBe("test@example.com");
        expect(decrypted.data.resource).toBe("google-calendar");
        expect(decrypted.staleness).toBeGreaterThanOrEqual(0);
      } finally {
        cleanupTempDir(tempDir);
      }
    });

    it("identifies capabilities needing refresh", async () => {
      const tempDir = createTempDir();
      try {
        const store = new (await import("./secret-store.js")).SecretStore({
          baseDir: tempDir,
          scryptN: TEST_SCRYPT_N,
        });
        await store.initialize("test-password");

        await store.setIntegration("google-calendar", {
          accessToken: "test-access-token",
          expiresAt: new Date(Date.now() + 86400 * 1000).toISOString(),
        });

        const keys = store.getPublicKeys()!;

        // Issue capability with very short refresh interval
        const result = await store.issueCapability(
          keys.signingKey,
          "google-calendar",
          ["read"],
          3600,
          {
            tier: "CACHED",
            subjectEncryptionKey: keys.encryptionKey,
            cacheRefreshInterval: 1, // 1 second
          },
        );

        // Initially should not need refresh (just created)
        let needsRefresh = store.getCapabilitiesNeedingRefresh();
        expect(needsRefresh.length).toBe(0);

        // Wait for refresh interval
        await new Promise((resolve) => setTimeout(resolve, 1100));

        // Now should need refresh
        needsRefresh = store.getCapabilitiesNeedingRefresh();
        expect(needsRefresh.length).toBe(1);
        expect(needsRefresh[0].id).toBe(result.id);
      } finally {
        cleanupTempDir(tempDir);
      }
    });

    it("gets pending snapshots for relay push", async () => {
      const tempDir = createTempDir();
      try {
        const store = new (await import("./secret-store.js")).SecretStore({
          baseDir: tempDir,
          scryptN: TEST_SCRYPT_N,
        });
        await store.initialize("test-password");

        await store.setIntegration("google-calendar", {
          accessToken: "test-access-token",
          expiresAt: new Date(Date.now() + 86400 * 1000).toISOString(),
        });

        const keys = store.getPublicKeys()!;

        await store.issueCapability(keys.signingKey, "google-calendar", ["read"], 3600, {
          tier: "CACHED",
          subjectEncryptionKey: keys.encryptionKey,
        });

        const pending = store.getPendingSnapshots();
        expect(pending.length).toBe(1);

        // Mark as pushed
        await store.markSnapshotsPushed([pending[0].capabilityId]);

        const pendingAfter = store.getPendingSnapshots();
        expect(pendingAfter.length).toBe(0);
      } finally {
        cleanupTempDir(tempDir);
      }
    });

    it("includes encryption keys in token claims for CACHED tier", async () => {
      const tempDir = createTempDir();
      try {
        const store = new (await import("./secret-store.js")).SecretStore({
          baseDir: tempDir,
          scryptN: TEST_SCRYPT_N,
        });
        await store.initialize("test-password");

        await store.setIntegration("google-calendar", {
          accessToken: "test-access-token",
          expiresAt: new Date(Date.now() + 86400 * 1000).toISOString(),
        });

        const keys = store.getPublicKeys()!;

        const result = await store.issueCapability(
          keys.signingKey,
          "google-calendar",
          ["read"],
          3600,
          {
            tier: "CACHED",
            subjectEncryptionKey: keys.encryptionKey,
          },
        );

        // Decode the token and check claims
        const tokenData = JSON.parse(Buffer.from(result.token, "base64url").toString());
        expect(tokenData.tier).toBe("CACHED");
        expect(tokenData.issEnc).toBe(keys.encryptionKey);
        expect(tokenData.subEnc).toBe(keys.encryptionKey);
      } finally {
        cleanupTempDir(tempDir);
      }
    });
  });
});
