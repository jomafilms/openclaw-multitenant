/**
 * Tests for Key Rotation
 *
 * Tests the key rotation mechanisms for the mesh security system.
 */

import { randomBytes } from "crypto";
import { describe, it, expect, beforeEach } from "vitest";
import {
  KeyRotationManager,
  KeyRotationState,
  generateVersionedIdentity,
  generateKeyId,
  createInitialRotationState,
  createFreshRotationState,
  rotateVaultKey,
  identifyCapabilitiesNeedingReissue,
  publicKeyFromBase64,
} from "./key-rotation.js";

// ─────────────────────────────────────────────────────────────────────────────
// Helper Functions
// ─────────────────────────────────────────────────────────────────────────────

function createTestRotationState(): KeyRotationState {
  return createFreshRotationState();
}

function createMockSaveFunction(): { save: () => Promise<void>; callCount: number } {
  const result = {
    save: async () => {
      result.callCount++;
    },
    callCount: 0,
  };
  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Key Generation Tests
// ─────────────────────────────────────────────────────────────────────────────

describe("Key generation", () => {
  describe("generateVersionedIdentity", () => {
    it("generates a valid versioned identity", () => {
      const identity = generateVersionedIdentity(1);

      expect(identity.version).toBe(1);
      expect(identity.keyId).toBeTruthy();
      expect(identity.keyId.length).toBe(32); // 16 bytes as hex
      expect(identity.publicKey).toBeTruthy();
      expect(identity.privateKeyPem).toContain("-----BEGIN PRIVATE KEY-----");
      expect(identity.encryptionPublicKey).toBeTruthy();
      expect(identity.encryptionPrivateKeyPem).toContain("-----BEGIN PRIVATE KEY-----");
      expect(identity.algorithm).toBe("Ed25519");
      expect(identity.createdAt).toBeTruthy();
    });

    it("generates unique identities each time", () => {
      const identity1 = generateVersionedIdentity(1);
      const identity2 = generateVersionedIdentity(1);

      expect(identity1.keyId).not.toBe(identity2.keyId);
      expect(identity1.publicKey).not.toBe(identity2.publicKey);
      expect(identity1.encryptionPublicKey).not.toBe(identity2.encryptionPublicKey);
    });

    it("generates 32-byte public keys", () => {
      const identity = generateVersionedIdentity(1);

      const signingKey = Buffer.from(identity.publicKey, "base64");
      const encryptionKey = Buffer.from(identity.encryptionPublicKey, "base64");

      expect(signingKey.length).toBe(32);
      expect(encryptionKey.length).toBe(32);
    });

    it("increments version correctly", () => {
      const identity1 = generateVersionedIdentity(1);
      const identity2 = generateVersionedIdentity(2);
      const identity3 = generateVersionedIdentity(5);

      expect(identity1.version).toBe(1);
      expect(identity2.version).toBe(2);
      expect(identity3.version).toBe(5);
    });
  });

  describe("generateKeyId", () => {
    it("generates consistent key IDs for same public key", () => {
      const publicKey = randomBytes(32).toString("base64");

      const keyId1 = generateKeyId(publicKey);
      const keyId2 = generateKeyId(publicKey);

      expect(keyId1).toBe(keyId2);
    });

    it("generates different key IDs for different public keys", () => {
      const publicKey1 = randomBytes(32).toString("base64");
      const publicKey2 = randomBytes(32).toString("base64");

      const keyId1 = generateKeyId(publicKey1);
      const keyId2 = generateKeyId(publicKey2);

      expect(keyId1).not.toBe(keyId2);
    });

    it("generates 32-character hex key IDs", () => {
      const publicKey = randomBytes(32).toString("base64");
      const keyId = generateKeyId(publicKey);

      expect(keyId.length).toBe(32);
      expect(keyId).toMatch(/^[0-9a-f]+$/);
    });
  });

  describe("publicKeyFromBase64", () => {
    it("creates KeyObject from valid 32-byte base64 key", () => {
      const identity = generateVersionedIdentity(1);
      const keyObject = publicKeyFromBase64(identity.publicKey);

      expect(keyObject).toBeTruthy();
      expect(keyObject.type).toBe("public");
      expect(keyObject.asymmetricKeyType).toBe("ed25519");
    });

    it("throws for invalid key length", () => {
      const shortKey = randomBytes(16).toString("base64");
      const longKey = randomBytes(64).toString("base64");

      expect(() => publicKeyFromBase64(shortKey)).toThrow("Invalid Ed25519 public key length");
      expect(() => publicKeyFromBase64(longKey)).toThrow("Invalid Ed25519 public key length");
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// KeyRotationManager Tests
// ─────────────────────────────────────────────────────────────────────────────

describe("KeyRotationManager", () => {
  let state: KeyRotationState;
  let mockSave: ReturnType<typeof createMockSaveFunction>;
  let manager: KeyRotationManager;

  beforeEach(() => {
    state = createTestRotationState();
    mockSave = createMockSaveFunction();
    manager = new KeyRotationManager(state, mockSave.save);
  });

  describe("initial state", () => {
    it("returns current identity", () => {
      const current = manager.getCurrentIdentity();

      expect(current).toBeTruthy();
      expect(current.version).toBe(1);
      expect(current.keyId).toBeTruthy();
    });

    it("has no previous identity initially", () => {
      const previous = manager.getPreviousIdentity();
      expect(previous).toBeUndefined();
    });

    it("is not in transition initially", () => {
      expect(manager.isInTransition()).toBe(false);
      expect(manager.getTransitionEndTime()).toBeNull();
    });

    it("has no archived keys initially", () => {
      const archived = manager.getArchivedKeys();
      expect(archived).toEqual([]);
    });
  });

  describe("rotateSigningKey", () => {
    it("rotates the signing key", async () => {
      const oldIdentity = manager.getCurrentIdentity();

      const result = await manager.rotateSigningKey(24, "Test rotation");

      expect(result.oldKeyId).toBe(oldIdentity.keyId);
      expect(result.newKeyId).not.toBe(oldIdentity.keyId);
      expect(result.newPublicKey).not.toBe(oldIdentity.publicKey);
      expect(result.transitionEndsAt).toBeTruthy();
    });

    it("starts a transition period", async () => {
      await manager.rotateSigningKey(24);

      expect(manager.isInTransition()).toBe(true);
      expect(manager.getTransitionEndTime()).not.toBeNull();
    });

    it("preserves the old identity as previous", async () => {
      const oldIdentity = manager.getCurrentIdentity();

      await manager.rotateSigningKey(24);

      const previous = manager.getPreviousIdentity();
      expect(previous).toBeTruthy();
      expect(previous!.keyId).toBe(oldIdentity.keyId);
      expect(previous!.publicKey).toBe(oldIdentity.publicKey);
    });

    it("updates the current identity to new key", async () => {
      const oldIdentity = manager.getCurrentIdentity();

      await manager.rotateSigningKey(24);

      const newIdentity = manager.getCurrentIdentity();
      expect(newIdentity.version).toBe(oldIdentity.version + 1);
      expect(newIdentity.keyId).not.toBe(oldIdentity.keyId);
    });

    it("archives the old key", async () => {
      const oldIdentity = manager.getCurrentIdentity();

      await manager.rotateSigningKey(24, "Security upgrade");

      const archived = manager.getArchivedKeys();
      expect(archived.length).toBe(1);
      expect(archived[0].keyId).toBe(oldIdentity.keyId);
      expect(archived[0].reason).toBe("Security upgrade");
      expect(archived[0].transitionActive).toBe(true);
    });

    it("respects custom transition duration", async () => {
      const before = Date.now();
      const result = await manager.rotateSigningKey(48);
      const after = Date.now();

      const transitionEnd = new Date(result.transitionEndsAt).getTime();
      const expectedMin = before + 48 * 60 * 60 * 1000;
      const expectedMax = after + 48 * 60 * 60 * 1000;

      expect(transitionEnd).toBeGreaterThanOrEqual(expectedMin);
      expect(transitionEnd).toBeLessThanOrEqual(expectedMax);
    });

    it("calls save after rotation", async () => {
      await manager.rotateSigningKey(24);
      expect(mockSave.callCount).toBe(1);
    });

    it("supports multiple rotations", async () => {
      await manager.rotateSigningKey(24, "First rotation");
      const midIdentity = manager.getCurrentIdentity();

      await manager.rotateSigningKey(24, "Second rotation");
      const finalIdentity = manager.getCurrentIdentity();

      expect(finalIdentity.version).toBe(3);
      expect(manager.getPreviousIdentity()!.keyId).toBe(midIdentity.keyId);
      expect(manager.getArchivedKeys().length).toBe(2);
    });
  });

  describe("completeTransition", () => {
    it("throws if no transition in progress", async () => {
      await expect(manager.completeTransition()).rejects.toThrow("No transition in progress");
    });

    it("completes an active transition", async () => {
      await manager.rotateSigningKey(24);
      expect(manager.isInTransition()).toBe(true);

      await manager.completeTransition();

      expect(manager.isInTransition()).toBe(false);
      expect(manager.getPreviousIdentity()).toBeUndefined();
      expect(manager.getTransitionEndTime()).toBeNull();
    });

    it("marks archived key as no longer in transition", async () => {
      await manager.rotateSigningKey(24);
      const archivedBefore = manager.getArchivedKeys()[0];
      expect(archivedBefore.transitionActive).toBe(true);

      await manager.completeTransition();

      const archivedAfter = manager.getArchivedKeys()[0];
      expect(archivedAfter.transitionActive).toBe(false);
    });

    it("calls save after completing transition", async () => {
      await manager.rotateSigningKey(24);
      mockSave.callCount = 0;

      await manager.completeTransition();

      expect(mockSave.callCount).toBe(1);
    });
  });

  describe("signing and verification", () => {
    it("signs data with current key", () => {
      const data = "Hello, World!";
      const result = manager.signWithCurrentKey(data);

      expect(result.signature).toBeTruthy();
      expect(result.keyVersion).toBe(1);
      expect(result.keyId).toBe(manager.getCurrentIdentity().keyId);
    });

    it("produces valid signatures", () => {
      const data = "Test data for signing";
      const { signature } = manager.signWithCurrentKey(data);
      const currentKey = manager.getCurrentIdentity().publicKey;

      const result = manager.verifyWithAnyValidKey(data, signature, currentKey);

      expect(result.valid).toBe(true);
      expect(result.keyVersion).toBe(1);
    });

    it("rejects invalid signatures", () => {
      const data = "Test data";
      const badSignature = randomBytes(64).toString("base64");
      const currentKey = manager.getCurrentIdentity().publicKey;

      const result = manager.verifyWithAnyValidKey(data, badSignature, currentKey);

      expect(result.valid).toBe(false);
    });

    it("verifies with previous key during transition", async () => {
      // Sign with old key
      const data = "Test data";
      const { signature } = manager.signWithCurrentKey(data);
      const oldPublicKey = manager.getCurrentIdentity().publicKey;

      // Rotate
      await manager.rotateSigningKey(24);

      // Old signature should still verify during transition
      const result = manager.verifyWithAnyValidKey(data, signature, oldPublicKey);

      expect(result.valid).toBe(true);
      expect(result.keyVersion).toBe(1);
    });

    it("rejects old key after transition completes", async () => {
      // Sign with old key
      const data = "Test data";
      const { signature } = manager.signWithCurrentKey(data);
      const oldPublicKey = manager.getCurrentIdentity().publicKey;

      // Rotate and complete
      await manager.rotateSigningKey(24);
      await manager.completeTransition();

      // Old signature should no longer verify
      const result = manager.verifyWithAnyValidKey(data, signature, oldPublicKey);

      expect(result.valid).toBe(false);
    });

    it("signs with new key after rotation", async () => {
      await manager.rotateSigningKey(24);

      const data = "New data";
      const { signature, keyVersion } = manager.signWithCurrentKey(data);
      const newPublicKey = manager.getCurrentIdentity().publicKey;

      expect(keyVersion).toBe(2);

      const result = manager.verifyWithAnyValidKey(data, signature, newPublicKey);
      expect(result.valid).toBe(true);
      expect(result.keyVersion).toBe(2);
    });
  });

  describe("key validity checks", () => {
    it("current key is valid", () => {
      const keyId = manager.getCurrentIdentity().keyId;
      expect(manager.isKeyValid(keyId)).toBe(true);
    });

    it("previous key is valid during transition", async () => {
      const oldKeyId = manager.getCurrentIdentity().keyId;

      await manager.rotateSigningKey(24);

      expect(manager.isKeyValid(oldKeyId)).toBe(true);
    });

    it("previous key is invalid after transition", async () => {
      const oldKeyId = manager.getCurrentIdentity().keyId;

      await manager.rotateSigningKey(24);
      await manager.completeTransition();

      expect(manager.isKeyValid(oldKeyId)).toBe(false);
    });

    it("random key is invalid", () => {
      const randomKeyId = randomBytes(16).toString("hex");
      expect(manager.isKeyValid(randomKeyId)).toBe(false);
    });
  });

  describe("getKeyIdForVersion", () => {
    it("returns current key ID for current version", () => {
      const keyId = manager.getKeyIdForVersion(1);
      expect(keyId).toBe(manager.getCurrentIdentity().keyId);
    });

    it("returns previous key ID during transition", async () => {
      const oldKeyId = manager.getCurrentIdentity().keyId;

      await manager.rotateSigningKey(24);

      expect(manager.getKeyIdForVersion(1)).toBe(oldKeyId);
      expect(manager.getKeyIdForVersion(2)).toBe(manager.getCurrentIdentity().keyId);
    });

    it("returns archived key ID", async () => {
      const oldKeyId = manager.getCurrentIdentity().keyId;

      await manager.rotateSigningKey(24);
      await manager.completeTransition();

      expect(manager.getKeyIdForVersion(1)).toBe(oldKeyId);
    });

    it("returns null for unknown version", () => {
      expect(manager.getKeyIdForVersion(999)).toBeNull();
    });
  });

  describe("rotation notifications", () => {
    it("creates rotation notification", async () => {
      await manager.rotateSigningKey(24);

      const notification = manager.createRotationNotification(["cap1", "cap2"]);

      expect(notification.type).toBe("key_rotation");
      expect(notification.oldKeyId).toBe(manager.getPreviousIdentity()!.keyId);
      expect(notification.newKeyId).toBe(manager.getCurrentIdentity().keyId);
      expect(notification.affectedCapabilityIds).toEqual(["cap1", "cap2"]);
      expect(notification.signature).toBeTruthy();
    });

    it("throws if no transition in progress", () => {
      expect(() => manager.createRotationNotification([])).toThrow("No transition in progress");
    });

    it("notification is verifiable", async () => {
      await manager.rotateSigningKey(24);

      const notification = manager.createRotationNotification(["cap1"]);
      const isValid = KeyRotationManager.verifyRotationNotification(notification);

      expect(isValid).toBe(true);
    });

    it("rejects tampered notification", async () => {
      await manager.rotateSigningKey(24);

      const notification = manager.createRotationNotification(["cap1"]);
      notification.affectedCapabilityIds.push("cap-injected");

      const isValid = KeyRotationManager.verifyRotationNotification(notification);

      expect(isValid).toBe(false);
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Vault Key Rotation Tests
// ─────────────────────────────────────────────────────────────────────────────

describe("Vault key rotation", () => {
  it("rotates vault encryption key with new password", () => {
    const plaintext = JSON.stringify({ secret: "data" });
    const oldPassword = "old-password";
    const newPassword = "new-password";
    const scryptN = 2 ** 14;

    // Initial encryption
    const { scryptSync, createCipheriv, createDecipheriv } = require("crypto");
    const salt = randomBytes(32);
    const key = scryptSync(oldPassword, salt, 32, { N: scryptN, r: 8, p: 1 });
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, nonce);
    const ciphertext = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()]);
    const tag = cipher.getAuthTag();

    // Rotate
    const result = rotateVaultKey({
      encryptedData: ciphertext,
      currentSalt: salt,
      currentKey: key,
      currentNonce: nonce,
      currentTag: tag,
      newPassword,
      scryptN,
    });

    // Verify can decrypt with new key
    const newDecipher = createDecipheriv("aes-256-gcm", result.newKey, result.newNonce);
    newDecipher.setAuthTag(result.newTag);
    const decrypted = Buffer.concat([
      newDecipher.update(result.encryptedData),
      newDecipher.final(),
    ]).toString("utf-8");

    expect(decrypted).toBe(plaintext);
    expect(result.newSalt.equals(salt)).toBe(false); // New salt
  });

  it("generates new salt on rotation", () => {
    const plaintext = "test";
    const { scryptSync, createCipheriv } = require("crypto");
    const salt = randomBytes(32);
    const key = scryptSync("password", salt, 32, { N: 2 ** 14, r: 8, p: 1 });
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, nonce);
    const ciphertext = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()]);
    const tag = cipher.getAuthTag();

    const result = rotateVaultKey({
      encryptedData: ciphertext,
      currentSalt: salt,
      currentKey: key,
      currentNonce: nonce,
      currentTag: tag,
      newPassword: "password", // Same password
      scryptN: 2 ** 14,
    });

    expect(result.newSalt.equals(salt)).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Capability Re-issuance Tracking Tests
// ─────────────────────────────────────────────────────────────────────────────

describe("Capability re-issuance tracking", () => {
  it("identifies capabilities signed with old key", () => {
    const grants = {
      "cap-1": {
        id: "cap-1",
        expires: new Date(Date.now() + 86400000).toISOString(),
        revoked: false,
      },
      "cap-2": {
        id: "cap-2",
        expires: new Date(Date.now() + 86400000).toISOString(),
        revoked: false,
      },
      "cap-3": {
        id: "cap-3",
        expires: new Date(Date.now() + 86400000).toISOString(),
        revoked: false,
      },
    };

    const capabilityVersions = new Map<string, number>([
      ["cap-1", 1], // Old key
      ["cap-2", 2], // New key
      ["cap-3", 1], // Old key
    ]);

    const needsReissue = identifyCapabilitiesNeedingReissue(grants, 1, capabilityVersions);

    expect(needsReissue.length).toBe(2);
    expect(needsReissue.map((c) => c.id)).toContain("cap-1");
    expect(needsReissue.map((c) => c.id)).toContain("cap-3");
    expect(needsReissue.map((c) => c.id)).not.toContain("cap-2");
  });

  it("excludes revoked capabilities", () => {
    const grants = {
      "cap-1": {
        id: "cap-1",
        expires: new Date(Date.now() + 86400000).toISOString(),
        revoked: true, // Revoked
      },
    };

    const capabilityVersions = new Map([["cap-1", 1]]);

    const needsReissue = identifyCapabilitiesNeedingReissue(grants, 1, capabilityVersions);

    expect(needsReissue.length).toBe(0);
  });

  it("excludes expired capabilities", () => {
    const grants = {
      "cap-1": {
        id: "cap-1",
        expires: new Date(Date.now() - 86400000).toISOString(), // Expired
        revoked: false,
      },
    };

    const capabilityVersions = new Map([["cap-1", 1]]);

    const needsReissue = identifyCapabilitiesNeedingReissue(grants, 1, capabilityVersions);

    expect(needsReissue.length).toBe(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Initialization Helpers Tests
// ─────────────────────────────────────────────────────────────────────────────

describe("Initialization helpers", () => {
  describe("createInitialRotationState", () => {
    it("creates state from existing identity", () => {
      const identity = generateVersionedIdentity(1);

      const state = createInitialRotationState({
        publicKey: identity.publicKey,
        privateKeyPem: identity.privateKeyPem,
        publicKeyPem: identity.publicKeyPem,
        encryptionPublicKey: identity.encryptionPublicKey,
        encryptionPrivateKeyPem: identity.encryptionPrivateKeyPem,
        encryptionPublicKeyPem: identity.encryptionPublicKeyPem,
      });

      expect(state.current.version).toBe(1);
      expect(state.current.publicKey).toBe(identity.publicKey);
      expect(state.archivedKeys).toEqual([]);
      expect(state.previous).toBeUndefined();
    });

    it("generates encryption keys if not present", () => {
      const identity = generateVersionedIdentity(1);

      const state = createInitialRotationState({
        publicKey: identity.publicKey,
        privateKeyPem: identity.privateKeyPem,
        // No encryption keys provided
      });

      expect(state.current.encryptionPublicKey).toBeTruthy();
      expect(state.current.encryptionPrivateKeyPem).toBeTruthy();
    });
  });

  describe("createFreshRotationState", () => {
    it("creates fresh state with new keys", () => {
      const state = createFreshRotationState();

      expect(state.current.version).toBe(1);
      expect(state.current.keyId).toBeTruthy();
      expect(state.current.publicKey).toBeTruthy();
      expect(state.current.encryptionPublicKey).toBeTruthy();
      expect(state.archivedKeys).toEqual([]);
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Edge Cases and Security Tests
// ─────────────────────────────────────────────────────────────────────────────

describe("Edge cases and security", () => {
  it("handles rapid successive rotations", async () => {
    const state = createFreshRotationState();
    const mockSave = createMockSaveFunction();
    const manager = new KeyRotationManager(state, mockSave.save);

    // Rotate 5 times rapidly
    for (let i = 0; i < 5; i++) {
      await manager.rotateSigningKey(24, `Rotation ${i + 1}`);
    }

    expect(manager.getCurrentIdentity().version).toBe(6);
    expect(manager.getArchivedKeys().length).toBe(5);
    expect(mockSave.callCount).toBe(5);
  });

  it("handles zero transition period", async () => {
    const state = createFreshRotationState();
    const mockSave = createMockSaveFunction();
    const manager = new KeyRotationManager(state, mockSave.save);

    const result = await manager.rotateSigningKey(0);

    // Transition should end immediately (or very soon)
    const transitionEnd = new Date(result.transitionEndsAt).getTime();
    expect(transitionEnd).toBeLessThanOrEqual(Date.now() + 1000);
  });

  it("signature determinism - same data produces same signature", () => {
    const state = createFreshRotationState();
    const mockSave = createMockSaveFunction();
    const manager = new KeyRotationManager(state, mockSave.save);

    const data = "Deterministic test data";

    const sig1 = manager.signWithCurrentKey(data);
    const sig2 = manager.signWithCurrentKey(data);

    // Ed25519 is deterministic
    expect(sig1.signature).toBe(sig2.signature);
  });

  it("rejects signature with wrong length", () => {
    const state = createFreshRotationState();
    const mockSave = createMockSaveFunction();
    const manager = new KeyRotationManager(state, mockSave.save);

    const data = "Test data";
    const shortSignature = randomBytes(32).toString("base64"); // Should be 64 bytes
    const publicKey = manager.getCurrentIdentity().publicKey;

    const result = manager.verifyWithAnyValidKey(data, shortSignature, publicKey);

    expect(result.valid).toBe(false);
  });

  it("handles empty data signing", () => {
    const state = createFreshRotationState();
    const mockSave = createMockSaveFunction();
    const manager = new KeyRotationManager(state, mockSave.save);

    const { signature } = manager.signWithCurrentKey("");
    const publicKey = manager.getCurrentIdentity().publicKey;

    const result = manager.verifyWithAnyValidKey("", signature, publicKey);

    expect(result.valid).toBe(true);
  });

  it("handles unicode data signing", () => {
    const state = createFreshRotationState();
    const mockSave = createMockSaveFunction();
    const manager = new KeyRotationManager(state, mockSave.save);

    const data = "Hello \u4e16\u754c! \ud83d\udd10 \u00e9\u00e0\u00fc";
    const { signature } = manager.signWithCurrentKey(data);
    const publicKey = manager.getCurrentIdentity().publicKey;

    const result = manager.verifyWithAnyValidKey(data, signature, publicKey);

    expect(result.valid).toBe(true);
  });
});
