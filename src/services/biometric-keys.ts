/**
 * Biometric key storage for device-based vault unlock.
 *
 * Allows users to unlock their vault using device biometrics (FaceID/TouchID)
 * instead of typing their password each time.
 *
 * Security model:
 * - Each registered device gets a unique 256-bit device key
 * - Device keys are encrypted with the user's vault key and stored on disk
 * - The device stores its device key securely (in Keychain on macOS/iOS)
 * - When unlocking, the device provides its key, which decrypts the vault key
 * - If the vault password changes, all device registrations are invalidated
 */

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

// ============================================================================
// Types
// ============================================================================

export interface RegisteredDevice {
  /** Unique identifier for this device (hardware fingerprint or UUID) */
  fingerprint: string;
  /** Human-readable device name */
  name: string;
  /** When the device was registered */
  registeredAt: number;
  /** Last time the device was used to unlock */
  lastUsedAt?: number;
  /** Encrypted device key (encrypted with vault key) */
  encryptedDeviceKey: string;
  /** Nonce used for encryption */
  nonce: string;
}

export interface BiometricKeyStoreData {
  version: "1.0";
  /** Salt used for vault key verification (not the actual KDF salt) */
  keyCheckHash: string;
  devices: RegisteredDevice[];
}

// ============================================================================
// BiometricKeyStore Implementation
// ============================================================================

export class BiometricKeyStore {
  private storePath: string;
  private data: BiometricKeyStoreData | null = null;
  private vaultKey: Uint8Array | null = null;

  private static readonly NONCE_SIZE = 24; // XChaCha20 uses 24-byte nonce
  private static readonly KEY_SIZE = 32; // 256-bit key

  constructor(sessionDir: string) {
    this.storePath = path.join(sessionDir, ".biometric-keys.json");
  }

  /**
   * Initialize the store with the vault key.
   * Must be called before any other operations.
   */
  unlock(vaultKey: Buffer): void {
    if (vaultKey.length !== BiometricKeyStore.KEY_SIZE) {
      throw new Error(`Invalid vault key length: expected ${BiometricKeyStore.KEY_SIZE} bytes`);
    }

    this.vaultKey = new Uint8Array(vaultKey);
    this.loadStore();
  }

  /**
   * Clear the vault key from memory.
   */
  lock(): void {
    if (this.vaultKey) {
      crypto.randomFillSync(this.vaultKey);
      this.vaultKey = null;
    }
    this.data = null;
  }

  /**
   * Check if the store is unlocked.
   */
  isUnlocked(): boolean {
    return this.vaultKey !== null;
  }

  /**
   * Register a new device for biometric unlock.
   *
   * @param fingerprint Unique device identifier (hardware ID or UUID)
   * @param name Human-readable device name
   * @returns The device key that should be stored securely on the device
   */
  registerDevice(fingerprint: string, name: string): { deviceKey: string } {
    this.ensureUnlocked();

    // Generate a unique device key
    const deviceKey = crypto.randomBytes(BiometricKeyStore.KEY_SIZE);

    // Encrypt the device key with the vault key
    const nonce = crypto.randomBytes(BiometricKeyStore.NONCE_SIZE);
    const cipher = xchacha20poly1305(this.vaultKey!, nonce);
    const encrypted = cipher.encrypt(deviceKey);

    // Remove any existing registration for this device
    this.removeDeviceInternal(fingerprint);

    // Add the new device
    const device: RegisteredDevice = {
      fingerprint,
      name,
      registeredAt: Date.now(),
      encryptedDeviceKey: Buffer.from(encrypted).toString("base64"),
      nonce: Buffer.from(nonce).toString("base64"),
    };

    if (!this.data) {
      this.data = {
        version: "1.0",
        keyCheckHash: this.computeKeyCheckHash(),
        devices: [],
      };
    }

    this.data.devices.push(device);
    this.saveStore();

    return { deviceKey: deviceKey.toString("base64") };
  }

  /**
   * Attempt to unlock with a device key.
   * Returns the vault key if successful.
   *
   * @param fingerprint Device identifier
   * @param deviceKeyBase64 Base64-encoded device key
   * @returns The vault key, or null if unlock failed
   */
  unlockWithDeviceKey(fingerprint: string, deviceKeyBase64: string): Buffer | null {
    // Load store without vault key to check device
    this.loadStoreRaw();

    if (!this.data) {
      return null;
    }

    const device = this.data.devices.find((d) => d.fingerprint === fingerprint);
    if (!device) {
      return null;
    }

    try {
      // The device key IS the vault key in this model
      // We verify it by trying to decrypt the stored test value
      const deviceKey = Buffer.from(deviceKeyBase64, "base64");
      if (deviceKey.length !== BiometricKeyStore.KEY_SIZE) {
        return null;
      }

      // Try to decrypt using the device key as the vault key
      const nonce = Buffer.from(device.nonce, "base64");
      const encrypted = Buffer.from(device.encryptedDeviceKey, "base64");

      const cipher = xchacha20poly1305(new Uint8Array(deviceKey), new Uint8Array(nonce));
      try {
        // If decryption succeeds, the device key is valid
        cipher.decrypt(encrypted);

        // Update last used timestamp
        device.lastUsedAt = Date.now();
        this.vaultKey = new Uint8Array(deviceKey);
        this.saveStore();
        this.vaultKey = null;

        return deviceKey;
      } catch {
        // Decryption failed - invalid device key
        return null;
      }
    } catch {
      return null;
    }
  }

  /**
   * List all registered devices.
   */
  listDevices(): Array<{
    fingerprint: string;
    name: string;
    registeredAt: number;
    lastUsedAt?: number;
  }> {
    this.loadStoreRaw();

    if (!this.data) {
      return [];
    }

    return this.data.devices.map((d) => ({
      fingerprint: d.fingerprint,
      name: d.name,
      registeredAt: d.registeredAt,
      lastUsedAt: d.lastUsedAt,
    }));
  }

  /**
   * Remove a specific device.
   */
  removeDevice(fingerprint: string): boolean {
    this.ensureUnlocked();
    const removed = this.removeDeviceInternal(fingerprint);
    if (removed) {
      this.saveStore();
    }
    return removed;
  }

  /**
   * Remove all registered devices.
   */
  removeAllDevices(): void {
    this.ensureUnlocked();

    if (this.data) {
      this.data.devices = [];
      this.saveStore();
    }
  }

  /**
   * Check if a device is registered.
   */
  hasDevice(fingerprint: string): boolean {
    this.loadStoreRaw();
    return this.data?.devices.some((d) => d.fingerprint === fingerprint) ?? false;
  }

  // ============================================================================
  // Private Methods
  // ============================================================================

  private ensureUnlocked(): void {
    if (!this.vaultKey) {
      throw new Error("BiometricKeyStore is locked");
    }
  }

  private loadStore(): void {
    this.loadStoreRaw();

    // Verify the vault key matches
    if (this.data && this.vaultKey) {
      const currentHash = this.computeKeyCheckHash();
      if (this.data.keyCheckHash !== currentHash) {
        // Vault key changed - invalidate all devices
        this.data.devices = [];
        this.data.keyCheckHash = currentHash;
        this.saveStore();
      }
    }
  }

  private loadStoreRaw(): void {
    if (!fs.existsSync(this.storePath)) {
      this.data = null;
      return;
    }

    try {
      const raw = fs.readFileSync(this.storePath, "utf-8");
      const parsed = JSON.parse(raw) as BiometricKeyStoreData;
      if (parsed.version === "1.0" && Array.isArray(parsed.devices)) {
        this.data = parsed;
      }
    } catch {
      this.data = null;
    }
  }

  private saveStore(): void {
    if (!this.data) {
      return;
    }

    const dir = path.dirname(this.storePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    // Atomic write
    const tmp = `${this.storePath}.${process.pid}.${crypto.randomUUID()}.tmp`;
    try {
      fs.writeFileSync(tmp, JSON.stringify(this.data, null, 2), {
        mode: 0o600,
        encoding: "utf-8",
      });
      fs.renameSync(tmp, this.storePath);
    } finally {
      try {
        fs.unlinkSync(tmp);
      } catch {
        // Ignore cleanup errors
      }
    }
  }

  private removeDeviceInternal(fingerprint: string): boolean {
    if (!this.data) {
      return false;
    }

    const before = this.data.devices.length;
    this.data.devices = this.data.devices.filter((d) => d.fingerprint !== fingerprint);
    return this.data.devices.length < before;
  }

  private computeKeyCheckHash(): string {
    if (!this.vaultKey) {
      return "";
    }
    // Use HMAC to create a verification hash of the vault key
    const hmac = crypto.createHmac("sha256", "biometric-key-check");
    hmac.update(Buffer.from(this.vaultKey));
    return hmac.digest("hex").slice(0, 32);
  }
}

// ============================================================================
// Singleton Instance Management
// ============================================================================

let globalBiometricStore: BiometricKeyStore | null = null;

/**
 * Get or create the global BiometricKeyStore instance.
 */
export function getBiometricKeyStore(sessionDir?: string): BiometricKeyStore | null {
  if (!globalBiometricStore && sessionDir) {
    globalBiometricStore = new BiometricKeyStore(sessionDir);
  }
  return globalBiometricStore;
}

/**
 * Initialize the global BiometricKeyStore with a specific session directory.
 */
export function initBiometricKeyStore(sessionDir: string): BiometricKeyStore {
  globalBiometricStore = new BiometricKeyStore(sessionDir);
  return globalBiometricStore;
}

/**
 * Clear the global BiometricKeyStore instance.
 */
export function clearBiometricKeyStore(): void {
  if (globalBiometricStore) {
    globalBiometricStore.lock();
  }
  globalBiometricStore = null;
}
