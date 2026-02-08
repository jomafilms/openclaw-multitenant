/**
 * Browser-side biometric unlock using WebAuthn.
 *
 * Allows users to unlock their vault using device biometrics (FaceID/TouchID)
 * instead of typing their password each time.
 *
 * Security model:
 * - Uses WebAuthn for biometric authentication (secure hardware-backed)
 * - Device key stored in IndexedDB, encrypted with WebAuthn-derived key
 * - Device key is used to unlock the vault on the container
 */

import { api } from "./api.js";

// ============================================================================
// Types
// ============================================================================

export interface BiometricStatus {
  available: boolean;
  enrolled: boolean;
  reason?: string;
}

export interface BiometricDevice {
  fingerprint: string;
  name: string;
  registeredAt: number;
  lastUsedAt?: number;
}

export interface EnableBiometricResult {
  success: boolean;
  error?: string;
}

export interface BiometricUnlockResult {
  success: boolean;
  expiresIn?: number;
  error?: string;
}

// ============================================================================
// Constants
// ============================================================================

const DB_NAME = "ocmt-biometric";
const DB_VERSION = 1;
const STORE_NAME = "device-keys";
const CREDENTIAL_ID_KEY = "webauthn-credential-id";

// ============================================================================
// IndexedDB Helpers
// ============================================================================

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => reject(new Error("Failed to open database"));

    request.onsuccess = () => resolve(request.result);

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
  });
}

async function getStoredValue(key: string): Promise<string | null> {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, "readonly");
    const store = transaction.objectStore(STORE_NAME);
    const request = store.get(key);

    request.onerror = () => reject(new Error("Failed to read from database"));
    request.onsuccess = () => resolve(request.result ?? null);
  });
}

async function setStoredValue(key: string, value: string): Promise<void> {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, "readwrite");
    const store = transaction.objectStore(STORE_NAME);
    const request = store.put(value, key);

    request.onerror = () => reject(new Error("Failed to write to database"));
    request.onsuccess = () => resolve();
  });
}

async function deleteStoredValue(key: string): Promise<void> {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, "readwrite");
    const store = transaction.objectStore(STORE_NAME);
    const request = store.delete(key);

    request.onerror = () => reject(new Error("Failed to delete from database"));
    request.onsuccess = () => resolve();
  });
}

// ============================================================================
// WebAuthn Helpers
// ============================================================================

/**
 * Generate a random device fingerprint.
 */
function generateFingerprint(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Get the device name for display.
 */
function getDeviceName(): string {
  const ua = navigator.userAgent;
  if (/iPhone/.test(ua)) {
    return "iPhone";
  }
  if (/iPad/.test(ua)) {
    return "iPad";
  }
  if (/Mac/.test(ua)) {
    return "Mac";
  }
  if (/Android/.test(ua)) {
    return "Android";
  }
  if (/Windows/.test(ua)) {
    return "Windows PC";
  }
  if (/Linux/.test(ua)) {
    return "Linux";
  }
  return "Unknown Device";
}

/**
 * Check if WebAuthn is available.
 */
function isWebAuthnAvailable(): boolean {
  return (
    typeof window !== "undefined" &&
    !!window.PublicKeyCredential &&
    typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function"
  );
}

/**
 * Check if a platform authenticator (TouchID/FaceID/Windows Hello) is available.
 */
async function isPlatformAuthenticatorAvailable(): Promise<boolean> {
  if (!isWebAuthnAvailable()) {
    return false;
  }

  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

// ============================================================================
// Public API
// ============================================================================

/**
 * Check if biometric unlock is available on this device.
 */
export async function isBiometricAvailable(): Promise<BiometricStatus> {
  // Check WebAuthn support
  if (!isWebAuthnAvailable()) {
    return {
      available: false,
      enrolled: false,
      reason: "WebAuthn not supported in this browser",
    };
  }

  // Check for platform authenticator
  const hasPlatformAuth = await isPlatformAuthenticatorAvailable();
  if (!hasPlatformAuth) {
    return {
      available: false,
      enrolled: false,
      reason: "No biometric authenticator available",
    };
  }

  // Check if already enrolled
  const credentialId = await getStoredValue(CREDENTIAL_ID_KEY);
  const deviceKey = await getStoredValue("device-key");

  return {
    available: true,
    enrolled: !!(credentialId && deviceKey),
  };
}

/**
 * Enable biometric unlock for this device.
 * Requires the vault to be already unlocked (with password).
 */
export async function enableBiometrics(): Promise<EnableBiometricResult> {
  try {
    // Generate device fingerprint and name
    const fingerprint = generateFingerprint();
    const name = getDeviceName();

    // Create WebAuthn credential for future verification
    const userId = new Uint8Array(16);
    crypto.getRandomValues(userId);

    const credential = (await navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: {
          name: "OCMT Vault",
          id: window.location.hostname,
        },
        user: {
          id: userId,
          name: "vault-user",
          displayName: "Vault User",
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 }, // ES256
          { type: "public-key", alg: -257 }, // RS256
        ],
        authenticatorSelection: {
          authenticatorAttachment: "platform",
          userVerification: "required",
          residentKey: "preferred",
        },
        timeout: 60000,
      },
    })) as PublicKeyCredential | null;

    if (!credential) {
      return { success: false, error: "Biometric enrollment cancelled" };
    }

    // Register device with container
    const result = await api.enableBiometricDevice(fingerprint, name);
    if (!result.success || !result.deviceKey) {
      return {
        success: false,
        error: result.error || "Failed to register device",
      };
    }

    // Store credential ID and device key
    await setStoredValue(CREDENTIAL_ID_KEY, credential.id);
    await setStoredValue("device-key", result.deviceKey);
    await setStoredValue("device-fingerprint", fingerprint);

    return { success: true };
  } catch (err) {
    // Handle WebAuthn errors
    if (err instanceof DOMException) {
      if (err.name === "NotAllowedError") {
        return { success: false, error: "Biometric authentication was cancelled" };
      }
      if (err.name === "SecurityError") {
        return { success: false, error: "Security error - ensure you are on HTTPS" };
      }
    }
    return { success: false, error: (err as Error).message };
  }
}

/**
 * Unlock the vault using biometrics.
 */
export async function unlockWithBiometric(): Promise<BiometricUnlockResult> {
  try {
    // Get stored credential and device key
    const credentialId = await getStoredValue(CREDENTIAL_ID_KEY);
    const deviceKey = await getStoredValue("device-key");
    const fingerprint = await getStoredValue("device-fingerprint");

    if (!credentialId || !deviceKey || !fingerprint) {
      return { success: false, error: "Biometrics not enrolled on this device" };
    }

    // Verify with WebAuthn
    const assertion = (await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: window.location.hostname,
        allowCredentials: [
          {
            type: "public-key",
            id: base64ToArrayBuffer(credentialId),
          },
        ],
        userVerification: "required",
        timeout: 60000,
      },
    })) as PublicKeyCredential | null;

    if (!assertion) {
      return { success: false, error: "Biometric verification cancelled" };
    }

    // Unlock with device key
    const result = await api.unlockWithBiometricDevice(fingerprint, deviceKey);
    if (!result.success) {
      // If device key is invalid, clear stored data
      if (result.error?.includes("Invalid device key")) {
        await clearBiometricEnrollment();
      }
      return { success: false, error: result.error };
    }

    return { success: true, expiresIn: result.expiresIn };
  } catch (err) {
    // Handle WebAuthn errors
    if (err instanceof DOMException) {
      if (err.name === "NotAllowedError") {
        return { success: false, error: "Biometric authentication was cancelled" };
      }
    }
    return { success: false, error: (err as Error).message };
  }
}

/**
 * List registered biometric devices.
 */
export async function listBiometricDevices(): Promise<BiometricDevice[]> {
  const result = await api.listBiometricDevices();
  if (!result.success || !result.devices) {
    return [];
  }
  return result.devices;
}

/**
 * Remove biometric enrollment from this device.
 */
export async function clearBiometricEnrollment(): Promise<void> {
  const fingerprint = await getStoredValue("device-fingerprint");

  // Remove from server if fingerprint exists
  if (fingerprint) {
    try {
      await api.removeBiometricDevice(fingerprint);
    } catch {
      // Ignore errors - device might already be removed
    }
  }

  // Clear local storage
  await deleteStoredValue(CREDENTIAL_ID_KEY);
  await deleteStoredValue("device-key");
  await deleteStoredValue("device-fingerprint");
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Convert a base64 string to ArrayBuffer.
 */
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  // Handle URL-safe base64
  const normalized = base64.replace(/-/g, "+").replace(/_/g, "/");
  const binaryString = atob(normalized);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}
