/**
 * Browser-side vault cryptography
 *
 * Handles key derivation and challenge signing entirely in the browser.
 * The password NEVER leaves the browser - only the derived key proof.
 */

// Argon2 parameters (must match container's secret-store.ts)
const ARGON2_TIME_COST = 3;
const ARGON2_MEMORY_COST = 65536; // 64MB
const ARGON2_PARALLELISM = 1;
const ARGON2_HASH_LENGTH = 32;

/**
 * Derive key from password using Argon2id
 * Uses argon2-browser library loaded from CDN
 */
export async function deriveKey(password: string, salt: string): Promise<Uint8Array> {
  // Load argon2-browser if not already loaded
  const argon2 = await loadArgon2();

  const saltBytes = base64ToBytes(salt);

  const result = await argon2.hash({
    pass: password,
    salt: saltBytes,
    time: ARGON2_TIME_COST,
    mem: ARGON2_MEMORY_COST,
    parallelism: ARGON2_PARALLELISM,
    hashLen: ARGON2_HASH_LENGTH,
    type: argon2.ArgonType.Argon2id,
  });

  return result.hash;
}

/**
 * Sign a challenge with the derived key using HMAC-SHA256
 */
export async function signChallenge(challenge: string, derivedKey: Uint8Array): Promise<string> {
  const encoder = new TextEncoder();
  const challengeBytes = encoder.encode(challenge);

  // Import key for HMAC
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    derivedKey,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  // Sign the challenge
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, challengeBytes);

  return bytesToBase64(new Uint8Array(signature));
}

/**
 * Complete unlock flow: derive key and sign challenge
 */
export async function createUnlockResponse(
  password: string,
  salt: string,
  challenge: string,
): Promise<{ response: string; derivedKey: string }> {
  // Derive key from password
  const derivedKey = await deriveKey(password, salt);

  // Sign the challenge
  const response = await signChallenge(challenge, derivedKey);

  return {
    response,
    derivedKey: bytesToBase64(derivedKey),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Argon2 loader
// ─────────────────────────────────────────────────────────────────────────────

interface Argon2Module {
  hash(options: {
    pass: string;
    salt: Uint8Array;
    time: number;
    mem: number;
    parallelism: number;
    hashLen: number;
    type: number;
  }): Promise<{ hash: Uint8Array; hashHex: string; encoded: string }>;
  ArgonType: {
    Argon2d: number;
    Argon2i: number;
    Argon2id: number;
  };
}

let argon2Promise: Promise<Argon2Module> | null = null;

async function loadArgon2(): Promise<Argon2Module> {
  if (argon2Promise) {
    return argon2Promise;
  }

  argon2Promise = new Promise((resolve, reject) => {
    // Check if already loaded
    if ((window as unknown as { argon2?: Argon2Module }).argon2) {
      resolve((window as unknown as { argon2: Argon2Module }).argon2);
      return;
    }

    // Load from CDN
    const script = document.createElement("script");
    script.src = "https://cdn.jsdelivr.net/npm/argon2-browser@1.18.0/dist/argon2-bundled.min.js";
    script.async = true;

    script.onload = () => {
      const argon2 = (window as unknown as { argon2?: Argon2Module }).argon2;
      if (argon2) {
        resolve(argon2);
      } else {
        reject(new Error("Argon2 failed to load"));
      }
    };

    script.onerror = () => {
      reject(new Error("Failed to load argon2-browser"));
    };

    document.head.appendChild(script);
  });

  return argon2Promise;
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility functions
// ─────────────────────────────────────────────────────────────────────────────

function base64ToBytes(base64: string): Uint8Array {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// ─────────────────────────────────────────────────────────────────────────────
// Session Encryption Key Derivation (for encrypted session storage)
// ─────────────────────────────────────────────────────────────────────────────

export interface SessionKdfParams {
  salt: string; // Base64 encoded
  memory: number; // e.g., 65536 (64 MB)
  iterations: number; // e.g., 3
  parallelism: number; // e.g., 4
}

/**
 * Derive session encryption key from password using dynamic KDF parameters.
 * This is used for encrypted session storage (different from the vault unlock flow).
 *
 * @param password - User's vault password
 * @param params - KDF parameters from the container
 * @returns Derived key as Uint8Array (32 bytes)
 */
export async function deriveSessionKey(
  password: string,
  params: SessionKdfParams,
): Promise<Uint8Array> {
  const argon2 = await loadArgon2();
  const saltBytes = base64ToBytes(params.salt);

  const result = await argon2.hash({
    pass: password,
    salt: saltBytes,
    time: params.iterations,
    mem: params.memory,
    parallelism: params.parallelism,
    hashLen: ARGON2_HASH_LENGTH,
    type: argon2.ArgonType.Argon2id,
  });

  return result.hash;
}

/**
 * Encode a derived key for transport (base64).
 */
export function encodeKey(key: Uint8Array): string {
  return bytesToBase64(key);
}

/**
 * Securely clear a key from memory by overwriting with random bytes.
 */
export function clearKey(key: Uint8Array): void {
  crypto.getRandomValues(key);
}

/**
 * Create session unlock payload from password and KDF params.
 * Used for the direct session unlock flow (simpler than challenge-response).
 */
export async function createSessionUnlockPayload(
  password: string,
  params: SessionKdfParams,
): Promise<{ derivedKey: string }> {
  const key = await deriveSessionKey(password, params);
  const encodedKey = encodeKey(key);

  // Clear the original key from memory
  clearKey(key);

  return { derivedKey: encodedKey };
}
