/**
 * Encrypted session store that wraps the existing session storage.
 * Uses XChaCha20-Poly1305 for encryption (better than AES-GCM for variable nonces).
 *
 * Security model:
 * - Sessions encrypted at rest with user's vault password
 * - Key derived via Argon2id in browser, sent directly to container
 * - Management server never sees password or derived key
 * - Key held in memory during unlock, securely erased on lock/timeout
 */

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

// ============================================================================
// Types
// ============================================================================

export interface Message {
  role: "user" | "assistant" | "system";
  content: string | Array<{ type: string; text?: string }>;
  [key: string]: unknown;
}

export interface SessionTranscript {
  messages: Message[];
}

export interface EncryptedSessionStoreInterface {
  // Encryption state
  isUnlocked(): boolean;
  getExpiresAt(): number | null;

  // Key management
  unlock(derivedKey: Buffer): Promise<void>;
  lock(): void;
  extend(): void;

  // Session operations (encrypted)
  readSession(sessionId: string): Promise<SessionTranscript>;
  writeSession(sessionId: string, data: SessionTranscript): Promise<void>;
  appendMessage(sessionId: string, message: Message): Promise<void>;

  // Migration
  migrateUnencryptedSessions(): Promise<{ migrated: number; failed: string[] }>;
}

// ============================================================================
// SecureSessionStore Implementation
// ============================================================================

export class SecureSessionStore implements EncryptedSessionStoreInterface {
  private key: Uint8Array | null = null;
  private expiresAt: number = 0;
  private sessionDir: string;
  private autoLockTimer: ReturnType<typeof setTimeout> | null = null;

  private static readonly SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes
  private static readonly ENCRYPTED_SUFFIX = ".enc";
  private static readonly NONCE_SIZE = 24; // XChaCha20 uses 24-byte nonce
  private static readonly KEY_SIZE = 32; // 256-bit key

  constructor(sessionDir: string) {
    this.sessionDir = sessionDir;
  }

  /**
   * Check if the session store is currently unlocked and not expired.
   */
  isUnlocked(): boolean {
    return this.key !== null && Date.now() < this.expiresAt;
  }

  /**
   * Get the expiration timestamp if unlocked, null otherwise.
   */
  getExpiresAt(): number | null {
    return this.isUnlocked() ? this.expiresAt : null;
  }

  /**
   * Get a copy of the current unlock key.
   * Returns null if locked. Use with caution - the key should be handled securely.
   */
  getUnlockKey(): Buffer | null {
    if (!this.isUnlocked() || !this.key) {
      return null;
    }
    // Return a copy to prevent external modification
    return Buffer.from(this.key);
  }

  /**
   * Unlock the session store with a derived key.
   * @param derivedKey - 32-byte key derived from user's password via Argon2id
   */
  async unlock(derivedKey: Buffer): Promise<void> {
    // Validate key length
    if (derivedKey.length !== SecureSessionStore.KEY_SIZE) {
      throw new Error(
        `Invalid key length: expected ${SecureSessionStore.KEY_SIZE} bytes, got ${derivedKey.length}`,
      );
    }

    // Clear any existing key first
    this.lock();

    // Store key in memory
    this.key = new Uint8Array(derivedKey);
    this.expiresAt = Date.now() + SecureSessionStore.SESSION_TIMEOUT;

    // Schedule auto-lock
    this.autoLockTimer = setTimeout(() => {
      this.lock();
    }, SecureSessionStore.SESSION_TIMEOUT);

    // Ensure session directory exists
    await fs.promises.mkdir(this.sessionDir, { recursive: true });
  }

  /**
   * Lock the session store and securely erase the key from memory.
   */
  lock(): void {
    if (this.autoLockTimer) {
      clearTimeout(this.autoLockTimer);
      this.autoLockTimer = null;
    }

    if (this.key) {
      // Secure erase: overwrite with random bytes before releasing
      crypto.randomFillSync(this.key);
      this.key = null;
    }
    this.expiresAt = 0;
  }

  /**
   * Extend the session timeout.
   */
  extend(): void {
    if (this.isUnlocked()) {
      // Clear existing timer
      if (this.autoLockTimer) {
        clearTimeout(this.autoLockTimer);
      }

      // Reset expiration
      this.expiresAt = Date.now() + SecureSessionStore.SESSION_TIMEOUT;

      // Schedule new auto-lock
      this.autoLockTimer = setTimeout(() => {
        this.lock();
      }, SecureSessionStore.SESSION_TIMEOUT);
    }
  }

  /**
   * Encrypt plaintext data using XChaCha20-Poly1305.
   * @returns nonce (24 bytes) + ciphertext (includes 16-byte auth tag)
   */
  private encrypt(plaintext: Uint8Array): Uint8Array {
    if (!this.key) {
      throw new Error("Session store is locked");
    }

    // Generate random nonce
    const nonce = crypto.randomBytes(SecureSessionStore.NONCE_SIZE);

    // Create cipher and encrypt
    const cipher = xchacha20poly1305(this.key, nonce);
    const ciphertext = cipher.encrypt(plaintext);

    // Format: nonce (24 bytes) + ciphertext (includes 16-byte tag)
    const result = new Uint8Array(nonce.length + ciphertext.length);
    result.set(nonce, 0);
    result.set(ciphertext, nonce.length);

    return result;
  }

  /**
   * Decrypt encrypted data using XChaCha20-Poly1305.
   * @param encrypted - nonce (24 bytes) + ciphertext (includes 16-byte auth tag)
   */
  private decrypt(encrypted: Uint8Array): Uint8Array {
    if (!this.key) {
      throw new Error("Session store is locked");
    }

    if (encrypted.length < SecureSessionStore.NONCE_SIZE + 16) {
      throw new Error("Invalid encrypted data: too short");
    }

    // Extract nonce and ciphertext
    const nonce = encrypted.slice(0, SecureSessionStore.NONCE_SIZE);
    const ciphertext = encrypted.slice(SecureSessionStore.NONCE_SIZE);

    // Create cipher and decrypt (will throw if authentication fails)
    const cipher = xchacha20poly1305(this.key, nonce);
    return cipher.decrypt(ciphertext);
  }

  /**
   * Read a session transcript from encrypted storage.
   */
  async readSession(sessionId: string): Promise<SessionTranscript> {
    if (!this.isUnlocked()) {
      throw new Error("Session store is locked");
    }

    const encryptedPath = this.getEncryptedPath(sessionId);
    const plaintextPath = this.getPlaintextPath(sessionId);

    // Try encrypted first
    if (fs.existsSync(encryptedPath)) {
      const encrypted = await fs.promises.readFile(encryptedPath);
      const decrypted = this.decrypt(new Uint8Array(encrypted));
      return this.parseJsonl(decrypted);
    }

    // Fall back to plaintext (legacy/migration)
    if (fs.existsSync(plaintextPath)) {
      const content = await fs.promises.readFile(plaintextPath, "utf-8");
      return this.parseJsonl(new TextEncoder().encode(content));
    }

    throw new Error(`Session not found: ${sessionId}`);
  }

  /**
   * Write a session transcript to encrypted storage.
   * Uses atomic write (temp file + rename) for crash safety.
   */
  async writeSession(sessionId: string, data: SessionTranscript): Promise<void> {
    if (!this.isUnlocked()) {
      throw new Error("Session store is locked");
    }

    const jsonl = this.toJsonl(data, sessionId);
    const encrypted = this.encrypt(new TextEncoder().encode(jsonl));

    const encryptedPath = this.getEncryptedPath(sessionId);
    const tempPath = `${encryptedPath}.${process.pid}.${crypto.randomUUID()}.tmp`;

    // Ensure directory exists
    await fs.promises.mkdir(path.dirname(encryptedPath), { recursive: true });

    // Atomic write: write to temp file, then rename
    try {
      await fs.promises.writeFile(tempPath, Buffer.from(encrypted), { mode: 0o600 });
      await fs.promises.rename(tempPath, encryptedPath);
    } finally {
      // Clean up temp file if it still exists
      await fs.promises.rm(tempPath, { force: true }).catch(() => {
        // ignore cleanup errors
      });
    }

    // Remove plaintext version if exists (migration)
    const plaintextPath = this.getPlaintextPath(sessionId);
    if (fs.existsSync(plaintextPath)) {
      await fs.promises.unlink(plaintextPath);
    }
  }

  /**
   * Append a message to an existing session.
   * Reads the current session, appends the message, and re-encrypts.
   */
  async appendMessage(sessionId: string, message: Message): Promise<void> {
    // Read current session
    let session: SessionTranscript;
    try {
      session = await this.readSession(sessionId);
    } catch {
      session = { messages: [] };
    }

    // Append message
    session.messages.push(message);

    // Write back (full re-encryption)
    await this.writeSession(sessionId, session);
  }

  /**
   * Migrate all unencrypted sessions to encrypted format.
   * @returns Object with count of migrated sessions and list of failed session IDs
   */
  async migrateUnencryptedSessions(): Promise<{ migrated: number; failed: string[] }> {
    if (!this.isUnlocked()) {
      throw new Error("Must unlock before migrating");
    }

    // Ensure directory exists
    if (!fs.existsSync(this.sessionDir)) {
      return { migrated: 0, failed: [] };
    }

    const files = await fs.promises.readdir(this.sessionDir);

    let migrated = 0;
    const failed: string[] = [];

    for (const file of files) {
      // Only migrate .jsonl files (not already .jsonl.enc)
      if (file.endsWith(".jsonl") && !file.endsWith(".jsonl.enc")) {
        const sessionId = file.replace(".jsonl", "");
        try {
          const plaintextPath = `${this.sessionDir}/${file}`;
          const content = await fs.promises.readFile(plaintextPath, "utf-8");
          const data = this.parseJsonl(new TextEncoder().encode(content));
          await this.writeSession(sessionId, data);
          migrated++;
        } catch (err) {
          failed.push(sessionId);
          console.error(`Failed to migrate session ${sessionId}:`, err);
        }
      }
    }

    return { migrated, failed };
  }

  /**
   * Check if a session exists (either encrypted or plaintext).
   */
  sessionExists(sessionId: string): boolean {
    return (
      fs.existsSync(this.getEncryptedPath(sessionId)) ||
      fs.existsSync(this.getPlaintextPath(sessionId))
    );
  }

  /**
   * List all session IDs (both encrypted and plaintext).
   */
  async listSessions(): Promise<string[]> {
    if (!fs.existsSync(this.sessionDir)) {
      return [];
    }

    const files = await fs.promises.readdir(this.sessionDir);
    const sessionIds = new Set<string>();

    for (const file of files) {
      if (file.endsWith(".jsonl.enc")) {
        sessionIds.add(file.replace(".jsonl.enc", ""));
      } else if (file.endsWith(".jsonl")) {
        sessionIds.add(file.replace(".jsonl", ""));
      }
    }

    return Array.from(sessionIds);
  }

  /**
   * Delete a session (both encrypted and plaintext versions).
   */
  async deleteSession(sessionId: string): Promise<void> {
    const encryptedPath = this.getEncryptedPath(sessionId);
    const plaintextPath = this.getPlaintextPath(sessionId);

    await fs.promises.rm(encryptedPath, { force: true });
    await fs.promises.rm(plaintextPath, { force: true });
  }

  // ============================================================================
  // Private Helpers
  // ============================================================================

  private getEncryptedPath(sessionId: string): string {
    return `${this.sessionDir}/${sessionId}.jsonl${SecureSessionStore.ENCRYPTED_SUFFIX}`;
  }

  private getPlaintextPath(sessionId: string): string {
    return `${this.sessionDir}/${sessionId}.jsonl`;
  }

  /**
   * Parse JSONL format into SessionTranscript.
   * Handles both the header line and message lines.
   */
  private parseJsonl(data: Uint8Array): SessionTranscript {
    const content = new TextDecoder().decode(data);
    const lines = content.trim().split("\n");
    const messages: Message[] = [];

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) {
        continue;
      }

      try {
        const entry = JSON.parse(trimmed);

        // Skip header/metadata lines
        if (entry.type === "session" || entry.type === "summary") {
          continue;
        }

        // Extract message from message entry
        if (entry.type === "message" && entry.message) {
          messages.push(entry.message);
        } else if (entry.role && (entry.content !== undefined || entry.text !== undefined)) {
          // Direct message format (role + content)
          messages.push(entry as Message);
        }
      } catch {
        // Skip malformed lines
        console.warn("Skipping malformed JSONL line:", trimmed.slice(0, 100));
      }
    }

    return { messages };
  }

  /**
   * Convert SessionTranscript to JSONL format.
   */
  private toJsonl(session: SessionTranscript, sessionId?: string): string {
    const lines: string[] = [];

    // Header
    lines.push(
      JSON.stringify({
        type: "session",
        version: "1.0",
        id: sessionId ?? crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        encrypted: true,
      }),
    );

    // Messages
    for (const message of session.messages) {
      lines.push(JSON.stringify({ type: "message", message }));
    }

    return lines.join("\n") + "\n";
  }
}

// ============================================================================
// Singleton Instance Management
// ============================================================================

let globalSecureStore: SecureSessionStore | null = null;

/**
 * Get or create the global SecureSessionStore instance.
 */
export function getSecureSessionStore(sessionDir?: string): SecureSessionStore | null {
  if (!globalSecureStore && sessionDir) {
    globalSecureStore = new SecureSessionStore(sessionDir);
  }
  return globalSecureStore;
}

/**
 * Initialize the global SecureSessionStore with a specific session directory.
 */
export function initSecureSessionStore(sessionDir: string): SecureSessionStore {
  globalSecureStore = new SecureSessionStore(sessionDir);
  return globalSecureStore;
}

/**
 * Clear the global SecureSessionStore instance.
 * Primarily for testing.
 */
export function clearSecureSessionStore(): void {
  if (globalSecureStore) {
    globalSecureStore.lock();
  }
  globalSecureStore = null;
}
