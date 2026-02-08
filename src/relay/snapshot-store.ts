/**
 * Cached Snapshot Store
 *
 * Manages storage of encrypted CACHED tier snapshots on the relay.
 * Snapshots are encrypted by the issuer and can only be decrypted by the recipient.
 * The relay stores them blindly without access to the plaintext.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { homedir } from "os";
import { dirname, join } from "path";
import type { CachedSnapshot } from "../container/secret-store.js";

export interface SnapshotStoreStats {
  totalSnapshots: number;
  totalBytes: number;
  oldestSnapshot: string | null;
  newestSnapshot: string | null;
}

/**
 * In-memory snapshot store with file persistence.
 * For production, this would use a proper database.
 */
export class SnapshotStore {
  private readonly storePath: string;
  private snapshots: Map<string, CachedSnapshot> = new Map();
  private dirty = false;
  private saveTimer: NodeJS.Timeout | null = null;

  constructor(baseDir?: string) {
    const base = baseDir ?? join(homedir(), ".ocmt", "relay");
    this.storePath = join(base, "snapshots.json");

    // Ensure directory exists
    const dir = dirname(this.storePath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
    }

    // Load existing data
    this.load();
  }

  /**
   * Store a snapshot. Overwrites any existing snapshot for the same capability.
   */
  async store(snapshot: CachedSnapshot): Promise<void> {
    // Validate the snapshot has required fields
    if (!snapshot.capabilityId || !snapshot.encryptedData || !snapshot.signature) {
      throw new Error("Invalid snapshot: missing required fields");
    }

    // Check expiry - don't store already expired snapshots
    if (new Date(snapshot.expiresAt).getTime() < Date.now()) {
      throw new Error("Snapshot has already expired");
    }

    this.snapshots.set(snapshot.capabilityId, snapshot);
    this.scheduleSave();
  }

  /**
   * Retrieve a snapshot by capability ID.
   */
  get(capabilityId: string): CachedSnapshot | null {
    const snapshot = this.snapshots.get(capabilityId);

    // Check if expired
    if (snapshot && new Date(snapshot.expiresAt).getTime() < Date.now()) {
      // Clean up expired snapshot
      this.snapshots.delete(capabilityId);
      this.scheduleSave();
      return null;
    }

    return snapshot ?? null;
  }

  /**
   * Delete a snapshot.
   */
  async delete(capabilityId: string): Promise<boolean> {
    const existed = this.snapshots.delete(capabilityId);
    if (existed) {
      this.scheduleSave();
    }
    return existed;
  }

  /**
   * Check if a snapshot exists.
   */
  has(capabilityId: string): boolean {
    return this.get(capabilityId) !== null;
  }

  /**
   * Clean up expired snapshots.
   */
  async cleanup(): Promise<number> {
    const now = Date.now();
    let removed = 0;

    const entries = Array.from(this.snapshots.entries());
    for (const [id, snapshot] of entries) {
      if (new Date(snapshot.expiresAt).getTime() < now) {
        this.snapshots.delete(id);
        removed++;
      }
    }

    if (removed > 0) {
      this.scheduleSave();
    }

    return removed;
  }

  /**
   * Get statistics about the snapshot store.
   */
  getStats(): SnapshotStoreStats {
    let totalBytes = 0;
    let oldest: Date | null = null;
    let newest: Date | null = null;

    const snapshots = Array.from(this.snapshots.values());
    for (const snapshot of snapshots) {
      // Estimate size of snapshot
      totalBytes += snapshot.encryptedData.length;
      totalBytes += snapshot.ephemeralPublicKey.length;
      totalBytes += snapshot.nonce.length;
      totalBytes += snapshot.tag.length;
      totalBytes += snapshot.signature.length;

      const created = new Date(snapshot.createdAt);
      if (!oldest || created < oldest) {
        oldest = created;
      }
      if (!newest || created > newest) {
        newest = created;
      }
    }

    return {
      totalSnapshots: this.snapshots.size,
      totalBytes,
      oldestSnapshot: oldest?.toISOString() ?? null,
      newestSnapshot: newest?.toISOString() ?? null,
    };
  }

  /**
   * Force save to disk.
   */
  async save(): Promise<void> {
    if (this.saveTimer) {
      clearTimeout(this.saveTimer);
      this.saveTimer = null;
    }

    const data = {
      version: 1,
      snapshots: Object.fromEntries(this.snapshots),
    };
    writeFileSync(this.storePath, JSON.stringify(data, null, 2), { mode: 0o600 });

    this.dirty = false;
  }

  /**
   * Close the store, saving any pending changes.
   */
  async close(): Promise<void> {
    if (this.dirty) {
      await this.save();
    }
  }

  /**
   * Load data from disk.
   */
  private load(): void {
    if (existsSync(this.storePath)) {
      try {
        const raw = readFileSync(this.storePath, "utf-8");
        const data = JSON.parse(raw);

        if (data.version === 1 && data.snapshots) {
          this.snapshots = new Map(Object.entries(data.snapshots));

          // Clean up any expired snapshots on load
          const now = Date.now();
          const entries = Array.from(this.snapshots.entries());
          for (const [id, snapshot] of entries) {
            if (new Date((snapshot as CachedSnapshot).expiresAt).getTime() < now) {
              this.snapshots.delete(id);
            }
          }
        }
      } catch (err) {
        console.error("[SnapshotStore] Failed to load snapshots:", err);
      }
    }
  }

  /**
   * Schedule a save operation (debounced).
   */
  private scheduleSave(): void {
    this.dirty = true;
    if (this.saveTimer) {
      return;
    }

    this.saveTimer = setTimeout(() => {
      this.save().catch((err) => {
        console.error("[SnapshotStore] Failed to save:", err);
      });
    }, 1000);
  }
}

// Singleton instance
let instance: SnapshotStore | null = null;

export function getSnapshotStore(baseDir?: string): SnapshotStore {
  if (!instance) {
    instance = new SnapshotStore(baseDir);
  }
  return instance;
}

/**
 * Reset the singleton (for testing).
 */
export function resetSnapshotStore(): void {
  instance = null;
}
