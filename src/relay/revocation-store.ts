/**
 * Capability Revocation Store
 *
 * Manages the persistent storage and fast lookup of revoked capabilities.
 * Uses a SQLite database for persistence and a Bloom filter for fast rejection.
 *
 * Architecture:
 * 1. Bloom filter provides O(1) "definitely not revoked" answers
 * 2. SQLite provides authoritative revocation records
 * 3. On startup, Bloom filter is rebuilt from SQLite
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { homedir } from "os";
import { dirname, join } from "path";
import { BloomFilter, createRevocationBloomFilter } from "./bloom-filter.js";

export interface RevocationRecord {
  /** The revoked capability ID */
  capabilityId: string;
  /** When the revocation was recorded (ISO timestamp) */
  revokedAt: string;
  /** Public key of the revoker (issuer of the capability) */
  revokedBy: string;
  /** Optional reason for revocation */
  reason?: string;
  /** Original capability expiry time (for cleanup) */
  originalExpiry?: string;
}

export interface RevocationCheckResult {
  /** Whether the capability is revoked */
  revoked: boolean;
  /** The revocation record if revoked */
  record?: RevocationRecord;
  /** Whether the result came from Bloom filter (fast path) or database */
  source: "bloom-filter" | "database";
}

/**
 * In-memory revocation store with Bloom filter optimization.
 * For production, this would use SQLite or another persistent store.
 */
export class RevocationStore {
  private readonly storePath: string;
  private readonly bloomPath: string;
  private bloomFilter: BloomFilter;
  private revocations: Map<string, RevocationRecord> = new Map();
  private dirty = false;
  private saveTimer: NodeJS.Timeout | null = null;

  // Stats for monitoring
  private stats = {
    bloomChecks: 0,
    bloomHits: 0, // Bloom filter said "might contain"
    dbChecks: 0,
    falsePositives: 0, // Bloom filter said yes, but DB said no
  };

  constructor(baseDir?: string) {
    const base = baseDir ?? join(homedir(), ".ocmt", "relay");
    this.storePath = join(base, "revocations.json");
    this.bloomPath = join(base, "revocations.bloom");

    // Ensure directory exists
    const dir = dirname(this.storePath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
    }

    // Initialize Bloom filter
    this.bloomFilter = createRevocationBloomFilter();

    // Load existing data
    this.load();
  }

  /**
   * Check if a capability has been revoked.
   * Uses Bloom filter for fast rejection path.
   */
  isRevoked(capabilityId: string): RevocationCheckResult {
    this.stats.bloomChecks++;

    // Fast path: Bloom filter says definitely not revoked
    if (!this.bloomFilter.mightContain(capabilityId)) {
      return { revoked: false, source: "bloom-filter" };
    }

    // Bloom filter says might be revoked - check authoritative store
    this.stats.bloomHits++;
    this.stats.dbChecks++;

    const record = this.revocations.get(capabilityId);
    if (record) {
      return { revoked: true, record, source: "database" };
    }

    // False positive from Bloom filter
    this.stats.falsePositives++;
    return { revoked: false, source: "database" };
  }

  /**
   * Add a revocation record.
   */
  async revoke(
    capabilityId: string,
    revokedBy: string,
    options?: { reason?: string; originalExpiry?: string },
  ): Promise<RevocationRecord> {
    // Check if already revoked
    if (this.revocations.has(capabilityId)) {
      return this.revocations.get(capabilityId)!;
    }

    const record: RevocationRecord = {
      capabilityId,
      revokedAt: new Date().toISOString(),
      revokedBy,
      reason: options?.reason,
      originalExpiry: options?.originalExpiry,
    };

    // Add to persistent store
    this.revocations.set(capabilityId, record);

    // Add to Bloom filter
    this.bloomFilter.add(capabilityId);

    // Schedule save
    this.scheduleSave();

    return record;
  }

  /**
   * Get a specific revocation record.
   */
  getRevocation(capabilityId: string): RevocationRecord | null {
    return this.revocations.get(capabilityId) ?? null;
  }

  /**
   * List all revocations (paginated).
   */
  listRevocations(options?: { limit?: number; offset?: number; revokedBy?: string }): {
    records: RevocationRecord[];
    total: number;
  } {
    let records = Array.from(this.revocations.values());

    // Filter by revoker if specified
    if (options?.revokedBy) {
      records = records.filter((r) => r.revokedBy === options.revokedBy);
    }

    const total = records.length;

    // Sort by revocation time (newest first)
    records.sort((a, b) => new Date(b.revokedAt).getTime() - new Date(a.revokedAt).getTime());

    // Apply pagination
    const offset = options?.offset ?? 0;
    const limit = options?.limit ?? 100;
    records = records.slice(offset, offset + limit);

    return { records, total };
  }

  /**
   * Clean up expired revocations.
   * Revocations can be removed after the original capability would have expired anyway.
   */
  async cleanup(beforeDate?: Date): Promise<number> {
    const cutoff = beforeDate ?? new Date();
    let removed = 0;

    for (const [id, record] of this.revocations) {
      if (record.originalExpiry) {
        const expiry = new Date(record.originalExpiry);
        if (expiry < cutoff) {
          this.revocations.delete(id);
          removed++;
        }
      }
    }

    if (removed > 0) {
      // Rebuild Bloom filter after cleanup
      this.rebuildBloomFilter();
      this.scheduleSave();
    }

    return removed;
  }

  /**
   * Get statistics about the revocation store.
   */
  getStats(): {
    totalRevocations: number;
    bloomFilterSize: number;
    bloomFilterFPR: number;
    bloomChecks: number;
    bloomHits: number;
    dbChecks: number;
    falsePositives: number;
    falsePositiveRate: number;
  } {
    return {
      totalRevocations: this.revocations.size,
      bloomFilterSize: this.bloomFilter.getItemCount(),
      bloomFilterFPR: this.bloomFilter.getEstimatedFalsePositiveRate(),
      bloomChecks: this.stats.bloomChecks,
      bloomHits: this.stats.bloomHits,
      dbChecks: this.stats.dbChecks,
      falsePositives: this.stats.falsePositives,
      falsePositiveRate:
        this.stats.bloomHits > 0 ? this.stats.falsePositives / this.stats.bloomHits : 0,
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

    // Save revocations as JSON
    const data = {
      version: 1,
      revocations: Object.fromEntries(this.revocations),
    };
    writeFileSync(this.storePath, JSON.stringify(data, null, 2), { mode: 0o600 });

    // Save Bloom filter
    writeFileSync(this.bloomPath, this.bloomFilter.serialize(), { mode: 0o600 });

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
    // Load revocations
    if (existsSync(this.storePath)) {
      try {
        const raw = readFileSync(this.storePath, "utf-8");
        const data = JSON.parse(raw);

        if (data.version === 1 && data.revocations) {
          this.revocations = new Map(Object.entries(data.revocations));
        }
      } catch (err) {
        console.error("[RevocationStore] Failed to load revocations:", err);
      }
    }

    // Try to load Bloom filter, or rebuild if missing/corrupted
    if (existsSync(this.bloomPath)) {
      try {
        const bloomData = readFileSync(this.bloomPath);
        this.bloomFilter = BloomFilter.deserialize(bloomData);
      } catch (err) {
        console.warn("[RevocationStore] Failed to load Bloom filter, rebuilding:", err);
        this.rebuildBloomFilter();
      }
    } else {
      this.rebuildBloomFilter();
    }
  }

  /**
   * Rebuild the Bloom filter from the revocations map.
   */
  private rebuildBloomFilter(): void {
    this.bloomFilter = createRevocationBloomFilter(Math.max(this.revocations.size * 2, 100_000));
    for (const capabilityId of this.revocations.keys()) {
      this.bloomFilter.add(capabilityId);
    }
  }

  /**
   * Schedule a save operation (debounced).
   */
  private scheduleSave(): void {
    this.dirty = true;
    if (this.saveTimer) {
      return; // Already scheduled
    }

    this.saveTimer = setTimeout(() => {
      this.save().catch((err) => {
        console.error("[RevocationStore] Failed to save:", err);
      });
    }, 1000);
  }
}

// Singleton instance
let instance: RevocationStore | null = null;

export function getRevocationStore(baseDir?: string): RevocationStore {
  if (!instance) {
    instance = new RevocationStore(baseDir);
  }
  return instance;
}

/**
 * Reset the singleton (for testing).
 */
export function resetRevocationStore(): void {
  instance = null;
}
