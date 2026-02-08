/**
 * Snapshot Store Tests
 */

import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { CachedSnapshot } from "../container/secret-store.js";
import { SnapshotStore } from "./snapshot-store.js";

describe("SnapshotStore", () => {
  let tempDir: string;
  let store: SnapshotStore;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "snapshot-store-test-"));
    store = new SnapshotStore(tempDir);
  });

  afterEach(async () => {
    await store.close();
    rmSync(tempDir, { recursive: true, force: true });
  });

  function createTestSnapshot(overrides?: Partial<CachedSnapshot>): CachedSnapshot {
    const future = new Date(Date.now() + 3600 * 1000).toISOString();
    return {
      capabilityId: "cap-" + Math.random().toString(36).slice(2),
      encryptedData: "encrypted-data-base64",
      ephemeralPublicKey: "ephemeral-key-base64",
      nonce: "nonce-base64",
      tag: "tag-base64",
      signature: "signature-base64",
      issuerPublicKey: "issuer-key-base64",
      createdAt: new Date().toISOString(),
      expiresAt: future,
      ...overrides,
    };
  }

  it("stores and retrieves a snapshot", async () => {
    const snapshot = createTestSnapshot();
    await store.store(snapshot);

    const retrieved = store.get(snapshot.capabilityId);
    expect(retrieved).toEqual(snapshot);
  });

  it("overwrites existing snapshot for same capability", async () => {
    const snapshot1 = createTestSnapshot({ capabilityId: "test-cap" });
    const snapshot2 = createTestSnapshot({
      capabilityId: "test-cap",
      encryptedData: "updated-data",
    });

    await store.store(snapshot1);
    await store.store(snapshot2);

    const retrieved = store.get("test-cap");
    expect(retrieved?.encryptedData).toBe("updated-data");
  });

  it("returns null for non-existent snapshot", () => {
    const retrieved = store.get("non-existent");
    expect(retrieved).toBeNull();
  });

  it("returns null for expired snapshot", async () => {
    const expiredSnapshot = createTestSnapshot({
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    });

    // Force store without expiry check by modifying internal map
    (store as unknown as { snapshots: Map<string, CachedSnapshot> }).snapshots.set(
      expiredSnapshot.capabilityId,
      expiredSnapshot,
    );

    const retrieved = store.get(expiredSnapshot.capabilityId);
    expect(retrieved).toBeNull();
  });

  it("rejects already expired snapshots", async () => {
    const expiredSnapshot = createTestSnapshot({
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    });

    await expect(store.store(expiredSnapshot)).rejects.toThrow("expired");
  });

  it("deletes a snapshot", async () => {
    const snapshot = createTestSnapshot();
    await store.store(snapshot);

    const deleted = await store.delete(snapshot.capabilityId);
    expect(deleted).toBe(true);

    const retrieved = store.get(snapshot.capabilityId);
    expect(retrieved).toBeNull();
  });

  it("returns false when deleting non-existent snapshot", async () => {
    const deleted = await store.delete("non-existent");
    expect(deleted).toBe(false);
  });

  it("checks if snapshot exists", async () => {
    const snapshot = createTestSnapshot();
    await store.store(snapshot);

    expect(store.has(snapshot.capabilityId)).toBe(true);
    expect(store.has("non-existent")).toBe(false);
  });

  it("cleans up expired snapshots", async () => {
    const validSnapshot = createTestSnapshot();
    const expiredSnapshot = createTestSnapshot({
      capabilityId: "expired-cap",
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    });

    await store.store(validSnapshot);

    // Force add expired snapshot by modifying internal map
    (store as unknown as { snapshots: Map<string, CachedSnapshot> }).snapshots.set(
      expiredSnapshot.capabilityId,
      expiredSnapshot,
    );

    const removed = await store.cleanup();
    expect(removed).toBe(1);

    expect(store.get(validSnapshot.capabilityId)).not.toBeNull();
    expect(store.get(expiredSnapshot.capabilityId)).toBeNull();
  });

  it("returns statistics", async () => {
    const snapshot1 = createTestSnapshot();
    const snapshot2 = createTestSnapshot();

    await store.store(snapshot1);
    await store.store(snapshot2);

    const stats = store.getStats();
    expect(stats.totalSnapshots).toBe(2);
    expect(stats.totalBytes).toBeGreaterThan(0);
    expect(stats.oldestSnapshot).not.toBeNull();
    expect(stats.newestSnapshot).not.toBeNull();
  });

  it("persists snapshots across instances", async () => {
    const snapshot = createTestSnapshot();
    await store.store(snapshot);
    await store.save();

    // Create a new store instance pointing to the same directory
    const store2 = new SnapshotStore(tempDir);

    const retrieved = store2.get(snapshot.capabilityId);
    expect(retrieved).toEqual(snapshot);

    await store2.close();
  });
});
