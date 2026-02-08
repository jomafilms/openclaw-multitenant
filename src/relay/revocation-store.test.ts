import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { RevocationStore, resetRevocationStore } from "./revocation-store.js";

describe("RevocationStore", () => {
  let tempDir: string;
  let store: RevocationStore;

  beforeEach(() => {
    resetRevocationStore();
    tempDir = mkdtempSync(join(tmpdir(), "revocation-store-test-"));
    store = new RevocationStore(tempDir);
  });

  afterEach(async () => {
    await store.close();
    rmSync(tempDir, { recursive: true, force: true });
  });

  describe("isRevoked", () => {
    it("returns false for unknown capability", () => {
      const result = store.isRevoked("unknown-cap");
      expect(result.revoked).toBe(false);
      expect(result.source).toBe("bloom-filter");
    });

    it("returns true for revoked capability", async () => {
      await store.revoke("cap-123", "public-key-abc");

      const result = store.isRevoked("cap-123");
      expect(result.revoked).toBe(true);
      expect(result.record).toBeDefined();
      expect(result.record!.capabilityId).toBe("cap-123");
      expect(result.record!.revokedBy).toBe("public-key-abc");
    });
  });

  describe("revoke", () => {
    it("creates a revocation record", async () => {
      const record = await store.revoke("cap-123", "key-xyz", {
        reason: "Compromised",
        originalExpiry: "2025-12-31T23:59:59Z",
      });

      expect(record.capabilityId).toBe("cap-123");
      expect(record.revokedBy).toBe("key-xyz");
      expect(record.reason).toBe("Compromised");
      expect(record.originalExpiry).toBe("2025-12-31T23:59:59Z");
      expect(record.revokedAt).toBeDefined();
    });

    it("returns existing record if already revoked", async () => {
      const record1 = await store.revoke("cap-123", "key-xyz");
      const record2 = await store.revoke("cap-123", "key-xyz");

      expect(record1.revokedAt).toBe(record2.revokedAt);
    });
  });

  describe("getRevocation", () => {
    it("returns null for unknown capability", () => {
      expect(store.getRevocation("unknown")).toBeNull();
    });

    it("returns record for revoked capability", async () => {
      await store.revoke("cap-123", "key-xyz");

      const record = store.getRevocation("cap-123");
      expect(record).not.toBeNull();
      expect(record!.capabilityId).toBe("cap-123");
    });
  });

  describe("listRevocations", () => {
    it("returns empty list initially", () => {
      const { records, total } = store.listRevocations();
      expect(records).toHaveLength(0);
      expect(total).toBe(0);
    });

    it("lists all revocations", async () => {
      await store.revoke("cap-1", "key-a");
      await store.revoke("cap-2", "key-b");
      await store.revoke("cap-3", "key-a");

      const { records, total } = store.listRevocations();
      expect(total).toBe(3);
      expect(records).toHaveLength(3);
    });

    it("filters by revoker", async () => {
      await store.revoke("cap-1", "key-a");
      await store.revoke("cap-2", "key-b");
      await store.revoke("cap-3", "key-a");

      const { records, total } = store.listRevocations({ revokedBy: "key-a" });
      expect(total).toBe(2);
      expect(records).toHaveLength(2);
      expect(records.every((r) => r.revokedBy === "key-a")).toBe(true);
    });

    it("supports pagination", async () => {
      for (let i = 0; i < 10; i++) {
        await store.revoke(`cap-${i}`, "key-a");
      }

      const page1 = store.listRevocations({ limit: 3, offset: 0 });
      const page2 = store.listRevocations({ limit: 3, offset: 3 });

      expect(page1.records).toHaveLength(3);
      expect(page2.records).toHaveLength(3);
      expect(page1.total).toBe(10);
      expect(page2.total).toBe(10);

      // Ensure different capabilities
      const ids1 = new Set(page1.records.map((r) => r.capabilityId));
      const ids2 = new Set(page2.records.map((r) => r.capabilityId));
      expect(ids1).not.toEqual(ids2);
    });
  });

  describe("cleanup", () => {
    it("removes expired revocations", async () => {
      // Add a revocation with past expiry
      await store.revoke("cap-old", "key-a", {
        originalExpiry: "2020-01-01T00:00:00Z",
      });

      // Add a revocation with future expiry
      await store.revoke("cap-new", "key-a", {
        originalExpiry: "2030-01-01T00:00:00Z",
      });

      // Add a revocation without expiry (should not be cleaned)
      await store.revoke("cap-forever", "key-a");

      const removed = await store.cleanup();

      expect(removed).toBe(1);
      expect(store.isRevoked("cap-old").revoked).toBe(false);
      expect(store.isRevoked("cap-new").revoked).toBe(true);
      expect(store.isRevoked("cap-forever").revoked).toBe(true);
    });
  });

  describe("getStats", () => {
    it("returns statistics", async () => {
      await store.revoke("cap-1", "key-a");
      await store.revoke("cap-2", "key-a");

      // Check a revoked one
      store.isRevoked("cap-1");
      // Check an unknown one
      store.isRevoked("cap-unknown");

      const stats = store.getStats();

      expect(stats.totalRevocations).toBe(2);
      expect(stats.bloomFilterSize).toBe(2);
      expect(stats.bloomChecks).toBe(2);
      expect(stats.dbChecks).toBeGreaterThanOrEqual(1); // At least one check went to DB
    });
  });

  describe("persistence", () => {
    it("saves and loads data", async () => {
      await store.revoke("cap-123", "key-xyz", {
        reason: "Test",
      });

      await store.save();

      // Create a new store instance pointing to same directory
      const store2 = new RevocationStore(tempDir);

      const result = store2.isRevoked("cap-123");
      expect(result.revoked).toBe(true);
      expect(result.record!.reason).toBe("Test");

      await store2.close();
    });
  });

  describe("Bloom filter efficiency", () => {
    it("uses Bloom filter for fast rejection", async () => {
      // Add some revocations
      for (let i = 0; i < 100; i++) {
        await store.revoke(`cap-${i}`, "key-a");
      }

      // Check many unknown capabilities
      for (let i = 1000; i < 2000; i++) {
        store.isRevoked(`cap-${i}`);
      }

      const stats = store.getStats();

      // Most checks should be handled by Bloom filter (not hitting DB)
      // The ratio of DB checks to Bloom checks should be low
      const bloomEfficiency = 1 - stats.dbChecks / stats.bloomChecks;
      expect(bloomEfficiency).toBeGreaterThan(0.9); // 90%+ handled by Bloom filter
    });
  });
});
