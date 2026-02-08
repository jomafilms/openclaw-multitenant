import { describe, it, expect, beforeEach } from "vitest";
import {
  BloomFilter,
  computeOptimalSize,
  computeOptimalHashCount,
  createRevocationBloomFilter,
} from "./bloom-filter.js";

describe("BloomFilter", () => {
  describe("computeOptimalSize", () => {
    it("computes correct size for 100k items at 0.1% FPR", () => {
      const size = computeOptimalSize(100_000, 0.001);
      // Expected: ~1.44M bits for 100k items at 0.1% FPR
      expect(size).toBeGreaterThan(1_400_000);
      expect(size).toBeLessThan(1_500_000);
    });

    it("computes larger size for lower FPR", () => {
      const size1 = computeOptimalSize(100_000, 0.01);
      const size2 = computeOptimalSize(100_000, 0.001);
      expect(size2).toBeGreaterThan(size1);
    });
  });

  describe("computeOptimalHashCount", () => {
    it("computes reasonable hash count", () => {
      const size = computeOptimalSize(100_000, 0.001);
      const hashCount = computeOptimalHashCount(size, 100_000);
      // Optimal k for 0.1% FPR is approximately 10
      expect(hashCount).toBeGreaterThanOrEqual(9);
      expect(hashCount).toBeLessThanOrEqual(11);
    });
  });

  describe("basic operations", () => {
    let filter: BloomFilter;

    beforeEach(() => {
      filter = new BloomFilter({ size: 10_000, hashCount: 7 });
    });

    it("returns false for items not added", () => {
      expect(filter.mightContain("not-added")).toBe(false);
    });

    it("returns true for added items", () => {
      filter.add("capability-123");
      expect(filter.mightContain("capability-123")).toBe(true);
    });

    it("tracks item count", () => {
      expect(filter.getItemCount()).toBe(0);
      filter.add("cap-1");
      filter.add("cap-2");
      expect(filter.getItemCount()).toBe(2);
    });

    it("handles many additions", () => {
      for (let i = 0; i < 1000; i++) {
        filter.add(`capability-${i}`);
      }

      // All added items should be found
      for (let i = 0; i < 1000; i++) {
        expect(filter.mightContain(`capability-${i}`)).toBe(true);
      }
    });

    it("reports estimated false positive rate", () => {
      // Empty filter should have 0 FPR
      expect(filter.getEstimatedFalsePositiveRate()).toBe(0);

      // Add some items
      for (let i = 0; i < 100; i++) {
        filter.add(`item-${i}`);
      }

      // Should have small but non-zero FPR
      const fpr = filter.getEstimatedFalsePositiveRate();
      expect(fpr).toBeGreaterThan(0);
      expect(fpr).toBeLessThan(0.1);
    });

    it("clears the filter", () => {
      filter.add("item-1");
      filter.add("item-2");
      expect(filter.mightContain("item-1")).toBe(true);

      filter.clear();

      expect(filter.mightContain("item-1")).toBe(false);
      expect(filter.getItemCount()).toBe(0);
    });
  });

  describe("serialization", () => {
    it("serializes and deserializes correctly", () => {
      const filter = new BloomFilter({ size: 10_000, hashCount: 7 });

      filter.add("cap-1");
      filter.add("cap-2");
      filter.add("cap-3");

      const serialized = filter.serialize();
      const restored = BloomFilter.deserialize(serialized);

      // All items should still be found
      expect(restored.mightContain("cap-1")).toBe(true);
      expect(restored.mightContain("cap-2")).toBe(true);
      expect(restored.mightContain("cap-3")).toBe(true);
      expect(restored.mightContain("cap-4")).toBe(false);

      expect(restored.getItemCount()).toBe(3);
    });

    it("throws on invalid serialized data", () => {
      const tooShort = Buffer.alloc(8);
      expect(() => BloomFilter.deserialize(tooShort)).toThrow("too short");
    });

    it("throws on size mismatch", () => {
      const filter = new BloomFilter({ size: 10_000, hashCount: 7 });
      const serialized = filter.serialize();

      // Corrupt the size field
      serialized.writeUInt32LE(5_000, 0);

      expect(() => BloomFilter.deserialize(serialized)).toThrow();
    });
  });

  describe("false positive rate", () => {
    it("maintains acceptable FPR for expected load", () => {
      // Create filter optimized for 10k items at 1% FPR
      const expectedItems = 10_000;
      const targetFPR = 0.01;

      const size = computeOptimalSize(expectedItems, targetFPR);
      const hashCount = computeOptimalHashCount(size, expectedItems);
      const filter = new BloomFilter({ size, hashCount });

      // Add expected number of items
      for (let i = 0; i < expectedItems; i++) {
        filter.add(`capability-${i}`);
      }

      // Check false positives on items that were NOT added
      let falsePositives = 0;
      const testCount = 10_000;

      for (let i = expectedItems; i < expectedItems + testCount; i++) {
        if (filter.mightContain(`capability-${i}`)) {
          falsePositives++;
        }
      }

      const actualFPR = falsePositives / testCount;

      // Should be within 2x of target (with some variance)
      expect(actualFPR).toBeLessThan(targetFPR * 2);
    });
  });

  describe("createRevocationBloomFilter", () => {
    it("creates a filter with default settings", () => {
      const filter = createRevocationBloomFilter();

      // Should be usable
      filter.add("test-cap");
      expect(filter.mightContain("test-cap")).toBe(true);
    });

    it("creates a filter with custom settings", () => {
      const filter = createRevocationBloomFilter(50_000, 0.0001);

      // Should be usable
      filter.add("test-cap");
      expect(filter.mightContain("test-cap")).toBe(true);
    });
  });
});
