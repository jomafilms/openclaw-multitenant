/**
 * Bloom Filter for Fast Capability Revocation Lookup
 *
 * A probabilistic data structure that provides O(1) lookup for revoked capabilities.
 * False positives are possible (and handled by checking the persistent store),
 * but false negatives are not - a revoked capability will never pass.
 */

import { createHash } from "crypto";

/**
 * Configuration for the Bloom filter.
 * Default settings optimized for ~100k capabilities with 0.1% false positive rate.
 */
export interface BloomFilterConfig {
  /** Number of bits in the filter (default: 1,437,759 for 100k items at 0.1% FPR) */
  size?: number;
  /** Number of hash functions (default: 10 for optimal performance) */
  hashCount?: number;
}

/**
 * Compute optimal Bloom filter size for given capacity and false positive rate.
 * Formula: m = -n * ln(p) / (ln(2)^2)
 */
export function computeOptimalSize(expectedItems: number, falsePositiveRate: number): number {
  const ln2Squared = Math.LN2 * Math.LN2;
  return Math.ceil((-expectedItems * Math.log(falsePositiveRate)) / ln2Squared);
}

/**
 * Compute optimal number of hash functions.
 * Formula: k = (m/n) * ln(2)
 */
export function computeOptimalHashCount(filterSize: number, expectedItems: number): number {
  return Math.max(1, Math.round((filterSize / expectedItems) * Math.LN2));
}

export class BloomFilter {
  private readonly bits: Uint8Array;
  private readonly size: number;
  private readonly hashCount: number;
  private itemCount = 0;

  constructor(config: BloomFilterConfig = {}) {
    // Default: 100k items at 0.1% false positive rate
    this.size = config.size ?? computeOptimalSize(100_000, 0.001);
    this.hashCount = config.hashCount ?? computeOptimalHashCount(this.size, 100_000);

    // Allocate bit array (packed into bytes)
    this.bits = new Uint8Array(Math.ceil(this.size / 8));
  }

  /**
   * Add an item to the filter.
   */
  add(item: string): void {
    const positions = this.getHashPositions(item);
    for (const pos of positions) {
      const byteIndex = Math.floor(pos / 8);
      const bitIndex = pos % 8;
      this.bits[byteIndex] |= 1 << bitIndex;
    }
    this.itemCount++;
  }

  /**
   * Check if an item might be in the filter.
   * Returns true if the item might be present (could be false positive).
   * Returns false if the item is definitely not present.
   */
  mightContain(item: string): boolean {
    const positions = this.getHashPositions(item);
    for (const pos of positions) {
      const byteIndex = Math.floor(pos / 8);
      const bitIndex = pos % 8;
      if ((this.bits[byteIndex] & (1 << bitIndex)) === 0) {
        return false;
      }
    }
    return true;
  }

  /**
   * Get the number of items added to the filter.
   */
  getItemCount(): number {
    return this.itemCount;
  }

  /**
   * Get the current estimated false positive rate.
   * Formula: (1 - e^(-kn/m))^k
   */
  getEstimatedFalsePositiveRate(): number {
    const exponent = (-this.hashCount * this.itemCount) / this.size;
    return Math.pow(1 - Math.exp(exponent), this.hashCount);
  }

  /**
   * Clear the filter and reset item count.
   */
  clear(): void {
    this.bits.fill(0);
    this.itemCount = 0;
  }

  /**
   * Serialize the filter to a Buffer for persistence.
   */
  serialize(): Buffer {
    const header = Buffer.alloc(16);
    header.writeUInt32LE(this.size, 0);
    header.writeUInt32LE(this.hashCount, 4);
    header.writeUInt32LE(this.itemCount, 8);
    // Reserved bytes 12-15

    return Buffer.concat([header, Buffer.from(this.bits)]);
  }

  /**
   * Deserialize a filter from a Buffer.
   */
  static deserialize(data: Buffer): BloomFilter {
    if (data.length < 16) {
      throw new Error("Invalid Bloom filter data: too short");
    }

    const size = data.readUInt32LE(0);
    const hashCount = data.readUInt32LE(4);
    const itemCount = data.readUInt32LE(8);

    const filter = new BloomFilter({ size, hashCount });
    filter.itemCount = itemCount;

    const bitsData = data.subarray(16);
    if (bitsData.length !== filter.bits.length) {
      throw new Error(
        `Invalid Bloom filter data: expected ${filter.bits.length} bytes, got ${bitsData.length}`,
      );
    }

    bitsData.copy(filter.bits);
    return filter;
  }

  /**
   * Generate hash positions for an item using double hashing.
   * Uses SHA-256 split into two 128-bit values for the two base hashes.
   */
  private getHashPositions(item: string): number[] {
    const hash = createHash("sha256").update(item).digest();

    // Split SHA-256 into two 64-bit numbers for double hashing
    const h1 = hash.readBigUInt64LE(0);
    const h2 = hash.readBigUInt64LE(8);

    const positions: number[] = [];
    const sizeBigInt = BigInt(this.size);

    for (let i = 0; i < this.hashCount; i++) {
      // Double hashing: h(i) = (h1 + i * h2) mod size
      const combined = (h1 + BigInt(i) * h2) % sizeBigInt;
      positions.push(Number(combined));
    }

    return positions;
  }
}

/**
 * Create a Bloom filter optimized for the expected number of revocations.
 */
export function createRevocationBloomFilter(
  expectedRevocations: number = 100_000,
  falsePositiveRate: number = 0.001,
): BloomFilter {
  const size = computeOptimalSize(expectedRevocations, falsePositiveRate);
  const hashCount = computeOptimalHashCount(size, expectedRevocations);
  return new BloomFilter({ size, hashCount });
}
