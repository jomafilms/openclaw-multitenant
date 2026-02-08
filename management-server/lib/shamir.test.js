import { describe, it, expect } from 'vitest';
import { split, combine, encodeShare, decodeShare, createSocialRecoveryShards, reconstructFromShards } from './shamir.js';
import crypto from 'crypto';

describe('Shamir Secret Sharing', () => {
  describe('split and combine', () => {
    it('should split and reconstruct a secret with exact threshold', () => {
      const secret = crypto.randomBytes(32);
      const shares = split(secret, 5, 3);

      expect(shares).toHaveLength(5);

      // Use exactly 3 shares
      const reconstructed = combine(shares.slice(0, 3));
      expect(reconstructed.equals(secret)).toBe(true);
    });

    it('should work with different share combinations', () => {
      const secret = crypto.randomBytes(32);
      const shares = split(secret, 5, 3);

      // First 3 shares
      expect(combine([shares[0], shares[1], shares[2]]).equals(secret)).toBe(true);

      // Last 3 shares
      expect(combine([shares[2], shares[3], shares[4]]).equals(secret)).toBe(true);

      // Non-contiguous shares
      expect(combine([shares[0], shares[2], shares[4]]).equals(secret)).toBe(true);
    });

    it('should work with more than threshold shares', () => {
      const secret = crypto.randomBytes(32);
      const shares = split(secret, 5, 3);

      // Use all 5 shares
      const reconstructed = combine(shares);
      expect(reconstructed.equals(secret)).toBe(true);
    });

    it('should fail with fewer than threshold shares', () => {
      const secret = crypto.randomBytes(32);
      const shares = split(secret, 5, 3);

      // Use only 2 shares (below threshold of 3)
      const wrongResult = combine(shares.slice(0, 2));
      // Result should be different from secret (mathematically impossible to recover)
      expect(wrongResult.equals(secret)).toBe(false);
    });

    it('should handle 2-of-3 split', () => {
      const secret = Buffer.from('test secret data');
      const shares = split(secret, 3, 2);

      expect(shares).toHaveLength(3);

      // Any 2 shares should work
      expect(combine([shares[0], shares[1]]).equals(secret)).toBe(true);
      expect(combine([shares[0], shares[2]]).equals(secret)).toBe(true);
      expect(combine([shares[1], shares[2]]).equals(secret)).toBe(true);
    });

    it('should handle large secrets', () => {
      const secret = crypto.randomBytes(256);
      const shares = split(secret, 5, 3);

      const reconstructed = combine(shares.slice(0, 3));
      expect(reconstructed.equals(secret)).toBe(true);
    });

    it('should reject invalid parameters', () => {
      const secret = crypto.randomBytes(32);

      expect(() => split(secret, 5, 1)).toThrow('Threshold must be at least 2');
      expect(() => split(secret, 2, 3)).toThrow('Total shares must be >= threshold');
      expect(() => split(secret, 256, 3)).toThrow('Maximum 255 shares supported');
    });

    it('should detect duplicate share indices', () => {
      const secret = crypto.randomBytes(32);
      const shares = split(secret, 5, 3);

      // Duplicate the first share
      expect(() => combine([shares[0], shares[0], shares[1]])).toThrow('Duplicate share indices');
    });

    it('should detect share length mismatch', () => {
      const secret1 = crypto.randomBytes(32);
      const secret2 = crypto.randomBytes(16);
      const shares1 = split(secret1, 3, 2);
      const shares2 = split(secret2, 3, 2);

      expect(() => combine([shares1[0], shares2[1]])).toThrow('Share length mismatch');
    });
  });

  describe('encodeShare and decodeShare', () => {
    it('should encode and decode shares correctly', () => {
      const secret = crypto.randomBytes(32);
      const shares = split(secret, 3, 2);

      const encoded = encodeShare(shares[0]);
      expect(typeof encoded).toBe('string');
      expect(encoded.length).toBeGreaterThan(0);

      const decoded = decodeShare(encoded);
      expect(decoded.x).toBe(shares[0].x);
      expect(decoded.data.equals(shares[0].data)).toBe(true);
    });

    it('should reject invalid encoded shares', () => {
      expect(() => decodeShare('abc')).toThrow('Invalid share format');
    });
  });

  describe('createSocialRecoveryShards', () => {
    it('should create shards for contacts', () => {
      const secret = crypto.randomBytes(32);
      const contacts = [
        { email: 'alice@example.com' },
        { email: 'bob@example.com' },
        { email: 'carol@example.com' },
        { email: 'dave@example.com' },
        { email: 'eve@example.com' },
      ];

      const shards = createSocialRecoveryShards(secret, 3, contacts);

      expect(shards).toHaveLength(5);
      expect(shards[0].email).toBe('alice@example.com');
      expect(shards[0].shard).toBeDefined();
      expect(shards[0].shareIndex).toBeGreaterThan(0);
    });

    it('should allow reconstruction from shards', () => {
      const secret = crypto.randomBytes(32);
      const contacts = [
        { email: 'alice@example.com' },
        { email: 'bob@example.com' },
        { email: 'carol@example.com' },
      ];

      const shards = createSocialRecoveryShards(secret, 2, contacts);
      const reconstructed = reconstructFromShards([
        { shard: shards[0].shard },
        { shard: shards[2].shard }
      ]);

      expect(reconstructed.equals(secret)).toBe(true);
    });
  });

  describe('deterministic behavior', () => {
    it('should produce different shares each time (random coefficients)', () => {
      const secret = crypto.randomBytes(32);

      const shares1 = split(secret, 3, 2);
      const shares2 = split(secret, 3, 2);

      // Same x-values
      expect(shares1[0].x).toBe(shares2[0].x);

      // But different data (random polynomial coefficients)
      expect(shares1[0].data.equals(shares2[0].data)).toBe(false);

      // Both should still reconstruct to the same secret
      expect(combine(shares1.slice(0, 2)).equals(secret)).toBe(true);
      expect(combine(shares2.slice(0, 2)).equals(secret)).toBe(true);
    });
  });
});
