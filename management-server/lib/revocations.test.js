import dotenv from "dotenv";
import pg from "pg";
/**
 * Tests for capability revocation persistence
 *
 * These tests verify that revocations are properly persisted to the database
 * and survive server restarts.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";

dotenv.config();

const { Pool } = pg;

// Use a test database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || "postgresql://localhost:5432/ocmt_test",
});

// Mock the db module to use our test pool
const mockQuery = async (text, params) => {
  return pool.query(text, params);
};

describe("Capability Revocations Persistence", () => {
  beforeAll(async () => {
    // Create the revocations table if it doesn't exist
    await pool.query(`
      CREATE TABLE IF NOT EXISTS capability_revocations (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        capability_id VARCHAR(255) NOT NULL UNIQUE,
        revoked_at TIMESTAMP NOT NULL DEFAULT NOW(),
        issuer_public_key VARCHAR(255) NOT NULL,
        reason TEXT,
        original_expiry TIMESTAMP,
        signature TEXT,
        metadata JSONB DEFAULT '{}'
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS org_token_revocations (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        org_id UUID NOT NULL,
        token_id VARCHAR(255) NOT NULL,
        user_id UUID,
        revoked_at TIMESTAMP NOT NULL DEFAULT NOW(),
        revoked_by UUID,
        reason TEXT,
        UNIQUE(org_id, token_id)
      )
    `);
  });

  beforeEach(async () => {
    // Clean up test data
    await pool.query("DELETE FROM capability_revocations WHERE capability_id LIKE $1", ["test-%"]);
    await pool.query("DELETE FROM org_token_revocations WHERE token_id LIKE $1", ["test-%"]);
  });

  afterAll(async () => {
    // Clean up and close connection
    await pool.query("DELETE FROM capability_revocations WHERE capability_id LIKE $1", ["test-%"]);
    await pool.query("DELETE FROM org_token_revocations WHERE token_id LIKE $1", ["test-%"]);
    await pool.end();
  });

  describe("capability_revocations table", () => {
    it("should insert a new revocation", async () => {
      const result = await pool.query(
        `
        INSERT INTO capability_revocations (capability_id, issuer_public_key, reason)
        VALUES ($1, $2, $3)
        RETURNING *
      `,
        ["test-cap-001", "test-public-key-abc", "Test revocation"],
      );

      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].capability_id).toBe("test-cap-001");
      expect(result.rows[0].issuer_public_key).toBe("test-public-key-abc");
      expect(result.rows[0].reason).toBe("Test revocation");
      expect(result.rows[0].revoked_at).toBeDefined();
    });

    it("should prevent duplicate capability revocations", async () => {
      await pool.query(
        `
        INSERT INTO capability_revocations (capability_id, issuer_public_key, reason)
        VALUES ($1, $2, $3)
      `,
        ["test-cap-002", "test-public-key", "First revocation"],
      );

      // Attempting to insert again should fail (unique constraint)
      await expect(
        pool.query(
          `
        INSERT INTO capability_revocations (capability_id, issuer_public_key, reason)
        VALUES ($1, $2, $3)
      `,
          ["test-cap-002", "test-public-key", "Duplicate revocation"],
        ),
      ).rejects.toThrow();
    });

    it("should check if capability is revoked", async () => {
      await pool.query(
        `
        INSERT INTO capability_revocations (capability_id, issuer_public_key)
        VALUES ($1, $2)
      `,
        ["test-cap-003", "test-public-key"],
      );

      // Check revoked capability
      const revokedResult = await pool.query(
        `
        SELECT 1 FROM capability_revocations WHERE capability_id = $1
      `,
        ["test-cap-003"],
      );
      expect(revokedResult.rows).toHaveLength(1);

      // Check non-revoked capability
      const notRevokedResult = await pool.query(
        `
        SELECT 1 FROM capability_revocations WHERE capability_id = $1
      `,
        ["test-cap-nonexistent"],
      );
      expect(notRevokedResult.rows).toHaveLength(0);
    });

    it("should batch check multiple capabilities", async () => {
      // Insert some revocations
      await pool.query(
        `
        INSERT INTO capability_revocations (capability_id, issuer_public_key, reason)
        VALUES ($1, $2, $3), ($4, $5, $6)
      `,
        ["test-cap-batch-1", "key1", "reason1", "test-cap-batch-2", "key2", "reason2"],
      );

      // Batch check
      const result = await pool.query(
        `
        SELECT capability_id, revoked_at, reason
        FROM capability_revocations
        WHERE capability_id = ANY($1)
      `,
        [["test-cap-batch-1", "test-cap-batch-2", "test-cap-batch-3"]],
      );

      expect(result.rows).toHaveLength(2);
      const capIds = result.rows.map((r) => r.capability_id);
      expect(capIds).toContain("test-cap-batch-1");
      expect(capIds).toContain("test-cap-batch-2");
    });

    it("should cleanup expired revocations", async () => {
      // Insert a revocation with past expiry
      await pool.query(
        `
        INSERT INTO capability_revocations (capability_id, issuer_public_key, original_expiry)
        VALUES ($1, $2, $3)
      `,
        ["test-cap-expired", "test-key", new Date("2020-01-01")],
      );

      // Insert a revocation with future expiry
      await pool.query(
        `
        INSERT INTO capability_revocations (capability_id, issuer_public_key, original_expiry)
        VALUES ($1, $2, $3)
      `,
        ["test-cap-valid", "test-key", new Date("2030-01-01")],
      );

      // Cleanup expired
      const deleteResult = await pool.query(`
        DELETE FROM capability_revocations
        WHERE original_expiry IS NOT NULL AND original_expiry < NOW()
        AND capability_id LIKE 'test-%'
        RETURNING capability_id
      `);

      expect(deleteResult.rows).toHaveLength(1);
      expect(deleteResult.rows[0].capability_id).toBe("test-cap-expired");

      // Verify valid one still exists
      const checkResult = await pool.query(
        `
        SELECT capability_id FROM capability_revocations WHERE capability_id = $1
      `,
        ["test-cap-valid"],
      );
      expect(checkResult.rows).toHaveLength(1);
    });

    it("should get all capability IDs for Bloom filter loading", async () => {
      // Insert some revocations
      await pool.query(
        `
        INSERT INTO capability_revocations (capability_id, issuer_public_key)
        VALUES ($1, $2), ($3, $4), ($5, $6)
      `,
        ["test-bloom-1", "key1", "test-bloom-2", "key2", "test-bloom-3", "key3"],
      );

      const result = await pool.query(`
        SELECT capability_id FROM capability_revocations WHERE capability_id LIKE 'test-bloom-%'
      `);

      expect(result.rows).toHaveLength(3);
      const ids = result.rows.map((r) => r.capability_id);
      expect(ids).toContain("test-bloom-1");
      expect(ids).toContain("test-bloom-2");
      expect(ids).toContain("test-bloom-3");
    });
  });

  describe("org_token_revocations table", () => {
    const testOrgId = "00000000-0000-0000-0000-000000000001";
    const testUserId = "00000000-0000-0000-0000-000000000002";

    it("should insert an org token revocation", async () => {
      const result = await pool.query(
        `
        INSERT INTO org_token_revocations (org_id, token_id, user_id, reason)
        VALUES ($1, $2, $3, $4)
        RETURNING *
      `,
        [testOrgId, "test-token-001", testUserId, "User requested revocation"],
      );

      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].org_id).toBe(testOrgId);
      expect(result.rows[0].token_id).toBe("test-token-001");
      expect(result.rows[0].reason).toBe("User requested revocation");
    });

    it("should prevent duplicate token revocations in same org", async () => {
      await pool.query(
        `
        INSERT INTO org_token_revocations (org_id, token_id)
        VALUES ($1, $2)
      `,
        [testOrgId, "test-token-002"],
      );

      // Attempting to insert again should fail
      await expect(
        pool.query(
          `
        INSERT INTO org_token_revocations (org_id, token_id)
        VALUES ($1, $2)
      `,
          [testOrgId, "test-token-002"],
        ),
      ).rejects.toThrow();
    });

    it("should allow same token ID in different orgs", async () => {
      const otherOrgId = "00000000-0000-0000-0000-000000000099";

      await pool.query(
        `
        INSERT INTO org_token_revocations (org_id, token_id)
        VALUES ($1, $2)
      `,
        [testOrgId, "test-token-003"],
      );

      // Same token ID in different org should work
      const result = await pool.query(
        `
        INSERT INTO org_token_revocations (org_id, token_id)
        VALUES ($1, $2)
        RETURNING *
      `,
        [otherOrgId, "test-token-003"],
      );

      expect(result.rows).toHaveLength(1);
    });

    it("should check if org token is revoked", async () => {
      await pool.query(
        `
        INSERT INTO org_token_revocations (org_id, token_id)
        VALUES ($1, $2)
      `,
        [testOrgId, "test-token-004"],
      );

      const revokedResult = await pool.query(
        `
        SELECT 1 FROM org_token_revocations WHERE org_id = $1 AND token_id = $2
      `,
        [testOrgId, "test-token-004"],
      );
      expect(revokedResult.rows).toHaveLength(1);

      const notRevokedResult = await pool.query(
        `
        SELECT 1 FROM org_token_revocations WHERE org_id = $1 AND token_id = $2
      `,
        [testOrgId, "test-token-nonexistent"],
      );
      expect(notRevokedResult.rows).toHaveLength(0);
    });

    it("should get all token IDs for an org", async () => {
      await pool.query(
        `
        INSERT INTO org_token_revocations (org_id, token_id)
        VALUES ($1, $2), ($3, $4), ($5, $6)
      `,
        [
          testOrgId,
          "test-org-token-1",
          testOrgId,
          "test-org-token-2",
          testOrgId,
          "test-org-token-3",
        ],
      );

      const result = await pool.query(
        `
        SELECT token_id FROM org_token_revocations WHERE org_id = $1 AND token_id LIKE 'test-org-token-%'
      `,
        [testOrgId],
      );

      expect(result.rows).toHaveLength(3);
      const tokenIds = result.rows.map((r) => r.token_id);
      expect(tokenIds).toContain("test-org-token-1");
      expect(tokenIds).toContain("test-org-token-2");
      expect(tokenIds).toContain("test-org-token-3");
    });
  });

  describe("persistence across restarts", () => {
    it("should retain revocations after connection pool restart", async () => {
      // Insert a revocation
      await pool.query(
        `
        INSERT INTO capability_revocations (capability_id, issuer_public_key, reason)
        VALUES ($1, $2, $3)
      `,
        ["test-persist-001", "test-key", "Testing persistence"],
      );

      // Create a new connection (simulating server restart)
      const newPool = new Pool({
        connectionString: process.env.DATABASE_URL || "postgresql://localhost:5432/ocmt_test",
      });

      try {
        // Verify the revocation persisted
        const result = await newPool.query(
          `
          SELECT * FROM capability_revocations WHERE capability_id = $1
        `,
          ["test-persist-001"],
        );

        expect(result.rows).toHaveLength(1);
        expect(result.rows[0].reason).toBe("Testing persistence");
      } finally {
        await newPool.end();
      }
    });
  });
});

describe("Bloom Filter for Revocations", () => {
  // Simple Bloom filter implementation for testing
  const BLOOM_SIZE = 1000;
  const BLOOM_HASH_COUNT = 3;

  function simpleHash(str, seed) {
    let hash = seed;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash + str.charCodeAt(i)) | 0;
    }
    return Math.abs(hash);
  }

  function getPositions(item) {
    const positions = [];
    for (let i = 0; i < BLOOM_HASH_COUNT; i++) {
      positions.push(simpleHash(item, i * 31337) % BLOOM_SIZE);
    }
    return positions;
  }

  it("should add items and check membership", () => {
    const bloom = new Uint8Array(Math.ceil(BLOOM_SIZE / 8));

    // Add an item
    const item = "test-capability-id";
    const positions = getPositions(item);
    for (const pos of positions) {
      const byteIndex = Math.floor(pos / 8);
      const bitIndex = pos % 8;
      bloom[byteIndex] |= 1 << bitIndex;
    }

    // Check membership
    let found = true;
    for (const pos of positions) {
      const byteIndex = Math.floor(pos / 8);
      const bitIndex = pos % 8;
      if ((bloom[byteIndex] & (1 << bitIndex)) === 0) {
        found = false;
        break;
      }
    }
    expect(found).toBe(true);
  });

  it("should return false for items not in the filter", () => {
    const bloom = new Uint8Array(Math.ceil(BLOOM_SIZE / 8));

    // Add one item
    const addedItem = "added-item";
    for (const pos of getPositions(addedItem)) {
      const byteIndex = Math.floor(pos / 8);
      const bitIndex = pos % 8;
      bloom[byteIndex] |= 1 << bitIndex;
    }

    // Check a different item - should likely return false
    // (with small filter, there might be false positives)
    const otherItem = "completely-different-item-not-added";
    const positions = getPositions(otherItem);
    let maybeContains = true;
    for (const pos of positions) {
      const byteIndex = Math.floor(pos / 8);
      const bitIndex = pos % 8;
      if ((bloom[byteIndex] & (1 << bitIndex)) === 0) {
        maybeContains = false;
        break;
      }
    }

    // This should be false (no false positive expected with such different strings)
    expect(maybeContains).toBe(false);
  });

  it("should work with many items", () => {
    const bloom = new Uint8Array(Math.ceil(BLOOM_SIZE / 8));
    const addedItems = [];

    // Add many items
    for (let i = 0; i < 100; i++) {
      const item = `capability-${i}`;
      addedItems.push(item);
      for (const pos of getPositions(item)) {
        const byteIndex = Math.floor(pos / 8);
        const bitIndex = pos % 8;
        bloom[byteIndex] |= 1 << bitIndex;
      }
    }

    // All added items should be "found"
    for (const item of addedItems) {
      let found = true;
      for (const pos of getPositions(item)) {
        const byteIndex = Math.floor(pos / 8);
        const bitIndex = pos % 8;
        if ((bloom[byteIndex] & (1 << bitIndex)) === 0) {
          found = false;
          break;
        }
      }
      expect(found).toBe(true);
    }
  });
});
