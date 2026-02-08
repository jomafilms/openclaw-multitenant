// Capability and token revocations (Mesh-wide revocation persistence)
import { query } from "./core.js";

// Capability revocations (for relay revocation service)
export const capabilityRevocations = {
  async create({ capabilityId, issuerPublicKey, reason, originalExpiry, signature, metadata }) {
    const res = await query(
      `INSERT INTO capability_revocations (capability_id, issuer_public_key, reason, original_expiry, signature, metadata)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (capability_id) DO NOTHING
       RETURNING *`,
      [
        capabilityId,
        issuerPublicKey,
        reason,
        originalExpiry ? new Date(originalExpiry) : null,
        signature,
        metadata ? JSON.stringify(metadata) : "{}",
      ],
    );
    return res.rows[0];
  },

  async findByCapabilityId(capabilityId) {
    const res = await query("SELECT * FROM capability_revocations WHERE capability_id = $1", [
      capabilityId,
    ]);
    return res.rows[0];
  },

  async isRevoked(capabilityId) {
    const res = await query("SELECT 1 FROM capability_revocations WHERE capability_id = $1", [
      capabilityId,
    ]);
    return res.rows.length > 0;
  },

  async batchCheckRevoked(capabilityIds) {
    if (!capabilityIds || capabilityIds.length === 0) return {};
    const res = await query(
      "SELECT capability_id, revoked_at, reason FROM capability_revocations WHERE capability_id = ANY($1)",
      [capabilityIds],
    );
    const results = {};
    for (const id of capabilityIds) {
      const row = res.rows.find((r) => r.capability_id === id);
      if (row) {
        results[id] = { revoked: true, revokedAt: row.revoked_at, reason: row.reason };
      } else {
        results[id] = { revoked: false };
      }
    }
    return results;
  },

  async listByIssuer(issuerPublicKey, limit = 100) {
    const res = await query(
      `SELECT * FROM capability_revocations
       WHERE issuer_public_key = $1
       ORDER BY revoked_at DESC
       LIMIT $2`,
      [issuerPublicKey, limit],
    );
    return res.rows;
  },

  async listAll(limit = 1000, offset = 0) {
    const res = await query(
      `SELECT * FROM capability_revocations
       ORDER BY revoked_at DESC
       LIMIT $1 OFFSET $2`,
      [limit, offset],
    );
    return res.rows;
  },

  async count() {
    const res = await query("SELECT COUNT(*) as count FROM capability_revocations");
    return parseInt(res.rows[0].count, 10);
  },

  async cleanupExpired(beforeDate = new Date()) {
    const res = await query(
      `DELETE FROM capability_revocations
       WHERE original_expiry IS NOT NULL AND original_expiry < $1
       RETURNING id`,
      [beforeDate],
    );
    return res.rowCount;
  },

  // For loading into Bloom filter at startup
  async getAllCapabilityIds() {
    const res = await query("SELECT capability_id FROM capability_revocations");
    return res.rows.map((r) => r.capability_id);
  },
};

// Group-scoped token revocations (renamed from orgTokenRevocations)
export const groupTokenRevocations = {
  async create({ groupId, tokenId, userId, revokedBy, reason }) {
    const res = await query(
      `INSERT INTO group_token_revocations (group_id, token_id, user_id, revoked_by, reason)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (group_id, token_id) DO NOTHING
       RETURNING *`,
      [groupId, tokenId, userId, revokedBy, reason],
    );
    return res.rows[0];
  },

  async isRevoked(groupId, tokenId) {
    const res = await query(
      "SELECT 1 FROM group_token_revocations WHERE group_id = $1 AND token_id = $2",
      [groupId, tokenId],
    );
    return res.rows.length > 0;
  },

  async findByToken(groupId, tokenId) {
    const res = await query(
      "SELECT * FROM group_token_revocations WHERE group_id = $1 AND token_id = $2",
      [groupId, tokenId],
    );
    return res.rows[0];
  },

  async listByGroup(groupId, limit = 100) {
    const res = await query(
      `SELECT gtr.*, u.name as user_name, rb.name as revoked_by_name
       FROM group_token_revocations gtr
       LEFT JOIN users u ON gtr.user_id = u.id
       LEFT JOIN users rb ON gtr.revoked_by = rb.id
       WHERE gtr.group_id = $1
       ORDER BY gtr.revoked_at DESC
       LIMIT $2`,
      [groupId, limit],
    );
    return res.rows;
  },

  async listByUser(groupId, userId) {
    const res = await query(
      "SELECT token_id FROM group_token_revocations WHERE group_id = $1 AND user_id = $2",
      [groupId, userId],
    );
    return res.rows.map((r) => r.token_id);
  },

  async revokeAllForUser(groupId, userId, revokedBy, reason) {
    // Get all active tokens for the user
    const tokens = await query(
      `SELECT token_hash FROM group_vault_tokens
       WHERE group_id = $1 AND user_id = $2 AND revoked_at IS NULL`,
      [groupId, userId],
    );

    // Create revocation records for each
    for (const token of tokens.rows) {
      await query(
        `INSERT INTO group_token_revocations (group_id, token_id, user_id, revoked_by, reason)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (group_id, token_id) DO NOTHING`,
        [groupId, token.token_hash, userId, revokedBy, reason],
      );
    }

    return tokens.rows.length;
  },

  // For loading into memory at group vault container startup
  async getAllTokenIdsForGroup(groupId) {
    const res = await query("SELECT token_id FROM group_token_revocations WHERE group_id = $1", [
      groupId,
    ]);
    return res.rows.map((r) => r.token_id);
  },
};
