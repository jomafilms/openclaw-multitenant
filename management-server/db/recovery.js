// Recovery methods and social recovery
import { query, decrypt } from "./core.js";

// Recovery methods (bip39, social, hardware)
export const recoveryMethods = {
  async create({ userId, methodType, configEncrypted, enabled = true }) {
    const res = await query(
      `INSERT INTO recovery_methods (user_id, method_type, config_encrypted, enabled)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id, method_type)
       DO UPDATE SET
         config_encrypted = COALESCE($3, recovery_methods.config_encrypted),
         enabled = $4,
         updated_at = NOW()
       RETURNING *`,
      [userId, methodType, configEncrypted, enabled],
    );
    return res.rows[0];
  },

  async findByUserAndType(userId, methodType) {
    const res = await query(
      "SELECT * FROM recovery_methods WHERE user_id = $1 AND method_type = $2",
      [userId, methodType],
    );
    return res.rows[0];
  },

  async listForUser(userId) {
    const res = await query(
      `SELECT id, method_type, enabled, created_at, updated_at
       FROM recovery_methods
       WHERE user_id = $1
       ORDER BY created_at`,
      [userId],
    );
    return res.rows;
  },

  async setEnabled(userId, methodType, enabled) {
    const res = await query(
      `UPDATE recovery_methods
       SET enabled = $3, updated_at = NOW()
       WHERE user_id = $1 AND method_type = $2
       RETURNING *`,
      [userId, methodType, enabled],
    );
    return res.rows[0];
  },

  async delete(userId, methodType) {
    await query("DELETE FROM recovery_methods WHERE user_id = $1 AND method_type = $2", [
      userId,
      methodType,
    ]);
  },

  async getDecryptedConfig(userId, methodType) {
    const res = await query(
      "SELECT config_encrypted FROM recovery_methods WHERE user_id = $1 AND method_type = $2 AND enabled = true",
      [userId, methodType],
    );
    if (!res.rows[0] || !res.rows[0].config_encrypted) return null;
    return JSON.parse(decrypt(res.rows[0].config_encrypted));
  },
};

// Recovery contacts for social recovery
export const recoveryContacts = {
  async create({ userId, recoveryId, contactEmail, contactName, shareIndex, shardEncrypted }) {
    const res = await query(
      `INSERT INTO recovery_contacts (user_id, recovery_id, contact_email, contact_name, share_index, shard_encrypted)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (user_id, contact_email)
       DO UPDATE SET
         recovery_id = $2,
         contact_name = $4,
         share_index = $5,
         shard_encrypted = $6,
         created_at = NOW()
       RETURNING *`,
      [userId, recoveryId, contactEmail.toLowerCase(), contactName, shareIndex, shardEncrypted],
    );
    return res.rows[0];
  },

  async listForUser(userId) {
    const res = await query(
      `SELECT id, contact_email, contact_name, share_index, notified_at, created_at
       FROM recovery_contacts
       WHERE user_id = $1
       ORDER BY share_index`,
      [userId],
    );
    return res.rows;
  },

  async findByUserAndEmail(userId, contactEmail) {
    const res = await query(
      "SELECT * FROM recovery_contacts WHERE user_id = $1 AND contact_email = $2",
      [userId, contactEmail.toLowerCase()],
    );
    return res.rows[0];
  },

  async findByEmail(contactEmail) {
    // Find all recovery contacts by email (for when a contact wants to help)
    const res = await query(
      `SELECT rc.*, u.name as user_name, u.email as user_email
       FROM recovery_contacts rc
       JOIN users u ON rc.user_id = u.id
       WHERE rc.contact_email = $1`,
      [contactEmail.toLowerCase()],
    );
    return res.rows;
  },

  async markNotified(id) {
    const res = await query(
      "UPDATE recovery_contacts SET notified_at = NOW() WHERE id = $1 RETURNING *",
      [id],
    );
    return res.rows[0];
  },

  async deleteForUser(userId) {
    await query("DELETE FROM recovery_contacts WHERE user_id = $1", [userId]);
  },

  async delete(id, userId) {
    await query("DELETE FROM recovery_contacts WHERE id = $1 AND user_id = $2", [id, userId]);
  },
};

// Recovery requests (active social recovery sessions)
export const recoveryRequests = {
  async create({ userId, recoveryId, tokenHash, threshold, expiresAt }) {
    const res = await query(
      `INSERT INTO recovery_requests (user_id, recovery_id, token_hash, threshold, expires_at)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [userId, recoveryId, tokenHash, threshold, expiresAt],
    );
    return res.rows[0];
  },

  async findByTokenHash(tokenHash) {
    const res = await query(
      `SELECT rr.*, u.name as user_name, u.email as user_email
       FROM recovery_requests rr
       JOIN users u ON rr.user_id = u.id
       WHERE rr.token_hash = $1 AND rr.expires_at > NOW()`,
      [tokenHash],
    );
    return res.rows[0];
  },

  async findActiveForUser(userId) {
    const res = await query(
      `SELECT * FROM recovery_requests
       WHERE user_id = $1 AND status = 'pending' AND expires_at > NOW()
       ORDER BY created_at DESC
       LIMIT 1`,
      [userId],
    );
    return res.rows[0];
  },

  async updateShardsCollected(id, count) {
    const res = await query(
      "UPDATE recovery_requests SET shards_collected = $2 WHERE id = $1 RETURNING *",
      [id, count],
    );
    return res.rows[0];
  },

  async complete(id) {
    const res = await query(
      `UPDATE recovery_requests
       SET status = 'completed', completed_at = NOW()
       WHERE id = $1
       RETURNING *`,
      [id],
    );
    return res.rows[0];
  },

  async cancel(id) {
    const res = await query(
      `UPDATE recovery_requests
       SET status = 'cancelled', completed_at = NOW()
       WHERE id = $1
       RETURNING *`,
      [id],
    );
    return res.rows[0];
  },

  async expireOld() {
    const res = await query(
      `UPDATE recovery_requests
       SET status = 'expired'
       WHERE status = 'pending' AND expires_at < NOW()
       RETURNING *`,
    );
    return res.rows;
  },
};

// Recovery shards (submitted during recovery)
export const recoveryShards = {
  async submit({ requestId, contactEmail, shard }) {
    const res = await query(
      `INSERT INTO recovery_shards (request_id, contact_email, shard)
       VALUES ($1, $2, $3)
       ON CONFLICT (request_id, contact_email) DO NOTHING
       RETURNING *`,
      [requestId, contactEmail.toLowerCase(), shard],
    );
    return res.rows[0];
  },

  async listForRequest(requestId) {
    const res = await query(
      "SELECT * FROM recovery_shards WHERE request_id = $1 ORDER BY submitted_at",
      [requestId],
    );
    return res.rows;
  },

  async countForRequest(requestId) {
    const res = await query("SELECT COUNT(*) as count FROM recovery_shards WHERE request_id = $1", [
      requestId,
    ]);
    return parseInt(res.rows[0].count, 10);
  },

  async deleteForRequest(requestId) {
    await query("DELETE FROM recovery_shards WHERE request_id = $1", [requestId]);
  },
};
