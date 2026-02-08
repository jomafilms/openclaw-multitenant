import dotenv from "dotenv";
import pg from "pg";

dotenv.config();

const { Pool } = pg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || "postgresql://localhost:5432/ocmt",
});

// Re-export mesh audit logging from management-server db
// (shared database connection allows us to log to the same audit table)
export { meshAuditLogs, MESH_AUDIT_EVENTS } from "../../management-server/db/index.js";

// Rate limit configuration
const RATE_LIMIT_MESSAGES = parseInt(process.env.RATE_LIMIT_MESSAGES_PER_HOUR || "100", 10);
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS || "3600000", 10); // 1 hour

// Helper for queries
export async function query(text, params) {
  const start = Date.now();
  const res = await pool.query(text, params);
  const duration = Date.now() - start;
  if (process.env.NODE_ENV !== "production") {
    console.log("Query:", { text: text.slice(0, 50), duration, rows: res.rowCount });
  }
  return res;
}

// Relay message operations
export const messages = {
  /**
   * Store a new encrypted message for delivery
   * NOTE: The relay NEVER decrypts payloads - zero-knowledge relay
   */
  async create({ fromContainerId, toContainerId, payloadEncrypted }) {
    const payloadSize = Buffer.byteLength(payloadEncrypted, "utf8");
    const res = await query(
      `INSERT INTO relay_messages (from_container_id, to_container_id, payload_encrypted, payload_size)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [fromContainerId, toContainerId, payloadEncrypted, payloadSize],
    );
    return res.rows[0];
  },

  /**
   * Get pending messages for a container
   */
  async getPending(containerId, limit = 50) {
    const res = await query(
      `SELECT id, from_container_id, payload_encrypted, payload_size, created_at
       FROM relay_messages
       WHERE to_container_id = $1 AND status = 'pending'
       ORDER BY created_at ASC
       LIMIT $2`,
      [containerId, limit],
    );
    return res.rows;
  },

  /**
   * Mark a message as delivered
   */
  async markDelivered(messageId) {
    const res = await query(
      `UPDATE relay_messages
       SET status = 'delivered', delivered_at = NOW()
       WHERE id = $1
       RETURNING *`,
      [messageId],
    );
    return res.rows[0];
  },

  /**
   * Mark multiple messages as delivered (batch)
   */
  async markManyDelivered(messageIds) {
    if (!messageIds || messageIds.length === 0) {
      return [];
    }
    const res = await query(
      `UPDATE relay_messages
       SET status = 'delivered', delivered_at = NOW()
       WHERE id = ANY($1)
       RETURNING id`,
      [messageIds],
    );
    return res.rows;
  },

  /**
   * Get message by ID
   */
  async findById(id) {
    const res = await query("SELECT * FROM relay_messages WHERE id = $1", [id]);
    return res.rows[0];
  },

  /**
   * Expire old undelivered messages (cleanup job)
   */
  async expireOldMessages(maxAgeHours = 24) {
    if (typeof maxAgeHours !== "number" || !Number.isFinite(maxAgeHours) || maxAgeHours < 0) {
      throw new Error("maxAgeHours must be a non-negative number");
    }
    const res = await query(
      `UPDATE relay_messages
       SET status = 'expired', expired_at = NOW()
       WHERE status = 'pending'
         AND created_at < NOW() - ($1 * INTERVAL '1 hour')
       RETURNING id`,
      [maxAgeHours],
    );
    return res.rows;
  },

  /**
   * Count pending messages for a container
   */
  async countPending(containerId) {
    const res = await query(
      `SELECT COUNT(*) FROM relay_messages WHERE to_container_id = $1 AND status = 'pending'`,
      [containerId],
    );
    return parseInt(res.rows[0].count, 10);
  },
};

// Rate limiting operations
export const rateLimits = {
  /**
   * Check if container is rate limited and increment counter
   * Returns { allowed: boolean, remaining: number, resetAt: Date }
   */
  async checkAndIncrement(containerId) {
    const now = new Date();
    const windowStart = new Date(now.getTime() - RATE_LIMIT_WINDOW_MS);

    // Try to get existing rate limit record
    const existing = await query("SELECT * FROM relay_rate_limits WHERE container_id = $1", [
      containerId,
    ]);

    if (existing.rows.length === 0) {
      // First message from this container
      await query(
        `INSERT INTO relay_rate_limits (container_id, window_start, message_count)
         VALUES ($1, $2, 1)
         ON CONFLICT (container_id) DO UPDATE SET window_start = $2, message_count = 1`,
        [containerId, now],
      );
      return {
        allowed: true,
        remaining: RATE_LIMIT_MESSAGES - 1,
        resetAt: new Date(now.getTime() + RATE_LIMIT_WINDOW_MS),
      };
    }

    const record = existing.rows[0];

    // Check if window has expired - reset if so
    if (record.window_start < windowStart) {
      await query(
        "UPDATE relay_rate_limits SET window_start = $2, message_count = 1 WHERE container_id = $1",
        [containerId, now],
      );
      return {
        allowed: true,
        remaining: RATE_LIMIT_MESSAGES - 1,
        resetAt: new Date(now.getTime() + RATE_LIMIT_WINDOW_MS),
      };
    }

    // Check if at limit
    if (record.message_count >= RATE_LIMIT_MESSAGES) {
      const resetAt = new Date(record.window_start.getTime() + RATE_LIMIT_WINDOW_MS);
      return {
        allowed: false,
        remaining: 0,
        resetAt,
      };
    }

    // Increment counter
    const newCount = record.message_count + 1;
    await query("UPDATE relay_rate_limits SET message_count = $2 WHERE container_id = $1", [
      containerId,
      newCount,
    ]);

    return {
      allowed: true,
      remaining: RATE_LIMIT_MESSAGES - newCount,
      resetAt: new Date(record.window_start.getTime() + RATE_LIMIT_WINDOW_MS),
    };
  },

  /**
   * Get current rate limit status without incrementing
   */
  async getStatus(containerId) {
    const windowStart = new Date(Date.now() - RATE_LIMIT_WINDOW_MS);

    const res = await query("SELECT * FROM relay_rate_limits WHERE container_id = $1", [
      containerId,
    ]);

    if (res.rows.length === 0 || res.rows[0].window_start < windowStart) {
      return {
        count: 0,
        remaining: RATE_LIMIT_MESSAGES,
        limit: RATE_LIMIT_MESSAGES,
      };
    }

    const record = res.rows[0];
    return {
      count: record.message_count,
      remaining: Math.max(0, RATE_LIMIT_MESSAGES - record.message_count),
      limit: RATE_LIMIT_MESSAGES,
      resetAt: new Date(record.window_start.getTime() + RATE_LIMIT_WINDOW_MS),
    };
  },
};

// Audit logging - logs who talked to whom (NOT content)
export const auditLog = {
  /**
   * Log a relay attempt
   */
  async log({ fromContainerId, toContainerId, payloadSize, status, errorMessage }) {
    await query(
      `INSERT INTO relay_audit_log (from_container_id, to_container_id, payload_size, status, error_message)
       VALUES ($1, $2, $3, $4, $5)`,
      [fromContainerId, toContainerId, payloadSize, status, errorMessage],
    );
  },

  /**
   * Get recent audit entries (admin use)
   */
  async getRecent(limit = 100) {
    const res = await query(`SELECT * FROM relay_audit_log ORDER BY timestamp DESC LIMIT $1`, [
      limit,
    ]);
    return res.rows;
  },

  /**
   * Get audit entries for a container
   */
  async getForContainer(containerId, limit = 100) {
    const res = await query(
      `SELECT * FROM relay_audit_log
       WHERE from_container_id = $1 OR to_container_id = $1
       ORDER BY timestamp DESC
       LIMIT $2`,
      [containerId, limit],
    );
    return res.rows;
  },
};

// ============================================================
// CACHED SNAPSHOTS (for CACHED tier sharing)
// ============================================================

export const cachedSnapshots = {
  /**
   * Store or update a cached snapshot
   */
  async upsert({
    capabilityId,
    recipientPublicKey,
    issuerPublicKey,
    encryptedData,
    ephemeralPublicKey,
    nonce,
    tag,
    signature,
    expiresAt,
  }) {
    const res = await query(
      `INSERT INTO relay_cached_snapshots
       (capability_id, recipient_public_key, issuer_public_key, encrypted_data, ephemeral_public_key, nonce, tag, signature, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       ON CONFLICT (capability_id)
       DO UPDATE SET
         encrypted_data = $4,
         ephemeral_public_key = $5,
         nonce = $6,
         tag = $7,
         signature = $8,
         created_at = NOW(),
         expires_at = $9
       RETURNING *`,
      [
        capabilityId,
        recipientPublicKey,
        issuerPublicKey,
        encryptedData,
        ephemeralPublicKey,
        nonce,
        tag,
        signature,
        expiresAt,
      ],
    );
    return res.rows[0];
  },

  /**
   * Get snapshot by capability ID
   */
  async findByCapabilityId(capabilityId) {
    const res = await query(
      "SELECT * FROM relay_cached_snapshots WHERE capability_id = $1 AND expires_at > NOW()",
      [capabilityId],
    );
    return res.rows[0];
  },

  /**
   * List snapshots available to a recipient
   */
  async listByRecipient(recipientPublicKey, limit = 100) {
    const res = await query(
      `SELECT * FROM relay_cached_snapshots
       WHERE recipient_public_key = $1 AND expires_at > NOW()
       ORDER BY created_at DESC
       LIMIT $2`,
      [recipientPublicKey, limit],
    );
    return res.rows;
  },

  /**
   * List snapshots by issuer
   */
  async listByIssuer(issuerPublicKey, limit = 100) {
    const res = await query(
      `SELECT * FROM relay_cached_snapshots
       WHERE issuer_public_key = $1 AND expires_at > NOW()
       ORDER BY created_at DESC
       LIMIT $2`,
      [issuerPublicKey, limit],
    );
    return res.rows;
  },

  /**
   * Delete snapshot by capability ID
   */
  async deleteByCapabilityId(capabilityId) {
    const res = await query(
      "DELETE FROM relay_cached_snapshots WHERE capability_id = $1 RETURNING id",
      [capabilityId],
    );
    return res.rowCount > 0;
  },

  /**
   * Delete all snapshots for an issuer (used when revoking all capabilities)
   */
  async deleteByIssuer(issuerPublicKey) {
    const res = await query(
      "DELETE FROM relay_cached_snapshots WHERE issuer_public_key = $1 RETURNING id",
      [issuerPublicKey],
    );
    return res.rowCount;
  },

  /**
   * Cleanup expired snapshots
   */
  async cleanupExpired() {
    const res = await query(
      "DELETE FROM relay_cached_snapshots WHERE expires_at < NOW() RETURNING id",
    );
    return res.rowCount;
  },

  /**
   * Count all active snapshots
   */
  async count() {
    const res = await query(
      "SELECT COUNT(*) as count FROM relay_cached_snapshots WHERE expires_at > NOW()",
    );
    return parseInt(res.rows[0].count, 10);
  },

  /**
   * Get snapshot stats
   */
  async getStats() {
    const res = await query(`
      SELECT
        COUNT(*) as total_snapshots,
        COUNT(DISTINCT issuer_public_key) as unique_issuers,
        COUNT(DISTINCT recipient_public_key) as unique_recipients,
        MIN(created_at) as oldest_snapshot,
        MAX(created_at) as newest_snapshot,
        SUM(LENGTH(encrypted_data)) as total_bytes
      FROM relay_cached_snapshots
      WHERE expires_at > NOW()
    `);
    return res.rows[0];
  },

  /**
   * Check if a capability has a valid snapshot
   */
  async hasValidSnapshot(capabilityId) {
    const res = await query(
      "SELECT 1 FROM relay_cached_snapshots WHERE capability_id = $1 AND expires_at > NOW()",
      [capabilityId],
    );
    return res.rows.length > 0;
  },
};

// ============================================================
// CONTAINER REGISTRY (for message forwarding)
// ============================================================

export const containerRegistry = {
  /**
   * Create a new container registration
   */
  async create({ containerId, publicKey, publicKeyHash, encryptionPublicKey, callbackUrl }) {
    const res = await query(
      `INSERT INTO relay_container_registry
       (container_id, public_key, public_key_hash, encryption_public_key, callback_url)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [containerId, publicKey, publicKeyHash, encryptionPublicKey, callbackUrl],
    );
    return res.rows[0];
  },

  /**
   * Update an existing container registration
   */
  async update(containerId, { publicKey, publicKeyHash, encryptionPublicKey, callbackUrl }) {
    const updates = [];
    const values = [containerId];
    let paramIndex = 2;

    if (publicKey !== undefined) {
      updates.push(`public_key = $${paramIndex++}`);
      values.push(publicKey);
    }
    if (publicKeyHash !== undefined) {
      updates.push(`public_key_hash = $${paramIndex++}`);
      values.push(publicKeyHash);
    }
    if (encryptionPublicKey !== undefined) {
      updates.push(`encryption_public_key = $${paramIndex++}`);
      values.push(encryptionPublicKey);
    }
    if (callbackUrl !== undefined) {
      updates.push(`callback_url = $${paramIndex++}`);
      values.push(callbackUrl);
    }

    if (updates.length === 0) {
      return null;
    }

    updates.push("updated_at = NOW()");

    const res = await query(
      `UPDATE relay_container_registry
       SET ${updates.join(", ")}
       WHERE container_id = $1
       RETURNING *`,
      values,
    );
    return res.rows[0];
  },

  /**
   * Find registration by container ID
   */
  async findByContainerId(containerId) {
    const res = await query("SELECT * FROM relay_container_registry WHERE container_id = $1", [
      containerId,
    ]);
    return res.rows[0];
  },

  /**
   * Find registration by public key hash
   */
  async findByPublicKeyHash(publicKeyHash) {
    const res = await query("SELECT * FROM relay_container_registry WHERE public_key_hash = $1", [
      publicKeyHash,
    ]);
    return res.rows[0];
  },

  /**
   * Find registration by public key
   */
  async findByPublicKey(publicKey) {
    const res = await query("SELECT * FROM relay_container_registry WHERE public_key = $1", [
      publicKey,
    ]);
    return res.rows[0];
  },

  /**
   * Delete a container registration
   */
  async delete(containerId) {
    const res = await query(
      "DELETE FROM relay_container_registry WHERE container_id = $1 RETURNING id",
      [containerId],
    );
    return res.rowCount > 0;
  },

  /**
   * List all registrations with callback URLs (for proactive delivery)
   */
  async listWithCallbacks(limit = 100) {
    const res = await query(
      `SELECT * FROM relay_container_registry
       WHERE callback_url IS NOT NULL
       ORDER BY updated_at DESC
       LIMIT $1`,
      [limit],
    );
    return res.rows;
  },

  /**
   * Count total registrations
   */
  async count() {
    const res = await query("SELECT COUNT(*) FROM relay_container_registry");
    return parseInt(res.rows[0].count, 10);
  },

  /**
   * Get registration stats
   */
  async getStats() {
    const res = await query(`
      SELECT
        COUNT(*) as total_registrations,
        COUNT(callback_url) as with_callback,
        COUNT(encryption_public_key) as with_encryption_key,
        MIN(created_at) as oldest_registration,
        MAX(updated_at) as last_activity
      FROM relay_container_registry
    `);
    return res.rows[0];
  },
};

// Container lookup (from users table - shared with management-server)
export const containers = {
  /**
   * Find container info by user ID
   */
  async findByUserId(userId) {
    const res = await query(
      "SELECT id, container_id, gateway_token, status FROM users WHERE id = $1",
      [userId],
    );
    return res.rows[0];
  },

  /**
   * Verify a container's gateway token
   */
  async verifyGatewayToken(userId, gatewayToken) {
    const res = await query(
      "SELECT id, container_id, status FROM users WHERE id = $1 AND gateway_token = $2",
      [userId, gatewayToken],
    );
    return res.rows[0];
  },

  /**
   * Get container status
   */
  async getStatus(userId) {
    const res = await query("SELECT id, container_id, status FROM users WHERE id = $1", [userId]);
    return res.rows[0];
  },
};

export default pool;
