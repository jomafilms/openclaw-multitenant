// MFA database operations
// Provides CRUD for user_mfa, mfa_backup_codes, mfa_attempts, pending_mfa_sessions

import { query } from "./core.js";

/**
 * User MFA configuration operations
 */
export const userMfa = {
  /**
   * Find MFA config by user ID
   * @param {string} userId - User UUID
   * @returns {Promise<Object|null>}
   */
  async findByUserId(userId) {
    const res = await query("SELECT * FROM user_mfa WHERE user_id = $1", [userId]);
    return res.rows[0] || null;
  },

  /**
   * Create or update MFA configuration for a user
   * @param {string} userId - User UUID
   * @param {Object} data - MFA configuration data
   */
  async upsert(userId, data) {
    const { totpSecretEncrypted, totpEnabled, totpVerifiedAt, mfaEnforced, preferredMethod } = data;

    const res = await query(
      `INSERT INTO user_mfa (user_id, totp_secret_encrypted, totp_enabled, totp_verified_at, mfa_enforced, preferred_method)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (user_id)
       DO UPDATE SET
         totp_secret_encrypted = COALESCE($2, user_mfa.totp_secret_encrypted),
         totp_enabled = COALESCE($3, user_mfa.totp_enabled),
         totp_verified_at = COALESCE($4, user_mfa.totp_verified_at),
         mfa_enforced = COALESCE($5, user_mfa.mfa_enforced),
         preferred_method = COALESCE($6, user_mfa.preferred_method),
         updated_at = NOW()
       RETURNING *`,
      [
        userId,
        totpSecretEncrypted ?? null,
        totpEnabled ?? null,
        totpVerifiedAt ?? null,
        mfaEnforced ?? null,
        preferredMethod ?? null,
      ],
    );
    return res.rows[0];
  },

  /**
   * Get MFA status for a user
   * Returns enabled state and backup code count
   * @param {string} userId - User UUID
   * @returns {Promise<Object>}
   */
  async getStatus(userId) {
    const mfaConfig = await this.findByUserId(userId);
    const backupCodesRemaining = await mfaBackupCodes.countUnused(userId);

    return {
      totpEnabled: mfaConfig?.totp_enabled || false,
      mfaEnforced: mfaConfig?.mfa_enforced || false,
      preferredMethod: mfaConfig?.preferred_method || "totp",
      backupCodesRemaining,
      totpVerifiedAt: mfaConfig?.totp_verified_at || null,
    };
  },

  /**
   * Setup MFA - store encrypted secret before verification
   * @param {string} userId - User UUID
   * @param {string} encryptedSecret - Encrypted TOTP secret
   */
  async setupTotp(userId, encryptedSecret) {
    return this.upsert(userId, {
      totpSecretEncrypted: encryptedSecret,
      totpEnabled: false,
    });
  },

  /**
   * Enable TOTP after successful verification
   * @param {string} userId - User UUID
   */
  async enableTotp(userId) {
    return this.upsert(userId, {
      totpEnabled: true,
      totpVerifiedAt: new Date(),
    });
  },

  /**
   * Disable TOTP and clear secret
   * @param {string} userId - User UUID
   */
  async disableTotp(userId) {
    const res = await query(
      `UPDATE user_mfa
       SET totp_secret_encrypted = NULL,
           totp_enabled = FALSE,
           totp_verified_at = NULL,
           updated_at = NOW()
       WHERE user_id = $1
       RETURNING *`,
      [userId],
    );
    return res.rows[0];
  },

  /**
   * Delete MFA config for a user
   * @param {string} userId - User UUID
   */
  async delete(userId) {
    await query("DELETE FROM user_mfa WHERE user_id = $1", [userId]);
  },
};

/**
 * MFA backup codes operations
 */
export const mfaBackupCodes = {
  /**
   * Get all unused backup codes for a user
   * @param {string} userId - User UUID
   * @returns {Promise<Array>}
   */
  async getUnused(userId) {
    const res = await query(
      "SELECT * FROM mfa_backup_codes WHERE user_id = $1 AND used_at IS NULL ORDER BY created_at",
      [userId],
    );
    return res.rows;
  },

  /**
   * Count unused backup codes
   * @param {string} userId - User UUID
   * @returns {Promise<number>}
   */
  async countUnused(userId) {
    const res = await query(
      "SELECT COUNT(*) as count FROM mfa_backup_codes WHERE user_id = $1 AND used_at IS NULL",
      [userId],
    );
    return parseInt(res.rows[0]?.count || 0, 10);
  },

  /**
   * Save new backup codes, replacing any existing ones
   * @param {string} userId - User UUID
   * @param {string[]} hashedCodes - Array of Argon2id hashed codes
   */
  async replaceAll(userId, hashedCodes) {
    // Delete all existing codes first
    await this.deleteAll(userId);

    // Insert new codes
    for (const hash of hashedCodes) {
      await query("INSERT INTO mfa_backup_codes (user_id, code_hash) VALUES ($1, $2)", [
        userId,
        hash,
      ]);
    }
  },

  /**
   * Mark a backup code as used
   * @param {string} codeId - Backup code UUID
   */
  async markUsed(codeId) {
    const res = await query(
      "UPDATE mfa_backup_codes SET used_at = NOW() WHERE id = $1 RETURNING *",
      [codeId],
    );
    return res.rows[0];
  },

  /**
   * Find backup code by hash (for verification)
   * Returns unused code matching the hash
   * @param {string} userId - User UUID
   * @param {string} codeHash - Hash to match
   * @returns {Promise<Object|null>}
   */
  async findByHash(userId, codeHash) {
    const res = await query(
      "SELECT * FROM mfa_backup_codes WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL",
      [userId, codeHash],
    );
    return res.rows[0] || null;
  },

  /**
   * Delete all backup codes for a user
   * @param {string} userId - User UUID
   */
  async deleteAll(userId) {
    await query("DELETE FROM mfa_backup_codes WHERE user_id = $1", [userId]);
  },
};

/**
 * MFA verification attempts logging
 */
export const mfaAttempts = {
  /**
   * Log an MFA verification attempt
   * @param {Object} data - Attempt data
   */
  async log(data) {
    const { userId, attemptType, success, ipAddress, userAgent } = data;
    const res = await query(
      `INSERT INTO mfa_attempts (user_id, attempt_type, success, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [userId, attemptType, success, ipAddress, userAgent || null],
    );
    return res.rows[0];
  },

  /**
   * Get recent failed attempts for rate limiting
   * @param {string} userId - User UUID
   * @param {number} windowMinutes - Time window in minutes
   * @returns {Promise<number>}
   */
  async countRecentFailed(userId, windowMinutes = 15) {
    const res = await query(
      `SELECT COUNT(*) as count FROM mfa_attempts
       WHERE user_id = $1
         AND success = FALSE
         AND created_at > NOW() - INTERVAL '1 minute' * $2`,
      [userId, windowMinutes],
    );
    return parseInt(res.rows[0]?.count || 0, 10);
  },

  /**
   * Get recent attempts for a user
   * @param {string} userId - User UUID
   * @param {number} limit - Max attempts to return
   * @returns {Promise<Array>}
   */
  async getRecent(userId, limit = 20) {
    const res = await query(
      `SELECT * FROM mfa_attempts
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT $2`,
      [userId, limit],
    );
    return res.rows;
  },

  /**
   * Delete old attempts (cleanup)
   * @param {number} daysOld - Delete attempts older than this many days
   */
  async deleteOld(daysOld = 30) {
    await query("DELETE FROM mfa_attempts WHERE created_at < NOW() - INTERVAL '1 day' * $1", [
      daysOld,
    ]);
  },
};

/**
 * Pending MFA sessions (between magic link and MFA verification)
 */
export const pendingMfaSessions = {
  /**
   * Create a pending MFA session
   * @param {Object} data - Session data
   * @returns {Promise<Object>}
   */
  async create(data) {
    const { userId, sessionToken, expiresAt } = data;
    const res = await query(
      `INSERT INTO pending_mfa_sessions (user_id, session_token, expires_at)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [userId, sessionToken, expiresAt],
    );
    return res.rows[0];
  },

  /**
   * Find pending session by token
   * @param {string} token - Session token
   * @returns {Promise<Object|null>}
   */
  async findByToken(token) {
    const res = await query("SELECT * FROM pending_mfa_sessions WHERE session_token = $1", [token]);
    return res.rows[0] || null;
  },

  /**
   * Find valid (non-expired) pending session by token
   * @param {string} token - Session token
   * @returns {Promise<Object|null>}
   */
  async findValidByToken(token) {
    const res = await query(
      "SELECT * FROM pending_mfa_sessions WHERE session_token = $1 AND expires_at > NOW()",
      [token],
    );
    return res.rows[0] || null;
  },

  /**
   * Delete a pending session by ID
   * @param {string} id - Session UUID
   */
  async delete(id) {
    await query("DELETE FROM pending_mfa_sessions WHERE id = $1", [id]);
  },

  /**
   * Delete pending session by token
   * @param {string} token - Session token
   */
  async deleteByToken(token) {
    await query("DELETE FROM pending_mfa_sessions WHERE session_token = $1", [token]);
  },

  /**
   * Delete all pending sessions for a user
   * @param {string} userId - User UUID
   */
  async deleteForUser(userId) {
    await query("DELETE FROM pending_mfa_sessions WHERE user_id = $1", [userId]);
  },

  /**
   * Delete expired sessions (cleanup)
   */
  async deleteExpired() {
    await query("DELETE FROM pending_mfa_sessions WHERE expires_at < NOW()");
  },
};

export default {
  userMfa,
  mfaBackupCodes,
  mfaAttempts,
  pendingMfaSessions,
};
