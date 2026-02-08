// Session and magic link operations
// SECURITY: Session tokens are stored hashed (SHA-256) to protect against database compromise.
// BREAKING CHANGE: Existing sessions will be invalidated after this change - users must re-login.
import crypto from "crypto";
import { query } from "./core.js";

/**
 * Hash a session token for storage/lookup
 * @param {string} rawToken - The raw session token
 * @returns {string} SHA-256 hash of the token
 */
function hashToken(rawToken) {
  return crypto.createHash("sha256").update(rawToken).digest("hex");
}

// Maximum concurrent sessions per user (default: 5)
const MAX_SESSIONS_PER_USER = parseInt(process.env.MAX_SESSIONS_PER_USER) || 5;

export const sessions = {
  /**
   * Create a new session with metadata
   * @param {string} userId
   * @param {string} token - Raw token (will be hashed before storage)
   * @param {Date} expiresAt
   * @param {object} metadata - Optional { ipAddress, userAgent, deviceInfo }
   * @returns {Promise<{session: object, rawToken: string}>} Session data and raw token (only available at creation)
   */
  async create(userId, token, expiresAt, metadata = {}) {
    const { ipAddress, userAgent, deviceInfo } = metadata;

    // Enforce session limit before creating new session
    await this.enforceSessionLimit(userId);

    // Hash token before storage - raw token is only returned at creation time
    const hashedToken = hashToken(token);

    const res = await query(
      `INSERT INTO sessions (user_id, token, expires_at, ip_address, user_agent, device_info, last_activity_at)
       VALUES ($1, $2, $3, $4, $5, $6, NOW())
       RETURNING *`,
      [
        userId,
        hashedToken,
        expiresAt,
        ipAddress || null,
        userAgent || null,
        deviceInfo ? JSON.stringify(deviceInfo) : "{}",
      ],
    );

    // Return session data along with the raw token (caller needs raw token for cookie)
    return {
      ...res.rows[0],
      rawToken: token, // Only time raw token is available
    };
  },

  /**
   * Find session by token (includes user data, checks revoked status)
   * @param {string} token - Raw token (will be hashed for lookup)
   */
  async findByToken(token) {
    const hashedToken = hashToken(token);
    const res = await query(
      `SELECT s.*, u.* FROM sessions s
       JOIN users u ON s.user_id = u.id
       WHERE s.token = $1
         AND s.expires_at > NOW()
         AND s.revoked_at IS NULL`,
      [hashedToken],
    );
    return res.rows[0];
  },

  /**
   * Find session by ID
   */
  async findById(sessionId) {
    const res = await query(`SELECT * FROM sessions WHERE id = $1`, [sessionId]);
    return res.rows[0];
  },

  /**
   * List all active sessions for a user
   */
  async listActiveForUser(userId) {
    const res = await query(
      `SELECT id, created_at, expires_at, ip_address, user_agent, device_info, last_activity_at
       FROM sessions
       WHERE user_id = $1
         AND expires_at > NOW()
         AND revoked_at IS NULL
       ORDER BY last_activity_at DESC`,
      [userId],
    );
    return res.rows;
  },

  /**
   * Update last activity timestamp and optionally IP
   */
  async updateLastActivity(sessionId, ipAddress = null) {
    await query(
      `UPDATE sessions
       SET last_activity_at = NOW(), ip_address = COALESCE($2, ip_address)
       WHERE id = $1`,
      [sessionId, ipAddress],
    );
  },

  /**
   * Revoke a specific session
   */
  async revokeById(sessionId, reason = "user_action") {
    const res = await query(
      `UPDATE sessions
       SET revoked_at = NOW(), revoke_reason = $2
       WHERE id = $1 AND revoked_at IS NULL
       RETURNING *`,
      [sessionId, reason],
    );
    return res.rows[0];
  },

  /**
   * Revoke all sessions for a user (optionally except one)
   */
  async revokeAllForUser(userId, exceptSessionId = null, reason = "user_action") {
    let queryText = `UPDATE sessions
                     SET revoked_at = NOW(), revoke_reason = $2
                     WHERE user_id = $1
                       AND revoked_at IS NULL
                       AND expires_at > NOW()`;
    const params = [userId, reason];

    if (exceptSessionId) {
      queryText += ` AND id != $3`;
      params.push(exceptSessionId);
    }

    queryText += ` RETURNING id`;
    const res = await query(queryText, params);
    return res.rows.length;
  },

  /**
   * Enforce maximum session limit by revoking oldest sessions
   */
  async enforceSessionLimit(userId) {
    const activeSessions = await this.listActiveForUser(userId);

    if (activeSessions.length >= MAX_SESSIONS_PER_USER) {
      // Revoke oldest session(s) to make room
      const sessionsToRevoke = activeSessions
        .toSorted((a, b) => new Date(a.last_activity_at) - new Date(b.last_activity_at))
        .slice(0, activeSessions.length - MAX_SESSIONS_PER_USER + 1);

      for (const session of sessionsToRevoke) {
        await this.revokeById(session.id, "session_limit_exceeded");
      }

      return sessionsToRevoke.length;
    }

    return 0;
  },

  async delete(token) {
    const hashedToken = hashToken(token);
    await query("DELETE FROM sessions WHERE token = $1", [hashedToken]);
  },

  /**
   * Delete session by token (alias for delete)
   * @param {string} token - Raw token (will be hashed for lookup)
   */
  async deleteByToken(token) {
    const hashedToken = hashToken(token);
    await query("DELETE FROM sessions WHERE token = $1", [hashedToken]);
  },

  /**
   * Delete all sessions for a user (used for SAML SLO)
   */
  async deleteAllForUser(userId) {
    const res = await query("DELETE FROM sessions WHERE user_id = $1 RETURNING id", [userId]);
    return res.rows.length;
  },

  async deleteExpired() {
    await query("DELETE FROM sessions WHERE expires_at < NOW()");
  },

  /**
   * Count active sessions for a user
   */
  async countActiveForUser(userId) {
    const res = await query(
      `SELECT COUNT(*) as count FROM sessions
       WHERE user_id = $1
         AND expires_at > NOW()
         AND revoked_at IS NULL`,
      [userId],
    );
    return parseInt(res.rows[0].count, 10);
  },
};

// Magic links for passwordless authentication
// SECURITY: Magic link tokens are also stored hashed to protect against database compromise.
export const magicLinks = {
  /**
   * Create a new magic link
   * @param {string} email
   * @param {string} token - Raw token (will be hashed before storage)
   * @param {Date} expiresAt
   * @returns {Promise<{link: object, rawToken: string}>} Link data and raw token (only available at creation)
   */
  async create(email, token, expiresAt) {
    const hashedToken = hashToken(token);
    const res = await query(
      `INSERT INTO magic_links (email, token, expires_at) VALUES ($1, $2, $3) RETURNING *`,
      [email, hashedToken, expiresAt],
    );
    return {
      ...res.rows[0],
      rawToken: token, // Only time raw token is available
    };
  },

  /**
   * Find magic link by token
   * @param {string} token - Raw token (will be hashed for lookup)
   */
  async findByToken(token) {
    const hashedToken = hashToken(token);
    const res = await query(
      `SELECT * FROM magic_links WHERE token = $1 AND expires_at > NOW() AND used_at IS NULL`,
      [hashedToken],
    );
    return res.rows[0];
  },

  /**
   * Mark a magic link as used
   * @param {string} token - Raw token (will be hashed for lookup)
   */
  async markUsed(token) {
    const hashedToken = hashToken(token);
    await query(`UPDATE magic_links SET used_at = NOW() WHERE token = $1`, [hashedToken]);
  },

  /**
   * Find and mark a magic link as used atomically
   * @param {string} token - Raw token (will be hashed for lookup)
   * @returns {Promise<object|null>} The link if found and not yet used, null otherwise
   */
  async findAndMarkUsed(token) {
    // Atomically find and mark as used in one query
    // Returns the link if found and not yet used, null otherwise
    const hashedToken = hashToken(token);
    const res = await query(
      `UPDATE magic_links
       SET used_at = NOW()
       WHERE token = $1
         AND used_at IS NULL
         AND expires_at > NOW()
       RETURNING *`,
      [hashedToken],
    );
    return res.rows[0] || null;
  },

  async deleteExpired() {
    await query("DELETE FROM magic_links WHERE expires_at < NOW()");
  },
};
