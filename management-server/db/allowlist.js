// User allowlist operations for auto-provisioning control
import { query } from "./core.js";

// Settings keys
const ALLOWLIST_ENABLED_KEY = "allowlist_enabled";

export const userAllowlist = {
  /**
   * Check if allowlist feature is enabled
   * @returns {Promise<boolean>}
   */
  async isEnabled() {
    const res = await query(
      `SELECT value FROM user_allowlist_settings WHERE key = $1`,
      [ALLOWLIST_ENABLED_KEY],
    );
    if (!res.rows[0]) {
      // Default: disabled (allow all users)
      return false;
    }
    return res.rows[0].value === true || res.rows[0].value?.enabled === true;
  },

  /**
   * Set allowlist enabled/disabled
   * @param {boolean} enabled
   * @param {string} [updatedBy] - User ID who made the change
   */
  async setEnabled(enabled, updatedBy = null) {
    await query(
      `INSERT INTO user_allowlist_settings (key, value, updated_by, updated_at)
       VALUES ($1, $2::jsonb, $3, NOW())
       ON CONFLICT (key) DO UPDATE SET
         value = $2::jsonb,
         updated_by = $3,
         updated_at = NOW()`,
      [ALLOWLIST_ENABLED_KEY, JSON.stringify({ enabled }), updatedBy],
    );
  },

  /**
   * Add an entry to the allowlist
   * @param {Object} params
   * @param {'email' | 'domain'} params.entryType
   * @param {string} params.value - Email address or domain
   * @param {string} [params.description]
   * @param {string} [params.createdBy] - User ID
   * @param {Date} [params.expiresAt]
   */
  async add({ entryType, value, description, createdBy, expiresAt }) {
    // Normalize value (lowercase for case-insensitive matching)
    const normalizedValue = value.toLowerCase().trim();

    const res = await query(
      `INSERT INTO user_allowlist (entry_type, value, description, created_by, expires_at)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (entry_type, value) DO UPDATE SET
         description = COALESCE($3, user_allowlist.description),
         expires_at = COALESCE($5, user_allowlist.expires_at),
         enabled = true
       RETURNING *`,
      [entryType, normalizedValue, description, createdBy, expiresAt],
    );
    return res.rows[0];
  },

  /**
   * Remove an entry from the allowlist by ID
   * @param {string} id
   */
  async remove(id) {
    const res = await query(
      `DELETE FROM user_allowlist WHERE id = $1 RETURNING *`,
      [id],
    );
    return res.rows[0];
  },

  /**
   * Disable an entry (soft delete)
   * @param {string} id
   */
  async disable(id) {
    const res = await query(
      `UPDATE user_allowlist SET enabled = false WHERE id = $1 RETURNING *`,
      [id],
    );
    return res.rows[0];
  },

  /**
   * Enable an entry
   * @param {string} id
   */
  async enable(id) {
    const res = await query(
      `UPDATE user_allowlist SET enabled = true WHERE id = $1 RETURNING *`,
      [id],
    );
    return res.rows[0];
  },

  /**
   * List all allowlist entries
   * @param {Object} [options]
   * @param {boolean} [options.includeDisabled] - Include disabled entries
   */
  async list({ includeDisabled = false } = {}) {
    const whereClause = includeDisabled ? "" : "WHERE enabled = true";
    const res = await query(
      `SELECT al.*, u.email as created_by_email, u.name as created_by_name
       FROM user_allowlist al
       LEFT JOIN users u ON al.created_by = u.id
       ${whereClause}
       ORDER BY created_at DESC`,
    );
    return res.rows;
  },

  /**
   * Check if an email is allowed
   * @param {string} email
   * @returns {Promise<{allowed: boolean, reason: string, entry?: object}>}
   */
  async checkEmail(email) {
    const normalizedEmail = email.toLowerCase().trim();
    const domain = normalizedEmail.split("@")[1];

    // Check if allowlist is enabled
    const enabled = await this.isEnabled();
    if (!enabled) {
      // Allowlist disabled = allow all
      return { allowed: true, reason: "allowlist_disabled" };
    }

    // Check for exact email match
    const emailMatch = await query(
      `SELECT * FROM user_allowlist
       WHERE entry_type = 'email'
         AND value = $1
         AND enabled = true
         AND (expires_at IS NULL OR expires_at > NOW())`,
      [normalizedEmail],
    );

    if (emailMatch.rows[0]) {
      return {
        allowed: true,
        reason: "email_match",
        entry: emailMatch.rows[0],
      };
    }

    // Check for domain match
    const domainMatch = await query(
      `SELECT * FROM user_allowlist
       WHERE entry_type = 'domain'
         AND value = $1
         AND enabled = true
         AND (expires_at IS NULL OR expires_at > NOW())`,
      [domain],
    );

    if (domainMatch.rows[0]) {
      return {
        allowed: true,
        reason: "domain_match",
        entry: domainMatch.rows[0],
      };
    }

    // No match found
    return { allowed: false, reason: "not_on_allowlist" };
  },

  /**
   * Get allowlist statistics
   */
  async getStats() {
    const res = await query(`
      SELECT
        (SELECT COUNT(*) FROM user_allowlist WHERE enabled = true) as enabled_count,
        (SELECT COUNT(*) FROM user_allowlist WHERE entry_type = 'email' AND enabled = true) as email_count,
        (SELECT COUNT(*) FROM user_allowlist WHERE entry_type = 'domain' AND enabled = true) as domain_count,
        (SELECT value->>'enabled' FROM user_allowlist_settings WHERE key = $1) as feature_enabled
    `, [ALLOWLIST_ENABLED_KEY]);

    const row = res.rows[0];
    return {
      totalEnabled: parseInt(row.enabled_count, 10),
      emailCount: parseInt(row.email_count, 10),
      domainCount: parseInt(row.domain_count, 10),
      featureEnabled: row.feature_enabled === "true",
    };
  },

  /**
   * Find entry by ID
   * @param {string} id
   */
  async findById(id) {
    const res = await query(
      `SELECT * FROM user_allowlist WHERE id = $1`,
      [id],
    );
    return res.rows[0];
  },
};
