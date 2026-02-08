/**
 * Admin Security Database Operations
 *
 * Provides database access for admin IP allowlist, security settings,
 * action confirmations, and emergency access tokens.
 */
import crypto from "crypto";
import { query } from "./core.js";

// ============================================================
// IP ALLOWLIST OPERATIONS
// ============================================================

export const adminIpAllowlist = {
  /**
   * Get all enabled, non-expired IP allowlist entries
   * @returns {Promise<Array>} List of allowlist entries with creator info
   */
  async list() {
    const res = await query(
      `SELECT a.*, u.email as created_by_email
       FROM admin_ip_allowlist a
       LEFT JOIN users u ON a.created_by = u.id
       WHERE a.enabled = true
         AND (a.expires_at IS NULL OR a.expires_at > NOW())
       ORDER BY a.created_at DESC`,
    );
    return res.rows;
  },

  /**
   * Get all allowlist entries including disabled/expired (for admin view)
   * @returns {Promise<Array>}
   */
  async listAll() {
    const res = await query(
      `SELECT a.*, u.email as created_by_email
       FROM admin_ip_allowlist a
       LEFT JOIN users u ON a.created_by = u.id
       ORDER BY a.created_at DESC`,
    );
    return res.rows;
  },

  /**
   * Add a new IP range to the allowlist
   * @param {Object} params
   * @param {string} params.ipRange - CIDR notation (e.g., "192.168.1.0/24")
   * @param {string} [params.description] - Human-readable description
   * @param {string} params.createdBy - User ID who added this entry
   * @param {Date} [params.expiresAt] - Optional expiration time
   * @returns {Promise<Object>} Created entry
   */
  async add({ ipRange, description, createdBy, expiresAt }) {
    const res = await query(
      `INSERT INTO admin_ip_allowlist (ip_range, description, created_by, expires_at)
       VALUES ($1::cidr, $2, $3, $4)
       RETURNING *`,
      [ipRange, description || null, createdBy, expiresAt || null],
    );
    return res.rows[0];
  },

  /**
   * Remove an IP range from the allowlist
   * @param {string} id - Entry ID
   * @returns {Promise<Object|null>} Removed entry or null if not found
   */
  async remove(id) {
    const res = await query(`DELETE FROM admin_ip_allowlist WHERE id = $1 RETURNING *`, [id]);
    return res.rows[0] || null;
  },

  /**
   * Disable an IP range (soft delete)
   * @param {string} id - Entry ID
   * @returns {Promise<Object|null>}
   */
  async disable(id) {
    const res = await query(
      `UPDATE admin_ip_allowlist SET enabled = false WHERE id = $1 RETURNING *`,
      [id],
    );
    return res.rows[0] || null;
  },

  /**
   * Check if an IP is in the allowlist and update hit count
   * Uses PostgreSQL CIDR containment operator (<<= means "is contained by or equals")
   * @param {string} ip - IP address to check
   * @returns {Promise<boolean>} True if IP is allowed
   */
  async checkIp(ip) {
    const res = await query(
      `UPDATE admin_ip_allowlist
       SET hit_count = hit_count + 1, last_used_at = NOW()
       WHERE enabled = true
         AND (expires_at IS NULL OR expires_at > NOW())
         AND $1::inet <<= ip_range
       RETURNING id`,
      [ip],
    );
    return res.rows.length > 0;
  },

  /**
   * Check if IP is allowed without updating hit count (for read-only checks)
   * @param {string} ip - IP address to check
   * @returns {Promise<boolean>}
   */
  async isIpAllowed(ip) {
    const res = await query(
      `SELECT 1 FROM admin_ip_allowlist
       WHERE enabled = true
         AND (expires_at IS NULL OR expires_at > NOW())
         AND $1::inet <<= ip_range
       LIMIT 1`,
      [ip],
    );
    return res.rows.length > 0;
  },

  /**
   * Check if the IP allowlist feature is enabled
   * @returns {Promise<boolean>}
   */
  async isAllowlistEnabled() {
    const res = await query(
      `SELECT value FROM admin_security_settings WHERE key = 'ip_allowlist_enabled'`,
    );
    // Default to false if not set
    return res.rows[0]?.value === true;
  },

  /**
   * Enable or disable the IP allowlist feature
   * @param {boolean} enabled
   * @param {string} updatedBy - User ID
   */
  async setAllowlistEnabled(enabled, updatedBy) {
    await query(
      `INSERT INTO admin_security_settings (key, value, updated_by, updated_at)
       VALUES ('ip_allowlist_enabled', $1, $2, NOW())
       ON CONFLICT (key) DO UPDATE SET value = $1, updated_by = $2, updated_at = NOW()`,
      [enabled, updatedBy],
    );
  },

  /**
   * Get allowlist entry by ID
   * @param {string} id
   * @returns {Promise<Object|null>}
   */
  async getById(id) {
    const res = await query(
      `SELECT a.*, u.email as created_by_email
       FROM admin_ip_allowlist a
       LEFT JOIN users u ON a.created_by = u.id
       WHERE a.id = $1`,
      [id],
    );
    return res.rows[0] || null;
  },
};

// ============================================================
// ADMIN SECURITY SETTINGS
// ============================================================

export const adminSecuritySettings = {
  /**
   * Get a single setting by key
   * @param {string} key - Setting key
   * @returns {Promise<any>} Setting value or undefined
   */
  async get(key) {
    const res = await query(`SELECT value FROM admin_security_settings WHERE key = $1`, [key]);
    return res.rows[0]?.value;
  },

  /**
   * Set a setting value
   * @param {string} key - Setting key
   * @param {any} value - Setting value (will be JSON stringified)
   * @param {string} updatedBy - User ID
   */
  async set(key, value, updatedBy) {
    await query(
      `INSERT INTO admin_security_settings (key, value, updated_by, updated_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (key) DO UPDATE SET value = $2, updated_by = $3, updated_at = NOW()`,
      [key, JSON.stringify(value), updatedBy],
    );
  },

  /**
   * Get all settings as an object
   * @returns {Promise<Object>}
   */
  async getAll() {
    const res = await query(`SELECT key, value, updated_at FROM admin_security_settings`);
    return Object.fromEntries(res.rows.map((r) => [r.key, r.value]));
  },

  /**
   * Delete a setting
   * @param {string} key
   */
  async delete(key) {
    await query(`DELETE FROM admin_security_settings WHERE key = $1`, [key]);
  },
};

// ============================================================
// ACTION CONFIRMATIONS (Dangerous Operation 2-Step)
// ============================================================

export const adminActionConfirmations = {
  /**
   * Create a confirmation request for a dangerous action
   * @param {Object} params
   * @param {string} params.adminId - Admin user ID
   * @param {string} params.actionType - Type of action requiring confirmation
   * @param {Object} params.actionDetails - Details about the action
   * @param {string} params.token - Confirmation token (plaintext)
   * @param {Date} params.expiresAt - When the confirmation expires
   * @param {string} [params.ipAddress] - Request IP address
   * @returns {Promise<Object>} Created confirmation
   */
  async create({ adminId, actionType, actionDetails, token, expiresAt, ipAddress }) {
    const res = await query(
      `INSERT INTO admin_action_confirmations
       (admin_id, action_type, action_details, token, expires_at, ip_address)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [adminId, actionType, JSON.stringify(actionDetails), token, expiresAt, ipAddress || null],
    );
    return res.rows[0];
  },

  /**
   * Find a valid confirmation by token
   * @param {string} token - Confirmation token
   * @returns {Promise<Object|null>}
   */
  async findByToken(token) {
    const res = await query(
      `SELECT * FROM admin_action_confirmations
       WHERE token = $1
         AND expires_at > NOW()
         AND confirmed_at IS NULL`,
      [token],
    );
    return res.rows[0] || null;
  },

  /**
   * Mark a confirmation as confirmed
   * @param {string} id - Confirmation ID
   */
  async confirm(id) {
    await query(`UPDATE admin_action_confirmations SET confirmed_at = NOW() WHERE id = $1`, [id]);
  },

  /**
   * Get pending confirmations for an admin
   * @param {string} adminId - Admin user ID
   * @returns {Promise<Array>}
   */
  async getPending(adminId) {
    const res = await query(
      `SELECT * FROM admin_action_confirmations
       WHERE admin_id = $1
         AND expires_at > NOW()
         AND confirmed_at IS NULL
       ORDER BY created_at DESC`,
      [adminId],
    );
    return res.rows;
  },

  /**
   * Clean up expired confirmations
   * @returns {Promise<number>} Number of deleted records
   */
  async cleanup() {
    const res = await query(
      `DELETE FROM admin_action_confirmations
       WHERE expires_at < NOW()
       RETURNING id`,
    );
    return res.rowCount;
  },
};

// ============================================================
// EMERGENCY ACCESS TOKENS
// ============================================================

export const emergencyAccessTokens = {
  /**
   * Create an emergency access token
   * Token should be hashed before storage
   * @param {Object} params
   * @param {string} params.tokenHash - SHA-256 hash of the token
   * @param {string} params.reason - Reason for emergency access
   * @param {Date} params.expiresAt - When the token expires
   * @param {boolean} [params.singleUse=true] - Whether token is single-use
   * @returns {Promise<Object>} Created token record (without the token itself)
   */
  async create({ tokenHash, reason, expiresAt, singleUse = true }) {
    const res = await query(
      `INSERT INTO emergency_access_tokens (token_hash, reason, expires_at, single_use)
       VALUES ($1, $2, $3, $4)
       RETURNING id, created_at, expires_at`,
      [tokenHash, reason, expiresAt, singleUse],
    );
    return res.rows[0];
  },

  /**
   * Validate an emergency access token
   * @param {string} tokenHash - SHA-256 hash of the provided token
   * @returns {Promise<Object|null>} Token record if valid, null otherwise
   */
  async validate(tokenHash) {
    const res = await query(
      `SELECT * FROM emergency_access_tokens
       WHERE token_hash = $1
         AND expires_at > NOW()
         AND (single_use = false OR used_at IS NULL)`,
      [tokenHash],
    );
    return res.rows[0] || null;
  },

  /**
   * Mark an emergency token as used
   * @param {string} id - Token record ID
   * @param {string} ip - IP address that used the token
   */
  async markUsed(id, ip) {
    await query(
      `UPDATE emergency_access_tokens
       SET used_at = NOW(), used_by_ip = $2
       WHERE id = $1`,
      [id, ip],
    );
  },

  /**
   * List all emergency tokens (for admin review)
   * @param {boolean} [includeUsed=false] - Include used tokens
   * @returns {Promise<Array>}
   */
  async list(includeUsed = false) {
    const whereClause = includeUsed ? "" : "WHERE used_at IS NULL";
    const res = await query(
      `SELECT id, reason, created_at, expires_at, used_at, used_by_ip, single_use
       FROM emergency_access_tokens
       ${whereClause}
       ORDER BY created_at DESC`,
    );
    return res.rows;
  },

  /**
   * Revoke an emergency token (delete it)
   * @param {string} id
   * @returns {Promise<boolean>} True if token was deleted
   */
  async revoke(id) {
    const res = await query(`DELETE FROM emergency_access_tokens WHERE id = $1 RETURNING id`, [id]);
    return res.rowCount > 0;
  },

  /**
   * Clean up expired tokens
   * @returns {Promise<number>} Number of deleted records
   */
  async cleanup() {
    const res = await query(
      `DELETE FROM emergency_access_tokens
       WHERE expires_at < NOW()
       RETURNING id`,
    );
    return res.rowCount;
  },
};

// ============================================================
// ADMIN SESSION TRACKING
// ============================================================

export const adminSessions = {
  /**
   * Update session activity timestamp
   * @param {string} sessionId - Session ID
   * @param {string} ipAddress - Current IP address
   */
  async updateActivity(sessionId, ipAddress) {
    await query(
      `UPDATE sessions
       SET last_activity_at = NOW(), last_ip = $2
       WHERE id = $1`,
      [sessionId, ipAddress],
    );
  },

  /**
   * Check if session has timed out due to inactivity
   * @param {string} sessionId - Session ID
   * @param {number} inactivityTimeoutMs - Inactivity timeout in milliseconds
   * @returns {Promise<boolean>} True if session is still active
   */
  async isActive(sessionId, inactivityTimeoutMs) {
    const res = await query(`SELECT last_activity_at FROM sessions WHERE id = $1`, [sessionId]);

    if (!res.rows[0]) return false;

    const lastActivity = res.rows[0].last_activity_at;
    if (!lastActivity) return true; // No activity tracked yet, consider active

    const inactiveTime = Date.now() - new Date(lastActivity).getTime();
    return inactiveTime < inactivityTimeoutMs;
  },
};

// ============================================================
// CONVENIENCE FUNCTIONS
// ============================================================

/**
 * Get all IP allowlist entries (wrapper for adminIpAllowlist.list)
 * @returns {Promise<Array>}
 */
export async function getIpAllowlist() {
  return adminIpAllowlist.list();
}

/**
 * Add IP to allowlist (wrapper for adminIpAllowlist.add)
 * @param {string} cidr - CIDR notation
 * @param {string} description - Description
 * @param {string} addedBy - User ID
 * @returns {Promise<Object>}
 */
export async function addIpToAllowlist(cidr, description, addedBy) {
  return adminIpAllowlist.add({
    ipRange: cidr,
    description,
    createdBy: addedBy,
  });
}

/**
 * Remove IP from allowlist (wrapper for adminIpAllowlist.remove)
 * @param {string} id - Entry ID
 * @returns {Promise<Object|null>}
 */
export async function removeFromAllowlist(id) {
  return adminIpAllowlist.remove(id);
}

/**
 * Check if IP is allowed (wrapper for adminIpAllowlist.isIpAllowed)
 * @param {string} ip - IP address
 * @returns {Promise<boolean>}
 */
export async function isIpAllowed(ip) {
  return adminIpAllowlist.isIpAllowed(ip);
}

// ============================================================
// DEFAULT EXPORT
// ============================================================

export default {
  adminIpAllowlist,
  adminSecuritySettings,
  adminActionConfirmations,
  emergencyAccessTokens,
  adminSessions,
  // Convenience functions
  getIpAllowlist,
  addIpToAllowlist,
  removeFromAllowlist,
  isIpAllowed,
};
