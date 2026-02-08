// API Keys for multi-tenant authentication
// Keys are stored hashed (SHA-256); only the prefix is visible for identification
import crypto from "crypto";
import { query } from "./core.js";

// Key format: opw_live_ + 32 random hex chars (total 40 chars)
const KEY_PREFIX = "opw_live_";
const KEY_RANDOM_BYTES = 16; // 16 bytes = 32 hex chars

// Scope hierarchy: admin > write > read
// '*' grants all scopes
const SCOPE_HIERARCHY = {
  read: ["read"],
  write: ["read", "write"],
  admin: ["read", "write", "admin"],
  "*": ["read", "write", "admin", "*"],
};

/**
 * Generate a secure API key
 * @returns {{ rawKey: string, keyHash: string, keyPrefix: string }}
 */
function generateKey() {
  const randomPart = crypto.randomBytes(KEY_RANDOM_BYTES).toString("hex");
  const rawKey = `${KEY_PREFIX}${randomPart}`;
  const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");
  const keyPrefix = rawKey.slice(0, 12); // "opw_live_xxx"

  return { rawKey, keyHash, keyPrefix };
}

/**
 * Hash a raw API key for lookup
 * @param {string} rawKey - The raw API key
 * @returns {string} SHA-256 hash of the key
 */
function hashKey(rawKey) {
  return crypto.createHash("sha256").update(rawKey).digest("hex");
}

export const apiKeys = {
  /**
   * Create a new API key for a tenant
   * Returns the raw key only once - it cannot be retrieved after creation
   * @param {string} tenantId - UUID of the tenant
   * @param {string} userId - UUID of the user creating the key
   * @param {string} name - Human-readable name for the key
   * @param {string[]} scopes - Array of scopes (default: ['read'])
   * @param {Date|null} expiresAt - Expiration date or null for no expiration
   * @returns {Promise<{ key: object, rawKey: string }>}
   */
  async create(tenantId, userId, name, scopes = ["read"], expiresAt = null) {
    const { rawKey, keyHash, keyPrefix } = generateKey();

    const res = await query(
      `INSERT INTO api_keys (tenant_id, user_id, name, key_hash, key_prefix, scopes, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, tenant_id, user_id, name, key_prefix, scopes, expires_at, created_at`,
      [tenantId, userId, name, keyHash, keyPrefix, JSON.stringify(scopes), expiresAt],
    );

    return {
      key: res.rows[0],
      rawKey, // Only returned at creation time
    };
  },

  /**
   * Find an API key by its UUID
   * @param {string} id - UUID of the key
   * @returns {Promise<object|undefined>}
   */
  async findById(id) {
    const res = await query(
      `SELECT id, tenant_id, user_id, name, key_prefix, scopes, rate_limit_override,
              last_used_at, expires_at, revoked_at, created_at
       FROM api_keys
       WHERE id = $1`,
      [id],
    );
    return res.rows[0];
  },

  /**
   * Find all API keys for a tenant
   * @param {string} tenantId - UUID of the tenant
   * @returns {Promise<object[]>}
   */
  async findByTenantId(tenantId) {
    const res = await query(
      `SELECT id, tenant_id, user_id, name, key_prefix, scopes, rate_limit_override,
              last_used_at, expires_at, revoked_at, created_at
       FROM api_keys
       WHERE tenant_id = $1
       ORDER BY created_at DESC`,
      [tenantId],
    );
    return res.rows;
  },

  /**
   * Find all API keys created by a user
   * @param {string} userId - UUID of the user
   * @returns {Promise<object[]>}
   */
  async findByUserId(userId) {
    const res = await query(
      `SELECT id, tenant_id, user_id, name, key_prefix, scopes, rate_limit_override,
              last_used_at, expires_at, revoked_at, created_at
       FROM api_keys
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [userId],
    );
    return res.rows;
  },

  /**
   * Revoke an API key (soft delete - sets revoked_at)
   * @param {string} id - UUID of the key
   * @returns {Promise<object|undefined>}
   */
  async revoke(id) {
    const res = await query(
      `UPDATE api_keys
       SET revoked_at = NOW()
       WHERE id = $1 AND revoked_at IS NULL
       RETURNING *`,
      [id],
    );
    return res.rows[0];
  },

  /**
   * Hard delete an API key
   * @param {string} id - UUID of the key
   * @returns {Promise<boolean>} True if a key was deleted
   */
  async delete(id) {
    const res = await query("DELETE FROM api_keys WHERE id = $1", [id]);
    return res.rowCount > 0;
  },

  /**
   * Validate an API key
   * Checks: exists, not expired, not revoked
   * Updates last_used_at on successful validation
   * @param {string} rawKey - The raw API key to validate
   * @returns {Promise<object|null>} Key data with tenant info, or null if invalid
   */
  async validateKey(rawKey) {
    // Check format
    if (!rawKey || !rawKey.startsWith(KEY_PREFIX)) {
      return null;
    }

    const keyHash = hashKey(rawKey);

    // Look up key and join with tenant
    const res = await query(
      `SELECT ak.id, ak.tenant_id, ak.user_id, ak.name, ak.key_prefix, ak.scopes,
              ak.rate_limit_override, ak.last_used_at, ak.expires_at, ak.revoked_at, ak.created_at,
              t.id as "tenant.id", t.name as "tenant.name", t.slug as "tenant.slug",
              t.status as "tenant.status", t.settings as "tenant.settings"
       FROM api_keys ak
       JOIN tenants t ON ak.tenant_id = t.id
       WHERE ak.key_hash = $1`,
      [keyHash],
    );

    const row = res.rows[0];
    if (!row) {
      return null;
    }

    // Check if revoked
    if (row.revoked_at) {
      return null;
    }

    // Check if expired
    if (row.expires_at && new Date(row.expires_at) < new Date()) {
      return null;
    }

    // Check if tenant is active
    if (row["tenant.status"] !== "active") {
      return null;
    }

    // Update last_used_at (fire and forget for performance)
    query("UPDATE api_keys SET last_used_at = NOW() WHERE id = $1", [row.id]).catch(() => {
      // Ignore errors updating last_used_at
    });

    // Structure the response
    return {
      id: row.id,
      tenantId: row.tenant_id,
      userId: row.user_id,
      name: row.name,
      keyPrefix: row.key_prefix,
      scopes: row.scopes,
      rateLimitOverride: row.rate_limit_override,
      lastUsedAt: row.last_used_at,
      expiresAt: row.expires_at,
      createdAt: row.created_at,
      tenant: {
        id: row["tenant.id"],
        name: row["tenant.name"],
        slug: row["tenant.slug"],
        status: row["tenant.status"],
        settings: row["tenant.settings"],
      },
    };
  },

  /**
   * Check if a key has the required scope
   * Scope hierarchy: admin > write > read
   * '*' grants all scopes
   * @param {object} keyData - Key data from validateKey
   * @param {string} requiredScope - The scope to check for
   * @returns {boolean}
   */
  checkScope(keyData, requiredScope) {
    if (!keyData || !keyData.scopes) {
      return false;
    }

    const scopes = Array.isArray(keyData.scopes) ? keyData.scopes : [];

    // Check for wildcard scope
    if (scopes.includes("*")) {
      return true;
    }

    // Check each scope the key has and see if it grants the required scope
    for (const scope of scopes) {
      const grantedScopes = SCOPE_HIERARCHY[scope] || [scope];
      if (grantedScopes.includes(requiredScope)) {
        return true;
      }
    }

    return false;
  },

  /**
   * Update rate limit override for a key
   * @param {string} id - UUID of the key
   * @param {number|null} rateLimitOverride - Custom rate limit or null for default
   * @returns {Promise<object|undefined>}
   */
  async updateRateLimit(id, rateLimitOverride) {
    const res = await query(
      `UPDATE api_keys
       SET rate_limit_override = $2
       WHERE id = $1
       RETURNING *`,
      [id, rateLimitOverride],
    );
    return res.rows[0];
  },

  /**
   * List all active (non-revoked, non-expired) keys for a tenant
   * @param {string} tenantId - UUID of the tenant
   * @returns {Promise<object[]>}
   */
  async listActiveByTenantId(tenantId) {
    const res = await query(
      `SELECT id, tenant_id, user_id, name, key_prefix, scopes, rate_limit_override,
              last_used_at, expires_at, created_at
       FROM api_keys
       WHERE tenant_id = $1
         AND revoked_at IS NULL
         AND (expires_at IS NULL OR expires_at > NOW())
       ORDER BY created_at DESC`,
      [tenantId],
    );
    return res.rows;
  },

  /**
   * Count active keys for a tenant (for quota enforcement)
   * @param {string} tenantId - UUID of the tenant
   * @returns {Promise<number>}
   */
  async countActiveByTenantId(tenantId) {
    const res = await query(
      `SELECT COUNT(*) as count
       FROM api_keys
       WHERE tenant_id = $1
         AND revoked_at IS NULL
         AND (expires_at IS NULL OR expires_at > NOW())`,
      [tenantId],
    );
    return parseInt(res.rows[0].count, 10);
  },
};
