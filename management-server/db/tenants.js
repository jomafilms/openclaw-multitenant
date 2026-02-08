// Tenant model and database operations
// Multi-tenant SaaS - Wave 1 Foundation (Task 1.2)
import { query } from "./core.js";

// Tenants table operations
export const tenants = {
  /**
   * Create a new tenant
   * @param {string} name - Display name for the tenant
   * @param {string} slug - URL-friendly unique identifier
   * @param {string} ownerId - UUID of the owner user
   * @param {object} settings - Optional JSONB settings
   * @returns {Promise<object>} Created tenant record
   */
  async create(name, slug, ownerId, settings = {}) {
    const res = await query(
      `INSERT INTO tenants (name, slug, owner_id, settings)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [name, slug, ownerId, JSON.stringify(settings)],
    );
    return res.rows[0];
  },

  /**
   * Find tenant by UUID
   * @param {string} id - Tenant UUID
   * @returns {Promise<object|undefined>} Tenant record or undefined
   */
  async findById(id) {
    const res = await query("SELECT * FROM tenants WHERE id = $1", [id]);
    return res.rows[0];
  },

  /**
   * Find tenant by slug
   * @param {string} slug - Tenant slug
   * @returns {Promise<object|undefined>} Tenant record or undefined
   */
  async findBySlug(slug) {
    const res = await query("SELECT * FROM tenants WHERE slug = $1", [slug]);
    return res.rows[0];
  },

  /**
   * Find all tenants owned by a user
   * @param {string} ownerId - Owner user UUID
   * @returns {Promise<object[]>} Array of tenant records
   */
  async findByOwnerId(ownerId) {
    const res = await query(`SELECT * FROM tenants WHERE owner_id = $1 ORDER BY created_at DESC`, [
      ownerId,
    ]);
    return res.rows;
  },

  /**
   * Update tenant properties
   * @param {string} id - Tenant UUID
   * @param {object} updates - Fields to update (name, slug, owner_id, settings, status)
   * @returns {Promise<object|undefined>} Updated tenant record
   */
  async update(id, updates) {
    const { name, slug, ownerId, settings, status } = updates;
    const res = await query(
      `UPDATE tenants SET
         name = COALESCE($2, name),
         slug = COALESCE($3, slug),
         owner_id = COALESCE($4, owner_id),
         settings = COALESCE($5, settings),
         status = COALESCE($6, status),
         updated_at = NOW()
       WHERE id = $1
       RETURNING *`,
      [id, name, slug, ownerId, settings ? JSON.stringify(settings) : null, status],
    );
    return res.rows[0];
  },

  /**
   * Soft delete tenant by setting status to 'deleted'
   * @param {string} id - Tenant UUID
   * @returns {Promise<object|undefined>} Updated tenant record
   */
  async delete(id) {
    const res = await query(
      `UPDATE tenants SET status = 'deleted', updated_at = NOW()
       WHERE id = $1
       RETURNING *`,
      [id],
    );
    return res.rows[0];
  },

  /**
   * Update tenant settings (merge with existing)
   * @param {string} tenantId - Tenant UUID
   * @param {object} settings - Settings to merge
   * @returns {Promise<object>} Updated settings
   */
  async updateSettings(tenantId, settings) {
    const res = await query(
      `UPDATE tenants
       SET settings = COALESCE(settings, '{}'::jsonb) || $2::jsonb,
           updated_at = NOW()
       WHERE id = $1
       RETURNING settings`,
      [tenantId, JSON.stringify(settings)],
    );
    return res.rows[0]?.settings || {};
  },

  /**
   * Set tenant status
   * @param {string} tenantId - Tenant UUID
   * @param {string} status - New status (active, suspended, deleted)
   * @returns {Promise<object|undefined>} Updated tenant record
   */
  async setStatus(tenantId, status) {
    const res = await query(
      `UPDATE tenants SET status = $2, updated_at = NOW()
       WHERE id = $1
       RETURNING *`,
      [tenantId, status],
    );
    return res.rows[0];
  },

  /**
   * List tenants with optional filters
   * @param {object} options - Filter options
   * @param {string} options.status - Filter by status
   * @param {number} options.limit - Max results (default 50)
   * @param {number} options.offset - Offset for pagination (default 0)
   * @returns {Promise<object[]>} Array of tenant records
   */
  async list({ status, limit = 50, offset = 0 } = {}) {
    let sql = "SELECT * FROM tenants";
    const params = [];
    let paramIndex = 1;

    if (status) {
      sql += ` WHERE status = $${paramIndex}`;
      params.push(status);
      paramIndex++;
    }

    sql += " ORDER BY created_at DESC";
    sql += ` LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
    params.push(limit, offset);

    const res = await query(sql, params);
    return res.rows;
  },

  /**
   * Count total tenants (optionally filtered by status)
   * @param {string} status - Optional status filter
   * @returns {Promise<number>} Count of tenants
   */
  async count(status) {
    let sql = "SELECT COUNT(*) FROM tenants";
    const params = [];

    if (status) {
      sql += " WHERE status = $1";
      params.push(status);
    }

    const res = await query(sql, params);
    return parseInt(res.rows[0].count, 10);
  },
};

// Tenant membership operations
// Links users to tenants via tenant_id column on users table
export const tenantMemberships = {
  /**
   * Get all members of a tenant
   * @param {string} tenantId - Tenant UUID
   * @returns {Promise<object[]>} Array of user records in the tenant
   */
  async getMembers(tenantId) {
    const res = await query(
      `SELECT u.id, u.name, u.email, u.status, u.created_at, u.updated_at
       FROM users u
       WHERE u.tenant_id = $1
       ORDER BY u.name`,
      [tenantId],
    );
    return res.rows;
  },

  /**
   * Add a user to a tenant
   * @param {string} tenantId - Tenant UUID
   * @param {string} userId - User UUID
   * @returns {Promise<object|undefined>} Updated user record
   */
  async addMember(tenantId, userId) {
    const res = await query(
      `UPDATE users SET tenant_id = $1, updated_at = NOW()
       WHERE id = $2
       RETURNING *`,
      [tenantId, userId],
    );
    return res.rows[0];
  },

  /**
   * Remove a user from a tenant (sets tenant_id to NULL)
   * @param {string} tenantId - Tenant UUID (for verification)
   * @param {string} userId - User UUID
   * @returns {Promise<object|undefined>} Updated user record
   */
  async removeMember(tenantId, userId) {
    const res = await query(
      `UPDATE users SET tenant_id = NULL, updated_at = NOW()
       WHERE id = $1 AND tenant_id = $2
       RETURNING *`,
      [userId, tenantId],
    );
    return res.rows[0];
  },

  /**
   * Get count of members in a tenant
   * @param {string} tenantId - Tenant UUID
   * @returns {Promise<number>} Count of members
   */
  async getMemberCount(tenantId) {
    const res = await query("SELECT COUNT(*) FROM users WHERE tenant_id = $1", [tenantId]);
    return parseInt(res.rows[0].count, 10);
  },

  /**
   * Check if a user is a member of a tenant
   * @param {string} tenantId - Tenant UUID
   * @param {string} userId - User UUID
   * @returns {Promise<boolean>} True if user is a member
   */
  async isMember(tenantId, userId) {
    const res = await query("SELECT 1 FROM users WHERE id = $1 AND tenant_id = $2", [
      userId,
      tenantId,
    ]);
    return res.rows.length > 0;
  },

  /**
   * Get the tenant a user belongs to
   * @param {string} userId - User UUID
   * @returns {Promise<object|undefined>} Tenant record or undefined
   */
  async getTenantForUser(userId) {
    const res = await query(
      `SELECT t.* FROM tenants t
       JOIN users u ON u.tenant_id = t.id
       WHERE u.id = $1`,
      [userId],
    );
    return res.rows[0];
  },

  /**
   * Check if a user is the owner of a tenant
   * @param {string} tenantId - Tenant UUID
   * @param {string} userId - User UUID
   * @returns {Promise<boolean>} True if user is the owner
   */
  async isOwner(tenantId, userId) {
    const res = await query("SELECT 1 FROM tenants WHERE id = $1 AND owner_id = $2", [
      tenantId,
      userId,
    ]);
    return res.rows.length > 0;
  },
};
