// Groups (formerly organizations) and group memberships/resources
import { query, encrypt, decrypt } from "./core.js";

// Groups (renamed from organizations)
export const groups = {
  async create({ name, slug, description }) {
    const res = await query(
      `INSERT INTO groups (name, slug, description)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [name, slug, description],
    );
    return res.rows[0];
  },

  async findById(id) {
    const res = await query("SELECT * FROM groups WHERE id = $1", [id]);
    return res.rows[0];
  },

  async findBySlug(slug) {
    const res = await query("SELECT * FROM groups WHERE slug = $1", [slug]);
    return res.rows[0];
  },

  async update(id, { name, description }) {
    const res = await query(
      `UPDATE groups SET name = COALESCE($2, name), description = COALESCE($3, description), updated_at = NOW()
       WHERE id = $1 RETURNING *`,
      [id, name, description],
    );
    return res.rows[0];
  },

  async delete(id) {
    await query("DELETE FROM groups WHERE id = $1", [id]);
  },

  async list() {
    const res = await query("SELECT * FROM groups ORDER BY name");
    return res.rows;
  },
};

// Group memberships (renamed from org_memberships)
export const groupMemberships = {
  async add(userId, groupId, role = "member") {
    const res = await query(
      `INSERT INTO group_memberships (user_id, group_id, role)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id, group_id) DO UPDATE SET role = $3
       RETURNING *`,
      [userId, groupId, role],
    );
    return res.rows[0];
  },

  async remove(userId, groupId) {
    await query("DELETE FROM group_memberships WHERE user_id = $1 AND group_id = $2", [
      userId,
      groupId,
    ]);
  },

  async findByUserAndGroup(userId, groupId) {
    const res = await query(
      "SELECT * FROM group_memberships WHERE user_id = $1 AND group_id = $2",
      [userId, groupId],
    );
    return res.rows[0];
  },

  async listByUser(userId) {
    const res = await query(
      `SELECT gm.*, g.name as group_name, g.slug as group_slug
       FROM group_memberships gm
       JOIN groups g ON gm.group_id = g.id
       WHERE gm.user_id = $1
       ORDER BY g.name`,
      [userId],
    );
    return res.rows;
  },

  async listByGroup(groupId) {
    const res = await query(
      `SELECT gm.*, u.name as user_name, u.email as user_email
       FROM group_memberships gm
       JOIN users u ON gm.user_id = u.id
       WHERE gm.group_id = $1
       ORDER BY u.name`,
      [groupId],
    );
    return res.rows;
  },

  async isAdmin(userId, groupId) {
    const res = await query(
      "SELECT 1 FROM group_memberships WHERE user_id = $1 AND group_id = $2 AND role = 'admin'",
      [userId, groupId],
    );
    return res.rows.length > 0;
  },

  async isMember(userId, groupId) {
    const res = await query(
      "SELECT 1 FROM group_memberships WHERE user_id = $1 AND group_id = $2",
      [userId, groupId],
    );
    return res.rows.length > 0;
  },
};

// Group resources (renamed from org_resources)
export const groupResources = {
  async create({ groupId, name, description, resourceType, endpoint, authConfig, metadata }) {
    const res = await query(
      `INSERT INTO group_resources (group_id, name, description, resource_type, endpoint, auth_config_encrypted, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [
        groupId,
        name,
        description,
        resourceType || "mcp_server",
        endpoint,
        authConfig ? encrypt(JSON.stringify(authConfig)) : null,
        metadata ? JSON.stringify(metadata) : "{}",
      ],
    );
    return res.rows[0];
  },

  async findById(id) {
    const res = await query("SELECT * FROM group_resources WHERE id = $1", [id]);
    return res.rows[0];
  },

  async update(id, { name, description, endpoint, authConfig, metadata, status }) {
    const res = await query(
      `UPDATE group_resources SET
         name = COALESCE($2, name),
         description = COALESCE($3, description),
         endpoint = COALESCE($4, endpoint),
         auth_config_encrypted = COALESCE($5, auth_config_encrypted),
         metadata = COALESCE($6, metadata),
         status = COALESCE($7, status),
         updated_at = NOW()
       WHERE id = $1 RETURNING *`,
      [
        id,
        name,
        description,
        endpoint,
        authConfig ? encrypt(JSON.stringify(authConfig)) : null,
        metadata ? JSON.stringify(metadata) : null,
        status,
      ],
    );
    return res.rows[0];
  },

  async delete(id) {
    await query("DELETE FROM group_resources WHERE id = $1", [id]);
  },

  async listByGroup(groupId) {
    const res = await query(
      `SELECT r.*,
         (SELECT COUNT(*) FROM shares s WHERE s.resource_id = r.id AND s.status != 'revoked') as share_count,
         (SELECT COUNT(*) FROM shares s WHERE s.resource_id = r.id AND s.status = 'connected') as connected_count
       FROM group_resources r
       WHERE r.group_id = $1 AND r.status = 'active'
       ORDER BY r.name`,
      [groupId],
    );
    return res.rows;
  },

  async getDecryptedAuthConfig(id) {
    const res = await query("SELECT auth_config_encrypted FROM group_resources WHERE id = $1", [
      id,
    ]);
    if (!res.rows[0] || !res.rows[0].auth_config_encrypted) return null;
    return JSON.parse(decrypt(res.rows[0].auth_config_encrypted));
  },
};
