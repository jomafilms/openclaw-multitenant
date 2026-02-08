// Unified shares (formerly org_grants + peer_grants)
import { query } from "./core.js";
import {
  normalizePermissions,
  hasPermission,
  hasAnyPermission,
  hasAllPermissions,
  getRequiredPermissionForMethod,
} from "./permissions.js";

// Shares (renamed from org_grants, unified with peer grants concept)
export const shares = {
  // Export permission helpers
  normalizePermissions,
  hasPermission,
  hasAnyPermission,
  hasAllPermissions,
  getRequiredPermissionForMethod,

  async create({ groupId, resourceId, userId, permissions, grantedBy }) {
    const normalizedPermissions = normalizePermissions(permissions);
    const res = await query(
      `INSERT INTO shares (group_id, resource_id, user_id, permissions, granted_by)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (resource_id, user_id)
       DO UPDATE SET
         permissions = $4,
         status = 'granted',
         granted_by = $5,
         granted_at = NOW(),
         revoked_at = NULL
       RETURNING *`,
      [groupId, resourceId, userId, JSON.stringify(normalizedPermissions), grantedBy],
    );
    return res.rows[0];
  },

  async findById(id) {
    const res = await query("SELECT * FROM shares WHERE id = $1", [id]);
    return res.rows[0];
  },

  async findByResourceAndUser(resourceId, userId) {
    const res = await query("SELECT * FROM shares WHERE resource_id = $1 AND user_id = $2", [
      resourceId,
      userId,
    ]);
    return res.rows[0];
  },

  async updatePermissions(id, permissions) {
    const normalizedPermissions = normalizePermissions(permissions);
    const res = await query("UPDATE shares SET permissions = $2 WHERE id = $1 RETURNING *", [
      id,
      JSON.stringify(normalizedPermissions),
    ]);
    return res.rows[0];
  },

  async connect(id) {
    const res = await query(
      "UPDATE shares SET status = 'connected', connected_at = NOW() WHERE id = $1 RETURNING *",
      [id],
    );
    return res.rows[0];
  },

  async disconnect(id) {
    const res = await query(
      "UPDATE shares SET status = 'granted', connected_at = NULL WHERE id = $1 RETURNING *",
      [id],
    );
    return res.rows[0];
  },

  async revoke(id) {
    const res = await query(
      "UPDATE shares SET status = 'revoked', revoked_at = NOW() WHERE id = $1 RETURNING *",
      [id],
    );
    return res.rows[0];
  },

  async delete(id) {
    await query("DELETE FROM shares WHERE id = $1", [id]);
  },

  async listByGroup(groupId) {
    const res = await query(
      `SELECT s.*, r.name as resource_name, u.name as user_name, u.email as user_email
       FROM shares s
       JOIN group_resources r ON s.resource_id = r.id
       JOIN users u ON s.user_id = u.id
       WHERE s.group_id = $1 AND s.status != 'revoked'
       ORDER BY r.name, u.name`,
      [groupId],
    );
    return res.rows;
  },

  async listByResource(resourceId) {
    const res = await query(
      `SELECT s.*, u.name as user_name, u.email as user_email
       FROM shares s
       JOIN users u ON s.user_id = u.id
       WHERE s.resource_id = $1 AND s.status != 'revoked'
       ORDER BY u.name`,
      [resourceId],
    );
    return res.rows;
  },

  async listAvailableForUser(userId) {
    const res = await query(
      `SELECT s.*, r.name as resource_name, r.description as resource_description,
              r.resource_type, g.name as group_name, g.slug as group_slug
       FROM shares s
       JOIN group_resources r ON s.resource_id = r.id
       JOIN groups g ON s.group_id = g.id
       WHERE s.user_id = $1 AND s.status = 'granted' AND r.status = 'active'
       ORDER BY g.name, r.name`,
      [userId],
    );
    return res.rows;
  },

  async listConnectedForUser(userId) {
    const res = await query(
      `SELECT s.*, r.name as resource_name, r.description as resource_description,
              r.resource_type, r.endpoint, r.metadata as resource_metadata,
              g.name as group_name, g.slug as group_slug
       FROM shares s
       JOIN group_resources r ON s.resource_id = r.id
       JOIN groups g ON s.group_id = g.id
       WHERE s.user_id = $1 AND s.status = 'connected' AND r.status = 'active'
       ORDER BY g.name, r.name`,
      [userId],
    );
    return res.rows;
  },
};

// Peer grants (user-to-user sharing with approval handshake)
// Kept separate as it has different semantics (capability-based vs resource-based)
export const peerGrants = {
  async create({ grantorId, granteeId, capability, reason }) {
    const res = await query(
      `INSERT INTO peer_grants (grantor_id, grantee_id, capability, reason)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (grantor_id, grantee_id, capability)
       DO UPDATE SET
         status = 'pending',
         reason = $4,
         expires_at = NULL,
         decided_at = NULL,
         created_at = NOW()
       RETURNING *`,
      [grantorId, granteeId, capability, reason],
    );
    return res.rows[0];
  },

  async findById(id) {
    const res = await query(
      `SELECT pg.*,
              grantor.name as grantor_name, grantor.email as grantor_email,
              grantee.name as grantee_name, grantee.email as grantee_email
       FROM peer_grants pg
       JOIN users grantor ON pg.grantor_id = grantor.id
       JOIN users grantee ON pg.grantee_id = grantee.id
       WHERE pg.id = $1`,
      [id],
    );
    return res.rows[0];
  },

  async findByGrantorGranteeCapability(grantorId, granteeId, capability) {
    const res = await query(
      `SELECT * FROM peer_grants
       WHERE grantor_id = $1 AND grantee_id = $2 AND capability = $3`,
      [grantorId, granteeId, capability],
    );
    return res.rows[0];
  },

  async approve(id, expiresAt = null) {
    const res = await query(
      `UPDATE peer_grants
       SET status = 'approved', expires_at = $2, decided_at = NOW()
       WHERE id = $1
       RETURNING *`,
      [id, expiresAt],
    );
    return res.rows[0];
  },

  async deny(id) {
    const res = await query(
      `UPDATE peer_grants
       SET status = 'denied', decided_at = NOW()
       WHERE id = $1
       RETURNING *`,
      [id],
    );
    return res.rows[0];
  },

  async revoke(id) {
    const res = await query(
      `UPDATE peer_grants
       SET status = 'revoked', decided_at = NOW()
       WHERE id = $1
       RETURNING *`,
      [id],
    );
    return res.rows[0];
  },

  async delete(id) {
    await query("DELETE FROM peer_grants WHERE id = $1", [id]);
  },

  // Requests waiting for my approval (I am the grantor)
  async listIncomingRequests(userId) {
    const res = await query(
      `SELECT pg.*,
              grantee.name as grantee_name, grantee.email as grantee_email
       FROM peer_grants pg
       JOIN users grantee ON pg.grantee_id = grantee.id
       WHERE pg.grantor_id = $1 AND pg.status = 'pending'
       ORDER BY pg.created_at DESC`,
      [userId],
    );
    return res.rows;
  },

  // My requests to others (I am the grantee)
  async listOutgoingRequests(userId) {
    const res = await query(
      `SELECT pg.*,
              grantor.name as grantor_name, grantor.email as grantor_email
       FROM peer_grants pg
       JOIN users grantor ON pg.grantor_id = grantor.id
       WHERE pg.grantee_id = $1 AND pg.status = 'pending'
       ORDER BY pg.created_at DESC`,
      [userId],
    );
    return res.rows;
  },

  // What I can access (approved grants to me, not expired)
  async listGrantsToMe(userId) {
    const res = await query(
      `SELECT pg.*,
              grantor.name as grantor_name, grantor.email as grantor_email
       FROM peer_grants pg
       JOIN users grantor ON pg.grantor_id = grantor.id
       WHERE pg.grantee_id = $1
         AND pg.status = 'approved'
         AND (pg.expires_at IS NULL OR pg.expires_at > NOW())
       ORDER BY pg.created_at DESC`,
      [userId],
    );
    return res.rows;
  },

  // What I've shared (approved grants from me)
  async listGrantsFromMe(userId) {
    const res = await query(
      `SELECT pg.*,
              grantee.name as grantee_name, grantee.email as grantee_email
       FROM peer_grants pg
       JOIN users grantee ON pg.grantee_id = grantee.id
       WHERE pg.grantor_id = $1
         AND pg.status = 'approved'
         AND (pg.expires_at IS NULL OR pg.expires_at > NOW())
       ORDER BY pg.created_at DESC`,
      [userId],
    );
    return res.rows;
  },

  // Check if grantee has active access to grantor's capability
  async hasAccess(grantorId, granteeId, capability) {
    const res = await query(
      `SELECT 1 FROM peer_grants
       WHERE grantor_id = $1
         AND grantee_id = $2
         AND capability = $3
         AND status = 'approved'
         AND (expires_at IS NULL OR expires_at > NOW())`,
      [grantorId, granteeId, capability],
    );
    return res.rows.length > 0;
  },

  // Clean up expired grants (can be run periodically)
  async expireOldGrants() {
    const res = await query(
      `UPDATE peer_grants
       SET status = 'revoked'
       WHERE status = 'approved'
         AND expires_at IS NOT NULL
         AND expires_at < NOW()
       RETURNING *`,
    );
    return res.rows;
  },
};
