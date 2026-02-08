// Resource shares (peer-to-peer integration sharing)
import { query } from "./core.js";
import { normalizePermissions } from "./permissions.js";

export const resourceShares = {
  async create({
    integrationId,
    ownerId,
    recipientEmail,
    recipientId,
    tier,
    permissions,
    expiresAt,
  }) {
    const normalizedPermissions = normalizePermissions(permissions || ["read"]);
    const res = await query(
      `INSERT INTO resource_shares (integration_id, owner_id, recipient_email, recipient_id, tier, permissions, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (integration_id, recipient_email)
       DO UPDATE SET
         tier = $5,
         permissions = $6,
         expires_at = $7,
         status = 'pending',
         revoked_at = NULL,
         accepted_at = NULL
       RETURNING *`,
      [
        integrationId,
        ownerId,
        recipientEmail,
        recipientId,
        tier || "LIVE",
        JSON.stringify(normalizedPermissions),
        expiresAt,
      ],
    );
    return res.rows[0];
  },

  async findById(id) {
    const res = await query(
      `SELECT rs.*,
              i.provider as resource_type, i.provider_email as resource_name,
              o.name as owner_name, o.email as owner_email,
              r.name as recipient_name, r.email as recipient_email_user
       FROM resource_shares rs
       JOIN user_integrations i ON rs.integration_id = i.id
       JOIN users o ON rs.owner_id = o.id
       LEFT JOIN users r ON rs.recipient_id = r.id
       WHERE rs.id = $1`,
      [id],
    );
    return res.rows[0];
  },

  async findByIntegrationAndRecipient(integrationId, recipientEmail) {
    const res = await query(
      "SELECT * FROM resource_shares WHERE integration_id = $1 AND recipient_email = $2",
      [integrationId, recipientEmail],
    );
    return res.rows[0];
  },

  async accept(id) {
    const res = await query(
      `UPDATE resource_shares
       SET status = 'active', accepted_at = NOW()
       WHERE id = $1
       RETURNING *`,
      [id],
    );
    return res.rows[0];
  },

  async decline(id) {
    const res = await query(
      `UPDATE resource_shares
       SET status = 'declined', accepted_at = NOW()
       WHERE id = $1
       RETURNING *`,
      [id],
    );
    return res.rows[0];
  },

  async revoke(id) {
    const res = await query(
      `UPDATE resource_shares
       SET status = 'revoked', revoked_at = NOW()
       WHERE id = $1
       RETURNING *`,
      [id],
    );
    return res.rows[0];
  },

  async delete(id) {
    await query("DELETE FROM resource_shares WHERE id = $1", [id]);
  },

  // Shares I've created (outgoing)
  async listByOwner(ownerId) {
    const res = await query(
      `SELECT rs.*,
              i.provider as resource_type,
              COALESCE(i.provider_email, i.provider) as resource_name,
              r.name as recipient_name, r.email as recipient_email_user
       FROM resource_shares rs
       JOIN user_integrations i ON rs.integration_id = i.id
       LEFT JOIN users r ON rs.recipient_id = r.id
       WHERE rs.owner_id = $1 AND rs.status != 'revoked'
       ORDER BY rs.created_at DESC`,
      [ownerId],
    );
    return res.rows;
  },

  // Shares offered to me (incoming) - by email or by user ID
  async listByRecipient(userId, email) {
    const res = await query(
      `SELECT rs.*,
              i.provider as resource_type,
              COALESCE(i.provider_email, i.provider) as resource_name,
              o.name as owner_name, o.email as owner_email
       FROM resource_shares rs
       JOIN user_integrations i ON rs.integration_id = i.id
       JOIN users o ON rs.owner_id = o.id
       WHERE (rs.recipient_id = $1 OR rs.recipient_email = $2)
         AND rs.status != 'revoked'
         AND (rs.expires_at IS NULL OR rs.expires_at > NOW())
       ORDER BY rs.created_at DESC`,
      [userId, email],
    );
    return res.rows;
  },

  // Pending shares offered to me
  async listPendingByRecipient(userId, email) {
    const res = await query(
      `SELECT rs.*,
              i.provider as resource_type,
              COALESCE(i.provider_email, i.provider) as resource_name,
              o.name as owner_name, o.email as owner_email
       FROM resource_shares rs
       JOIN user_integrations i ON rs.integration_id = i.id
       JOIN users o ON rs.owner_id = o.id
       WHERE (rs.recipient_id = $1 OR rs.recipient_email = $2)
         AND rs.status = 'pending'
         AND (rs.expires_at IS NULL OR rs.expires_at > NOW())
       ORDER BY rs.created_at DESC`,
      [userId, email],
    );
    return res.rows;
  },

  // Active shares I've accepted
  async listActiveByRecipient(userId, email) {
    const res = await query(
      `SELECT rs.*,
              i.provider as resource_type,
              COALESCE(i.provider_email, i.provider) as resource_name,
              o.name as owner_name, o.email as owner_email
       FROM resource_shares rs
       JOIN user_integrations i ON rs.integration_id = i.id
       JOIN users o ON rs.owner_id = o.id
       WHERE (rs.recipient_id = $1 OR rs.recipient_email = $2)
         AND rs.status = 'active'
         AND (rs.expires_at IS NULL OR rs.expires_at > NOW())
       ORDER BY rs.created_at DESC`,
      [userId, email],
    );
    return res.rows;
  },

  // Update recipient_id when a user signs up with matching email
  async linkRecipient(email, userId) {
    const res = await query(
      `UPDATE resource_shares
       SET recipient_id = $2
       WHERE recipient_email = $1 AND recipient_id IS NULL
       RETURNING *`,
      [email, userId],
    );
    return res.rows;
  },
};
