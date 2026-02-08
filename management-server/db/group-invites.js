// Group invites (formerly org_invites) - consent-based membership
// States: pending, accepted, declined, expired, cancelled
import crypto from "crypto";
import { query } from "./core.js";

const INVITE_EXPIRATION_DAYS = 7;

export const groupInvites = {
  async create({ groupId, inviterId, inviteeEmail, inviteeId, role }) {
    // Generate secure random token
    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + INVITE_EXPIRATION_DAYS * 24 * 60 * 60 * 1000);

    // First check for existing pending invite
    const existing = await query(
      `SELECT id FROM group_invites WHERE group_id = $1 AND invitee_email = $2 AND status = 'pending'`,
      [groupId, inviteeEmail.toLowerCase()],
    );

    if (existing.rows.length > 0) {
      // Update existing pending invite with new token and expiration
      const res = await query(
        `UPDATE group_invites SET
           inviter_id = $2,
           invitee_id = COALESCE($3, invitee_id),
           role = $4,
           token = $5,
           expires_at = $6,
           created_at = NOW()
         WHERE id = $1
         RETURNING *`,
        [existing.rows[0].id, inviterId, inviteeId, role || "member", token, expiresAt],
      );
      return res.rows[0];
    }

    // Create new invite
    const res = await query(
      `INSERT INTO group_invites (group_id, inviter_id, invitee_email, invitee_id, role, status, token, expires_at)
       VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7)
       RETURNING *`,
      [
        groupId,
        inviterId,
        inviteeEmail.toLowerCase(),
        inviteeId,
        role || "member",
        token,
        expiresAt,
      ],
    );
    return res.rows[0];
  },

  async findById(id) {
    const res = await query(
      `SELECT i.*, g.name as group_name, g.slug as group_slug,
              inviter.name as inviter_name, inviter.email as inviter_email
       FROM group_invites i
       JOIN groups g ON i.group_id = g.id
       JOIN users inviter ON i.inviter_id = inviter.id
       WHERE i.id = $1`,
      [id],
    );
    return res.rows[0];
  },

  async findByToken(token) {
    const res = await query(
      `SELECT i.*, g.name as group_name, g.slug as group_slug,
              inviter.name as inviter_name, inviter.email as inviter_email
       FROM group_invites i
       JOIN groups g ON i.group_id = g.id
       JOIN users inviter ON i.inviter_id = inviter.id
       WHERE i.token = $1`,
      [token],
    );
    return res.rows[0];
  },

  async findPendingByGroupAndEmail(groupId, email) {
    const res = await query(
      `SELECT * FROM group_invites
       WHERE group_id = $1 AND invitee_email = $2 AND status = 'pending'
         AND (expires_at IS NULL OR expires_at > NOW())`,
      [groupId, email.toLowerCase()],
    );
    return res.rows[0];
  },

  async listPendingForUser(userId) {
    // Find invites by user ID or by email (for users who signed up after invite)
    // Only return non-expired invites
    const res = await query(
      `SELECT i.*, g.name as group_name, g.slug as group_slug,
              inviter.name as inviter_name, inviter.email as inviter_email
       FROM group_invites i
       JOIN groups g ON i.group_id = g.id
       JOIN users inviter ON i.inviter_id = inviter.id
       WHERE i.status = 'pending'
         AND (i.expires_at IS NULL OR i.expires_at > NOW())
         AND (i.invitee_id = $1 OR i.invitee_email = (SELECT email FROM users WHERE id = $1))
       ORDER BY i.created_at DESC`,
      [userId],
    );
    return res.rows;
  },

  async listByGroup(groupId) {
    const res = await query(
      `SELECT i.*, inviter.name as inviter_name, inviter.email as inviter_email
       FROM group_invites i
       JOIN users inviter ON i.inviter_id = inviter.id
       WHERE i.group_id = $1
       ORDER BY i.created_at DESC`,
      [groupId],
    );
    return res.rows;
  },

  async accept(id, userId) {
    // Only accept if still pending and not expired
    const res = await query(
      `UPDATE group_invites
       SET status = 'accepted', invitee_id = $2, decided_at = NOW()
       WHERE id = $1 AND status = 'pending'
         AND (expires_at IS NULL OR expires_at > NOW())
       RETURNING *`,
      [id, userId],
    );
    return res.rows[0];
  },

  async decline(id, userId) {
    const res = await query(
      `UPDATE group_invites
       SET status = 'declined', invitee_id = $2, decided_at = NOW()
       WHERE id = $1 AND status = 'pending'
       RETURNING *`,
      [id, userId],
    );
    return res.rows[0];
  },

  async cancel(id) {
    const res = await query(
      `UPDATE group_invites
       SET status = 'cancelled', decided_at = NOW()
       WHERE id = $1 AND status = 'pending'
       RETURNING *`,
      [id],
    );
    return res.rows[0];
  },

  async delete(id) {
    await query("DELETE FROM group_invites WHERE id = $1", [id]);
  },

  // Expire old pending invites
  async expireOld() {
    const res = await query(
      `UPDATE group_invites
       SET status = 'expired', decided_at = NOW()
       WHERE status = 'pending' AND expires_at < NOW()
       RETURNING *`,
    );
    return res.rows;
  },

  // Check if invite is still valid (pending and not expired)
  isValid(invite) {
    if (!invite) return false;
    if (invite.status !== "pending") return false;
    if (invite.expires_at && new Date(invite.expires_at) < new Date()) return false;
    return true;
  },
};
