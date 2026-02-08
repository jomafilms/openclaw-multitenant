// Capability approvals (human-in-the-loop for sensitive agent operations)
import crypto from "crypto";
import { query } from "./core.js";

export const capabilityApprovals = {
  async create({
    userId,
    operationType,
    subjectPublicKey,
    subjectEmail,
    resource,
    scope,
    expiresInSeconds,
    maxCalls,
    reason,
    agentContext,
  }) {
    // Generate a unique token for approval via push notification or magic link
    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hour expiry for the approval request

    const res = await query(
      `INSERT INTO capability_approvals
       (user_id, operation_type, subject_public_key, subject_email, resource, scope, expires_in_seconds, max_calls, reason, agent_context, token, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
       RETURNING *`,
      [
        userId,
        operationType,
        subjectPublicKey,
        subjectEmail,
        resource,
        scope,
        expiresInSeconds,
        maxCalls,
        reason,
        agentContext ? JSON.stringify(agentContext) : "{}",
        token,
        expiresAt,
      ],
    );
    return res.rows[0];
  },

  async findById(id) {
    const res = await query(
      `SELECT ca.*, u.name as user_name, u.email as user_email
       FROM capability_approvals ca
       JOIN users u ON ca.user_id = u.id
       WHERE ca.id = $1`,
      [id],
    );
    return res.rows[0];
  },

  async findByToken(token) {
    const res = await query(
      `SELECT ca.*, u.name as user_name, u.email as user_email
       FROM capability_approvals ca
       JOIN users u ON ca.user_id = u.id
       WHERE ca.token = $1 AND ca.expires_at > NOW()`,
      [token],
    );
    return res.rows[0];
  },

  async findPendingByUserAndSubject(userId, subjectPublicKey, resource) {
    const res = await query(
      `SELECT * FROM capability_approvals
       WHERE user_id = $1
         AND subject_public_key = $2
         AND resource = $3
         AND status = 'pending'
         AND expires_at > NOW()`,
      [userId, subjectPublicKey, resource],
    );
    return res.rows[0];
  },

  async listPendingForUser(userId) {
    const res = await query(
      `SELECT * FROM capability_approvals
       WHERE user_id = $1 AND status = 'pending' AND expires_at > NOW()
       ORDER BY created_at DESC`,
      [userId],
    );
    return res.rows;
  },

  async listAllForUser(userId, limit = 50) {
    const res = await query(
      `SELECT * FROM capability_approvals
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT $2`,
      [userId, limit],
    );
    return res.rows;
  },

  async approve(id) {
    const res = await query(
      `UPDATE capability_approvals
       SET status = 'approved', decided_at = NOW()
       WHERE id = $1 AND status = 'pending'
       RETURNING *`,
      [id],
    );
    return res.rows[0];
  },

  async approveWithConstraints(id, constraints = {}) {
    // Build the update dynamically based on provided constraints
    const updates = ["status = 'approved'", "decided_at = NOW()"];
    const params = [id];
    let paramIndex = 2;

    if (constraints.expiresInSeconds !== undefined) {
      updates.push(`expires_in_seconds = $${paramIndex}`);
      params.push(constraints.expiresInSeconds);
      paramIndex++;
    }

    if (constraints.scope !== undefined) {
      updates.push(`scope = $${paramIndex}`);
      params.push(constraints.scope);
      paramIndex++;
    }

    if (constraints.maxCalls !== undefined) {
      updates.push(`max_calls = $${paramIndex}`);
      params.push(constraints.maxCalls);
      paramIndex++;
    }

    const res = await query(
      `UPDATE capability_approvals
       SET ${updates.join(", ")}
       WHERE id = $1 AND status = 'pending'
       RETURNING *`,
      params,
    );
    return res.rows[0];
  },

  async deny(id) {
    const res = await query(
      `UPDATE capability_approvals
       SET status = 'denied', decided_at = NOW()
       WHERE id = $1 AND status = 'pending'
       RETURNING *`,
      [id],
    );
    return res.rows[0];
  },

  async markIssued(id) {
    const res = await query(
      `UPDATE capability_approvals
       SET status = 'issued', decided_at = NOW()
       WHERE id = $1 AND status = 'approved'
       RETURNING *`,
      [id],
    );
    return res.rows[0];
  },

  async expireOld() {
    const res = await query(
      `UPDATE capability_approvals
       SET status = 'expired'
       WHERE status = 'pending' AND expires_at < NOW()
       RETURNING *`,
    );
    return res.rows;
  },

  async delete(id) {
    await query("DELETE FROM capability_approvals WHERE id = $1", [id]);
  },
};
