// Group vault threshold unlock (renamed from org vault)
import { query } from "./core.js";

// Group unlock requests (renamed from orgUnlockRequests)
export const groupUnlockRequests = {
  async create({ groupId, requestedBy, reason, requiredApprovals, expiresAt }) {
    const res = await query(
      `INSERT INTO group_unlock_requests (group_id, requested_by, reason, required_approvals, expires_at)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [groupId, requestedBy, reason, requiredApprovals, expiresAt],
    );
    return res.rows[0];
  },

  async findById(id) {
    const res = await query(
      `SELECT r.*, g.name as group_name, g.slug as group_slug, u.name as requester_name, u.email as requester_email
       FROM group_unlock_requests r
       JOIN groups g ON r.group_id = g.id
       JOIN users u ON r.requested_by = u.id
       WHERE r.id = $1`,
      [id],
    );
    return res.rows[0];
  },

  async findPendingForGroup(groupId) {
    const res = await query(
      `SELECT r.*, u.name as requester_name, u.email as requester_email
       FROM group_unlock_requests r
       JOIN users u ON r.requested_by = u.id
       WHERE r.group_id = $1 AND r.status = 'pending' AND r.expires_at > NOW()
       ORDER BY r.created_at DESC`,
      [groupId],
    );
    return res.rows;
  },

  async findActiveForGroup(groupId) {
    const res = await query(
      `SELECT r.*, u.name as requester_name, u.email as requester_email
       FROM group_unlock_requests r
       JOIN users u ON r.requested_by = u.id
       WHERE r.group_id = $1 AND r.status = 'unlocked' AND r.expires_at > NOW()
       ORDER BY r.created_at DESC
       LIMIT 1`,
      [groupId],
    );
    return res.rows[0];
  },

  async getApprovals(requestId) {
    const res = await query(
      `SELECT a.*, u.name as approver_name, u.email as approver_email
       FROM group_unlock_approvals a
       JOIN users u ON a.approved_by = u.id
       WHERE a.request_id = $1
       ORDER BY a.approved_at`,
      [requestId],
    );
    return res.rows;
  },

  async countApprovals(requestId) {
    const res = await query(
      "SELECT COUNT(*) as count FROM group_unlock_approvals WHERE request_id = $1",
      [requestId],
    );
    return parseInt(res.rows[0].count, 10);
  },

  async addApproval(requestId, approvedBy) {
    const res = await query(
      `INSERT INTO group_unlock_approvals (request_id, approved_by)
       VALUES ($1, $2)
       ON CONFLICT (request_id, approved_by) DO NOTHING
       RETURNING *`,
      [requestId, approvedBy],
    );
    return res.rows[0];
  },

  async hasApproved(requestId, userId) {
    const res = await query(
      "SELECT 1 FROM group_unlock_approvals WHERE request_id = $1 AND approved_by = $2",
      [requestId, userId],
    );
    return res.rows.length > 0;
  },

  async unlock(id, sessionKeyEncrypted) {
    const res = await query(
      `UPDATE group_unlock_requests
       SET status = 'unlocked', session_key_encrypted = $2, unlocked_at = NOW()
       WHERE id = $1
       RETURNING *`,
      [id, sessionKeyEncrypted],
    );
    return res.rows[0];
  },

  async lock(id) {
    const res = await query(
      `UPDATE group_unlock_requests
       SET status = 'locked', locked_at = NOW()
       WHERE id = $1
       RETURNING *`,
      [id],
    );
    return res.rows[0];
  },

  async cancel(id) {
    const res = await query(
      `UPDATE group_unlock_requests
       SET status = 'cancelled'
       WHERE id = $1 AND status = 'pending'
       RETURNING *`,
      [id],
    );
    return res.rows[0];
  },

  async expireOld() {
    const res = await query(
      `UPDATE group_unlock_requests
       SET status = 'expired'
       WHERE status IN ('pending', 'unlocked') AND expires_at < NOW()
       RETURNING *`,
    );
    return res.rows;
  },

  async listForGroup(groupId, limit = 50) {
    const res = await query(
      `SELECT r.*, u.name as requester_name, u.email as requester_email,
              (SELECT COUNT(*) FROM group_unlock_approvals a WHERE a.request_id = r.id) as approval_count
       FROM group_unlock_requests r
       JOIN users u ON r.requested_by = u.id
       WHERE r.group_id = $1
       ORDER BY r.created_at DESC
       LIMIT $2`,
      [groupId, limit],
    );
    return res.rows;
  },
};

// Group threshold configuration (renamed from orgThreshold)
export const groupThreshold = {
  async get(groupId) {
    const res = await query("SELECT unlock_threshold, vault_config FROM groups WHERE id = $1", [
      groupId,
    ]);
    return res.rows[0];
  },

  async set(groupId, threshold) {
    const res = await query(
      `UPDATE groups
       SET unlock_threshold = $2, updated_at = NOW()
       WHERE id = $1
       RETURNING *`,
      [groupId, threshold],
    );
    return res.rows[0];
  },

  async setVaultConfig(groupId, config) {
    const res = await query(
      `UPDATE groups
       SET vault_config = $2, updated_at = NOW()
       WHERE id = $1
       RETURNING *`,
      [groupId, JSON.stringify(config)],
    );
    return res.rows[0];
  },

  async getAdminCount(groupId) {
    const res = await query(
      "SELECT COUNT(*) as count FROM group_memberships WHERE group_id = $1 AND role = 'admin'",
      [groupId],
    );
    return parseInt(res.rows[0].count, 10);
  },

  async listAdmins(groupId) {
    const res = await query(
      `SELECT u.id, u.name, u.email
       FROM group_memberships gm
       JOIN users u ON gm.user_id = u.id
       WHERE gm.group_id = $1 AND gm.role = 'admin'
       ORDER BY u.name`,
      [groupId],
    );
    return res.rows;
  },
};

// Group Vaults (dedicated container-based secret storage, renamed from orgVaults)
export const groupVaults = {
  async create(groupId) {
    const res = await query(
      `INSERT INTO group_vaults (group_id, status)
       VALUES ($1, 'pending')
       ON CONFLICT (group_id) DO NOTHING
       RETURNING *`,
      [groupId],
    );
    return res.rows[0];
  },

  async findByGroup(groupId) {
    const res = await query("SELECT * FROM group_vaults WHERE group_id = $1", [groupId]);
    return res.rows[0];
  },

  async updateContainer(groupId, { containerId, containerPort }) {
    const res = await query(
      `UPDATE group_vaults SET container_id = $2, container_port = $3, status = 'active', updated_at = NOW()
       WHERE group_id = $1 RETURNING *`,
      [groupId, containerId, containerPort],
    );
    return res.rows[0];
  },

  async updateStatus(groupId, status) {
    const res = await query(
      `UPDATE group_vaults SET status = $2, updated_at = NOW() WHERE group_id = $1 RETURNING *`,
      [groupId, status],
    );
    return res.rows[0];
  },

  async setVaultData(groupId, vaultEncrypted) {
    const res = await query(
      `UPDATE group_vaults SET vault_encrypted = $2, updated_at = NOW() WHERE group_id = $1 RETURNING *`,
      [groupId, JSON.stringify(vaultEncrypted)],
    );
    return res.rows[0];
  },

  async getVaultData(groupId) {
    const res = await query("SELECT vault_encrypted FROM group_vaults WHERE group_id = $1", [
      groupId,
    ]);
    return res.rows[0]?.vault_encrypted;
  },

  async delete(groupId) {
    await query("DELETE FROM group_vaults WHERE group_id = $1", [groupId]);
  },
};

// Group Vault Audit Log (renamed from orgVaultAudit)
export const groupVaultAudit = {
  async log({
    groupId,
    userId,
    action,
    secretKey,
    ipAddress,
    success = true,
    errorMessage,
    metadata,
  }) {
    await query(
      `INSERT INTO group_vault_audit (group_id, user_id, action, secret_key, ip_address, success, error_message, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        groupId,
        userId,
        action,
        secretKey,
        ipAddress,
        success,
        errorMessage,
        metadata ? JSON.stringify(metadata) : "{}",
      ],
    );
  },

  async getRecent(groupId, limit = 100) {
    const res = await query(
      `SELECT gva.*, u.name as user_name, u.email as user_email
       FROM group_vault_audit gva
       LEFT JOIN users u ON gva.user_id = u.id
       WHERE gva.group_id = $1
       ORDER BY gva.created_at DESC
       LIMIT $2`,
      [groupId, limit],
    );
    return res.rows;
  },

  async getForSecret(groupId, secretKey, limit = 50) {
    const res = await query(
      `SELECT gva.*, u.name as user_name, u.email as user_email
       FROM group_vault_audit gva
       LEFT JOIN users u ON gva.user_id = u.id
       WHERE gva.group_id = $1 AND gva.secret_key = $2
       ORDER BY gva.created_at DESC
       LIMIT $3`,
      [groupId, secretKey, limit],
    );
    return res.rows;
  },

  async getForUser(groupId, userId, limit = 50) {
    const res = await query(
      `SELECT * FROM group_vault_audit
       WHERE group_id = $1 AND user_id = $2
       ORDER BY created_at DESC
       LIMIT $3`,
      [groupId, userId, limit],
    );
    return res.rows;
  },
};

// Group Vault Capability Tokens (renamed from orgVaultTokens)
export const groupVaultTokens = {
  async create({ groupId, userId, tokenHash, allowedSecrets, permissions, issuedBy, expiresAt }) {
    const res = await query(
      `INSERT INTO group_vault_tokens (group_id, user_id, token_hash, allowed_secrets, permissions, issued_by, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [
        groupId,
        userId,
        tokenHash,
        allowedSecrets || ["*"],
        permissions || ["read"],
        issuedBy,
        expiresAt,
      ],
    );
    return res.rows[0];
  },

  async findByHash(tokenHash) {
    const res = await query(
      `SELECT gvt.*, u.name as user_name, u.email as user_email
       FROM group_vault_tokens gvt
       JOIN users u ON gvt.user_id = u.id
       WHERE gvt.token_hash = $1 AND gvt.revoked_at IS NULL AND gvt.expires_at > NOW()`,
      [tokenHash],
    );
    return res.rows[0];
  },

  async listByGroup(groupId) {
    const res = await query(
      `SELECT gvt.*, u.name as user_name, u.email as user_email, iu.name as issued_by_name
       FROM group_vault_tokens gvt
       JOIN users u ON gvt.user_id = u.id
       LEFT JOIN users iu ON gvt.issued_by = iu.id
       WHERE gvt.group_id = $1 AND gvt.revoked_at IS NULL
       ORDER BY gvt.created_at DESC`,
      [groupId],
    );
    return res.rows;
  },

  async listActiveByUser(groupId, userId) {
    const res = await query(
      `SELECT * FROM group_vault_tokens
       WHERE group_id = $1 AND user_id = $2 AND revoked_at IS NULL AND expires_at > NOW()
       ORDER BY created_at DESC`,
      [groupId, userId],
    );
    return res.rows;
  },

  async revoke(id) {
    const res = await query(
      "UPDATE group_vault_tokens SET revoked_at = NOW() WHERE id = $1 RETURNING *",
      [id],
    );
    return res.rows[0];
  },

  async revokeByHash(tokenHash) {
    const res = await query(
      "UPDATE group_vault_tokens SET revoked_at = NOW() WHERE token_hash = $1 RETURNING *",
      [tokenHash],
    );
    return res.rows[0];
  },

  async revokeAllForUser(groupId, userId) {
    const res = await query(
      "UPDATE group_vault_tokens SET revoked_at = NOW() WHERE group_id = $1 AND user_id = $2 AND revoked_at IS NULL RETURNING *",
      [groupId, userId],
    );
    return res.rows;
  },

  async deleteExpired() {
    await query("DELETE FROM group_vault_tokens WHERE expires_at < NOW() - INTERVAL '7 days'");
  },
};
