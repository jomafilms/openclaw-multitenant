// Audit log operations
import { query } from "./core.js";

export const audit = {
  async log(userId, action, details, ipAddress, targetUserId = null) {
    await query(
      `INSERT INTO audit_log (user_id, action, details, ip_address, target_user_id) VALUES ($1, $2, $3, $4, $5)`,
      [userId, action, details ? JSON.stringify(details) : null, ipAddress, targetUserId],
    );
  },

  async getRecent(limit = 50) {
    const res = await query(
      `SELECT a.*, u.name as user_name, tu.name as target_user_name
       FROM audit_log a
       LEFT JOIN users u ON a.user_id = u.id
       LEFT JOIN users tu ON a.target_user_id = tu.id
       ORDER BY a.timestamp DESC
       LIMIT $1`,
      [limit],
    );
    return res.rows;
  },

  async getForUser(userId, limit = 100) {
    const res = await query(
      `SELECT a.*, u.name as user_name, tu.name as target_user_name
       FROM audit_log a
       LEFT JOIN users u ON a.user_id = u.id
       LEFT JOIN users tu ON a.target_user_id = tu.id
       WHERE a.user_id = $1 OR a.target_user_id = $1
       ORDER BY a.timestamp DESC
       LIMIT $2`,
      [userId, limit],
    );
    return res.rows;
  },
};
