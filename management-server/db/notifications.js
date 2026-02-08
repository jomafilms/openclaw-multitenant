// User notifications
import { query } from "./core.js";

export const notifications = {
  async create({ userId, type, title, message, severity, metadata }) {
    const res = await query(
      `INSERT INTO notifications (user_id, type, title, message, severity, metadata)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [
        userId,
        type,
        title,
        message,
        severity || "info",
        metadata ? JSON.stringify(metadata) : "{}",
      ],
    );
    return res.rows[0];
  },

  async getUnread(userId) {
    const res = await query(
      `SELECT * FROM notifications
       WHERE user_id = $1 AND read_at IS NULL
       ORDER BY created_at DESC`,
      [userId],
    );
    return res.rows;
  },

  async getRecent(userId, limit = 50) {
    const res = await query(
      `SELECT * FROM notifications
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT $2`,
      [userId, limit],
    );
    return res.rows;
  },

  async markRead(id, userId) {
    const res = await query(
      `UPDATE notifications
       SET read_at = NOW()
       WHERE id = $1 AND user_id = $2
       RETURNING *`,
      [id, userId],
    );
    return res.rows[0];
  },

  async markAllRead(userId) {
    const res = await query(
      `UPDATE notifications
       SET read_at = NOW()
       WHERE user_id = $1 AND read_at IS NULL
       RETURNING *`,
      [userId],
    );
    return res.rows;
  },

  async countUnread(userId) {
    const res = await query(
      `SELECT COUNT(*) as count FROM notifications
       WHERE user_id = $1 AND read_at IS NULL`,
      [userId],
    );
    return parseInt(res.rows[0].count, 10);
  },

  async delete(id, userId) {
    await query(`DELETE FROM notifications WHERE id = $1 AND user_id = $2`, [id, userId]);
  },
};
