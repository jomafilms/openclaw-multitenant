// Agent activity and anomaly detection
import { query } from "./core.js";

// Agent activity log (for behavioral anomaly detection)
export const agentActivity = {
  async log(userId, actionType, resource = null, metadata = {}) {
    const res = await query(
      `INSERT INTO agent_activity_log (user_id, action_type, resource, metadata)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [userId, actionType, resource, JSON.stringify(metadata)],
    );
    return res.rows[0];
  },

  async countByUserAndPeriod(userId, actionType, startTime, endTime) {
    const res = await query(
      `SELECT COUNT(*) as count FROM agent_activity_log
       WHERE user_id = $1 AND action_type = $2
         AND timestamp >= $3 AND timestamp < $4`,
      [userId, actionType, startTime, endTime],
    );
    return parseInt(res.rows[0].count, 10);
  },

  async getHourlyDistribution(userId, days = 30) {
    if (typeof days !== "number" || !Number.isFinite(days) || days < 0) {
      throw new Error("days must be a non-negative number");
    }
    const res = await query(
      `SELECT hour_of_day, COUNT(*) as count
       FROM agent_activity_log
       WHERE user_id = $1 AND timestamp > NOW() - ($2 * INTERVAL '1 day')
       GROUP BY hour_of_day
       ORDER BY hour_of_day`,
      [userId, days],
    );
    return res.rows;
  },

  async getDailyStats(userId, days = 30) {
    if (typeof days !== "number" || !Number.isFinite(days) || days < 0) {
      throw new Error("days must be a non-negative number");
    }
    const res = await query(
      `SELECT
         DATE(timestamp) as date,
         action_type,
         COUNT(*) as count
       FROM agent_activity_log
       WHERE user_id = $1 AND timestamp > NOW() - ($2 * INTERVAL '1 day')
       GROUP BY DATE(timestamp), action_type
       ORDER BY date DESC`,
      [userId, days],
    );
    return res.rows;
  },

  async getResourceStats(userId, days = 7) {
    if (typeof days !== "number" || !Number.isFinite(days) || days < 0) {
      throw new Error("days must be a non-negative number");
    }
    const res = await query(
      `SELECT resource, COUNT(*) as count
       FROM agent_activity_log
       WHERE user_id = $1 AND timestamp > NOW() - ($2 * INTERVAL '1 day')
         AND resource IS NOT NULL
       GROUP BY resource
       ORDER BY count DESC
       LIMIT 20`,
      [userId, days],
    );
    return res.rows;
  },

  async getRecentActivity(userId, limit = 100) {
    const res = await query(
      `SELECT * FROM agent_activity_log
       WHERE user_id = $1
       ORDER BY timestamp DESC
       LIMIT $2`,
      [userId, limit],
    );
    return res.rows;
  },

  async getTodayCount(userId, actionType = null) {
    let sql = `SELECT COUNT(*) as count FROM agent_activity_log
               WHERE user_id = $1 AND timestamp >= CURRENT_DATE`;
    const params = [userId];

    if (actionType) {
      sql += " AND action_type = $2";
      params.push(actionType);
    }

    const res = await query(sql, params);
    return parseInt(res.rows[0].count, 10);
  },

  async getHourCount(userId, hoursAgo = 1) {
    if (typeof hoursAgo !== "number" || !Number.isFinite(hoursAgo) || hoursAgo < 0) {
      throw new Error("hoursAgo must be a non-negative number");
    }
    const res = await query(
      `SELECT COUNT(*) as count FROM agent_activity_log
       WHERE user_id = $1 AND timestamp > NOW() - ($2 * INTERVAL '1 hour')`,
      [userId, hoursAgo],
    );
    return parseInt(res.rows[0].count, 10);
  },

  async cleanup(daysToKeep = 90) {
    if (typeof daysToKeep !== "number" || !Number.isFinite(daysToKeep) || daysToKeep < 0) {
      throw new Error("daysToKeep must be a non-negative number");
    }
    const res = await query(
      `DELETE FROM agent_activity_log
       WHERE timestamp < NOW() - ($1 * INTERVAL '1 day')
       RETURNING id`,
      [daysToKeep],
    );
    return res.rowCount;
  },
};

// Agent baselines (rolling averages for anomaly detection)
export const agentBaselines = {
  async upsert(userId, metricName, value) {
    // Use exponential moving average for baseline
    // alpha = 0.1 means new value contributes 10%
    const res = await query(
      `INSERT INTO agent_baselines (user_id, metric_name, baseline_value, stddev_value, sample_count)
       VALUES ($1, $2, $3, 0, 1)
       ON CONFLICT (user_id, metric_name)
       DO UPDATE SET
         baseline_value = agent_baselines.baseline_value * 0.9 + $3 * 0.1,
         stddev_value = GREATEST(
           agent_baselines.stddev_value * 0.9 + ABS($3 - agent_baselines.baseline_value) * 0.1,
           1
         ),
         sample_count = agent_baselines.sample_count + 1,
         updated_at = NOW()
       RETURNING *`,
      [userId, metricName, value],
    );
    return res.rows[0];
  },

  async get(userId, metricName) {
    const res = await query(
      `SELECT * FROM agent_baselines WHERE user_id = $1 AND metric_name = $2`,
      [userId, metricName],
    );
    return res.rows[0];
  },

  async getAllForUser(userId) {
    const res = await query(`SELECT * FROM agent_baselines WHERE user_id = $1`, [userId]);
    return res.rows;
  },

  async delete(userId, metricName) {
    await query(`DELETE FROM agent_baselines WHERE user_id = $1 AND metric_name = $2`, [
      userId,
      metricName,
    ]);
  },
};

// Anomaly alerts
export const anomalyAlerts = {
  async create({
    userId,
    alertType,
    severity,
    metricName,
    expectedValue,
    actualValue,
    deviationFactor,
    description,
    metadata,
    actionTaken,
  }) {
    const res = await query(
      `INSERT INTO anomaly_alerts
       (user_id, alert_type, severity, metric_name, expected_value, actual_value, deviation_factor, description, metadata, action_taken)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING *`,
      [
        userId,
        alertType,
        severity || "warning",
        metricName,
        expectedValue,
        actualValue,
        deviationFactor,
        description,
        metadata ? JSON.stringify(metadata) : "{}",
        actionTaken,
      ],
    );
    return res.rows[0];
  },

  async getUnacknowledged(userId) {
    const res = await query(
      `SELECT * FROM anomaly_alerts
       WHERE user_id = $1 AND acknowledged_at IS NULL
       ORDER BY created_at DESC`,
      [userId],
    );
    return res.rows;
  },

  async getRecent(userId, limit = 50) {
    const res = await query(
      `SELECT * FROM anomaly_alerts
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT $2`,
      [userId, limit],
    );
    return res.rows;
  },

  async acknowledge(id, userId) {
    const res = await query(
      `UPDATE anomaly_alerts
       SET acknowledged_at = NOW()
       WHERE id = $1 AND user_id = $2
       RETURNING *`,
      [id, userId],
    );
    return res.rows[0];
  },

  async acknowledgeAll(userId) {
    const res = await query(
      `UPDATE anomaly_alerts
       SET acknowledged_at = NOW()
       WHERE user_id = $1 AND acknowledged_at IS NULL
       RETURNING *`,
      [userId],
    );
    return res.rows;
  },

  async countBySeverity(userId, days = 7) {
    if (typeof days !== "number" || !Number.isFinite(days) || days < 0) {
      throw new Error("days must be a non-negative number");
    }
    const res = await query(
      `SELECT severity, COUNT(*) as count
       FROM anomaly_alerts
       WHERE user_id = $1 AND created_at > NOW() - ($2 * INTERVAL '1 day')
       GROUP BY severity`,
      [userId, days],
    );
    return res.rows;
  },
};
