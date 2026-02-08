// Security events database operations
// Handles security_events, alert_rules, and alert_channels tables

import { query, encrypt, decrypt } from "./core.js";

// ============================================================
// SECURITY EVENTS
// ============================================================

export const securityEvents = {
  /**
   * Insert a new security event
   */
  async insert({ type, userId, groupId, severity, details, ipAddress, userAgent }) {
    const res = await query(
      `INSERT INTO security_events (event_type, user_id, group_id, severity, details, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [
        type,
        userId || null,
        groupId || null,
        severity || "info",
        details ? JSON.stringify(details) : "{}",
        ipAddress || null,
        userAgent || null,
      ],
    );
    return res.rows[0];
  },

  /**
   * Get security events with filters
   */
  async getEvents({
    userId,
    groupId,
    eventType,
    severity,
    limit = 100,
    offset = 0,
    startDate,
    endDate,
  }) {
    let whereConditions = [];
    let params = [];
    let paramIndex = 1;

    if (userId) {
      whereConditions.push(`user_id = $${paramIndex++}`);
      params.push(userId);
    }
    if (groupId) {
      whereConditions.push(`group_id = $${paramIndex++}`);
      params.push(groupId);
    }
    if (eventType) {
      whereConditions.push(`event_type = $${paramIndex++}`);
      params.push(eventType);
    }
    if (severity) {
      whereConditions.push(`severity = $${paramIndex++}`);
      params.push(severity);
    }
    if (startDate) {
      whereConditions.push(`created_at >= $${paramIndex++}`);
      params.push(startDate);
    }
    if (endDate) {
      whereConditions.push(`created_at <= $${paramIndex++}`);
      params.push(endDate);
    }

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

    params.push(limit, offset);

    const res = await query(
      `SELECT se.*, u.email as user_email, u.name as user_name
       FROM security_events se
       LEFT JOIN users u ON se.user_id = u.id
       ${whereClause}
       ORDER BY se.created_at DESC
       LIMIT $${paramIndex++} OFFSET $${paramIndex}`,
      params,
    );
    return res.rows;
  },

  /**
   * Count events matching filters (for pagination)
   */
  async countEvents({ userId, groupId, eventType, severity, startDate, endDate }) {
    let whereConditions = [];
    let params = [];
    let paramIndex = 1;

    if (userId) {
      whereConditions.push(`user_id = $${paramIndex++}`);
      params.push(userId);
    }
    if (groupId) {
      whereConditions.push(`group_id = $${paramIndex++}`);
      params.push(groupId);
    }
    if (eventType) {
      whereConditions.push(`event_type = $${paramIndex++}`);
      params.push(eventType);
    }
    if (severity) {
      whereConditions.push(`severity = $${paramIndex++}`);
      params.push(severity);
    }
    if (startDate) {
      whereConditions.push(`created_at >= $${paramIndex++}`);
      params.push(startDate);
    }
    if (endDate) {
      whereConditions.push(`created_at <= $${paramIndex++}`);
      params.push(endDate);
    }

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

    const res = await query(`SELECT COUNT(*) as count FROM security_events ${whereClause}`, params);
    return parseInt(res.rows[0].count, 10);
  },

  /**
   * Get recent events for a user
   */
  async getRecentForUser(userId, limit = 50) {
    const res = await query(
      `SELECT * FROM security_events
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT $2`,
      [userId, limit],
    );
    return res.rows;
  },

  /**
   * Count events by type in time window (for threshold detection)
   */
  async countByTypeInWindow(eventType, userId, windowMinutes) {
    const windowStart = new Date(Date.now() - windowMinutes * 60 * 1000);
    const res = await query(
      `SELECT COUNT(*) as count FROM security_events
       WHERE event_type = $1 AND user_id = $2 AND created_at >= $3`,
      [eventType, userId, windowStart],
    );
    return parseInt(res.rows[0].count, 10);
  },

  /**
   * Delete old events (for cleanup)
   */
  async deleteOlderThan(days) {
    const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
    const res = await query(`DELETE FROM security_events WHERE created_at < $1`, [cutoff]);
    return res.rowCount;
  },
};

// ============================================================
// ALERT RULES
// ============================================================

export const alertRules = {
  /**
   * Create or update an alert rule
   */
  async upsert({
    id,
    userId,
    groupId,
    eventType,
    severityThreshold,
    thresholdCount,
    thresholdWindowMinutes,
    enabled,
    cooldownMinutes,
    channels,
    metadata,
  }) {
    if (id) {
      // Update existing
      const res = await query(
        `UPDATE alert_rules SET
           event_type = COALESCE($2, event_type),
           severity_threshold = COALESCE($3, severity_threshold),
           threshold_count = COALESCE($4, threshold_count),
           threshold_window_minutes = COALESCE($5, threshold_window_minutes),
           enabled = COALESCE($6, enabled),
           cooldown_minutes = COALESCE($7, cooldown_minutes),
           channels = COALESCE($8, channels),
           metadata = COALESCE($9, metadata),
           updated_at = NOW()
         WHERE id = $1 AND user_id = $10
         RETURNING *`,
        [
          id,
          eventType,
          severityThreshold,
          thresholdCount,
          thresholdWindowMinutes,
          enabled,
          cooldownMinutes,
          channels ? JSON.stringify(channels) : null,
          metadata ? JSON.stringify(metadata) : null,
          userId,
        ],
      );
      return res.rows[0];
    } else {
      // Create new
      const res = await query(
        `INSERT INTO alert_rules (user_id, group_id, event_type, severity_threshold, threshold_count, threshold_window_minutes, enabled, cooldown_minutes, channels, metadata)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         RETURNING *`,
        [
          userId,
          groupId || null,
          eventType,
          severityThreshold || "warning",
          thresholdCount || 1,
          thresholdWindowMinutes || 15,
          enabled !== false,
          cooldownMinutes || 60,
          JSON.stringify(channels || ["in_app", "email"]),
          metadata ? JSON.stringify(metadata) : "{}",
        ],
      );
      return res.rows[0];
    }
  },

  /**
   * Get rules for a user
   */
  async listForUser(userId) {
    const res = await query(
      `SELECT * FROM alert_rules
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [userId],
    );
    return res.rows;
  },

  /**
   * Get rules for a group
   */
  async listForGroup(groupId) {
    const res = await query(
      `SELECT * FROM alert_rules
       WHERE group_id = $1
       ORDER BY created_at DESC`,
      [groupId],
    );
    return res.rows;
  },

  /**
   * Find applicable rules for an event
   */
  async findApplicable(userId, groupId, eventType) {
    const res = await query(
      `SELECT * FROM alert_rules
       WHERE enabled = true
         AND (event_type = $3 OR event_type = '*')
         AND (
           (user_id = $1 AND (group_id IS NULL OR group_id = $2))
           OR (user_id IS NULL AND group_id = $2)
         )
       ORDER BY
         CASE WHEN event_type = $3 THEN 0 ELSE 1 END,
         CASE WHEN user_id IS NOT NULL THEN 0 ELSE 1 END`,
      [userId, groupId, eventType],
    );
    return res.rows;
  },

  /**
   * Get a single rule by ID
   */
  async getById(id) {
    const res = await query(`SELECT * FROM alert_rules WHERE id = $1`, [id]);
    return res.rows[0];
  },

  /**
   * Delete a rule
   */
  async delete(id, userId) {
    const res = await query(`DELETE FROM alert_rules WHERE id = $1 AND user_id = $2 RETURNING id`, [
      id,
      userId,
    ]);
    return res.rowCount > 0;
  },
};

// ============================================================
// ALERT CHANNELS (Webhooks)
// ============================================================

export const alertChannels = {
  /**
   * Create a new alert channel
   */
  async create({ userId, groupId, channelType, name, config }) {
    const configEncrypted = encrypt(JSON.stringify(config));
    const res = await query(
      `INSERT INTO alert_channels (user_id, group_id, channel_type, name, config_encrypted, enabled)
       VALUES ($1, $2, $3, $4, $5, true)
       RETURNING id, user_id, group_id, channel_type, name, enabled, created_at`,
      [userId, groupId || null, channelType, name, configEncrypted],
    );
    return res.rows[0];
  },

  /**
   * Get channels for a user
   */
  async listForUser(userId) {
    const res = await query(
      `SELECT id, user_id, group_id, channel_type, name, enabled, last_success_at, last_failure_at, failure_count, created_at
       FROM alert_channels
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [userId],
    );
    return res.rows;
  },

  /**
   * Find channels by type for user/group
   */
  async findByType(userId, groupId, channelType) {
    const res = await query(
      `SELECT * FROM alert_channels
       WHERE channel_type = $3 AND enabled = true
         AND (user_id = $1 OR (group_id = $2 AND $2 IS NOT NULL))`,
      [userId, groupId, channelType],
    );
    return res.rows;
  },

  /**
   * Get decrypted config for a channel
   */
  async getDecryptedConfig(id) {
    const res = await query(`SELECT config_encrypted FROM alert_channels WHERE id = $1`, [id]);
    if (!res.rows[0]) return null;
    return JSON.parse(decrypt(res.rows[0].config_encrypted));
  },

  /**
   * Update channel enabled status
   */
  async setEnabled(id, userId, enabled) {
    const res = await query(
      `UPDATE alert_channels SET enabled = $3 WHERE id = $1 AND user_id = $2 RETURNING *`,
      [id, userId, enabled],
    );
    return res.rows[0];
  },

  /**
   * Record successful webhook delivery
   */
  async recordSuccess(id) {
    await query(
      `UPDATE alert_channels SET last_success_at = NOW(), failure_count = 0 WHERE id = $1`,
      [id],
    );
  },

  /**
   * Record failed webhook delivery
   */
  async recordFailure(id, errorMessage) {
    await query(
      `UPDATE alert_channels SET last_failure_at = NOW(), failure_count = failure_count + 1 WHERE id = $1`,
      [id],
    );
  },

  /**
   * Delete a channel
   */
  async delete(id, userId) {
    const res = await query(
      `DELETE FROM alert_channels WHERE id = $1 AND user_id = $2 RETURNING id`,
      [id, userId],
    );
    return res.rowCount > 0;
  },
};

// ============================================================
// ALERT HISTORY (for deduplication)
// ============================================================

export const alertHistory = {
  /**
   * Create an alert history entry
   */
  async create({
    ruleId,
    userId,
    groupId,
    eventType,
    severity,
    title,
    message,
    metadata,
    dedupKey,
    channelsSent,
  }) {
    const res = await query(
      `INSERT INTO alert_history (rule_id, user_id, group_id, event_type, severity, title, message, metadata, dedup_key, channels_sent)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING *`,
      [
        ruleId || null,
        userId || null,
        groupId || null,
        eventType,
        severity,
        title,
        message,
        metadata ? JSON.stringify(metadata) : "{}",
        dedupKey,
        JSON.stringify(channelsSent || []),
      ],
    );
    return res.rows[0];
  },

  /**
   * Count recent alerts with same dedup key
   */
  async countRecent(dedupKey, windowMinutes) {
    const windowStart = new Date(Date.now() - windowMinutes * 60 * 1000);
    const res = await query(
      `SELECT COUNT(*) as count FROM alert_history
       WHERE dedup_key = $1 AND created_at >= $2`,
      [dedupKey, windowStart],
    );
    return parseInt(res.rows[0].count, 10);
  },

  /**
   * Get alert history for a user
   */
  async listForUser(userId, limit = 50) {
    const res = await query(
      `SELECT * FROM alert_history
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT $2`,
      [userId, limit],
    );
    return res.rows;
  },
};

// ============================================================
// ALERT COOLDOWNS (throttling)
// ============================================================

export const alertCooldowns = {
  /**
   * Find cooldown by key
   */
  async findByKey(dedupKey) {
    const res = await query(`SELECT * FROM alert_cooldowns WHERE dedup_key = $1`, [dedupKey]);
    return res.rows[0];
  },

  /**
   * Upsert a cooldown entry
   */
  async upsert(dedupKey, expiresAt) {
    await query(
      `INSERT INTO alert_cooldowns (dedup_key, last_alerted_at, expires_at)
       VALUES ($1, NOW(), $2)
       ON CONFLICT (dedup_key) DO UPDATE SET
         last_alerted_at = NOW(),
         alert_count = alert_cooldowns.alert_count + 1,
         expires_at = $2`,
      [dedupKey, expiresAt],
    );
  },

  /**
   * Delete expired cooldowns
   */
  async deleteExpired() {
    const res = await query(`DELETE FROM alert_cooldowns WHERE expires_at < NOW()`);
    return res.rowCount;
  },
};
