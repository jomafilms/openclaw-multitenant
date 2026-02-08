// Mesh audit logs (Persistent audit trail for security events)
import { query } from "./core.js";

// Event type constants for mesh security audit
export const MESH_AUDIT_EVENTS = {
  // Capability events
  CAPABILITY_ISSUED: "capability.issued",
  CAPABILITY_USED: "capability.used",
  CAPABILITY_REVOKED: "capability.revoked",
  CAPABILITY_EXPIRED: "capability.expired",
  CAPABILITY_DENIED: "capability.denied",

  // Vault events
  VAULT_UNLOCKED: "vault.unlocked",
  VAULT_LOCKED: "vault.locked",
  VAULT_UNLOCK_FAILED: "vault.unlock_failed",
  VAULT_CREATED: "vault.created",
  VAULT_PASSWORD_CHANGED: "vault.password_changed",
  VAULT_RECOVERED: "vault.recovered",

  // Group vault events (renamed from org_vault)
  GROUP_VAULT_UNLOCKED: "group_vault.unlocked",
  GROUP_VAULT_LOCKED: "group_vault.locked",
  GROUP_VAULT_UNLOCK_REQUESTED: "group_vault.unlock_requested",
  GROUP_VAULT_UNLOCK_APPROVED: "group_vault.unlock_approved",
  GROUP_VAULT_THRESHOLD_MET: "group_vault.threshold_met",
  GROUP_VAULT_TOKEN_ISSUED: "group_vault.token_issued",
  GROUP_VAULT_TOKEN_REVOKED: "group_vault.token_revoked",

  // Sharing events
  SHARE_GRANTED: "share.granted",
  SHARE_REVOKED: "share.revoked",
  SHARE_REQUESTED: "share.requested",
  SHARE_APPROVED: "share.approved",
  SHARE_DENIED: "share.denied",
  SHARE_USED: "share.used",

  // Authentication events
  AUTH_LOGIN: "auth.login",
  AUTH_LOGOUT: "auth.logout",
  AUTH_FAILED: "auth.failed",
  AUTH_MFA_SUCCESS: "auth.mfa_success",
  AUTH_MFA_FAILED: "auth.mfa_failed",
  AUTH_TOKEN_REFRESHED: "auth.token_refreshed",

  // Relay/mesh events
  RELAY_MESSAGE_FORWARDED: "relay.message_forwarded",
  RELAY_MESSAGE_DENIED: "relay.message_denied",
  RELAY_REVOCATION_SUBMITTED: "relay.revocation_submitted",

  // Integration events
  INTEGRATION_CONNECTED: "integration.connected",
  INTEGRATION_DISCONNECTED: "integration.disconnected",
  INTEGRATION_TOKEN_REFRESHED: "integration.token_refreshed",
  INTEGRATION_ACCESS_DENIED: "integration.access_denied",
};

// Mesh audit log operations
export const meshAuditLogs = {
  /**
   * Log a mesh security event
   * @param {Object} entry - Audit entry
   * @param {string} entry.eventType - Event type from MESH_AUDIT_EVENTS
   * @param {string} [entry.actorId] - User or entity performing the action
   * @param {string} [entry.targetId] - Target of the action (user, resource, etc.)
   * @param {string} [entry.groupId] - Group context
   * @param {Object} [entry.details] - Additional structured details
   * @param {string} [entry.ipAddress] - IP address of the request
   * @param {boolean} [entry.success=true] - Whether the action succeeded
   * @param {string} [entry.errorMessage] - Error message if failed
   * @param {string} [entry.source='management-server'] - Source service
   */
  async log({
    eventType,
    actorId,
    targetId,
    groupId,
    details,
    ipAddress,
    success = true,
    errorMessage,
    source = "management-server",
  }) {
    try {
      await query(
        `INSERT INTO mesh_audit_logs
         (event_type, actor_id, target_id, group_id, details, ip_address, success, error_message, source)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [
          eventType,
          actorId,
          targetId,
          groupId,
          details ? JSON.stringify(details) : null,
          ipAddress,
          success,
          errorMessage,
          source,
        ],
      );
    } catch (err) {
      // Log to console but don't throw - audit logging should not break operations
      console.error("[meshAuditLogs] Failed to log event:", err.message, { eventType, actorId });
    }
  },

  /**
   * Log multiple events in a batch (for high-throughput scenarios)
   * @param {Array} entries - Array of audit entries
   */
  async logBatch(entries) {
    if (!entries || entries.length === 0) {
      return;
    }

    try {
      const values = entries
        .map((entry, i) => {
          const offset = i * 9;
          return `($${offset + 1}, $${offset + 2}, $${offset + 3}, $${offset + 4}, $${offset + 5}, $${offset + 6}, $${offset + 7}, $${offset + 8}, $${offset + 9})`;
        })
        .join(", ");

      const params = entries.flatMap((entry) => [
        entry.eventType,
        entry.actorId,
        entry.targetId,
        entry.groupId,
        entry.details ? JSON.stringify(entry.details) : null,
        entry.ipAddress,
        entry.success !== false,
        entry.errorMessage,
        entry.source || "management-server",
      ]);

      await query(
        `INSERT INTO mesh_audit_logs
         (event_type, actor_id, target_id, group_id, details, ip_address, success, error_message, source)
         VALUES ${values}`,
        params,
      );
    } catch (err) {
      console.error("[meshAuditLogs] Failed to log batch:", err.message);
    }
  },

  /**
   * Query audit logs with filtering and pagination
   * @param {Object} options - Query options
   * @param {string} [options.groupId] - Filter by group
   * @param {string} [options.actorId] - Filter by actor
   * @param {string} [options.targetId] - Filter by target
   * @param {string} [options.eventType] - Filter by event type (supports prefix match with *)
   * @param {boolean} [options.successOnly] - Only return successful events
   * @param {boolean} [options.failuresOnly] - Only return failed events
   * @param {Date} [options.startTime] - Start of time range
   * @param {Date} [options.endTime] - End of time range
   * @param {number} [options.limit=100] - Maximum results
   * @param {number} [options.offset=0] - Pagination offset
   * @returns {Promise<{logs: Array, total: number}>}
   */
  async query({
    groupId,
    actorId,
    targetId,
    eventType,
    successOnly,
    failuresOnly,
    startTime,
    endTime,
    limit = 100,
    offset = 0,
  } = {}) {
    const conditions = [];
    const params = [];
    let paramIndex = 1;

    if (groupId) {
      conditions.push(`group_id = $${paramIndex++}`);
      params.push(groupId);
    }

    if (actorId) {
      conditions.push(`actor_id = $${paramIndex++}`);
      params.push(actorId);
    }

    if (targetId) {
      conditions.push(`target_id = $${paramIndex++}`);
      params.push(targetId);
    }

    if (eventType) {
      if (eventType.endsWith("*")) {
        // Prefix match
        conditions.push(`event_type LIKE $${paramIndex++}`);
        params.push(eventType.slice(0, -1) + "%");
      } else {
        conditions.push(`event_type = $${paramIndex++}`);
        params.push(eventType);
      }
    }

    if (successOnly) {
      conditions.push("success = true");
    } else if (failuresOnly) {
      conditions.push("success = false");
    }

    if (startTime) {
      conditions.push(`timestamp >= $${paramIndex++}`);
      params.push(startTime);
    }

    if (endTime) {
      conditions.push(`timestamp <= $${paramIndex++}`);
      params.push(endTime);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

    // Get total count
    const countRes = await query(
      `SELECT COUNT(*) as count FROM mesh_audit_logs ${whereClause}`,
      params,
    );
    const total = parseInt(countRes.rows[0].count, 10);

    // Get logs with pagination
    params.push(limit, offset);
    const res = await query(
      `SELECT * FROM mesh_audit_logs ${whereClause}
       ORDER BY timestamp DESC
       LIMIT $${paramIndex++} OFFSET $${paramIndex++}`,
      params,
    );

    return {
      logs: res.rows,
      total,
      limit,
      offset,
    };
  },

  /**
   * Get recent audit logs
   * @param {number} [limit=100] - Maximum results
   * @returns {Promise<Array>}
   */
  async getRecent(limit = 100) {
    const res = await query(
      `SELECT * FROM mesh_audit_logs
       ORDER BY timestamp DESC
       LIMIT $1`,
      [limit],
    );
    return res.rows;
  },

  /**
   * Get audit logs for a specific user
   * @param {string} userId - User ID
   * @param {number} [limit=100] - Maximum results
   * @returns {Promise<Array>}
   */
  async getForUser(userId, limit = 100) {
    const res = await query(
      `SELECT * FROM mesh_audit_logs
       WHERE actor_id = $1 OR target_id = $1
       ORDER BY timestamp DESC
       LIMIT $2`,
      [userId, limit],
    );
    return res.rows;
  },

  /**
   * Get audit logs for a group
   * @param {string} groupId - Group ID
   * @param {number} [limit=100] - Maximum results
   * @returns {Promise<Array>}
   */
  async getForGroup(groupId, limit = 100) {
    const res = await query(
      `SELECT * FROM mesh_audit_logs
       WHERE group_id = $1
       ORDER BY timestamp DESC
       LIMIT $2`,
      [groupId, limit],
    );
    return res.rows;
  },

  /**
   * Get failed authentication attempts for a user
   * @param {string} userId - User ID
   * @param {number} [hours=24] - Time window in hours
   * @returns {Promise<Array>}
   */
  async getFailedAuthAttempts(userId, hours = 24) {
    if (typeof hours !== "number" || !Number.isFinite(hours) || hours < 0) {
      throw new Error("hours must be a non-negative number");
    }
    const res = await query(
      `SELECT * FROM mesh_audit_logs
       WHERE (actor_id = $1 OR target_id = $1)
         AND event_type LIKE 'auth.%'
         AND success = false
         AND timestamp > NOW() - ($2 * INTERVAL '1 hour')
       ORDER BY timestamp DESC`,
      [userId, hours],
    );
    return res.rows;
  },

  /**
   * Get security event summary for a group
   * @param {string} groupId - Group ID
   * @param {number} [days=7] - Time window in days
   * @returns {Promise<Object>} Summary statistics
   */
  async getSecuritySummary(groupId, days = 7) {
    if (typeof days !== "number" || !Number.isFinite(days) || days < 0) {
      throw new Error("days must be a non-negative number");
    }
    const res = await query(
      `SELECT
         event_type,
         success,
         COUNT(*) as count
       FROM mesh_audit_logs
       WHERE group_id = $1
         AND timestamp > NOW() - ($2 * INTERVAL '1 day')
       GROUP BY event_type, success
       ORDER BY count DESC`,
      [groupId, days],
    );

    const summary = {
      totalEvents: 0,
      successfulEvents: 0,
      failedEvents: 0,
      byEventType: {},
    };

    for (const row of res.rows) {
      const count = parseInt(row.count, 10);
      summary.totalEvents += count;
      if (row.success) {
        summary.successfulEvents += count;
      } else {
        summary.failedEvents += count;
      }
      if (!summary.byEventType[row.event_type]) {
        summary.byEventType[row.event_type] = { success: 0, failed: 0 };
      }
      if (row.success) {
        summary.byEventType[row.event_type].success += count;
      } else {
        summary.byEventType[row.event_type].failed += count;
      }
    }

    return summary;
  },

  /**
   * Clean up old audit logs (retention policy)
   * @param {number} [daysToKeep=365] - Number of days to retain
   * @returns {Promise<number>} Number of deleted records
   */
  async cleanup(daysToKeep = 365) {
    if (typeof daysToKeep !== "number" || !Number.isFinite(daysToKeep) || daysToKeep < 0) {
      throw new Error("daysToKeep must be a non-negative number");
    }
    const res = await query(
      `DELETE FROM mesh_audit_logs
       WHERE timestamp < NOW() - ($1 * INTERVAL '1 day')
       RETURNING id`,
      [daysToKeep],
    );
    return res.rowCount;
  },

  /**
   * Export audit logs for compliance
   * @param {Object} options - Export options
   * @param {string} [options.groupId] - Filter by group
   * @param {Date} options.startTime - Start of export range
   * @param {Date} options.endTime - End of export range
   * @returns {Promise<Array>}
   */
  async exportForCompliance({ groupId, startTime, endTime }) {
    const conditions = ["timestamp >= $1", "timestamp <= $2"];
    const params = [startTime, endTime];

    if (groupId) {
      conditions.push("group_id = $3");
      params.push(groupId);
    }

    const res = await query(
      `SELECT
         id,
         timestamp,
         event_type,
         actor_id,
         target_id,
         group_id,
         details,
         ip_address,
         success,
         error_message,
         source
       FROM mesh_audit_logs
       WHERE ${conditions.join(" AND ")}
       ORDER BY timestamp ASC`,
      params,
    );

    return res.rows;
  },
};
