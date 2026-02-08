// group-vault/lib/audit.js
// Audit logging for group vault operations
// Logs are persisted to mesh_audit_logs table and also kept in-memory for fast access

import pg from "pg";

/**
 * Audit log entry
 * @typedef {Object} AuditEntry
 * @property {string} timestamp - ISO timestamp
 * @property {string} groupId - Group ID
 * @property {string} userId - User who performed the action
 * @property {string} action - Action type
 * @property {string} [secretKey] - Secret key accessed (if applicable)
 * @property {string} [ipAddress] - IP address
 * @property {boolean} success - Whether the action succeeded
 * @property {string} [error] - Error message if failed
 */

// Database connection for persistent logging
let pool = null;

/**
 * Initialize database connection for persistent audit logging
 * Call this at startup if you want persistent logs
 */
export function initDb() {
  if (!pool) {
    pool = new pg.Pool({
      connectionString: process.env.DATABASE_URL || "postgresql://localhost:5432/ocmt",
    });
  }
  return pool;
}

// In-memory audit log (per group) - kept for fast local access
const auditLogs = new Map();

// Max entries to keep per group in memory
const MAX_ENTRIES_PER_GROUP = 10000;

// Event type mapping for mesh audit
const MESH_EVENT_TYPES = {
  "vault.initialized": "group_vault.created",
  "vault.imported": "group_vault.imported",
  "vault.exported": "group_vault.exported",
  "vault.unlocked": "group_vault.unlocked",
  "vault.unlock_failed": "group_vault.unlock_failed",
  "vault.locked": "group_vault.locked",
  "token.issued": "group_vault.token_issued",
  "token.revoked": "group_vault.token_revoked",
  "tokens.revoked.user": "group_vault.tokens_revoked_user",
  "secret.read": "group_vault.secret_read",
  "secret.read.denied": "group_vault.secret_read_denied",
  "secret.write.denied": "group_vault.secret_write_denied",
  "secret.delete.denied": "group_vault.secret_delete_denied",
  "secrets.listed": "group_vault.secrets_listed",
  "secret.created": "group_vault.secret_created",
  "secret.updated": "group_vault.secret_updated",
  "secret.deleted": "group_vault.secret_deleted",
};

/**
 * Log an audit event (persists to database and keeps in memory)
 * @param {string} groupId - Group ID
 * @param {AuditEntry} entry - Audit entry
 */
export async function log(groupId, entry) {
  const timestamp = new Date().toISOString();
  const fullEntry = {
    timestamp,
    groupId,
    ...entry,
  };

  // Store in memory for fast access
  if (!auditLogs.has(groupId)) {
    auditLogs.set(groupId, []);
  }

  const logs = auditLogs.get(groupId);
  logs.push(fullEntry);

  // Trim old entries in memory
  if (logs.length > MAX_ENTRIES_PER_GROUP) {
    logs.splice(0, logs.length - MAX_ENTRIES_PER_GROUP);
  }

  // Log to console for debugging
  console.log(
    `[audit] ${groupId.slice(0, 8)}... ${entry.action} by ${entry.userId?.slice(0, 8) || "system"}... ${entry.success ? "OK" : "FAILED"}`,
  );

  // Persist to database asynchronously (don't block on this)
  persistToDb(groupId, fullEntry).catch((err) => {
    console.error("[audit] Failed to persist to database:", err.message);
  });
}

/**
 * Persist audit entry to mesh_audit_logs table
 */
async function persistToDb(groupId, entry) {
  if (!pool) {
    initDb();
  }

  if (!pool) {
    return; // No database connection
  }

  const meshEventType =
    MESH_EVENT_TYPES[entry.action] || `group_vault.${entry.action.replace(/\./g, "_")}`;

  try {
    await pool.query(
      `INSERT INTO mesh_audit_logs
       (event_type, actor_id, target_id, group_id, details, ip_address, success, error_message, source)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        meshEventType,
        entry.userId || null,
        entry.secretKey || entry.targetUserId || null,
        groupId,
        JSON.stringify({
          action: entry.action,
          secretKey: entry.secretKey,
          ...entry.metadata,
        }),
        entry.ipAddress || null,
        entry.success !== false,
        entry.error || null,
        "group-vault",
      ],
    );
  } catch (err) {
    // Log but don't throw - audit logging should not break operations
    console.error("[audit] Database persist error:", err.message);
  }
}

/**
 * Get audit logs for group (from memory, falls back to database)
 * @param {string} groupId - Group ID
 * @param {number} [limit=100] - Max entries to return
 * @returns {Promise<AuditEntry[]>}
 */
export async function getLogs(groupId, limit = 100) {
  // First try memory
  const memoryLogs = auditLogs.get(groupId) || [];
  if (memoryLogs.length > 0) {
    return memoryLogs.slice(-limit).toReversed();
  }

  // Fall back to database
  if (!pool) {
    initDb();
  }

  if (!pool) {
    return [];
  }

  try {
    const res = await pool.query(
      `SELECT
         timestamp,
         actor_id as "userId",
         target_id as "secretKey",
         details->>'action' as action,
         ip_address as "ipAddress",
         success,
         error_message as error
       FROM mesh_audit_logs
       WHERE group_id = $1 AND source = 'group-vault'
       ORDER BY timestamp DESC
       LIMIT $2`,
      [groupId, limit],
    );
    return res.rows.map((row) => ({
      ...row,
      timestamp: row.timestamp.toISOString(),
    }));
  } catch (err) {
    console.error("[audit] Database query error:", err.message);
    return [];
  }
}

/**
 * Get audit logs for specific secret
 * @param {string} groupId - Group ID
 * @param {string} secretKey - Secret key
 * @param {number} [limit=50] - Max entries to return
 * @returns {Promise<AuditEntry[]>}
 */
export async function getSecretLogs(groupId, secretKey, limit = 50) {
  // First try memory
  const memoryLogs = auditLogs.get(groupId) || [];
  const filteredMemory = memoryLogs.filter((entry) => entry.secretKey === secretKey);
  if (filteredMemory.length > 0) {
    return filteredMemory.slice(-limit).toReversed();
  }

  // Fall back to database
  if (!pool) {
    initDb();
  }

  if (!pool) {
    return [];
  }

  try {
    const res = await pool.query(
      `SELECT
         timestamp,
         actor_id as "userId",
         target_id as "secretKey",
         details->>'action' as action,
         ip_address as "ipAddress",
         success,
         error_message as error
       FROM mesh_audit_logs
       WHERE group_id = $1 AND target_id = $2 AND source = 'group-vault'
       ORDER BY timestamp DESC
       LIMIT $3`,
      [groupId, secretKey, limit],
    );
    return res.rows.map((row) => ({
      ...row,
      timestamp: row.timestamp.toISOString(),
    }));
  } catch (err) {
    console.error("[audit] Database query error:", err.message);
    return [];
  }
}

/**
 * Clear old audit logs from memory (database has its own retention)
 * @param {string} groupId - Group ID
 * @param {number} olderThanMs - Clear entries older than this many ms
 */
export function clearOldLogs(groupId, olderThanMs = 30 * 24 * 60 * 60 * 1000) {
  const logs = auditLogs.get(groupId);
  if (!logs) {
    return;
  }

  const cutoff = Date.now() - olderThanMs;
  const filtered = logs.filter((entry) => new Date(entry.timestamp).getTime() > cutoff);
  auditLogs.set(groupId, filtered);
}

/**
 * Close database connection (for graceful shutdown)
 */
export async function close() {
  if (pool) {
    await pool.end();
    pool = null;
  }
}

export default {
  initDb,
  log,
  getLogs,
  getSecretLogs,
  clearOldLogs,
  close,
};
