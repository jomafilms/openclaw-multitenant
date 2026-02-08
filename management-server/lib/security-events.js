// Security event logging service
// Logs security-relevant events and triggers alerting

import { securityEvents } from "../db/security-events.js";
import { triggerAlert, ALERT_EVENTS } from "./alerting.js";

// Security event types
export const SECURITY_EVENT_TYPES = {
  // Authentication events
  LOGIN_SUCCESS: "login_success",
  LOGIN_FAILED: "login_failed",
  LOGIN_BLOCKED: "login_blocked",
  LOGOUT: "logout",
  SESSION_CREATED: "session_created",
  SESSION_REVOKED: "session_revoked",
  SESSION_EXPIRED: "session_expired",

  // MFA events
  MFA_ENABLED: "mfa_enabled",
  MFA_DISABLED: "mfa_disabled",
  MFA_VERIFIED: "mfa_verified",
  MFA_FAILED: "mfa_failed",
  MFA_BACKUP_USED: "mfa_backup_used",

  // Vault events
  VAULT_CREATED: "vault_created",
  VAULT_UNLOCKED: "vault_unlocked",
  VAULT_UNLOCK_FAILED: "vault_unlock_failed",
  VAULT_LOCKED: "vault_locked",
  VAULT_LOCKED_BY_ANOMALY: "vault_locked_by_anomaly",
  VAULT_PASSWORD_CHANGED: "vault_password_changed",
  VAULT_SECRET_READ: "vault_secret_read",
  VAULT_SECRET_WRITE: "vault_secret_write",
  VAULT_SECRET_DELETE: "vault_secret_delete",

  // Rate limit events
  RATE_LIMIT_EXCEEDED: "rate_limit_exceeded",
  RATE_LIMIT_AUTH: "rate_limit_auth",
  RATE_LIMIT_VAULT: "rate_limit_vault",

  // Admin actions
  ADMIN_USER_CREATED: "admin_user_created",
  ADMIN_USER_DELETED: "admin_user_deleted",
  ADMIN_USER_SUSPENDED: "admin_user_suspended",
  ADMIN_SETTINGS_CHANGED: "admin_settings_changed",
  ADMIN_LOGIN: "admin_login",

  // Group/Org events
  GROUP_CREATED: "group_created",
  GROUP_DELETED: "group_deleted",
  GROUP_MEMBER_ADDED: "group_member_added",
  GROUP_MEMBER_REMOVED: "group_member_removed",
  GROUP_ADMIN_CHANGED: "group_admin_changed",
  GROUP_INVITE_SENT: "group_invite_sent",
  GROUP_INVITE_ACCEPTED: "group_invite_accepted",

  // Token events
  TOKEN_CREATED: "token_created",
  TOKEN_REVOKED: "token_revoked",
  TOKEN_REVOKED_ALL: "token_revoked_all",

  // Recovery events
  RECOVERY_INITIATED: "recovery_initiated",
  RECOVERY_COMPLETED: "recovery_completed",
  RECOVERY_FAILED: "recovery_failed",

  // Anomaly events
  ANOMALY_DETECTED: "anomaly_detected",
  ANOMALY_CRITICAL: "anomaly_critical",

  // API events
  API_KEY_CREATED: "api_key_created",
  API_KEY_REVOKED: "api_key_revoked",
  API_UNAUTHORIZED: "api_unauthorized",
};

// Severity levels
export const SEVERITY = {
  DEBUG: "debug",
  INFO: "info",
  WARNING: "warning",
  CRITICAL: "critical",
};

// Default severity for each event type
const EVENT_SEVERITY = {
  [SECURITY_EVENT_TYPES.LOGIN_SUCCESS]: SEVERITY.INFO,
  [SECURITY_EVENT_TYPES.LOGIN_FAILED]: SEVERITY.WARNING,
  [SECURITY_EVENT_TYPES.LOGIN_BLOCKED]: SEVERITY.WARNING,
  [SECURITY_EVENT_TYPES.LOGOUT]: SEVERITY.INFO,
  [SECURITY_EVENT_TYPES.SESSION_CREATED]: SEVERITY.INFO,
  [SECURITY_EVENT_TYPES.SESSION_REVOKED]: SEVERITY.INFO,
  [SECURITY_EVENT_TYPES.SESSION_EXPIRED]: SEVERITY.DEBUG,

  [SECURITY_EVENT_TYPES.MFA_ENABLED]: SEVERITY.INFO,
  [SECURITY_EVENT_TYPES.MFA_DISABLED]: SEVERITY.WARNING,
  [SECURITY_EVENT_TYPES.MFA_VERIFIED]: SEVERITY.DEBUG,
  [SECURITY_EVENT_TYPES.MFA_FAILED]: SEVERITY.WARNING,
  [SECURITY_EVENT_TYPES.MFA_BACKUP_USED]: SEVERITY.WARNING,

  [SECURITY_EVENT_TYPES.VAULT_CREATED]: SEVERITY.INFO,
  [SECURITY_EVENT_TYPES.VAULT_UNLOCKED]: SEVERITY.INFO,
  [SECURITY_EVENT_TYPES.VAULT_UNLOCK_FAILED]: SEVERITY.WARNING,
  [SECURITY_EVENT_TYPES.VAULT_LOCKED]: SEVERITY.INFO,
  [SECURITY_EVENT_TYPES.VAULT_LOCKED_BY_ANOMALY]: SEVERITY.CRITICAL,
  [SECURITY_EVENT_TYPES.VAULT_PASSWORD_CHANGED]: SEVERITY.WARNING,
  [SECURITY_EVENT_TYPES.VAULT_SECRET_READ]: SEVERITY.DEBUG,
  [SECURITY_EVENT_TYPES.VAULT_SECRET_WRITE]: SEVERITY.INFO,
  [SECURITY_EVENT_TYPES.VAULT_SECRET_DELETE]: SEVERITY.WARNING,

  [SECURITY_EVENT_TYPES.RATE_LIMIT_EXCEEDED]: SEVERITY.WARNING,
  [SECURITY_EVENT_TYPES.RATE_LIMIT_AUTH]: SEVERITY.WARNING,
  [SECURITY_EVENT_TYPES.RATE_LIMIT_VAULT]: SEVERITY.CRITICAL,

  [SECURITY_EVENT_TYPES.ADMIN_USER_CREATED]: SEVERITY.INFO,
  [SECURITY_EVENT_TYPES.ADMIN_USER_DELETED]: SEVERITY.WARNING,
  [SECURITY_EVENT_TYPES.ADMIN_USER_SUSPENDED]: SEVERITY.WARNING,
  [SECURITY_EVENT_TYPES.ADMIN_SETTINGS_CHANGED]: SEVERITY.WARNING,
  [SECURITY_EVENT_TYPES.ADMIN_LOGIN]: SEVERITY.INFO,

  [SECURITY_EVENT_TYPES.GROUP_CREATED]: SEVERITY.INFO,
  [SECURITY_EVENT_TYPES.GROUP_DELETED]: SEVERITY.WARNING,
  [SECURITY_EVENT_TYPES.GROUP_MEMBER_ADDED]: SEVERITY.INFO,
  [SECURITY_EVENT_TYPES.GROUP_MEMBER_REMOVED]: SEVERITY.INFO,
  [SECURITY_EVENT_TYPES.GROUP_ADMIN_CHANGED]: SEVERITY.WARNING,
  [SECURITY_EVENT_TYPES.GROUP_INVITE_SENT]: SEVERITY.DEBUG,
  [SECURITY_EVENT_TYPES.GROUP_INVITE_ACCEPTED]: SEVERITY.INFO,

  [SECURITY_EVENT_TYPES.TOKEN_CREATED]: SEVERITY.INFO,
  [SECURITY_EVENT_TYPES.TOKEN_REVOKED]: SEVERITY.INFO,
  [SECURITY_EVENT_TYPES.TOKEN_REVOKED_ALL]: SEVERITY.CRITICAL,

  [SECURITY_EVENT_TYPES.RECOVERY_INITIATED]: SEVERITY.WARNING,
  [SECURITY_EVENT_TYPES.RECOVERY_COMPLETED]: SEVERITY.INFO,
  [SECURITY_EVENT_TYPES.RECOVERY_FAILED]: SEVERITY.WARNING,

  [SECURITY_EVENT_TYPES.ANOMALY_DETECTED]: SEVERITY.WARNING,
  [SECURITY_EVENT_TYPES.ANOMALY_CRITICAL]: SEVERITY.CRITICAL,

  [SECURITY_EVENT_TYPES.API_KEY_CREATED]: SEVERITY.INFO,
  [SECURITY_EVENT_TYPES.API_KEY_REVOKED]: SEVERITY.INFO,
  [SECURITY_EVENT_TYPES.API_UNAUTHORIZED]: SEVERITY.WARNING,
};

// Event to alert event mapping
const EVENT_TO_ALERT = {
  [SECURITY_EVENT_TYPES.LOGIN_FAILED]: ALERT_EVENTS.AUTH_FAILED_THRESHOLD,
  [SECURITY_EVENT_TYPES.VAULT_UNLOCK_FAILED]: ALERT_EVENTS.VAULT_UNLOCK_FAILED_THRESHOLD,
  [SECURITY_EVENT_TYPES.VAULT_LOCKED_BY_ANOMALY]: ALERT_EVENTS.VAULT_LOCKED_BY_ANOMALY,
  [SECURITY_EVENT_TYPES.VAULT_PASSWORD_CHANGED]: ALERT_EVENTS.VAULT_PASSWORD_CHANGED,
  [SECURITY_EVENT_TYPES.RATE_LIMIT_AUTH]: ALERT_EVENTS.RATE_LIMIT_AUTH,
  [SECURITY_EVENT_TYPES.RATE_LIMIT_VAULT]: ALERT_EVENTS.RATE_LIMIT_VAULT,
  [SECURITY_EVENT_TYPES.ADMIN_USER_DELETED]: ALERT_EVENTS.ADMIN_USER_DELETED,
  [SECURITY_EVENT_TYPES.ADMIN_SETTINGS_CHANGED]: ALERT_EVENTS.ADMIN_SETTINGS_CHANGED,
  [SECURITY_EVENT_TYPES.GROUP_ADMIN_CHANGED]: ALERT_EVENTS.GROUP_ADMIN_CHANGED,
  [SECURITY_EVENT_TYPES.TOKEN_REVOKED_ALL]: ALERT_EVENTS.TOKEN_REVOKED_ALL,
  [SECURITY_EVENT_TYPES.ANOMALY_DETECTED]: ALERT_EVENTS.ANOMALY_DETECTED,
  [SECURITY_EVENT_TYPES.ANOMALY_CRITICAL]: ALERT_EVENTS.ANOMALY_CRITICAL,
};

// Title templates for alerts
const ALERT_TITLES = {
  [SECURITY_EVENT_TYPES.LOGIN_FAILED]: "Failed Login Attempt",
  [SECURITY_EVENT_TYPES.VAULT_UNLOCK_FAILED]: "Failed Vault Unlock Attempt",
  [SECURITY_EVENT_TYPES.VAULT_LOCKED_BY_ANOMALY]: "Vault Locked Due to Suspicious Activity",
  [SECURITY_EVENT_TYPES.VAULT_PASSWORD_CHANGED]: "Vault Password Changed",
  [SECURITY_EVENT_TYPES.RATE_LIMIT_AUTH]: "Authentication Rate Limit Exceeded",
  [SECURITY_EVENT_TYPES.RATE_LIMIT_VAULT]: "Vault Rate Limit Exceeded",
  [SECURITY_EVENT_TYPES.ADMIN_USER_DELETED]: "User Account Deleted by Admin",
  [SECURITY_EVENT_TYPES.ADMIN_SETTINGS_CHANGED]: "System Settings Changed",
  [SECURITY_EVENT_TYPES.GROUP_ADMIN_CHANGED]: "Group Admin Role Changed",
  [SECURITY_EVENT_TYPES.TOKEN_REVOKED_ALL]: "All Tokens Revoked",
  [SECURITY_EVENT_TYPES.ANOMALY_DETECTED]: "Unusual Activity Detected",
  [SECURITY_EVENT_TYPES.ANOMALY_CRITICAL]: "Critical: Suspicious Activity Detected",
};

/**
 * Log a security event and optionally trigger an alert
 * @param {string} type - Event type from SECURITY_EVENT_TYPES
 * @param {string|null} userId - User ID associated with the event
 * @param {object} details - Additional event details
 * @param {string|null} severity - Override default severity
 * @param {object} options - Additional options (groupId, ipAddress, userAgent, skipAlert)
 */
export async function logSecurityEvent(type, userId, details = {}, severity = null, options = {}) {
  const { groupId, ipAddress, userAgent, skipAlert = false } = options;

  // Determine severity (use provided, or look up default, or default to info)
  const effectiveSeverity = severity || EVENT_SEVERITY[type] || SEVERITY.INFO;

  try {
    // Store the event
    const event = await securityEvents.insert({
      type,
      userId,
      groupId,
      severity: effectiveSeverity,
      details,
      ipAddress,
      userAgent,
    });

    console.log(
      `[security-event] ${type} | user=${userId || "anon"} | severity=${effectiveSeverity}`,
    );

    // Check if this event should trigger an alert
    if (!skipAlert && EVENT_TO_ALERT[type]) {
      const alertEvent = EVENT_TO_ALERT[type];
      const title = ALERT_TITLES[type] || type;

      await triggerAlert({
        eventType: alertEvent,
        userId,
        groupId,
        title,
        message: formatAlertMessage(type, details),
        severity: effectiveSeverity,
        metadata: {
          ...details,
          ipAddress,
          userAgent,
          securityEventId: event.id,
        },
      });
    }

    return event;
  } catch (err) {
    console.error(`[security-event] Failed to log event ${type}:`, err.message);
    // Don't throw - logging should not break the main flow
    return null;
  }
}

/**
 * Format alert message from event details
 */
function formatAlertMessage(type, details) {
  switch (type) {
    case SECURITY_EVENT_TYPES.LOGIN_FAILED:
      return `A login attempt failed${details.email ? ` for ${details.email}` : ""}.${details.reason ? ` Reason: ${details.reason}` : ""}`;

    case SECURITY_EVENT_TYPES.VAULT_UNLOCK_FAILED:
      return "A vault unlock attempt failed. If this wasn't you, please review your account security.";

    case SECURITY_EVENT_TYPES.VAULT_LOCKED_BY_ANOMALY:
      return "Your vault has been locked due to suspicious activity. Please verify your identity to unlock.";

    case SECURITY_EVENT_TYPES.VAULT_PASSWORD_CHANGED:
      return "Your vault password was changed. If this wasn't you, please contact support immediately.";

    case SECURITY_EVENT_TYPES.RATE_LIMIT_AUTH:
      return `Authentication rate limit exceeded.${details.ipAddress ? ` IP: ${details.ipAddress}` : ""}`;

    case SECURITY_EVENT_TYPES.RATE_LIMIT_VAULT:
      return "Multiple failed vault unlock attempts detected. Access has been temporarily restricted.";

    case SECURITY_EVENT_TYPES.ADMIN_USER_DELETED:
      return `A user account was deleted by an admin.${details.deletedEmail ? ` Email: ${details.deletedEmail}` : ""}`;

    case SECURITY_EVENT_TYPES.ADMIN_SETTINGS_CHANGED:
      return `System settings were modified.${details.setting ? ` Setting: ${details.setting}` : ""}`;

    case SECURITY_EVENT_TYPES.GROUP_ADMIN_CHANGED:
      return `Admin role was changed in a group.${details.groupName ? ` Group: ${details.groupName}` : ""}`;

    case SECURITY_EVENT_TYPES.TOKEN_REVOKED_ALL:
      return "All active tokens have been revoked. You may need to re-authenticate on all devices.";

    case SECURITY_EVENT_TYPES.ANOMALY_DETECTED:
      return `Unusual activity detected: ${details.description || "Please review your recent activity."}`;

    case SECURITY_EVENT_TYPES.ANOMALY_CRITICAL:
      return `Critical security alert: ${details.description || "Immediate action may be required."}`;

    default:
      return details.message || `Security event: ${type}`;
  }
}

/**
 * Helper to extract IP and user agent from Express request
 */
export function getRequestContext(req) {
  const forwardedFor = req.headers["x-forwarded-for"];
  const ipAddress = forwardedFor
    ? forwardedFor.split(",")[0].trim()
    : req.ip || req.socket?.remoteAddress;

  return {
    ipAddress,
    userAgent: req.headers["user-agent"],
  };
}

/**
 * Convenience function for logging from a request context
 */
export async function logFromRequest(req, type, details = {}, severity = null) {
  const { ipAddress, userAgent } = getRequestContext(req);
  return logSecurityEvent(type, req.user?.id, details, severity, {
    ipAddress,
    userAgent,
    groupId: details.groupId,
  });
}

export default {
  logSecurityEvent,
  logFromRequest,
  getRequestContext,
  SECURITY_EVENT_TYPES,
  SEVERITY,
};
