// Database module - unified exports
// All modules are split into separate files for maintainability

// Core database utilities
export {
  query,
  encrypt,
  decrypt,
  pool,
  getKeyVersion,
  needsReEncryption,
  reEncrypt,
} from "./core.js";
export { default } from "./core.js";

// User management
export { users } from "./users.js";

// Audit logging
export { audit } from "./audit.js";

// Sessions and magic links
export { sessions, magicLinks } from "./sessions.js";

// Usage tracking
export { usage } from "./usage.js";

// Integrations (OAuth, API keys)
export { integrations } from "./integrations.js";

// Device keys (WebAuthn/biometrics)
export { deviceKeys } from "./device-keys.js";

// Permissions
export {
  PERMISSION_LEVELS,
  DEFAULT_PERMISSIONS,
  FULL_PERMISSIONS,
  normalizePermissions,
  hasPermission,
  hasAnyPermission,
  hasAllPermissions,
  getRequiredPermissionForMethod,
} from "./permissions.js";

// Groups (renamed from organizations)
export { groups, groupMemberships, groupResources } from "./groups.js";

// Shares (unified from org_grants + peer_grants)
export { shares, peerGrants } from "./shares.js";

// Resource shares (peer-to-peer integration sharing)
export { resourceShares } from "./resource-shares.js";

// Group invites (renamed from org_invites)
export { groupInvites } from "./group-invites.js";

// Capability approvals
export { capabilityApprovals } from "./approvals.js";

// Agent activity and anomaly detection
export { agentActivity, agentBaselines, anomalyAlerts } from "./agent.js";

// Notifications
export { notifications } from "./notifications.js";

// Recovery methods
export { recoveryMethods, recoveryContacts, recoveryRequests, recoveryShards } from "./recovery.js";

// Group vault and threshold unlock (renamed from org vault)
export {
  groupUnlockRequests,
  groupThreshold,
  groupVaults,
  groupVaultAudit,
  groupVaultTokens,
} from "./group-vault.js";

// Revocations
export { capabilityRevocations, groupTokenRevocations } from "./revocations.js";

// Mesh audit logs
export { MESH_AUDIT_EVENTS, meshAuditLogs } from "./mesh-audit.js";

// MFA (Multi-Factor Authentication)
export { userMfa, mfaBackupCodes, mfaAttempts, pendingMfaSessions } from "./mfa.js";

// Admin security (IP allowlist, settings, emergency tokens)
export {
  adminIpAllowlist,
  adminSecuritySettings,
  adminActionConfirmations,
  emergencyAccessTokens,
  adminSessions,
  getIpAllowlist,
  addIpToAllowlist,
  removeFromAllowlist,
  isIpAllowed,
} from "./admin.js";

// Security events and alerting
export {
  securityEvents,
  alertRules,
  alertChannels,
  alertHistory,
  alertCooldowns,
} from "./security-events.js";

// Tenants (multi-tenant SaaS)
export { tenants, tenantMemberships } from "./tenants.js";

// API keys for multi-tenant authentication
export { apiKeys } from "./api-keys.js";

// Subscriptions and billing (multi-tenant SaaS)
export { subscriptions, SUBSCRIPTION_PLANS, SUBSCRIPTION_STATUSES } from "./subscriptions.js";

// Tenant-scoped query builder (multi-tenant data isolation)
export {
  // Safety checks
  assertTenantContext,
  validateTenantOwnership,
  requireTenantOwnership,
  filterByTenant,
  // Query scoping functions
  tenantScoped,
  withTenantId,
  scopeWhere,
  // SQL builders
  buildSelect,
  buildInsert,
  buildUpdate,
  buildDelete,
  // Query execution helpers
  queryScoped,
  findByIdScoped,
  existsInTenant,
  countScoped,
  selectScoped,
  insertScoped,
  updateScoped,
  deleteScoped,
  // Advanced helpers
  findAllScoped,
  findOneScoped,
  createScopedTable,
  // Error classes
  TenantContextError,
  TenantIsolationError,
} from "./query-builder.js";

// Tenant branding (white-label customization)
export {
  tenantBranding,
  generateBrandingCss,
  invalidateCssCache,
  getBrandedEmailTemplate,
  DEFAULT_BRANDING,
  ALLOWED_CSS_PROPERTIES,
  ASSET_SIZE_LIMITS,
  ALLOWED_IMAGE_TYPES,
  isValidHexColor,
  isValidUrl,
  sanitizeCustomCss,
  sanitizeEmailHtml,
  validateBranding,
} from "./tenant-branding.js";
