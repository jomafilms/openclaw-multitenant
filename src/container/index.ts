/**
 * Container-Side Security Module
 *
 * This module provides container-local secret storage and credential management.
 * All secrets stay within the container and never leave in plaintext.
 */

// Secret Store - encrypted local storage for user secrets
export {
  SecretStore,
  getSecretStore,
  type Integration,
  type Identity,
  type CapabilityGrant,
  type ReceivedCapability,
  type SecretStoreData,
} from "./secret-store.js";

// Secret Store API - HTTP endpoints for vault management
export {
  generateUnlockChallenge,
  verifyUnlockChallenge,
  getVaultStatus,
  lockVault,
  extendSession,
  setIntegration,
  getIntegration,
  listIntegrations,
  issueCapability,
  revokeCapability,
  listCapabilities,
  executeCapability,
  createSecretRouter,
  type UnlockChallengeResponse,
  type UnlockVerifyRequest,
  type UnlockVerifyResponse,
  // Agent Capability Ceiling APIs
  issueCapabilityAsAgent,
  getAgentCeiling,
  setAgentCeiling,
  setAgentCeilingFromRole,
  removeAgentCeiling,
  listAgentCeilings,
  listEscalationRequests,
  approveEscalationRequest,
  denyEscalationRequest,
  getCeilingRoles,
} from "./secret-api.js";

// Agent Credentials - interface for agents to access local credentials
export {
  createLocalCredentialProvider,
  getCredentialProvider,
  storeCredential,
  removeCredential,
  isCredentialExpired,
  toOAuthCredentials,
  type AgentCredential,
  type CredentialProvider,
} from "./agent-credentials.js";

// Capability Ceilings - hard limits on agent permissions
export {
  PERMISSION_LEVELS,
  DEFAULT_AGENT_CEILING,
  CEILING_ROLES,
  isValidPermission,
  getPermissionOrder,
  isWithinCeiling,
  partitionPermissions,
  getCeilingForRole,
  CeilingExceededError,
  InsufficientPermissionsError,
  CeilingManager,
  createEmptyCeilingStoreData,
  type PermissionLevel,
  type CeilingRole,
  type AgentCeilingConfig,
  type EscalationRequest,
  type CeilingStoreData,
  type UserPermissionConfig,
} from "./capability-ceiling.js";

// Key Rotation - secure key rotation for signing and encryption keys
export {
  KeyRotationManager,
  generateVersionedIdentity,
  generateKeyId,
  createInitialRotationState,
  createFreshRotationState,
  rotateVaultKey,
  identifyCapabilitiesNeedingReissue,
  publicKeyFromBase64,
  type KeyRotationState,
  type KeyRotationResult,
  type VersionedIdentity,
  type ArchivedKey,
  type KeyRotationNotification,
  type VaultKeyRotationParams,
  type VaultKeyRotationResult,
  type VersionedCapability,
} from "./key-rotation.js";
