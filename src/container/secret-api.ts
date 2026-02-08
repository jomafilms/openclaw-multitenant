/**
 * Container Secret Store API
 *
 * HTTP endpoints for unlocking the vault and managing capabilities.
 * These run INSIDE each user's container.
 */

import { randomBytes, createHmac, timingSafeEqual } from "crypto";
import {
  ContainerVaultService,
  type VaultChallenge,
  type VaultStatus as SessionVaultStatus,
  getVaultService,
  initVaultService,
} from "../services/vault-service.js";
import { getSecretStore, type SecretStore } from "./secret-store.js";

// Challenge storage for unlock flow
const pendingChallenges = new Map<string, { challenge: string; expires: number }>();
const CHALLENGE_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

// Cleanup expired challenges
setInterval(() => {
  const now = Date.now();
  for (const [id, data] of pendingChallenges) {
    if (data.expires < now) {
      pendingChallenges.delete(id);
    }
  }
}, 60 * 1000);

export interface UnlockChallengeResponse {
  challengeId: string;
  challenge: string;
  salt: string | null;
}

export interface UnlockVerifyRequest {
  challengeId: string;
  response: string; // HMAC(challenge, derivedKey)
  derivedKey: string; // Base64-encoded derived key
}

export interface UnlockVerifyResponse {
  success: boolean;
  expiresIn?: number;
  error?: string;
}

/**
 * Generate an unlock challenge
 * Called by: Browser/Mobile app directly to container
 */
export function generateUnlockChallenge(): UnlockChallengeResponse {
  const store = getSecretStore();
  const salt = store.getSalt();

  const challengeId = randomBytes(16).toString("hex");
  const challenge = randomBytes(32).toString("base64");

  pendingChallenges.set(challengeId, {
    challenge,
    expires: Date.now() + CHALLENGE_TIMEOUT_MS,
  });

  return { challengeId, challenge, salt };
}

/**
 * Verify challenge response and unlock vault
 * Called by: Browser/Mobile app directly to container
 */
export async function verifyUnlockChallenge(
  req: UnlockVerifyRequest,
): Promise<UnlockVerifyResponse> {
  const { challengeId, response, derivedKey } = req;

  // Get pending challenge
  const pending = pendingChallenges.get(challengeId);
  if (!pending) {
    return { success: false, error: "Invalid or expired challenge" };
  }

  // Check expiry
  if (pending.expires < Date.now()) {
    pendingChallenges.delete(challengeId);
    return { success: false, error: "Challenge expired" };
  }

  // Verify response: HMAC(challenge, derivedKey) should match
  const keyBuffer = Buffer.from(derivedKey, "base64");
  const expectedResponse = createHmac("sha256", keyBuffer)
    .update(pending.challenge)
    .digest("base64");

  if (!timingSafeEqual(Buffer.from(response), Buffer.from(expectedResponse))) {
    return { success: false, error: "Invalid response" };
  }

  // Remove used challenge
  pendingChallenges.delete(challengeId);

  // Unlock the store
  const store = getSecretStore();
  const unlocked = await store.unlockWithKey(keyBuffer);

  if (!unlocked) {
    return { success: false, error: "Failed to unlock vault" };
  }

  return {
    success: true,
    expiresIn: store.getSessionTimeRemaining(),
  };
}

/**
 * Get vault status
 */
export function getVaultStatus(): {
  initialized: boolean;
  locked: boolean;
  expiresIn: number;
  publicKey: string | null;
} {
  const store = getSecretStore();
  const salt = store.getSalt();

  return {
    initialized: salt !== null,
    locked: !store.isUnlocked(),
    expiresIn: store.getSessionTimeRemaining(),
    publicKey: store.getPublicKey(),
  };
}

/**
 * Lock the vault
 */
export function lockVault(): { success: boolean } {
  const store = getSecretStore();
  store.lock();
  return { success: true };
}

/**
 * Extend vault session
 */
export function extendSession(): { success: boolean; expiresIn: number } {
  const store = getSecretStore();

  if (!store.isUnlocked()) {
    throw new Error("Vault is locked");
  }

  store.extendSession();
  return {
    success: true,
    expiresIn: store.getSessionTimeRemaining(),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration Management
// ─────────────────────────────────────────────────────────────────────────────

export async function setIntegration(
  provider: string,
  integration: {
    accessToken: string;
    refreshToken?: string;
    expiresAt: string;
    email?: string;
    scopes?: string[];
  },
): Promise<{ success: boolean }> {
  const store = getSecretStore();
  await store.setIntegration(provider, integration);
  return { success: true };
}

export function getIntegration(provider: string): {
  success: boolean;
  integration?: unknown;
  error?: string;
} {
  const store = getSecretStore();

  if (!store.isUnlocked()) {
    return { success: false, error: "Vault is locked" };
  }

  const integration = store.getIntegration(provider);
  if (!integration) {
    return { success: false, error: "Integration not found" };
  }

  return { success: true, integration };
}

export function listIntegrations(): {
  success: boolean;
  integrations?: Array<{ provider: string; email?: string; expiresAt: string }>;
  error?: string;
} {
  const store = getSecretStore();

  if (!store.isUnlocked()) {
    return { success: false, error: "Vault is locked" };
  }

  return {
    success: true,
    integrations: store.listIntegrations(),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// API Key Management (Zero-Knowledge)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * API key credential structure.
 * Stored encrypted in the container vault.
 */
export interface ApiKeyCredential {
  provider: string;
  apiKey: string;
  addedAt: string;
  metadata?: Record<string, unknown>;
}

/**
 * List of supported API key providers.
 * These are distinct from OAuth integrations.
 */
export const API_KEY_PROVIDERS = ["github", "anthropic", "openai"] as const;
export type ApiKeyProvider = (typeof API_KEY_PROVIDERS)[number];

/**
 * Store an API key in the container vault.
 * The key is encrypted at rest and only decrypted when vault is unlocked.
 * Management server NEVER sees the plaintext key.
 */
export async function setApiKey(
  provider: ApiKeyProvider,
  apiKey: string,
  metadata?: Record<string, unknown>,
): Promise<{ success: boolean; error?: string }> {
  const store = getSecretStore();

  if (!store.isUnlocked()) {
    return { success: false, error: "Vault is locked" };
  }

  if (!API_KEY_PROVIDERS.includes(provider)) {
    return { success: false, error: `Invalid provider: ${provider}` };
  }

  try {
    // Store as an integration with a special marker
    await store.setIntegration(`apikey:${provider}`, {
      accessToken: apiKey,
      expiresAt: "9999-12-31T23:59:59.999Z", // API keys don't expire (from our perspective)
      metadata: {
        ...metadata,
        type: "api_key",
        provider,
        addedAt: new Date().toISOString(),
      },
    });

    return { success: true };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  }
}

/**
 * Get an API key from the container vault.
 * Requires vault to be unlocked.
 * Returns the plaintext API key for use by the agent.
 */
export function getApiKey(provider: ApiKeyProvider): {
  success: boolean;
  apiKey?: string;
  addedAt?: string;
  error?: string;
} {
  const store = getSecretStore();

  if (!store.isUnlocked()) {
    return { success: false, error: "Vault is locked" };
  }

  if (!API_KEY_PROVIDERS.includes(provider)) {
    return { success: false, error: `Invalid provider: ${provider}` };
  }

  try {
    const integration = store.getIntegration(`apikey:${provider}`);
    if (!integration) {
      return { success: false, error: `No API key found for ${provider}` };
    }

    return {
      success: true,
      apiKey: integration.accessToken,
      addedAt: (integration.metadata?.addedAt as string) || undefined,
    };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  }
}

/**
 * List all stored API keys (without exposing the actual keys).
 * Returns provider names and when they were added.
 */
export function listApiKeys(): {
  success: boolean;
  keys?: Array<{ provider: ApiKeyProvider; addedAt: string }>;
  error?: string;
} {
  const store = getSecretStore();

  if (!store.isUnlocked()) {
    return { success: false, error: "Vault is locked" };
  }

  try {
    const allIntegrations = store.listIntegrations();
    const apiKeys = allIntegrations
      .filter((i) => i.provider.startsWith("apikey:"))
      .map((i) => ({
        provider: i.provider.replace("apikey:", "") as ApiKeyProvider,
        addedAt: i.expiresAt, // We store addedAt in metadata, but this is close enough
      }));

    return { success: true, keys: apiKeys };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  }
}

/**
 * Remove an API key from the container vault.
 */
export async function removeApiKey(provider: ApiKeyProvider): Promise<{
  success: boolean;
  error?: string;
}> {
  const store = getSecretStore();

  if (!store.isUnlocked()) {
    return { success: false, error: "Vault is locked" };
  }

  if (!API_KEY_PROVIDERS.includes(provider)) {
    return { success: false, error: `Invalid provider: ${provider}` };
  }

  try {
    await store.removeIntegration(`apikey:${provider}`);
    return { success: true };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  }
}

/**
 * Check if an API key exists for a provider (without returning the key).
 */
export function hasApiKey(provider: ApiKeyProvider): {
  success: boolean;
  exists?: boolean;
  error?: string;
} {
  const store = getSecretStore();

  if (!store.isUnlocked()) {
    return { success: false, error: "Vault is locked" };
  }

  if (!API_KEY_PROVIDERS.includes(provider)) {
    return { success: false, error: `Invalid provider: ${provider}` };
  }

  try {
    const integration = store.getIntegration(`apikey:${provider}`);
    return { success: true, exists: integration !== null };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Capability Management
// ─────────────────────────────────────────────────────────────────────────────

export async function issueCapability(req: {
  subjectPublicKey: string;
  resource: string;
  scope: string[];
  expiresInSeconds: number;
  maxCalls?: number;
  tier?: "LIVE" | "CACHED" | "DELEGATED";
  subjectEncryptionKey?: string;
  cacheRefreshInterval?: number;
}): Promise<{
  success: boolean;
  id?: string;
  token?: string;
  snapshot?: unknown;
  error?: string;
}> {
  const store = getSecretStore();

  if (!store.isUnlocked()) {
    return { success: false, error: "Vault is locked" };
  }

  try {
    const result = await store.issueCapability(
      req.subjectPublicKey,
      req.resource,
      req.scope,
      req.expiresInSeconds,
      {
        maxCalls: req.maxCalls,
        tier: req.tier,
        subjectEncryptionKey: req.subjectEncryptionKey,
        cacheRefreshInterval: req.cacheRefreshInterval,
      },
    );

    return {
      success: true,
      id: result.id,
      token: result.token,
      snapshot: result.snapshot,
    };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  }
}

export async function revokeCapability(id: string): Promise<{ success: boolean; error?: string }> {
  const store = getSecretStore();

  if (!store.isUnlocked()) {
    return { success: false, error: "Vault is locked" };
  }

  try {
    await store.revokeCapability(id);
    return { success: true };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  }
}

export function listCapabilities(type: "issued" | "received"): {
  success: boolean;
  capabilities?: unknown[];
  error?: string;
} {
  const store = getSecretStore();

  if (!store.isUnlocked()) {
    return { success: false, error: "Vault is locked" };
  }

  const capabilities =
    type === "issued" ? store.listIssuedCapabilities() : store.listReceivedCapabilities();

  return { success: true, capabilities };
}

export async function executeCapability(req: {
  token: string;
  operation: string;
  params: Record<string, unknown>;
}): Promise<{ success: boolean; result?: unknown; error?: string }> {
  const store = getSecretStore();

  if (!store.isUnlocked()) {
    return { success: false, error: "Vault is locked" };
  }

  try {
    const result = await store.executeCapability(req.token, req.operation, req.params);

    return { success: true, result };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// CACHED Tier Management
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Refresh all CACHED tier snapshots that are due.
 */
export async function refreshCachedSnapshots(): Promise<{
  success: boolean;
  refreshed?: number;
  error?: string;
}> {
  const store = getSecretStore();

  if (!store.isUnlocked()) {
    return { success: false, error: "Vault is locked" };
  }

  try {
    const snapshots = await store.refreshCachedSnapshots();
    return { success: true, refreshed: snapshots.length };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  }
}

/**
 * Push pending snapshots to the relay.
 */
export async function pushSnapshotsToRelay(): Promise<{
  success: boolean;
  pushed?: number;
  failed?: number;
  errors?: string[];
  error?: string;
}> {
  const store = getSecretStore();

  if (!store.isUnlocked()) {
    return { success: false, error: "Vault is locked" };
  }

  try {
    const result = await store.pushSnapshotsToRelay();
    return {
      success: true,
      pushed: result.pushed,
      failed: result.failed,
      errors: result.errors,
    };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  }
}

/**
 * Access a CACHED capability's data (tries relay first, falls back to local cache).
 */
export async function accessCachedCapability(capabilityId: string): Promise<{
  success: boolean;
  data?: Record<string, unknown>;
  source?: "live" | "cache";
  updatedAt?: string;
  staleness?: number;
  error?: string;
}> {
  const store = getSecretStore();

  if (!store.isUnlocked()) {
    return { success: false, error: "Vault is locked" };
  }

  try {
    const result = await store.accessCachedCapability(capabilityId);
    if (!result) {
      return { success: false, error: "No cached data available" };
    }

    return {
      success: true,
      data: result.data,
      source: result.source,
      updatedAt: result.updatedAt,
      staleness: result.staleness,
    };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  }
}

/**
 * Get the user's public keys for sharing.
 */
export function getPublicKeys(): {
  success: boolean;
  signingKey?: string;
  encryptionKey?: string;
  error?: string;
} {
  const store = getSecretStore();

  if (!store.isUnlocked()) {
    return { success: false, error: "Vault is locked" };
  }

  const keys = store.getPublicKeys();
  if (!keys) {
    return { success: false, error: "No keys available" };
  }

  return {
    success: true,
    signingKey: keys.signingKey,
    encryptionKey: keys.encryptionKey,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Agent Capability Ceiling Management
// ─────────────────────────────────────────────────────────────────────────────

import {
  type PermissionLevel,
  type CeilingRole,
  type AgentCeilingConfig,
  type EscalationRequest,
  CeilingExceededError,
  InsufficientPermissionsError,
  CEILING_ROLES,
  getCeilingForRole,
} from "./capability-ceiling.js";

/**
 * Issue a capability as an agent with ceiling validation.
 * If the agent tries to grant permissions above their ceiling, this will either
 * throw an error or create an escalation request (if requestEscalation is true).
 */
export async function issueCapabilityAsAgent(req: {
  agentId: string;
  subjectPublicKey: string;
  resource: string;
  scope: string[];
  expiresInSeconds: number;
  maxCalls?: number;
  tier?: "LIVE" | "CACHED" | "DELEGATED";
  subjectEncryptionKey?: string;
  cacheRefreshInterval?: number;
  requestEscalation?: boolean;
}): Promise<{
  success: boolean;
  id?: string;
  token?: string;
  snapshot?: unknown;
  escalationRequest?: EscalationRequest;
  requiresApproval?: boolean;
  error?: string;
}> {
  const store = getSecretStore();

  if (!store.isUnlocked()) {
    return { success: false, error: "Vault is locked" };
  }

  try {
    const result = await store.issueCapabilityAsAgent(
      req.agentId,
      req.subjectPublicKey,
      req.resource,
      req.scope,
      req.expiresInSeconds,
      {
        maxCalls: req.maxCalls,
        tier: req.tier,
        subjectEncryptionKey: req.subjectEncryptionKey,
        cacheRefreshInterval: req.cacheRefreshInterval,
        requestEscalation: req.requestEscalation,
      },
    );

    return {
      success: true,
      id: result.id,
      token: result.token,
      snapshot: result.snapshot,
      escalationRequest: result.escalationRequest,
      requiresApproval: result.requiresApproval,
    };
  } catch (err) {
    if (err instanceof CeilingExceededError) {
      return {
        success: false,
        error: err.message,
        requiresApproval: true,
      };
    }
    return { success: false, error: (err as Error).message };
  }
}

/**
 * Get the ceiling for an agent.
 */
export function getAgentCeiling(agentId: string): {
  success: boolean;
  ceiling?: PermissionLevel[];
  error?: string;
} {
  const store = getSecretStore();

  if (!store.isUnlocked()) {
    return { success: false, error: "Vault is locked" };
  }

  try {
    const ceilingManager = store.getCeilingManager();
    const ceiling = ceilingManager.getAgentCeiling(agentId);
    return { success: true, ceiling };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  }
}

/**
 * Set the ceiling for an agent.
 * Optionally validates that the user setting the ceiling has the required permissions.
 */
export async function setAgentCeiling(req: {
  agentId: string;
  ceiling: PermissionLevel[];
  setBy: string;
  reason?: string;
  validateUserPermissions?: boolean;
}): Promise<{ success: boolean; error?: string }> {
  const store = getSecretStore();

  if (!store.isUnlocked()) {
    return { success: false, error: "Vault is locked" };
  }

  try {
    const ceilingManager = store.getCeilingManager();

    if (req.validateUserPermissions) {
      await ceilingManager.setAgentCeilingWithValidation(
        req.agentId,
        req.ceiling,
        req.setBy,
        req.reason,
      );
    } else {
      await ceilingManager.setAgentCeiling(req.agentId, req.ceiling, req.setBy, req.reason);
    }

    return { success: true };
  } catch (err) {
    if (err instanceof InsufficientPermissionsError) {
      return { success: false, error: err.message };
    }
    return { success: false, error: (err as Error).message };
  }
}

/**
 * Set an agent ceiling from a predefined role.
 */
export async function setAgentCeilingFromRole(req: {
  agentId: string;
  role: CeilingRole;
  setBy: string;
  reason?: string;
  validateUserPermissions?: boolean;
}): Promise<{ success: boolean; error?: string }> {
  const store = getSecretStore();

  if (!store.isUnlocked()) {
    return { success: false, error: "Vault is locked" };
  }

  try {
    const ceilingManager = store.getCeilingManager();
    const ceiling = getCeilingForRole(req.role);

    if (req.validateUserPermissions) {
      await ceilingManager.setAgentCeilingWithValidation(
        req.agentId,
        ceiling,
        req.setBy,
        req.reason,
      );
    } else {
      await ceilingManager.setAgentCeiling(req.agentId, ceiling, req.setBy, req.reason);
    }

    return { success: true };
  } catch (err) {
    if (err instanceof InsufficientPermissionsError) {
      return { success: false, error: err.message };
    }
    return { success: false, error: (err as Error).message };
  }
}

/**
 * Remove an agent's ceiling configuration (revert to default).
 */
export async function removeAgentCeiling(agentId: string): Promise<{
  success: boolean;
  error?: string;
}> {
  const store = getSecretStore();

  if (!store.isUnlocked()) {
    return { success: false, error: "Vault is locked" };
  }

  try {
    const ceilingManager = store.getCeilingManager();
    await ceilingManager.removeAgentCeiling(agentId);
    return { success: true };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  }
}

/**
 * List all agent ceiling configurations.
 */
export function listAgentCeilings(): {
  success: boolean;
  ceilings?: AgentCeilingConfig[];
  error?: string;
} {
  const store = getSecretStore();

  if (!store.isUnlocked()) {
    return { success: false, error: "Vault is locked" };
  }

  try {
    const ceilingManager = store.getCeilingManager();
    return { success: true, ceilings: ceilingManager.listAgentCeilings() };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  }
}

/**
 * List escalation requests, optionally filtered by status.
 */
export function listEscalationRequests(status?: "pending" | "approved" | "denied"): {
  success: boolean;
  requests?: EscalationRequest[];
  error?: string;
} {
  const store = getSecretStore();

  if (!store.isUnlocked()) {
    return { success: false, error: "Vault is locked" };
  }

  try {
    const ceilingManager = store.getCeilingManager();
    return { success: true, requests: ceilingManager.listEscalationRequests(status) };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  }
}

/**
 * Approve an escalation request and issue the capability.
 * Optionally validates that the approving user has the required permissions.
 */
export async function approveEscalationRequest(req: {
  escalationRequestId: string;
  approvedBy: string;
  validateUserPermissions?: boolean;
  tier?: "LIVE" | "CACHED" | "DELEGATED";
  subjectEncryptionKey?: string;
  cacheRefreshInterval?: number;
}): Promise<{
  success: boolean;
  id?: string;
  token?: string;
  snapshot?: unknown;
  error?: string;
}> {
  const store = getSecretStore();

  if (!store.isUnlocked()) {
    return { success: false, error: "Vault is locked" };
  }

  try {
    const ceilingManager = store.getCeilingManager();

    // Approve the escalation request
    if (req.validateUserPermissions) {
      await ceilingManager.approveEscalationRequestWithValidation(
        req.escalationRequestId,
        req.approvedBy,
      );
    } else {
      await ceilingManager.approveEscalationRequest(req.escalationRequestId, req.approvedBy);
    }

    // Issue the capability
    const result = await store.approveEscalationAndIssue(req.escalationRequestId, req.approvedBy, {
      tier: req.tier,
      subjectEncryptionKey: req.subjectEncryptionKey,
      cacheRefreshInterval: req.cacheRefreshInterval,
    });

    return {
      success: true,
      id: result.id,
      token: result.token,
      snapshot: result.snapshot,
    };
  } catch (err) {
    if (err instanceof InsufficientPermissionsError) {
      return { success: false, error: err.message };
    }
    return { success: false, error: (err as Error).message };
  }
}

/**
 * Deny an escalation request.
 */
export async function denyEscalationRequest(req: {
  escalationRequestId: string;
  deniedBy: string;
  reason?: string;
}): Promise<{ success: boolean; error?: string }> {
  const store = getSecretStore();

  if (!store.isUnlocked()) {
    return { success: false, error: "Vault is locked" };
  }

  try {
    const ceilingManager = store.getCeilingManager();
    await ceilingManager.denyEscalationRequest(req.escalationRequestId, req.deniedBy, req.reason);
    return { success: true };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  }
}

/**
 * Get available ceiling roles.
 */
export function getCeilingRoles(): {
  success: boolean;
  roles?: Record<CeilingRole, PermissionLevel[]>;
} {
  return {
    success: true,
    roles: { ...CEILING_ROLES } as Record<CeilingRole, PermissionLevel[]>,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Encrypted Session Store Management
// ─────────────────────────────────────────────────────────────────────────────

let sessionVaultService: ContainerVaultService | null = null;

/**
 * Initialize the encrypted session store.
 * Call this during container startup.
 */
export async function initializeSessionVault(
  sessionDir: string,
): Promise<{ salt: string; isNew: boolean }> {
  sessionVaultService = new ContainerVaultService({ sessionDir });
  return sessionVaultService.initialize();
}

/**
 * Get the session vault service instance.
 */
export function getSessionVaultService(): ContainerVaultService | null {
  return sessionVaultService;
}

/**
 * Get challenge (salt + KDF params) for session encryption.
 * Browser uses this to derive the encryption key.
 */
export function getSessionChallenge(): {
  success: boolean;
  challenge?: VaultChallenge;
  error?: string;
} {
  if (!sessionVaultService) {
    return { success: false, error: "Session vault not initialized" };
  }

  try {
    const challenge = sessionVaultService.getChallenge();
    return { success: true, challenge };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  }
}

/**
 * Unlock the session vault with a derived key.
 * Key is derived from password via Argon2id in the browser.
 */
export async function unlockSessionVault(derivedKey: string): Promise<{
  success: boolean;
  expiresIn?: number;
  error?: string;
}> {
  if (!sessionVaultService) {
    return { success: false, error: "Session vault not initialized" };
  }

  try {
    const keyBuffer = Buffer.from(derivedKey, "base64");
    const result = await sessionVaultService.unlock(keyBuffer);
    return { success: true, expiresIn: result.expiresIn };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  }
}

/**
 * Lock the session vault.
 */
export function lockSessionVault(): { success: boolean } {
  if (!sessionVaultService) {
    return { success: true }; // Already locked/not initialized
  }

  sessionVaultService.lock();
  return { success: true };
}

/**
 * Extend the session vault timeout.
 */
export function extendSessionVault(): {
  success: boolean;
  expiresIn?: number;
  error?: string;
} {
  if (!sessionVaultService) {
    return { success: false, error: "Session vault not initialized" };
  }

  const status = sessionVaultService.getStatus();
  if (status.locked) {
    return { success: false, error: "Session vault is locked" };
  }

  const result = sessionVaultService.extend();
  return { success: true, expiresIn: result.expiresIn };
}

/**
 * Get session vault status.
 */
export function getSessionVaultStatus(): {
  success: boolean;
  status?: SessionVaultStatus;
  error?: string;
} {
  if (!sessionVaultService) {
    return {
      success: true,
      status: {
        initialized: false,
        locked: true,
        expiresIn: null,
        sessionsEncrypted: false,
      },
    };
  }

  return { success: true, status: sessionVaultService.getStatus() };
}

/**
 * Migrate unencrypted sessions to encrypted format.
 */
export async function migrateSessionsToEncrypted(): Promise<{
  success: boolean;
  migrated?: number;
  failed?: string[];
  error?: string;
}> {
  if (!sessionVaultService) {
    return { success: false, error: "Session vault not initialized" };
  }

  const status = sessionVaultService.getStatus();
  if (status.locked) {
    return { success: false, error: "Session vault must be unlocked to migrate" };
  }

  try {
    const result = await sessionVaultService.migrateExistingSessions();
    return { success: true, migrated: result.migrated, failed: result.failed };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Biometric Key Management (device-based vault unlock)
// ─────────────────────────────────────────────────────────────────────────────

import {
  BiometricKeyStore,
  getBiometricKeyStore,
  initBiometricKeyStore,
} from "../services/biometric-keys.js";

let biometricKeyStore: BiometricKeyStore | null = null;

/**
 * Initialize the biometric key store with the session directory.
 */
function ensureBiometricKeyStore(sessionDir?: string): BiometricKeyStore | null {
  if (!biometricKeyStore && sessionDir) {
    biometricKeyStore = initBiometricKeyStore(sessionDir);
  }
  return biometricKeyStore;
}

/**
 * Enable biometric unlock for a device.
 * Requires the vault to be unlocked.
 */
export function enableBiometricDevice(params: {
  fingerprint: string;
  name: string;
  sessionDir?: string;
}): {
  success: boolean;
  deviceKey?: string;
  error?: string;
} {
  // Ensure session vault is unlocked
  if (!sessionVaultService) {
    return { success: false, error: "Session vault not initialized" };
  }

  const status = sessionVaultService.getStatus();
  if (status.locked) {
    return { success: false, error: "Vault must be unlocked to enable biometrics" };
  }

  // Initialize biometric store if needed
  const store = ensureBiometricKeyStore(params.sessionDir);
  if (!store) {
    return { success: false, error: "Failed to initialize biometric key store" };
  }

  // Get the current vault key from the session vault service
  const vaultKey = sessionVaultService.getUnlockKey();
  if (!vaultKey) {
    return { success: false, error: "Could not get vault key" };
  }

  try {
    // Unlock the biometric store with the vault key
    store.unlock(vaultKey);

    // Register the device
    const result = store.registerDevice(params.fingerprint, params.name);

    return { success: true, deviceKey: result.deviceKey };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  }
}

/**
 * Unlock vault using biometric device key.
 */
export async function unlockWithBiometricDevice(params: {
  fingerprint: string;
  deviceKey: string;
  sessionDir?: string;
}): Promise<{
  success: boolean;
  expiresIn?: number;
  error?: string;
}> {
  // Initialize biometric store if needed
  const store = ensureBiometricKeyStore(params.sessionDir);
  if (!store) {
    return { success: false, error: "Failed to initialize biometric key store" };
  }

  try {
    // Try to unlock with device key
    const vaultKey = store.unlockWithDeviceKey(params.fingerprint, params.deviceKey);
    if (!vaultKey) {
      return { success: false, error: "Invalid device key" };
    }

    // Use the vault key to unlock the session vault
    if (!sessionVaultService) {
      return { success: false, error: "Session vault not initialized" };
    }

    const result = await sessionVaultService.unlock(vaultKey);
    return { success: true, expiresIn: result.expiresIn };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  }
}

/**
 * List registered biometric devices.
 * Requires the vault to be unlocked.
 */
export function listBiometricDevices(sessionDir?: string): {
  success: boolean;
  devices?: Array<{
    fingerprint: string;
    name: string;
    registeredAt: number;
    lastUsedAt?: number;
  }>;
  error?: string;
} {
  // Ensure session vault is unlocked
  if (!sessionVaultService) {
    return { success: false, error: "Session vault not initialized" };
  }

  const status = sessionVaultService.getStatus();
  if (status.locked) {
    return { success: false, error: "Vault must be unlocked to list devices" };
  }

  const store = ensureBiometricKeyStore(sessionDir);
  if (!store) {
    return { success: true, devices: [] };
  }

  try {
    const devices = store.listDevices();
    return { success: true, devices };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  }
}

/**
 * Remove a biometric device.
 * Requires the vault to be unlocked.
 */
export function removeBiometricDevice(params: { fingerprint: string; sessionDir?: string }): {
  success: boolean;
  error?: string;
} {
  // Ensure session vault is unlocked
  if (!sessionVaultService) {
    return { success: false, error: "Session vault not initialized" };
  }

  const status = sessionVaultService.getStatus();
  if (status.locked) {
    return { success: false, error: "Vault must be unlocked to remove devices" };
  }

  const store = ensureBiometricKeyStore(params.sessionDir);
  if (!store) {
    return { success: true }; // No store = no devices = success
  }

  // Get the current vault key from the session vault service
  const vaultKey = sessionVaultService.getUnlockKey();
  if (!vaultKey) {
    return { success: false, error: "Could not get vault key" };
  }

  try {
    store.unlock(vaultKey);
    store.removeDevice(params.fingerprint);
    return { success: true };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// WebSocket Handler for direct browser unlock
// ─────────────────────────────────────────────────────────────────────────────

interface WebSocketMessage {
  id: string;
  type: string;
  [key: string]: unknown;
}

type WebSocketSend = (data: string) => void;

/**
 * Handle WebSocket messages for vault operations
 * This enables direct browser-to-container unlock without management server
 */
export async function handleVaultWebSocketMessage(
  message: WebSocketMessage,
  send: WebSocketSend,
): Promise<void> {
  const { id, type } = message;

  // Use a more permissive type to accept typed response objects
  const respond = <T extends object>(data: T) => {
    send(JSON.stringify({ id, ...data }));
  };

  try {
    switch (type) {
      case "vault:status":
        respond(getVaultStatus());
        break;

      case "vault:challenge":
        respond(generateUnlockChallenge());
        break;

      case "vault:verify": {
        const result = await verifyUnlockChallenge({
          challengeId: message.challengeId as string,
          response: message.response as string,
          derivedKey: message.derivedKey as string,
        });
        respond(result);
        break;
      }

      case "vault:lock":
        respond(lockVault());
        break;

      case "vault:extend":
        try {
          respond(extendSession());
        } catch (err) {
          respond({ success: false, error: (err as Error).message });
        }
        break;

      // Session vault operations (encrypted sessions)
      case "session:status":
        respond(getSessionVaultStatus());
        break;

      case "session:challenge":
        respond(getSessionChallenge());
        break;

      case "session:unlock": {
        const result = await unlockSessionVault(message.derivedKey as string);
        respond(result);
        break;
      }

      case "session:lock":
        respond(lockSessionVault());
        break;

      case "session:extend":
        respond(extendSessionVault());
        break;

      case "session:migrate": {
        const result = await migrateSessionsToEncrypted();
        respond(result);
        break;
      }

      // API key operations (zero-knowledge)
      case "apikey:set": {
        const result = await setApiKey(
          message.provider as ApiKeyProvider,
          message.apiKey as string,
          message.metadata as Record<string, unknown> | undefined,
        );
        respond(result);
        break;
      }

      case "apikey:get": {
        const result = getApiKey(message.provider as ApiKeyProvider);
        respond(result);
        break;
      }

      case "apikey:list":
        respond(listApiKeys());
        break;

      case "apikey:remove": {
        const result = await removeApiKey(message.provider as ApiKeyProvider);
        respond(result);
        break;
      }

      case "apikey:has": {
        const result = hasApiKey(message.provider as ApiKeyProvider);
        respond(result);
        break;
      }

      default:
        respond({ error: `Unknown message type: ${type}` });
    }
  } catch (err) {
    respond({ error: (err as Error).message });
  }
}

/**
 * Set up WebSocket server for vault operations
 * Call this when starting the container's internal server
 */
export function setupVaultWebSocket(server: unknown): void {
  // Dynamic import to avoid requiring ws if not used
  const { WebSocketServer } = require("ws");
  const wss = new WebSocketServer({ server, path: "/vault/ws" });

  wss.on(
    "connection",
    (ws: { on: (event: string, handler: (data: Buffer) => void) => void; send: WebSocketSend }) => {
      ws.on("message", async (data: Buffer) => {
        try {
          const message = JSON.parse(data.toString()) as WebSocketMessage;
          await handleVaultWebSocketMessage(message, (response) => ws.send(response));
        } catch (err) {
          ws.send(JSON.stringify({ error: "Invalid message format" }));
        }
      });
    },
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Express Router (if using Express in container)
// ─────────────────────────────────────────────────────────────────────────────

export function createSecretRouter() {
  // Dynamic import to avoid requiring express if not used
  const express = require("express");
  const router = express.Router();

  // Vault status
  router.get("/status", (_req: unknown, res: { json: (data: unknown) => void }) => {
    res.json(getVaultStatus());
  });

  // Generate unlock challenge
  router.post("/unlock/challenge", (_req: unknown, res: { json: (data: unknown) => void }) => {
    res.json(generateUnlockChallenge());
  });

  // Verify unlock challenge
  router.post(
    "/unlock/verify",
    async (req: { body: UnlockVerifyRequest }, res: { json: (data: unknown) => void }) => {
      const result = await verifyUnlockChallenge(req.body);
      res.json(result);
    },
  );

  // Lock vault
  router.post("/lock", (_req: unknown, res: { json: (data: unknown) => void }) => {
    res.json(lockVault());
  });

  // Extend session
  router.post("/extend", (_req: unknown, res: { json: (data: unknown) => void }) => {
    try {
      res.json(extendSession());
    } catch (err) {
      res.json({ success: false, error: (err as Error).message });
    }
  });

  // List integrations
  router.get("/integrations", (_req: unknown, res: { json: (data: unknown) => void }) => {
    res.json(listIntegrations());
  });

  // Get specific integration
  router.get(
    "/integrations/:provider",
    (req: { params: { provider: string } }, res: { json: (data: unknown) => void }) => {
      res.json(getIntegration(req.params.provider));
    },
  );

  // Issue capability
  router.post(
    "/capabilities/issue",
    async (
      req: { body: Parameters<typeof issueCapability>[0] },
      res: { json: (data: unknown) => void },
    ) => {
      res.json(await issueCapability(req.body));
    },
  );

  // Revoke capability
  router.post(
    "/capabilities/:id/revoke",
    async (req: { params: { id: string } }, res: { json: (data: unknown) => void }) => {
      res.json(await revokeCapability(req.params.id));
    },
  );

  // List capabilities
  router.get(
    "/capabilities/:type",
    (req: { params: { type: "issued" | "received" } }, res: { json: (data: unknown) => void }) => {
      res.json(listCapabilities(req.params.type));
    },
  );

  // Execute capability
  router.post(
    "/capabilities/execute",
    async (
      req: { body: Parameters<typeof executeCapability>[0] },
      res: { json: (data: unknown) => void },
    ) => {
      res.json(await executeCapability(req.body));
    },
  );

  // ─────────────────────────────────────────────────────────────────────────────
  // Session Vault Routes (encrypted session storage)
  // ─────────────────────────────────────────────────────────────────────────────

  // Session vault status
  router.get("/session/status", (_req: unknown, res: { json: (data: unknown) => void }) => {
    res.json(getSessionVaultStatus());
  });

  // Get session challenge (salt + KDF params)
  router.get("/session/challenge", (_req: unknown, res: { json: (data: unknown) => void }) => {
    res.json(getSessionChallenge());
  });

  // Unlock session vault with derived key
  router.post(
    "/session/unlock",
    async (req: { body: { derivedKey: string } }, res: { json: (data: unknown) => void }) => {
      if (!req.body?.derivedKey) {
        return res.json({ success: false, error: "derivedKey required" });
      }
      res.json(await unlockSessionVault(req.body.derivedKey));
    },
  );

  // Lock session vault
  router.post("/session/lock", (_req: unknown, res: { json: (data: unknown) => void }) => {
    res.json(lockSessionVault());
  });

  // Extend session vault timeout
  router.post("/session/extend", (_req: unknown, res: { json: (data: unknown) => void }) => {
    res.json(extendSessionVault());
  });

  // Migrate unencrypted sessions
  router.post("/session/migrate", async (_req: unknown, res: { json: (data: unknown) => void }) => {
    res.json(await migrateSessionsToEncrypted());
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // API Key Routes (Zero-Knowledge)
  // These enable MCP to retrieve API keys without management server decryption
  // ─────────────────────────────────────────────────────────────────────────────

  // List stored API keys (without exposing actual keys)
  router.get("/apikeys", (_req: unknown, res: { json: (data: unknown) => void }) => {
    res.json(listApiKeys());
  });

  // Store an API key
  router.post(
    "/apikeys/:provider",
    async (
      req: {
        params: { provider: string };
        body: { apiKey: string; metadata?: Record<string, unknown> };
      },
      res: { json: (data: unknown) => void },
    ) => {
      if (!req.body?.apiKey) {
        return res.json({ success: false, error: "apiKey required" });
      }
      res.json(
        await setApiKey(req.params.provider as ApiKeyProvider, req.body.apiKey, req.body.metadata),
      );
    },
  );

  // Get an API key
  router.get(
    "/apikeys/:provider",
    (req: { params: { provider: string } }, res: { json: (data: unknown) => void }) => {
      res.json(getApiKey(req.params.provider as ApiKeyProvider));
    },
  );

  // Check if an API key exists
  router.get(
    "/apikeys/:provider/exists",
    (req: { params: { provider: string } }, res: { json: (data: unknown) => void }) => {
      res.json(hasApiKey(req.params.provider as ApiKeyProvider));
    },
  );

  // Remove an API key
  router.delete(
    "/apikeys/:provider",
    async (req: { params: { provider: string } }, res: { json: (data: unknown) => void }) => {
      res.json(await removeApiKey(req.params.provider as ApiKeyProvider));
    },
  );

  return router;
}
