/**
 * Capability Ceilings for Agents
 *
 * Agents have limited permissions - they can issue capability tokens for read/list
 * operations, but NOT for delete/admin/share-further. Escalation requires human approval.
 *
 * This implements hard limits on what autonomous agents can do with capability tokens.
 * Even if an agent is compromised or manipulated via prompt injection, it cannot exceed
 * these ceilings. This limits the damage from prompt injection attacks.
 */

import { randomBytes } from "crypto";

// ─────────────────────────────────────────────────────────────────────────────
// Permission Levels
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Permission levels for capability tokens, ordered from least to most privileged.
 * Agents have a "ceiling" - the maximum permissions they can grant without human approval.
 */
export const PERMISSION_LEVELS = [
  "read",
  "list",
  "write",
  "delete",
  "admin",
  "share-further",
] as const;
export type PermissionLevel = (typeof PERMISSION_LEVELS)[number];

/**
 * Permission level ordering for comparison.
 * Higher index = more privileged.
 */
const PERMISSION_ORDER: Record<PermissionLevel, number> = {
  read: 0,
  list: 1,
  write: 2,
  delete: 3,
  admin: 4,
  "share-further": 5,
};

// ─────────────────────────────────────────────────────────────────────────────
// Role-Based Ceiling Levels
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Predefined role-based ceiling levels.
 * These provide common permission sets that can be assigned to agents.
 */
export const CEILING_ROLES = {
  /** Most restrictive: read-only access */
  READONLY: ["read", "list"] as PermissionLevel[],

  /** Default agent ceiling: read and list only (safe for autonomous operation) */
  AGENT: ["read", "list"] as PermissionLevel[],

  /** Standard user: can read, list, and write */
  USER: ["read", "list", "write"] as PermissionLevel[],

  /** Power user: can read, list, write, and delete */
  POWER_USER: ["read", "list", "write", "delete"] as PermissionLevel[],

  /** Admin: full permissions except share-further */
  ADMIN: ["read", "list", "write", "delete", "admin"] as PermissionLevel[],

  /** Full access: all permissions including share-further (use with caution) */
  FULL: ["read", "list", "write", "delete", "admin", "share-further"] as PermissionLevel[],
} as const;

export type CeilingRole = keyof typeof CEILING_ROLES;

/**
 * Get ceiling permissions for a predefined role.
 */
export function getCeilingForRole(role: CeilingRole): PermissionLevel[] {
  return [...CEILING_ROLES[role]];
}

/**
 * Default ceiling for agents: can only grant read and list permissions.
 * Any higher permissions require human approval.
 */
export const DEFAULT_AGENT_CEILING: PermissionLevel[] = CEILING_ROLES.AGENT;

// ─────────────────────────────────────────────────────────────────────────────
// Permission Utilities
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Check if a permission level is valid.
 */
export function isValidPermission(permission: string): permission is PermissionLevel {
  return PERMISSION_LEVELS.includes(permission as PermissionLevel);
}

/**
 * Get the numeric order of a permission level.
 */
export function getPermissionOrder(permission: PermissionLevel): number {
  return PERMISSION_ORDER[permission];
}

/**
 * Check if all requested permissions are within a ceiling.
 * A permission is within ceiling if its order is <= the max ceiling order.
 */
export function isWithinCeiling(
  requestedPermissions: string[],
  ceiling: PermissionLevel[],
): boolean {
  if (ceiling.length === 0) return false;

  const maxCeilingOrder = Math.max(...ceiling.map((p) => PERMISSION_ORDER[p]));

  for (const perm of requestedPermissions) {
    if (!isValidPermission(perm)) {
      // Unknown permissions are treated as exceeding ceiling for safety
      return false;
    }
    if (PERMISSION_ORDER[perm] > maxCeilingOrder) {
      return false;
    }
  }

  return true;
}

/**
 * Partition permissions into those within ceiling and those that exceed it.
 */
export function partitionPermissions(
  requestedPermissions: string[],
  ceiling: PermissionLevel[],
): { grantable: PermissionLevel[]; escalated: string[] } {
  const maxCeilingOrder =
    ceiling.length > 0 ? Math.max(...ceiling.map((p) => PERMISSION_ORDER[p])) : -1;

  const grantable: PermissionLevel[] = [];
  const escalated: string[] = [];

  for (const perm of requestedPermissions) {
    if (!isValidPermission(perm)) {
      escalated.push(perm);
    } else if (PERMISSION_ORDER[perm] <= maxCeilingOrder) {
      grantable.push(perm);
    } else {
      escalated.push(perm);
    }
  }

  return { grantable, escalated };
}

// ─────────────────────────────────────────────────────────────────────────────
// Agent Ceiling Configuration
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Agent ceiling configuration - maximum permissions an agent can grant.
 */
export interface AgentCeilingConfig {
  /** Agent identifier (public key or agent ID) */
  agentId: string;
  /** Maximum permissions this agent can grant without human approval */
  ceiling: PermissionLevel[];
  /** Human-readable description of why this ceiling was set */
  reason?: string;
  /** When this ceiling was last modified */
  modifiedAt: string;
  /** Who set this ceiling (public key of the human who approved) */
  setBy?: string;
}

/**
 * Pending escalation request - agent requested permissions above their ceiling.
 */
export interface EscalationRequest {
  id: string;
  /** Agent requesting the escalation */
  agentId: string;
  /** Resource for the capability */
  resource: string;
  /** All requested permissions */
  requestedScope: string[];
  /** Permissions that are within ceiling (already grantable) */
  grantableScope: PermissionLevel[];
  /** Permissions that need human approval */
  escalatedScope: string[];
  /** Target for the capability */
  subjectPublicKey: string;
  /** Requested expiry in seconds */
  expiresInSeconds: number;
  /** Optional max calls */
  maxCalls?: number;
  /** When the request was created */
  createdAt: string;
  /** Status of the request */
  status: "pending" | "approved" | "denied";
  /** Human who resolved this request */
  resolvedBy?: string;
  /** When resolved */
  resolvedAt?: string;
  /** Denial reason if denied */
  denialReason?: string;
}

/**
 * Error thrown when an agent attempts to issue permissions above their ceiling.
 */
export class CeilingExceededError extends Error {
  constructor(
    public readonly agentId: string,
    public readonly requestedScope: string[],
    public readonly ceiling: PermissionLevel[],
    public readonly escalatedPermissions: string[],
    public readonly escalationRequestId?: string,
  ) {
    super(
      `Agent '${agentId}' attempted to grant permissions [${escalatedPermissions.join(", ")}] ` +
        `which exceed ceiling [${ceiling.join(", ")}]. Human approval required.`,
    );
    this.name = "CeilingExceededError";
  }
}

/**
 * Error thrown when a user attempts to grant permissions they don't have.
 */
export class InsufficientPermissionsError extends Error {
  constructor(
    public readonly userId: string,
    public readonly attemptedPermissions: string[],
    public readonly userPermissions: PermissionLevel[],
    public readonly exceededPermissions: string[],
  ) {
    super(
      `User '${userId}' cannot grant permissions [${exceededPermissions.join(", ")}] ` +
        `because they exceed their own permissions [${userPermissions.join(", ")}].`,
    );
    this.name = "InsufficientPermissionsError";
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Ceiling Store Data Types
// ─────────────────────────────────────────────────────────────────────────────

/**
 * User permission configuration.
 * Defines what permissions a user can grant to agents.
 */
export interface UserPermissionConfig {
  /** User identifier (public key) */
  userId: string;
  /** Permissions this user can grant to agents */
  grantablePermissions: PermissionLevel[];
  /** When this was last modified */
  modifiedAt: string;
  /** Role-based preset (if using one) */
  role?: CeilingRole;
}

/**
 * Data stored for capability ceiling management.
 * This is stored in the secret store alongside other secure data.
 */
export interface CeilingStoreData {
  /** Agent ceiling configurations */
  agentCeilings: Record<string, AgentCeilingConfig>;
  /** Pending escalation requests */
  escalationRequests: Record<string, EscalationRequest>;
  /** User permission configurations (what permissions users can grant) */
  userPermissions?: Record<string, UserPermissionConfig>;
}

/**
 * Create initial empty ceiling store data.
 */
export function createEmptyCeilingStoreData(): CeilingStoreData {
  return {
    agentCeilings: {},
    escalationRequests: {},
    userPermissions: {},
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Ceiling Manager
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Manages agent capability ceilings and escalation requests.
 */
export class CeilingManager {
  private data: CeilingStoreData;
  private onSave: () => Promise<void>;

  constructor(data: CeilingStoreData, onSave: () => Promise<void>) {
    this.data = data;
    this.onSave = onSave;
  }

  /**
   * Get the ceiling for an agent.
   * Returns the default ceiling if no specific ceiling is configured.
   */
  getAgentCeiling(agentId: string): PermissionLevel[] {
    const config = this.data.agentCeilings[agentId];
    return config?.ceiling ?? DEFAULT_AGENT_CEILING;
  }

  /**
   * Set or update the ceiling for an agent.
   * This requires human approval (the setBy parameter).
   */
  async setAgentCeiling(
    agentId: string,
    ceiling: PermissionLevel[],
    setBy: string,
    reason?: string,
  ): Promise<void> {
    // Validate all permissions
    for (const perm of ceiling) {
      if (!isValidPermission(perm)) {
        throw new Error(`Invalid permission level: ${perm}`);
      }
    }

    this.data.agentCeilings[agentId] = {
      agentId,
      ceiling,
      reason,
      modifiedAt: new Date().toISOString(),
      setBy,
    };

    await this.onSave();
  }

  /**
   * Remove ceiling configuration for an agent (revert to default).
   */
  async removeAgentCeiling(agentId: string): Promise<void> {
    delete this.data.agentCeilings[agentId];
    await this.onSave();
  }

  /**
   * List all agent ceiling configurations.
   */
  listAgentCeilings(): AgentCeilingConfig[] {
    return Object.values(this.data.agentCeilings);
  }

  /**
   * Validate that an agent can issue the requested permissions.
   * Throws CeilingExceededError if permissions exceed ceiling.
   */
  validateAgentPermissions(agentId: string, requestedScope: string[]): void {
    const ceiling = this.getAgentCeiling(agentId);

    if (!isWithinCeiling(requestedScope, ceiling)) {
      const { escalated } = partitionPermissions(requestedScope, ceiling);
      throw new CeilingExceededError(agentId, requestedScope, ceiling, escalated);
    }
  }

  /**
   * Create an escalation request for permissions that exceed an agent's ceiling.
   * Returns the escalation request ID.
   */
  async createEscalationRequest(
    agentId: string,
    resource: string,
    requestedScope: string[],
    subjectPublicKey: string,
    expiresInSeconds: number,
    maxCalls?: number,
  ): Promise<EscalationRequest> {
    const ceiling = this.getAgentCeiling(agentId);
    const { grantable, escalated } = partitionPermissions(requestedScope, ceiling);

    if (escalated.length === 0) {
      throw new Error("No escalation needed - all permissions are within ceiling");
    }

    const id = randomBytes(16).toString("hex");
    const request: EscalationRequest = {
      id,
      agentId,
      resource,
      requestedScope,
      grantableScope: grantable,
      escalatedScope: escalated,
      subjectPublicKey,
      expiresInSeconds,
      maxCalls,
      createdAt: new Date().toISOString(),
      status: "pending",
    };

    this.data.escalationRequests[id] = request;
    await this.onSave();

    return request;
  }

  /**
   * Get an escalation request by ID.
   */
  getEscalationRequest(id: string): EscalationRequest | null {
    return this.data.escalationRequests[id] ?? null;
  }

  /**
   * List all escalation requests, optionally filtered by status.
   */
  listEscalationRequests(status?: EscalationRequest["status"]): EscalationRequest[] {
    const requests = Object.values(this.data.escalationRequests);
    if (status) {
      return requests.filter((r) => r.status === status);
    }
    return requests;
  }

  /**
   * Approve an escalation request.
   * Returns the full approved scope (grantable + escalated).
   */
  async approveEscalationRequest(id: string, approvedBy: string): Promise<string[]> {
    const request = this.data.escalationRequests[id];
    if (!request) {
      throw new Error("Escalation request not found");
    }

    if (request.status !== "pending") {
      throw new Error(`Escalation request is already ${request.status}`);
    }

    request.status = "approved";
    request.resolvedBy = approvedBy;
    request.resolvedAt = new Date().toISOString();

    await this.onSave();

    return request.requestedScope;
  }

  /**
   * Deny an escalation request.
   */
  async denyEscalationRequest(id: string, deniedBy: string, reason?: string): Promise<void> {
    const request = this.data.escalationRequests[id];
    if (!request) {
      throw new Error("Escalation request not found");
    }

    if (request.status !== "pending") {
      throw new Error(`Escalation request is already ${request.status}`);
    }

    request.status = "denied";
    request.resolvedBy = deniedBy;
    request.resolvedAt = new Date().toISOString();
    request.denialReason = reason;

    await this.onSave();
  }

  /**
   * Clean up old escalation requests.
   * Removes requests older than the specified number of days.
   */
  async cleanupOldRequests(maxAgeDays: number = 30): Promise<number> {
    const cutoff = Date.now() - maxAgeDays * 24 * 60 * 60 * 1000;
    let removed = 0;

    for (const [id, request] of Object.entries(this.data.escalationRequests)) {
      const createdAt = new Date(request.createdAt).getTime();
      if (createdAt < cutoff && request.status !== "pending") {
        delete this.data.escalationRequests[id];
        removed++;
      }
    }

    if (removed > 0) {
      await this.onSave();
    }

    return removed;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // User Permission Management
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Get the permissions a user can grant to agents.
   * By default, users have FULL permissions (can grant anything).
   */
  getUserPermissions(userId: string): PermissionLevel[] {
    if (!this.data.userPermissions) {
      this.data.userPermissions = {};
    }
    const config = this.data.userPermissions[userId];
    // Default to FULL permissions if not configured
    return config?.grantablePermissions ?? CEILING_ROLES.FULL;
  }

  /**
   * Set the permissions a user can grant to agents.
   * This is typically set by an admin to limit what a user can delegate.
   */
  async setUserPermissions(
    userId: string,
    permissions: PermissionLevel[],
    role?: CeilingRole,
  ): Promise<void> {
    // Validate all permissions
    for (const perm of permissions) {
      if (!isValidPermission(perm)) {
        throw new Error(`Invalid permission level: ${perm}`);
      }
    }

    if (!this.data.userPermissions) {
      this.data.userPermissions = {};
    }

    this.data.userPermissions[userId] = {
      userId,
      grantablePermissions: permissions,
      modifiedAt: new Date().toISOString(),
      role,
    };

    await this.onSave();
  }

  /**
   * Set user permissions from a predefined role.
   */
  async setUserPermissionsFromRole(userId: string, role: CeilingRole): Promise<void> {
    const permissions = getCeilingForRole(role);
    await this.setUserPermissions(userId, permissions, role);
  }

  /**
   * Remove user permission configuration (revert to default FULL).
   */
  async removeUserPermissions(userId: string): Promise<void> {
    if (this.data.userPermissions) {
      delete this.data.userPermissions[userId];
      await this.onSave();
    }
  }

  /**
   * List all user permission configurations.
   */
  listUserPermissions(): UserPermissionConfig[] {
    if (!this.data.userPermissions) {
      return [];
    }
    return Object.values(this.data.userPermissions);
  }

  /**
   * Validate that a user can grant the specified permissions.
   * Users cannot grant permissions they don't have themselves.
   * Throws InsufficientPermissionsError if the user tries to grant permissions
   * that exceed their own.
   */
  validateUserCanGrant(userId: string, permissionsToGrant: string[]): void {
    const userPermissions = this.getUserPermissions(userId);

    if (!isWithinCeiling(permissionsToGrant, userPermissions)) {
      const { escalated } = partitionPermissions(permissionsToGrant, userPermissions);
      throw new InsufficientPermissionsError(
        userId,
        permissionsToGrant,
        userPermissions,
        escalated,
      );
    }
  }

  /**
   * Set an agent ceiling with user permission validation.
   * The user cannot grant an agent permissions that exceed their own.
   *
   * @param agentId - The agent to configure
   * @param ceiling - The ceiling to set for the agent
   * @param setByUserId - The user setting this ceiling
   * @param reason - Optional reason for the ceiling
   * @throws InsufficientPermissionsError if user tries to grant permissions they don't have
   */
  async setAgentCeilingWithValidation(
    agentId: string,
    ceiling: PermissionLevel[],
    setByUserId: string,
    reason?: string,
  ): Promise<void> {
    // First, validate that the user can grant these permissions
    this.validateUserCanGrant(setByUserId, ceiling);

    // Then set the ceiling
    await this.setAgentCeiling(agentId, ceiling, setByUserId, reason);
  }

  /**
   * Set an agent ceiling from a predefined role with user permission validation.
   */
  async setAgentCeilingFromRoleWithValidation(
    agentId: string,
    role: CeilingRole,
    setByUserId: string,
    reason?: string,
  ): Promise<void> {
    const ceiling = getCeilingForRole(role);
    await this.setAgentCeilingWithValidation(agentId, ceiling, setByUserId, reason);
  }

  /**
   * Check if a user has sufficient permissions to approve an escalation request.
   * The user must have all the permissions being requested.
   */
  canApproveEscalation(
    userId: string,
    escalationRequestId: string,
  ): {
    canApprove: boolean;
    missingPermissions: string[];
  } {
    const request = this.getEscalationRequest(escalationRequestId);
    if (!request) {
      return { canApprove: false, missingPermissions: [] };
    }

    const userPermissions = this.getUserPermissions(userId);
    const { escalated } = partitionPermissions(request.requestedScope, userPermissions);

    return {
      canApprove: escalated.length === 0,
      missingPermissions: escalated,
    };
  }

  /**
   * Approve an escalation request with user permission validation.
   * The approving user must have all the permissions being requested.
   */
  async approveEscalationRequestWithValidation(
    escalationRequestId: string,
    approvedByUserId: string,
  ): Promise<string[]> {
    const { canApprove, missingPermissions } = this.canApproveEscalation(
      approvedByUserId,
      escalationRequestId,
    );

    if (!canApprove) {
      const userPermissions = this.getUserPermissions(approvedByUserId);
      const request = this.getEscalationRequest(escalationRequestId);
      throw new InsufficientPermissionsError(
        approvedByUserId,
        request?.requestedScope ?? [],
        userPermissions,
        missingPermissions,
      );
    }

    return this.approveEscalationRequest(escalationRequestId, approvedByUserId);
  }
}
