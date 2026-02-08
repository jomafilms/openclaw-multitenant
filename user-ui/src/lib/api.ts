// API client for OCMT management server

// Use empty string for production (relative URLs through nginx proxy)
// or explicit URL for local development
const API_URL = import.meta.env.VITE_API_URL ?? "";

interface ApiResponse<T = unknown> {
  success?: boolean;
  error?: string;
  [key: string]: T | boolean | string | undefined;
}

/**
 * Generic result type for API operations.
 * Used for operations that need explicit success/error handling.
 */
export type ApiResult<T> = { success: true; data: T } | { success: false; error: string };

interface User {
  id: string;
  name: string;
  email: string;
  status: string;
}

interface GatewayInfo {
  host: string;
  port: number;
  token: string;
}

interface Integration {
  id: string;
  provider: string;
  integration_type: string;
  provider_email?: string;
  metadata?: Record<string, unknown>;
  status: string;
  created_at: string;
  updated_at?: string;
}

interface ChatMessage {
  role: "user" | "assistant" | "system";
  content: string;
  timestamp: string;
}

// ============================================================
// GROUP/SHARES INTERFACES
// ============================================================

interface Group {
  id: string;
  name: string;
  slug: string;
  description?: string;
  created_at: string;
  updated_at?: string;
}

interface GroupMembership {
  user_id: string;
  group_id: string;
  role: string;
  group_name: string;
  group_slug: string;
  joined_at: string;
}

interface GroupDetails {
  group: Group;
  members: GroupMember[];
  resources: GroupResourceAdmin[];
  isAdmin: boolean;
}

interface GroupMember {
  user_id: string;
  user_name: string;
  user_email: string;
  role: string;
  joined_at: string;
}

interface GroupResourceAdmin {
  id: string;
  name: string;
  description?: string;
  resource_type: string;
  endpoint: string;
  status: string;
  share_count?: number;
  connected_count?: number;
  created_at: string;
}

interface GroupShareAdmin {
  id: string;
  resource_id: string;
  resource_name: string;
  user_id: string;
  user_name: string;
  user_email: string;
  permissions: string[];
  status: string;
  granted_at: string;
  connected_at?: string;
}

interface GroupResource {
  id: string;
  resource_name: string;
  resource_description?: string;
  resource_type: string;
  group_name: string;
  group_slug: string;
  permissions: string[];
  status: string;
  connected_at?: string;
}

interface GroupInvite {
  id: string;
  groupId: string;
  groupName: string;
  groupSlug: string;
  inviterName: string;
  inviterEmail: string;
  role: string;
  status: string;
  createdAt: string;
  expiresAt?: string;
  decidedAt?: string;
}

// Group invite as seen by group admins
interface GroupInviteAdmin {
  id: string;
  inviteeEmail: string;
  inviterName: string;
  role: string;
  status: string;
  createdAt: string;
  expiresAt?: string;
  decidedAt?: string;
}

interface Share {
  id: string;
  resourceId: string;
  groupId?: string;
  userId?: string;
  permissions: string[];
  status: "pending" | "connected" | "revoked";
  grantedBy: string;
  grantedAt: string;
  connectedAt?: string;
  resource?: GroupResourceAdmin;
  group?: Group;
}

interface PeerGrant {
  id: string;
  grantor_id?: string;
  grantee_id?: string;
  grantor_name?: string;
  grantor_email?: string;
  grantee_name?: string;
  grantee_email?: string;
  capability: string;
  status: string;
  reason?: string;
  expires_at?: string;
  created_at: string;
  decided_at?: string;
}

interface AuditLogEntry {
  id: number;
  timestamp: string;
  user_id: string;
  user_name?: string;
  target_user_id?: string;
  target_user_name?: string;
  action: string;
  details?: Record<string, unknown>;
}

interface VaultStatus {
  hasVault: boolean;
  isUnlocked: boolean;
  expiresIn: number;
  biometrics?: {
    enabled: boolean;
    canUse: boolean;
    lastPasswordAt?: string;
    maxAgeDays: number;
  };
}

// Session security interfaces
interface SessionInfo {
  id: string;
  createdAt: string;
  expiresAt: string;
  lastActivityAt: string;
  ipAddress: string | null;
  deviceInfo: {
    type: string;
    name: string;
    browser?: string;
    os?: string;
  };
  isCurrent: boolean;
}

// MFA interfaces
interface MfaSetupResponse {
  secret: string;
  qrUri: string;
  message: string;
}

interface MfaVerifyResponse {
  success: boolean;
  message: string;
  backupCodes?: string[];
  warning?: string;
}

interface MfaStatusResponse {
  totpEnabled: boolean;
  backupCodesRemaining: number;
  lastVerifiedAt?: string;
}

interface MfaBackupCodesResponse {
  success: boolean;
  backupCodes: string[];
}

interface BiometricsStatus {
  biometricsEnabled: boolean;
  canUseBiometrics: boolean;
  deviceRegistered: boolean;
  lastPasswordAt?: string;
  maxAgeDays: number;
  passwordRequiredReason?: string;
}

interface DeviceInfo {
  id: string;
  device_name: string;
  device_fingerprint?: string;
  created_at: string;
  last_used_at?: string;
  has_webauthn?: boolean;
}

interface SessionInfo {
  id: string;
  createdAt: string;
  expiresAt: string;
  lastActivityAt: string;
  ipAddress: string | null;
  userAgent: string | null;
  deviceInfo: {
    type: string;
    name: string;
    browser?: string;
    os?: string;
  };
  isCurrent: boolean;
}

class ApiClient {
  private sessionToken: string | null = null;
  private gatewayInfo: GatewayInfo | null = null;
  private vaultSessionToken: string | null = null;
  private csrfToken: string | null = null;

  constructor() {
    // Try to restore session from localStorage
    this.sessionToken = localStorage.getItem("ocmt_session");
    // Try to restore vault session
    this.vaultSessionToken = localStorage.getItem("ocmt_vault_session");
    // Try to restore gateway info
    const savedGateway = localStorage.getItem("ocmt_gateway");
    if (savedGateway) {
      try {
        this.gatewayInfo = JSON.parse(savedGateway);
      } catch {
        this.gatewayInfo = null;
      }
    }
    // Read CSRF token from cookie
    this.csrfToken = this.getCsrfTokenFromCookie();
  }

  /**
   * Read CSRF token from XSRF-TOKEN cookie
   */
  private getCsrfTokenFromCookie(): string | null {
    const match = document.cookie.match(/XSRF-TOKEN=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : null;
  }

  getGatewayInfo(): GatewayInfo | null {
    return this.gatewayInfo;
  }

  private setGatewayInfo(info: GatewayInfo) {
    this.gatewayInfo = info;
    localStorage.setItem("ocmt_gateway", JSON.stringify(info));
  }

  private clearGatewayInfo() {
    this.gatewayInfo = null;
    localStorage.removeItem("ocmt_gateway");
  }

  private async request<T>(
    path: string,
    options: RequestInit = {},
    retryOnCsrf = true,
  ): Promise<T> {
    const url = `${API_URL}${path}`;
    const method = options.method?.toUpperCase() || "GET";

    const headers: HeadersInit = {
      "Content-Type": "application/json",
      Accept: "application/json",
      ...options.headers,
    };

    if (this.sessionToken) {
      (headers as Record<string, string>)["X-Session-Token"] = this.sessionToken;
    }

    if (this.vaultSessionToken) {
      (headers as Record<string, string>)["X-Vault-Session"] = this.vaultSessionToken;
    }

    // Add CSRF token for state-changing requests
    if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
      // Refresh token from cookie (may have been updated by another request)
      this.csrfToken = this.getCsrfTokenFromCookie();
      if (this.csrfToken) {
        (headers as Record<string, string>)["X-CSRF-Token"] = this.csrfToken;
      }
    }

    const response = await fetch(url, {
      ...options,
      headers,
      credentials: "include", // Include cookies for session and CSRF
    });

    // Update CSRF token from response header if provided
    const newCsrfToken = response.headers.get("X-CSRF-Token");
    if (newCsrfToken) {
      this.csrfToken = newCsrfToken;
    }

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: "Request failed" }));

      // Handle CSRF token errors - refresh and retry once
      if (error.code === "CSRF_INVALID" && retryOnCsrf) {
        // Refresh CSRF token from cookie
        this.csrfToken = this.getCsrfTokenFromCookie();
        // Retry the request once
        return this.request<T>(path, options, false);
      }

      // Ensure error message is always a string
      const errorMessage =
        typeof error.error === "string" ? error.error : error.message || `HTTP ${response.status}`;
      throw new Error(errorMessage);
    }

    return response.json();
  }

  // Authentication

  async login(
    email: string,
  ): Promise<{ success: boolean; message: string; _dev_verify_url?: string }> {
    return this.request("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email }),
    });
  }

  async verifyToken(
    token: string,
  ): Promise<{ success: boolean; user: User; sessionToken: string; gateway?: GatewayInfo }> {
    const result = await this.request<{
      success: boolean;
      user: User;
      sessionToken: string;
      gateway?: GatewayInfo;
    }>(`/api/auth/verify?token=${encodeURIComponent(token)}`);

    if (result.sessionToken) {
      this.sessionToken = result.sessionToken;
      localStorage.setItem("ocmt_session", result.sessionToken);
    }

    // Store gateway connection info if provided
    if (result.gateway) {
      this.setGatewayInfo(result.gateway);
    }

    return result;
  }

  async getMe(): Promise<{ user: User; gateway?: GatewayInfo }> {
    const result = await this.request<{ user: User; gateway?: GatewayInfo }>("/api/auth/me");

    // Update gateway info if provided
    if (result.gateway) {
      this.setGatewayInfo(result.gateway);
    }

    return result;
  }

  async logout(): Promise<void> {
    await this.request("/api/auth/logout", { method: "POST" });
    this.clearSession();
  }

  // Session Management

  /**
   * List all active sessions for the current user
   */
  async getSessions(): Promise<{ sessions: SessionInfo[]; count: number }> {
    return this.request("/api/auth/sessions");
  }

  /**
   * Revoke a specific session by ID
   */
  async revokeSession(sessionId: string): Promise<{ success: boolean; message: string }> {
    return this.request(`/api/auth/sessions/${sessionId}`, {
      method: "DELETE",
    });
  }

  /**
   * Revoke all sessions except the current one (sign out everywhere)
   */
  async revokeAllSessions(): Promise<{ success: boolean; revokedCount: number; message: string }> {
    return this.request("/api/auth/sessions", {
      method: "DELETE",
    });
  }

  // Multi-Factor Authentication (MFA)

  /**
   * Get MFA status for current user
   */
  async getMfaStatus(): Promise<MfaStatusResponse> {
    return this.request("/api/mfa/status");
  }

  /**
   * Begin MFA setup - returns secret and QR URI
   */
  async setupMfa(): Promise<MfaSetupResponse> {
    return this.request("/api/mfa/setup", {
      method: "POST",
    });
  }

  /**
   * Verify MFA setup with a TOTP code
   */
  async verifyMfa(code: string): Promise<MfaVerifyResponse> {
    return this.request("/api/mfa/verify", {
      method: "POST",
      body: JSON.stringify({ code }),
    });
  }

  /**
   * Disable MFA (requires TOTP code for verification)
   */
  async disableMfa(code: string): Promise<MfaVerifyResponse> {
    return this.request("/api/mfa/disable", {
      method: "POST",
      body: JSON.stringify({ code }),
    });
  }

  /**
   * Regenerate backup codes (requires TOTP code for verification)
   */
  async regenerateBackupCodes(code: string): Promise<MfaBackupCodesResponse> {
    return this.request("/api/mfa/backup-codes", {
      method: "POST",
      body: JSON.stringify({ code }),
    });
  }

  /**
   * Get count of remaining unused backup codes
   */
  async getBackupCodesCount(): Promise<{ remaining: number }> {
    return this.request("/api/mfa/backup-codes/count");
  }

  /**
   * Verify TOTP during login (after magic link, before session creation)
   */
  async verifyMfaLogin(
    pendingToken: string,
    code: string,
  ): Promise<{ success: boolean; sessionToken: string; user: User }> {
    const result = await this.request<{
      success: boolean;
      sessionToken: string;
      user: User;
    }>("/api/mfa/verify/totp", {
      method: "POST",
      body: JSON.stringify({ pendingToken, code }),
    });

    if (result.sessionToken) {
      this.sessionToken = result.sessionToken;
      localStorage.setItem("ocmt_session", result.sessionToken);
    }

    return result;
  }

  /**
   * Verify backup code during login
   */
  async verifyMfaLoginWithBackupCode(
    pendingToken: string,
    code: string,
  ): Promise<{
    success: boolean;
    sessionToken: string;
    user: User;
    backupCodesRemaining: number;
    warning?: string;
  }> {
    const result = await this.request<{
      success: boolean;
      sessionToken: string;
      user: User;
      backupCodesRemaining: number;
      warning?: string;
    }>("/api/mfa/verify/backup-code", {
      method: "POST",
      body: JSON.stringify({ pendingToken, code }),
    });

    if (result.sessionToken) {
      this.sessionToken = result.sessionToken;
      localStorage.setItem("ocmt_session", result.sessionToken);
    }

    return result;
  }

  // Clear session locally (for when session is already invalid)
  clearSession(): void {
    this.sessionToken = null;
    this.vaultSessionToken = null;
    // Clear all ocmt_ prefixed items from localStorage
    const keysToRemove: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && key.startsWith("ocmt_")) {
        keysToRemove.push(key);
      }
    }
    keysToRemove.forEach((key) => localStorage.removeItem(key));
    this.clearGatewayInfo();
  }

  isAuthenticated(): boolean {
    return !!this.sessionToken;
  }

  // Chat

  async sendMessage(
    message: string,
  ): Promise<{ success: boolean; response: string; timestamp: string }> {
    return this.request("/api/chat/send", {
      method: "POST",
      body: JSON.stringify({ message }),
    });
  }

  createChatStream(
    onMessage: (msg: ChatMessage) => void,
    onError: (err: string) => void,
  ): EventSource {
    // Include token in query for SSE (EventSource can't set custom headers)
    const tokenParam = this.sessionToken ? `?token=${encodeURIComponent(this.sessionToken)}` : "";
    const base = API_URL || window.location.origin;
    const url = `${base}/api/chat/stream${tokenParam}`;
    const eventSource = new EventSource(url, { withCredentials: true });

    eventSource.addEventListener("connected", (event) => {
      console.log("Chat stream connected", JSON.parse(event.data));
    });

    eventSource.addEventListener("message", (event) => {
      const msg = JSON.parse(event.data) as ChatMessage;
      onMessage(msg);
    });

    eventSource.addEventListener("error", (event) => {
      const data = (event as MessageEvent).data;
      if (data) {
        const err = JSON.parse(data);
        onError(err.message || "Stream error");
      }
    });

    eventSource.onerror = () => {
      onError("Connection lost");
    };

    return eventSource;
  }

  // Integrations

  async listIntegrations(): Promise<{ integrations: Integration[] }> {
    return this.request("/api/integrations");
  }

  /**
   * Add an API key using zero-knowledge flow.
   * Uses management server proxy to send key to container (key never touches management server storage).
   * Falls back to legacy management server storage if container unavailable.
   */
  async addApiKey(
    provider: string,
    apiKey: string,
    metadata?: Record<string, unknown>,
  ): Promise<ApiResponse> {
    // Try zero-knowledge flow via proxy: send API key to container through management server proxy
    // SECURITY: The management server adds auth server-side, key goes directly to container
    try {
      const response = await fetch(`/api/container/vault/apikeys/${provider}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        credentials: "include",
        body: JSON.stringify({ apiKey, metadata }),
      });

      const result = await response.json();

      if (result.success) {
        // Also notify management server that an API key was added (for listing purposes)
        // But NOT sending the actual key - just the provider name
        await this.request("/api/integrations/api-key/notify", {
          method: "POST",
          body: JSON.stringify({ provider, zeroKnowledge: true }),
        }).catch(() => {
          // Notification failure is non-fatal
        });

        return { success: true };
      }

      // If vault is locked, return error
      if (result.error === "Vault is locked") {
        return {
          success: false,
          error: "vault_locked",
        };
      }

      // Fall through to legacy if container operation failed
      console.warn(`[api] Container API key storage failed: ${result.error}`);
    } catch (err) {
      console.warn(`[api] Zero-knowledge API key flow failed: ${(err as Error).message}`);
    }

    // Fall back to legacy management server storage
    // (for migration period or when container is unavailable)
    return this.request("/api/integrations/api-key", {
      method: "POST",
      body: JSON.stringify({ provider, apiKey, metadata }),
    });
  }

  /**
   * Delete an integration using zero-knowledge flow.
   * Deletes from container vault first (via proxy), then from management server records.
   */
  async deleteIntegration(provider: string): Promise<ApiResponse> {
    // Try zero-knowledge flow via proxy: delete from container vault first
    // SECURITY: Uses management server proxy, no authToken exposed to browser
    try {
      await fetch(`/api/container/vault/apikeys/${provider}`, {
        method: "DELETE",
        credentials: "include",
      }).catch(() => {
        // Container delete failure is non-fatal - key may not exist in vault
      });
    } catch (err) {
      console.warn(`[api] Zero-knowledge delete failed: ${(err as Error).message}`);
    }

    // Always delete from management server records
    return this.request(`/api/integrations/${provider}`, {
      method: "DELETE",
    });
  }

  getOAuthUrl(provider: string, scope?: string, scopeLevel?: string): string {
    const path = `/api/oauth/${provider}/start`;
    const base = API_URL || window.location.origin;
    const url = new URL(path, base);
    if (scope) {
      url.searchParams.set("scope", scope);
    }
    if (scopeLevel) {
      url.searchParams.set("scopeLevel", scopeLevel);
    }
    return url.toString();
  }

  async getDriveScopeOptions(): Promise<{
    options: Array<{ level: string; name: string; description: string; capabilities: string[] }>;
  }> {
    return this.request("/api/oauth/google/drive/scope-options");
  }

  async listAvailableResources(): Promise<{ resources: GroupResource[] }> {
    return this.request("/api/available-resources");
  }

  async listConnectedResources(): Promise<{ resources: GroupResource[] }> {
    return this.request("/api/connected-resources");
  }

  async connectResource(grantId: string): Promise<ApiResponse> {
    return this.request(`/api/connect-resource/${grantId}`, {
      method: "POST",
    });
  }

  async disconnectResource(grantId: string): Promise<ApiResponse> {
    return this.request(`/api/disconnect-resource/${grantId}`, {
      method: "DELETE",
    });
  }

  // Peer Sharing

  async createPeerRequest(
    grantorEmail: string,
    capability: string,
    reason?: string,
  ): Promise<ApiResponse> {
    return this.request("/api/shares/peer/requests", {
      method: "POST",
      body: JSON.stringify({ grantorEmail, capability, reason }),
    });
  }

  async listIncomingRequests(): Promise<{ requests: PeerGrant[] }> {
    return this.request("/api/shares/peer/requests/incoming");
  }

  async listOutgoingRequests(): Promise<{ requests: PeerGrant[] }> {
    return this.request("/api/shares/peer/requests/outgoing");
  }

  async approvePeerRequest(
    grantId: string,
    duration?: "day" | "week" | "month" | "always",
  ): Promise<ApiResponse> {
    return this.request(`/api/shares/peer/grants/${grantId}/approve`, {
      method: "POST",
      body: JSON.stringify({ duration }),
    });
  }

  async denyPeerRequest(grantId: string): Promise<ApiResponse> {
    return this.request(`/api/shares/peer/grants/${grantId}/deny`, {
      method: "POST",
    });
  }

  async revokePeerGrant(grantId: string): Promise<ApiResponse> {
    return this.request(`/api/shares/peer/grants/${grantId}`, {
      method: "DELETE",
    });
  }

  async listGrantsToMe(): Promise<{ grants: PeerGrant[] }> {
    return this.request("/api/shares/peer/grants/to-me");
  }

  async listGrantsFromMe(): Promise<{ grants: PeerGrant[] }> {
    return this.request("/api/shares/peer/grants/from-me");
  }

  async getAuditLog(): Promise<{ logs: AuditLogEntry[] }> {
    return this.request("/api/audit-log");
  }

  // Vault

  async getVaultStatus(): Promise<VaultStatus> {
    return this.request("/api/vault/status");
  }

  async createVault(
    password: string,
  ): Promise<{ success: boolean; recoveryPhrase: string; message: string }> {
    return this.request("/api/vault/setup", {
      method: "POST",
      body: JSON.stringify({ password }),
    });
  }

  async unlockVault(
    password: string,
  ): Promise<{ success: boolean; vaultSessionToken: string; expiresIn: number }> {
    const result = await this.request<{
      success: boolean;
      vaultSessionToken: string;
      expiresIn: number;
    }>("/api/vault/unlock", {
      method: "POST",
      body: JSON.stringify({ password }),
    });

    if (result.vaultSessionToken) {
      this.vaultSessionToken = result.vaultSessionToken;
      localStorage.setItem("ocmt_vault_session", result.vaultSessionToken);
    }

    return result;
  }

  async lockVault(): Promise<void> {
    await this.request("/api/vault/lock", { method: "POST" });
    this.vaultSessionToken = null;
    localStorage.removeItem("ocmt_vault_session");
  }

  async extendVaultSession(): Promise<{ expiresIn: number }> {
    return this.request("/api/vault/extend", { method: "POST" });
  }

  async recoverVault(
    recoveryPhrase: string,
    newPassword: string,
  ): Promise<{ success: boolean; message: string }> {
    const result = await this.request<{ success: boolean; message: string }>("/api/vault/recover", {
      method: "POST",
      body: JSON.stringify({ recoveryPhrase, newPassword }),
    });

    // Clear vault session after recovery
    this.vaultSessionToken = null;
    localStorage.removeItem("ocmt_vault_session");

    return result;
  }

  async changeVaultPassword(
    currentPassword: string,
    newPassword: string,
  ): Promise<{ success: boolean; message: string }> {
    const result = await this.request<{ success: boolean; message: string }>(
      "/api/vault/change-password",
      {
        method: "POST",
        body: JSON.stringify({ currentPassword, newPassword }),
      },
    );

    // Clear vault session after password change
    this.vaultSessionToken = null;
    localStorage.removeItem("ocmt_vault_session");

    return result;
  }

  getVaultBackupUrl(): string {
    const base = API_URL || window.location.origin;
    return `${base}/api/vault/backup`;
  }

  isVaultUnlocked(): boolean {
    return !!this.vaultSessionToken;
  }

  // Unlock token (from agent magic links)

  async validateUnlockToken(token: string): Promise<{
    valid: boolean;
    userId: string;
    userName: string;
    email: string;
    expiresIn: number;
    agentServerUrl?: string;
  }> {
    return this.request("/api/vault/validate-unlock-token", {
      method: "POST",
      body: JSON.stringify({ token }),
    });
  }

  async unlockVaultWithToken(
    token: string,
    password: string,
  ): Promise<{ success: boolean; vaultSessionToken: string; expiresIn: number }> {
    const result = await this.request<{
      success: boolean;
      vaultSessionToken: string;
      expiresIn: number;
    }>("/api/vault/unlock-with-token", {
      method: "POST",
      body: JSON.stringify({ token, password }),
    });

    if (result.vaultSessionToken) {
      this.vaultSessionToken = result.vaultSessionToken;
      localStorage.setItem("ocmt_vault_session", result.vaultSessionToken);
    }

    return result;
  }

  // Biometrics

  async getBiometricsStatus(deviceFingerprint?: string): Promise<BiometricsStatus> {
    const params = deviceFingerprint
      ? `?deviceFingerprint=${encodeURIComponent(deviceFingerprint)}`
      : "";
    return this.request(`/api/vault/biometrics/status${params}`);
  }

  async enableBiometrics(
    deviceName: string,
    deviceFingerprint: string,
  ): Promise<{ success: boolean; deviceKey: string }> {
    return this.request("/api/vault/biometrics/enable", {
      method: "POST",
      body: JSON.stringify({ deviceName, deviceFingerprint }),
    });
  }

  async unlockVaultWithBiometrics(
    deviceKey: string,
    deviceFingerprint: string,
  ): Promise<{ success: boolean; vaultSessionToken: string; expiresIn: number }> {
    const result = await this.request<{
      success: boolean;
      vaultSessionToken: string;
      expiresIn: number;
    }>("/api/vault/biometrics/unlock", {
      method: "POST",
      body: JSON.stringify({ deviceKey, deviceFingerprint }),
    });

    if (result.vaultSessionToken) {
      this.vaultSessionToken = result.vaultSessionToken;
      localStorage.setItem("ocmt_vault_session", result.vaultSessionToken);
    }

    return result;
  }

  async disableBiometrics(): Promise<void> {
    await this.request("/api/vault/biometrics/disable", { method: "POST" });
  }

  async listDevices(): Promise<{ devices: DeviceInfo[] }> {
    return this.request("/api/vault/devices");
  }

  async removeDevice(deviceId: string): Promise<void> {
    await this.request(`/api/vault/devices/${deviceId}`, { method: "DELETE" });
  }

  // Container management

  async wakeContainer(): Promise<{
    status: string;
    wakeTime: number;
    queued?: boolean;
    reason?: string;
  }> {
    return this.request("/api/container/wake", { method: "POST" });
  }

  async getContainerStatus(): Promise<{
    exists: boolean;
    ready: boolean;
    hibernationState: string;
    idleMs: number | null;
  }> {
    return this.request("/api/container/status");
  }

  /**
   * Get unlock info for vault operations.
   * SECURITY: authToken is no longer returned - use proxy endpoints instead.
   */
  async getContainerUnlockInfo(): Promise<
    ApiResult<{
      userId: string;
      proxyEnabled?: boolean;
      vaultProxyPath?: string;
      // Legacy fields (deprecated, may be null)
      agentServerUrl?: string | null;
      wsPath?: string | null;
      httpPathPrefix?: string;
      authToken?: string;
    }>
  > {
    try {
      const data = await this.request<{
        userId: string;
        proxyEnabled?: boolean;
        vaultProxyPath?: string;
        agentServerUrl?: string | null;
        wsPath?: string | null;
        httpPathPrefix?: string;
        authToken?: string;
      }>("/api/container/unlock-info");
      return { success: true, data };
    } catch (err) {
      return { success: false, error: (err as Error).message };
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Biometric Unlock (device-based vault unlock)
  // ─────────────────────────────────────────────────────────────────────────────

  /**
   * Enable biometric unlock for a device.
   * Requires the vault to be already unlocked.
   */
  async enableBiometricDevice(
    fingerprint: string,
    name: string,
  ): Promise<{ success: boolean; deviceKey?: string; error?: string }> {
    try {
      return await this.request("/api/vault/biometrics/enable", {
        method: "POST",
        body: JSON.stringify({ fingerprint, name }),
      });
    } catch (err) {
      return { success: false, error: (err as Error).message };
    }
  }

  /**
   * Unlock vault using biometric device key.
   */
  async unlockWithBiometricDevice(
    fingerprint: string,
    deviceKey: string,
  ): Promise<{ success: boolean; expiresIn?: number; error?: string }> {
    try {
      return await this.request("/api/vault/biometrics/unlock", {
        method: "POST",
        body: JSON.stringify({ fingerprint, deviceKey }),
      });
    } catch (err) {
      return { success: false, error: (err as Error).message };
    }
  }

  /**
   * List registered biometric devices.
   */
  async listBiometricDevices(): Promise<{
    success: boolean;
    devices?: Array<{
      fingerprint: string;
      name: string;
      registeredAt: number;
      lastUsedAt?: number;
    }>;
    error?: string;
  }> {
    try {
      return await this.request("/api/vault/biometrics/devices");
    } catch (err) {
      return { success: false, error: (err as Error).message };
    }
  }

  /**
   * Remove a biometric device.
   */
  async removeBiometricDevice(fingerprint: string): Promise<{ success: boolean; error?: string }> {
    try {
      return await this.request(`/api/vault/biometrics/devices/${fingerprint}`, {
        method: "DELETE",
      });
    } catch (err) {
      return { success: false, error: (err as Error).message };
    }
  }

  // Messaging Channels (via agent-server -> OpenClaw container)

  async getChannelStatus(): Promise<{ channels: ChannelStatus[] }> {
    return this.request("/api/channels/status");
  }

  async connectChannel(
    channel: string,
    config: { token?: string; phone?: string },
  ): Promise<{ status: string; channel: string; message?: string }> {
    return this.request(`/api/channels/${channel}/connect`, {
      method: "POST",
      body: JSON.stringify(config),
    });
  }

  async disconnectChannel(channel: string): Promise<{ status: string; channel: string }> {
    return this.request(`/api/channels/${channel}/disconnect`, {
      method: "POST",
    });
  }

  async setAgentConfig(
    key: string,
    value: string | null,
  ): Promise<{ status: string; key: string }> {
    return this.request("/api/agent/config", {
      method: "POST",
      body: JSON.stringify({ key, value }),
    });
  }

  async getAgentConfig(key: string): Promise<{ key: string; value: string | null }> {
    return this.request(`/api/agent/config/${encodeURIComponent(key)}`);
  }

  // User search (for inviting to groups)
  async searchUsers(
    query: string,
  ): Promise<{ users: Array<{ id: string; name: string; email: string }> }> {
    return this.request(`/api/users/search?q=${encodeURIComponent(query)}`);
  }

  // User settings
  async getSettings(): Promise<{ settings: UserSettings }> {
    return this.request("/api/settings");
  }

  async updateSettings(updates: Partial<UserSettings>): Promise<{ settings: UserSettings }> {
    return this.request("/api/settings", {
      method: "PATCH",
      body: JSON.stringify(updates),
    });
  }

  // Capability Approvals (human-in-the-loop)

  async listPendingApprovals(): Promise<{ approvals: CapabilityApproval[] }> {
    return this.request("/api/approvals/pending");
  }

  async listApprovalHistory(limit?: number): Promise<{ approvals: CapabilityApproval[] }> {
    const params = limit ? `?limit=${limit}` : "";
    return this.request(`/api/approvals/history${params}`);
  }

  async getApproval(id: string): Promise<{ approval: CapabilityApproval }> {
    return this.request(`/api/approvals/${id}`);
  }

  async approveCapability(id: string): Promise<ApiResponse> {
    return this.request(`/api/approvals/${id}/approve`, {
      method: "POST",
    });
  }

  async approveCapabilityWithConstraints(
    id: string,
    constraints: {
      expiresInSeconds?: number;
      scope?: string[];
      maxCalls?: number | null;
    },
  ): Promise<ApiResponse> {
    return this.request(`/api/approvals/${id}/approve`, {
      method: "POST",
      body: JSON.stringify({
        constraints: {
          expiresInSeconds: constraints.expiresInSeconds,
          scope: constraints.scope,
          maxCalls: constraints.maxCalls,
        },
      }),
    });
  }

  async denyCapability(id: string): Promise<ApiResponse> {
    return this.request(`/api/approvals/${id}/deny`, {
      method: "POST",
    });
  }

  async validateApprovalToken(token: string): Promise<{
    valid: boolean;
    approval: {
      id: string;
      status: string;
      resource: string;
      scope: string[];
      subjectEmail?: string;
      reason?: string;
      agentContext?: Record<string, unknown>;
      createdAt: string;
      expiresAt: string;
      userName: string;
    };
  }> {
    return this.request(`/api/approvals/token/${token}`);
  }

  async approveCapabilityByToken(token: string): Promise<ApiResponse> {
    return this.request(`/api/approvals/token/${token}/approve`, {
      method: "POST",
    });
  }

  async denyCapabilityByToken(token: string): Promise<ApiResponse> {
    return this.request(`/api/approvals/token/${token}/deny`, {
      method: "POST",
    });
  }

  // Resource Sharing (capability-based sharing with friendly UI)

  async createResourceShare(config: {
    resourceId: string;
    recipientEmail: string;
    tier: "LIVE" | "CACHED" | "DELEGATED";
    permissions: string[];
    expiresAt?: string;
  }): Promise<{ success: boolean; shareId: string }> {
    return this.request("/api/resource-shares", {
      method: "POST",
      body: JSON.stringify(config),
    });
  }

  async listMyShares(): Promise<{ shares: SharedResourceInfo[] }> {
    return this.request("/api/resource-shares/outgoing");
  }

  async listReceivedShares(): Promise<{ shares: ReceivedShareInfo[] }> {
    return this.request("/api/resource-shares/incoming");
  }

  async revokeResourceShare(shareId: string): Promise<ApiResponse> {
    return this.request(`/api/resource-shares/${shareId}`, {
      method: "DELETE",
    });
  }

  async acceptReceivedShare(shareId: string): Promise<ApiResponse> {
    return this.request(`/api/resource-shares/${shareId}/accept`, {
      method: "POST",
    });
  }

  async declineReceivedShare(shareId: string): Promise<ApiResponse> {
    return this.request(`/api/resource-shares/${shareId}/decline`, {
      method: "POST",
    });
  }

  async listShareableResources(): Promise<{ resources: ShareableResourceInfo[] }> {
    return this.request("/api/shareable-resources");
  }

  // ============================================================
  // NEW GROUP/SHARES API METHODS (organizations → groups refactor)
  // ============================================================

  // Groups

  async listMyGroups(): Promise<{ groups: GroupMembership[] }> {
    return this.request("/api/my-groups");
  }

  async createGroup(
    name: string,
    slug: string,
    description?: string,
  ): Promise<{ success: boolean; group: Group }> {
    return this.request("/api/groups", {
      method: "POST",
      body: JSON.stringify({ name, slug, description }),
    });
  }

  async getGroup(groupId: string): Promise<GroupDetails> {
    return this.request(`/api/groups/${groupId}`);
  }

  async updateGroup(
    groupId: string,
    data: { name?: string; description?: string },
  ): Promise<ApiResponse> {
    return this.request(`/api/groups/${groupId}`, {
      method: "PUT",
      body: JSON.stringify(data),
    });
  }

  async listGroupMembers(groupId: string): Promise<{ members: GroupMember[] }> {
    return this.request(`/api/groups/${groupId}/members`);
  }

  async addGroupMember(groupId: string, userId: string, role?: string): Promise<ApiResponse> {
    return this.request(`/api/groups/${groupId}/members`, {
      method: "POST",
      body: JSON.stringify({ userId, role }),
    });
  }

  async removeGroupMember(groupId: string, userId: string): Promise<ApiResponse> {
    return this.request(`/api/groups/${groupId}/members/${userId}`, {
      method: "DELETE",
    });
  }

  async listGroupResources(groupId: string): Promise<{ resources: GroupResourceAdmin[] }> {
    return this.request(`/api/groups/${groupId}/resources`);
  }

  async createGroupResource(
    groupId: string,
    resource: {
      name: string;
      description?: string;
      resourceType?: string;
      endpoint: string;
      authConfig?: Record<string, unknown>;
      metadata?: Record<string, unknown>;
    },
  ): Promise<ApiResponse> {
    return this.request(`/api/groups/${groupId}/resources`, {
      method: "POST",
      body: JSON.stringify(resource),
    });
  }

  async deleteGroupResource(groupId: string, resourceId: string): Promise<ApiResponse> {
    return this.request(`/api/groups/${groupId}/resources/${resourceId}`, {
      method: "DELETE",
    });
  }

  async listGroupShares(groupId: string): Promise<{ shares: GroupShareAdmin[] }> {
    return this.request(`/api/groups/${groupId}/shares`);
  }

  async createGroupShare(
    groupId: string,
    resourceId: string,
    userId: string,
    permissions?: string[],
  ): Promise<ApiResponse> {
    return this.request(`/api/groups/${groupId}/shares`, {
      method: "POST",
      body: JSON.stringify({ resourceId, userId, permissions }),
    });
  }

  async revokeGroupShare(groupId: string, shareId: string): Promise<ApiResponse> {
    return this.request(`/api/groups/${groupId}/shares/${shareId}`, {
      method: "DELETE",
    });
  }

  async inviteToGroup(groupId: string, email: string, role?: string): Promise<ApiResponse> {
    return this.request(`/api/groups/${groupId}/invite`, {
      method: "POST",
      body: JSON.stringify({ email, role }),
    });
  }

  // Group Invites (admin-facing)
  async listGroupInvites(groupId: string): Promise<{ invites: GroupInviteAdmin[] }> {
    return this.request(`/api/groups/${groupId}/invites`);
  }

  async cancelGroupInvite(groupId: string, inviteId: string): Promise<ApiResponse> {
    return this.request(`/api/groups/${groupId}/invites/${inviteId}`, {
      method: "DELETE",
    });
  }

  // Group Invites (user-facing)

  async listMyGroupInvites(): Promise<{ invites: GroupInvite[] }> {
    return this.request("/api/group-invites");
  }

  async getGroupInvite(id: string): Promise<{ invite: GroupInvite }> {
    return this.request(`/api/group-invites/${id}`);
  }

  async acceptGroupInvite(id: string): Promise<{
    success: boolean;
    message: string;
    membership: { groupId: string; groupName: string; groupSlug: string; role: string };
  }> {
    return this.request(`/api/group-invites/${id}/accept`, {
      method: "POST",
    });
  }

  async declineGroupInvite(id: string): Promise<ApiResponse> {
    return this.request(`/api/group-invites/${id}/decline`, {
      method: "POST",
    });
  }

  async getGroupInviteByToken(token: string): Promise<{
    valid: boolean;
    invite: {
      id: string;
      groupName: string;
      groupSlug: string;
      inviterName: string;
      role: string;
      expiresAt?: string;
    };
  }> {
    return this.request(`/api/group-invites/token/${token}`);
  }

  async acceptGroupInviteByToken(token: string): Promise<{
    success: boolean;
    message: string;
    membership: { groupId: string; groupName: string; groupSlug: string; role: string };
  }> {
    return this.request(`/api/group-invites/token/${token}/accept`, {
      method: "POST",
    });
  }

  // Unified Shares

  async listAvailableShares(): Promise<{ shares: Share[] }> {
    return this.request("/api/shares/available");
  }

  async listConnectedShares(): Promise<{ shares: Share[] }> {
    return this.request("/api/shares/connected");
  }

  async connectShare(shareId: string): Promise<ApiResponse> {
    return this.request(`/api/shares/${shareId}/connect`, {
      method: "POST",
    });
  }

  async disconnectShare(shareId: string): Promise<ApiResponse> {
    return this.request(`/api/shares/${shareId}/disconnect`, {
      method: "DELETE",
    });
  }

  async revokeShare(shareId: string): Promise<ApiResponse> {
    return this.request(`/api/shares/${shareId}`, {
      method: "DELETE",
    });
  }

  // Peer sharing via unified shares API
  async createPeerShareRequest(
    grantorEmail: string,
    capability: string,
    reason?: string,
  ): Promise<ApiResponse> {
    return this.request("/api/shares/peer/requests", {
      method: "POST",
      body: JSON.stringify({ grantorEmail, capability, reason }),
    });
  }

  async listIncomingPeerRequests(): Promise<{ requests: PeerGrant[] }> {
    return this.request("/api/shares/peer/requests/incoming");
  }

  async listOutgoingPeerRequests(): Promise<{ requests: PeerGrant[] }> {
    return this.request("/api/shares/peer/requests/outgoing");
  }

  async approvePeerShareRequest(
    grantId: string,
    duration?: "day" | "week" | "month" | "always",
  ): Promise<ApiResponse> {
    return this.request(`/api/shares/peer/grants/${grantId}/approve`, {
      method: "POST",
      body: JSON.stringify({ duration }),
    });
  }

  async denyPeerShareRequest(grantId: string): Promise<ApiResponse> {
    return this.request(`/api/shares/peer/grants/${grantId}/deny`, {
      method: "POST",
    });
  }

  async revokePeerShare(grantId: string): Promise<ApiResponse> {
    return this.request(`/api/shares/peer/grants/${grantId}`, {
      method: "DELETE",
    });
  }

  async listPeerSharesGrantedToMe(): Promise<{ grants: PeerGrant[] }> {
    return this.request("/api/shares/peer/grants/to-me");
  }

  async listPeerSharesGrantedByMe(): Promise<{ grants: PeerGrant[] }> {
    return this.request("/api/shares/peer/grants/from-me");
  }

  // ============================================================
  // ADMIN SECURITY API METHODS
  // ============================================================

  /**
   * Get IP allowlist configuration (admin only)
   */
  async getIpAllowlist(): Promise<IpAllowlistResponse> {
    return this.request("/api/admin/security/ip-allowlist");
  }

  /**
   * Add an IP range to the allowlist (admin only)
   */
  async addIpToAllowlist(
    ipRange: string,
    description?: string,
    expiresInHours?: number,
  ): Promise<{ success: boolean; entry: IpAllowlistEntry }> {
    return this.request("/api/admin/security/ip-allowlist", {
      method: "POST",
      body: JSON.stringify({ ipRange, description, expiresInHours }),
    });
  }

  /**
   * Remove an IP range from the allowlist (admin only)
   */
  async removeIpFromAllowlist(id: string): Promise<{ success: boolean }> {
    return this.request(`/api/admin/security/ip-allowlist/${id}`, {
      method: "DELETE",
    });
  }

  /**
   * Toggle IP allowlist enabled/disabled (admin only)
   */
  async toggleIpAllowlist(
    enabled: boolean,
    confirmationToken?: string,
  ): Promise<{ success: boolean; enabled: boolean }> {
    const headers: Record<string, string> = {};
    if (confirmationToken) {
      headers["X-Confirmation-Token"] = confirmationToken;
    }
    return this.request("/api/admin/security/ip-allowlist/toggle", {
      method: "POST",
      body: JSON.stringify({ enabled }),
      headers,
    });
  }

  /**
   * Add current IP to allowlist (admin only)
   */
  async addCurrentIpToAllowlist(
    description?: string,
    expiresInHours?: number,
  ): Promise<{ success: boolean; entry: IpAllowlistEntry }> {
    return this.request("/api/admin/security/ip-allowlist/add-current", {
      method: "POST",
      body: JSON.stringify({ description, expiresInHours }),
    });
  }

  /**
   * Get security settings (admin only)
   */
  async getSecuritySettings(): Promise<SecuritySettingsResponse> {
    return this.request("/api/admin/security/settings");
  }

  /**
   * Update a security setting (admin only)
   */
  async updateSecuritySetting(
    key: string,
    value: string | number | boolean,
    confirmationToken?: string,
  ): Promise<{ success: boolean; key: string; value: unknown }> {
    const headers: Record<string, string> = {};
    if (confirmationToken) {
      headers["X-Confirmation-Token"] = confirmationToken;
    }
    return this.request(`/api/admin/security/settings/${key}`, {
      method: "PUT",
      body: JSON.stringify({ value }),
      headers,
    });
  }

  /**
   * Delete a security setting (admin only)
   */
  async deleteSecuritySetting(key: string): Promise<{ success: boolean }> {
    return this.request(`/api/admin/security/settings/${key}`, {
      method: "DELETE",
    });
  }

  /**
   * List emergency access tokens (admin only)
   */
  async listEmergencyTokens(includeUsed = false): Promise<{ tokens: EmergencyToken[] }> {
    const params = includeUsed ? "?includeUsed=true" : "";
    return this.request(`/api/admin/security/emergency-tokens${params}`);
  }

  /**
   * Create an emergency access token (admin only)
   */
  async createEmergencyToken(
    reason: string,
    expiresInHours?: number,
    singleUse?: boolean,
    confirmationToken?: string,
  ): Promise<EmergencyTokenCreateResponse> {
    const headers: Record<string, string> = {};
    if (confirmationToken) {
      headers["X-Confirmation-Token"] = confirmationToken;
    }
    return this.request("/api/admin/security/emergency-tokens", {
      method: "POST",
      body: JSON.stringify({ reason, expiresInHours, singleUse }),
      headers,
    });
  }

  /**
   * Revoke an emergency access token (admin only)
   */
  async revokeEmergencyToken(id: string): Promise<{ success: boolean }> {
    return this.request(`/api/admin/security/emergency-tokens/${id}`, {
      method: "DELETE",
    });
  }

  /**
   * Get admin session info (admin only)
   */
  async getAdminSessionInfo(): Promise<AdminSessionInfo> {
    return this.request("/api/admin/security/session");
  }

  /**
   * Get known VPN ranges (admin only)
   */
  async getVpnRanges(): Promise<{
    ranges: Array<{ name: string; cidr: string; description: string }>;
  }> {
    return this.request("/api/admin/security/vpn-ranges");
  }

  /**
   * Check if current user is an admin
   */
  async checkAdminStatus(): Promise<{ isAdmin: boolean }> {
    try {
      await this.request("/api/admin/security/session");
      return { isAdmin: true };
    } catch {
      return { isAdmin: false };
    }
  }

  // ============================================================
  // PLATFORM ADMIN API METHODS
  // ============================================================

  /**
   * Check if current user is a platform admin
   */
  async checkPlatformAdminStatus(): Promise<{ isPlatformAdmin: boolean }> {
    try {
      await this.request("/api/platform-admin/status");
      return { isPlatformAdmin: true };
    } catch {
      return { isPlatformAdmin: false };
    }
  }

  /**
   * Get platform overview stats
   */
  async getPlatformStats(): Promise<PlatformStats> {
    return this.request("/api/platform-admin/stats");
  }

  /**
   * List all tenants (platform admin only)
   */
  async listTenants(
    options: {
      status?: string;
      search?: string;
      limit?: number;
      offset?: number;
    } = {},
  ): Promise<{ tenants: TenantInfo[]; total: number }> {
    const params = new URLSearchParams();
    if (options.status) {
      params.set("status", options.status);
    }
    if (options.search) {
      params.set("search", options.search);
    }
    if (options.limit) {
      params.set("limit", String(options.limit));
    }
    if (options.offset) {
      params.set("offset", String(options.offset));
    }
    const queryStr = params.toString();
    return this.request(`/api/platform-admin/tenants${queryStr ? `?${queryStr}` : ""}`);
  }

  /**
   * Get tenant details (platform admin only)
   */
  async getTenantDetails(tenantId: string): Promise<TenantDetails> {
    return this.request(`/api/platform-admin/tenants/${tenantId}`);
  }

  /**
   * Suspend a tenant (platform admin only)
   */
  async suspendTenant(tenantId: string, reason?: string): Promise<{ success: boolean }> {
    return this.request(`/api/platform-admin/tenants/${tenantId}/suspend`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    });
  }

  /**
   * Unsuspend a tenant (platform admin only)
   */
  async unsuspendTenant(tenantId: string): Promise<{ success: boolean }> {
    return this.request(`/api/platform-admin/tenants/${tenantId}/unsuspend`, {
      method: "POST",
    });
  }

  /**
   * Delete a tenant (platform admin only)
   */
  async deleteTenant(tenantId: string, confirmationToken: string): Promise<{ success: boolean }> {
    return this.request(`/api/platform-admin/tenants/${tenantId}`, {
      method: "DELETE",
      headers: { "X-Confirmation-Token": confirmationToken },
    });
  }

  /**
   * List all users across tenants (platform admin only)
   */
  async listAllUsers(
    options: {
      tenantId?: string;
      status?: string;
      search?: string;
      limit?: number;
      offset?: number;
    } = {},
  ): Promise<{ users: PlatformUserInfo[]; total: number }> {
    const params = new URLSearchParams();
    if (options.tenantId) {
      params.set("tenantId", options.tenantId);
    }
    if (options.status) {
      params.set("status", options.status);
    }
    if (options.search) {
      params.set("search", options.search);
    }
    if (options.limit) {
      params.set("limit", String(options.limit));
    }
    if (options.offset) {
      params.set("offset", String(options.offset));
    }
    const queryStr = params.toString();
    return this.request(`/api/platform-admin/users${queryStr ? `?${queryStr}` : ""}`);
  }

  /**
   * Get user details (platform admin only)
   */
  async getPlatformUserDetails(userId: string): Promise<PlatformUserDetails> {
    return this.request(`/api/platform-admin/users/${userId}`);
  }

  /**
   * Impersonate a user (platform admin only)
   */
  async impersonateUser(userId: string): Promise<{
    success: boolean;
    sessionToken: string;
    user: User;
  }> {
    const result = await this.request<{
      success: boolean;
      sessionToken: string;
      user: User;
    }>(`/api/platform-admin/users/${userId}/impersonate`, {
      method: "POST",
    });

    // Store the impersonation session
    if (result.sessionToken) {
      // Save original session for later restoration
      const originalSession = this.sessionToken;
      if (originalSession) {
        localStorage.setItem("ocmt_original_session", originalSession);
      }
      this.sessionToken = result.sessionToken;
      localStorage.setItem("ocmt_session", result.sessionToken);
      localStorage.setItem("ocmt_impersonating", "true");
    }

    return result;
  }

  /**
   * Stop impersonating and restore original session
   */
  async stopImpersonation(): Promise<{ success: boolean }> {
    const originalSession = localStorage.getItem("ocmt_original_session");
    if (originalSession) {
      this.sessionToken = originalSession;
      localStorage.setItem("ocmt_session", originalSession);
      localStorage.removeItem("ocmt_original_session");
      localStorage.removeItem("ocmt_impersonating");
    }
    return { success: true };
  }

  /**
   * Check if currently impersonating
   */
  isImpersonating(): boolean {
    return localStorage.getItem("ocmt_impersonating") === "true";
  }

  /**
   * Enable/disable a user (platform admin only)
   */
  async setUserStatus(
    userId: string,
    status: "active" | "disabled",
  ): Promise<{ success: boolean }> {
    return this.request(`/api/platform-admin/users/${userId}/status`, {
      method: "PUT",
      body: JSON.stringify({ status }),
    });
  }

  /**
   * List all containers (platform admin only)
   */
  async listAllContainers(
    options: {
      status?: string;
      tenantId?: string;
      limit?: number;
      offset?: number;
    } = {},
  ): Promise<{ containers: ContainerInfo[]; total: number }> {
    const params = new URLSearchParams();
    if (options.status) {
      params.set("status", options.status);
    }
    if (options.tenantId) {
      params.set("tenantId", options.tenantId);
    }
    if (options.limit) {
      params.set("limit", String(options.limit));
    }
    if (options.offset) {
      params.set("offset", String(options.offset));
    }
    const queryStr = params.toString();
    return this.request(`/api/platform-admin/containers${queryStr ? `?${queryStr}` : ""}`);
  }

  /**
   * Restart a container (platform admin only)
   */
  async restartContainer(containerId: string): Promise<{ success: boolean }> {
    return this.request(`/api/platform-admin/containers/${containerId}/restart`, {
      method: "POST",
    });
  }

  /**
   * Stop a container (platform admin only)
   */
  async stopContainer(containerId: string): Promise<{ success: boolean }> {
    return this.request(`/api/platform-admin/containers/${containerId}/stop`, {
      method: "POST",
    });
  }

  /**
   * Get platform metrics (platform admin only)
   */
  async getPlatformMetrics(
    timeRange: "1h" | "24h" | "7d" | "30d" = "24h",
  ): Promise<PlatformMetrics> {
    return this.request(`/api/platform-admin/metrics?range=${timeRange}`);
  }
}

// Admin Security Types
interface IpAllowlistEntry {
  id: string;
  ipRange: string;
  description?: string;
  createdBy?: string;
  createdAt: string;
  expiresAt?: string;
  lastUsedAt?: string;
  hitCount?: number;
}

interface IpAllowlistResponse {
  enabled: boolean;
  entries: IpAllowlistEntry[];
  settings: Record<string, unknown>;
  knownVpnRanges: Record<string, string>;
  localIps: string[];
  clientIp: string;
}

interface SecuritySettingsResponse {
  settings: Record<string, unknown>;
  envSettings: {
    sessionTimeoutMs: number;
    inactivityTimeoutMs: number;
    reauthIntervalMs: number;
  };
}

interface EmergencyToken {
  id: string;
  reason: string;
  createdAt: string;
  expiresAt: string;
  usedAt?: string;
  usedByIp?: string;
  singleUse: boolean;
}

interface EmergencyTokenCreateResponse {
  success: boolean;
  token: string;
  tokenId: string;
  expiresAt: string;
  singleUse: boolean;
  warning: string;
}

interface AdminSessionInfo {
  user: {
    id: string;
    email: string;
    name: string;
  };
  session: {
    id: string;
    isAdmin: boolean;
    emergencyAccess: boolean;
  };
  security: {
    clientIp: string;
    sessionTimeoutMs: number;
    inactivityTimeoutMs: number;
  };
}

// Platform Admin Types
interface PlatformStats {
  totalTenants: number;
  activeTenants: number;
  suspendedTenants: number;
  totalUsers: number;
  activeUsers: number;
  totalContainers: number;
  runningContainers: number;
  subscriptionsByPlan: Record<string, number>;
  storageUsedGB: number;
  apiCallsToday: number;
  newSignupsThisWeek: number;
}

interface TenantInfo {
  id: string;
  name: string;
  slug: string;
  ownerId: string;
  ownerName: string;
  ownerEmail: string;
  status: "active" | "suspended" | "deleted";
  plan: string;
  userCount: number;
  containerCount: number;
  createdAt: string;
  updatedAt?: string;
}

interface TenantDetails extends TenantInfo {
  settings: Record<string, unknown>;
  subscription?: {
    plan: string;
    status: string;
    currentPeriodEnd?: string;
    cancelAtPeriodEnd?: boolean;
  };
  users: PlatformUserInfo[];
  containers: ContainerInfo[];
  usageStats: {
    apiCalls: number;
    storageUsedMB: number;
    lastActivityAt?: string;
  };
}

interface PlatformUserInfo {
  id: string;
  name: string;
  email: string;
  status: "active" | "pending" | "disabled";
  tenantId?: string;
  tenantName?: string;
  role?: string;
  lastLoginAt?: string;
  createdAt: string;
}

interface PlatformUserDetails extends PlatformUserInfo {
  tenant?: TenantInfo;
  sessions: SessionInfo[];
  integrations: string[];
  containers: ContainerInfo[];
}

interface ContainerInfo {
  id: string;
  containerId: string;
  userId: string;
  userName?: string;
  userEmail?: string;
  tenantId?: string;
  tenantName?: string;
  status: "running" | "paused" | "stopped" | "error";
  memoryUsageMB: number;
  cpuPercent: number;
  createdAt: string;
  lastActivityAt?: string;
}

interface PlatformMetrics {
  apiCalls: TimeSeriesData[];
  storageUsage: TimeSeriesData[];
  newSignups: TimeSeriesData[];
  activeUsers: TimeSeriesData[];
}

interface TimeSeriesData {
  timestamp: string;
  value: number;
}

interface UserSettings {
  vaultAutoLock?: boolean;
  theme?: string;
  notifications?: boolean;
}

interface CapabilityApproval {
  id: string;
  user_id: string;
  operation_type: string;
  subject_public_key: string;
  subject_email?: string;
  resource: string;
  scope: string[];
  expires_in_seconds: number;
  max_calls?: number;
  reason?: string;
  agent_context?: Record<string, unknown>;
  status: "pending" | "approved" | "denied" | "issued" | "expired";
  token?: string;
  created_at: string;
  decided_at?: string;
  expires_at: string;
}

interface ChannelStatus {
  id: string;
  name: string;
  status: "connected" | "disconnected" | "connecting" | "error";
  error?: string;
  metadata?: Record<string, unknown>;
}

interface SharedResourceInfo {
  id: string;
  resourceId: string;
  resourceName: string;
  resourceType: string;
  recipientId: string;
  recipientName: string;
  recipientEmail: string;
  tier: "LIVE" | "CACHED" | "DELEGATED";
  permissions: string[];
  status: "active" | "pending" | "expired" | "revoked";
  expiresAt?: string;
  createdAt: string;
  approvedAt?: string;
}

interface ReceivedShareInfo {
  id: string;
  resourceId: string;
  resourceName: string;
  resourceType: string;
  ownerId: string;
  ownerName: string;
  ownerEmail: string;
  tier: "LIVE" | "CACHED" | "DELEGATED";
  permissions: string[];
  status: "active" | "pending_approval" | "expired" | "revoked";
  ownerOnline?: boolean;
  lastSyncAt?: string;
  expiresAt?: string;
  sharedAt: string;
}

interface ShareableResourceInfo {
  id: string;
  name: string;
  type: string;
  icon?: string;
  source: "integration" | "group";
  sourceName?: string;
}

export const api = new ApiClient();
export type {
  User,
  Integration,
  ChatMessage,
  GatewayInfo,
  PeerGrant,
  AuditLogEntry,
  VaultStatus,
  BiometricsStatus,
  DeviceInfo,
  UserSettings,
  CapabilityApproval,
  SharedResourceInfo,
  ReceivedShareInfo,
  ShareableResourceInfo,
  // Group types
  Group,
  GroupMembership,
  GroupDetails,
  GroupMember,
  GroupResourceAdmin,
  GroupShareAdmin,
  GroupResource,
  GroupInvite,
  GroupInviteAdmin,
  Share,
  // Session security types
  SessionInfo,
  // MFA types
  MfaSetupResponse,
  MfaVerifyResponse,
  MfaBackupCodesResponse,
  MfaStatusResponse,
  // Admin Security types
  IpAllowlistEntry,
  IpAllowlistResponse,
  SecuritySettingsResponse,
  EmergencyToken,
  EmergencyTokenCreateResponse,
  AdminSessionInfo,
  // Platform Admin types
  PlatformStats,
  TenantInfo,
  TenantDetails,
  PlatformUserInfo,
  PlatformUserDetails,
  ContainerInfo,
  PlatformMetrics,
  TimeSeriesData,
};
