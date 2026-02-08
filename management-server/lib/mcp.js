import axios from "axios";
// MCP Tool Definitions and Handler
import crypto from "crypto";
import dns from "dns";
import { promisify } from "util";
import { isPrivateIp } from "./ip-utils.js";

const dnsLookup = promisify(dns.lookup);
import {
  users,
  integrations,
  shares as groupShares,
  groupResources,
  groupMemberships,
  audit,
  PERMISSION_LEVELS,
  DEFAULT_PERMISSIONS,
  FULL_PERMISSIONS,
} from "../db/index.js";
import { logActivity, ACTION_TYPES } from "./anomaly-detection.js";
import { syncCredentialsFromVaultData, AGENT_SERVER_URL, AGENT_SERVER_TOKEN } from "./context.js";
import { decryptGatewayToken, validateEphemeralToken, detectTokenType } from "./gateway-tokens.js";
import { createUnlockToken } from "./unlock-tokens.js";
import { vaultSessions, VAULT_SESSION_TIMEOUT_MS } from "./vault-sessions.js";
import { unlockVaultWithKey, updateVaultWithKey } from "./vault.js";
import { wakeContainerIfNeeded, getWakeOnRequestMetrics } from "./wake-on-request.js";

// Rate limiting for resource calls
// Key: `${userId}:${resourceId}` -> { calls: [{timestamp}], windowStart }
const rateLimitStore = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000; // 1 hour
const DEFAULT_RATE_LIMIT = 100; // calls per hour per resource per user

function checkRateLimit(userId, resourceId, limit = DEFAULT_RATE_LIMIT) {
  const key = `${userId}:${resourceId}`;
  const now = Date.now();
  const windowStart = now - RATE_LIMIT_WINDOW_MS;

  let bucket = rateLimitStore.get(key);
  if (!bucket) {
    bucket = { calls: [] };
    rateLimitStore.set(key, bucket);
  }

  // Remove calls outside the window
  bucket.calls = bucket.calls.filter((ts) => ts > windowStart);

  const remaining = limit - bucket.calls.length;
  const resetAt =
    bucket.calls.length > 0 ? new Date(bucket.calls[0] + RATE_LIMIT_WINDOW_MS).toISOString() : null;

  if (remaining <= 0) {
    return {
      allowed: false,
      remaining: 0,
      limit,
      resetAt,
      retryAfter: Math.ceil((bucket.calls[0] + RATE_LIMIT_WINDOW_MS - now) / 1000),
    };
  }

  // Record this call
  bucket.calls.push(now);
  rateLimitStore.set(key, bucket);

  return { allowed: true, remaining: remaining - 1, limit, resetAt };
}

// Cleanup old rate limit entries periodically
setInterval(
  () => {
    const now = Date.now();
    const windowStart = now - RATE_LIMIT_WINDOW_MS;
    for (const [key, bucket] of rateLimitStore) {
      bucket.calls = bucket.calls.filter((ts) => ts > windowStart);
      if (bucket.calls.length === 0) {
        rateLimitStore.delete(key);
      }
    }
  },
  5 * 60 * 1000,
); // Every 5 minutes

// ============================================================
// SSRF Protection
// ============================================================

/**
 * Check if a URL points to a private/internal IP address (SSRF protection)
 * Resolves hostnames and validates against private IP ranges.
 *
 * @param {string} urlString - The URL to validate
 * @returns {Promise<{ safe: boolean, error?: string, resolvedIp?: string }>}
 */
async function validateUrlForSSRF(urlString) {
  try {
    const url = new URL(urlString);
    const hostname = url.hostname;

    // Block localhost variations
    const localhostPatterns = [
      "localhost",
      "localhost.localdomain",
      "127.0.0.1",
      "::1",
      "0.0.0.0",
      "[::1]",
      "[::ffff:127.0.0.1]",
    ];

    if (localhostPatterns.includes(hostname.toLowerCase())) {
      return {
        safe: false,
        error: `SSRF blocked: localhost addresses are not allowed`,
      };
    }

    // Check if hostname is already an IP address
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Regex = /^\[?([a-fA-F0-9:]+)\]?$/;

    let ipToCheck = null;

    if (ipv4Regex.test(hostname)) {
      ipToCheck = hostname;
    } else if (ipv6Regex.test(hostname)) {
      // Remove brackets for IPv6
      ipToCheck = hostname.replace(/^\[|\]$/g, "");
    } else {
      // Resolve hostname to IP
      try {
        const result = await dnsLookup(hostname, { all: false });
        ipToCheck = result.address;
      } catch (dnsErr) {
        return {
          safe: false,
          error: `SSRF blocked: failed to resolve hostname "${hostname}"`,
        };
      }
    }

    // Check if the resolved IP is private
    if (isPrivateIp(ipToCheck)) {
      return {
        safe: false,
        error: `SSRF blocked: private IP address detected (${ipToCheck})`,
        resolvedIp: ipToCheck,
      };
    }

    return { safe: true, resolvedIp: ipToCheck };
  } catch (err) {
    return {
      safe: false,
      error: `SSRF validation error: ${err.message}`,
    };
  }
}

export const MCP_TOOLS = [
  {
    name: "ocmt_vault_status",
    description: "Check if the user's vault is currently unlocked",
    inputSchema: { type: "object", properties: {}, required: [] },
  },
  {
    name: "ocmt_unlock_link",
    description: "Generate a magic link for the user to unlock their vault",
    inputSchema: { type: "object", properties: {}, required: [] },
  },
  {
    name: "ocmt_integrations",
    description: "List all connected integrations and their status",
    inputSchema: {
      type: "object",
      properties: {
        provider: { type: "string", description: "Optional: filter by provider" },
      },
      required: [],
    },
  },
  {
    name: "ocmt_extend_session",
    description: "Extend the vault session during active conversation",
    inputSchema: { type: "object", properties: {}, required: [] },
  },
  {
    name: "ocmt_group_resources",
    description: "List group resources the user has access to",
    inputSchema: {
      type: "object",
      properties: {
        status: { type: "string", enum: ["connected", "available", "all"] },
        groupSlug: { type: "string" },
      },
      required: [],
    },
  },
  {
    name: "ocmt_get_credentials",
    description: "Get credentials for a connected integration (OAuth tokens or API keys)",
    inputSchema: {
      type: "object",
      properties: {
        provider: {
          type: "string",
          enum: [
            "google",
            "google_calendar",
            "google_gmail",
            "google_drive",
            "github",
            "anthropic",
            "openai",
          ],
        },
      },
      required: ["provider"],
    },
  },
  {
    name: "ocmt_call_resource",
    description: "Call a group resource API endpoint. The resource must be connected first.",
    inputSchema: {
      type: "object",
      properties: {
        resourceId: {
          type: "string",
          description: "The resource UUID to call",
        },
        method: {
          type: "string",
          enum: ["GET", "POST", "PUT", "PATCH", "DELETE"],
          description: "HTTP method (default: GET)",
        },
        path: {
          type: "string",
          description: 'Path to append to the resource endpoint (e.g., "/users/123")',
        },
        query: {
          type: "object",
          description: "Query parameters as key-value pairs",
        },
        body: {
          type: "object",
          description: "Request body (for POST/PUT/PATCH)",
        },
        headers: {
          type: "object",
          description: "Additional headers to include",
        },
      },
      required: ["resourceId"],
    },
  },
  {
    name: "ocmt_list_my_groups",
    description: "List groups the user is a member of",
    inputSchema: { type: "object", properties: {}, required: [] },
  },
  {
    name: "ocmt_create_resource",
    description: "Create a new API resource in a group. User must be group admin.",
    inputSchema: {
      type: "object",
      properties: {
        groupId: { type: "string", description: "Group UUID" },
        name: { type: "string", description: "Resource display name" },
        description: { type: "string", description: "What this resource does" },
        endpoint: { type: "string", description: "Base URL for the API" },
        resourceType: {
          type: "string",
          description: "Type of resource (default: api)",
          enum: ["api", "mcp_server", "webhook"],
        },
        authConfig: {
          type: "object",
          description:
            'Auth configuration. Examples: {type:"api_key",key:"xxx",header:"X-API-Key"} or {type:"bearer",token:"xxx"}',
        },
      },
      required: ["groupId", "name", "endpoint"],
    },
  },
  {
    name: "ocmt_grant_resource_access",
    description:
      "Grant a user access to a resource with granular permissions. User must be group admin. Use your own userId to grant yourself access.",
    inputSchema: {
      type: "object",
      properties: {
        resourceId: { type: "string", description: "Resource UUID" },
        userId: {
          type: "string",
          description: 'User UUID to grant access to (use "me" for yourself)',
        },
        permissions: {
          type: "object",
          description:
            "Granular permissions object. Keys: read, list, write, delete, admin, share. Values: true/false. Default: {read:true}. Also accepts legacy array format.",
          properties: {
            read: { type: "boolean", description: "View resource data (GET requests)" },
            list: { type: "boolean", description: "List items in resource" },
            write: { type: "boolean", description: "Create/update data (POST, PUT, PATCH)" },
            delete: { type: "boolean", description: "Delete data (DELETE requests)" },
            admin: { type: "boolean", description: "Manage the resource itself" },
            share: { type: "boolean", description: "Can share resource with others" },
          },
        },
        autoConnect: {
          type: "boolean",
          description: "Automatically connect after granting (default: true for self-grants)",
        },
      },
      required: ["resourceId"],
    },
  },
  {
    name: "ocmt_delete_resource",
    description: "Delete a resource from a group. User must be group admin.",
    inputSchema: {
      type: "object",
      properties: {
        resourceId: { type: "string", description: "Resource UUID to delete" },
      },
      required: ["resourceId"],
    },
  },
  {
    name: "ocmt_wake_metrics",
    description: "Get wake-on-request metrics for monitoring container hibernation/wake patterns",
    inputSchema: { type: "object", properties: {}, required: [] },
  },
];

/**
 * Handle MCP tool calls
 */
export async function handleMcpToolCall(toolName, params, userId, vaultSessionToken) {
  // Log all MCP tool calls for anomaly detection
  logActivity(userId, ACTION_TYPES.MCP_TOOL_CALL, toolName, { params }).catch((err) => {
    console.error(`[mcp] Failed to log activity: ${err.message}`);
  });

  // Normalize legacy tool names
  const normalizedToolName =
    {
      ocmt_org_resources: "ocmt_group_resources",
      ocmt_list_my_orgs: "ocmt_list_my_groups",
    }[toolName] || toolName;

  switch (normalizedToolName) {
    case "ocmt_vault_status": {
      const hasVault = await users.hasVault(userId);
      if (!hasVault) {
        return { hasVault: false, locked: true, expiresIn: null, credentialsSynced: false };
      }

      // Check if credentials are already synced to container
      let credentialsSynced = false;
      try {
        const profilesRes = await axios.get(
          `${AGENT_SERVER_URL}/api/containers/${userId}/auth-profiles`,
          { headers: { "x-auth-token": AGENT_SERVER_TOKEN }, timeout: 5000 },
        );
        if (profilesRes.data?.profiles && Object.keys(profilesRes.data.profiles).length > 0) {
          credentialsSynced = true;
        }
      } catch {
        // Container may not be running or endpoint not available
      }

      if (!vaultSessionToken || !vaultSessions.has(vaultSessionToken)) {
        return {
          hasVault: true,
          locked: true,
          expiresIn: null,
          credentialsSynced,
          hint: credentialsSynced
            ? "Vault session expired but credentials are synced to container. You can use Google APIs directly via auth-profiles.json."
            : "Vault is locked. Request an unlock link for the user.",
        };
      }

      const session = vaultSessions.get(vaultSessionToken);
      if (session.userId !== userId || session.expiresAt <= Date.now()) {
        return {
          hasVault: true,
          locked: true,
          expiresIn: null,
          credentialsSynced,
          hint: credentialsSynced
            ? "Vault session expired but credentials are synced to container. You can use Google APIs directly via auth-profiles.json."
            : "Vault session expired. Request a new unlock link.",
        };
      }

      return {
        hasVault: true,
        locked: false,
        expiresIn: Math.floor((session.expiresAt - Date.now()) / 1000),
        credentialsSynced,
      };
    }

    case "ocmt_unlock_link": {
      const token = createUnlockToken(userId);
      const baseUrl = process.env.BASE_URL || process.env.USER_UI_URL || "https://YOUR_DOMAIN";
      return { url: `${baseUrl}/unlock?t=${token}`, expiresIn: 900 };
    }

    case "ocmt_integrations": {
      const userIntegrations = await integrations.listForUser(userId);
      const { provider } = params || {};

      const hasVaultSession = vaultSessionToken && vaultSessions.has(vaultSessionToken);
      const session = hasVaultSession ? vaultSessions.get(vaultSessionToken) : null;
      const vaultUnlocked =
        session && session.userId === userId && session.expiresAt > Date.now() && session.vaultKey;

      let results = userIntegrations.map((int) => ({
        provider: int.provider,
        type: int.integration_type,
        status: int.status,
        email: int.provider_email,
        storedInVault: int.metadata?.storedInVault || false,
        tokensAccessible: int.metadata?.storedInVault && vaultUnlocked,
      }));

      if (provider) {
        results = results.filter(
          (r) => r.provider === provider || r.provider.startsWith(provider + "_"),
        );
      }

      return {
        integrations: results,
        vaultUnlocked,
        hint: vaultUnlocked
          ? "Vault is unlocked. Use ocmt_get_credentials to get access tokens."
          : "Vault is locked. Ask the user to unlock their vault.",
      };
    }

    case "ocmt_extend_session": {
      if (!vaultSessionToken || !vaultSessions.has(vaultSessionToken)) {
        return { success: false, error: "Vault is locked", needsUnlock: true };
      }

      const session = vaultSessions.get(vaultSessionToken);
      if (session.userId !== userId || session.expiresAt <= Date.now()) {
        return { success: false, error: "Vault session expired", needsUnlock: true };
      }

      session.expiresAt = Date.now() + VAULT_SESSION_TIMEOUT_MS;
      return { success: true, expiresIn: 1800 };
    }

    case "ocmt_group_resources": {
      const { status = "connected", groupSlug } = params || {};
      const available = await groupShares.listAvailableForUser(userId);
      const connected = await groupShares.listConnectedForUser(userId);

      const formatResource = (grant, isConnected) => ({
        id: grant.id,
        resourceId: grant.resource_id,
        name: grant.resource_name,
        type: grant.resource_type,
        group: { name: grant.group_name, slug: grant.group_slug },
        permissions: grant.permissions,
        status: isConnected ? "connected" : "available",
        endpoint: isConnected ? grant.endpoint : undefined,
      });

      let resources = [];
      if (status === "all" || status === "available") {
        resources = resources.concat(available.map((g) => formatResource(g, false)));
      }
      if (status === "all" || status === "connected") {
        resources = resources.concat(connected.map((g) => formatResource(g, true)));
      }

      if (groupSlug) {
        resources = resources.filter((r) => r.group.slug === groupSlug);
      }

      return {
        resources,
        summary: {
          total: resources.length,
          connected: connected.length,
          available: available.length,
        },
      };
    }

    case "ocmt_get_credentials": {
      const { provider } = params || {};
      if (!provider) {
        throw new Error("Provider is required");
      }

      // API key providers - stored encrypted in container vault (zero-knowledge)
      // Management server NEVER decrypts these keys
      const apiKeyProviders = ["github", "anthropic", "openai"];
      if (apiKeyProviders.includes(provider)) {
        try {
          // First, wake the container if needed
          await wakeContainerIfNeeded(userId, "credential-access");

          // Proxy request to container - container has the decrypted key
          const containerResponse = await axios.get(
            `${AGENT_SERVER_URL}/api/containers/${userId}/vault/apikeys/${provider}`,
            {
              headers: {
                Authorization: `Bearer ${AGENT_SERVER_TOKEN}`,
                "X-User-Id": userId,
              },
              timeout: 10000,
            },
          );

          const result = containerResponse.data;

          if (!result.success) {
            // Check if vault is locked
            if (result.error === "Vault is locked") {
              return {
                success: false,
                error: "vault_locked",
                message: "Vault is locked. Unlock your vault to access API keys.",
              };
            }

            // API key not found in container vault
            // Fall back to legacy integrations table for migration period
            const legacyIntegration = await integrations.getDecryptedTokens(userId, provider);
            if (legacyIntegration?.apiKey) {
              // Log credential access for anomaly detection
              logActivity(userId, ACTION_TYPES.CREDENTIAL_ACCESS, provider, {
                source: "legacy",
              }).catch((err) => {
                console.error(`[mcp] Failed to log credential access: ${err.message}`);
              });

              return {
                success: true,
                provider,
                apiKey: legacyIntegration.apiKey,
                type: "api_key",
                migrationHint:
                  "API key retrieved from legacy storage. Consider re-adding via vault.",
              };
            }

            return {
              success: false,
              error: "not_connected",
              message: `No ${provider} API key found. Add it in Connections.`,
            };
          }

          // Log credential access for anomaly detection (note: we never log the actual key)
          logActivity(userId, ACTION_TYPES.CREDENTIAL_ACCESS, provider, {
            source: "container_vault",
          }).catch((err) => {
            console.error(`[mcp] Failed to log credential access: ${err.message}`);
          });

          return {
            success: true,
            provider,
            apiKey: result.apiKey,
            type: "api_key",
          };
        } catch (err) {
          // If container communication fails, try legacy fallback for migration period
          console.error(`[mcp] Container API key request failed: ${err.message}`);

          const legacyIntegration = await integrations.getDecryptedTokens(userId, provider);
          if (legacyIntegration?.apiKey) {
            logActivity(userId, ACTION_TYPES.CREDENTIAL_ACCESS, provider, {
              source: "legacy_fallback",
            }).catch(() => {});

            return {
              success: true,
              provider,
              apiKey: legacyIntegration.apiKey,
              type: "api_key",
              migrationHint: "Container unreachable. Retrieved from legacy storage.",
            };
          }

          return {
            success: false,
            error: "not_connected",
            message: `No ${provider} API key found. Add it in Connections.`,
          };
        }
      }

      // OAuth providers - stored in vault, requires unlock
      if (!vaultSessionToken || !vaultSessions.has(vaultSessionToken)) {
        return { success: false, error: "vault_locked", message: "Vault is locked." };
      }

      const session = vaultSessions.get(vaultSessionToken);
      if (session.userId !== userId || session.expiresAt <= Date.now()) {
        return { success: false, error: "vault_locked", message: "Vault session expired." };
      }

      const user = await users.findById(userId);
      if (!user.vault) {
        return { success: false, error: "no_vault", message: "No vault set up." };
      }

      try {
        const vaultData = unlockVaultWithKey(user.vault, session.vaultKey);

        if (!vaultData.integrations || !vaultData.integrations[provider]) {
          return {
            success: false,
            error: "not_connected",
            message: `No ${provider} integration found.`,
          };
        }

        let integration = vaultData.integrations[provider];

        // Check if token is expired and needs refresh
        if (new Date(integration.expiresAt) <= new Date()) {
          if (!integration.refreshToken) {
            return {
              success: false,
              error: "token_expired",
              message: "Token expired, no refresh token.",
            };
          }

          try {
            const refreshResponse = await axios.post("https://oauth2.googleapis.com/token", {
              client_id: process.env.GOOGLE_CLIENT_ID,
              client_secret: process.env.GOOGLE_CLIENT_SECRET,
              refresh_token: integration.refreshToken,
              grant_type: "refresh_token",
            });

            const { access_token, expires_in } = refreshResponse.data;
            integration.accessToken = access_token;
            integration.expiresAt = new Date(Date.now() + expires_in * 1000).toISOString();
            vaultData.integrations[provider] = integration;

            const updatedVault = updateVaultWithKey(user.vault, session.vaultKey, vaultData);
            await users.updateVault(userId, updatedVault);

            // Sync refreshed credentials to container's auth-profiles.json
            syncCredentialsFromVaultData(userId, vaultData).catch((err) => {
              console.error(`[mcp] Failed to sync refreshed credentials: ${err.message}`);
            });
          } catch (refreshErr) {
            return { success: false, error: "refresh_failed", message: refreshErr.message };
          }
        }

        // Log credential access for anomaly detection
        logActivity(userId, ACTION_TYPES.CREDENTIAL_ACCESS, provider, {
          email: integration.email,
        }).catch((err) => {
          console.error(`[mcp] Failed to log credential access: ${err.message}`);
        });

        return {
          success: true,
          provider,
          accessToken: integration.accessToken,
          expiresAt: integration.expiresAt,
          email: integration.email,
          scope: integration.scope,
          type: "oauth",
        };
      } catch (err) {
        return { success: false, error: "decrypt_failed", message: "Failed to decrypt vault." };
      }
    }

    case "ocmt_call_resource": {
      const {
        resourceId,
        method = "GET",
        path = "",
        query,
        body,
        headers: customHeaders,
      } = params || {};

      if (!resourceId) {
        return { success: false, error: "missing_resource_id", message: "resourceId is required" };
      }

      // Check if user has connected access to this resource
      const grant = await groupShares.findByResourceAndUser(resourceId, userId);
      if (!grant) {
        return {
          success: false,
          error: "no_access",
          message: "You do not have access to this resource",
        };
      }
      if (grant.status !== "connected") {
        return {
          success: false,
          error: "not_connected",
          message: "Resource not connected. Connect it first via the UI.",
        };
      }

      // Check granular permission for the HTTP method
      const requiredPermission = groupShares.getRequiredPermissionForMethod(method);
      if (!groupShares.hasPermission(grant, requiredPermission)) {
        // Parse permissions for helpful error message
        const perms =
          typeof grant.permissions === "string" ? JSON.parse(grant.permissions) : grant.permissions;
        const grantedPerms = Object.entries(perms)
          .filter(([_, v]) => v)
          .map(([k]) => k);

        return {
          success: false,
          error: "permission_denied",
          message: `Permission denied: ${method} requests require '${requiredPermission}' permission`,
          requiredPermission,
          grantedPermissions: grantedPerms,
          hint: `Ask an org admin to grant '${requiredPermission}' permission for this resource`,
        };
      }

      // Get resource details
      const resource = await groupResources.findById(resourceId);
      if (!resource) {
        return { success: false, error: "resource_not_found", message: "Resource not found" };
      }
      if (resource.status !== "active") {
        return { success: false, error: "resource_inactive", message: "Resource is not active" };
      }

      // Check if this resource belongs to another user's container (for wake-on-request)
      // Resource metadata may contain ownerUserId for peer-to-peer resources
      let wakeResult = null;
      const resourceMetadata = resource.metadata || {};
      const ownerUserId = resourceMetadata.ownerUserId;

      if (ownerUserId && ownerUserId !== userId) {
        // This is a peer resource - wake the owner's container if needed
        console.log(
          `[mcp] Resource ${resourceId} belongs to user ${ownerUserId.slice(0, 8)}, checking wake...`,
        );
        wakeResult = await wakeContainerIfNeeded(ownerUserId, "peer-resource-call");

        if (!wakeResult.success) {
          return {
            success: false,
            error: "owner_container_unavailable",
            message: wakeResult.error || "The resource owner's container is unavailable",
            wakeStatus: wakeResult.status,
            wakeTime: wakeResult.wakeTime,
          };
        }

        if (wakeResult.wakeTime > 0) {
          console.log(`[mcp] Owner container woke in ${wakeResult.wakeTime}ms`);
        }
      }

      // Check rate limit
      const rateLimit = checkRateLimit(userId, resourceId);
      if (!rateLimit.allowed) {
        return {
          success: false,
          error: "rate_limited",
          message: `Rate limit exceeded. Try again in ${rateLimit.retryAfter} seconds.`,
          rateLimit: {
            limit: rateLimit.limit,
            remaining: 0,
            resetAt: rateLimit.resetAt,
            retryAfter: rateLimit.retryAfter,
          },
        };
      }

      // Get decrypted auth config
      const authConfig = await groupResources.getDecryptedAuthConfig(resourceId);

      // Build request URL
      let url = resource.endpoint;
      if (path) {
        // Ensure proper URL joining
        url = url.replace(/\/$/, "") + "/" + path.replace(/^\//, "");
      }
      if (query && Object.keys(query).length > 0) {
        const queryString = new URLSearchParams(query).toString();
        url += (url.includes("?") ? "&" : "?") + queryString;
      }

      // Build headers
      // Security: Filter out sensitive headers from customHeaders to prevent header injection
      const BLOCKED_HEADERS = new Set([
        "authorization",
        "host",
        "cookie",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
        "referer",
        "origin",
      ]);

      const safeHeaders = Object.fromEntries(
        Object.entries(customHeaders || {}).filter(
          ([key]) => !BLOCKED_HEADERS.has(key.toLowerCase()),
        ),
      );

      const requestHeaders = {
        "Content-Type": "application/json",
        "User-Agent": "OpenPaw/1.0",
        ...safeHeaders,
      };

      // Apply auth from authConfig
      // Supports multiple formats:
      // - {type:"bearer", token:"xxx"}
      // - {type:"api_key", key:"xxx", header:"X-API-Key"}
      // - {type:"api_key", key:"xxx", query:"token"}
      // - {type:"api_key", location:"query", key:"token", value:"xxx"} (alternative format)
      // - {type:"api_key", location:"header", key:"X-API-Key", value:"xxx"} (alternative format)
      // - {type:"basic", username:"xxx", password:"xxx"}
      if (authConfig) {
        if (authConfig.type === "bearer" && authConfig.token) {
          requestHeaders["Authorization"] = `Bearer ${authConfig.token}`;
        } else if (authConfig.type === "api_key") {
          // Get the actual API key value
          const apiKeyValue = authConfig.value || authConfig.key;

          // Determine location (query or header)
          const location = authConfig.location || (authConfig.query ? "query" : "header");

          if (location === "query") {
            // Query parameter: key is the param name, value is the actual key
            const paramName = authConfig.location ? authConfig.key : authConfig.query;
            url +=
              (url.includes("?") ? "&" : "?") + `${paramName}=${encodeURIComponent(apiKeyValue)}`;
          } else {
            // Header: key is the header name (or default), value is the actual key
            const headerName = authConfig.location
              ? authConfig.key
              : authConfig.header || "X-API-Key";
            requestHeaders[headerName] = apiKeyValue;
          }
        } else if (authConfig.type === "basic") {
          const basicAuth = Buffer.from(`${authConfig.username}:${authConfig.password}`).toString(
            "base64",
          );
          requestHeaders["Authorization"] = `Basic ${basicAuth}`;
        }
      }

      // SSRF Protection: Validate URL does not point to private/internal IPs
      const ssrfCheck = await validateUrlForSSRF(url);
      if (!ssrfCheck.safe) {
        console.warn(
          `[mcp] SSRF attempt blocked for user ${userId.slice(0, 8)}: ${ssrfCheck.error}`,
        );
        return {
          success: false,
          error: "ssrf_blocked",
          message: ssrfCheck.error,
        };
      }

      try {
        const response = await axios({
          method: method.toLowerCase(),
          url,
          headers: requestHeaders,
          data: body,
          timeout: 30000,
          validateStatus: () => true, // Don't throw on non-2xx
          maxContentLength: 5 * 1024 * 1024, // 5MB response size limit
          maxBodyLength: 5 * 1024 * 1024, // 5MB request body limit
        });

        // Audit log the call (include wake info if applicable)
        audit
          .log(userId, "resource.call", {
            resourceId,
            resourceName: resource.name,
            groupId: resource.group_id,
            method,
            path,
            status: response.status,
            wakeTime: wakeResult?.wakeTime || 0,
            ownerUserId: ownerUserId || null,
          })
          .catch(() => {}); // Don't fail on audit errors

        // Log for anomaly detection
        logActivity(userId, ACTION_TYPES.GROUP_RESOURCE_CALL, resource.name, {
          resourceId,
          method,
          path,
          status: response.status,
          wakeTime: wakeResult?.wakeTime || 0,
        }).catch((err) => {
          console.error(`[mcp] Failed to log resource call: ${err.message}`);
        });

        const result = {
          success: true,
          status: response.status,
          statusText: response.statusText,
          headers: response.headers,
          data: response.data,
          rateLimit: {
            remaining: rateLimit.remaining,
            limit: rateLimit.limit,
          },
        };

        // Include wake info if container was woken
        if (wakeResult && wakeResult.wakeTime > 0) {
          result.wake = {
            wakeTime: wakeResult.wakeTime,
            status: wakeResult.status,
          };
        }

        return result;
      } catch (err) {
        return {
          success: false,
          error: "request_failed",
          message: err.message,
          code: err.code,
          rateLimit: {
            remaining: rateLimit.remaining,
            limit: rateLimit.limit,
          },
        };
      }
    }

    case "ocmt_list_my_groups": {
      const memberships = await groupMemberships.listByUser(userId);
      return {
        success: true,
        groups: memberships.map((m) => ({
          groupId: m.group_id,
          name: m.group_name,
          slug: m.group_slug,
          role: m.role,
          joinedAt: m.joined_at,
        })),
      };
    }

    case "ocmt_create_resource": {
      const { groupId, name, description, endpoint, resourceType, authConfig } = params || {};

      if (!groupId || !name || !endpoint) {
        return {
          success: false,
          error: "missing_params",
          message: "groupId, name, and endpoint are required",
        };
      }

      // Check if user is admin of this group
      const isAdmin = await groupMemberships.isAdmin(userId, groupId);
      if (!isAdmin) {
        return {
          success: false,
          error: "not_admin",
          message: "You must be a group admin to create resources",
        };
      }

      // SSRF Protection: Validate endpoint URL does not point to private/internal IPs
      const ssrfCheck = await validateUrlForSSRF(endpoint);
      if (!ssrfCheck.safe) {
        console.warn(
          `[mcp] SSRF attempt blocked in resource creation for user ${userId.slice(0, 8)}: ${ssrfCheck.error}`,
        );
        return {
          success: false,
          error: "ssrf_blocked",
          message: ssrfCheck.error,
        };
      }

      const resource = await groupResources.create({
        groupId,
        name,
        description,
        endpoint,
        resourceType: resourceType || "api",
        authConfig,
        metadata: {},
      });

      return {
        success: true,
        resource: {
          id: resource.id,
          name: resource.name,
          endpoint: resource.endpoint,
          resourceType: resource.resource_type,
          status: resource.status,
        },
        hint: `Resource created! Grant yourself access with: ocmt_grant_resource_access {"resourceId":"${resource.id}","userId":"me"}`,
      };
    }

    case "ocmt_grant_resource_access": {
      const { resourceId, userId: targetUserId, permissions, autoConnect } = params || {};

      if (!resourceId) {
        return { success: false, error: "missing_params", message: "resourceId is required" };
      }

      // Get resource to find org
      const resource = await groupResources.findById(resourceId);
      if (!resource) {
        return { success: false, error: "not_found", message: "Resource not found" };
      }

      // Check if user is admin of this org
      const isAdmin = await groupMemberships.isAdmin(userId, resource.group_id);
      if (!isAdmin) {
        return {
          success: false,
          error: "not_admin",
          message: "You must be an org admin to grant access",
        };
      }

      // Handle "me" as target
      const granteeId = targetUserId === "me" || !targetUserId ? userId : targetUserId;

      // Check target is group member
      const isMember = await groupMemberships.isMember(granteeId, resource.group_id);
      if (!isMember) {
        return {
          success: false,
          error: "not_member",
          message: "Target user must be a group member",
        };
      }

      const grant = await groupShares.create({
        groupId: resource.group_id,
        resourceId,
        userId: granteeId,
        permissions: permissions || ["read", "write"],
        grantedBy: userId,
      });

      // Auto-connect if granting to self or explicitly requested
      const shouldAutoConnect =
        autoConnect !== false && (granteeId === userId || autoConnect === true);
      if (shouldAutoConnect) {
        await groupShares.connect(grant.id);
      }

      return {
        success: true,
        grant: {
          id: grant.id,
          resourceId,
          userId: granteeId,
          status: shouldAutoConnect ? "connected" : "granted",
          permissions: grant.permissions,
        },
        hint: shouldAutoConnect
          ? `Access granted and connected! You can now use: ocmt_call_resource {"resourceId":"${resourceId}"}`
          : "Access granted. User needs to connect via UI to use the resource.",
      };
    }

    case "ocmt_delete_resource": {
      const { resourceId } = params || {};

      if (!resourceId) {
        return { success: false, error: "missing_params", message: "resourceId is required" };
      }

      const resource = await groupResources.findById(resourceId);
      if (!resource) {
        return { success: false, error: "not_found", message: "Resource not found" };
      }

      const isAdmin = await groupMemberships.isAdmin(userId, resource.group_id);
      if (!isAdmin) {
        return {
          success: false,
          error: "not_admin",
          message: "You must be an org admin to delete resources",
        };
      }

      await groupResources.delete(resourceId);

      return { success: true, message: `Resource "${resource.name}" deleted` };
    }

    case "ocmt_wake_metrics": {
      // Get wake-on-request metrics
      const metrics = getWakeOnRequestMetrics();
      return {
        success: true,
        metrics,
        hint: "These metrics track container wake operations triggered by resource requests",
      };
    }

    default:
      throw new Error(`Unknown tool: ${toolName}`);
  }
}

/**
 * Middleware to authenticate container requests
 * Supports both ephemeral tokens (preferred) and legacy permanent tokens
 */
export async function requireContainerAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  const userId = req.headers["x-user-id"];

  if (!authHeader?.startsWith("Bearer ") || !userId) {
    return res.status(401).json({ error: "Missing authorization" });
  }

  const token = authHeader.slice(7);

  try {
    const user = await users.findById(userId);
    if (!user || !user.gateway_token) {
      return res.status(403).json({ error: "Invalid container token" });
    }

    // Detect token type and validate accordingly
    const tokenType = detectTokenType(token);

    if (tokenType === "ephemeral") {
      // Validate ephemeral token using the stored permanent token as key
      let permanentToken;
      try {
        // Try to decrypt stored token (encrypted format)
        permanentToken = decryptGatewayToken(user.gateway_token);
      } catch {
        // Legacy unencrypted token
        permanentToken = user.gateway_token;
      }

      const payload = validateEphemeralToken(token, permanentToken);
      if (!payload) {
        return res.status(403).json({ error: "Invalid or expired container token" });
      }

      // Verify userId matches
      if (payload.userId !== userId) {
        return res.status(403).json({ error: "Token userId mismatch" });
      }
    } else if (tokenType === "permanent") {
      // Legacy flow: direct comparison with stored token
      // Get the raw permanent token for comparison
      let storedRawToken;
      try {
        storedRawToken = decryptGatewayToken(user.gateway_token);
      } catch {
        // Legacy unencrypted token
        storedRawToken = user.gateway_token;
      }

      // Timing-safe comparison to prevent timing attacks
      const tokenBuf = Buffer.from(token);
      const storedBuf = Buffer.from(storedRawToken);
      if (tokenBuf.length !== storedBuf.length || !crypto.timingSafeEqual(tokenBuf, storedBuf)) {
        return res.status(403).json({ error: "Invalid container token" });
      }
    } else {
      return res.status(403).json({ error: "Invalid token format" });
    }

    req.userId = userId;
    req.containerUser = user;
    next();
  } catch (err) {
    console.error("[mcp] Container auth error:", err.message);
    res.status(500).json({ error: "Authentication failed" });
  }
}
