/**
 * Secret Store HTTP Handler
 *
 * Wires the container-side secret store API into the gateway HTTP server.
 * All secret operations are local to the container - secrets never leave
 * in plaintext.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import type { ResolvedGatewayAuth } from "./auth.js";
import { loadConfig } from "../config/config.js";
import {
  executeCapability,
  extendSession,
  generateUnlockChallenge,
  getIntegration,
  getVaultStatus,
  issueCapability,
  listCapabilities,
  listIntegrations,
  lockVault,
  revokeCapability,
  setIntegration,
  verifyUnlockChallenge,
  type UnlockVerifyRequest,
} from "../container/secret-api.js";
import { getSecretStore } from "../container/secret-store.js";
import { authorizeGatewayConnect } from "./auth.js";
import { readJsonBody } from "./hooks.js";
import {
  sendInvalidRequest,
  sendJson,
  sendMethodNotAllowed,
  sendUnauthorized,
} from "./http-common.js";
import { getBearerToken } from "./http-utils.js";
import { getClientIp } from "./http-utils.js";

const SECRET_STORE_BASE_PATH = "/v1/secrets";
const MAX_BODY_BYTES = 64 * 1024; // 64KB max for secret store requests

// Rate limiting for secret store - prevent brute force on unlock
const RATE_LIMIT_WINDOW_MS = 60_000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 30; // 30 requests per minute per IP
const rateLimitStore = new Map<string, { count: number; windowStart: number }>();

// Exponential backoff for failed vault unlock attempts
const failedAttempts = new Map<
  string,
  { count: number; lastAttempt: number; lockedUntil: number }
>();

function getBackoffMs(failures: number): number {
  // Exponential backoff: 1s, 2s, 4s, 8s, 16s, 32s, 60s, 120s, 300s (max 5 min)
  return Math.min(1000 * Math.pow(2, failures - 1), 300000);
}

function checkFailedAttempts(ip: string): { allowed: boolean; retryAfterMs?: number } {
  const entry = failedAttempts.get(ip);
  if (!entry) {
    return { allowed: true };
  }

  const now = Date.now();
  if (entry.lockedUntil > now) {
    return { allowed: false, retryAfterMs: entry.lockedUntil - now };
  }

  return { allowed: true };
}

function recordFailedAttempt(ip: string): void {
  const entry = failedAttempts.get(ip) || { count: 0, lastAttempt: 0, lockedUntil: 0 };
  entry.count++;
  entry.lastAttempt = Date.now();
  entry.lockedUntil = Date.now() + getBackoffMs(entry.count);
  failedAttempts.set(ip, entry);

  // Log for security monitoring
  console.warn(
    `[security] Failed vault unlock attempt ${entry.count} from ${ip}, locked for ${getBackoffMs(entry.count)}ms`,
  );
}

function recordSuccessfulAttempt(ip: string): void {
  failedAttempts.delete(ip); // Reset on success
}

// Cleanup stale rate limit entries periodically
const cleanupInterval = setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitStore.entries()) {
    if (now - entry.windowStart > RATE_LIMIT_WINDOW_MS * 2) {
      rateLimitStore.delete(key);
    }
  }
  // Also clean up old failed attempt entries (1 hour max age)
  const maxAge = 3600000;
  for (const [ip, entry] of failedAttempts.entries()) {
    if (now - entry.lastAttempt > maxAge) {
      failedAttempts.delete(ip);
    }
  }
}, RATE_LIMIT_WINDOW_MS);
cleanupInterval.unref();

function checkRateLimit(req: IncomingMessage): boolean {
  const ip = getClientIp(req) ?? "unknown";
  const now = Date.now();
  let entry = rateLimitStore.get(ip);

  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
    entry = { count: 1, windowStart: now };
    rateLimitStore.set(ip, entry);
    return true;
  }

  entry.count++;
  if (entry.count > RATE_LIMIT_MAX_REQUESTS) {
    return false;
  }
  return true;
}

type SecretStoreHttpOpts = {
  auth: ResolvedGatewayAuth;
  trustedProxies?: string[];
};

/**
 * Handle secret store HTTP requests
 * Returns true if the request was handled, false otherwise
 */
export async function handleSecretStoreHttpRequest(
  req: IncomingMessage,
  res: ServerResponse,
  opts: SecretStoreHttpOpts,
): Promise<boolean> {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);

  // Check if this is a secret store request
  if (!url.pathname.startsWith(SECRET_STORE_BASE_PATH)) {
    return false;
  }

  // Rate limit check - prevent brute force attacks on vault unlock
  if (!checkRateLimit(req)) {
    res.statusCode = 429;
    res.setHeader("Content-Type", "application/json");
    res.setHeader("Retry-After", "60");
    res.end(JSON.stringify({ error: "Too many requests" }));
    return true;
  }

  // Extract subpath after base
  const subPath = url.pathname.slice(SECRET_STORE_BASE_PATH.length);

  // Authenticate request (secret store requires gateway auth)
  const cfg = loadConfig();
  const token = getBearerToken(req);
  const authResult = await authorizeGatewayConnect({
    auth: opts.auth,
    connectAuth: token ? { token, password: token } : null,
    req,
    trustedProxies: opts.trustedProxies ?? cfg.gateway?.trustedProxies,
  });

  if (!authResult.ok) {
    sendUnauthorized(res);
    return true;
  }

  // Route to appropriate handler
  try {
    // GET /v1/secrets/status - Get vault status (no body)
    if (subPath === "/status" && req.method === "GET") {
      const status = getVaultStatus();
      sendJson(res, 200, status);
      return true;
    }

    // POST /v1/secrets/unlock/challenge - Generate unlock challenge
    if (subPath === "/unlock/challenge" && req.method === "POST") {
      const challenge = generateUnlockChallenge();
      sendJson(res, 200, challenge);
      return true;
    }

    // POST /v1/secrets/unlock/verify - Verify challenge and unlock
    if (subPath === "/unlock/verify" && req.method === "POST") {
      const clientIp = getClientIp(req) ?? "unknown";

      // Check exponential backoff for failed attempts
      const backoffCheck = checkFailedAttempts(clientIp);
      if (!backoffCheck.allowed) {
        res.statusCode = 429;
        res.setHeader("Content-Type", "application/json");
        res.setHeader("Retry-After", String(Math.ceil((backoffCheck.retryAfterMs ?? 0) / 1000)));
        res.end(
          JSON.stringify({
            error: "Too many failed attempts",
            retryAfterMs: backoffCheck.retryAfterMs,
          }),
        );
        return true;
      }

      const body = await readJsonBody(req, MAX_BODY_BYTES);
      if (!body.ok) {
        sendInvalidRequest(res, body.error);
        return true;
      }
      const result = await verifyUnlockChallenge(body.value as UnlockVerifyRequest);

      // Track failed/successful attempts for exponential backoff
      if (result.success) {
        recordSuccessfulAttempt(clientIp);
      } else {
        recordFailedAttempt(clientIp);
      }

      sendJson(res, result.success ? 200 : 401, result);
      return true;
    }

    // POST /v1/secrets/lock - Lock the vault
    if (subPath === "/lock" && req.method === "POST") {
      const result = lockVault();
      sendJson(res, 200, result);
      return true;
    }

    // POST /v1/secrets/extend - Extend session
    if (subPath === "/extend" && req.method === "POST") {
      try {
        const result = extendSession();
        sendJson(res, 200, result);
      } catch (err) {
        sendJson(res, 400, { success: false, error: (err as Error).message });
      }
      return true;
    }

    // POST /v1/secrets/initialize - Initialize new vault
    if (subPath === "/initialize" && req.method === "POST") {
      const body = await readJsonBody(req, MAX_BODY_BYTES);
      if (!body.ok) {
        sendInvalidRequest(res, body.error);
        return true;
      }
      const payload = body.value as { password?: string };
      if (!payload.password || typeof payload.password !== "string") {
        sendInvalidRequest(res, "password is required");
        return true;
      }
      try {
        const store = getSecretStore();
        await store.initialize(payload.password);
        sendJson(res, 200, { success: true });
      } catch (err) {
        sendJson(res, 400, { success: false, error: (err as Error).message });
      }
      return true;
    }

    // POST /v1/secrets/unlock - Unlock with password directly
    if (subPath === "/unlock" && req.method === "POST") {
      const clientIp = getClientIp(req) ?? "unknown";

      // Check exponential backoff for failed attempts
      const backoffCheck = checkFailedAttempts(clientIp);
      if (!backoffCheck.allowed) {
        res.statusCode = 429;
        res.setHeader("Content-Type", "application/json");
        res.setHeader("Retry-After", String(Math.ceil((backoffCheck.retryAfterMs ?? 0) / 1000)));
        res.end(
          JSON.stringify({
            error: "Too many failed attempts",
            retryAfterMs: backoffCheck.retryAfterMs,
          }),
        );
        return true;
      }

      const body = await readJsonBody(req, MAX_BODY_BYTES);
      if (!body.ok) {
        sendInvalidRequest(res, body.error);
        return true;
      }
      const payload = body.value as { password?: string };
      if (!payload.password || typeof payload.password !== "string") {
        sendInvalidRequest(res, "password is required");
        return true;
      }
      try {
        const store = getSecretStore();
        const unlocked = await store.unlock(payload.password);
        if (unlocked) {
          recordSuccessfulAttempt(clientIp);
          sendJson(res, 200, {
            success: true,
            expiresIn: store.getSessionTimeRemaining(),
          });
        } else {
          recordFailedAttempt(clientIp);
          sendJson(res, 401, { success: false, error: "Invalid password" });
        }
      } catch (err) {
        sendJson(res, 400, { success: false, error: (err as Error).message });
      }
      return true;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Integration Management
    // ─────────────────────────────────────────────────────────────────────────

    // GET /v1/secrets/integrations - List integrations
    if (subPath === "/integrations" && req.method === "GET") {
      const result = listIntegrations();
      sendJson(res, result.success ? 200 : 400, result);
      return true;
    }

    // GET /v1/secrets/integrations/:provider - Get specific integration
    const integrationMatch = subPath.match(/^\/integrations\/([^/]+)$/);
    if (integrationMatch && req.method === "GET") {
      const provider = decodeURIComponent(integrationMatch[1]);
      const result = getIntegration(provider);
      sendJson(res, result.success ? 200 : 400, result);
      return true;
    }

    // PUT /v1/secrets/integrations/:provider - Set integration
    if (integrationMatch && req.method === "PUT") {
      const provider = decodeURIComponent(integrationMatch[1]);
      const body = await readJsonBody(req, MAX_BODY_BYTES);
      if (!body.ok) {
        sendInvalidRequest(res, body.error);
        return true;
      }
      const integration = body.value as {
        accessToken: string;
        refreshToken?: string;
        expiresAt: string;
        email?: string;
        scopes?: string[];
      };
      if (!integration.accessToken || !integration.expiresAt) {
        sendInvalidRequest(res, "accessToken and expiresAt are required");
        return true;
      }
      try {
        const result = await setIntegration(provider, integration);
        sendJson(res, 200, result);
      } catch (err) {
        sendJson(res, 400, { success: false, error: (err as Error).message });
      }
      return true;
    }

    // DELETE /v1/secrets/integrations/:provider - Remove integration
    if (integrationMatch && req.method === "DELETE") {
      const provider = decodeURIComponent(integrationMatch[1]);
      try {
        const store = getSecretStore();
        await store.removeIntegration(provider);
        sendJson(res, 200, { success: true });
      } catch (err) {
        sendJson(res, 400, { success: false, error: (err as Error).message });
      }
      return true;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Capability Management
    // ─────────────────────────────────────────────────────────────────────────

    // POST /v1/secrets/capabilities/issue - Issue a capability
    if (subPath === "/capabilities/issue" && req.method === "POST") {
      const body = await readJsonBody(req, MAX_BODY_BYTES);
      if (!body.ok) {
        sendInvalidRequest(res, body.error);
        return true;
      }
      const result = await issueCapability(body.value as Parameters<typeof issueCapability>[0]);
      sendJson(res, result.success ? 200 : 400, result);
      return true;
    }

    // POST /v1/secrets/capabilities/:id/revoke - Revoke a capability
    const revokeMatch = subPath.match(/^\/capabilities\/([^/]+)\/revoke$/);
    if (revokeMatch && req.method === "POST") {
      const id = decodeURIComponent(revokeMatch[1]);
      const result = await revokeCapability(id);
      sendJson(res, result.success ? 200 : 400, result);
      return true;
    }

    // GET /v1/secrets/capabilities/issued - List issued capabilities
    if (subPath === "/capabilities/issued" && req.method === "GET") {
      const result = listCapabilities("issued");
      sendJson(res, result.success ? 200 : 400, result);
      return true;
    }

    // GET /v1/secrets/capabilities/received - List received capabilities
    if (subPath === "/capabilities/received" && req.method === "GET") {
      const result = listCapabilities("received");
      sendJson(res, result.success ? 200 : 400, result);
      return true;
    }

    // POST /v1/secrets/capabilities/execute - Execute a capability
    if (subPath === "/capabilities/execute" && req.method === "POST") {
      const body = await readJsonBody(req, MAX_BODY_BYTES);
      if (!body.ok) {
        sendInvalidRequest(res, body.error);
        return true;
      }
      const result = await executeCapability(body.value as Parameters<typeof executeCapability>[0]);
      sendJson(res, result.success ? 200 : 400, result);
      return true;
    }

    // POST /v1/secrets/capabilities/store - Store a received capability
    if (subPath === "/capabilities/store" && req.method === "POST") {
      const body = await readJsonBody(req, MAX_BODY_BYTES);
      if (!body.ok) {
        sendInvalidRequest(res, body.error);
        return true;
      }
      const payload = body.value as { token: string; issuerContainerId: string };
      if (!payload.token || !payload.issuerContainerId) {
        sendInvalidRequest(res, "token and issuerContainerId are required");
        return true;
      }
      try {
        const store = getSecretStore();
        const id = await store.storeReceivedCapability(payload.token, payload.issuerContainerId);
        sendJson(res, 200, { success: true, id });
      } catch (err) {
        sendJson(res, 400, { success: false, error: (err as Error).message });
      }
      return true;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Migration Support
    // ─────────────────────────────────────────────────────────────────────────

    // POST /v1/secrets/import - Bulk import integrations (for migration)
    if (subPath === "/import" && req.method === "POST") {
      const body = await readJsonBody(req, MAX_BODY_BYTES);
      if (!body.ok) {
        sendInvalidRequest(res, body.error);
        return true;
      }
      const payload = body.value as {
        integrations?: Record<
          string,
          {
            accessToken: string;
            refreshToken?: string;
            expiresAt: string;
            email?: string;
            scopes?: string[];
          }
        >;
      };
      if (!payload.integrations || typeof payload.integrations !== "object") {
        sendInvalidRequest(res, "integrations object is required");
        return true;
      }

      try {
        const store = getSecretStore();
        if (!store.isUnlocked()) {
          sendJson(res, 400, { success: false, error: "Vault is locked" });
          return true;
        }

        const results: { imported: string[]; failed: Array<{ provider: string; error: string }> } =
          {
            imported: [],
            failed: [],
          };

        for (const [provider, integration] of Object.entries(payload.integrations)) {
          try {
            if (!integration.accessToken || !integration.expiresAt) {
              results.failed.push({ provider, error: "accessToken and expiresAt are required" });
              continue;
            }
            await store.setIntegration(provider, integration);
            results.imported.push(provider);
          } catch (err) {
            results.failed.push({ provider, error: (err as Error).message });
          }
        }

        sendJson(res, 200, {
          success: results.failed.length === 0,
          partial: results.imported.length > 0 && results.failed.length > 0,
          imported: results.imported,
          failed: results.failed,
        });
      } catch (err) {
        sendJson(res, 400, { success: false, error: (err as Error).message });
      }
      return true;
    }

    // GET /v1/secrets/export - Export all integrations (for backup/migration)
    if (subPath === "/export" && req.method === "GET") {
      try {
        const store = getSecretStore();
        if (!store.isUnlocked()) {
          sendJson(res, 400, { success: false, error: "Vault is locked" });
          return true;
        }

        // Get full integration data (including tokens)
        const integrations = store.listIntegrations();
        const fullIntegrations: Record<string, unknown> = {};

        for (const { provider } of integrations) {
          const integration = store.getIntegration(provider);
          if (integration) {
            fullIntegrations[provider] = integration;
          }
        }

        sendJson(res, 200, {
          success: true,
          integrations: fullIntegrations,
          exportedAt: new Date().toISOString(),
        });
      } catch (err) {
        sendJson(res, 400, { success: false, error: (err as Error).message });
      }
      return true;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Snapshot Management (CACHED tier sharing)
    // ─────────────────────────────────────────────────────────────────────────

    // POST /v1/secrets/snapshots/sync - Sync CACHED tier snapshots
    // Refreshes due snapshots and pushes them to the relay
    if (subPath === "/snapshots/sync" && req.method === "POST") {
      try {
        const store = getSecretStore();
        if (!store.isUnlocked()) {
          sendJson(res, 400, { success: false, error: "Vault is locked" });
          return true;
        }

        const result = await store.syncSnapshots();
        sendJson(res, 200, {
          success: true,
          ...result,
        });
      } catch (err) {
        sendJson(res, 500, { success: false, error: (err as Error).message });
      }
      return true;
    }

    // GET /v1/secrets/snapshots/status - Get snapshot status
    // Returns pending snapshots count and capabilities needing refresh
    if (subPath === "/snapshots/status" && req.method === "GET") {
      try {
        const store = getSecretStore();
        if (!store.isUnlocked()) {
          sendJson(res, 400, { success: false, error: "Vault is locked" });
          return true;
        }

        const pendingSnapshots = store.getPendingSnapshots();
        const needingRefresh = store.getCapabilitiesNeedingRefresh();

        sendJson(res, 200, {
          success: true,
          pendingCount: pendingSnapshots.length,
          needingRefreshCount: needingRefresh.length,
          pendingCapabilityIds: pendingSnapshots.map((s) => s.capabilityId),
          needingRefreshCapabilityIds: needingRefresh.map((g) => g.id),
        });
      } catch (err) {
        sendJson(res, 500, { success: false, error: (err as Error).message });
      }
      return true;
    }

    // POST /v1/secrets/snapshots/fetch - Fetch all available snapshots from relay
    // Used to sync CACHED tier capabilities when coming online
    if (subPath === "/snapshots/fetch" && req.method === "POST") {
      try {
        const store = getSecretStore();
        if (!store.isUnlocked()) {
          sendJson(res, 400, { success: false, error: "Vault is locked" });
          return true;
        }

        const result = await store.fetchAllAvailableSnapshots();
        sendJson(res, 200, {
          success: result.errors.length === 0,
          ...result,
        });
      } catch (err) {
        sendJson(res, 500, { success: false, error: (err as Error).message });
      }
      return true;
    }

    // Method not allowed for known paths
    if (subPath === "/status") {
      sendMethodNotAllowed(res, "GET");
      return true;
    }
    if (subPath === "/unlock/challenge" || subPath === "/unlock/verify" || subPath === "/lock") {
      sendMethodNotAllowed(res, "POST");
      return true;
    }
    if (subPath === "/integrations") {
      sendMethodNotAllowed(res, "GET");
      return true;
    }
    if (integrationMatch) {
      sendMethodNotAllowed(res, "GET, PUT, DELETE");
      return true;
    }

    // Not found
    sendJson(res, 404, { error: "Not found" });
    return true;
  } catch (err) {
    sendJson(res, 500, { error: (err as Error).message });
    return true;
  }
}
