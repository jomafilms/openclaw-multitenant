import cookieParser from "cookie-parser";
import dotenv from "dotenv";
// OCMT Management Server
import express from "express";
import { createServer } from "http";
import { Resend } from "resend";
// Error handling and security
import { AppError, serializeError } from "./lib/errors.js";
import { generalApiLimiter } from "./lib/rate-limit.js";
import { getRelayStatus } from "./lib/relay.js";
import { setupWebSocketProxy } from "./lib/ws-proxy.js";
// Security middleware
import { attachCsrfToken, csrfProtection } from "./middleware/csrf.js";
import {
  bodyLimitConfig,
  corsMiddleware,
  createSecurityHeaders,
  httpsRedirect,
} from "./middleware/security-headers.js";
import adminSecurityRouter from "./routes/admin-security.js";
// Route imports
import adminRouter from "./routes/admin.js";
import agentRouter from "./routes/agent.js";
import approvalsRouter from "./routes/approvals.js";
import auditExportRouter from "./routes/audit-export.js";
import auditRouter from "./routes/audit.js";
import authOAuthRouter from "./routes/auth-oauth.js";
import authSamlRouter from "./routes/auth-saml.js";
import authRouter, { setResend } from "./routes/auth.js";
// Billing routes (subscription management, Stripe integration)
import billingRouter from "./routes/billing.js";
import biometricsRouter from "./routes/biometrics.js";
import channelsRouter from "./routes/channels.js";
import chatRouter from "./routes/chat.js";
import containerRouter from "./routes/container.js";
import groupInvitesRouter from "./routes/group-invites.js";
import groupVaultContainerRouter from "./routes/group-vault-container.js";
// Group vault routes (threshold unlock, container management)
import groupVaultRouter from "./routes/group-vault.js";
// Group/shares routes (unified naming)
import groupsRouter from "./routes/groups.js";
import integrationsRouter from "./routes/integrations.js";
import internalRouter from "./routes/internal.js";
import mcpRouter from "./routes/mcp.js";
import mfaRouter from "./routes/mfa.js";
import notificationsRouter from "./routes/notifications.js";
import oauthRouter from "./routes/oauth.js";
// Platform admin routes (tenant/user/container management, platform stats)
import platformAdminRouter from "./routes/platform-admin.js";
// RBAC routes (role and permission management)
import rbacRouter from "./routes/rbac.js";
import recoveryRouter from "./routes/recovery.js";
import relayRouter from "./routes/relay.js";
import resourceSharesRouter from "./routes/resource-shares.js";
import securityEventsRouter from "./routes/security-events.js";
import sessionsRouter from "./routes/sessions.js";
import settingsRouter from "./routes/settings.js";
import sharesRouter from "./routes/shares.js";
// SLA monitoring routes (SLA status, reports, credits)
import slaRouter from "./routes/sla.js";
// Tenant backup and restore (per-tenant backup/restore, export/import)
import tenantBackupRouter from "./routes/tenant-backup.js";
// Tenant branding routes (white-label customization)
import tenantBrandingRouter from "./routes/tenant-branding.js";
import unlockRouter from "./routes/unlock.js";
import userGroupsRouter from "./routes/user-groups.js";
import vaultRouter from "./routes/vault.js";

dotenv.config();

const app = express();

// Trust proxy configuration for secure IP detection
// TRUST_PROXY can be: number (1, 2), 'true', 'false', 'loopback', or IP ranges
const TRUST_PROXY = process.env.TRUST_PROXY || "loopback";

if (TRUST_PROXY === "true" || TRUST_PROXY === "1") {
  app.set("trust proxy", true);
} else if (TRUST_PROXY === "false" || TRUST_PROXY === "0") {
  app.set("trust proxy", false);
} else if (/^\d+$/.test(TRUST_PROXY)) {
  app.set("trust proxy", parseInt(TRUST_PROXY, 10));
} else {
  // String value like "loopback" or "10.0.0.0/8, 172.16.0.0/12"
  app.set("trust proxy", TRUST_PROXY);
}

// ============================================================
// SECURITY MIDDLEWARE (applied in order)
// ============================================================

// 1. HTTPS redirect (first, before anything else in production)
app.use(httpsRedirect());

// 2. Security headers (Helmet - CSP, HSTS, X-Frame-Options, etc.)
const USER_UI_URL = process.env.USER_UI_URL || "http://localhost:5173";
app.use(
  createSecurityHeaders({
    isDevelopment: process.env.NODE_ENV !== "production",
    additionalConnectSrc: [USER_UI_URL],
  }),
);

// 3. Body size limits and parsers
const bodyLimits = bodyLimitConfig(process.env.REQUEST_BODY_LIMIT || "100kb");

// For Stripe webhook: capture raw body for signature verification
// Must come before general body parsers
app.use("/api/billing/webhook", express.raw({ type: "application/json" }));

// For MCP endpoint: capture raw body for debugging JSON parse errors
// Must come before general body parsers
app.use("/api/mcp", express.raw({ type: "application/json", limit: "10mb" }), (req, res, next) => {
  if (req.body && Buffer.isBuffer(req.body)) {
    let rawBody = req.body.toString("utf8");
    try {
      req.body = JSON.parse(rawBody);
    } catch (err) {
      // Try to fix common malformations before giving up
      // Pattern: extra } before , "id" - e.g., }}, "id" should be }, "id"
      const fixedBody = rawBody
        .replace(/\}\}\}, "id"/g, '}}, "id"') // Fix triple } before "id"
        .replace(/\}\}\}\}, "id"/g, '}}, "id"'); // Fix quadruple } before "id"

      if (fixedBody !== rawBody) {
        try {
          req.body = JSON.parse(fixedBody);
          console.log("[mcp] Fixed malformed JSON (extra closing braces)");
          return next();
        } catch (fixErr) {
          // Fix didn't work, continue to error handling
        }
      }

      console.error("[mcp] JSON parse error:", err.message);
      console.error("[mcp] Raw body (first 500 chars):", rawBody.slice(0, 500));
      console.error("[mcp] Raw body length:", rawBody.length);
      // Check for common issues
      if (rawBody.includes("\n")) {
        console.error("[mcp] Body contains newlines - possible double-encoding");
      }
      if (rawBody.includes("\\n")) {
        console.error("[mcp] Body contains escaped newlines");
      }
      return res.status(400).json({
        jsonrpc: "2.0",
        id: null,
        error: {
          code: -32700,
          message: `Parse error: ${err.message}`,
          // Note: rawBodyPreview removed from response to prevent leaking secrets
          // Server-side logging above captures details for debugging
        },
      });
    }
  }
  next();
});

// General body parsers with size limits
app.use(express.json(bodyLimits.json));
app.use(express.urlencoded(bodyLimits.urlencoded));

// 4. Cookie parser (needed for session cookies)
app.use(cookieParser());

// 5. CORS middleware (replaces inline CORS handling)
// Uses security-headers corsMiddleware for proper origin validation
app.use("/api", corsMiddleware({ origin: USER_UI_URL, credentials: true }));

// Initialize email service
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;
setResend(resend);

// ============================================================
// PUBLIC PAGES - Redirect to User UI
// ============================================================

app.get("/", (req, res) => res.redirect(USER_UI_URL));
app.get("/signup", (req, res) => res.redirect(USER_UI_URL));
app.get("/welcome", (req, res) => res.redirect(`${USER_UI_URL}/dashboard`));
app.get("/about", (req, res) => res.redirect(USER_UI_URL));
app.get("/status", (req, res) => res.redirect(`${USER_UI_URL}/dashboard`));
app.post("/signup", (req, res) => res.redirect(USER_UI_URL));

// Health check (includes relay status)
app.get("/health", (req, res) => {
  const relayStatus = getRelayStatus();
  res.json({
    status: "ok",
    relay: {
      healthy: relayStatus.healthy,
      url: relayStatus.url,
    },
  });
});

// Unlock page handler (from agent-generated magic links)
app.use("/unlock", unlockRouter);

// ============================================================
// API ROUTES
// ============================================================

// Apply general rate limiting to all API routes
// 1000 requests per hour per IP
app.use("/api", generalApiLimiter);

// 6. Attach CSRF token to responses (for authenticated requests)
// This sets the XSRF-TOKEN cookie that the frontend can read
app.use("/api", attachCsrfToken);

// 7. CSRF protection for state-changing requests
// Applied to all API routes - skips safe methods (GET, HEAD, OPTIONS)
// and requests with API keys or Bearer tokens
app.use("/api", csrfProtection);

// Authentication
app.use("/api/auth", authRouter);
app.use("/api/auth", authOAuthRouter);
app.use("/api/auth/saml", authSamlRouter);

// Session management (list, revoke, sign out everywhere)
app.use("/api/auth/sessions", sessionsRouter);

// MFA routes (TOTP setup, verification, backup codes)
app.use("/api/mfa", mfaRouter);

// Vault management
app.use("/api/vault", vaultRouter);
app.use("/api/vault/biometrics", biometricsRouter);

// Recovery options (social recovery, hardware backup)
app.use("/api/recovery", recoveryRouter);

// Unlock token endpoints (for UI)
app.use("/api/vault", unlockRouter);

// Integrations and OAuth
app.use("/api/integrations", integrationsRouter);
app.use("/api/oauth", oauthRouter);

// User settings
app.use("/api/settings", settingsRouter);

// MCP endpoint (for containers)
app.use("/api/mcp", mcpRouter);

// Channel management (proxy to agent server)
app.use("/api/channels", channelsRouter);

// Container wake
app.use("/api/container", containerRouter);

// Chat with SSE
app.use("/api/chat", chatRouter);

// ============================================================
// GROUPS API (Unified model - replaces organizations)
// ============================================================

// Groups CRUD and member management
app.use("/api/groups", groupsRouter);

// Group vault threshold unlock (2 of N admins)
app.use("/api/groups", groupVaultRouter);

// Group vault container management
app.use("/api/groups", groupVaultContainerRouter);

// User's groups and resources (must be before group-invites /:id route)
app.use("/api", userGroupsRouter);

// Group invites (consent-based membership)
app.use("/api/group-invites", groupInvitesRouter);
app.use("/api/invites", groupInvitesRouter);

// ============================================================
// SHARES API (Unified sharing - replaces org grants + peer grants)
// ============================================================

app.use("/api/shares", sharesRouter);

// Resource shares (peer-to-peer integration sharing)
app.use("/api", resourceSharesRouter);

// ============================================================
// OTHER API ROUTES
// ============================================================

// Audit log
app.use("/api/audit-log", auditRouter);

// Audit log export (SIEM integration, webhooks, batch export)
app.use("/api/audit", auditExportRouter);

// Capability approvals (human-in-the-loop)
app.use("/api/approvals", approvalsRouter);

// Notifications SSE stream
app.use("/api/notifications", notificationsRouter);

// Agent activity and anomaly detection
app.use("/api/agent", agentRouter);

// Relay status and revocation checks
app.use("/api/relay", relayRouter);

// Internal API (for agent server)
app.use("/api/internal", internalRouter);

// Security events and alerting
app.use("/api/security-events", securityEventsRouter);

// ============================================================
// BILLING API (Subscription management, Stripe integration)
// ============================================================

app.use("/api/billing", billingRouter);

// ============================================================
// ADMIN PAGES
// ============================================================

app.use("/admin", adminRouter);

// Admin security management (IP allowlist, emergency tokens, settings)
app.use("/api/admin/security", adminSecurityRouter);

// Platform admin dashboard (tenants, users, containers, stats)
app.use("/api/admin", platformAdminRouter);

// ============================================================
// TENANT BRANDING API (White-label customization)
// ============================================================

// Tenant branding management and public branding endpoint
app.use("/api", tenantBrandingRouter);

// ============================================================
// RBAC API (Role-Based Access Control)
// ============================================================

// RBAC routes (roles, permissions, custom roles for enterprise)
app.use("/api/rbac", rbacRouter);

// ============================================================
// TENANT BACKUP API (Per-tenant backup/restore)
// ============================================================

// Tenant backup, restore, export, import
app.use("/api", tenantBackupRouter);

// ============================================================
// SLA MONITORING API (SLA status, reports, credits)
// ============================================================

// SLA monitoring routes (status, reports, history, credits)
app.use("/api", slaRouter);

// Serve branding uploads (logos, favicons, backgrounds)
// Note: In production, these should be served from a CDN or object storage
const BRANDING_UPLOAD_DIR = process.env.BRANDING_UPLOAD_DIR || "./uploads/branding";
app.use(
  "/uploads/branding",
  express.static(BRANDING_UPLOAD_DIR, {
    maxAge: "7d", // Cache for 7 days
    immutable: true, // Files won't change once uploaded
  }),
);

// ============================================================
// ERROR HANDLING MIDDLEWARE (must be last)
// ============================================================

// 404 handler for undefined routes
app.use((req, res, next) => {
  res.status(404).json({
    error: {
      code: "NOT_FOUND",
      message: `Route not found: ${req.method} ${req.path}`,
    },
  });
});

// Global error handler
// Handles AppError instances and unexpected errors
// In production: hides stack traces and internal details
// In development: includes full error information
app.use((err, req, res, next) => {
  // Log the error (with stack in development)
  if (process.env.NODE_ENV !== "production") {
    console.error("Error:", err);
  } else {
    console.error("Error:", err.message);
  }

  // Handle AppError instances
  if (err instanceof AppError) {
    const response = serializeError(err);
    return res.status(err.statusCode).json(response);
  }

  // Handle body-parser errors (JSON parse errors, payload too large)
  if (err.type === "entity.parse.failed") {
    return res.status(400).json({
      error: {
        code: "INVALID_JSON",
        message: "Invalid JSON in request body",
      },
    });
  }

  if (err.type === "entity.too.large") {
    return res.status(413).json({
      error: {
        code: "PAYLOAD_TOO_LARGE",
        message: "Request body too large",
      },
    });
  }

  // Handle unexpected errors
  const statusCode = err.statusCode || err.status || 500;
  const response = serializeError(err);
  res.status(statusCode).json(response);
});

// ============================================================
// START SERVER
// ============================================================

const PORT = process.env.PORT || 3000;

// Create HTTP server from Express app for WebSocket support
const server = createServer(app);

// Setup WebSocket proxy (authenticates via httpOnly cookie, proxies to container)
// Gateway tokens are never exposed to the browser - they're injected server-side
setupWebSocketProxy(server);

// Use server.listen instead of app.listen for WebSocket support
server.listen(PORT, "0.0.0.0", () => {
  console.log(`OCMT Management Server running on http://0.0.0.0:${PORT}`);
});
