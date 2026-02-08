/**
 * SAML SSO authentication routes
 * Wave 5 Enterprise Features (Task 5.1)
 *
 * Provides SAML 2.0 SSO endpoints for enterprise tenants:
 * - Initiate SAML login flow
 * - Handle SAML assertion callback (ACS)
 * - Serve SP metadata
 * - Handle Single Logout (SLO)
 * - Admin routes for SAML configuration
 */

import axios from "axios";
import crypto from "crypto";
import { Router } from "express";
import {
  tenants,
  tenantMemberships,
  users,
  sessions,
  audit,
  meshAuditLogs,
  MESH_AUDIT_EVENTS,
} from "../db/index.js";
import { updateAgentContext, AGENT_SERVER_URL, AGENT_SERVER_TOKEN } from "../lib/context.js";
import { generatePermanentToken, encryptGatewayToken } from "../lib/gateway-tokens.js";
import { loginLimiter, strictAuthLimiter } from "../lib/rate-limit.js";
import {
  createSamlStrategy,
  generateSpMetadata,
  validateSamlAssertion,
  mapSamlAttributes,
  validateSamlConfig,
  testSamlConfig,
  isJitProvisioningEnabled,
  getJitRole,
  generateRelayState,
  parseRelayState,
} from "../lib/saml.js";
import { closeUserConnections } from "../lib/ws-proxy.js";
import { setSessionCookie, clearSessionCookie } from "../middleware/auth.js";
import { requireUser } from "../middleware/auth.js";
import { loadTenantFromParam, requireTenantOwner } from "../middleware/tenant-context.js";

const router = Router();

const USER_UI_URL = process.env.USER_UI_URL || "http://localhost:5173";
const BASE_URL = process.env.BASE_URL || "http://localhost:3000";
const SESSION_MAX_AGE = 7 * 24 * 60 * 60 * 1000; // 7 days
const AGENT_SERVER_HOST = process.env.AGENT_SERVER_HOST || "localhost";

// ============================================================
// HELPER FUNCTIONS
// ============================================================

/**
 * Get effective API key for container provisioning
 */
async function getEffectiveApiKey(provider) {
  if (provider === "anthropic" && process.env.ANTHROPIC_API_KEY) {
    return { key: process.env.ANTHROPIC_API_KEY, source: "business" };
  }
  if (provider === "openai" && process.env.OPENAI_API_KEY) {
    return { key: process.env.OPENAI_API_KEY, source: "business" };
  }
  return null;
}

/**
 * Provision container for new user
 */
async function provisionContainerForUser(user) {
  try {
    console.log(`[saml] Provisioning container for user ${user.id}...`);

    const anthropicKey = await getEffectiveApiKey("anthropic");
    const openaiKey = await getEffectiveApiKey("openai");

    const provisionBody = {
      userId: user.id,
      userName: user.name,
    };

    if (anthropicKey?.key) {
      provisionBody.anthropicApiKey = anthropicKey.key;
    } else if (process.env.ANTHROPIC_SETUP_TOKEN) {
      provisionBody.anthropicSetupToken = process.env.ANTHROPIC_SETUP_TOKEN;
    }

    if (openaiKey?.key) {
      provisionBody.openaiApiKey = openaiKey.key;
    }

    const containerRes = await axios.post(`${AGENT_SERVER_URL}/api/provision`, provisionBody, {
      headers: { "x-auth-token": AGENT_SERVER_TOKEN },
      timeout: 60000,
    });

    if (containerRes.data.containerId) {
      await users.updateContainer(user.id, {
        containerId: containerRes.data.containerId,
        containerPort: containerRes.data.port,
      });
      if (containerRes.data.gatewayToken) {
        await users.updateGatewayToken(user.id, containerRes.data.gatewayToken);
      }
      console.log(`[saml] Container provisioned: ${containerRes.data.containerId}`);

      updateAgentContext(user.id).catch((err) => {
        console.error("[saml] Failed to initialize agent context:", err.message);
      });

      return true;
    }
  } catch (containerErr) {
    console.error("[saml] Failed to provision container:", containerErr.message);
  }
  return false;
}

/**
 * Create session and set cookie for user
 */
async function createSessionForUser(user, req, res) {
  const sessionToken = crypto.randomBytes(32).toString("hex");
  const sessionExpiresAt = new Date(Date.now() + SESSION_MAX_AGE);

  await sessions.create(user.id, sessionToken, sessionExpiresAt, {
    ipAddress: req.ip,
    userAgent: req.headers["user-agent"],
  });

  setSessionCookie(res, sessionToken, sessionExpiresAt);

  return { sessionToken, sessionExpiresAt };
}

// ============================================================
// SAML LOGIN FLOW
// ============================================================

/**
 * GET /auth/saml/:tenantSlug
 *
 * Initiate SAML SSO login flow for a tenant
 *
 * Query params:
 * - redirect: URL to redirect after login (optional, must be same origin)
 */
router.get("/:tenantSlug", loginLimiter, async (req, res) => {
  const { tenantSlug } = req.params;

  try {
    // Find tenant by slug
    const tenant = await tenants.findBySlug(tenantSlug);

    if (!tenant) {
      console.warn(`[saml] Tenant not found: ${tenantSlug}`);
      return res.redirect(`${USER_UI_URL}/login?error=tenant_not_found`);
    }

    // Check if SAML is configured for this tenant
    if (!tenant.settings?.saml?.entryPoint) {
      console.warn(`[saml] SAML not configured for tenant: ${tenantSlug}`);
      return res.redirect(`${USER_UI_URL}/login?error=saml_not_configured`);
    }

    // Check tenant status
    if (tenant.status !== "active") {
      console.warn(`[saml] Tenant not active: ${tenantSlug} (status: ${tenant.status})`);
      return res.redirect(`${USER_UI_URL}/login?error=tenant_inactive`);
    }

    // Validate redirect URL if provided
    let redirectUrl = null;
    const { redirect } = req.query;
    if (redirect) {
      try {
        const url = new URL(redirect, USER_UI_URL);
        if (url.origin === new URL(USER_UI_URL).origin) {
          redirectUrl = redirect;
        }
      } catch (e) {
        // Invalid URL, ignore
      }
    }

    // Create SAML strategy for this tenant
    const saml = createSamlStrategy(tenant);

    // Generate RelayState with redirect URL and tenant info
    const { encoded: relayState } = generateRelayState({
      tenantId: tenant.id,
      tenantSlug: tenant.slug,
      redirectUrl,
      ip: req.ip,
    });

    // Get SAML authorization URL
    const authUrl = await saml.getAuthorizeUrlAsync(relayState, null, {});

    console.log(`[saml] Initiating SAML login for tenant: ${tenantSlug}`);

    res.redirect(authUrl);
  } catch (err) {
    console.error(`[saml] Error initiating SAML login for ${tenantSlug}:`, err);
    await meshAuditLogs.log({
      eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
      ipAddress: req.ip,
      success: false,
      errorMessage: `SAML login initiation failed: ${err.message}`,
      details: { method: "saml", tenantSlug },
    });
    res.redirect(`${USER_UI_URL}/login?error=saml_init_failed`);
  }
});

/**
 * POST /auth/saml/:tenantSlug/callback
 *
 * Handle SAML assertion callback (ACS - Assertion Consumer Service)
 * This is where the IdP posts the SAML response after authentication
 */
router.post("/:tenantSlug/callback", strictAuthLimiter, async (req, res) => {
  const { tenantSlug } = req.params;
  const { SAMLResponse, RelayState } = req.body;

  try {
    // Find tenant
    const tenant = await tenants.findBySlug(tenantSlug);

    if (!tenant) {
      console.error(`[saml] Callback for unknown tenant: ${tenantSlug}`);
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
        ipAddress: req.ip,
        success: false,
        errorMessage: "SAML callback for unknown tenant",
        details: { method: "saml", tenantSlug },
      });
      return res.redirect(`${USER_UI_URL}/login?error=tenant_not_found`);
    }

    if (!SAMLResponse) {
      console.error(`[saml] No SAMLResponse in callback for ${tenantSlug}`);
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
        ipAddress: req.ip,
        success: false,
        errorMessage: "No SAMLResponse in callback",
        details: { method: "saml", tenantSlug },
      });
      return res.redirect(`${USER_UI_URL}/login?error=missing_saml_response`);
    }

    // Parse and validate RelayState
    let relayStateData = {};
    if (RelayState) {
      const parsed = parseRelayState(RelayState);
      if (parsed.valid) {
        relayStateData = parsed.data;
      } else {
        console.warn(`[saml] Invalid RelayState: ${parsed.error}`);
      }
    }

    // Create SAML strategy for this tenant
    const saml = createSamlStrategy(tenant);

    // Validate SAML assertion
    let samlProfile;
    try {
      samlProfile = await validateSamlAssertion(saml, SAMLResponse);
    } catch (validationErr) {
      console.error(`[saml] Assertion validation failed for ${tenantSlug}:`, validationErr.message);
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
        ipAddress: req.ip,
        success: false,
        errorMessage: `SAML assertion validation failed: ${validationErr.message}`,
        details: { method: "saml", tenantSlug },
      });
      return res.redirect(`${USER_UI_URL}/login?error=saml_validation_failed`);
    }

    // Map SAML attributes to user fields
    const userAttrs = mapSamlAttributes(samlProfile, tenant);

    if (!userAttrs.email) {
      console.error(`[saml] No email in SAML assertion for ${tenantSlug}`);
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
        ipAddress: req.ip,
        success: false,
        errorMessage: "No email in SAML assertion",
        details: { method: "saml", tenantSlug, samlProfile },
      });
      return res.redirect(`${USER_UI_URL}/login?error=no_email`);
    }

    console.log(`[saml] SAML login for ${tenantSlug}: ${userAttrs.email}`);

    // Find existing user by email
    let user = await users.findByEmail(userAttrs.email);
    let isNewUser = false;

    if (!user) {
      // Check if JIT provisioning is enabled
      if (!isJitProvisioningEnabled(tenant)) {
        console.warn(`[saml] JIT disabled, user not found: ${userAttrs.email} in ${tenantSlug}`);
        await meshAuditLogs.log({
          eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
          ipAddress: req.ip,
          success: false,
          errorMessage: "User not found and JIT provisioning is disabled",
          details: { method: "saml", tenantSlug, email: userAttrs.email },
        });
        return res.redirect(`${USER_UI_URL}/login?error=user_not_found`);
      }

      // Create new user via JIT provisioning
      isNewUser = true;
      const rawToken = generatePermanentToken();
      const encryptedToken = encryptGatewayToken(rawToken);

      user = await users.create({
        name: userAttrs.name || userAttrs.email.split("@")[0],
        email: userAttrs.email,
        gatewayToken: encryptedToken,
      });

      // Store SAML-related info in user settings
      await users.updateSettings(user.id, {
        saml_provider: tenantSlug,
        saml_external_id: userAttrs.externalId,
        saml_groups: userAttrs.groups,
        oauth_provider: "saml",
      });

      // Add user to tenant
      await tenantMemberships.addMember(tenant.id, user.id);

      // Get role based on SAML groups
      const role = getJitRole(tenant, userAttrs.groups);

      await audit.log(
        user.id,
        "user.created",
        {
          email: userAttrs.email,
          method: "saml_jit",
          tenantSlug,
          role,
          groups: userAttrs.groups,
        },
        req.ip,
      );

      console.log(`[saml] JIT provisioned user: ${userAttrs.email} for tenant ${tenantSlug}`);
    } else {
      // Existing user - verify they belong to this tenant
      const isMember = await tenantMemberships.isMember(tenant.id, user.id);

      if (!isMember) {
        // Add user to tenant if they're not already a member
        // This handles cases where user exists but hasn't been linked to tenant
        const settings = tenant.settings?.saml || {};
        if (settings.allowAutoJoin !== false) {
          await tenantMemberships.addMember(tenant.id, user.id);
          console.log(
            `[saml] Auto-joined existing user ${userAttrs.email} to tenant ${tenantSlug}`,
          );
        } else {
          console.warn(
            `[saml] User ${userAttrs.email} not member of ${tenantSlug}, auto-join disabled`,
          );
          await meshAuditLogs.log({
            eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
            ipAddress: req.ip,
            success: false,
            errorMessage: "User not member of tenant and auto-join is disabled",
            details: { method: "saml", tenantSlug, email: userAttrs.email },
          });
          return res.redirect(`${USER_UI_URL}/login?error=not_tenant_member`);
        }
      }

      // Update SAML info in user settings
      const currentSettings = await users.getSettings(user.id);
      await users.updateSettings(user.id, {
        saml_provider: currentSettings.saml_provider || tenantSlug,
        saml_external_id: userAttrs.externalId || currentSettings.saml_external_id,
        saml_groups: userAttrs.groups,
        saml_last_login: new Date().toISOString(),
      });
    }

    // Provision container if needed
    if (!user.container_id) {
      await provisionContainerForUser(user);
      user = await users.findById(user.id);
    } else {
      updateAgentContext(user.id).catch((err) => {
        console.error("[saml] Failed to refresh agent context:", err.message);
      });
    }

    // Create session
    await createSessionForUser(user, req, res);
    await audit.log(user.id, "user.login", { method: "saml", tenantSlug }, req.ip);

    // Log successful auth
    await meshAuditLogs.log({
      eventType: MESH_AUDIT_EVENTS.AUTH_LOGIN,
      actorId: user.id,
      ipAddress: req.ip,
      success: true,
      details: {
        method: "saml",
        tenantSlug,
        isNewUser,
        samlEmail: userAttrs.email,
      },
    });

    // Redirect to custom URL, onboarding (for new users), or dashboard
    let redirectTo = relayStateData.redirectUrl || "/dashboard";
    if (isNewUser && tenant.settings?.saml?.onboardingUrl) {
      redirectTo = tenant.settings.saml.onboardingUrl;
    }

    res.redirect(`${USER_UI_URL}${redirectTo.startsWith("/") ? redirectTo : "/" + redirectTo}`);
  } catch (err) {
    console.error(`[saml] Callback error for ${tenantSlug}:`, err);
    await meshAuditLogs.log({
      eventType: MESH_AUDIT_EVENTS.AUTH_FAILED,
      ipAddress: req.ip,
      success: false,
      errorMessage: err.message,
      details: { method: "saml", tenantSlug },
    });
    res.redirect(`${USER_UI_URL}/login?error=saml_callback_failed`);
  }
});

// ============================================================
// SP METADATA
// ============================================================

/**
 * GET /auth/saml/:tenantSlug/metadata
 *
 * Return SP (Service Provider) metadata XML for the tenant
 * This is used by IdP administrators to configure the SAML integration
 */
router.get("/:tenantSlug/metadata", async (req, res) => {
  const { tenantSlug } = req.params;

  try {
    const tenant = await tenants.findBySlug(tenantSlug);

    if (!tenant) {
      return res.status(404).json({
        error: "Tenant not found",
        code: "TENANT_NOT_FOUND",
      });
    }

    const metadata = generateSpMetadata(tenant);

    res.set("Content-Type", "application/xml");
    res.send(metadata);
  } catch (err) {
    console.error(`[saml] Metadata generation error for ${tenantSlug}:`, err);
    res.status(500).json({
      error: "Failed to generate metadata",
      code: "METADATA_ERROR",
    });
  }
});

// ============================================================
// SINGLE LOGOUT (SLO)
// ============================================================

/**
 * POST /auth/saml/:tenantSlug/logout
 *
 * Handle SAML Single Logout request from IdP
 */
router.post("/:tenantSlug/logout", async (req, res) => {
  const { tenantSlug } = req.params;
  const { SAMLRequest, SAMLResponse, RelayState } = req.body;

  try {
    const tenant = await tenants.findBySlug(tenantSlug);

    if (!tenant) {
      return res.status(404).json({
        error: "Tenant not found",
        code: "TENANT_NOT_FOUND",
      });
    }

    // Check if SLO is configured
    if (!tenant.settings?.saml?.logoutUrl) {
      return res.status(400).json({
        error: "Single Logout not configured",
        code: "SLO_NOT_CONFIGURED",
      });
    }

    const saml = createSamlStrategy(tenant);

    // Handle logout request from IdP
    if (SAMLRequest) {
      try {
        // Validate and process logout request
        const result = await saml.validateLogoutRequestAsync({
          SAMLRequest,
          RelayState,
        });

        if (result && result.profile) {
          // Find user by NameID
          const email = result.profile.nameID;
          if (email) {
            const user = await users.findByEmail(email);
            if (user) {
              // Close WebSocket connections
              closeUserConnections(user.id);

              // Delete all sessions for user
              await sessions.deleteAllForUser(user.id);

              await audit.log(user.id, "user.slo_logout", { tenantSlug }, req.ip);

              console.log(`[saml] SLO completed for user: ${email}`);
            }
          }
        }

        // Generate logout response
        const logoutResponseUrl = await saml.getLogoutResponseUrlAsync(result, RelayState, {});
        return res.redirect(logoutResponseUrl);
      } catch (err) {
        console.error(`[saml] SLO request validation failed:`, err);
        return res.status(400).json({
          error: "Invalid logout request",
          code: "INVALID_SLO_REQUEST",
        });
      }
    }

    // Handle logout response from IdP (after SP-initiated logout)
    if (SAMLResponse) {
      try {
        await saml.validateLogoutResponseAsync({
          SAMLResponse,
          RelayState,
        });

        console.log(`[saml] SLO response validated for tenant: ${tenantSlug}`);

        // Redirect to login page
        return res.redirect(`${USER_UI_URL}/login?logout=success`);
      } catch (err) {
        console.error(`[saml] SLO response validation failed:`, err);
        return res.redirect(`${USER_UI_URL}/login?logout=failed`);
      }
    }

    return res.status(400).json({
      error: "Missing SAML logout data",
      code: "MISSING_SLO_DATA",
    });
  } catch (err) {
    console.error(`[saml] SLO error for ${tenantSlug}:`, err);
    res.status(500).json({
      error: "Single logout failed",
      code: "SLO_ERROR",
    });
  }
});

/**
 * GET /auth/saml/:tenantSlug/logout
 *
 * Initiate SP-initiated Single Logout
 */
router.get("/:tenantSlug/logout", requireUser, async (req, res) => {
  const { tenantSlug } = req.params;

  try {
    const tenant = await tenants.findBySlug(tenantSlug);

    if (!tenant) {
      return res.status(404).json({
        error: "Tenant not found",
        code: "TENANT_NOT_FOUND",
      });
    }

    // Check if SLO is configured
    if (!tenant.settings?.saml?.logoutUrl) {
      // No SLO configured, just do local logout
      closeUserConnections(req.user.id);
      clearSessionCookie(res);
      await sessions.deleteByToken(req.sessionToken);
      return res.redirect(`${USER_UI_URL}/login`);
    }

    const saml = createSamlStrategy(tenant);

    // Generate logout request URL
    const { encoded: relayState } = generateRelayState({
      tenantId: tenant.id,
      userId: req.user.id,
    });

    const logoutUrl = await saml.getLogoutUrlAsync(
      {
        nameID: req.user.email,
        nameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        sessionIndex: null,
      },
      relayState,
      {},
    );

    // Clear local session
    closeUserConnections(req.user.id);
    clearSessionCookie(res);
    await sessions.deleteByToken(req.sessionToken);

    await audit.log(req.user.id, "user.logout", { method: "saml_slo", tenantSlug }, req.ip);

    // Redirect to IdP for logout
    res.redirect(logoutUrl);
  } catch (err) {
    console.error(`[saml] SP-initiated SLO error for ${tenantSlug}:`, err);
    // Fall back to local logout
    clearSessionCookie(res);
    res.redirect(`${USER_UI_URL}/login`);
  }
});

// ============================================================
// ADMIN ROUTES - SAML CONFIGURATION
// ============================================================

/**
 * PUT /api/tenants/:tenantId/saml
 *
 * Configure SAML for a tenant (tenant owner only)
 */
router.put("/config/:tenantId", requireUser, requireTenantOwner, async (req, res) => {
  const tenant = req.tenant;
  const { saml } = req.body;

  if (!saml) {
    return res.status(400).json({
      error: "SAML configuration required",
      code: "SAML_CONFIG_REQUIRED",
    });
  }

  // Validate SAML configuration
  const validation = validateSamlConfig(saml);
  if (!validation.valid) {
    return res.status(400).json({
      error: "Invalid SAML configuration",
      code: "INVALID_SAML_CONFIG",
      details: validation.errors,
    });
  }

  try {
    // Merge with existing settings
    const currentSettings = tenant.settings || {};
    const updatedSettings = {
      ...currentSettings,
      saml: {
        ...saml,
        configuredAt: new Date().toISOString(),
        configuredBy: req.user.id,
      },
    };

    await tenants.updateSettings(tenant.id, { saml: updatedSettings.saml });

    await audit.log(
      req.user.id,
      "tenant.saml_configured",
      {
        tenantId: tenant.id,
        tenantSlug: tenant.slug,
        entryPoint: saml.entryPoint,
      },
      req.ip,
    );

    console.log(`[saml] SAML configured for tenant: ${tenant.slug}`);

    res.json({
      success: true,
      message: "SAML configuration saved",
      metadata_url: `${BASE_URL}/api/auth/saml/${tenant.slug}/metadata`,
      login_url: `${BASE_URL}/api/auth/saml/${tenant.slug}`,
      acs_url: `${BASE_URL}/api/auth/saml/${tenant.slug}/callback`,
    });
  } catch (err) {
    console.error(`[saml] Failed to save SAML config for ${tenant.slug}:`, err);
    res.status(500).json({
      error: "Failed to save SAML configuration",
      code: "SAML_SAVE_ERROR",
    });
  }
});

/**
 * DELETE /api/tenants/:tenantId/saml
 *
 * Remove SAML configuration from a tenant (tenant owner only)
 */
router.delete("/config/:tenantId", requireUser, requireTenantOwner, async (req, res) => {
  const tenant = req.tenant;

  try {
    // Remove SAML settings
    const currentSettings = tenant.settings || {};
    delete currentSettings.saml;

    await tenants.update(tenant.id, { settings: currentSettings });

    await audit.log(
      req.user.id,
      "tenant.saml_removed",
      {
        tenantId: tenant.id,
        tenantSlug: tenant.slug,
      },
      req.ip,
    );

    console.log(`[saml] SAML configuration removed for tenant: ${tenant.slug}`);

    res.json({
      success: true,
      message: "SAML configuration removed",
    });
  } catch (err) {
    console.error(`[saml] Failed to remove SAML config for ${tenant.slug}:`, err);
    res.status(500).json({
      error: "Failed to remove SAML configuration",
      code: "SAML_REMOVE_ERROR",
    });
  }
});

/**
 * POST /api/tenants/:tenantId/saml/test
 *
 * Test SAML configuration without saving
 */
router.post("/config/:tenantId/test", requireUser, requireTenantOwner, async (req, res) => {
  const tenant = req.tenant;
  const { saml } = req.body;

  if (!saml) {
    return res.status(400).json({
      error: "SAML configuration required",
      code: "SAML_CONFIG_REQUIRED",
    });
  }

  // Create a temporary tenant object with the test configuration
  const testTenant = {
    ...tenant,
    settings: {
      ...tenant.settings,
      saml,
    },
  };

  try {
    const result = await testSamlConfig(testTenant);

    if (result.success) {
      res.json({
        success: true,
        message: "SAML configuration is valid",
        issuer: result.issuer,
        acs_url: result.acsUrl,
        metadata: result.metadata,
      });
    } else {
      res.status(400).json({
        success: false,
        error: result.error,
        code: "SAML_TEST_FAILED",
      });
    }
  } catch (err) {
    console.error(`[saml] SAML test failed for ${tenant.slug}:`, err);
    res.status(500).json({
      success: false,
      error: err.message,
      code: "SAML_TEST_ERROR",
    });
  }
});

/**
 * GET /api/tenants/:tenantId/saml
 *
 * Get current SAML configuration for a tenant (without certificate)
 */
router.get("/config/:tenantId", requireUser, loadTenantFromParam, async (req, res) => {
  const tenant = req.tenant;
  const samlConfig = tenant.settings?.saml;

  if (!samlConfig) {
    return res.json({
      configured: false,
      message: "SAML is not configured for this tenant",
    });
  }

  // Return config without sensitive fields
  res.json({
    configured: true,
    entryPoint: samlConfig.entryPoint,
    issuer: samlConfig.issuer || `ocmt-${tenant.slug}`,
    logoutUrl: samlConfig.logoutUrl,
    jitProvisioning: samlConfig.jitProvisioning !== false,
    attributeMapping: samlConfig.attributeMapping,
    roleMapping: samlConfig.roleMapping,
    configuredAt: samlConfig.configuredAt,
    metadata_url: `${BASE_URL}/api/auth/saml/${tenant.slug}/metadata`,
    login_url: `${BASE_URL}/api/auth/saml/${tenant.slug}`,
    acs_url: `${BASE_URL}/api/auth/saml/${tenant.slug}/callback`,
    // Don't return the certificate for security
    hasCertificate: Boolean(samlConfig.cert || samlConfig.certificate),
  });
});

// ============================================================
// PROVIDER STATUS
// ============================================================

/**
 * GET /auth/saml/providers
 *
 * List tenants that have SAML configured (for login page)
 * Only returns public information (slug, name)
 */
router.get("/providers", async (req, res) => {
  try {
    // Get tenants with SAML configured
    const allTenants = await tenants.list({ status: "active" });

    const samlTenants = allTenants
      .filter((t) => t.settings?.saml?.entryPoint)
      .map((t) => ({
        slug: t.slug,
        name: t.name,
        loginUrl: `${BASE_URL}/api/auth/saml/${t.slug}`,
      }));

    res.json({ providers: samlTenants });
  } catch (err) {
    console.error("[saml] Failed to list SAML providers:", err);
    res.status(500).json({
      error: "Failed to list providers",
      code: "PROVIDERS_ERROR",
    });
  }
});

export default router;
