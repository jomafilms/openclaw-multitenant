/**
 * Tenant context utilities for multi-tenant SaaS
 *
 * Provides utilities for:
 * - Extracting tenant information from requests
 * - Managing tenant context on request objects
 * - Parsing subdomains for tenant identification
 * - Validating cross-tenant access
 * - Security logging for cross-tenant access attempts
 */

import { logSecurityEvent, SECURITY_EVENT_TYPES, getRequestContext } from "./security-events.js";

// ============================================================
// RESERVED SUBDOMAINS
// ============================================================

/**
 * List of reserved subdomains that cannot be used as tenant slugs
 * These are used for platform services, marketing, and system functions
 */
export const RESERVED_SUBDOMAINS = [
  // Platform services
  "www",
  "api",
  "app",
  "admin",
  "dashboard",
  "console",

  // Authentication and security
  "auth",
  "login",
  "sso",
  "oauth",

  // Infrastructure
  "cdn",
  "static",
  "assets",
  "images",
  "media",

  // Documentation and support
  "docs",
  "help",
  "support",
  "status",

  // Marketing and legal
  "blog",
  "news",
  "legal",
  "privacy",
  "terms",

  // Development and testing
  "dev",
  "staging",
  "test",
  "demo",
  "sandbox",

  // Email and communications
  "mail",
  "email",
  "smtp",

  // Mobile and native apps
  "mobile",
  "ios",
  "android",

  // Potential future services
  "ai",
  "agent",
  "agents",
  "bot",
  "bots",
  "workspace",
  "workspaces",
];

// ============================================================
// TENANT CONTEXT SOURCES
// ============================================================

/**
 * Sources from which tenant context can be extracted
 */
export const TENANT_SOURCE = {
  API_KEY: "api_key",
  SESSION: "session",
  SUBDOMAIN: "subdomain",
  QUERY: "query", // Admin use only
};

// ============================================================
// CONTEXT EXTRACTION
// ============================================================

/**
 * Extract tenant information from various request sources
 *
 * Priority order:
 * 1. API key header (x-api-key)
 * 2. Session/JWT (req.user.tenant_id)
 * 3. Subdomain (tenant-slug.YOUR_DOMAIN)
 * 4. Query parameter (?tenant=slug) - admin use only
 *
 * @param {object} req - Express request object
 * @param {object} options - Options for extraction
 * @param {function} options.validateApiKey - Function to validate API key and return tenant
 * @param {function} options.findTenantById - Function to find tenant by ID
 * @param {function} options.findTenantBySlug - Function to find tenant by slug
 * @param {boolean} options.allowQueryParam - Whether to allow query param (admin only)
 * @returns {Promise<{source: string, tenantId: string, tenant: object|null}|null>}
 */
export async function extractTenantFromRequest(req, options = {}) {
  const { validateApiKey, findTenantById, findTenantBySlug, allowQueryParam = false } = options;

  // Priority 1: API key header
  const apiKey = req.headers["x-api-key"];
  if (apiKey && validateApiKey) {
    try {
      const keyData = await validateApiKey(apiKey);
      if (keyData && keyData.tenant_id) {
        const tenant =
          keyData.tenant || (findTenantById ? await findTenantById(keyData.tenant_id) : null);
        return {
          source: TENANT_SOURCE.API_KEY,
          tenantId: keyData.tenant_id,
          tenant,
          apiKeyData: keyData,
        };
      }
    } catch (err) {
      console.warn("[tenant-context] API key validation failed:", err.message);
    }
  }

  // Priority 2: Session/JWT
  if (req.user?.tenant_id) {
    const tenant = findTenantById ? await findTenantById(req.user.tenant_id) : null;
    return {
      source: TENANT_SOURCE.SESSION,
      tenantId: req.user.tenant_id,
      tenant,
    };
  }

  // Priority 3: Subdomain
  const host = req.headers.host;
  if (host) {
    const subdomain = parseSubdomain(host);
    if (subdomain && !isReservedSubdomain(subdomain) && findTenantBySlug) {
      try {
        const tenant = await findTenantBySlug(subdomain);
        if (tenant) {
          return {
            source: TENANT_SOURCE.SUBDOMAIN,
            tenantId: tenant.id,
            tenant,
          };
        }
      } catch (err) {
        console.warn("[tenant-context] Subdomain lookup failed:", err.message);
      }
    }
  }

  // Priority 4: Query parameter (admin use only)
  if (allowQueryParam && req.query.tenant && findTenantBySlug) {
    // Only allow query param for system admins
    const isAdmin = req.user?.isSystemAdmin || req.user?.is_platform_admin;
    if (isAdmin) {
      try {
        const tenant = await findTenantBySlug(req.query.tenant);
        if (tenant) {
          return {
            source: TENANT_SOURCE.QUERY,
            tenantId: tenant.id,
            tenant,
          };
        }
      } catch (err) {
        console.warn("[tenant-context] Query param tenant lookup failed:", err.message);
      }
    }
  }

  return null;
}

// ============================================================
// CONTEXT HELPERS
// ============================================================

/**
 * Attach tenant to request object
 * @param {object} req - Express request object
 * @param {object} tenant - Tenant object to attach
 * @param {string} source - Source of tenant context
 */
export function setTenantContext(req, tenant, source = null) {
  if (!tenant) {
    throw new Error("Cannot set null tenant context");
  }

  req.tenant = tenant;
  req.tenantId = tenant.id;
  req.tenantSource = source;
}

/**
 * Get tenant from request object
 * @param {object} req - Express request object
 * @returns {object} Tenant object
 * @throws {Error} If tenant context is not set
 */
export function getTenantContext(req) {
  if (!req.tenant) {
    throw new Error("Tenant context not set. Use tenant detection middleware first.");
  }
  return req.tenant;
}

/**
 * Check if tenant context exists on request
 * @param {object} req - Express request object
 * @returns {boolean} True if tenant context is set
 */
export function hasTenantContext(req) {
  return req.tenant != null && req.tenantId != null;
}

/**
 * Remove tenant from request object
 * @param {object} req - Express request object
 */
export function clearTenantContext(req) {
  delete req.tenant;
  delete req.tenantId;
  delete req.tenantSource;
}

// ============================================================
// SUBDOMAIN PARSING
// ============================================================

/**
 * Extract subdomain from host header
 *
 * Examples:
 * - "acme.YOUR_DOMAIN" -> "acme"
 * - "www.YOUR_DOMAIN" -> "www"
 * - "YOUR_DOMAIN" -> null
 * - "localhost:3000" -> null
 * - "acme.dev.YOUR_DOMAIN" -> "acme" (extracts first subdomain)
 *
 * @param {string} host - Host header value
 * @returns {string|null} Subdomain or null if none
 */
export function parseSubdomain(host) {
  if (!host) {
    return null;
  }

  // Remove port if present
  const hostWithoutPort = host.split(":")[0];

  // Skip localhost and IP addresses
  if (hostWithoutPort === "localhost" || /^\d+\.\d+\.\d+\.\d+$/.test(hostWithoutPort)) {
    return null;
  }

  // Split by dots
  const parts = hostWithoutPort.split(".");

  // Need at least 3 parts for a subdomain (subdomain.domain.tld)
  // Or 4+ parts for subdomains with multi-part TLDs (subdomain.domain.co.uk)
  if (parts.length < 3) {
    return null;
  }

  // Return the first part as the subdomain
  // This handles cases like "acme.YOUR_DOMAIN" -> "acme"
  // and "acme.dev.YOUR_DOMAIN" -> "acme"
  return parts[0].toLowerCase();
}

/**
 * Check if a subdomain is reserved
 * @param {string} subdomain - Subdomain to check
 * @returns {boolean} True if subdomain is reserved
 */
export function isReservedSubdomain(subdomain) {
  if (!subdomain) {
    return false;
  }
  return RESERVED_SUBDOMAINS.includes(subdomain.toLowerCase());
}

// ============================================================
// TENANT VALIDATION
// ============================================================

/**
 * Validate that request's tenant matches a resource's tenant
 * @param {object} req - Express request object with tenant context
 * @param {string} resourceTenantId - Tenant ID of the resource being accessed
 * @returns {boolean} True if tenants match
 */
export function validateTenantAccess(req, resourceTenantId) {
  if (!hasTenantContext(req)) {
    return false;
  }

  if (!resourceTenantId) {
    // Resource has no tenant - could be shared/global
    return true;
  }

  return req.tenantId === resourceTenantId;
}

/**
 * Require that request's tenant matches a resource's tenant
 * Throws an error if tenants don't match
 *
 * @param {object} req - Express request object with tenant context
 * @param {string} resourceTenantId - Tenant ID of the resource being accessed
 * @param {string} resourceType - Type of resource for error message
 * @throws {Error} If tenants don't match
 */
export function requireSameTenant(req, resourceTenantId, resourceType = "resource") {
  if (!hasTenantContext(req)) {
    throw new Error("Tenant context required for access validation");
  }

  if (resourceTenantId && req.tenantId !== resourceTenantId) {
    throw new Error(`Access denied: ${resourceType} belongs to a different tenant`);
  }
}

// ============================================================
// CROSS-TENANT DETECTION (SECURITY)
// ============================================================

/**
 * Detect if a request is attempting cross-tenant access
 * @param {object} req - Express request object with tenant context
 * @param {string} targetTenantId - Tenant ID being accessed
 * @returns {boolean} True if this is a cross-tenant access attempt
 */
export function detectCrossTenantAccess(req, targetTenantId) {
  if (!hasTenantContext(req)) {
    return false;
  }

  if (!targetTenantId) {
    return false;
  }

  return req.tenantId !== targetTenantId;
}

/**
 * Log a potential cross-tenant access attempt
 * This is for security auditing and anomaly detection
 *
 * @param {object} req - Express request object
 * @param {string} targetTenantId - Tenant ID that was attempted to be accessed
 * @param {string} resource - Description of the resource being accessed
 * @param {object} additionalDetails - Any additional details to log
 */
export async function logCrossTenantAttempt(req, targetTenantId, resource, additionalDetails = {}) {
  const { ipAddress, userAgent } = getRequestContext(req);

  const details = {
    sourceTenantId: req.tenantId || null,
    targetTenantId,
    resource,
    method: req.method,
    path: req.path,
    tenantSource: req.tenantSource,
    ...additionalDetails,
  };

  // Log as a security event
  // Note: Using ANOMALY_DETECTED for cross-tenant attempts
  // A dedicated event type could be added to SECURITY_EVENT_TYPES
  await logSecurityEvent(
    SECURITY_EVENT_TYPES.ANOMALY_DETECTED,
    req.user?.id,
    {
      ...details,
      description: `Cross-tenant access attempt to ${resource}`,
    },
    null,
    {
      ipAddress,
      userAgent,
      groupId: additionalDetails.groupId,
    },
  );

  console.warn(
    `[tenant-context] Cross-tenant access attempt: ` +
      `source=${req.tenantId || "none"} target=${targetTenantId} ` +
      `resource=${resource} user=${req.user?.id || "anon"} ip=${ipAddress}`,
  );
}

// ============================================================
// DEFAULT EXPORT
// ============================================================

export default {
  // Constants
  RESERVED_SUBDOMAINS,
  TENANT_SOURCE,

  // Context extraction
  extractTenantFromRequest,

  // Context helpers
  setTenantContext,
  getTenantContext,
  hasTenantContext,
  clearTenantContext,

  // Subdomain parsing
  parseSubdomain,
  isReservedSubdomain,

  // Tenant validation
  validateTenantAccess,
  requireSameTenant,

  // Cross-tenant detection
  detectCrossTenantAccess,
  logCrossTenantAttempt,
};
