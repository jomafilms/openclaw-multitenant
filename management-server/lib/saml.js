/**
 * SAML/SSO integration library
 * Wave 5 Enterprise Features (Task 5.1)
 *
 * Provides SAML 2.0 authentication for enterprise tenants:
 * - Per-tenant SAML strategy creation
 * - SP metadata generation
 * - SAML assertion validation
 * - Attribute mapping (SAML attributes to user fields)
 * - JIT (Just-In-Time) user provisioning
 * - Group membership from SAML assertions
 */

import { SAML } from "@node-saml/node-saml";
import crypto from "crypto";
import fs from "fs";
import path from "path";

// ============================================================
// CONFIGURATION
// ============================================================

const BASE_URL = process.env.BASE_URL || "http://localhost:3000";

// SP certificate and private key paths (for signing/encryption)
const SP_PRIVATE_KEY_PATH = process.env.SAML_PRIVATE_KEY_PATH;
const SP_CERTIFICATE_PATH = process.env.SAML_CERTIFICATE_PATH;

// Load SP credentials if available
let spPrivateKey = null;
let spCertificate = null;

if (SP_PRIVATE_KEY_PATH && fs.existsSync(SP_PRIVATE_KEY_PATH)) {
  try {
    spPrivateKey = fs.readFileSync(SP_PRIVATE_KEY_PATH, "utf8");
    console.log("[saml] Loaded SP private key");
  } catch (err) {
    console.warn("[saml] Failed to load SP private key:", err.message);
  }
}

if (SP_CERTIFICATE_PATH && fs.existsSync(SP_CERTIFICATE_PATH)) {
  try {
    spCertificate = fs.readFileSync(SP_CERTIFICATE_PATH, "utf8");
    console.log("[saml] Loaded SP certificate");
  } catch (err) {
    console.warn("[saml] Failed to load SP certificate:", err.message);
  }
}

// ============================================================
// SAML ATTRIBUTE MAPPINGS
// ============================================================

/**
 * Default attribute mappings from SAML assertions to user fields
 * Can be overridden per-tenant in tenant.settings.saml.attributeMapping
 */
export const DEFAULT_ATTRIBUTE_MAPPING = {
  // Email is usually the NameID, but can also be an attribute
  email: [
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "email",
    "mail",
    "Email",
    "http://schemas.microsoft.com/identity/claims/emailaddress",
  ],
  // Display name
  name: [
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
    "displayName",
    "name",
    "Name",
    "cn",
    "http://schemas.microsoft.com/identity/claims/displayname",
  ],
  // First name
  firstName: [
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
    "firstName",
    "givenName",
    "first_name",
    "FirstName",
  ],
  // Last name
  lastName: [
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
    "lastName",
    "surname",
    "sn",
    "last_name",
    "LastName",
  ],
  // Groups/roles
  groups: [
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
    "groups",
    "memberOf",
    "Group",
    "role",
    "roles",
  ],
  // External user ID from IdP
  externalId: [
    "http://schemas.microsoft.com/identity/claims/objectidentifier",
    "sub",
    "uid",
    "userId",
    "externalId",
  ],
};

// ============================================================
// SAML STRATEGY FACTORY
// ============================================================

/**
 * Create a SAML strategy for a specific tenant
 *
 * Uses tenant.settings.saml for configuration:
 * - entryPoint: IdP SSO URL (required)
 * - issuer: SP entity ID (defaults to `ocmt-${tenant.slug}`)
 * - cert: IdP public certificate for signature verification (required)
 * - callbackUrl: ACS URL (auto-generated)
 * - wantAuthnResponseSigned: Whether to require signed responses (default: true)
 * - signatureAlgorithm: Algorithm for signing (default: sha256)
 *
 * @param {object} tenant - Tenant object with settings.saml configuration
 * @returns {SAML} Configured SAML instance
 * @throws {Error} If SAML is not configured for the tenant
 */
export function createSamlStrategy(tenant) {
  const samlConfig = tenant.settings?.saml;

  if (!samlConfig) {
    throw new Error(`SAML not configured for tenant: ${tenant.slug}`);
  }

  if (!samlConfig.entryPoint) {
    throw new Error(`SAML entryPoint not configured for tenant: ${tenant.slug}`);
  }

  if (!samlConfig.cert && !samlConfig.certificate) {
    throw new Error(`SAML IdP certificate not configured for tenant: ${tenant.slug}`);
  }

  // Build SAML configuration
  const config = {
    // Required settings
    entryPoint: samlConfig.entryPoint,
    issuer: samlConfig.issuer || `ocmt-${tenant.slug}`,
    cert: samlConfig.cert || samlConfig.certificate,
    callbackUrl: `${BASE_URL}/api/auth/saml/${tenant.slug}/callback`,

    // Optional security settings
    wantAuthnResponseSigned: samlConfig.wantAuthnResponseSigned !== false,
    wantAssertionsSigned: samlConfig.wantAssertionsSigned !== false,
    signatureAlgorithm: samlConfig.signatureAlgorithm || "sha256",
    digestAlgorithm: samlConfig.digestAlgorithm || "sha256",

    // Request signing (optional, requires SP private key)
    authnRequestsSigned: Boolean(spPrivateKey && samlConfig.signAuthnRequests),

    // Logout settings
    logoutUrl: samlConfig.logoutUrl || null,
    logoutCallbackUrl: samlConfig.logoutUrl
      ? `${BASE_URL}/api/auth/saml/${tenant.slug}/logout`
      : null,

    // Identity settings
    identifierFormat:
      samlConfig.identifierFormat || "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",

    // Validation settings
    validateInResponseTo: samlConfig.validateInResponseTo || "never",
    disableRequestedAuthnContext: samlConfig.disableRequestedAuthnContext === true,

    // Audience restriction
    audience: samlConfig.audience || samlConfig.issuer || `ocmt-${tenant.slug}`,
  };

  // Add SP private key for signing if available
  if (spPrivateKey) {
    config.privateKey = spPrivateKey;
  }

  // Add SP certificate for metadata generation if available
  if (spCertificate) {
    config.decryptionPvk = spPrivateKey;
    config.cert = samlConfig.cert || samlConfig.certificate;
  }

  // Add any extra configuration from tenant settings
  if (samlConfig.additionalParams) {
    Object.assign(config, samlConfig.additionalParams);
  }

  return new SAML(config);
}

// ============================================================
// SP METADATA GENERATION
// ============================================================

/**
 * Generate SP (Service Provider) metadata XML for a tenant
 *
 * The metadata includes:
 * - Entity ID (issuer)
 * - ACS (Assertion Consumer Service) URL and binding
 * - SLO (Single Logout) URL if configured
 * - NameID format
 * - SP certificate for signature verification (if available)
 *
 * @param {object} tenant - Tenant object
 * @returns {string} SP metadata XML
 */
export function generateSpMetadata(tenant) {
  const samlConfig = tenant.settings?.saml || {};
  const entityId = samlConfig.issuer || `ocmt-${tenant.slug}`;
  const acsUrl = `${BASE_URL}/api/auth/saml/${tenant.slug}/callback`;
  const sloUrl = samlConfig.logoutUrl ? `${BASE_URL}/api/auth/saml/${tenant.slug}/logout` : null;

  // Build certificate element if available
  let certElement = "";
  if (spCertificate) {
    // Clean certificate (remove headers and newlines for XML embedding)
    const cleanCert = spCertificate
      .replace(/-----BEGIN CERTIFICATE-----/g, "")
      .replace(/-----END CERTIFICATE-----/g, "")
      .replace(/\s/g, "");

    certElement = `
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>${cleanCert}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>${cleanCert}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>`;
  }

  // Build SLO element if configured
  let sloElement = "";
  if (sloUrl) {
    sloElement = `
    <md:SingleLogoutService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="${escapeXml(sloUrl)}"
    />
    <md:SingleLogoutService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="${escapeXml(sloUrl)}"
    />`;
  }

  const metadata = `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
  xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
  entityID="${escapeXml(entityId)}">
  <md:SPSSODescriptor
    AuthnRequestsSigned="${Boolean(spPrivateKey && samlConfig.signAuthnRequests)}"
    WantAssertionsSigned="true"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    ${certElement}
    ${sloElement}
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="${escapeXml(acsUrl)}"
      index="0"
      isDefault="true"
    />
  </md:SPSSODescriptor>
  <md:Organization>
    <md:OrganizationName xml:lang="en">${escapeXml(tenant.name)}</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="en">${escapeXml(tenant.name)}</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="en">${escapeXml(BASE_URL)}</md:OrganizationURL>
  </md:Organization>
</md:EntityDescriptor>`;

  return metadata;
}

// ============================================================
// SAML ASSERTION VALIDATION
// ============================================================

/**
 * Validate a SAML assertion response
 *
 * @param {SAML} samlStrategy - SAML instance for the tenant
 * @param {string} samlResponse - Base64-encoded SAML response
 * @returns {Promise<object>} Validated profile with user attributes
 * @throws {Error} If validation fails
 */
export async function validateSamlAssertion(samlStrategy, samlResponse) {
  try {
    const result = await samlStrategy.validatePostResponseAsync({
      SAMLResponse: samlResponse,
    });

    if (!result || !result.profile) {
      throw new Error("SAML assertion validation failed: no profile returned");
    }

    return result.profile;
  } catch (err) {
    console.error("[saml] Assertion validation error:", err.message);
    throw new Error(`SAML assertion validation failed: ${err.message}`, { cause: err });
  }
}

// ============================================================
// ATTRIBUTE MAPPING
// ============================================================

/**
 * Extract user attributes from SAML profile using attribute mapping
 *
 * @param {object} samlProfile - Profile returned from SAML validation
 * @param {object} tenant - Tenant object (for custom attribute mapping)
 * @returns {object} Mapped user attributes { email, name, firstName, lastName, groups, externalId }
 */
export function mapSamlAttributes(samlProfile, tenant) {
  const customMapping = tenant.settings?.saml?.attributeMapping || {};
  const mapping = { ...DEFAULT_ATTRIBUTE_MAPPING, ...customMapping };

  const result = {
    email: null,
    name: null,
    firstName: null,
    lastName: null,
    groups: [],
    externalId: null,
    rawAttributes: {},
  };

  // Store raw attributes for debugging
  result.rawAttributes = { ...samlProfile };

  // Email from NameID (common for email-based SSO)
  if (samlProfile.nameID && samlProfile.nameID.includes("@")) {
    result.email = samlProfile.nameID.toLowerCase();
  }

  // Map each attribute type
  for (const [field, possibleNames] of Object.entries(mapping)) {
    const names = Array.isArray(possibleNames) ? possibleNames : [possibleNames];

    for (const attrName of names) {
      const value = samlProfile[attrName];

      if (value !== undefined && value !== null) {
        if (field === "groups") {
          // Groups can be a string or array
          result.groups = Array.isArray(value) ? value : [value];
        } else if (field === "email" && value) {
          result.email = String(value).toLowerCase();
        } else if (value) {
          result[field] = String(value);
        }
        break; // Found a value, stop checking other attribute names
      }
    }
  }

  // Build name from firstName + lastName if name not directly available
  if (!result.name && (result.firstName || result.lastName)) {
    result.name = [result.firstName, result.lastName].filter(Boolean).join(" ");
  }

  // Fallback name from email
  if (!result.name && result.email) {
    result.name = result.email.split("@")[0];
  }

  return result;
}

// ============================================================
// JIT USER PROVISIONING
// ============================================================

/**
 * Check if JIT provisioning is enabled for a tenant
 *
 * @param {object} tenant - Tenant object
 * @returns {boolean} True if JIT provisioning is enabled
 */
export function isJitProvisioningEnabled(tenant) {
  return tenant.settings?.saml?.jitProvisioning !== false;
}

/**
 * Get role to assign to JIT-provisioned users
 *
 * @param {object} tenant - Tenant object
 * @param {string[]} samlGroups - Groups from SAML assertion
 * @returns {string} Role to assign ('member' by default)
 */
export function getJitRole(tenant, samlGroups = []) {
  const roleMapping = tenant.settings?.saml?.roleMapping || {};

  // Check group-to-role mapping
  for (const [role, groups] of Object.entries(roleMapping)) {
    const groupList = Array.isArray(groups) ? groups : [groups];
    if (samlGroups.some((g) => groupList.includes(g))) {
      return role;
    }
  }

  // Default role for JIT users
  return tenant.settings?.saml?.defaultRole || "member";
}

// ============================================================
// SAML CONFIG VALIDATION
// ============================================================

/**
 * Validate SAML configuration before saving
 *
 * @param {object} samlConfig - SAML configuration object
 * @returns {{ valid: boolean, errors: string[] }} Validation result
 */
export function validateSamlConfig(samlConfig) {
  const errors = [];

  if (!samlConfig) {
    return { valid: false, errors: ["SAML configuration is required"] };
  }

  // Required fields
  if (!samlConfig.entryPoint) {
    errors.push("entryPoint (IdP SSO URL) is required");
  } else if (!isValidUrl(samlConfig.entryPoint)) {
    errors.push("entryPoint must be a valid HTTPS URL");
  }

  if (!samlConfig.cert && !samlConfig.certificate) {
    errors.push("IdP certificate is required");
  } else {
    const cert = samlConfig.cert || samlConfig.certificate;
    if (!isValidCertificate(cert)) {
      errors.push("Invalid IdP certificate format");
    }
  }

  // Optional URL validation
  if (samlConfig.logoutUrl && !isValidUrl(samlConfig.logoutUrl)) {
    errors.push("logoutUrl must be a valid HTTPS URL");
  }

  // Signature algorithm validation
  const validAlgorithms = ["sha1", "sha256", "sha512"];
  if (samlConfig.signatureAlgorithm && !validAlgorithms.includes(samlConfig.signatureAlgorithm)) {
    errors.push(`signatureAlgorithm must be one of: ${validAlgorithms.join(", ")}`);
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Test SAML configuration by attempting to create a SAML strategy
 *
 * @param {object} tenant - Tenant object with settings.saml
 * @returns {{ success: boolean, error?: string, metadata?: string }} Test result
 */
export async function testSamlConfig(tenant) {
  try {
    // Validate config first
    const validation = validateSamlConfig(tenant.settings?.saml);
    if (!validation.valid) {
      return {
        success: false,
        error: `Configuration errors: ${validation.errors.join(", ")}`,
      };
    }

    // Try to create the SAML strategy
    const saml = createSamlStrategy(tenant);

    // Generate metadata to verify configuration
    const metadata = generateSpMetadata(tenant);

    // Try to generate an auth URL (validates entryPoint parsing)
    const authUrl = await saml.getAuthorizeUrlAsync("", null, {});

    return {
      success: true,
      metadata,
      authUrl,
      issuer: tenant.settings.saml.issuer || `ocmt-${tenant.slug}`,
      acsUrl: `${BASE_URL}/api/auth/saml/${tenant.slug}/callback`,
    };
  } catch (err) {
    return {
      success: false,
      error: err.message,
    };
  }
}

// ============================================================
// HELPER FUNCTIONS
// ============================================================

/**
 * Escape special characters for XML
 */
function escapeXml(str) {
  if (!str) {
    return "";
  }
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/**
 * Validate URL format (must be HTTPS in production)
 */
function isValidUrl(url) {
  try {
    const parsed = new URL(url);
    // Allow http in development, require https in production
    if (process.env.NODE_ENV === "production") {
      return parsed.protocol === "https:";
    }
    return ["http:", "https:"].includes(parsed.protocol);
  } catch {
    return false;
  }
}

/**
 * Basic certificate format validation
 */
function isValidCertificate(cert) {
  if (!cert || typeof cert !== "string") {
    return false;
  }

  // Certificate can be with or without PEM headers
  const cleaned = cert.trim();

  // If it has PEM headers, validate format
  if (cleaned.startsWith("-----BEGIN")) {
    return (
      cleaned.includes("-----BEGIN CERTIFICATE-----") &&
      cleaned.includes("-----END CERTIFICATE-----")
    );
  }

  // Otherwise, should be base64-encoded certificate content
  // Should be reasonably long and contain only base64 chars
  const base64Content = cleaned.replace(/\s/g, "");
  return base64Content.length >= 100 && /^[A-Za-z0-9+/=]+$/.test(base64Content);
}

/**
 * Generate a random RelayState for SAML flow
 */
export function generateRelayState(data = {}) {
  const state = crypto.randomBytes(16).toString("hex");
  return {
    state,
    encoded: Buffer.from(
      JSON.stringify({
        state,
        ...data,
        createdAt: Date.now(),
      }),
    ).toString("base64"),
  };
}

/**
 * Parse and validate RelayState
 */
export function parseRelayState(relayState, maxAgeMs = 10 * 60 * 1000) {
  try {
    const decoded = JSON.parse(Buffer.from(relayState, "base64").toString("utf8"));

    // Check age
    if (decoded.createdAt && Date.now() - decoded.createdAt > maxAgeMs) {
      return { valid: false, error: "RelayState expired" };
    }

    return { valid: true, data: decoded };
  } catch (err) {
    return { valid: false, error: "Invalid RelayState format" };
  }
}

// ============================================================
// EXPORTS
// ============================================================

export default {
  // Strategy creation
  createSamlStrategy,

  // Metadata
  generateSpMetadata,

  // Validation
  validateSamlAssertion,
  validateSamlConfig,
  testSamlConfig,

  // Attribute mapping
  mapSamlAttributes,
  DEFAULT_ATTRIBUTE_MAPPING,

  // JIT provisioning
  isJitProvisioningEnabled,
  getJitRole,

  // Helpers
  generateRelayState,
  parseRelayState,
};
