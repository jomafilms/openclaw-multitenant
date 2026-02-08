/**
 * Data residency controls for multi-tenant SaaS
 * Wave 5.3 - Enterprise feature for compliance
 *
 * Provides:
 * - Region definitions (US, EU, APAC, custom)
 * - Tenant region settings management
 * - Data routing helpers for multi-region deployments
 * - Compliance helpers (GDPR, data transfer validation)
 * - Data location tracking for auditing
 * - Express middleware for enforcing residency policies
 *
 * Note: This module is designed to work with single-region deployments
 * while preparing for future multi-region expansion.
 */

import { tenants, audit, query } from "../db/index.js";
import { isAtLeastPlan } from "./quotas.js";
import { logSecurityEvent, SECURITY_EVENT_TYPES, getRequestContext } from "./security-events.js";

// ============================================================
// REGION DEFINITIONS
// ============================================================

/**
 * Supported data residency regions
 * Each region has metadata about location, compliance, and endpoints
 */
export const REGIONS = {
  // United States regions
  "us-east": {
    id: "us-east",
    name: "US East (N. Virginia)",
    country: "US",
    continent: "NA",
    complianceFrameworks: ["SOC2", "HIPAA"],
    isGDPR: false,
    defaultEndpoint: "https://api-us-east.YOUR_DOMAIN",
  },
  "us-west": {
    id: "us-west",
    name: "US West (Oregon)",
    country: "US",
    continent: "NA",
    complianceFrameworks: ["SOC2", "HIPAA"],
    isGDPR: false,
    defaultEndpoint: "https://api-us-west.YOUR_DOMAIN",
  },

  // European Union regions
  "eu-west": {
    id: "eu-west",
    name: "EU West (Ireland)",
    country: "IE",
    continent: "EU",
    complianceFrameworks: ["GDPR", "SOC2"],
    isGDPR: true,
    defaultEndpoint: "https://api-eu-west.YOUR_DOMAIN",
  },
  "eu-central": {
    id: "eu-central",
    name: "EU Central (Frankfurt)",
    country: "DE",
    continent: "EU",
    complianceFrameworks: ["GDPR", "SOC2", "BSI"],
    isGDPR: true,
    defaultEndpoint: "https://api-eu-central.YOUR_DOMAIN",
  },

  // Asia-Pacific regions
  "ap-southeast": {
    id: "ap-southeast",
    name: "Asia Pacific (Singapore)",
    country: "SG",
    continent: "AS",
    complianceFrameworks: ["SOC2", "PDPA"],
    isGDPR: false,
    defaultEndpoint: "https://api-ap-southeast.YOUR_DOMAIN",
  },
  "ap-northeast": {
    id: "ap-northeast",
    name: "Asia Pacific (Tokyo)",
    country: "JP",
    continent: "AS",
    complianceFrameworks: ["SOC2", "APPI"],
    isGDPR: false,
    defaultEndpoint: "https://api-ap-northeast.YOUR_DOMAIN",
  },
};

/**
 * Default region when not specified
 */
export const DEFAULT_REGION = "us-east";

/**
 * Current deployment region (from environment or default)
 * In a multi-region setup, this would be set per deployment
 */
export const CURRENT_REGION = process.env.OCMT_REGION || DEFAULT_REGION;

/**
 * Services that can have region-specific endpoints
 */
export const SERVICES = {
  api: "api",
  storage: "storage",
  database: "database",
  cache: "cache",
  agent: "agent",
  backup: "backup",
};

// ============================================================
// COMPLIANCE REQUIREMENTS
// ============================================================

/**
 * Compliance framework requirements
 */
export const COMPLIANCE_REQUIREMENTS = {
  GDPR: {
    id: "GDPR",
    name: "General Data Protection Regulation",
    regions: ["eu-west", "eu-central"],
    requirements: {
      dataProcessingAgreement: true,
      dataSubjectRights: true,
      privacyByDesign: true,
      breachNotification72h: true,
      dpoRequired: true,
      crossBorderTransferRestrictions: true,
    },
  },
  HIPAA: {
    id: "HIPAA",
    name: "Health Insurance Portability and Accountability Act",
    regions: ["us-east", "us-west"],
    requirements: {
      businessAssociateAgreement: true,
      phiProtection: true,
      auditControls: true,
      accessControls: true,
      encryptionRequired: true,
    },
  },
  SOC2: {
    id: "SOC2",
    name: "System and Organization Controls 2",
    regions: ["us-east", "us-west", "eu-west", "eu-central", "ap-southeast", "ap-northeast"],
    requirements: {
      securityPolicies: true,
      accessManagement: true,
      changeManagement: true,
      riskManagement: true,
      vendorManagement: true,
    },
  },
  PDPA: {
    id: "PDPA",
    name: "Personal Data Protection Act (Singapore)",
    regions: ["ap-southeast"],
    requirements: {
      consentRequired: true,
      purposeLimitation: true,
      dataProtectionOfficer: true,
      accessAndCorrection: true,
    },
  },
  APPI: {
    id: "APPI",
    name: "Act on Protection of Personal Information (Japan)",
    regions: ["ap-northeast"],
    requirements: {
      purposeSpecification: true,
      consentForThirdParty: true,
      securityMeasures: true,
      crossBorderTransferRestrictions: true,
    },
  },
};

/**
 * Data transfer rules between regions
 * Defines which region pairs can transfer data and under what conditions
 */
export const TRANSFER_RULES = {
  // EU to US requires specific legal framework (SCCs, DPF, etc.)
  "eu-west->us-east": {
    allowed: true,
    requiresSccs: true,
    requiresDataProcessingAgreement: true,
    notes: "Requires Standard Contractual Clauses or EU-US Data Privacy Framework",
  },
  "eu-west->us-west": {
    allowed: true,
    requiresSccs: true,
    requiresDataProcessingAgreement: true,
    notes: "Requires Standard Contractual Clauses or EU-US Data Privacy Framework",
  },
  "eu-central->us-east": {
    allowed: true,
    requiresSccs: true,
    requiresDataProcessingAgreement: true,
    notes: "Requires Standard Contractual Clauses or EU-US Data Privacy Framework",
  },
  "eu-central->us-west": {
    allowed: true,
    requiresSccs: true,
    requiresDataProcessingAgreement: true,
    notes: "Requires Standard Contractual Clauses or EU-US Data Privacy Framework",
  },
  // Intra-EU transfers are unrestricted
  "eu-west->eu-central": { allowed: true, notes: "Intra-EU transfer, no restrictions" },
  "eu-central->eu-west": { allowed: true, notes: "Intra-EU transfer, no restrictions" },
  // Intra-US transfers are unrestricted
  "us-east->us-west": { allowed: true, notes: "Intra-US transfer, no restrictions" },
  "us-west->us-east": { allowed: true, notes: "Intra-US transfer, no restrictions" },
  // APAC transfers
  "ap-southeast->ap-northeast": { allowed: true, notes: "Intra-APAC transfer" },
  "ap-northeast->ap-southeast": { allowed: true, notes: "Intra-APAC transfer" },
};

/**
 * Data types for transfer validation
 */
export const DATA_TYPES = {
  personalData: {
    id: "personalData",
    name: "Personal Data",
    gdprRelevant: true,
    hipaaRelevant: false,
  },
  sensitivePersonalData: {
    id: "sensitivePersonalData",
    name: "Sensitive Personal Data (Special Categories)",
    gdprRelevant: true,
    hipaaRelevant: false,
    requiresExplicitConsent: true,
  },
  healthData: {
    id: "healthData",
    name: "Protected Health Information (PHI)",
    gdprRelevant: true,
    hipaaRelevant: true,
    requiresEncryption: true,
  },
  financialData: {
    id: "financialData",
    name: "Financial/Payment Data",
    gdprRelevant: true,
    hipaaRelevant: false,
  },
  usageData: {
    id: "usageData",
    name: "Usage/Analytics Data",
    gdprRelevant: true,
    hipaaRelevant: false,
  },
  systemData: {
    id: "systemData",
    name: "System/Technical Data",
    gdprRelevant: false,
    hipaaRelevant: false,
  },
};

// ============================================================
// REGION VALIDATION
// ============================================================

/**
 * Check if a region ID is valid
 * @param {string} region - Region ID to validate
 * @returns {boolean} True if region is valid
 */
export function validateRegion(region) {
  return region != null && REGIONS[region] != null;
}

/**
 * Get region details
 * @param {string} region - Region ID
 * @returns {object|null} Region details or null if not found
 */
export function getRegion(region) {
  return REGIONS[region] || null;
}

/**
 * Get all available regions
 * @returns {object[]} Array of region objects
 */
export function getAllRegions() {
  return Object.values(REGIONS);
}

/**
 * Get regions that support a specific compliance framework
 * @param {string} framework - Compliance framework (e.g., 'GDPR', 'HIPAA')
 * @returns {object[]} Array of regions supporting the framework
 */
export function getRegionsByCompliance(framework) {
  return getAllRegions().filter((r) => r.complianceFrameworks.includes(framework));
}

// ============================================================
// TENANT REGION SETTINGS
// ============================================================

/**
 * Set data residency region for a tenant
 * Requires enterprise plan
 *
 * @param {string} tenantId - Tenant UUID
 * @param {string} region - Region ID to set
 * @param {object} options - Additional options
 * @param {string} options.changedBy - User ID making the change
 * @param {string} options.reason - Reason for the change
 * @returns {Promise<object>} Updated settings
 * @throws {Error} If region is invalid or tenant not on enterprise plan
 */
export async function setTenantRegion(tenantId, region, options = {}) {
  const { changedBy, reason } = options;

  // Validate region
  if (!validateRegion(region)) {
    throw new Error(`Invalid region: ${region}`);
  }

  // Get tenant to check plan
  const tenant = await tenants.findById(tenantId);
  if (!tenant) {
    throw new Error("Tenant not found");
  }

  // Check if tenant is on enterprise plan (data residency is enterprise-only)
  const subscription = await query("SELECT plan FROM subscriptions WHERE tenant_id = $1", [
    tenantId,
  ]);
  const plan = subscription.rows[0]?.plan || "free";

  if (!isAtLeastPlan(plan, "enterprise")) {
    throw new Error("Data residency controls require an enterprise plan");
  }

  // Get previous region for audit
  const previousRegion = tenant.settings?.data_region || DEFAULT_REGION;

  // Update tenant settings
  const newSettings = await tenants.updateSettings(tenantId, {
    data_region: region,
    data_region_updated_at: new Date().toISOString(),
    data_region_updated_by: changedBy,
  });

  // Log the change
  if (changedBy) {
    await audit.log(changedBy, "data_residency.region_changed", {
      tenantId,
      previousRegion,
      newRegion: region,
      reason,
    });
  }

  console.log(`[data-residency] Tenant ${tenantId} region changed: ${previousRegion} -> ${region}`);

  return newSettings;
}

/**
 * Get data residency region for a tenant
 * @param {string} tenantId - Tenant UUID
 * @returns {Promise<string>} Region ID (returns default if not set)
 */
export async function getTenantRegion(tenantId) {
  const tenant = await tenants.findById(tenantId);
  if (!tenant) {
    return DEFAULT_REGION;
  }

  return tenant.settings?.data_region || DEFAULT_REGION;
}

/**
 * Get full region configuration for a tenant
 * @param {string} tenantId - Tenant UUID
 * @returns {Promise<object>} Full region configuration
 */
export async function getTenantRegionConfig(tenantId) {
  const regionId = await getTenantRegion(tenantId);
  const region = getRegion(regionId);

  return {
    regionId,
    region,
    isDefault: regionId === DEFAULT_REGION,
    complianceFrameworks: region?.complianceFrameworks || [],
    isGDPR: region?.isGDPR || false,
  };
}

// ============================================================
// DATA ROUTING
// ============================================================

/**
 * Get regional endpoint for a service
 * In a multi-region setup, this returns the appropriate endpoint
 * For single-region, it returns the current/default endpoint
 *
 * @param {string} tenantId - Tenant UUID
 * @param {string} service - Service name (api, storage, database, etc.)
 * @returns {Promise<string>} Service endpoint URL
 */
export async function getRegionEndpoint(tenantId, service) {
  const regionId = await getTenantRegion(tenantId);
  const region = getRegion(regionId);

  if (!region) {
    console.warn(`[data-residency] Unknown region ${regionId}, using default`);
    return REGIONS[DEFAULT_REGION].defaultEndpoint;
  }

  // For now, return the default endpoint for the region
  // In a multi-region setup, this would be service-specific
  const serviceEndpoints = {
    api: region.defaultEndpoint,
    storage: region.defaultEndpoint.replace("api-", "storage-"),
    database: region.defaultEndpoint.replace("api-", "db-"),
    cache: region.defaultEndpoint.replace("api-", "cache-"),
    agent: region.defaultEndpoint.replace("api-", "agent-"),
    backup: region.defaultEndpoint.replace("api-", "backup-"),
  };

  return serviceEndpoints[service] || region.defaultEndpoint;
}

/**
 * Check if a request should be routed to a specific region
 * Compares the tenant's region with the target region
 *
 * @param {string} tenantId - Tenant UUID
 * @param {string} targetRegion - Region to check against
 * @returns {Promise<boolean>} True if request should go to the target region
 */
export async function shouldRouteToRegion(tenantId, targetRegion) {
  const tenantRegion = await getTenantRegion(tenantId);
  return tenantRegion === targetRegion;
}

/**
 * Check if the current deployment can serve a tenant
 * In multi-region, checks if current region matches tenant region
 *
 * @param {string} tenantId - Tenant UUID
 * @returns {Promise<{canServe: boolean, tenantRegion: string, currentRegion: string}>}
 */
export async function canServeInCurrentRegion(tenantId) {
  const tenantRegion = await getTenantRegion(tenantId);
  const canServe = tenantRegion === CURRENT_REGION;

  return {
    canServe,
    tenantRegion,
    currentRegion: CURRENT_REGION,
    redirectEndpoint: canServe ? null : REGIONS[tenantRegion]?.defaultEndpoint,
  };
}

// ============================================================
// COMPLIANCE HELPERS
// ============================================================

/**
 * Check if a region is GDPR-compliant
 * @param {string} region - Region ID
 * @returns {boolean} True if region is GDPR-compliant
 */
export function isGDPRRegion(region) {
  const regionData = getRegion(region);
  return regionData?.isGDPR === true;
}

/**
 * Get compliance requirements for a region
 * @param {string} region - Region ID
 * @returns {object} Compliance requirements object
 */
export function getComplianceRequirements(region) {
  const regionData = getRegion(region);
  if (!regionData) {
    return {
      region: null,
      frameworks: [],
      requirements: {},
    };
  }

  // Aggregate requirements from all applicable frameworks
  const requirements = {};
  const frameworkDetails = [];

  for (const frameworkId of regionData.complianceFrameworks) {
    const framework = COMPLIANCE_REQUIREMENTS[frameworkId];
    if (framework) {
      frameworkDetails.push({
        id: framework.id,
        name: framework.name,
        requirements: framework.requirements,
      });

      // Merge requirements
      Object.assign(requirements, framework.requirements);
    }
  }

  return {
    region: regionData,
    frameworks: frameworkDetails,
    requirements,
    isGDPR: regionData.isGDPR,
  };
}

/**
 * Validate if a data transfer is allowed between regions
 *
 * @param {string} fromRegion - Source region ID
 * @param {string} toRegion - Destination region ID
 * @param {string} dataType - Type of data being transferred (see DATA_TYPES)
 * @returns {object} Validation result with allowed, requirements, and notes
 */
export function validateDataTransfer(fromRegion, toRegion, dataType = "personalData") {
  // Same region transfers are always allowed
  if (fromRegion === toRegion) {
    return {
      allowed: true,
      sameRegion: true,
      requirements: [],
      notes: "Intra-region transfer, no restrictions",
    };
  }

  // Check if regions are valid
  if (!validateRegion(fromRegion) || !validateRegion(toRegion)) {
    return {
      allowed: false,
      error: "Invalid region specified",
      requirements: [],
      notes: null,
    };
  }

  // Look up transfer rule
  const ruleKey = `${fromRegion}->${toRegion}`;
  const rule = TRANSFER_RULES[ruleKey];

  // If no explicit rule, check if it's a same-continent transfer
  if (!rule) {
    const fromContinent = REGIONS[fromRegion].continent;
    const toContinent = REGIONS[toRegion].continent;

    if (fromContinent === toContinent) {
      return {
        allowed: true,
        requirements: [],
        notes: `Intra-${fromContinent} transfer, check local regulations`,
      };
    }

    // Cross-continent transfer without explicit rule
    const fromIsGDPR = isGDPRRegion(fromRegion);
    const dataTypeInfo = DATA_TYPES[dataType] || DATA_TYPES.personalData;

    if (fromIsGDPR && dataTypeInfo.gdprRelevant) {
      return {
        allowed: true, // Allowed but with requirements
        conditional: true,
        requirements: [
          "Standard Contractual Clauses (SCCs)",
          "Data Processing Agreement",
          "Supplementary measures assessment",
        ],
        notes: "Cross-border transfer from GDPR region requires legal basis",
      };
    }

    return {
      allowed: true,
      requirements: [],
      notes: "No specific restrictions found, verify local regulations",
    };
  }

  // Build requirements list from rule
  const requirements = [];
  if (rule.requiresSccs) {
    requirements.push("Standard Contractual Clauses (SCCs)");
  }
  if (rule.requiresDataProcessingAgreement) {
    requirements.push("Data Processing Agreement");
  }

  return {
    allowed: rule.allowed,
    requirements,
    notes: rule.notes,
  };
}

// ============================================================
// DATA LOCATION TRACKING
// ============================================================

/**
 * In-memory store for data locations (in production, use Redis or DB)
 */
const dataLocationCache = new Map();

/**
 * Record where data is stored for a tenant
 * Used for compliance reporting
 *
 * @param {string} tenantId - Tenant UUID
 * @param {string} dataType - Type of data (see DATA_TYPES)
 * @param {string} region - Region where data is stored
 * @param {object} details - Additional details
 */
export async function recordDataLocation(tenantId, dataType, region, details = {}) {
  const key = `${tenantId}:${dataType}`;
  const record = {
    tenantId,
    dataType,
    region,
    recordedAt: new Date().toISOString(),
    ...details,
  };

  // Store in cache
  let tenantLocations = dataLocationCache.get(tenantId);
  if (!tenantLocations) {
    tenantLocations = new Map();
    dataLocationCache.set(tenantId, tenantLocations);
  }
  tenantLocations.set(dataType, record);

  // Also persist to database for compliance
  try {
    await query(
      `INSERT INTO data_location_audit (tenant_id, data_type, region, details, recorded_at)
       VALUES ($1, $2, $3, $4, NOW())
       ON CONFLICT (tenant_id, data_type)
       DO UPDATE SET region = $3, details = $4, recorded_at = NOW()`,
      [tenantId, dataType, region, JSON.stringify(details)],
    );
  } catch (err) {
    // Table might not exist in all deployments, log and continue
    if (!err.message.includes("does not exist")) {
      console.error(`[data-residency] Failed to persist data location: ${err.message}`);
    }
  }
}

/**
 * Get all data locations for a tenant
 * @param {string} tenantId - Tenant UUID
 * @returns {Promise<object[]>} Array of data location records
 */
export async function getDataLocations(tenantId) {
  // Try database first
  try {
    const result = await query(`SELECT * FROM data_location_audit WHERE tenant_id = $1`, [
      tenantId,
    ]);
    if (result.rows.length > 0) {
      return result.rows;
    }
  } catch (err) {
    // Fall through to cache
  }

  // Fall back to cache
  const tenantLocations = dataLocationCache.get(tenantId);
  if (tenantLocations) {
    return Array.from(tenantLocations.values());
  }

  // Return default locations based on tenant region
  const tenantRegion = await getTenantRegion(tenantId);
  return Object.keys(DATA_TYPES).map((dataType) => ({
    tenantId,
    dataType,
    region: tenantRegion,
    recordedAt: null,
    isDefault: true,
  }));
}

/**
 * Log cross-region data access for compliance auditing
 *
 * @param {object} params - Access parameters
 * @param {string} params.tenantId - Tenant UUID
 * @param {string} params.userId - User UUID making the access
 * @param {string} params.dataRegion - Region where data resides
 * @param {string} params.accessRegion - Region from which access is made
 * @param {string} params.dataType - Type of data accessed
 * @param {string} params.operation - Operation performed (read, write, delete)
 * @param {string} params.ipAddress - IP address of accessor
 */
export async function logCrossRegionAccess(params) {
  const {
    tenantId,
    userId,
    dataRegion,
    accessRegion,
    dataType = "personalData",
    operation = "read",
    ipAddress,
  } = params;

  // Only log if regions differ
  if (dataRegion === accessRegion) {
    return;
  }

  const eventDetails = {
    tenantId,
    dataRegion,
    accessRegion,
    dataType,
    operation,
    timestamp: new Date().toISOString(),
  };

  // Log via security events
  await logSecurityEvent(
    SECURITY_EVENT_TYPES.ANOMALY_DETECTED,
    userId,
    {
      ...eventDetails,
      description: `Cross-region data access: ${dataType} from ${accessRegion} to ${dataRegion}`,
    },
    null,
    { ipAddress },
  );

  // Also log to audit
  if (userId) {
    await audit.log(userId, "data_residency.cross_region_access", eventDetails, ipAddress);
  }

  console.log(
    `[data-residency] Cross-region access: tenant=${tenantId} ` +
      `data_region=${dataRegion} access_region=${accessRegion} ` +
      `type=${dataType} op=${operation}`,
  );
}

// ============================================================
// EXPRESS MIDDLEWARE
// ============================================================

/**
 * Middleware to enforce data residency for requests
 * Checks if the current region can serve the tenant
 *
 * Options:
 * - strict: If true, rejects requests from wrong region (default: false)
 * - logViolations: If true, logs violations (default: true)
 *
 * @param {object} options - Middleware options
 * @returns {Function} Express middleware
 */
export function enforceDataResidency(options = {}) {
  const { strict = false, logViolations = true } = options;

  return async (req, res, next) => {
    // Skip if no tenant context
    const tenantId = req.tenant?.id || req.tenantId;
    if (!tenantId) {
      return next();
    }

    try {
      const { canServe, tenantRegion, currentRegion, redirectEndpoint } =
        await canServeInCurrentRegion(tenantId);

      // Attach region info to request
      req.dataResidency = {
        tenantRegion,
        currentRegion,
        canServe,
        isCompliant: canServe,
      };

      if (!canServe) {
        const { ipAddress, userAgent } = getRequestContext(req);

        // Log the violation
        if (logViolations) {
          await logCrossRegionAccess({
            tenantId,
            userId: req.user?.id,
            dataRegion: tenantRegion,
            accessRegion: currentRegion,
            operation: req.method.toLowerCase(),
            ipAddress,
          });
        }

        // In strict mode, reject the request
        if (strict) {
          return res.status(421).json({
            error: "Data residency violation",
            code: "DATA_RESIDENCY_MISMATCH",
            tenantRegion,
            currentRegion,
            redirectTo: redirectEndpoint,
            message: `This tenant's data resides in ${tenantRegion}. Please use the correct regional endpoint.`,
          });
        }

        // In non-strict mode, add warning header and continue
        res.set(
          "X-Data-Residency-Warning",
          `tenant-region=${tenantRegion};current-region=${currentRegion}`,
        );
      }

      next();
    } catch (err) {
      console.error(`[data-residency] Middleware error: ${err.message}`);
      // Don't block request on errors
      next();
    }
  };
}

/**
 * Middleware that requires enterprise plan for data residency features
 * Use before routes that modify region settings
 *
 * @returns {Function} Express middleware
 */
export function requireEnterpriseForResidency() {
  return async (req, res, next) => {
    const tenantId = req.tenant?.id || req.tenantId;
    if (!tenantId) {
      return res.status(400).json({
        error: "Tenant context required",
        code: "TENANT_REQUIRED",
      });
    }

    try {
      const subscription = await query("SELECT plan FROM subscriptions WHERE tenant_id = $1", [
        tenantId,
      ]);
      const plan = subscription.rows[0]?.plan || "free";

      if (!isAtLeastPlan(plan, "enterprise")) {
        return res.status(402).json({
          error: "Enterprise plan required",
          code: "ENTERPRISE_REQUIRED",
          feature: "data_residency",
          message: "Data residency controls are available on the Enterprise plan",
          upgrade_url: "/billing/upgrade",
        });
      }

      req.subscriptionPlan = plan;
      next();
    } catch (err) {
      console.error(`[data-residency] Plan check error: ${err.message}`);
      res.status(500).json({ error: "Failed to verify subscription" });
    }
  };
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

/**
 * Get summary of data residency status for a tenant
 * Useful for admin dashboards and compliance reports
 *
 * @param {string} tenantId - Tenant UUID
 * @returns {Promise<object>} Data residency summary
 */
export async function getDataResidencySummary(tenantId) {
  const [regionConfig, dataLocations] = await Promise.all([
    getTenantRegionConfig(tenantId),
    getDataLocations(tenantId),
  ]);

  const compliance = getComplianceRequirements(regionConfig.regionId);

  // Check for any data stored outside the tenant's region
  const outOfRegionData = dataLocations.filter((loc) => loc.region !== regionConfig.regionId);

  return {
    tenantId,
    region: regionConfig,
    compliance: {
      frameworks: compliance.frameworks.map((f) => f.id),
      isGDPR: compliance.isGDPR,
      requirements: Object.keys(compliance.requirements),
    },
    dataLocations: dataLocations.map((loc) => ({
      dataType: loc.dataType,
      region: loc.region,
      inRegion: loc.region === regionConfig.regionId,
    })),
    outOfRegionDataCount: outOfRegionData.length,
    isFullyCompliant: outOfRegionData.length === 0,
    generatedAt: new Date().toISOString(),
  };
}

/**
 * Create a custom region definition
 * For enterprise customers with specific requirements
 *
 * @param {object} regionDef - Region definition
 * @returns {object} Created region (added to REGIONS temporarily)
 */
export function createCustomRegion(regionDef) {
  const {
    id,
    name,
    country,
    continent,
    complianceFrameworks = [],
    isGDPR = false,
    endpoint,
  } = regionDef;

  if (!id || !name || !country) {
    throw new Error("Custom region requires id, name, and country");
  }

  if (REGIONS[id]) {
    throw new Error(`Region ${id} already exists`);
  }

  const customRegion = {
    id,
    name,
    country,
    continent: continent || "CUSTOM",
    complianceFrameworks,
    isGDPR,
    defaultEndpoint: endpoint || `https://api-${id}.YOUR_DOMAIN`,
    isCustom: true,
  };

  // Add to regions (runtime only, not persisted)
  REGIONS[id] = customRegion;

  console.log(`[data-residency] Custom region created: ${id}`);

  return customRegion;
}

// ============================================================
// EXPORTS
// ============================================================

export default {
  // Constants
  REGIONS,
  DEFAULT_REGION,
  CURRENT_REGION,
  SERVICES,
  COMPLIANCE_REQUIREMENTS,
  TRANSFER_RULES,
  DATA_TYPES,

  // Region validation
  validateRegion,
  getRegion,
  getAllRegions,
  getRegionsByCompliance,

  // Tenant region settings
  setTenantRegion,
  getTenantRegion,
  getTenantRegionConfig,

  // Data routing
  getRegionEndpoint,
  shouldRouteToRegion,
  canServeInCurrentRegion,

  // Compliance helpers
  isGDPRRegion,
  getComplianceRequirements,
  validateDataTransfer,

  // Data location tracking
  recordDataLocation,
  getDataLocations,
  logCrossRegionAccess,

  // Middleware
  enforceDataResidency,
  requireEnterpriseForResidency,

  // Utility functions
  getDataResidencySummary,
  createCustomRegion,
};
