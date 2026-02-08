/**
 * Data Residency Routes
 * Wave 5.3 - Enterprise feature for compliance
 *
 * Provides endpoints for:
 * - GET /api/tenants/:id/region - Get tenant region
 * - PUT /api/tenants/:id/region - Set tenant region (enterprise only)
 * - GET /api/regions - List available regions
 * - GET /api/tenants/:id/data-locations - Show where data is stored
 * - GET /api/tenants/:id/data-residency/summary - Full residency summary
 * - POST /api/tenants/:id/data-residency/validate-transfer - Validate data transfer
 *
 * All tenant-specific routes require authentication and tenant membership
 */

import { Router } from "express";
import { z } from "zod";
import { tenants, tenantMemberships, audit, subscriptions } from "../db/index.js";
import {
  REGIONS,
  DEFAULT_REGION,
  CURRENT_REGION,
  DATA_TYPES,
  COMPLIANCE_REQUIREMENTS,
  validateRegion,
  getRegion,
  getAllRegions,
  getRegionsByCompliance,
  setTenantRegion,
  getTenantRegion,
  getTenantRegionConfig,
  getComplianceRequirements,
  validateDataTransfer,
  getDataLocations,
  getDataResidencySummary,
  requireEnterpriseForResidency,
} from "../lib/data-residency.js";
import { isAtLeastPlan } from "../lib/quotas.js";
import { requireUser } from "../middleware/auth.js";

const router = Router();

// ============================================================
// VALIDATION SCHEMAS
// ============================================================

const uuidSchema = z.string().uuid();

const setRegionSchema = z.object({
  region: z.string().min(2).max(50),
  reason: z.string().max(500).optional(),
});

const validateTransferSchema = z.object({
  toRegion: z.string().min(2).max(50),
  dataType: z.string().optional().default("personalData"),
});

// ============================================================
// HELPER MIDDLEWARE
// ============================================================

/**
 * Verify user has access to the tenant
 */
async function verifyTenantAccess(req, res, next) {
  const tenantId = req.params.id;

  // Validate UUID
  const parseResult = uuidSchema.safeParse(tenantId);
  if (!parseResult.success) {
    return res.status(400).json({ error: "Invalid tenant ID" });
  }

  // Check tenant exists
  const tenant = await tenants.findById(tenantId);
  if (!tenant) {
    return res.status(404).json({ error: "Tenant not found" });
  }

  // Check user is member or owner
  const [isMember, isOwner] = await Promise.all([
    tenantMemberships.isMember(tenantId, req.user.id),
    tenantMemberships.isOwner(tenantId, req.user.id),
  ]);

  if (!isMember && !isOwner && !req.user.is_platform_admin) {
    return res.status(403).json({
      error: "Access denied",
      code: "TENANT_ACCESS_DENIED",
    });
  }

  req.targetTenant = tenant;
  req.isOwner = isOwner;
  next();
}

/**
 * Require tenant owner or platform admin for write operations
 */
function requireTenantOwner(req, res, next) {
  if (!req.isOwner && !req.user.is_platform_admin) {
    return res.status(403).json({
      error: "Tenant owner access required",
      code: "OWNER_REQUIRED",
    });
  }
  next();
}

// ============================================================
// PUBLIC ROUTES (No auth required)
// ============================================================

/**
 * GET /api/regions
 * List all available regions with metadata
 */
router.get("/", async (req, res) => {
  try {
    const regions = getAllRegions().map((region) => ({
      id: region.id,
      name: region.name,
      country: region.country,
      continent: region.continent,
      complianceFrameworks: region.complianceFrameworks,
      isGDPR: region.isGDPR,
      isCustom: region.isCustom || false,
    }));

    res.json({
      regions,
      defaultRegion: DEFAULT_REGION,
      currentDeploymentRegion: CURRENT_REGION,
      count: regions.length,
    });
  } catch (err) {
    console.error("[data-residency] List regions error:", err);
    res.status(500).json({ error: "Failed to list regions" });
  }
});

/**
 * GET /api/regions/:id
 * Get details for a specific region
 */
router.get("/:regionId", async (req, res) => {
  try {
    const { regionId } = req.params;
    const region = getRegion(regionId);

    if (!region) {
      return res.status(404).json({ error: "Region not found" });
    }

    const compliance = getComplianceRequirements(regionId);

    res.json({
      ...region,
      compliance: {
        frameworks: compliance.frameworks,
        requirements: compliance.requirements,
      },
    });
  } catch (err) {
    console.error("[data-residency] Get region error:", err);
    res.status(500).json({ error: "Failed to get region details" });
  }
});

/**
 * GET /api/regions/by-compliance/:framework
 * Get regions that support a specific compliance framework
 */
router.get("/by-compliance/:framework", async (req, res) => {
  try {
    const { framework } = req.params;

    if (!COMPLIANCE_REQUIREMENTS[framework]) {
      return res.status(404).json({
        error: "Unknown compliance framework",
        availableFrameworks: Object.keys(COMPLIANCE_REQUIREMENTS),
      });
    }

    const regions = getRegionsByCompliance(framework).map((r) => ({
      id: r.id,
      name: r.name,
      country: r.country,
    }));

    res.json({
      framework,
      frameworkName: COMPLIANCE_REQUIREMENTS[framework].name,
      regions,
      count: regions.length,
    });
  } catch (err) {
    console.error("[data-residency] Get regions by compliance error:", err);
    res.status(500).json({ error: "Failed to get regions" });
  }
});

/**
 * GET /api/regions/data-types
 * List available data types for transfer validation
 */
router.get("/meta/data-types", async (req, res) => {
  try {
    res.json({
      dataTypes: Object.values(DATA_TYPES),
    });
  } catch (err) {
    console.error("[data-residency] List data types error:", err);
    res.status(500).json({ error: "Failed to list data types" });
  }
});

/**
 * GET /api/regions/compliance-frameworks
 * List available compliance frameworks
 */
router.get("/meta/compliance-frameworks", async (req, res) => {
  try {
    const frameworks = Object.values(COMPLIANCE_REQUIREMENTS).map((f) => ({
      id: f.id,
      name: f.name,
      regions: f.regions,
      requirementCount: Object.keys(f.requirements).length,
    }));

    res.json({ frameworks });
  } catch (err) {
    console.error("[data-residency] List compliance frameworks error:", err);
    res.status(500).json({ error: "Failed to list frameworks" });
  }
});

// ============================================================
// TENANT-SPECIFIC ROUTES
// ============================================================

/**
 * GET /api/tenants/:id/region
 * Get the data residency region for a tenant
 */
router.get("/tenants/:id/region", requireUser, verifyTenantAccess, async (req, res) => {
  try {
    const tenantId = req.params.id;
    const regionConfig = await getTenantRegionConfig(tenantId);

    res.json({
      tenantId,
      ...regionConfig,
      deploymentRegion: CURRENT_REGION,
      isServingFromCorrectRegion: regionConfig.regionId === CURRENT_REGION,
    });
  } catch (err) {
    console.error("[data-residency] Get tenant region error:", err);
    res.status(500).json({ error: "Failed to get tenant region" });
  }
});

/**
 * PUT /api/tenants/:id/region
 * Set the data residency region for a tenant
 * Requires enterprise plan
 */
router.put(
  "/tenants/:id/region",
  requireUser,
  verifyTenantAccess,
  requireTenantOwner,
  async (req, res) => {
    try {
      const tenantId = req.params.id;

      // Validate request body
      const parseResult = setRegionSchema.safeParse(req.body);
      if (!parseResult.success) {
        return res.status(400).json({
          error: "Invalid request",
          details: parseResult.error.issues,
        });
      }

      const { region, reason } = parseResult.data;

      // Validate region exists
      if (!validateRegion(region)) {
        return res.status(400).json({
          error: "Invalid region",
          code: "INVALID_REGION",
          availableRegions: Object.keys(REGIONS),
        });
      }

      // Check enterprise plan
      const subscription = await subscriptions.findByTenantId(tenantId);
      const plan = subscription?.plan || "free";

      if (!isAtLeastPlan(plan, "enterprise")) {
        return res.status(402).json({
          error: "Enterprise plan required",
          code: "ENTERPRISE_REQUIRED",
          feature: "data_residency",
          currentPlan: plan,
          message: "Data residency controls are available on the Enterprise plan",
          upgrade_url: "/billing/upgrade",
        });
      }

      // Get previous region for response
      const previousRegion = await getTenantRegion(tenantId);

      // Set the new region
      await setTenantRegion(tenantId, region, {
        changedBy: req.user.id,
        reason,
      });

      // Get updated config
      const newConfig = await getTenantRegionConfig(tenantId);

      res.json({
        success: true,
        tenantId,
        previousRegion,
        newRegion: region,
        regionConfig: newConfig,
        message: `Data residency region updated to ${region}`,
        note:
          previousRegion !== region
            ? "Existing data may need to be migrated to the new region for full compliance"
            : null,
      });
    } catch (err) {
      console.error("[data-residency] Set tenant region error:", err);

      if (err.message.includes("enterprise plan")) {
        return res.status(402).json({
          error: err.message,
          code: "ENTERPRISE_REQUIRED",
        });
      }

      res.status(500).json({ error: "Failed to set tenant region" });
    }
  },
);

/**
 * GET /api/tenants/:id/data-locations
 * Get data location information for a tenant
 */
router.get("/tenants/:id/data-locations", requireUser, verifyTenantAccess, async (req, res) => {
  try {
    const tenantId = req.params.id;
    const tenantRegion = await getTenantRegion(tenantId);
    const locations = await getDataLocations(tenantId);

    // Categorize locations
    const inRegion = locations.filter((l) => l.region === tenantRegion);
    const outOfRegion = locations.filter((l) => l.region !== tenantRegion);

    res.json({
      tenantId,
      tenantRegion,
      locations,
      summary: {
        total: locations.length,
        inRegion: inRegion.length,
        outOfRegion: outOfRegion.length,
        isFullyCompliant: outOfRegion.length === 0,
      },
      outOfRegionDetails: outOfRegion.length > 0 ? outOfRegion : undefined,
    });
  } catch (err) {
    console.error("[data-residency] Get data locations error:", err);
    res.status(500).json({ error: "Failed to get data locations" });
  }
});

/**
 * GET /api/tenants/:id/data-residency/summary
 * Get full data residency summary for a tenant
 */
router.get(
  "/tenants/:id/data-residency/summary",
  requireUser,
  verifyTenantAccess,
  async (req, res) => {
    try {
      const tenantId = req.params.id;
      const summary = await getDataResidencySummary(tenantId);

      res.json(summary);
    } catch (err) {
      console.error("[data-residency] Get summary error:", err);
      res.status(500).json({ error: "Failed to get data residency summary" });
    }
  },
);

/**
 * POST /api/tenants/:id/data-residency/validate-transfer
 * Validate if a data transfer to another region is allowed
 */
router.post(
  "/tenants/:id/data-residency/validate-transfer",
  requireUser,
  verifyTenantAccess,
  async (req, res) => {
    try {
      const tenantId = req.params.id;

      // Validate request body
      const parseResult = validateTransferSchema.safeParse(req.body);
      if (!parseResult.success) {
        return res.status(400).json({
          error: "Invalid request",
          details: parseResult.error.issues,
        });
      }

      const { toRegion, dataType } = parseResult.data;

      // Validate destination region
      if (!validateRegion(toRegion)) {
        return res.status(400).json({
          error: "Invalid destination region",
          code: "INVALID_REGION",
          availableRegions: Object.keys(REGIONS),
        });
      }

      // Validate data type
      if (dataType && !DATA_TYPES[dataType]) {
        return res.status(400).json({
          error: "Invalid data type",
          code: "INVALID_DATA_TYPE",
          availableTypes: Object.keys(DATA_TYPES),
        });
      }

      // Get source region (tenant's region)
      const fromRegion = await getTenantRegion(tenantId);

      // Validate transfer
      const validation = validateDataTransfer(fromRegion, toRegion, dataType);

      // Log the validation check
      await audit.log(
        req.user.id,
        "data_residency.transfer_validated",
        {
          tenantId,
          fromRegion,
          toRegion,
          dataType,
          allowed: validation.allowed,
        },
        req.ip,
      );

      res.json({
        tenantId,
        fromRegion,
        toRegion,
        dataType,
        ...validation,
      });
    } catch (err) {
      console.error("[data-residency] Validate transfer error:", err);
      res.status(500).json({ error: "Failed to validate transfer" });
    }
  },
);

/**
 * GET /api/tenants/:id/data-residency/compliance
 * Get compliance requirements for the tenant's region
 */
router.get(
  "/tenants/:id/data-residency/compliance",
  requireUser,
  verifyTenantAccess,
  async (req, res) => {
    try {
      const tenantId = req.params.id;
      const region = await getTenantRegion(tenantId);
      const compliance = getComplianceRequirements(region);

      res.json({
        tenantId,
        region,
        ...compliance,
      });
    } catch (err) {
      console.error("[data-residency] Get compliance error:", err);
      res.status(500).json({ error: "Failed to get compliance requirements" });
    }
  },
);

export default router;
