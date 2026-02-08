/**
 * Tenant Branding Routes
 * Wave 5 Enterprise Features (Task 5.6)
 *
 * Provides endpoints for managing tenant branding:
 * - GET /api/tenants/:id/branding - Get tenant branding
 * - PUT /api/tenants/:id/branding - Update tenant branding
 * - DELETE /api/tenants/:id/branding - Reset to defaults
 * - POST /api/tenants/:id/branding/logo - Upload logo
 * - GET /api/tenants/:id/branding/css - Get generated CSS
 *
 * Public endpoint:
 * - GET /api/branding/:tenantSlug - Public branding for login page
 */

import crypto from "crypto";
import { Router } from "express";
import fs from "fs/promises";
import multer from "multer";
import path from "path";
import { z } from "zod";
import { audit, tenants } from "../db/index.js";
import {
  tenantBranding,
  generateBrandingCss,
  invalidateCssCache,
  isValidHexColor,
  isValidUrl,
  ASSET_SIZE_LIMITS,
  ALLOWED_IMAGE_TYPES,
  DEFAULT_BRANDING,
} from "../db/tenant-branding.js";
import { requireUser } from "../middleware/auth.js";
import {
  detectTenant,
  requireTenant,
  requireTenantOwnerRole,
  loadTenantFromParam,
} from "../middleware/tenant-context.js";

const router = Router();

// ============================================================
// MULTER CONFIGURATION FOR FILE UPLOADS
// ============================================================

// Storage configuration
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const uploadDir = process.env.BRANDING_UPLOAD_DIR || "./uploads/branding";
    try {
      await fs.mkdir(uploadDir, { recursive: true });
      cb(null, uploadDir);
    } catch (err) {
      cb(err);
    }
  },
  filename: (req, file, cb) => {
    // Generate unique filename with tenant ID prefix
    const tenantId = req.tenantId || req.params.id;
    const ext = path.extname(file.originalname).toLowerCase();
    const hash = crypto.randomBytes(8).toString("hex");
    cb(null, `${tenantId}-${Date.now()}-${hash}${ext}`);
  },
});

// File filter for image types
const imageFilter = (req, file, cb) => {
  if (ALLOWED_IMAGE_TYPES.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error(`Invalid file type. Allowed types: ${ALLOWED_IMAGE_TYPES.join(", ")}`), false);
  }
};

// Configure multer for different upload types
const uploadLogo = multer({
  storage,
  fileFilter: imageFilter,
  limits: { fileSize: ASSET_SIZE_LIMITS.logo },
}).single("logo");

const uploadFavicon = multer({
  storage,
  fileFilter: imageFilter,
  limits: { fileSize: ASSET_SIZE_LIMITS.favicon },
}).single("favicon");

const uploadBackground = multer({
  storage,
  fileFilter: imageFilter,
  limits: { fileSize: ASSET_SIZE_LIMITS.background },
}).single("background");

// ============================================================
// VALIDATION SCHEMAS
// ============================================================

const hexColorSchema = z.string().refine((val) => isValidHexColor(val), {
  message: "Invalid hex color format. Use #RGB, #RRGGBB, or #RRGGBBAA",
});

const urlSchema = z
  .string()
  .nullable()
  .refine((val) => val === null || isValidUrl(val), {
    message: "Invalid URL. Must be HTTPS or a relative path",
  });

const brandingUpdateSchema = z.object({
  // Logo URLs (set via upload endpoint, can be cleared here)
  logoUrl: urlSchema.optional(),
  logoDarkUrl: urlSchema.optional(),
  faviconUrl: urlSchema.optional(),
  loginBackgroundUrl: urlSchema.optional(),

  // Colors
  primaryColor: hexColorSchema.nullable().optional(),
  secondaryColor: hexColorSchema.nullable().optional(),
  accentColor: hexColorSchema.nullable().optional(),
  backgroundColor: hexColorSchema.nullable().optional(),
  textColor: hexColorSchema.nullable().optional(),

  // Typography
  fontFamily: z.string().max(500).nullable().optional(),
  headingFontFamily: z.string().max(500).nullable().optional(),

  // Custom CSS (will be sanitized)
  customCss: z.string().max(ASSET_SIZE_LIMITS.customCss).nullable().optional(),

  // Email branding (will be sanitized)
  emailHeaderHtml: z.string().max(50000).nullable().optional(),
  emailFooterHtml: z.string().max(50000).nullable().optional(),

  // Login page
  loginTitle: z.string().max(200).nullable().optional(),
  loginSubtitle: z.string().max(500).nullable().optional(),

  // Feature flags
  showPoweredBy: z.boolean().optional(),
});

const logoTypeSchema = z.enum(["logo", "logoDark", "favicon", "loginBackground"]);

// ============================================================
// AUTHENTICATED ROUTES (Tenant Management)
// ============================================================

/**
 * GET /api/tenants/:id/branding
 * Get branding settings for a tenant
 * Requires tenant membership
 */
router.get("/tenants/:id/branding", requireUser, loadTenantFromParam, async (req, res) => {
  try {
    const tenantId = req.params.id;
    const branding = await tenantBranding.getBranding(tenantId);

    // Remove internal fields for response
    const { _tenantId, ...publicBranding } = branding;

    res.json({
      branding: publicBranding,
      defaults: DEFAULT_BRANDING,
    });
  } catch (err) {
    console.error("[branding] Error getting branding:", err);
    res.status(500).json({ error: "Failed to get branding settings" });
  }
});

/**
 * PUT /api/tenants/:id/branding
 * Update branding settings for a tenant
 * Requires tenant owner
 */
router.put(
  "/tenants/:id/branding",
  requireUser,
  loadTenantFromParam,
  requireTenantOwnerRole,
  async (req, res) => {
    try {
      // Validate request body
      const parseResult = brandingUpdateSchema.safeParse(req.body);
      if (!parseResult.success) {
        return res.status(400).json({
          error: "Invalid branding settings",
          details: parseResult.error.issues,
        });
      }

      const tenantId = req.params.id;
      const branding = await tenantBranding.updateBranding(tenantId, parseResult.data);

      // Invalidate CSS cache
      invalidateCssCache(tenantId);

      // Audit log
      await audit.log(
        req.user.id,
        "tenant.branding.update",
        {
          tenantId,
          fields: Object.keys(parseResult.data),
        },
        req.ip,
      );

      // Remove internal fields for response
      const { _tenantId, ...publicBranding } = branding;

      res.json({
        success: true,
        branding: publicBranding,
      });
    } catch (err) {
      console.error("[branding] Error updating branding:", err);

      if (err.message.includes("Invalid")) {
        return res.status(400).json({ error: err.message });
      }

      res.status(500).json({ error: "Failed to update branding settings" });
    }
  },
);

/**
 * DELETE /api/tenants/:id/branding
 * Reset branding to defaults
 * Requires tenant owner
 */
router.delete(
  "/tenants/:id/branding",
  requireUser,
  loadTenantFromParam,
  requireTenantOwnerRole,
  async (req, res) => {
    try {
      const tenantId = req.params.id;
      const branding = await tenantBranding.resetBranding(tenantId);

      // Invalidate CSS cache
      invalidateCssCache(tenantId);

      // Audit log
      await audit.log(req.user.id, "tenant.branding.reset", { tenantId }, req.ip);

      // Remove internal fields for response
      const { _tenantId, ...publicBranding } = branding;

      res.json({
        success: true,
        message: "Branding reset to defaults",
        branding: publicBranding,
      });
    } catch (err) {
      console.error("[branding] Error resetting branding:", err);
      res.status(500).json({ error: "Failed to reset branding" });
    }
  },
);

/**
 * POST /api/tenants/:id/branding/logo
 * Upload a logo image
 * Requires tenant owner
 *
 * Query params:
 * - type: logo | logoDark | favicon | loginBackground
 */
router.post(
  "/tenants/:id/branding/logo",
  requireUser,
  loadTenantFromParam,
  requireTenantOwnerRole,
  (req, res, next) => {
    // Validate logo type before upload
    const type = req.query.type || "logo";
    const typeResult = logoTypeSchema.safeParse(type);

    if (!typeResult.success) {
      return res.status(400).json({
        error: "Invalid logo type",
        message: `Type must be one of: logo, logoDark, favicon, loginBackground`,
      });
    }

    req.logoType = type;

    // Select appropriate uploader based on type
    if (type === "favicon") {
      uploadFavicon(req, res, next);
    } else if (type === "loginBackground") {
      uploadBackground(req, res, next);
    } else {
      uploadLogo(req, res, next);
    }
  },
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: "No file uploaded" });
      }

      const tenantId = req.params.id;
      const type = req.logoType;

      // Build URL for the uploaded file
      const baseUrl = process.env.BRANDING_BASE_URL || "/uploads/branding";
      const fileUrl = `${baseUrl}/${req.file.filename}`;

      // Store the URL in branding settings
      const branding = await tenantBranding.setLogoUrl(tenantId, fileUrl, type);

      // Invalidate CSS cache
      invalidateCssCache(tenantId);

      // Audit log
      await audit.log(
        req.user.id,
        "tenant.branding.logo.upload",
        {
          tenantId,
          type,
          filename: req.file.filename,
          size: req.file.size,
        },
        req.ip,
      );

      res.json({
        success: true,
        message: `${type} uploaded successfully`,
        url: fileUrl,
        branding: {
          logoUrl: branding.logoUrl,
          logoDarkUrl: branding.logoDarkUrl,
          faviconUrl: branding.faviconUrl,
          loginBackgroundUrl: branding.loginBackgroundUrl,
        },
      });
    } catch (err) {
      console.error("[branding] Error uploading logo:", err);

      // Clean up uploaded file on error
      if (req.file) {
        try {
          await fs.unlink(req.file.path);
        } catch (unlinkErr) {
          console.error("[branding] Failed to clean up file:", unlinkErr);
        }
      }

      res.status(500).json({ error: "Failed to upload logo" });
    }
  },
);

/**
 * DELETE /api/tenants/:id/branding/logo
 * Remove a logo
 * Requires tenant owner
 *
 * Query params:
 * - type: logo | logoDark | favicon | loginBackground
 */
router.delete(
  "/tenants/:id/branding/logo",
  requireUser,
  loadTenantFromParam,
  requireTenantOwnerRole,
  async (req, res) => {
    try {
      const type = req.query.type || "logo";
      const typeResult = logoTypeSchema.safeParse(type);

      if (!typeResult.success) {
        return res.status(400).json({
          error: "Invalid logo type",
          message: `Type must be one of: logo, logoDark, favicon, loginBackground`,
        });
      }

      const tenantId = req.params.id;

      // Get current branding to find file to delete
      const currentBranding = await tenantBranding.getBranding(tenantId);
      const urlFieldMap = {
        logo: "logoUrl",
        logoDark: "logoDarkUrl",
        favicon: "faviconUrl",
        loginBackground: "loginBackgroundUrl",
      };
      const currentUrl = currentBranding[urlFieldMap[type]];

      // Remove logo from branding
      const branding = await tenantBranding.removeLogo(tenantId, type);

      // Try to delete the file if it's a local upload
      if (currentUrl && currentUrl.startsWith("/uploads/branding/")) {
        const uploadDir = process.env.BRANDING_UPLOAD_DIR || "./uploads/branding";
        const filename = currentUrl.split("/").pop();
        try {
          await fs.unlink(path.join(uploadDir, filename));
        } catch (unlinkErr) {
          // File may not exist, that's okay
          console.warn("[branding] Could not delete file:", unlinkErr.message);
        }
      }

      // Invalidate CSS cache
      invalidateCssCache(tenantId);

      // Audit log
      await audit.log(req.user.id, "tenant.branding.logo.remove", { tenantId, type }, req.ip);

      res.json({
        success: true,
        message: `${type} removed`,
        branding: {
          logoUrl: branding.logoUrl,
          logoDarkUrl: branding.logoDarkUrl,
          faviconUrl: branding.faviconUrl,
          loginBackgroundUrl: branding.loginBackgroundUrl,
        },
      });
    } catch (err) {
      console.error("[branding] Error removing logo:", err);
      res.status(500).json({ error: "Failed to remove logo" });
    }
  },
);

/**
 * GET /api/tenants/:id/branding/css
 * Get generated CSS for the tenant
 * Returns CSS with custom properties and custom CSS
 */
router.get("/tenants/:id/branding/css", requireUser, loadTenantFromParam, async (req, res) => {
  try {
    const tenantId = req.params.id;
    const includeCustomCss = req.query.includeCustomCss !== "false";

    const css = await generateBrandingCss(tenantId, { includeCustomCss });

    res.type("text/css").send(css);
  } catch (err) {
    console.error("[branding] Error generating CSS:", err);
    res.status(500).json({ error: "Failed to generate CSS" });
  }
});

// ============================================================
// PUBLIC ROUTES (No Authentication Required)
// ============================================================

/**
 * GET /api/branding/:tenantSlug
 * Public endpoint for fetching tenant branding
 * Used on login pages and public-facing interfaces
 *
 * Returns minimal branding info suitable for public display
 */
router.get("/branding/:tenantSlug", async (req, res) => {
  try {
    const slug = req.params.tenantSlug;

    // Validate slug format
    if (!slug || typeof slug !== "string" || slug.length > 100) {
      return res.status(400).json({ error: "Invalid tenant slug" });
    }

    const branding = await tenantBranding.getBrandingBySlug(slug);

    if (!branding) {
      return res.status(404).json({ error: "Tenant not found" });
    }

    // Return only public-safe branding info
    res.json({
      tenantName: branding._tenantName,
      tenantSlug: branding._tenantSlug,
      logoUrl: branding.logoUrl,
      logoDarkUrl: branding.logoDarkUrl,
      faviconUrl: branding.faviconUrl,
      primaryColor: branding.primaryColor,
      secondaryColor: branding.secondaryColor,
      accentColor: branding.accentColor,
      backgroundColor: branding.backgroundColor,
      textColor: branding.textColor,
      fontFamily: branding.fontFamily,
      loginTitle: branding.loginTitle,
      loginSubtitle: branding.loginSubtitle,
      loginBackgroundUrl: branding.loginBackgroundUrl,
      showPoweredBy: branding.showPoweredBy,
    });
  } catch (err) {
    console.error("[branding] Error fetching public branding:", err);
    res.status(500).json({ error: "Failed to fetch branding" });
  }
});

/**
 * GET /api/branding/:tenantSlug/css
 * Public endpoint for tenant CSS
 * Returns CSS without custom CSS for security
 */
router.get("/branding/:tenantSlug/css", async (req, res) => {
  try {
    const slug = req.params.tenantSlug;

    // Validate slug format
    if (!slug || typeof slug !== "string" || slug.length > 100) {
      return res.status(400).json({ error: "Invalid tenant slug" });
    }

    // Look up tenant
    const tenant = await tenants.findBySlug(slug);
    if (!tenant || tenant.status !== "active") {
      return res.status(404).json({ error: "Tenant not found" });
    }

    // Generate CSS without custom CSS (public endpoint = no custom CSS for security)
    const css = await generateBrandingCss(tenant.id, { includeCustomCss: false });

    // Set caching headers
    res.set({
      "Content-Type": "text/css",
      "Cache-Control": "public, max-age=300", // 5 minutes
    });

    res.send(css);
  } catch (err) {
    console.error("[branding] Error generating public CSS:", err);
    res.status(500).json({ error: "Failed to generate CSS" });
  }
});

// ============================================================
// ERROR HANDLING FOR MULTER
// ============================================================

router.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({
        error: "File too large",
        message: `Maximum file size is ${Math.round(ASSET_SIZE_LIMITS.logo / 1024 / 1024)}MB for logos`,
      });
    }
    return res.status(400).json({ error: err.message });
  }

  if (err.message && err.message.includes("Invalid file type")) {
    return res.status(400).json({ error: err.message });
  }

  next(err);
});

export default router;
