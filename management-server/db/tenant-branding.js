/**
 * Custom branding system for multi-tenant white-label deployments
 * Wave 5 Enterprise Features (Task 5.6)
 *
 * Provides:
 * - Logo management (light/dark variants)
 * - Color scheme customization
 * - Custom CSS with security sanitization
 * - Email branding templates
 * - CSS variable generation
 *
 * Branding is stored in tenant.settings.branding (JSONB)
 */

import { query } from "./core.js";
import { tenants } from "./tenants.js";

// ============================================================
// CONSTANTS
// ============================================================

/**
 * Default branding settings applied when no custom branding exists
 */
export const DEFAULT_BRANDING = {
  // Logo URLs
  logoUrl: null,
  logoDarkUrl: null, // For dark mode
  faviconUrl: null,

  // Color scheme (hex colors)
  primaryColor: "#2563eb", // Blue-600
  secondaryColor: "#475569", // Slate-600
  accentColor: "#f59e0b", // Amber-500
  backgroundColor: "#ffffff",
  textColor: "#1e293b", // Slate-800

  // Typography
  fontFamily: "Inter, system-ui, sans-serif",
  headingFontFamily: null, // Falls back to fontFamily

  // Custom CSS (sanitized)
  customCss: null,

  // Email branding
  emailHeaderHtml: null,
  emailFooterHtml: null,

  // Login page customization
  loginTitle: null, // Falls back to tenant name
  loginSubtitle: null,
  loginBackgroundUrl: null,

  // Feature flags
  showPoweredBy: true, // "Powered by OCMT" footer
};

/**
 * Allowed CSS properties for custom CSS sanitization
 * This whitelist prevents injection of dangerous CSS properties
 */
export const ALLOWED_CSS_PROPERTIES = [
  // Colors
  "color",
  "background-color",
  "background",
  "border-color",
  "outline-color",

  // Typography
  "font-family",
  "font-size",
  "font-weight",
  "font-style",
  "line-height",
  "letter-spacing",
  "text-align",
  "text-decoration",
  "text-transform",

  // Spacing
  "padding",
  "padding-top",
  "padding-right",
  "padding-bottom",
  "padding-left",
  "margin",
  "margin-top",
  "margin-right",
  "margin-bottom",
  "margin-left",

  // Sizing
  "width",
  "max-width",
  "min-width",
  "height",
  "max-height",
  "min-height",

  // Borders
  "border",
  "border-width",
  "border-style",
  "border-radius",
  "box-shadow",

  // Display
  "display",
  "opacity",
  "visibility",

  // Flexbox (safe subset)
  "flex",
  "flex-direction",
  "justify-content",
  "align-items",
  "gap",
];

/**
 * Maximum sizes for uploaded assets
 */
export const ASSET_SIZE_LIMITS = {
  logo: 2 * 1024 * 1024, // 2MB
  favicon: 512 * 1024, // 512KB
  background: 5 * 1024 * 1024, // 5MB
  customCss: 50 * 1024, // 50KB
};

/**
 * Allowed image MIME types
 */
export const ALLOWED_IMAGE_TYPES = [
  "image/png",
  "image/jpeg",
  "image/gif",
  "image/svg+xml",
  "image/webp",
  "image/x-icon",
  "image/vnd.microsoft.icon",
];

// ============================================================
// VALIDATION HELPERS
// ============================================================

/**
 * Validate hex color format
 * Accepts: #RGB, #RRGGBB, #RRGGBBAA
 *
 * @param {string} color - Color string to validate
 * @returns {boolean} True if valid hex color
 */
export function isValidHexColor(color) {
  if (!color || typeof color !== "string") {
    return false;
  }
  return /^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6}|[0-9A-Fa-f]{8})$/.test(color);
}

/**
 * Validate URL is HTTPS (or relative path for internal assets)
 *
 * @param {string} url - URL to validate
 * @param {object} options - Validation options
 * @param {boolean} options.allowRelative - Allow relative paths (default: true)
 * @param {boolean} options.allowDataUri - Allow data: URIs (default: false)
 * @returns {boolean} True if valid URL
 */
export function isValidUrl(url, options = {}) {
  const { allowRelative = true, allowDataUri = false } = options;

  if (!url || typeof url !== "string") {
    return false;
  }

  // Block dangerous protocols
  const dangerousProtocols = ["javascript:", "vbscript:", "data:"];
  const lowerUrl = url.toLowerCase().trim();

  for (const protocol of dangerousProtocols) {
    if (lowerUrl.startsWith(protocol)) {
      // Allow data: URIs only if explicitly enabled
      if (protocol === "data:" && allowDataUri) {
        // Only allow image data URIs
        if (/^data:image\/(png|jpeg|gif|svg\+xml|webp);base64,/i.test(url)) {
          return true;
        }
      }
      return false;
    }
  }

  // Allow relative paths
  if (allowRelative && (url.startsWith("/") || url.startsWith("./"))) {
    return true;
  }

  // Validate absolute URLs
  try {
    const parsed = new URL(url);
    // Only allow https in production, http in development
    if (parsed.protocol === "https:") {
      return true;
    }
    if (parsed.protocol === "http:" && process.env.NODE_ENV !== "production") {
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Sanitize custom CSS by removing dangerous properties and values
 * Uses a whitelist approach for maximum security
 *
 * @param {string} css - Raw CSS string
 * @returns {string} Sanitized CSS string
 */
export function sanitizeCustomCss(css) {
  if (!css || typeof css !== "string") {
    return "";
  }

  // Limit size
  if (css.length > ASSET_SIZE_LIMITS.customCss) {
    throw new Error(`Custom CSS exceeds maximum size of ${ASSET_SIZE_LIMITS.customCss} bytes`);
  }

  // Remove comments
  let sanitized = css.replace(/\/\*[\s\S]*?\*\//g, "");

  // Remove @import, @charset, @namespace (potential security risks)
  sanitized = sanitized.replace(/@(import|charset|namespace)[^;]*;/gi, "");

  // Remove @font-face (can load external resources)
  sanitized = sanitized.replace(/@font-face\s*\{[^}]*\}/gi, "");

  // Remove url() references except for simple relative paths
  sanitized = sanitized.replace(
    /url\s*\(\s*(['"]?)([^'")\s]+)\1\s*\)/gi,
    (match, quote, urlValue) => {
      // Only allow relative paths starting with /
      if (urlValue.startsWith("/") && !urlValue.includes("..")) {
        return `url(${quote}${urlValue}${quote})`;
      }
      // Remove other url() references
      return "";
    },
  );

  // Remove expression() (IE-specific, dangerous)
  sanitized = sanitized.replace(/expression\s*\([^)]*\)/gi, "");

  // Remove behavior: (IE-specific, dangerous)
  sanitized = sanitized.replace(/behavior\s*:[^;]*;/gi, "");

  // Remove -moz-binding (Firefox-specific, dangerous)
  sanitized = sanitized.replace(/-moz-binding\s*:[^;]*;/gi, "");

  // Parse and filter CSS rules
  const lines = sanitized.split("\n");
  const filteredLines = [];

  for (const line of lines) {
    // Keep selectors and braces as-is
    if (line.includes("{") || line.includes("}")) {
      // Basic selector validation - block dangerous selectors
      if (!line.includes("javascript:") && !line.includes("expression(") && !line.includes("\\")) {
        filteredLines.push(line);
      }
    } else if (line.includes(":")) {
      // Parse property declarations
      const colonIndex = line.indexOf(":");
      const property = line.substring(0, colonIndex).trim().toLowerCase();

      // Check if property is in whitelist
      if (ALLOWED_CSS_PROPERTIES.includes(property)) {
        // Additional value validation
        const value = line.substring(colonIndex + 1).trim();
        if (!value.includes("javascript:") && !value.includes("expression(")) {
          filteredLines.push(line);
        }
      }
    } else {
      // Keep empty lines and other content
      filteredLines.push(line);
    }
  }

  return filteredLines.join("\n").trim();
}

/**
 * Sanitize HTML for email headers/footers
 * Strips dangerous elements and attributes
 *
 * @param {string} html - Raw HTML string
 * @returns {string} Sanitized HTML string
 */
export function sanitizeEmailHtml(html) {
  if (!html || typeof html !== "string") {
    return "";
  }

  // Limit size (max 50KB)
  if (html.length > 50 * 1024) {
    throw new Error("Email HTML exceeds maximum size of 50KB");
  }

  // Remove script tags and their contents
  let sanitized = html.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "");

  // Remove style tags (CSS should be inline)
  sanitized = sanitized.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "");

  // Remove event handlers (onclick, onload, etc.)
  sanitized = sanitized.replace(/\s+on\w+\s*=\s*(['"])[^'"]*\1/gi, "");
  sanitized = sanitized.replace(/\s+on\w+\s*=\s*[^\s>]+/gi, "");

  // Remove javascript: and data: URLs in href/src
  sanitized = sanitized.replace(/(href|src)\s*=\s*(['"])\s*javascript:[^'"]*\2/gi, "$1=$2#$2");
  sanitized = sanitized.replace(/(href|src)\s*=\s*(['"])\s*data:[^'"]*\2/gi, "$1=$2#$2");

  // Remove dangerous elements
  const dangerousElements = ["iframe", "object", "embed", "form", "input", "button", "textarea"];
  for (const element of dangerousElements) {
    sanitized = sanitized.replace(
      new RegExp(`<${element}[^>]*>[\\s\\S]*?<\\/${element}>`, "gi"),
      "",
    );
    sanitized = sanitized.replace(new RegExp(`<${element}[^>]*\\/?>`, "gi"), "");
  }

  return sanitized.trim();
}

/**
 * Validate branding settings object
 * Returns an object with valid fields only
 *
 * @param {object} branding - Branding settings to validate
 * @returns {object} Validated branding settings
 */
export function validateBranding(branding) {
  if (!branding || typeof branding !== "object") {
    return {};
  }

  const validated = {};

  // Validate URLs
  const urlFields = ["logoUrl", "logoDarkUrl", "faviconUrl", "loginBackgroundUrl"];
  for (const field of urlFields) {
    if (branding[field] !== undefined) {
      if (branding[field] === null || branding[field] === "") {
        validated[field] = null;
      } else if (isValidUrl(branding[field])) {
        validated[field] = branding[field];
      } else {
        throw new Error(`Invalid URL for ${field}: must be HTTPS or a relative path`);
      }
    }
  }

  // Validate colors
  const colorFields = [
    "primaryColor",
    "secondaryColor",
    "accentColor",
    "backgroundColor",
    "textColor",
  ];
  for (const field of colorFields) {
    if (branding[field] !== undefined) {
      if (branding[field] === null || branding[field] === "") {
        validated[field] = null;
      } else if (isValidHexColor(branding[field])) {
        validated[field] = branding[field].toLowerCase();
      } else {
        throw new Error(
          `Invalid color for ${field}: must be hex format (#RGB, #RRGGBB, or #RRGGBBAA)`,
        );
      }
    }
  }

  // Validate typography
  const textFields = ["fontFamily", "headingFontFamily", "loginTitle", "loginSubtitle"];
  for (const field of textFields) {
    if (branding[field] !== undefined) {
      if (branding[field] === null || branding[field] === "") {
        validated[field] = null;
      } else if (typeof branding[field] === "string" && branding[field].length <= 500) {
        validated[field] = branding[field];
      }
    }
  }

  // Validate and sanitize custom CSS
  if (branding.customCss !== undefined) {
    if (branding.customCss === null || branding.customCss === "") {
      validated.customCss = null;
    } else {
      validated.customCss = sanitizeCustomCss(branding.customCss);
    }
  }

  // Validate and sanitize email HTML
  if (branding.emailHeaderHtml !== undefined) {
    if (branding.emailHeaderHtml === null || branding.emailHeaderHtml === "") {
      validated.emailHeaderHtml = null;
    } else {
      validated.emailHeaderHtml = sanitizeEmailHtml(branding.emailHeaderHtml);
    }
  }

  if (branding.emailFooterHtml !== undefined) {
    if (branding.emailFooterHtml === null || branding.emailFooterHtml === "") {
      validated.emailFooterHtml = null;
    } else {
      validated.emailFooterHtml = sanitizeEmailHtml(branding.emailFooterHtml);
    }
  }

  // Validate boolean flags
  if (branding.showPoweredBy !== undefined) {
    validated.showPoweredBy = Boolean(branding.showPoweredBy);
  }

  return validated;
}

// ============================================================
// BRANDING DATABASE OPERATIONS
// ============================================================

/**
 * Tenant branding operations
 */
export const tenantBranding = {
  /**
   * Get branding settings for a tenant with defaults applied
   *
   * @param {string} tenantId - Tenant UUID
   * @returns {Promise<object>} Branding settings with defaults
   */
  async getBranding(tenantId) {
    const tenant = await tenants.findById(tenantId);

    if (!tenant) {
      throw new Error(`Tenant not found: ${tenantId}`);
    }

    const customBranding = tenant.settings?.branding || {};

    // Merge with defaults
    return {
      ...DEFAULT_BRANDING,
      ...customBranding,
      // Add tenant info for context
      _tenantId: tenantId,
      _tenantName: tenant.name,
      _tenantSlug: tenant.slug,
    };
  },

  /**
   * Get branding settings by tenant slug (for public endpoints)
   *
   * @param {string} slug - Tenant slug
   * @returns {Promise<object|null>} Branding settings or null if not found
   */
  async getBrandingBySlug(slug) {
    const tenant = await tenants.findBySlug(slug);

    if (!tenant || tenant.status !== "active") {
      return null;
    }

    const customBranding = tenant.settings?.branding || {};

    return {
      ...DEFAULT_BRANDING,
      ...customBranding,
      // Public branding excludes internal tenant ID
      _tenantName: tenant.name,
      _tenantSlug: tenant.slug,
    };
  },

  /**
   * Update branding settings for a tenant
   * Merges with existing settings
   *
   * @param {string} tenantId - Tenant UUID
   * @param {object} branding - Branding settings to update
   * @returns {Promise<object>} Updated branding settings
   */
  async updateBranding(tenantId, branding) {
    // Validate branding settings
    const validated = validateBranding(branding);

    // Get current settings
    const tenant = await tenants.findById(tenantId);
    if (!tenant) {
      throw new Error(`Tenant not found: ${tenantId}`);
    }

    const currentSettings = tenant.settings || {};
    const currentBranding = currentSettings.branding || {};

    // Merge settings
    const newBranding = {
      ...currentBranding,
      ...validated,
      updatedAt: new Date().toISOString(),
    };

    // Update tenant settings
    const res = await query(
      `UPDATE tenants
       SET settings = jsonb_set(
         COALESCE(settings, '{}'::jsonb),
         '{branding}',
         $2::jsonb
       ),
       updated_at = NOW()
       WHERE id = $1
       RETURNING settings`,
      [tenantId, JSON.stringify(newBranding)],
    );

    if (res.rows.length === 0) {
      throw new Error(`Failed to update branding for tenant: ${tenantId}`);
    }

    // Return full branding with defaults
    return {
      ...DEFAULT_BRANDING,
      ...res.rows[0].settings?.branding,
      _tenantId: tenantId,
    };
  },

  /**
   * Reset branding to defaults
   *
   * @param {string} tenantId - Tenant UUID
   * @returns {Promise<object>} Default branding settings
   */
  async resetBranding(tenantId) {
    const tenant = await tenants.findById(tenantId);
    if (!tenant) {
      throw new Error(`Tenant not found: ${tenantId}`);
    }

    // Remove branding from settings
    await query(
      `UPDATE tenants
       SET settings = settings - 'branding',
           updated_at = NOW()
       WHERE id = $1`,
      [tenantId],
    );

    return {
      ...DEFAULT_BRANDING,
      _tenantId: tenantId,
      _tenantName: tenant.name,
      _tenantSlug: tenant.slug,
    };
  },

  /**
   * Store a logo URL for a tenant
   * Validates URL before storing
   *
   * @param {string} tenantId - Tenant UUID
   * @param {string} url - Logo URL (after upload to storage)
   * @param {string} type - Logo type: 'logo', 'logoDark', 'favicon', 'loginBackground'
   * @returns {Promise<object>} Updated branding settings
   */
  async setLogoUrl(tenantId, url, type) {
    const urlFieldMap = {
      logo: "logoUrl",
      logoDark: "logoDarkUrl",
      favicon: "faviconUrl",
      loginBackground: "loginBackgroundUrl",
    };

    const field = urlFieldMap[type];
    if (!field) {
      throw new Error(
        `Invalid logo type: ${type}. Must be one of: ${Object.keys(urlFieldMap).join(", ")}`,
      );
    }

    if (!isValidUrl(url)) {
      throw new Error("Invalid URL: must be HTTPS or a relative path");
    }

    return this.updateBranding(tenantId, { [field]: url });
  },

  /**
   * Remove a logo from tenant branding
   *
   * @param {string} tenantId - Tenant UUID
   * @param {string} type - Logo type to remove
   * @returns {Promise<object>} Updated branding settings
   */
  async removeLogo(tenantId, type) {
    const urlFieldMap = {
      logo: "logoUrl",
      logoDark: "logoDarkUrl",
      favicon: "faviconUrl",
      loginBackground: "loginBackgroundUrl",
    };

    const field = urlFieldMap[type];
    if (!field) {
      throw new Error(`Invalid logo type: ${type}`);
    }

    return this.updateBranding(tenantId, { [field]: null });
  },
};

// ============================================================
// CSS GENERATION
// ============================================================

// Simple in-memory cache for generated CSS
const cssCache = new Map();
const CSS_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

/**
 * Generate CSS variables from branding settings
 * Uses CSS custom properties for easy theming
 *
 * @param {string} tenantId - Tenant UUID
 * @param {object} options - Generation options
 * @param {boolean} options.includeCustomCss - Include custom CSS (default: true)
 * @returns {Promise<string>} Generated CSS string
 */
export async function generateBrandingCss(tenantId, options = {}) {
  const { includeCustomCss = true } = options;

  // Check cache
  const cacheKey = `${tenantId}:${includeCustomCss}`;
  const cached = cssCache.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < CSS_CACHE_TTL) {
    return cached.css;
  }

  const branding = await tenantBranding.getBranding(tenantId);

  // Generate CSS variables
  const cssVariables = [];

  // Colors
  if (branding.primaryColor) {
    cssVariables.push(`--brand-primary: ${branding.primaryColor};`);
    // Generate lighter/darker variants
    cssVariables.push(`--brand-primary-hover: ${adjustBrightness(branding.primaryColor, -10)};`);
    cssVariables.push(`--brand-primary-light: ${adjustBrightness(branding.primaryColor, 20)};`);
  }

  if (branding.secondaryColor) {
    cssVariables.push(`--brand-secondary: ${branding.secondaryColor};`);
    cssVariables.push(
      `--brand-secondary-hover: ${adjustBrightness(branding.secondaryColor, -10)};`,
    );
  }

  if (branding.accentColor) {
    cssVariables.push(`--brand-accent: ${branding.accentColor};`);
    cssVariables.push(`--brand-accent-hover: ${adjustBrightness(branding.accentColor, -10)};`);
  }

  if (branding.backgroundColor) {
    cssVariables.push(`--brand-background: ${branding.backgroundColor};`);
  }

  if (branding.textColor) {
    cssVariables.push(`--brand-text: ${branding.textColor};`);
    cssVariables.push(`--brand-text-muted: ${adjustBrightness(branding.textColor, 30)};`);
  }

  // Typography
  if (branding.fontFamily) {
    cssVariables.push(`--brand-font-family: ${branding.fontFamily};`);
  }

  if (branding.headingFontFamily) {
    cssVariables.push(`--brand-heading-font-family: ${branding.headingFontFamily};`);
  } else if (branding.fontFamily) {
    cssVariables.push(`--brand-heading-font-family: ${branding.fontFamily};`);
  }

  // Logo URLs as CSS variables (for background-image usage)
  if (branding.logoUrl) {
    cssVariables.push(`--brand-logo-url: url('${branding.logoUrl}');`);
  }

  if (branding.logoDarkUrl) {
    cssVariables.push(`--brand-logo-dark-url: url('${branding.logoDarkUrl}');`);
  }

  // Build CSS
  let css = `:root {\n  ${cssVariables.join("\n  ")}\n}\n`;

  // Add custom CSS if enabled
  if (includeCustomCss && branding.customCss) {
    css += `\n/* Custom CSS */\n${branding.customCss}\n`;
  }

  // Cache the result
  cssCache.set(cacheKey, { css, timestamp: Date.now() });

  return css;
}

/**
 * Invalidate CSS cache for a tenant
 * Call this when branding is updated
 *
 * @param {string} tenantId - Tenant UUID
 */
export function invalidateCssCache(tenantId) {
  // Remove all cache entries for this tenant
  for (const key of cssCache.keys()) {
    if (key.startsWith(`${tenantId}:`)) {
      cssCache.delete(key);
    }
  }
}

/**
 * Adjust brightness of a hex color
 *
 * @param {string} hex - Hex color
 * @param {number} percent - Percentage to adjust (-100 to 100)
 * @returns {string} Adjusted hex color
 */
function adjustBrightness(hex, percent) {
  // Remove # if present
  hex = hex.replace(/^#/, "");

  // Parse hex
  let r, g, b;
  if (hex.length === 3) {
    r = parseInt(hex[0] + hex[0], 16);
    g = parseInt(hex[1] + hex[1], 16);
    b = parseInt(hex[2] + hex[2], 16);
  } else {
    r = parseInt(hex.slice(0, 2), 16);
    g = parseInt(hex.slice(2, 4), 16);
    b = parseInt(hex.slice(4, 6), 16);
  }

  // Adjust
  const adjust = (value) => {
    const adjusted = value + Math.round((percent / 100) * 255);
    return Math.max(0, Math.min(255, adjusted));
  };

  r = adjust(r);
  g = adjust(g);
  b = adjust(b);

  // Convert back to hex
  return `#${r.toString(16).padStart(2, "0")}${g.toString(16).padStart(2, "0")}${b.toString(16).padStart(2, "0")}`;
}

// ============================================================
// EMAIL BRANDING
// ============================================================

/**
 * Default email template sections
 */
const DEFAULT_EMAIL_HEADER = `
<table width="100%" cellpadding="0" cellspacing="0" style="background-color: {{primaryColor}}; padding: 20px 0;">
  <tr>
    <td align="center">
      {{#if logoUrl}}
      <img src="{{logoUrl}}" alt="{{tenantName}}" style="max-height: 50px; max-width: 200px;" />
      {{else}}
      <h1 style="color: white; margin: 0; font-family: {{fontFamily}};">{{tenantName}}</h1>
      {{/if}}
    </td>
  </tr>
</table>
`.trim();

const DEFAULT_EMAIL_FOOTER = `
<table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f3f4f6; padding: 20px 0; margin-top: 20px;">
  <tr>
    <td align="center" style="color: #6b7280; font-size: 12px; font-family: {{fontFamily}};">
      {{#if showPoweredBy}}
      <p style="margin: 0;">Powered by OCMT</p>
      {{/if}}
      <p style="margin: 5px 0 0 0;">&copy; {{year}} {{tenantName}}</p>
    </td>
  </tr>
</table>
`.trim();

/**
 * Apply branding to an email template
 *
 * @param {string} tenantId - Tenant UUID
 * @param {string} template - Email template HTML
 * @param {object} data - Additional template data
 * @returns {Promise<string>} Branded email HTML
 */
export async function getBrandedEmailTemplate(tenantId, template, data = {}) {
  const branding = await tenantBranding.getBranding(tenantId);

  // Build template context
  const context = {
    ...data,
    tenantName: branding._tenantName,
    primaryColor: branding.primaryColor || DEFAULT_BRANDING.primaryColor,
    secondaryColor: branding.secondaryColor || DEFAULT_BRANDING.secondaryColor,
    accentColor: branding.accentColor || DEFAULT_BRANDING.accentColor,
    backgroundColor: branding.backgroundColor || DEFAULT_BRANDING.backgroundColor,
    textColor: branding.textColor || DEFAULT_BRANDING.textColor,
    fontFamily: branding.fontFamily || DEFAULT_BRANDING.fontFamily,
    logoUrl: branding.logoUrl,
    showPoweredBy: branding.showPoweredBy !== false,
    year: new Date().getFullYear(),
  };

  // Get header and footer
  const header = branding.emailHeaderHtml || DEFAULT_EMAIL_HEADER;
  const footer = branding.emailFooterHtml || DEFAULT_EMAIL_FOOTER;

  // Simple template replacement (basic mustache-like)
  const replaceVars = (html) => {
    let result = html;

    // Replace simple variables {{var}}
    result = result.replace(/\{\{(\w+)\}\}/g, (match, key) => {
      return context[key] !== undefined ? String(context[key]) : match;
    });

    // Handle conditionals {{#if var}}...{{/if}}
    result = result.replace(/\{\{#if\s+(\w+)\}\}([\s\S]*?)\{\{\/if\}\}/g, (match, key, content) => {
      return context[key] ? content : "";
    });

    // Handle inverse conditionals {{#unless var}}...{{/unless}}
    result = result.replace(
      /\{\{#unless\s+(\w+)\}\}([\s\S]*?)\{\{\/unless\}\}/g,
      (match, key, content) => {
        return !context[key] ? content : "";
      },
    );

    // Handle else {{#if var}}...{{else}}...{{/if}}
    result = result.replace(
      /\{\{#if\s+(\w+)\}\}([\s\S]*?)\{\{else\}\}([\s\S]*?)\{\{\/if\}\}/g,
      (match, key, ifContent, elseContent) => {
        return context[key] ? ifContent : elseContent;
      },
    );

    return result;
  };

  const brandedHeader = replaceVars(header);
  const brandedFooter = replaceVars(footer);
  const brandedContent = replaceVars(template);

  // Wrap in email container with branding styles
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body {
      margin: 0;
      padding: 0;
      font-family: ${context.fontFamily};
      background-color: ${context.backgroundColor};
      color: ${context.textColor};
    }
    a {
      color: ${context.primaryColor};
    }
    .btn-primary {
      background-color: ${context.primaryColor};
      color: white;
      padding: 12px 24px;
      text-decoration: none;
      border-radius: 4px;
      display: inline-block;
    }
    .btn-primary:hover {
      background-color: ${adjustBrightness(context.primaryColor, -10)};
    }
  </style>
</head>
<body>
  <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 600px; margin: 0 auto;">
    <tr>
      <td>
        ${brandedHeader}
      </td>
    </tr>
    <tr>
      <td style="padding: 20px;">
        ${brandedContent}
      </td>
    </tr>
    <tr>
      <td>
        ${brandedFooter}
      </td>
    </tr>
  </table>
</body>
</html>
  `.trim();
}

// ============================================================
// EXPORTS
// ============================================================

export default {
  // Constants
  DEFAULT_BRANDING,
  ALLOWED_CSS_PROPERTIES,
  ASSET_SIZE_LIMITS,
  ALLOWED_IMAGE_TYPES,

  // Validation
  isValidHexColor,
  isValidUrl,
  sanitizeCustomCss,
  sanitizeEmailHtml,
  validateBranding,

  // Database operations
  ...tenantBranding,

  // CSS generation
  generateBrandingCss,
  invalidateCssCache,

  // Email branding
  getBrandedEmailTemplate,
};
