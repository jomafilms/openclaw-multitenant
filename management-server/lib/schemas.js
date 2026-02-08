/**
 * Zod schemas for API input validation
 *
 * This module provides centralized validation schemas for all API endpoints.
 * Use the validate() middleware or validateBody()/validateParams() helpers
 * to validate request data at the start of route handlers.
 */
import { z } from "zod";

// ============================================================
// PRIMITIVE SCHEMAS
// ============================================================

/** Valid email address (trimmed and lowercased) */
export const emailSchema = z.preprocess(
  (val) => (typeof val === "string" ? val.trim().toLowerCase() : val),
  z.string().email("Invalid email format").max(255, "Email must be less than 255 characters"),
);

/** UUID v4 format */
export const uuidSchema = z.string().uuid("Invalid UUID format");

/** Non-empty string with max length */
export const nonEmptyStringSchema = (maxLength = 255) =>
  z
    .string()
    .min(1, "This field is required")
    .max(maxLength, `Must be less than ${maxLength} characters`);

/** Optional non-empty string */
export const optionalStringSchema = (maxLength = 255) =>
  z.string().max(maxLength, `Must be less than ${maxLength} characters`).optional();

/** Password with minimum requirements */
export const passwordSchema = z.string().min(12, "Password must be at least 12 characters");

/** Strong password for vault (16+ chars) */
export const vaultPasswordSchema = z
  .string()
  .min(16, "Vault password must be at least 16 characters");

/** Org slug (lowercase letters, numbers, hyphens) */
export const slugSchema = z
  .string()
  .min(2, "Slug must be at least 2 characters")
  .max(50, "Slug must be less than 50 characters")
  .regex(/^[a-z0-9-]+$/, "Slug must contain only lowercase letters, numbers, and hyphens");

/** Base64 encoded string */
export const base64Schema = z.string().regex(/^[A-Za-z0-9+/]*={0,2}$/, "Invalid base64 format");

/** Hex encoded string */
export const hexSchema = z.string().regex(/^[a-fA-F0-9]+$/, "Invalid hex format");

/** ISO 8601 date string */
export const isoDateSchema = z.string().datetime({ message: "Invalid ISO 8601 date format" });

/** Positive integer */
export const positiveIntSchema = z
  .number()
  .int("Must be a whole number")
  .positive("Must be a positive number");

/** Non-negative integer */
export const nonNegativeIntSchema = z
  .number()
  .int("Must be a whole number")
  .nonnegative("Must be zero or positive");

/** URL */
export const urlSchema = z
  .string()
  .url("Invalid URL format")
  .max(2048, "URL must be less than 2048 characters");

// ============================================================
// PERMISSION SCHEMAS
// ============================================================

/** Valid permission levels */
export const permissionLevels = ["read", "list", "write", "delete", "admin", "share"];

/** Single permission level */
export const permissionLevelSchema = z.enum(["read", "list", "write", "delete", "admin", "share"]);

/** Array of permission levels (legacy format) */
export const permissionsArraySchema = z
  .array(permissionLevelSchema)
  .min(1, "At least one permission is required");

/** Permission object format */
export const permissionsObjectSchema = z
  .object({
    read: z.boolean().optional(),
    list: z.boolean().optional(),
    write: z.boolean().optional(),
    delete: z.boolean().optional(),
    admin: z.boolean().optional(),
    share: z.boolean().optional(),
  })
  .refine(
    (obj) => Object.values(obj).some((v) => v === true),
    "At least one permission must be true",
  );

/** Permissions - accepts both array and object format */
export const permissionsSchema = z.union([permissionsArraySchema, permissionsObjectSchema]);

// ============================================================
// ORG ROLE SCHEMAS
// ============================================================

/** Valid org member roles */
export const orgRoleSchema = z.enum(["member", "admin"]);

// ============================================================
// CAPABILITY TOKEN SCHEMAS
// ============================================================

/** Capability token permissions */
export const capabilityPermissionsSchema = z
  .array(z.enum(["read", "write", "delete", "admin"]))
  .default(["read"]);

/** Allowed secrets pattern */
export const allowedSecretsSchema = z
  .array(z.string())
  .min(1, "At least one secret pattern required")
  .default(["*"]);

/** Capability token structure */
export const capabilityTokenSchema = z.object({
  userId: uuidSchema,
  allowedSecrets: allowedSecretsSchema,
  permissions: capabilityPermissionsSchema,
  ttlSeconds: z
    .number()
    .int()
    .min(60, "TTL must be at least 60 seconds")
    .max(86400 * 30, "TTL cannot exceed 30 days")
    .default(3600),
});

// ============================================================
// AUTH SCHEMAS
// ============================================================

/** Login/signup email */
export const authEmailSchema = z.object({
  email: emailSchema,
});

/** Magic link token */
export const magicLinkTokenSchema = z.object({
  token: z.string().min(32, "Invalid token format"),
});

// ============================================================
// VAULT SCHEMAS
// ============================================================

/** Vault setup */
export const vaultSetupSchema = z.object({
  password: passwordSchema,
});

/** Vault unlock */
export const vaultUnlockSchema = z.object({
  password: z.string().min(1, "Password is required"),
});

/** Vault password change */
export const vaultChangePasswordSchema = z.object({
  currentPassword: z.string().min(1, "Current password is required"),
  newPassword: passwordSchema,
});

/** Vault recovery */
export const vaultRecoverSchema = z.object({
  recoveryPhrase: z
    .string()
    .min(1, "Recovery phrase is required")
    .refine(
      (phrase) => phrase.trim().split(/\s+/).length >= 12,
      "Recovery phrase must contain at least 12 words",
    ),
  newPassword: passwordSchema,
});

/** Vault data update */
export const vaultDataUpdateSchema = z.object({
  password: z.string().min(1, "Password required to update vault"),
  data: z.record(z.unknown()).optional(),
});

// ============================================================
// GROUP SCHEMAS
// ============================================================

/** Create group */
export const createGroupSchema = z.object({
  name: nonEmptyStringSchema(100),
  slug: slugSchema,
  description: optionalStringSchema(500),
});

/** Update group */
export const updateGroupSchema = z.object({
  name: optionalStringSchema(100),
  description: optionalStringSchema(500),
});

/** Add group member */
export const addGroupMemberSchema = z.object({
  userId: uuidSchema,
  role: orgRoleSchema.optional().default("member"),
});

/** Invite to group by email */
export const inviteToGroupSchema = z.object({
  email: emailSchema,
  role: orgRoleSchema.optional().default("member"),
});

// ============================================================
// GROUP RESOURCE SCHEMAS
// ============================================================

/** Resource type */
export const resourceTypeSchema = z
  .enum(["mcp_server", "api", "database", "file_storage", "other"])
  .default("mcp_server");

/** Create group resource */
export const createResourceSchema = z.object({
  name: nonEmptyStringSchema(100),
  description: optionalStringSchema(500),
  resourceType: resourceTypeSchema.optional(),
  endpoint: urlSchema,
  authConfig: z.record(z.unknown()).optional(),
  metadata: z.record(z.unknown()).optional(),
});

/** Update group resource */
export const updateResourceSchema = z.object({
  name: optionalStringSchema(100),
  description: optionalStringSchema(500),
  endpoint: urlSchema.optional(),
  authConfig: z.record(z.unknown()).optional(),
  metadata: z.record(z.unknown()).optional(),
  status: z.enum(["active", "inactive", "deleted"]).optional(),
});

// ============================================================
// GROUP GRANT SCHEMAS
// ============================================================

/** Create resource grant */
export const createGrantSchema = z.object({
  resourceId: uuidSchema,
  userId: uuidSchema,
  permissions: permissionsSchema.optional(),
});

/** Update grant permissions */
export const updateGrantSchema = z.object({
  permissions: permissionsSchema,
});

// ============================================================
// REVOCATION SCHEMAS (for relay-server)
// ============================================================

/** Capability revocation request */
export const revocationRequestSchema = z.object({
  capabilityId: z.string().min(1, "Capability ID is required"),
  revokedBy: base64Schema,
  signature: base64Schema,
  reason: z.string().max(500).optional(),
  originalExpiry: isoDateSchema.optional(),
  timestamp: isoDateSchema,
});

/** Batch revocation check */
export const batchRevocationCheckSchema = z.object({
  capabilityIds: z
    .array(z.string())
    .min(1, "At least one capability ID required")
    .max(100, "Maximum 100 IDs per request"),
});

// ============================================================
// SNAPSHOT SCHEMAS (for relay-server)
// ============================================================

/** Cached snapshot */
export const snapshotSchema = z.object({
  capabilityId: z.string().min(1),
  encryptedData: z.string().min(1),
  ephemeralPublicKey: base64Schema,
  issuerPublicKey: base64Schema,
  signature: base64Schema,
  expiresAt: isoDateSchema,
});

// ============================================================
// GROUP VAULT SCHEMAS
// ============================================================

/** Initialize group vault */
export const initGroupVaultSchema = z.object({
  password: vaultPasswordSchema,
});

/** Unlock group vault */
export const unlockGroupVaultSchema = z.object({
  password: z.string().min(1, "Password is required"),
  userId: uuidSchema.optional(),
});

/** Issue capability token */
export const issueTokenSchema = z.object({
  userId: uuidSchema,
  allowedSecrets: allowedSecretsSchema.optional(),
  permissions: capabilityPermissionsSchema.optional(),
  ttlSeconds: z
    .number()
    .int()
    .min(60)
    .max(86400 * 30)
    .optional()
    .default(3600),
});

/** Store secret */
export const storeSecretSchema = z.object({
  value: z.string().min(1, "Value is required"),
  metadata: z.record(z.unknown()).optional(),
});

// ============================================================
// OAUTH SCHEMAS
// ============================================================

/** OAuth scope levels */
export const oauthScopeSchema = z.enum(["profile", "calendar", "gmail", "drive"]);

/** OAuth scope level for Drive */
export const driveScopeLevelSchema = z.enum(["minimal", "standard", "full"]);

// ============================================================
// PARAM SCHEMAS (for URL parameters)
// ============================================================

/** Common ID parameter */
export const idParamSchema = z.object({
  id: uuidSchema,
});

/** Group ID parameter */
export const groupIdParamSchema = z.object({
  groupId: uuidSchema,
});

/** User ID parameter */
export const userIdParamSchema = z.object({
  userId: uuidSchema,
});

/** Resource ID parameter */
export const resourceIdParamSchema = z.object({
  resourceId: uuidSchema,
});

/** Grant ID parameter */
export const grantIdParamSchema = z.object({
  grantId: uuidSchema,
});

/** Invite ID parameter */
export const inviteIdParamSchema = z.object({
  inviteId: uuidSchema,
});

/** Secret key parameter (non-UUID) */
export const secretKeyParamSchema = z.object({
  key: z
    .string()
    .min(1, "Secret key is required")
    .max(255, "Secret key must be less than 255 characters")
    .regex(
      /^[a-zA-Z0-9_.-]+$/,
      "Secret key must contain only letters, numbers, underscores, dots, and hyphens",
    ),
});

/** Capability ID parameter (non-UUID) */
export const capabilityIdParamSchema = z.object({
  capabilityId: z.string().min(1, "Capability ID is required"),
});

/** Token parameter */
export const tokenParamSchema = z.object({
  token: z.string().min(16, "Invalid token"),
});

// ============================================================
// VALIDATION HELPERS
// ============================================================

/**
 * Format Zod errors into a user-friendly message
 */
export function formatZodError(error) {
  if (!error.errors || error.errors.length === 0) {
    return "Validation failed";
  }

  const messages = error.errors.map((err) => {
    const path = err.path.length > 0 ? `${err.path.join(".")}: ` : "";
    return `${path}${err.message}`;
  });

  return messages.join("; ");
}

/**
 * Validate request body against a schema
 * Returns { success: true, data } or { success: false, error }
 */
export function validateBody(schema, body) {
  const result = schema.safeParse(body);
  if (result.success) {
    return { success: true, data: result.data };
  }
  return { success: false, error: formatZodError(result.error) };
}

/**
 * Validate request params against a schema
 * Returns { success: true, data } or { success: false, error }
 */
export function validateParams(schema, params) {
  const result = schema.safeParse(params);
  if (result.success) {
    return { success: true, data: result.data };
  }
  return { success: false, error: formatZodError(result.error) };
}

/**
 * Validate request query against a schema
 * Returns { success: true, data } or { success: false, error }
 */
export function validateQuery(schema, query) {
  const result = schema.safeParse(query);
  if (result.success) {
    return { success: true, data: result.data };
  }
  return { success: false, error: formatZodError(result.error) };
}

/**
 * Express middleware factory for validation
 * Usage: validate({ body: myBodySchema, params: myParamsSchema })
 */
export function validate({ body: bodySchema, params: paramsSchema, query: querySchema }) {
  return (req, res, next) => {
    // Validate params
    if (paramsSchema) {
      const result = paramsSchema.safeParse(req.params);
      if (!result.success) {
        return res.status(400).json({
          error: "Invalid URL parameters",
          details: formatZodError(result.error),
        });
      }
      req.validatedParams = result.data;
    }

    // Validate query
    if (querySchema) {
      const result = querySchema.safeParse(req.query);
      if (!result.success) {
        return res.status(400).json({
          error: "Invalid query parameters",
          details: formatZodError(result.error),
        });
      }
      req.validatedQuery = result.data;
    }

    // Validate body
    if (bodySchema) {
      const result = bodySchema.safeParse(req.body);
      if (!result.success) {
        return res.status(400).json({
          error: "Invalid request body",
          details: formatZodError(result.error),
        });
      }
      req.validatedBody = result.data;
    }

    next();
  };
}

export default {
  // Primitives
  emailSchema,
  uuidSchema,
  nonEmptyStringSchema,
  optionalStringSchema,
  passwordSchema,
  vaultPasswordSchema,
  slugSchema,
  base64Schema,
  hexSchema,
  isoDateSchema,
  positiveIntSchema,
  nonNegativeIntSchema,
  urlSchema,

  // Permissions
  permissionLevels,
  permissionLevelSchema,
  permissionsArraySchema,
  permissionsObjectSchema,
  permissionsSchema,
  orgRoleSchema,

  // Capability tokens
  capabilityPermissionsSchema,
  allowedSecretsSchema,
  capabilityTokenSchema,

  // Auth
  authEmailSchema,
  magicLinkTokenSchema,

  // Vault
  vaultSetupSchema,
  vaultUnlockSchema,
  vaultChangePasswordSchema,
  vaultRecoverSchema,
  vaultDataUpdateSchema,

  // Group
  createGroupSchema,
  updateGroupSchema,
  addGroupMemberSchema,
  inviteToGroupSchema,

  // Resources
  resourceTypeSchema,
  createResourceSchema,
  updateResourceSchema,

  // Grants
  createGrantSchema,
  updateGrantSchema,

  // Revocation
  revocationRequestSchema,
  batchRevocationCheckSchema,

  // Snapshots
  snapshotSchema,

  // Org vault
  initGroupVaultSchema,
  unlockGroupVaultSchema,
  issueTokenSchema,
  storeSecretSchema,

  // OAuth
  oauthScopeSchema,
  driveScopeLevelSchema,

  // Param schemas
  idParamSchema,
  groupIdParamSchema,
  userIdParamSchema,
  resourceIdParamSchema,
  grantIdParamSchema,
  inviteIdParamSchema,
  secretKeyParamSchema,
  capabilityIdParamSchema,
  tokenParamSchema,

  // Helpers
  formatZodError,
  validateBody,
  validateParams,
  validateQuery,
  validate,
};
