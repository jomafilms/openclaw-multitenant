/**
 * Zod schemas for Group Vault API validation
 *
 * These schemas validate vault operations and capability token requests.
 */
import { z } from "zod";

// ============================================================
// PRIMITIVE SCHEMAS
// ============================================================

/** UUID v4 format */
export const uuidSchema = z.string().uuid("Invalid UUID format");

/** Strong password for vault (16+ chars) */
export const vaultPasswordSchema = z
  .string()
  .min(16, "Vault password must be at least 16 characters");

/** Non-empty string with max length */
export const nonEmptyStringSchema = (maxLength = 255) =>
  z
    .string()
    .min(1, "This field is required")
    .max(maxLength, `Must be less than ${maxLength} characters`);

/** Secret key format - alphanumeric with underscores/hyphens/dots */
export const secretKeySchema = z
  .string()
  .min(1, "Secret key is required")
  .max(255, "Secret key must be less than 255 characters")
  .regex(
    /^[a-zA-Z0-9_.-]+$/,
    "Secret key must contain only letters, numbers, underscores, dots, and hyphens",
  );

// ============================================================
// VAULT SCHEMAS
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

/** Lock vault (optional userId) */
export const lockVaultSchema = z.object({
  userId: uuidSchema.optional(),
});

// ============================================================
// CAPABILITY TOKEN SCHEMAS
// ============================================================

/** Valid token permissions */
export const tokenPermissionSchema = z.enum(["read", "write", "delete", "admin"]);

/** Capability token permissions array */
export const capabilityPermissionsSchema = z.array(tokenPermissionSchema).default(["read"]);

/** Allowed secrets pattern */
export const allowedSecretsSchema = z
  .array(z.string())
  .min(1, "At least one secret pattern required")
  .default(["*"]);

/** Issue capability token */
export const issueTokenSchema = z.object({
  userId: uuidSchema,
  allowedSecrets: allowedSecretsSchema.optional(),
  permissions: capabilityPermissionsSchema.optional(),
  ttlSeconds: z
    .number()
    .int("TTL must be a whole number")
    .min(60, "TTL must be at least 60 seconds")
    .max(86400 * 30, "TTL cannot exceed 30 days")
    .optional()
    .default(3600),
});

/** Revoke token */
export const revokeTokenSchema = z.object({
  revokedBy: uuidSchema.optional(),
  reason: z.string().max(500).optional(),
});

// ============================================================
// SECRET SCHEMAS
// ============================================================

/** Store secret */
export const storeSecretSchema = z.object({
  value: z.string().min(1, "Value is required"),
  metadata: z.record(z.unknown()).optional(),
});

/** Secret key URL parameter */
export const secretKeyParamSchema = z.object({
  key: secretKeySchema,
});

/** Token ID URL parameter */
export const tokenIdParamSchema = z.object({
  tokenId: z.string().min(1, "Token ID is required"),
});

/** User ID URL parameter */
export const userIdParamSchema = z.object({
  userId: uuidSchema,
});

// ============================================================
// QUERY SCHEMAS
// ============================================================

/** Audit log query */
export const auditQuerySchema = z.object({
  limit: z
    .string()
    .transform((val) => parseInt(val, 10))
    .pipe(z.number().int().min(1).max(1000))
    .optional()
    .default("100"),
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
  uuidSchema,
  vaultPasswordSchema,
  nonEmptyStringSchema,
  secretKeySchema,

  // Vault
  initGroupVaultSchema,
  unlockGroupVaultSchema,
  lockVaultSchema,

  // Tokens
  tokenPermissionSchema,
  capabilityPermissionsSchema,
  allowedSecretsSchema,
  issueTokenSchema,
  revokeTokenSchema,

  // Secrets
  storeSecretSchema,
  secretKeyParamSchema,
  tokenIdParamSchema,
  userIdParamSchema,

  // Query
  auditQuerySchema,

  // Helpers
  formatZodError,
  validateBody,
  validateParams,
  validate,
};
