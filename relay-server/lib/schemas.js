/**
 * Zod schemas for Relay Server API validation
 *
 * These schemas validate capability revocation and snapshot requests.
 */
import { z } from "zod";

// ============================================================
// PRIMITIVE SCHEMAS
// ============================================================

/** Base64 encoded string */
export const base64Schema = z.string().regex(/^[A-Za-z0-9+/]*={0,2}$/, "Invalid base64 format");

/** ISO 8601 date string */
export const isoDateSchema = z.string().datetime({ message: "Invalid ISO 8601 date format" });

/** Non-empty string with max length */
export const nonEmptyStringSchema = (maxLength = 255) =>
  z
    .string()
    .min(1, "This field is required")
    .max(maxLength, `Must be less than ${maxLength} characters`);

// ============================================================
// REVOCATION SCHEMAS
// ============================================================

/** Capability revocation request */
export const revocationRequestSchema = z.object({
  capabilityId: nonEmptyStringSchema(256),
  revokedBy: base64Schema,
  signature: base64Schema,
  reason: z.string().max(500).optional(),
  originalExpiry: isoDateSchema.optional(),
  timestamp: isoDateSchema,
});

/** Batch revocation check - limit to 1000 IDs */
export const batchRevocationCheckSchema = z.object({
  capabilityIds: z
    .array(z.string().min(1).max(256))
    .min(1, "At least one capability ID required")
    .max(1000, "Maximum 1000 IDs per request"),
});

/** Capability ID URL parameter */
export const capabilityIdParamSchema = z.object({
  capabilityId: nonEmptyStringSchema(256),
});

// ============================================================
// SNAPSHOT SCHEMAS
// ============================================================

/** Cached snapshot for storage */
export const snapshotSchema = z.object({
  capabilityId: nonEmptyStringSchema(256),
  encryptedData: z.string().min(1, "Encrypted data is required"),
  ephemeralPublicKey: base64Schema,
  nonce: base64Schema,
  tag: base64Schema,
  issuerPublicKey: base64Schema,
  recipientPublicKey: base64Schema,
  signature: base64Schema,
  createdAt: isoDateSchema.optional(),
  expiresAt: isoDateSchema,
});

/** Snapshot list request */
export const snapshotListSchema = z.object({
  recipientPublicKey: base64Schema,
  signature: base64Schema,
  timestamp: isoDateSchema,
});

/** Recipient public key URL parameter */
export const recipientParamSchema = z.object({
  recipientPublicKey: base64Schema,
});

// ============================================================
// MESSAGE SCHEMAS
// ============================================================

/** UUID validation */
export const uuidSchema = z.string().uuid("Invalid UUID format");

/** Send message request (simple mode) */
export const sendMessageSchema = z.object({
  toContainerId: uuidSchema,
  payload: z.string().min(1, "Payload is required"),
});

/** Capability envelope for message forwarding */
export const capabilityEnvelopeSchema = z.object({
  toContainerId: uuidSchema,
  capabilityToken: z.string().min(1, "Capability token is required"),
  encryptedPayload: z.string().min(1, "Encrypted payload is required"),
  nonce: base64Schema.optional(),
  signature: base64Schema.optional(),
});

// ============================================================
// WEBSOCKET MESSAGE SCHEMAS
// ============================================================

/** Maximum batch size for acknowledging messages */
const WS_MAX_BATCH_SIZE = 100;

/** Single message acknowledgment */
export const wsAckMessageSchema = z.object({
  type: z.literal("ack"),
  messageId: z.string().uuid("Invalid message ID format"),
});

/** Batch message acknowledgment */
export const wsAckBatchMessageSchema = z.object({
  type: z.literal("ack_batch"),
  messageIds: z
    .array(z.string().uuid("Invalid message ID format"))
    .min(1, "At least one message ID required")
    .max(WS_MAX_BATCH_SIZE, `Maximum ${WS_MAX_BATCH_SIZE} messages per batch`),
});

/** Ping message */
export const wsPingMessageSchema = z.object({
  type: z.literal("ping"),
});

/** All valid WebSocket message types */
export const wsMessageSchema = z.discriminatedUnion("type", [
  wsAckMessageSchema,
  wsAckBatchMessageSchema,
  wsPingMessageSchema,
]);

// ============================================================
// CONTAINER REGISTRY SCHEMAS
// ============================================================

/** Container registration request */
export const registerContainerSchema = z.object({
  publicKey: base64Schema,
  encryptionPublicKey: base64Schema.optional(),
  callbackUrl: z.string().url("Invalid URL format").optional(),
  challenge: z.string().min(1, "Challenge is required"),
  signature: base64Schema,
});

/** Update registration request */
export const updateRegistrationSchema = z.object({
  callbackUrl: z.string().url("Invalid URL format").optional().nullable(),
  encryptionPublicKey: base64Schema.optional().nullable(),
});

/** Public key hash lookup parameter */
export const publicKeyLookupSchema = z.object({
  publicKeyHash: z.string().length(32, "Public key hash must be 32 characters"),
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
export function validate({ body: bodySchema, params: paramsSchema }) {
  return (req, res, next) => {
    // Validate params
    if (paramsSchema) {
      const result = paramsSchema.safeParse(req.params);
      if (!result.success) {
        return res.status(400).json({
          success: false,
          error: "Invalid URL parameters",
          details: formatZodError(result.error),
        });
      }
      req.validatedParams = result.data;
    }

    // Validate body
    if (bodySchema) {
      const result = bodySchema.safeParse(req.body);
      if (!result.success) {
        return res.status(400).json({
          success: false,
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
  base64Schema,
  isoDateSchema,
  nonEmptyStringSchema,
  uuidSchema,

  // Revocation
  revocationRequestSchema,
  batchRevocationCheckSchema,
  capabilityIdParamSchema,

  // Snapshots
  snapshotSchema,
  snapshotListSchema,
  recipientParamSchema,

  // Messages
  sendMessageSchema,
  capabilityEnvelopeSchema,

  // WebSocket
  wsAckMessageSchema,
  wsAckBatchMessageSchema,
  wsPingMessageSchema,
  wsMessageSchema,

  // Registry
  registerContainerSchema,
  updateRegistrationSchema,
  publicKeyLookupSchema,

  // Helpers
  formatZodError,
  validateBody,
  validateParams,
  validate,
};
