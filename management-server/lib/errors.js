/**
 * Application error classes and utilities
 *
 * Provides a consistent error handling approach:
 * - AppError hierarchy for operational errors
 * - Error codes for client-facing responses
 * - Safe serialization (no stack traces in production)
 */

/**
 * Application error codes
 * Use these for consistent error responses
 */
export const ErrorCodes = {
  // Authentication (401)
  AUTH_REQUIRED: "AUTH_REQUIRED",
  AUTH_INVALID: "AUTH_INVALID",
  AUTH_EXPIRED: "AUTH_EXPIRED",
  MFA_REQUIRED: "MFA_REQUIRED",

  // Authorization (403)
  FORBIDDEN: "FORBIDDEN",
  ADMIN_REQUIRED: "ADMIN_REQUIRED",
  IP_NOT_ALLOWED: "IP_NOT_ALLOWED",
  CSRF_INVALID: "CSRF_INVALID",

  // Rate limiting (429)
  RATE_LIMIT_EXCEEDED: "RATE_LIMIT_EXCEEDED",

  // Validation (400)
  VALIDATION_ERROR: "VALIDATION_ERROR",
  INVALID_INPUT: "INVALID_INPUT",
  MISSING_FIELD: "MISSING_FIELD",

  // Not found (404)
  NOT_FOUND: "NOT_FOUND",
  USER_NOT_FOUND: "USER_NOT_FOUND",
  ORG_NOT_FOUND: "ORG_NOT_FOUND",
  RESOURCE_NOT_FOUND: "RESOURCE_NOT_FOUND",

  // Conflict (409)
  ALREADY_EXISTS: "ALREADY_EXISTS",
  CONFLICT: "CONFLICT",

  // Server errors (500)
  INTERNAL_ERROR: "INTERNAL_ERROR",
  DATABASE_ERROR: "DATABASE_ERROR",
  EXTERNAL_SERVICE_ERROR: "EXTERNAL_SERVICE_ERROR",

  // Service unavailable (503)
  CONTAINER_UNAVAILABLE: "CONTAINER_UNAVAILABLE",
  SERVICE_UNAVAILABLE: "SERVICE_UNAVAILABLE",
};

/**
 * Base application error class
 * All operational errors should extend or use this
 */
export class AppError extends Error {
  /**
   * @param {string} code - Error code from ErrorCodes
   * @param {string} message - Human-readable error message
   * @param {number} statusCode - HTTP status code
   * @param {object|null} details - Additional error details (hidden in production)
   */
  constructor(code, message, statusCode = 500, details = null) {
    super(message);
    this.name = "AppError";
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
    this.isOperational = true; // Expected errors we can handle gracefully
    this.timestamp = new Date().toISOString();

    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Validation error (400)
 */
export class ValidationError extends AppError {
  constructor(message, details = null) {
    super(ErrorCodes.VALIDATION_ERROR, message, 400, details);
    this.name = "ValidationError";
  }
}

/**
 * Authentication error (401)
 */
export class AuthError extends AppError {
  constructor(message = "Authentication required", code = ErrorCodes.AUTH_REQUIRED) {
    super(code, message, 401);
    this.name = "AuthError";
  }
}

/**
 * Authorization/forbidden error (403)
 */
export class ForbiddenError extends AppError {
  constructor(message = "Access denied", code = ErrorCodes.FORBIDDEN) {
    super(code, message, 403);
    this.name = "ForbiddenError";
  }
}

/**
 * Not found error (404)
 */
export class NotFoundError extends AppError {
  constructor(resource, id = null) {
    const message = id ? `${resource} not found: ${id}` : `${resource} not found`;
    super(ErrorCodes.NOT_FOUND, message, 404);
    this.name = "NotFoundError";
    this.resource = resource;
  }
}

/**
 * Conflict error (409)
 */
export class ConflictError extends AppError {
  constructor(message = "Resource already exists", code = ErrorCodes.ALREADY_EXISTS) {
    super(code, message, 409);
    this.name = "ConflictError";
  }
}

/**
 * Rate limit error (429)
 */
export class RateLimitError extends AppError {
  constructor(retryAfter = null) {
    super(ErrorCodes.RATE_LIMIT_EXCEEDED, "Too many requests", 429);
    this.name = "RateLimitError";
    this.retryAfter = retryAfter;
  }
}

/**
 * Internal server error (500)
 */
export class InternalError extends AppError {
  constructor(message = "Internal server error", code = ErrorCodes.INTERNAL_ERROR) {
    super(code, message, 500);
    this.name = "InternalError";
  }
}

/**
 * Service unavailable error (503)
 */
export class ServiceUnavailableError extends AppError {
  constructor(message = "Service temporarily unavailable", code = ErrorCodes.SERVICE_UNAVAILABLE) {
    super(code, message, 503);
    this.name = "ServiceUnavailableError";
  }
}

// ============================================================
// FACTORY FUNCTIONS
// ============================================================

/**
 * Create a generic AppError
 */
export function createError(code, message, statusCode = 500, details = null) {
  return new AppError(code, message, statusCode, details);
}

/**
 * Create a validation error
 */
export function validationError(message, details = null) {
  return new ValidationError(message, details);
}

/**
 * Create a not found error
 */
export function notFoundError(resource, id = null) {
  return new NotFoundError(resource, id);
}

/**
 * Create an auth error
 */
export function authError(message = "Authentication required") {
  return new AuthError(message);
}

/**
 * Create a forbidden error
 */
export function forbiddenError(message = "Access denied") {
  return new ForbiddenError(message);
}

/**
 * Create a rate limit error
 */
export function rateLimitError(retryAfter = null) {
  return new RateLimitError(retryAfter);
}

/**
 * Create an internal error
 */
export function internalError(message = "Internal server error") {
  return new InternalError(message);
}

// ============================================================
// ERROR UTILITIES
// ============================================================

/**
 * Check if error is operational (expected) vs programmer error
 * Operational errors are safe to expose to clients
 */
export function isOperationalError(error) {
  if (error instanceof AppError) {
    return error.isOperational;
  }
  return false;
}

// Database error patterns that should be sanitized
const DB_ERROR_PATTERNS = [
  /duplicate key/i,
  /violates.*constraint/i,
  /relation.*does not exist/i,
  /column.*does not exist/i,
  /syntax error/i,
  /invalid input syntax/i,
];

/**
 * Check if error message contains database-specific information
 */
export function isDatabaseError(error) {
  const message = error?.message || "";
  return DB_ERROR_PATTERNS.some((pattern) => pattern.test(message));
}

/**
 * Serialize error for client response
 * In production, hides stack traces and internal details
 *
 * @param {Error} error - The error to serialize
 * @param {boolean} isProduction - Whether we're in production mode
 * @returns {object} Safe error response object
 */
export function serializeError(error, isProduction = process.env.NODE_ENV === "production") {
  const response = {
    error: {
      code: error.code || ErrorCodes.INTERNAL_ERROR,
      message: error.message,
    },
  };

  // Add retry-after for rate limits
  if (error.retryAfter) {
    response.error.retryAfter = error.retryAfter;
  }

  if (isProduction) {
    // Replace database errors with generic message
    if (isDatabaseError(error)) {
      response.error.message = "A database error occurred";
      response.error.code = ErrorCodes.DATABASE_ERROR;
    }

    // For non-operational errors, use generic message
    if (!isOperationalError(error)) {
      response.error.message = "An unexpected error occurred";
      response.error.code = ErrorCodes.INTERNAL_ERROR;
    }

    // Never include stack or details in production
  } else {
    // In development, include debugging info
    if (error.stack) {
      response.error.stack = error.stack;
    }
    if (error.details) {
      response.error.details = error.details;
    }
  }

  return response;
}

/**
 * Convert Zod validation error to AppError
 * @param {import('zod').ZodError} zodError
 * @returns {ValidationError}
 */
export function fromZodError(zodError) {
  const details = zodError.errors.map((e) => ({
    field: e.path.join("."),
    message: e.message,
  }));

  return new ValidationError("Validation failed", details);
}

export default {
  // Error codes
  ErrorCodes,

  // Error classes
  AppError,
  ValidationError,
  AuthError,
  ForbiddenError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  InternalError,
  ServiceUnavailableError,

  // Factory functions
  createError,
  validationError,
  notFoundError,
  authError,
  forbiddenError,
  rateLimitError,
  internalError,

  // Utilities
  isOperationalError,
  isDatabaseError,
  serializeError,
  fromZodError,
};
