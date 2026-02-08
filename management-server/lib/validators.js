/**
 * Input validation utilities
 *
 * Provides reusable validation functions and middleware for:
 * - UUID validation
 * - Common input patterns
 * - Route parameter validation
 */

import { validate as uuidValidate, version as uuidVersion } from "uuid";
import { ErrorCodes, ValidationError } from "./errors.js";

// ============================================================
// UUID VALIDATION
// ============================================================

/**
 * Check if string is a valid UUID v4
 * @param {string} id - String to validate
 * @returns {boolean}
 */
export function isValidUUID(id) {
  if (typeof id !== "string") {
    return false;
  }
  return uuidValidate(id);
}

/**
 * Check if string is a valid UUID v4 specifically
 * @param {string} id - String to validate
 * @returns {boolean}
 */
export function isValidUUIDv4(id) {
  if (typeof id !== "string") {
    return false;
  }
  return uuidValidate(id) && uuidVersion(id) === 4;
}

/**
 * Middleware to validate UUID route parameters
 * Returns 400 if the parameter is not a valid UUID
 *
 * @param {string} paramName - Name of the route parameter to validate
 * @returns {import('express').RequestHandler}
 *
 * @example
 * router.get('/users/:id', validateUUIDParam('id'), handler);
 * router.get('/groups/:groupId/members/:userId',
 *   validateUUIDParam('groupId'),
 *   validateUUIDParam('userId'),
 *   handler
 * );
 */
export function validateUUIDParam(paramName) {
  return (req, res, next) => {
    const value = req.params[paramName];

    if (!value) {
      // Let other middleware handle missing params
      return next();
    }

    if (!isValidUUIDv4(value)) {
      return res.status(400).json({
        error: {
          code: ErrorCodes.INVALID_INPUT,
          message: "Invalid resource identifier format",
        },
      });
    }

    next();
  };
}

/**
 * Validate multiple UUID params at once
 * @param {...string} paramNames - Names of route parameters to validate
 * @returns {import('express').RequestHandler}
 *
 * @example
 * router.get('/groups/:groupId/resources/:resourceId',
 *   validateUUIDParams('groupId', 'resourceId'),
 *   handler
 * );
 */
export function validateUUIDParams(...paramNames) {
  return (req, res, next) => {
    for (const paramName of paramNames) {
      const value = req.params[paramName];

      if (value && !isValidUUIDv4(value)) {
        return res.status(400).json({
          error: {
            code: ErrorCodes.INVALID_INPUT,
            message: "Invalid resource identifier format",
          },
        });
      }
    }

    next();
  };
}

// ============================================================
// STRING VALIDATION
// ============================================================

/**
 * Check if string is a valid email address
 * @param {string} email - String to validate
 * @returns {boolean}
 */
export function isValidEmail(email) {
  if (typeof email !== "string") {
    return false;
  }
  // Basic email regex - matches most valid emails
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email) && email.length <= 255;
}

/**
 * Check if string is a valid slug (lowercase letters, numbers, hyphens)
 * @param {string} slug - String to validate
 * @returns {boolean}
 */
export function isValidSlug(slug) {
  if (typeof slug !== "string") {
    return false;
  }
  const slugRegex = /^[a-z0-9-]+$/;
  return slugRegex.test(slug) && slug.length >= 2 && slug.length <= 50;
}

/**
 * Check if string is valid base64
 * @param {string} str - String to validate
 * @returns {boolean}
 */
export function isValidBase64(str) {
  if (typeof str !== "string") {
    return false;
  }
  const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
  return base64Regex.test(str);
}

/**
 * Check if string is valid hex
 * @param {string} str - String to validate
 * @returns {boolean}
 */
export function isValidHex(str) {
  if (typeof str !== "string") {
    return false;
  }
  const hexRegex = /^[a-fA-F0-9]+$/;
  return hexRegex.test(str);
}

// ============================================================
// NUMBER VALIDATION
// ============================================================

/**
 * Check if value is a positive integer
 * @param {any} value - Value to validate
 * @returns {boolean}
 */
export function isPositiveInt(value) {
  return Number.isInteger(value) && value > 0;
}

/**
 * Check if value is a non-negative integer
 * @param {any} value - Value to validate
 * @returns {boolean}
 */
export function isNonNegativeInt(value) {
  return Number.isInteger(value) && value >= 0;
}

/**
 * Parse and validate a positive integer from string
 * @param {string} str - String to parse
 * @returns {number|null} - Parsed number or null if invalid
 */
export function parsePositiveInt(str) {
  const num = parseInt(str, 10);
  if (isNaN(num) || num <= 0) {
    return null;
  }
  return num;
}

// ============================================================
// SECURITY VALIDATION
// ============================================================

/**
 * Check if string contains potentially dangerous characters for SQL
 * This is a defense-in-depth measure - always use parameterized queries
 * @param {string} str - String to check
 * @returns {boolean} - True if string appears safe
 */
export function isSafeSQLInput(str) {
  if (typeof str !== "string") {
    return false;
  }
  // Check for common SQL injection patterns
  const dangerousPatterns = [
    /['";]/, // Quote characters
    /--/, // SQL comments
    /\/\*/, // Block comments
    /\bOR\b/i, // OR keyword
    /\bAND\b/i, // AND keyword
    /\bUNION\b/i, // UNION keyword
    /\bSELECT\b/i, // SELECT keyword
    /\bDROP\b/i, // DROP keyword
    /\bDELETE\b/i, // DELETE keyword
    /\bINSERT\b/i, // INSERT keyword
    /\bUPDATE\b/i, // UPDATE keyword
  ];

  return !dangerousPatterns.some((pattern) => pattern.test(str));
}

/**
 * Sanitize string for safe use in logs (remove potential injection)
 * @param {string} str - String to sanitize
 * @param {number} maxLength - Maximum length
 * @returns {string}
 */
export function sanitizeForLog(str, maxLength = 500) {
  if (typeof str !== "string") {
    return String(str).slice(0, maxLength);
  }
  // Remove control characters and limit length
  return str.replace(/[\x00-\x1F\x7F]/g, "").slice(0, maxLength);
}

// ============================================================
// VALIDATION MIDDLEWARE HELPERS
// ============================================================

/**
 * Create middleware that validates request body fields exist
 * @param {...string} fields - Required field names
 * @returns {import('express').RequestHandler}
 *
 * @example
 * router.post('/users', requireBodyFields('email', 'name'), handler);
 */
export function requireBodyFields(...fields) {
  return (req, res, next) => {
    const missing = fields.filter((field) => {
      const value = req.body[field];
      return value === undefined || value === null || value === "";
    });

    if (missing.length > 0) {
      return res.status(400).json({
        error: {
          code: ErrorCodes.MISSING_FIELD,
          message: `Missing required fields: ${missing.join(", ")}`,
        },
      });
    }

    next();
  };
}

/**
 * Create middleware that validates query params
 * @param {Object} schema - Object mapping param names to validator functions
 * @returns {import('express').RequestHandler}
 *
 * @example
 * router.get('/items', validateQueryParams({
 *   page: isPositiveInt,
 *   limit: isPositiveInt,
 * }), handler);
 */
export function validateQueryParams(schema) {
  return (req, res, next) => {
    const errors = [];

    for (const [param, validator] of Object.entries(schema)) {
      const value = req.query[param];
      if (value !== undefined && !validator(value)) {
        errors.push(`Invalid value for '${param}'`);
      }
    }

    if (errors.length > 0) {
      return res.status(400).json({
        error: {
          code: ErrorCodes.VALIDATION_ERROR,
          message: errors.join("; "),
        },
      });
    }

    next();
  };
}

export default {
  // UUID validation
  isValidUUID,
  isValidUUIDv4,
  validateUUIDParam,
  validateUUIDParams,

  // String validation
  isValidEmail,
  isValidSlug,
  isValidBase64,
  isValidHex,

  // Number validation
  isPositiveInt,
  isNonNegativeInt,
  parsePositiveInt,

  // Security validation
  isSafeSQLInput,
  sanitizeForLog,

  // Middleware helpers
  requireBodyFields,
  validateQueryParams,
};
