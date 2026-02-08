# Security Plan 10: Error Handling & Information Disclosure

## Overview

**Problem**: Error responses may leak sensitive information:

- Stack traces exposing file paths and code structure
- Database errors revealing schema details
- Internal service errors showing infrastructure
- Validation errors exposing field names and constraints

**Solution**:

1. Centralized error handling middleware
2. Error classification (operational vs programmer)
3. Sanitized responses in production
4. Structured logging without client exposure

---

## Current State

Errors are handled inconsistently:

```javascript
// Pattern 1: Full error exposed
catch (err) {
  res.status(500).json({ error: err.message, stack: err.stack });
}

// Pattern 2: Generic but no logging
catch (err) {
  res.status(500).json({ error: 'Internal error' });
}

// Pattern 3: Database errors exposed
catch (err) {
  res.status(500).json({ error: err.message });
  // Might expose: "duplicate key value violates unique constraint..."
}
```

---

## Implementation

### 1. Error Classes

**Create `management-server/lib/errors.js`:**

```javascript
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
 */
export class AppError extends Error {
  constructor(code, message, statusCode = 500, details = null) {
    super(message);
    this.name = "AppError";
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
    this.isOperational = true; // Expected errors we can handle
    this.timestamp = new Date().toISOString();

    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Factory functions for common errors
 */
export function createError(code, message, statusCode = 500, details = null) {
  return new AppError(code, message, statusCode, details);
}

export function validationError(message, details = null) {
  return new AppError(ErrorCodes.VALIDATION_ERROR, message, 400, details);
}

export function notFoundError(resource, id = null) {
  const message = id ? `${resource} not found: ${id}` : `${resource} not found`;
  return new AppError(ErrorCodes.NOT_FOUND, message, 404);
}

export function authError(message = "Authentication required") {
  return new AppError(ErrorCodes.AUTH_REQUIRED, message, 401);
}

export function forbiddenError(message = "Access denied") {
  return new AppError(ErrorCodes.FORBIDDEN, message, 403);
}

export function rateLimitError(retryAfter = null) {
  const error = new AppError(ErrorCodes.RATE_LIMIT_EXCEEDED, "Too many requests", 429);
  error.retryAfter = retryAfter;
  return error;
}

export function internalError(message = "Internal server error") {
  return new AppError(ErrorCodes.INTERNAL_ERROR, message, 500);
}

/**
 * Check if error is operational (expected) vs programmer error
 */
export function isOperationalError(error) {
  if (error instanceof AppError) {
    return error.isOperational;
  }
  return false;
}
```

### 2. Error Handler Middleware

**Create `management-server/middleware/error-handler.js`:**

```javascript
import { isOperationalError, ErrorCodes } from "../lib/errors.js";
import { audit } from "../db/index.js";

// Sensitive patterns to redact from logs
const SENSITIVE_PATTERNS = [
  /password/i,
  /token/i,
  /secret/i,
  /key/i,
  /authorization/i,
  /cookie/i,
  /session/i,
  /credential/i,
];

// Database error patterns
const DB_ERROR_PATTERNS = [
  /duplicate key/i,
  /violates.*constraint/i,
  /relation.*does not exist/i,
  /column.*does not exist/i,
  /syntax error/i,
];

/**
 * Sanitize error details for client response
 */
function sanitizeForClient(error, isProduction) {
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

  // In production, hide internal error details
  if (isProduction) {
    // Replace database errors with generic message
    if (DB_ERROR_PATTERNS.some((p) => p.test(error.message))) {
      response.error.message = "A database error occurred";
      response.error.code = ErrorCodes.DATABASE_ERROR;
    }

    // Never expose stack traces
    delete response.error.stack;

    // Remove internal details
    delete response.error.details;

    // Sanitize specific error types
    if (!isOperationalError(error)) {
      response.error.message = "An unexpected error occurred";
      response.error.code = ErrorCodes.INTERNAL_ERROR;
    }
  } else {
    // In development, include stack for debugging
    response.error.stack = error.stack;
    response.error.details = error.details;
  }

  return response;
}

/**
 * Sanitize error for logging (remove secrets)
 */
function sanitizeForLogging(error, req) {
  const sanitized = {
    code: error.code,
    message: error.message,
    statusCode: error.statusCode,
    stack: error.stack,
    timestamp: new Date().toISOString(),
    request: {
      method: req.method,
      path: req.path,
      ip: req.ip,
    },
  };

  // Redact sensitive fields from error message
  let message = sanitized.message;
  SENSITIVE_PATTERNS.forEach((pattern) => {
    message = message.replace(pattern, "[REDACTED]");
  });
  sanitized.message = message;

  // Include user ID if available (for audit)
  if (req.user?.id) {
    sanitized.userId = req.user.id;
  }

  return sanitized;
}

/**
 * Central error handler middleware
 * Must be registered LAST in middleware chain
 */
export function errorHandler(err, req, res, next) {
  // If headers already sent, delegate to default handler
  if (res.headersSent) {
    return next(err);
  }

  const isProduction = process.env.NODE_ENV === "production";
  const statusCode = err.statusCode || 500;

  // Log error server-side
  const logData = sanitizeForLogging(err, req);

  if (statusCode >= 500) {
    console.error("Server Error:", JSON.stringify(logData, null, 2));

    // Log to audit trail for 500 errors
    audit
      .log(req.user?.id || null, "error.server", { code: err.code, path: req.path }, req.ip)
      .catch(console.error);
  } else if (statusCode >= 400) {
    console.warn("Client Error:", JSON.stringify(logData));
  }

  // Send sanitized response to client
  const response = sanitizeForClient(err, isProduction);
  res.status(statusCode).json(response);
}

/**
 * 404 handler for unmatched routes
 */
export function notFoundHandler(req, res, next) {
  const error = {
    code: ErrorCodes.NOT_FOUND,
    message: "Endpoint not found",
    statusCode: 404,
    isOperational: true,
  };
  next(error);
}

/**
 * Async route wrapper - catches promise rejections
 */
export function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}
```

### 3. Server Integration

**Update `management-server/server.js`:**

```javascript
import { errorHandler, notFoundHandler, asyncHandler } from "./middleware/error-handler.js";

// ... all route registrations ...

// 404 handler (after all routes)
app.use(notFoundHandler);

// Error handler (MUST be last)
app.use(errorHandler);
```

### 4. Route Migration

**Update routes to use error utilities:**

```javascript
// BEFORE
router.get("/users/:id", async (req, res) => {
  try {
    const user = await users.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message }); // LEAKS INFO
  }
});

// AFTER
import { asyncHandler } from "../middleware/error-handler.js";
import { notFoundError } from "../lib/errors.js";

router.get(
  "/users/:id",
  asyncHandler(async (req, res) => {
    const user = await users.findById(req.params.id);
    if (!user) {
      throw notFoundError("User", req.params.id);
    }
    res.json(user);
    // Errors automatically caught and sanitized
  }),
);
```

### 5. Validation Error Handling

**Create helper for Zod errors:**

```javascript
// In lib/errors.js
import { ZodError } from "zod";

/**
 * Convert Zod validation error to AppError
 */
export function fromZodError(zodError) {
  const details = zodError.errors.map((e) => ({
    field: e.path.join("."),
    message: e.message,
  }));

  return new AppError(ErrorCodes.VALIDATION_ERROR, "Validation failed", 400, details);
}

/**
 * Validation middleware wrapper
 */
export function validate(schema) {
  return (req, res, next) => {
    try {
      req.validated = schema.parse(req.body);
      next();
    } catch (err) {
      if (err instanceof ZodError) {
        next(fromZodError(err));
      } else {
        next(err);
      }
    }
  };
}
```

### 6. Database Error Handling

**Wrap database operations:**

```javascript
// In db/index.js
import { AppError, ErrorCodes } from "../lib/errors.js";

/**
 * Wrap database query with error handling
 */
export async function safeQuery(sql, params) {
  try {
    return await query(sql, params);
  } catch (err) {
    // Log full error server-side
    console.error("Database error:", err);

    // Check for common errors
    if (err.code === "23505") {
      // Unique violation
      throw new AppError(ErrorCodes.ALREADY_EXISTS, "Resource already exists", 409);
    }

    if (err.code === "23503") {
      // Foreign key violation
      throw new AppError(ErrorCodes.NOT_FOUND, "Referenced resource not found", 404);
    }

    // Generic database error (don't expose details)
    throw new AppError(ErrorCodes.DATABASE_ERROR, "Database operation failed", 500);
  }
}
```

---

## Response Format

**Production error response:**

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Validation failed"
  }
}
```

**Development error response:**

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Validation failed",
    "details": [{ "field": "email", "message": "Invalid email format" }],
    "stack": "Error: Validation failed\n    at ..."
  }
}
```

---

## 7. UUID Validation

Add UUID validation for route parameters to prevent invalid ID injection:

### 7.1 UUID Validation Utility

**Add to `management-server/lib/errors.js`:**

```javascript
import { validate as uuidValidate, version as uuidVersion } from "uuid";

/**
 * Check if string is a valid UUID v4
 */
export function isValidUUIDv4(id) {
  return typeof id === "string" && uuidValidate(id) && uuidVersion(id) === 4;
}

/**
 * Middleware to validate UUID route parameters
 * @param {string} paramName - Name of the route parameter to validate
 */
export function validateUUIDParam(paramName) {
  return (req, res, next) => {
    const value = req.params[paramName];

    if (!value) {
      return next(); // Let other middleware handle missing params
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
```

### 7.2 Usage in Routes

```javascript
import { validateUUIDParam } from "../lib/errors.js";

// Validate :id param is a valid UUID
router.get(
  "/users/:id",
  validateUUIDParam("id"),
  requireUser,
  asyncHandler(async (req, res) => {
    const user = await users.findById(req.params.id);
    // ...
  }),
);

// Multiple UUID params
router.get(
  "/groups/:groupId/members/:userId",
  validateUUIDParam("orgId"),
  validateUUIDParam("userId"),
  requireUser,
  asyncHandler(async (req, res) => {
    // ...
  }),
);
```

### 7.3 Add uuid Dependency

```bash
npm install uuid
```

---

## Files to Create

| File                          | Purpose                                   |
| ----------------------------- | ----------------------------------------- |
| `lib/errors.js`               | Error classes, utilities, UUID validation |
| `middleware/error-handler.js` | Central error handling                    |

## Files to Modify

| File           | Changes                                              |
| -------------- | ---------------------------------------------------- |
| `server.js`    | Add error middleware                                 |
| `routes/*.js`  | Migrate to asyncHandler pattern, add UUID validation |
| `db/index.js`  | Add safeQuery wrapper                                |
| `package.json` | Add uuid dependency                                  |

---

## Testing

```bash
# Test 404 handling
curl http://localhost:3000/api/nonexistent
# Should return: {"error":{"code":"NOT_FOUND","message":"Endpoint not found"}}

# Test validation error
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "invalid"}'
# Should return sanitized validation error

# Test 500 error (in development)
# Force an error and verify stack trace appears

# Test 500 error (in production)
NODE_ENV=production npm start
# Force same error and verify stack trace is hidden
```

---

## Priority

**HIGH** - Information disclosure helps attackers understand system internals.

## Estimated Effort

- Error classes: 1 hour
- Error middleware: 2 hours
- Route migration: 2-3 hours
- Testing: 1 hour

**Total: ~6-7 hours**
