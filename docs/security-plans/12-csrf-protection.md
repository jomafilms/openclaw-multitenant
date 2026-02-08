# Security Plan 12: CSRF Protection

## Overview

**Problem**: State-changing requests (POST, PUT, DELETE) are vulnerable to Cross-Site Request Forgery attacks. An attacker can trick a logged-in user into making unintended requests.

**Solution**:

1. Double-submit cookie pattern with cryptographic tokens
2. SameSite cookie attribute for additional protection
3. Origin/Referer header validation
4. Exemption for API-key authenticated requests

---

## Attack Scenario

```html
<!-- Malicious site embeds this -->
<form action="https://ocmt.example.com/api/group-invites/abc123/accept" method="POST"></form>
<script>
  document.forms[0].submit();
</script>
```

If the user has an active session, this form submission succeeds because cookies are sent automatically.

---

## CRITICAL: High-Value CSRF Targets (Groups + Shares Refactor)

The Groups + Shares refactor introduced endpoints that are particularly attractive CSRF targets:

| Endpoint                              | Risk         | Impact if Exploited                                  |
| ------------------------------------- | ------------ | ---------------------------------------------------- |
| `POST /api/group-invites/:id/accept`  | **CRITICAL** | Attacker tricks user into joining malicious group    |
| `POST /api/group-invites/:id/decline` | HIGH         | Attacker prevents user from joining legitimate group |
| `POST /api/groups/:id/invites`        | HIGH         | Spam invites sent from victim's account              |
| `DELETE /api/groups/:id`              | **CRITICAL** | Attacker deletes user's group                        |
| `POST /api/shares`                    | HIGH         | Unauthorized sharing of resources                    |
| `DELETE /api/shares/:id`              | HIGH         | Revoke victim's access to shared resources           |

**These endpoints MUST have CSRF protection before the feature goes live.**

### Attack Example: Force Group Join

```html
<!-- Attacker's page: evil-site.com -->
<h1>Click to claim your prize!</h1>
<form
  id="csrf"
  action="https://ocmt.example.com/api/group-invites/attacker-invite-id/accept"
  method="POST"
></form>
<script>
  // User with active OCMT session visits this page
  // Form auto-submits, user unknowingly joins attacker's group
  document.getElementById("csrf").submit();
</script>
```

---

## Implementation

### 1. CSRF Token Generation

**Create `management-server/lib/csrf.js`:**

```javascript
import crypto from "crypto";

const CSRF_SECRET = process.env.CSRF_SECRET || crypto.randomBytes(32).toString("hex");
const TOKEN_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Generate CSRF token bound to session
 * Uses HMAC to bind token to session without server-side storage
 */
export function generateCsrfToken(sessionId) {
  const timestamp = Date.now();
  const random = crypto.randomBytes(16).toString("hex");
  const payload = `${sessionId}:${timestamp}:${random}`;

  const signature = crypto.createHmac("sha256", CSRF_SECRET).update(payload).digest("hex");

  // Token format: payload.signature (both base64url encoded)
  const token =
    Buffer.from(payload).toString("base64url") + "." + Buffer.from(signature).toString("base64url");

  return token;
}

/**
 * Validate CSRF token
 * Returns { valid: boolean, error?: string }
 */
export function validateCsrfToken(token, sessionId) {
  if (!token) {
    return { valid: false, error: "CSRF token missing" };
  }

  const parts = token.split(".");
  if (parts.length !== 2) {
    return { valid: false, error: "Invalid CSRF token format" };
  }

  try {
    const payload = Buffer.from(parts[0], "base64url").toString("utf8");
    const providedSignature = Buffer.from(parts[1], "base64url").toString("hex");

    // Verify signature
    const expectedSignature = crypto
      .createHmac("sha256", CSRF_SECRET)
      .update(payload)
      .digest("hex");

    // Timing-safe comparison
    if (
      !crypto.timingSafeEqual(
        Buffer.from(providedSignature, "hex"),
        Buffer.from(expectedSignature, "hex"),
      )
    ) {
      return { valid: false, error: "Invalid CSRF token signature" };
    }

    // Parse payload
    const [tokenSessionId, timestamp] = payload.split(":");

    // Verify session binding
    if (tokenSessionId !== sessionId) {
      return { valid: false, error: "CSRF token session mismatch" };
    }

    // Check expiry
    const tokenAge = Date.now() - parseInt(timestamp, 10);
    if (tokenAge > TOKEN_EXPIRY_MS) {
      return { valid: false, error: "CSRF token expired" };
    }

    return { valid: true };
  } catch (err) {
    return { valid: false, error: "CSRF token validation failed" };
  }
}

/**
 * Get CSRF token from request
 * Checks header first, then body
 */
export function getCsrfTokenFromRequest(req) {
  // Header takes precedence (X-CSRF-Token or X-XSRF-Token)
  const headerToken = req.headers["x-csrf-token"] || req.headers["x-xsrf-token"];
  if (headerToken) {
    return headerToken;
  }

  // Fall back to body field
  if (req.body && req.body._csrf) {
    return req.body._csrf;
  }

  return null;
}
```

### 2. CSRF Middleware

**Create `management-server/middleware/csrf.js`:**

```javascript
import { validateCsrfToken, getCsrfTokenFromRequest, generateCsrfToken } from "../lib/csrf.js";
import { audit } from "../db/index.js";

// Methods that require CSRF protection
const PROTECTED_METHODS = ["POST", "PUT", "PATCH", "DELETE"];

// Paths exempt from CSRF (e.g., webhooks, API endpoints with their own auth)
const EXEMPT_PATHS = [/^\/api\/webhooks\//, /^\/api\/callbacks\//, /^\/health$/];

/**
 * CSRF protection middleware
 */
export function csrfProtection(req, res, next) {
  // Skip safe methods
  if (!PROTECTED_METHODS.includes(req.method)) {
    return next();
  }

  // Skip exempt paths
  if (EXEMPT_PATHS.some((pattern) => pattern.test(req.path))) {
    return next();
  }

  // Skip if using API key authentication (not cookie-based)
  if (req.headers["x-api-key"] || req.headers.authorization?.startsWith("Bearer ")) {
    return next();
  }

  // Validate Origin/Referer header
  const originResult = validateOrigin(req);
  if (!originResult.valid) {
    logCsrfFailure(req, originResult.error);
    return res.status(403).json({
      error: "CSRF validation failed",
      code: "CSRF_ORIGIN_INVALID",
    });
  }

  // Validate CSRF token
  const token = getCsrfTokenFromRequest(req);
  const sessionId = req.sessionId;

  if (!sessionId) {
    // No session = no CSRF token needed (request will fail auth anyway)
    return next();
  }

  const result = validateCsrfToken(token, sessionId);

  if (!result.valid) {
    logCsrfFailure(req, result.error);
    return res.status(403).json({
      error: "CSRF validation failed",
      code: "CSRF_INVALID",
    });
  }

  next();
}

/**
 * Validate Origin or Referer header matches expected origin
 */
function validateOrigin(req) {
  const origin = req.headers.origin;
  const referer = req.headers.referer;

  // At least one must be present for non-same-origin requests
  if (!origin && !referer) {
    // Allow if no origin/referer (same-origin request from browser)
    // This is safe because CSRF attacks from other origins include these headers
    return { valid: true };
  }

  const allowedOrigins = getAllowedOrigins();

  // Check Origin header
  if (origin) {
    if (allowedOrigins.includes(origin)) {
      return { valid: true };
    }
    return { valid: false, error: `Origin not allowed: ${origin}` };
  }

  // Check Referer header
  if (referer) {
    try {
      const refererUrl = new URL(referer);
      const refererOrigin = refererUrl.origin;
      if (allowedOrigins.includes(refererOrigin)) {
        return { valid: true };
      }
      return { valid: false, error: `Referer origin not allowed: ${refererOrigin}` };
    } catch {
      return { valid: false, error: "Invalid Referer header" };
    }
  }

  return { valid: false, error: "No Origin or Referer header" };
}

/**
 * Get allowed origins from environment
 */
function getAllowedOrigins() {
  const origins = process.env.ALLOWED_ORIGINS?.split(",").map((o) => o.trim()) || [];

  // Always allow the app's own origin
  const appUrl = process.env.APP_URL || "http://localhost:3000";
  if (!origins.includes(appUrl)) {
    origins.push(appUrl);
  }

  return origins;
}

/**
 * Log CSRF failures for security monitoring
 */
async function logCsrfFailure(req, reason) {
  console.warn("CSRF validation failed:", {
    path: req.path,
    method: req.method,
    ip: req.ip,
    reason,
    origin: req.headers.origin,
    referer: req.headers.referer,
  });

  await audit
    .log(req.user?.id || null, "security.csrf_failed", { path: req.path, reason }, req.ip)
    .catch(console.error);
}

/**
 * Middleware to attach CSRF token to response
 * Call this after session authentication
 */
export function attachCsrfToken(req, res, next) {
  if (req.sessionId) {
    const token = generateCsrfToken(req.sessionId);

    // Set as cookie for JavaScript access
    res.cookie("XSRF-TOKEN", token, {
      httpOnly: false, // JavaScript needs to read this
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    });

    // Also expose in header for API responses
    res.setHeader("X-CSRF-Token", token);
  }

  next();
}
```

### 3. SameSite Cookie Configuration

**Update session cookie settings in `middleware/auth.js`:**

```javascript
const SESSION_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax", // 'strict' for maximum security, 'lax' for usability
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  path: "/",
};

// For admin sessions, use stricter settings
const ADMIN_SESSION_COOKIE_OPTIONS = {
  ...SESSION_COOKIE_OPTIONS,
  sameSite: "strict",
  maxAge: 60 * 60 * 1000, // 1 hour
};
```

### 4. Server Integration

**Update `management-server/server.js`:**

```javascript
import { csrfProtection, attachCsrfToken } from "./middleware/csrf.js";

// After session authentication middleware
app.use(attachCsrfToken);

// Before route handlers
app.use(csrfProtection);
```

### 5. Frontend Integration

**Update `user-ui/src/lib/api.ts`:**

```typescript
class ApiClient {
  private csrfToken: string | null = null;

  constructor() {
    // Read CSRF token from cookie
    this.csrfToken = this.getCsrfTokenFromCookie();
  }

  private getCsrfTokenFromCookie(): string | null {
    const match = document.cookie.match(/XSRF-TOKEN=([^;]+)/);
    return match ? match[1] : null;
  }

  private async request(method: string, path: string, body?: unknown) {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };

    // Add CSRF token for state-changing requests
    if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
      // Refresh token from cookie (may have been updated)
      this.csrfToken = this.getCsrfTokenFromCookie();

      if (this.csrfToken) {
        headers["X-CSRF-Token"] = this.csrfToken;
      }
    }

    const response = await fetch(`/api${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
      credentials: "include", // Include cookies
    });

    // Update CSRF token from response header
    const newToken = response.headers.get("X-CSRF-Token");
    if (newToken) {
      this.csrfToken = newToken;
    }

    if (!response.ok) {
      const error = await response.json();

      // Handle CSRF errors specifically
      if (error.code === "CSRF_INVALID") {
        // Refresh token and retry once
        this.csrfToken = this.getCsrfTokenFromCookie();
        // Could implement retry logic here
      }

      throw new ApiError(error.error, error.code, response.status);
    }

    return response.json();
  }

  async post(path: string, body: unknown) {
    return this.request("POST", path, body);
  }

  async put(path: string, body: unknown) {
    return this.request("PUT", path, body);
  }

  async delete(path: string) {
    return this.request("DELETE", path);
  }
}
```

### 6. HTML Form Support

For traditional form submissions (non-SPA):

```javascript
// Middleware to inject CSRF token into rendered pages
export function injectCsrfToken(req, res, next) {
  res.locals.csrfToken = req.csrfToken;
  next();
}
```

```html
<!-- In HTML templates -->
<form method="POST" action="/api/settings">
  <input type="hidden" name="_csrf" value="<%= csrfToken %>" />
  <!-- form fields -->
  <button type="submit">Save</button>
</form>
```

---

## Environment Variables

```bash
# Secret for CSRF token signing (generate with: openssl rand -hex 32)
CSRF_SECRET=<64-char-hex>

# Allowed origins for Origin/Referer validation
ALLOWED_ORIGINS=https://app.ocmt.example.com,https://admin.ocmt.example.com
```

---

## Files to Create

| File                 | Purpose                         |
| -------------------- | ------------------------------- |
| `lib/csrf.js`        | Token generation and validation |
| `middleware/csrf.js` | Request protection middleware   |

## Files to Modify

| File                      | Changes                                 |
| ------------------------- | --------------------------------------- |
| `server.js`               | Add CSRF middleware                     |
| `middleware/auth.js`      | Update cookie SameSite settings         |
| `user-ui/src/lib/api.ts`  | Add CSRF token handling                 |
| `routes/group-invites.js` | Verify CSRF applied (high-value target) |
| `routes/shares.js`        | Verify CSRF applied (high-value target) |
| `routes/groups.js`        | Verify CSRF applied                     |

---

## Testing

```bash
# Test CSRF protection on invite accept (CRITICAL - Groups refactor)
curl -X POST http://localhost:3000/api/group-invites/abc123/accept \
  -H "Content-Type: application/json" \
  -H "Cookie: ocmt_session=valid-session"
# Should return 403 CSRF_INVALID

# Test CSRF protection is active
curl -X POST http://localhost:3000/api/groups \
  -H "Content-Type: application/json" \
  -H "Cookie: ocmt_session=valid-session" \
  -d '{"name": "test"}'
# Should return 403 CSRF_INVALID

# Test with valid token
curl -X POST http://localhost:3000/api/groups \
  -H "Content-Type: application/json" \
  -H "Cookie: ocmt_session=valid-session" \
  -H "X-CSRF-Token: valid-token" \
  -d '{"name": "test"}'
# Should succeed

# Test Origin validation
curl -X POST http://localhost:3000/api/groups \
  -H "Content-Type: application/json" \
  -H "Cookie: ocmt_session=valid-session" \
  -H "Origin: https://evil.com" \
  -H "X-CSRF-Token: valid-token" \
  -d '{"name": "test"}'
# Should return 403 CSRF_ORIGIN_INVALID
```

---

## Security Considerations

1. **Token Binding**: Tokens are cryptographically bound to session ID
2. **Timing-Safe**: All comparisons use constant-time algorithms
3. **Origin Validation**: Defense-in-depth against token theft
4. **SameSite Cookies**: Browser-level protection
5. **Exempt Paths**: Webhooks use signature validation instead

---

## Priority

**HIGH** - CSRF enables attackers to perform actions as authenticated users.

## Estimated Effort

- Token library: 2 hours
- Middleware: 2 hours
- Frontend integration: 1 hour
- Testing: 1 hour

**Total: ~6 hours**
