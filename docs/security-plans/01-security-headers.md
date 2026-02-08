# Security Plan 01: Security Headers Implementation

## Overview

Add comprehensive security headers to the OCMT management server using Helmet middleware, including Content-Security-Policy, Strict-Transport-Security (HSTS), and other protective headers.

## Current State

- Express 4.x server at `management-server/server.js`
- No security headers currently configured
- Frontend: Lit-based SPA using Vite
- External resources: Google Fonts
- WebSocket connections to container gateway
- SSE for notifications

---

## Implementation Plan

### 1. Install Dependencies

```bash
cd management-server
npm install helmet
```

Add to `management-server/package.json`:

```json
{
  "dependencies": {
    "helmet": "^8.0.0"
  }
}
```

---

### 2. Create Security Headers Module

Create `management-server/lib/security-headers.js`:

```javascript
// Security headers middleware using Helmet
// Configures Content-Security-Policy, HSTS, and other protective headers
import helmet from "helmet";

/**
 * Create security headers middleware
 * @param {Object} options
 * @param {boolean} options.isDevelopment - True for dev mode (relaxed CSP)
 * @param {string[]} [options.additionalConnectSrc] - Extra connect-src domains
 * @param {string[]} [options.additionalScriptSrc] - Extra script-src domains
 * @returns {Function} Express middleware
 */
export function createSecurityHeaders(options = {}) {
  const {
    isDevelopment = process.env.NODE_ENV !== "production",
    additionalConnectSrc = [],
    additionalScriptSrc = [],
  } = options;

  // Base CSP directives
  const cspDirectives = {
    // Default fallback for all resource types
    defaultSrc: ["'self'"],

    // Scripts: Only from same origin
    // Lit uses template literals, not inline scripts
    scriptSrc: ["'self'", ...additionalScriptSrc],

    // Styles: Same origin + inline styles (required for Lit's static styles)
    styleSrc: [
      "'self'",
      "'unsafe-inline'", // Required for Lit's adoptedStyleSheets
      "https://fonts.googleapis.com",
    ],

    // Style elements in shadow DOM
    styleSrcElem: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],

    // Fonts: Same origin + Google Fonts
    fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],

    // Images: Same origin + data URIs
    imgSrc: ["'self'", "data:", "blob:"],

    // Connections: API, WebSocket, SSE
    connectSrc: [
      "'self'",
      isDevelopment ? "ws:" : "wss:",
      ...(isDevelopment ? ["ws://localhost:*", "ws://127.0.0.1:*"] : []),
      ...additionalConnectSrc,
    ],

    // Frame ancestors: Prevent clickjacking
    frameAncestors: ["'none'"],

    // Object/embed: Disallow plugins
    objectSrc: ["'none'"],

    // Base URI: Restrict <base> tag
    baseUri: ["'self'"],

    // Form action: Only submit to same origin
    formAction: ["'self'"],

    // Manifest: Allow PWA manifest
    manifestSrc: ["'self'"],

    // Worker: Allow service workers
    workerSrc: ["'self'", "blob:"],

    // Media: Same origin
    mediaSrc: ["'self'", "blob:"],

    // Child/frame: Disallow iframes
    childSrc: ["'none'"],
    frameSrc: ["'none'"],

    // Upgrade insecure requests in production
    ...(isDevelopment ? {} : { upgradeInsecureRequests: [] }),
  };

  return helmet({
    // Content Security Policy
    contentSecurityPolicy: {
      directives: cspDirectives,
    },

    // Strict-Transport-Security (HSTS)
    strictTransportSecurity: {
      maxAge: 31536000, // 1 year
      includeSubDomains: true,
      preload: true,
    },

    // X-Content-Type-Options: nosniff
    contentTypeOptions: true,

    // X-Frame-Options: DENY
    frameguard: {
      action: "deny",
    },

    // X-XSS-Protection - disabled (CSP is better)
    xssFilter: false,

    // X-DNS-Prefetch-Control
    dnsPrefetchControl: {
      allow: false,
    },

    // X-Download-Options
    ieNoOpen: true,

    // X-Permitted-Cross-Domain-Policies
    permittedCrossDomainPolicies: {
      permittedPolicies: "none",
    },

    // Referrer-Policy
    referrerPolicy: {
      policy: "strict-origin-when-cross-origin",
    },

    // Origin-Agent-Cluster
    originAgentCluster: true,

    // Cross-Origin-Embedder-Policy - disabled to avoid breaking embedding
    crossOriginEmbedderPolicy: false,

    // Cross-Origin-Opener-Policy
    crossOriginOpenerPolicy: {
      policy: "same-origin",
    },

    // Cross-Origin-Resource-Policy
    crossOriginResourcePolicy: {
      policy: "same-origin",
    },
  });
}

/**
 * Additional security headers for API responses
 */
export function apiSecurityHeaders() {
  return (req, res, next) => {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    res.setHeader("Surrogate-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");
    next();
  };
}

/**
 * CSP violation report handler (for debugging)
 */
export function cspReportHandler() {
  return (req, res) => {
    if (req.body) {
      console.warn("[CSP-VIOLATION]", JSON.stringify(req.body, null, 2));
    }
    res.status(204).end();
  };
}

export default {
  createSecurityHeaders,
  apiSecurityHeaders,
  cspReportHandler,
};
```

---

### 3. Integrate into Server

Modify `management-server/server.js`:

```javascript
// Add import at top
import { createSecurityHeaders, apiSecurityHeaders } from "./lib/security-headers.js";

// Add after dotenv.config() and BEFORE app.use(express.json())
const isDevelopment = process.env.NODE_ENV !== "production";

// Apply security headers to all requests (must be first middleware)
app.use(
  createSecurityHeaders({
    isDevelopment,
    additionalConnectSrc: process.env.ADDITIONAL_CSP_CONNECT_SRC
      ? process.env.ADDITIONAL_CSP_CONNECT_SRC.split(",")
      : [],
  }),
);

// Apply additional API-specific security headers
app.use("/api", apiSecurityHeaders());
```

---

### 4. CSP Policy for Lit Frontend

| Directive        | Value                    | Reason                                        |
| ---------------- | ------------------------ | --------------------------------------------- |
| `script-src`     | `'self'`                 | Lit uses ES modules, no inline scripts needed |
| `style-src`      | `'self' 'unsafe-inline'` | **Required** for Lit's `adoptedStyleSheets`   |
| `style-src-elem` | `'self' 'unsafe-inline'` | Lit injects styles into shadow roots          |
| `connect-src`    | `'self' wss:`            | WebSocket for gateway, SSE for notifications  |
| `font-src`       | Google Fonts             | External fonts from CDN                       |

**Note**: `'unsafe-inline'` for styles is required because Lit's `static styles` use `CSSStyleSheet` with `adoptedStyleSheets`. This is safe because it only applies to CSS, not scripts.

---

### 5. HSTS Configuration

```javascript
strictTransportSecurity: {
  maxAge: 31536000,       // 1 year - industry standard
  includeSubDomains: true, // Protect all subdomains
  preload: true,           // Allow browser preload list submission
}
```

**Important considerations:**

- Only sent over HTTPS (Helmet handles this automatically)
- For HSTS preload submission: https://hstspreload.org/
- Test thoroughly before enabling `preload` - it's difficult to undo

---

### 6. Environment Variables

```bash
# Required
NODE_ENV=production  # or "development"

# Optional - comma-separated additional CSP sources
ADDITIONAL_CSP_CONNECT_SRC=https://api.example.com,wss://ws.example.com
```

**Development mode** (`NODE_ENV !== 'production'`):

- Allows `ws://` WebSocket connections
- Includes `localhost` in connect-src
- HSTS not sent over HTTP

**Production mode**:

- Only `wss://` WebSocket allowed
- `upgrade-insecure-requests` directive added
- Full HSTS with preload

---

### 7. Testing

#### 7.1 Manual Testing

```bash
# Test headers are present
curl -I https://your-domain.com/api/health

# Expected headers:
# Content-Security-Policy: ...
# Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
# Referrer-Policy: strict-origin-when-cross-origin
```

#### 7.2 Unit Tests

Create `management-server/lib/security-headers.test.js`:

```javascript
import { describe, it, expect, beforeEach } from "vitest";
import express from "express";
import request from "supertest";
import { createSecurityHeaders, apiSecurityHeaders } from "./security-headers.js";

describe("Security Headers", () => {
  let app;

  beforeEach(() => {
    app = express();
    app.use(createSecurityHeaders({ isDevelopment: false }));
    app.get("/test", (req, res) => res.json({ ok: true }));
  });

  it("should set Content-Security-Policy header", async () => {
    const res = await request(app).get("/test");
    expect(res.headers["content-security-policy"]).toBeDefined();
    expect(res.headers["content-security-policy"]).toContain("default-src 'self'");
  });

  it("should set Strict-Transport-Security header", async () => {
    const res = await request(app).get("/test");
    expect(res.headers["strict-transport-security"]).toBeDefined();
    expect(res.headers["strict-transport-security"]).toContain("max-age=31536000");
  });

  it("should set X-Content-Type-Options header", async () => {
    const res = await request(app).get("/test");
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
  });

  it("should set X-Frame-Options header", async () => {
    const res = await request(app).get("/test");
    expect(res.headers["x-frame-options"]).toBe("DENY");
  });

  it("should allow WebSocket in CSP", async () => {
    const res = await request(app).get("/test");
    expect(res.headers["content-security-policy"]).toContain("wss:");
  });

  describe("Development mode", () => {
    beforeEach(() => {
      app = express();
      app.use(createSecurityHeaders({ isDevelopment: true }));
      app.get("/test", (req, res) => res.json({ ok: true }));
    });

    it("should allow ws:// in development", async () => {
      const res = await request(app).get("/test");
      expect(res.headers["content-security-policy"]).toContain("ws:");
    });
  });
});
```

#### 7.3 Browser Testing Checklist

- [ ] Open DevTools Network tab - verify headers present
- [ ] Check Console - no CSP violations for normal operation
- [ ] Test WebSocket chat functionality
- [ ] Test SSE notification stream
- [ ] Test Google Fonts loading
- [ ] Test iframe embedding is blocked

#### 7.4 Security Scanning Tools

- https://securityheaders.com - Overall grade
- https://observatory.mozilla.org - Mozilla assessment
- https://csp-evaluator.withgoogle.com - CSP analysis

---

### 8. Rollout Strategy

1. **Phase 1**: Deploy with CSP in report-only mode

   ```javascript
   contentSecurityPolicy: {
     directives: cspDirectives,
     reportOnly: true, // Only report, don't block
   }
   ```

2. **Phase 2**: Monitor CSP violation reports for 1-2 weeks

3. **Phase 3**: Switch to enforcement mode

4. **Phase 4**: Submit to HSTS preload list (after 30+ days stable)

---

### 9. Request Body Size Limits (DoS Prevention)

Configure Express body parsers with size limits to prevent large payload DoS attacks:

**Update `management-server/server.js`:**

```javascript
// Apply size limits to body parsers
app.use(
  express.json({
    limit: "100kb", // Reject JSON bodies larger than 100kb
  }),
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "100kb", // Reject URL-encoded bodies larger than 100kb
  }),
);

// For file upload routes, use a larger limit with multer
// import multer from 'multer';
// const upload = multer({ limits: { fileSize: 10 * 1024 * 1024 } }); // 10MB
```

**Environment variable for configuration:**

```bash
# Optional - override default 100kb limit
REQUEST_BODY_LIMIT=100kb
```

```javascript
const bodyLimit = process.env.REQUEST_BODY_LIMIT || "100kb";
app.use(express.json({ limit: bodyLimit }));
```

---

## Files to Modify

| File                             | Change                                             |
| -------------------------------- | -------------------------------------------------- |
| `management-server/package.json` | Add helmet dependency                              |
| `management-server/server.js`    | Import and apply middleware, configure body limits |

## Files to Create

| File                                             | Purpose                     |
| ------------------------------------------------ | --------------------------- |
| `management-server/lib/security-headers.js`      | Security headers middleware |
| `management-server/lib/security-headers.test.js` | Unit tests                  |

---

## Expected Headers After Implementation

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob:; connect-src 'self' wss:; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Origin-Agent-Cluster: ?1
Referrer-Policy: strict-origin-when-cross-origin
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-DNS-Prefetch-Control: off
X-Download-Options: noopen
X-Frame-Options: DENY
X-Permitted-Cross-Domain-Policies: none
```

---

## Priority

**High** - Fundamental protection against XSS, clickjacking, and MITM attacks.

## Estimated Effort

- Implementation: 1-2 hours
- Testing: 1-2 hours
- Rollout (report-only to enforcement): 1-2 weeks

**Total: 2-4 hours active work + monitoring period**
