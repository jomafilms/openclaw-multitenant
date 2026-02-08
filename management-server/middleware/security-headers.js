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
 * Adds cache control and content-type protection
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
 * Logs CSP violations to console for monitoring
 */
export function cspReportHandler() {
  return (req, res) => {
    if (req.body) {
      console.warn("[CSP-VIOLATION]", JSON.stringify(req.body, null, 2));
    }
    res.status(204).end();
  };
}

/**
 * CORS configuration middleware
 * @param {Object} options
 * @param {string|string[]} options.origin - Allowed origins
 * @param {boolean} [options.credentials] - Allow credentials (cookies)
 * @returns {Function} Express middleware
 */
export function corsMiddleware(options = {}) {
  const { origin = process.env.USER_UI_URL || "http://localhost:5173", credentials = true } =
    options;

  return (req, res, next) => {
    const allowedOrigin = Array.isArray(origin) ? origin : [origin];
    const requestOrigin = req.headers.origin;

    // Check if request origin is in allowed list
    if (requestOrigin && allowedOrigin.includes(requestOrigin)) {
      res.header("Access-Control-Allow-Origin", requestOrigin);
    } else if (!requestOrigin && allowedOrigin.length === 1) {
      // No origin header (same-origin request or non-browser client)
      res.header("Access-Control-Allow-Origin", allowedOrigin[0]);
    }

    if (credentials) {
      res.header("Access-Control-Allow-Credentials", "true");
    }

    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS");
    res.header(
      "Access-Control-Allow-Headers",
      "Content-Type, Authorization, X-Session-Token, X-Vault-Session",
    );

    // Handle preflight requests
    if (req.method === "OPTIONS") {
      return res.sendStatus(200);
    }

    next();
  };
}

/**
 * HTTPS redirect middleware for production
 * Redirects HTTP requests to HTTPS in production
 * @returns {Function} Express middleware
 */
export function httpsRedirect() {
  return (req, res, next) => {
    // Skip in development
    if (process.env.NODE_ENV !== "production") {
      return next();
    }

    // Check various headers that indicate HTTPS
    const isSecure =
      req.secure ||
      req.headers["x-forwarded-proto"] === "https" ||
      req.headers["x-forwarded-ssl"] === "on";

    if (!isSecure) {
      const host = req.headers.host || req.hostname;
      return res.redirect(301, `https://${host}${req.url}`);
    }

    next();
  };
}

/**
 * Request body size limit configuration
 * Returns options object for express.json() and express.urlencoded()
 * @param {string} [limit] - Size limit (e.g., "100kb")
 * @returns {{ json: Object, urlencoded: Object }} Configuration objects
 */
export function bodyLimitConfig(limit) {
  const bodyLimit = limit || process.env.REQUEST_BODY_LIMIT || "100kb";

  return {
    json: {
      limit: bodyLimit,
    },
    urlencoded: {
      extended: true,
      limit: bodyLimit,
    },
  };
}

export default {
  createSecurityHeaders,
  apiSecurityHeaders,
  cspReportHandler,
  corsMiddleware,
  httpsRedirect,
  bodyLimitConfig,
};
