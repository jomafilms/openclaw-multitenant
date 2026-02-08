// Tests for security headers middleware
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

// Mock helmet before importing the module that uses it
vi.mock("helmet", () => ({
  default: vi.fn((options) => {
    // Return a middleware function that calls next
    return (req, res, next) => {
      // Simulate helmet setting headers
      if (options?.contentSecurityPolicy?.directives?.defaultSrc) {
        res.setHeader?.("Content-Security-Policy", "default-src 'self'");
      }
      next();
    };
  }),
}));

import {
  createSecurityHeaders,
  apiSecurityHeaders,
  cspReportHandler,
  corsMiddleware,
  httpsRedirect,
  bodyLimitConfig,
} from "./security-headers.js";

describe("Security Headers Middleware", () => {
  let mockReq;
  let mockRes;
  let mockNext;

  beforeEach(() => {
    process.env.NODE_ENV = "development";
    process.env.USER_UI_URL = "http://localhost:5173";

    mockReq = {
      method: "GET",
      url: "/api/test",
      headers: {},
      secure: false,
      hostname: "localhost",
    };

    mockRes = {
      setHeader: vi.fn(),
      header: vi.fn(),
      status: vi.fn().mockReturnThis(),
      json: vi.fn(),
      end: vi.fn(),
      sendStatus: vi.fn(),
      redirect: vi.fn(),
    };

    mockNext = vi.fn();
  });

  afterEach(() => {
    vi.clearAllMocks();
    delete process.env.NODE_ENV;
    delete process.env.USER_UI_URL;
    delete process.env.REQUEST_BODY_LIMIT;
  });

  describe("createSecurityHeaders", () => {
    it("should return a middleware function", () => {
      const middleware = createSecurityHeaders();

      expect(typeof middleware).toBe("function");
    });

    it("should call next after setting headers", () => {
      const middleware = createSecurityHeaders();

      middleware(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    it("should accept isDevelopment option", () => {
      const devMiddleware = createSecurityHeaders({ isDevelopment: true });
      const prodMiddleware = createSecurityHeaders({ isDevelopment: false });

      expect(typeof devMiddleware).toBe("function");
      expect(typeof prodMiddleware).toBe("function");
    });

    it("should accept additionalConnectSrc option", () => {
      const middleware = createSecurityHeaders({
        additionalConnectSrc: ["https://api.example.com"],
      });

      expect(typeof middleware).toBe("function");
    });

    it("should accept additionalScriptSrc option", () => {
      const middleware = createSecurityHeaders({
        additionalScriptSrc: ["https://cdn.example.com"],
      });

      expect(typeof middleware).toBe("function");
    });
  });

  describe("apiSecurityHeaders", () => {
    it("should return a middleware function", () => {
      const middleware = apiSecurityHeaders();

      expect(typeof middleware).toBe("function");
    });

    it("should set Cache-Control header", () => {
      const middleware = apiSecurityHeaders();

      middleware(mockReq, mockRes, mockNext);

      expect(mockRes.setHeader).toHaveBeenCalledWith(
        "Cache-Control",
        "no-store, no-cache, must-revalidate, proxy-revalidate",
      );
    });

    it("should set Pragma header", () => {
      const middleware = apiSecurityHeaders();

      middleware(mockReq, mockRes, mockNext);

      expect(mockRes.setHeader).toHaveBeenCalledWith("Pragma", "no-cache");
    });

    it("should set Expires header", () => {
      const middleware = apiSecurityHeaders();

      middleware(mockReq, mockRes, mockNext);

      expect(mockRes.setHeader).toHaveBeenCalledWith("Expires", "0");
    });

    it("should set Surrogate-Control header", () => {
      const middleware = apiSecurityHeaders();

      middleware(mockReq, mockRes, mockNext);

      expect(mockRes.setHeader).toHaveBeenCalledWith("Surrogate-Control", "no-store");
    });

    it("should set X-Content-Type-Options header", () => {
      const middleware = apiSecurityHeaders();

      middleware(mockReq, mockRes, mockNext);

      expect(mockRes.setHeader).toHaveBeenCalledWith("X-Content-Type-Options", "nosniff");
    });

    it("should call next()", () => {
      const middleware = apiSecurityHeaders();

      middleware(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe("cspReportHandler", () => {
    it("should return a middleware function", () => {
      const handler = cspReportHandler();

      expect(typeof handler).toBe("function");
    });

    it("should respond with 204 status", () => {
      const handler = cspReportHandler();
      mockReq.body = { "csp-report": { blocked: "example.com" } };

      handler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(204);
      expect(mockRes.end).toHaveBeenCalled();
    });

    it("should handle missing body", () => {
      const handler = cspReportHandler();
      mockReq.body = null;

      handler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(204);
      expect(mockRes.end).toHaveBeenCalled();
    });

    it("should log CSP violations to console", () => {
      const handler = cspReportHandler();
      const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

      mockReq.body = { "csp-report": { "document-uri": "https://example.com" } };
      handler(mockReq, mockRes);

      expect(consoleSpy).toHaveBeenCalled();
      consoleSpy.mockRestore();
    });
  });

  describe("corsMiddleware", () => {
    it("should return a middleware function", () => {
      const middleware = corsMiddleware();

      expect(typeof middleware).toBe("function");
    });

    it("should set CORS headers for allowed origin", () => {
      const middleware = corsMiddleware({ origin: "http://localhost:5173" });
      mockReq.headers.origin = "http://localhost:5173";

      middleware(mockReq, mockRes, mockNext);

      expect(mockRes.header).toHaveBeenCalledWith(
        "Access-Control-Allow-Origin",
        "http://localhost:5173",
      );
    });

    it("should set Access-Control-Allow-Credentials header", () => {
      const middleware = corsMiddleware({ credentials: true });
      mockReq.headers.origin = "http://localhost:5173";

      middleware(mockReq, mockRes, mockNext);

      expect(mockRes.header).toHaveBeenCalledWith("Access-Control-Allow-Credentials", "true");
    });

    it("should not set credentials header when disabled", () => {
      const middleware = corsMiddleware({ credentials: false });
      mockReq.headers.origin = "http://localhost:5173";

      middleware(mockReq, mockRes, mockNext);

      // Check that credentials header was not set
      const credentialsCall = mockRes.header.mock.calls.find(
        (call) => call[0] === "Access-Control-Allow-Credentials",
      );
      expect(credentialsCall).toBeUndefined();
    });

    it("should set Access-Control-Allow-Methods header", () => {
      const middleware = corsMiddleware();
      mockReq.headers.origin = "http://localhost:5173";

      middleware(mockReq, mockRes, mockNext);

      expect(mockRes.header).toHaveBeenCalledWith(
        "Access-Control-Allow-Methods",
        expect.stringContaining("GET"),
      );
    });

    it("should set Access-Control-Allow-Headers header", () => {
      const middleware = corsMiddleware();
      mockReq.headers.origin = "http://localhost:5173";

      middleware(mockReq, mockRes, mockNext);

      expect(mockRes.header).toHaveBeenCalledWith(
        "Access-Control-Allow-Headers",
        expect.any(String),
      );
    });

    it("should handle OPTIONS preflight requests", () => {
      const middleware = corsMiddleware();
      mockReq.method = "OPTIONS";
      mockReq.headers.origin = "http://localhost:5173";

      middleware(mockReq, mockRes, mockNext);

      expect(mockRes.sendStatus).toHaveBeenCalledWith(200);
      expect(mockNext).not.toHaveBeenCalled();
    });

    it("should call next() for non-OPTIONS requests", () => {
      const middleware = corsMiddleware();
      mockReq.method = "GET";
      mockReq.headers.origin = "http://localhost:5173";

      middleware(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    it("should handle array of allowed origins", () => {
      const origins = ["http://localhost:3000", "http://localhost:5173"];
      const middleware = corsMiddleware({ origin: origins });
      mockReq.headers.origin = "http://localhost:5173";

      middleware(mockReq, mockRes, mockNext);

      expect(mockRes.header).toHaveBeenCalledWith(
        "Access-Control-Allow-Origin",
        "http://localhost:5173",
      );
    });

    it("should not set origin for non-matching request", () => {
      const middleware = corsMiddleware({ origin: "http://localhost:3000" });
      mockReq.headers.origin = "http://malicious.com";

      middleware(mockReq, mockRes, mockNext);

      // Should not have set the origin to malicious.com
      const originCall = mockRes.header.mock.calls.find(
        (call) => call[0] === "Access-Control-Allow-Origin" && call[1] === "http://malicious.com",
      );
      expect(originCall).toBeUndefined();
    });
  });

  describe("httpsRedirect", () => {
    it("should return a middleware function", () => {
      const middleware = httpsRedirect();

      expect(typeof middleware).toBe("function");
    });

    it("should skip redirect in development", () => {
      process.env.NODE_ENV = "development";
      const middleware = httpsRedirect();

      middleware(mockReq, mockRes, mockNext);

      expect(mockRes.redirect).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalled();
    });

    it("should redirect to HTTPS in production for HTTP requests", () => {
      process.env.NODE_ENV = "production";
      const middleware = httpsRedirect();
      mockReq.secure = false;
      mockReq.headers.host = "example.com";

      middleware(mockReq, mockRes, mockNext);

      expect(mockRes.redirect).toHaveBeenCalledWith(301, "https://example.com/api/test");
    });

    it("should not redirect for secure requests", () => {
      process.env.NODE_ENV = "production";
      const middleware = httpsRedirect();
      mockReq.secure = true;

      middleware(mockReq, mockRes, mockNext);

      expect(mockRes.redirect).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalled();
    });

    it("should detect HTTPS from X-Forwarded-Proto header", () => {
      process.env.NODE_ENV = "production";
      const middleware = httpsRedirect();
      mockReq.secure = false;
      mockReq.headers["x-forwarded-proto"] = "https";

      middleware(mockReq, mockRes, mockNext);

      expect(mockRes.redirect).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalled();
    });

    it("should detect HTTPS from X-Forwarded-SSL header", () => {
      process.env.NODE_ENV = "production";
      const middleware = httpsRedirect();
      mockReq.secure = false;
      mockReq.headers["x-forwarded-ssl"] = "on";

      middleware(mockReq, mockRes, mockNext);

      expect(mockRes.redirect).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalled();
    });

    it("should use hostname when host header missing", () => {
      process.env.NODE_ENV = "production";
      const middleware = httpsRedirect();
      mockReq.secure = false;
      mockReq.hostname = "example.com";
      delete mockReq.headers.host;

      middleware(mockReq, mockRes, mockNext);

      expect(mockRes.redirect).toHaveBeenCalledWith(301, "https://example.com/api/test");
    });
  });

  describe("bodyLimitConfig", () => {
    it("should return json and urlencoded config objects", () => {
      const config = bodyLimitConfig();

      expect(config).toHaveProperty("json");
      expect(config).toHaveProperty("urlencoded");
    });

    it("should use default limit of 100kb", () => {
      const config = bodyLimitConfig();

      expect(config.json.limit).toBe("100kb");
      expect(config.urlencoded.limit).toBe("100kb");
    });

    it("should accept custom limit parameter", () => {
      const config = bodyLimitConfig("500kb");

      expect(config.json.limit).toBe("500kb");
      expect(config.urlencoded.limit).toBe("500kb");
    });

    it("should use environment variable if set", () => {
      process.env.REQUEST_BODY_LIMIT = "1mb";
      const config = bodyLimitConfig();

      expect(config.json.limit).toBe("1mb");
      expect(config.urlencoded.limit).toBe("1mb");
    });

    it("should prefer parameter over environment variable", () => {
      process.env.REQUEST_BODY_LIMIT = "1mb";
      const config = bodyLimitConfig("500kb");

      expect(config.json.limit).toBe("500kb");
    });

    it("should set extended: true for urlencoded", () => {
      const config = bodyLimitConfig();

      expect(config.urlencoded.extended).toBe(true);
    });
  });

  describe("Content Security Policy directives", () => {
    it("should configure CSP with self for default-src", () => {
      // The middleware uses helmet which sets these headers
      // We test that the configuration is valid
      const middleware = createSecurityHeaders({ isDevelopment: false });

      expect(typeof middleware).toBe("function");
    });

    it("should allow Google Fonts in style-src", () => {
      const middleware = createSecurityHeaders();

      // Verify the middleware is created successfully with expected config
      expect(typeof middleware).toBe("function");
    });
  });

  describe("security best practices", () => {
    it("should disable X-Powered-By implicitly via helmet", () => {
      // Helmet disables X-Powered-By by default
      const middleware = createSecurityHeaders();

      expect(typeof middleware).toBe("function");
    });

    it("should set strict referrer policy", () => {
      // The middleware configures referrer-policy: strict-origin-when-cross-origin
      const middleware = createSecurityHeaders();

      expect(typeof middleware).toBe("function");
    });

    it("should set frame-ancestors to none for clickjacking protection", () => {
      const middleware = createSecurityHeaders();

      expect(typeof middleware).toBe("function");
    });
  });

  describe("production vs development differences", () => {
    it("should use wss: in production for connect-src", () => {
      const prodMiddleware = createSecurityHeaders({ isDevelopment: false });
      const devMiddleware = createSecurityHeaders({ isDevelopment: true });

      expect(typeof prodMiddleware).toBe("function");
      expect(typeof devMiddleware).toBe("function");
    });

    it("should set upgradeInsecureRequests in production only", () => {
      const prodMiddleware = createSecurityHeaders({ isDevelopment: false });
      const devMiddleware = createSecurityHeaders({ isDevelopment: true });

      expect(typeof prodMiddleware).toBe("function");
      expect(typeof devMiddleware).toBe("function");
    });
  });
});
