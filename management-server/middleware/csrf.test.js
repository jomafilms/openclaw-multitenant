// Tests for CSRF middleware
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { generateCsrfToken } from "../lib/csrf.js";
import { csrfProtection, attachCsrfToken, injectCsrfToken } from "./csrf.js";

// Mock the audit module
vi.mock("../db/index.js", () => ({
  audit: {
    log: vi.fn().mockResolvedValue(undefined),
  },
}));

describe("CSRF Middleware", () => {
  let mockReq;
  let mockRes;
  let mockNext;

  beforeEach(() => {
    // Save original env
    process.env.APP_URL = "http://localhost:3000";
    process.env.NODE_ENV = "development";

    mockReq = {
      method: "POST",
      path: "/api/test",
      headers: {},
      body: {},
      query: {},
      sessionToken: "test-session-token-12345",
      ip: "127.0.0.1",
      user: null,
    };

    mockRes = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
      cookie: vi.fn(),
      setHeader: vi.fn(),
      locals: {},
    };

    mockNext = vi.fn();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe("csrfProtection", () => {
    describe("safe methods", () => {
      it("should allow GET requests without CSRF token", () => {
        mockReq.method = "GET";

        csrfProtection(mockReq, mockRes, mockNext);

        expect(mockNext).toHaveBeenCalled();
        expect(mockRes.status).not.toHaveBeenCalled();
      });

      it("should allow HEAD requests without CSRF token", () => {
        mockReq.method = "HEAD";

        csrfProtection(mockReq, mockRes, mockNext);

        expect(mockNext).toHaveBeenCalled();
      });

      it("should allow OPTIONS requests without CSRF token", () => {
        mockReq.method = "OPTIONS";

        csrfProtection(mockReq, mockRes, mockNext);

        expect(mockNext).toHaveBeenCalled();
      });
    });

    describe("protected methods", () => {
      it("should validate CSRF token for POST requests", () => {
        mockReq.method = "POST";
        const token = generateCsrfToken(mockReq.sessionToken);
        mockReq.headers["x-csrf-token"] = token;
        mockReq.headers.origin = "http://localhost:3000";

        csrfProtection(mockReq, mockRes, mockNext);

        expect(mockNext).toHaveBeenCalled();
        expect(mockRes.status).not.toHaveBeenCalled();
      });

      it("should validate CSRF token for PUT requests", () => {
        mockReq.method = "PUT";
        const token = generateCsrfToken(mockReq.sessionToken);
        mockReq.headers["x-csrf-token"] = token;
        mockReq.headers.origin = "http://localhost:3000";

        csrfProtection(mockReq, mockRes, mockNext);

        expect(mockNext).toHaveBeenCalled();
      });

      it("should validate CSRF token for PATCH requests", () => {
        mockReq.method = "PATCH";
        const token = generateCsrfToken(mockReq.sessionToken);
        mockReq.headers["x-csrf-token"] = token;
        mockReq.headers.origin = "http://localhost:3000";

        csrfProtection(mockReq, mockRes, mockNext);

        expect(mockNext).toHaveBeenCalled();
      });

      it("should validate CSRF token for DELETE requests", () => {
        mockReq.method = "DELETE";
        const token = generateCsrfToken(mockReq.sessionToken);
        mockReq.headers["x-csrf-token"] = token;
        mockReq.headers.origin = "http://localhost:3000";

        csrfProtection(mockReq, mockRes, mockNext);

        expect(mockNext).toHaveBeenCalled();
      });
    });

    describe("exempt paths", () => {
      it("should skip CSRF for webhook paths", () => {
        mockReq.path = "/api/webhooks/stripe";

        csrfProtection(mockReq, mockRes, mockNext);

        expect(mockNext).toHaveBeenCalled();
      });

      it("should skip CSRF for callback paths", () => {
        mockReq.path = "/api/callbacks/oauth";

        csrfProtection(mockReq, mockRes, mockNext);

        expect(mockNext).toHaveBeenCalled();
      });

      it("should skip CSRF for health check", () => {
        mockReq.path = "/health";

        csrfProtection(mockReq, mockRes, mockNext);

        expect(mockNext).toHaveBeenCalled();
      });

      it("should skip CSRF for API health check", () => {
        mockReq.path = "/api/health";

        csrfProtection(mockReq, mockRes, mockNext);

        expect(mockNext).toHaveBeenCalled();
      });
    });

    describe("API key authentication", () => {
      it("should skip CSRF when X-API-Key header is present", () => {
        mockReq.headers["x-api-key"] = "some-api-key";

        csrfProtection(mockReq, mockRes, mockNext);

        expect(mockNext).toHaveBeenCalled();
      });
    });

    describe("Bearer token authentication", () => {
      it("should skip CSRF when Bearer token is present", () => {
        mockReq.headers.authorization = "Bearer some-jwt-token";

        csrfProtection(mockReq, mockRes, mockNext);

        expect(mockNext).toHaveBeenCalled();
      });

      it("should not skip for non-Bearer auth headers", () => {
        mockReq.headers.authorization = "Basic base64credentials";
        mockReq.headers.origin = "http://malicious.com";

        csrfProtection(mockReq, mockRes, mockNext);

        expect(mockRes.status).toHaveBeenCalledWith(403);
      });
    });

    describe("origin validation", () => {
      it("should allow same-origin requests without Origin header", () => {
        // No origin or referer = same-origin
        const token = generateCsrfToken(mockReq.sessionToken);
        mockReq.headers["x-csrf-token"] = token;

        csrfProtection(mockReq, mockRes, mockNext);

        expect(mockNext).toHaveBeenCalled();
      });

      it("should allow requests from allowed origins", () => {
        const token = generateCsrfToken(mockReq.sessionToken);
        mockReq.headers["x-csrf-token"] = token;
        mockReq.headers.origin = "http://localhost:3000";

        csrfProtection(mockReq, mockRes, mockNext);

        expect(mockNext).toHaveBeenCalled();
      });

      it("should reject requests from disallowed origins", () => {
        mockReq.headers.origin = "http://malicious.com";

        csrfProtection(mockReq, mockRes, mockNext);

        expect(mockRes.status).toHaveBeenCalledWith(403);
        expect(mockRes.json).toHaveBeenCalledWith(
          expect.objectContaining({
            code: "CSRF_ORIGIN_INVALID",
          }),
        );
      });

      it("should validate Referer header when Origin is missing", () => {
        const token = generateCsrfToken(mockReq.sessionToken);
        mockReq.headers["x-csrf-token"] = token;
        mockReq.headers.referer = "http://localhost:3000/some/path";

        csrfProtection(mockReq, mockRes, mockNext);

        expect(mockNext).toHaveBeenCalled();
      });

      it("should reject invalid Referer origins", () => {
        mockReq.headers.referer = "http://malicious.com/attack";

        csrfProtection(mockReq, mockRes, mockNext);

        expect(mockRes.status).toHaveBeenCalledWith(403);
      });
    });

    describe("CSRF token validation", () => {
      it("should reject missing CSRF token", () => {
        mockReq.headers.origin = "http://localhost:3000";
        // No CSRF token

        csrfProtection(mockReq, mockRes, mockNext);

        expect(mockRes.status).toHaveBeenCalledWith(403);
        expect(mockRes.json).toHaveBeenCalledWith(
          expect.objectContaining({
            code: "CSRF_INVALID",
          }),
        );
      });

      it("should reject invalid CSRF token", () => {
        mockReq.headers.origin = "http://localhost:3000";
        mockReq.headers["x-csrf-token"] = "invalid-token";

        csrfProtection(mockReq, mockRes, mockNext);

        expect(mockRes.status).toHaveBeenCalledWith(403);
      });

      it("should reject CSRF token from different session", () => {
        mockReq.headers.origin = "http://localhost:3000";
        const tokenForDifferentSession = generateCsrfToken("different-session");
        mockReq.headers["x-csrf-token"] = tokenForDifferentSession;

        csrfProtection(mockReq, mockRes, mockNext);

        expect(mockRes.status).toHaveBeenCalledWith(403);
      });

      it("should accept CSRF token from X-XSRF-Token header", () => {
        const token = generateCsrfToken(mockReq.sessionToken);
        mockReq.headers["x-xsrf-token"] = token;
        mockReq.headers.origin = "http://localhost:3000";

        csrfProtection(mockReq, mockRes, mockNext);

        expect(mockNext).toHaveBeenCalled();
      });

      it("should accept CSRF token from body", () => {
        const token = generateCsrfToken(mockReq.sessionToken);
        mockReq.body._csrf = token;
        mockReq.headers.origin = "http://localhost:3000";

        csrfProtection(mockReq, mockRes, mockNext);

        expect(mockNext).toHaveBeenCalled();
      });
    });

    describe("no session", () => {
      it("should skip CSRF validation when no session", () => {
        mockReq.sessionToken = null;
        mockReq.headers.origin = "http://localhost:3000";

        csrfProtection(mockReq, mockRes, mockNext);

        // Should pass without CSRF token since no session
        expect(mockNext).toHaveBeenCalled();
      });
    });
  });

  describe("attachCsrfToken", () => {
    it("should set CSRF token cookie when session exists", () => {
      mockReq.sessionToken = "test-session";

      attachCsrfToken(mockReq, mockRes, mockNext);

      expect(mockRes.cookie).toHaveBeenCalledWith(
        "XSRF-TOKEN",
        expect.any(String),
        expect.objectContaining({
          httpOnly: false, // Should be readable by JS
          sameSite: "strict",
          path: "/",
        }),
      );
    });

    it("should set X-CSRF-Token header when session exists", () => {
      mockReq.sessionToken = "test-session";

      attachCsrfToken(mockReq, mockRes, mockNext);

      expect(mockRes.setHeader).toHaveBeenCalledWith("X-CSRF-Token", expect.any(String));
    });

    it("should attach token to request for templates", () => {
      mockReq.sessionToken = "test-session";

      attachCsrfToken(mockReq, mockRes, mockNext);

      expect(mockReq.csrfToken).toBeDefined();
      expect(typeof mockReq.csrfToken).toBe("string");
    });

    it("should not set token when no session", () => {
      mockReq.sessionToken = null;

      attachCsrfToken(mockReq, mockRes, mockNext);

      expect(mockRes.cookie).not.toHaveBeenCalled();
      expect(mockRes.setHeader).not.toHaveBeenCalled();
    });

    it("should call next()", () => {
      attachCsrfToken(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe("injectCsrfToken", () => {
    it("should inject token into res.locals when present", () => {
      mockReq.csrfToken = "test-csrf-token";

      injectCsrfToken(mockReq, mockRes, mockNext);

      expect(mockRes.locals.csrfToken).toBe("test-csrf-token");
    });

    it("should not inject token when not present", () => {
      mockReq.csrfToken = undefined;

      injectCsrfToken(mockReq, mockRes, mockNext);

      expect(mockRes.locals.csrfToken).toBeUndefined();
    });

    it("should call next()", () => {
      injectCsrfToken(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe("development mode origins", () => {
    it("should allow localhost:5173 in development", () => {
      process.env.NODE_ENV = "development";
      const token = generateCsrfToken(mockReq.sessionToken);
      mockReq.headers["x-csrf-token"] = token;
      mockReq.headers.origin = "http://localhost:5173";

      csrfProtection(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    it("should allow 127.0.0.1:3000 in development", () => {
      process.env.NODE_ENV = "development";
      const token = generateCsrfToken(mockReq.sessionToken);
      mockReq.headers["x-csrf-token"] = token;
      mockReq.headers.origin = "http://127.0.0.1:3000";

      csrfProtection(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe("security logging", () => {
    it("should log CSRF failures", async () => {
      const { audit } = await import("../db/index.js");
      mockReq.headers.origin = "http://malicious.com";

      csrfProtection(mockReq, mockRes, mockNext);

      // Wait for async logging
      await new Promise((resolve) => setTimeout(resolve, 10));

      expect(mockRes.status).toHaveBeenCalledWith(403);
    });
  });
});
