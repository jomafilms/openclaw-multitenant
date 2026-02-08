// Tests for rate limiting middleware
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  createRateLimiter,
  createTenantRateLimiter,
  getClientIp,
  getRateLimitStatus,
  resetRateLimit,
  getAllRateLimitEntries,
  getTenantRateLimitKey,
  getTenantRateLimit,
  DEFAULT_PLAN_RATE_LIMITS,
  tenantApiLimiter,
  tenantSensitiveLimiter,
  inviteAcceptLimiter,
  inviteDeclineLimiter,
  inviteCreateLimiter,
  shareCreateLimiter,
  shareDeleteLimiter,
} from "./rate-limit.js";

// Mock the redis module
vi.mock("./redis.js", () => ({
  getRedisClient: vi.fn(),
  isRedisConnected: vi.fn(() => false),
}));

import { getRedisClient, isRedisConnected } from "./redis.js";

// Helper to create a mock request with trust proxy enabled
const createTrustedReq = (overrides = {}) => ({
  headers: {},
  app: { get: (key) => key === "trust proxy" },
  ...overrides,
});

describe("rate-limit", () => {
  describe("getClientIp", () => {
    it("should extract IP from X-Forwarded-For header", () => {
      const req = createTrustedReq({
        headers: { "x-forwarded-for": "1.2.3.4, 5.6.7.8" },
        ip: "1.2.3.4", // Express sets req.ip from X-Forwarded-For when trust proxy is enabled
      });
      expect(getClientIp(req)).toBe("1.2.3.4");
    });

    it("should extract IP from X-Real-IP header", () => {
      const req = createTrustedReq({
        headers: { "x-real-ip": "10.0.0.1" },
        ip: "10.0.0.1", // Express would set this
      });
      expect(getClientIp(req)).toBe("10.0.0.1");
    });

    it("should use req.ip as fallback", () => {
      const req = createTrustedReq({
        headers: {},
        ip: "192.168.1.1",
      });
      expect(getClientIp(req)).toBe("192.168.1.1");
    });

    it("should use socket.remoteAddress as last resort", () => {
      const req = {
        headers: {},
        socket: { remoteAddress: "::1" },
      };
      expect(getClientIp(req)).toBe("::1");
    });

    it("should return unknown if no IP found", () => {
      const req = { headers: {} };
      expect(getClientIp(req)).toBe("unknown");
    });
  });

  describe("createRateLimiter", () => {
    let mockReq;
    let mockRes;
    let mockNext;

    beforeEach(() => {
      mockReq = {
        headers: {},
        ip: "1.2.3.4",
        app: { get: (key) => key === "trust proxy" },
      };
      mockRes = {
        setHeader: vi.fn(),
        status: vi.fn().mockReturnThis(),
        json: vi.fn(),
      };
      mockNext = vi.fn();
    });

    it("should allow requests under the limit", async () => {
      const limiter = createRateLimiter({
        name: "test-allow",
        windowMs: 60000,
        maxRequests: 5,
      });

      await limiter(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(mockRes.status).not.toHaveBeenCalled();
      expect(mockRes.setHeader).toHaveBeenCalledWith("RateLimit-Limit", 5);
      // Remaining is calculated before incrementing, so first request shows 5 remaining
      expect(mockRes.setHeader).toHaveBeenCalledWith("RateLimit-Remaining", 5);
    });

    it("should block requests over the limit", async () => {
      const limiter = createRateLimiter({
        name: "test-block",
        windowMs: 60000,
        maxRequests: 2,
      });

      // First two requests should pass
      await limiter(mockReq, mockRes, mockNext);
      await limiter(mockReq, mockRes, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(2);

      // Reset mocks
      mockNext.mockClear();
      mockRes.status.mockClear();
      mockRes.json.mockClear();

      // Third request should be blocked
      await limiter(mockReq, mockRes, mockNext);

      expect(mockNext).not.toHaveBeenCalled();
      expect(mockRes.status).toHaveBeenCalledWith(429);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.any(String),
          code: "RATE_LIMIT_EXCEEDED",
          retryAfter: expect.any(Number),
        }),
      );
    });

    it("should set Retry-After header when blocked", async () => {
      const limiter = createRateLimiter({
        name: "test-retry-after",
        windowMs: 60000,
        maxRequests: 1,
      });

      await limiter(mockReq, mockRes, mockNext);
      mockRes.setHeader.mockClear();

      await limiter(mockReq, mockRes, mockNext);

      expect(mockRes.setHeader).toHaveBeenCalledWith("Retry-After", expect.any(Number));
    });

    it("should use custom key generator", async () => {
      const customKey = "user-123";
      const limiter = createRateLimiter({
        name: "test-custom-key",
        windowMs: 60000,
        maxRequests: 2,
        keyGenerator: () => customKey,
      });

      await limiter(mockReq, mockRes, mockNext);

      const status = getRateLimitStatus("test-custom-key", customKey);
      expect(status).not.toBeNull();
      expect(status.count).toBe(1);
    });

    it("should use custom error message", async () => {
      const customMessage = "Custom rate limit message";
      const limiter = createRateLimiter({
        name: "test-custom-message",
        windowMs: 60000,
        maxRequests: 1,
        message: customMessage,
      });

      await limiter(mockReq, mockRes, mockNext);
      await limiter(mockReq, mockRes, mockNext);

      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: customMessage,
        }),
      );
    });

    it("should call onLimitReached callback when limit exceeded", async () => {
      const onLimitReached = vi.fn();
      const limiter = createRateLimiter({
        name: "test-callback",
        windowMs: 60000,
        maxRequests: 1,
        onLimitReached,
      });

      await limiter(mockReq, mockRes, mockNext);
      expect(onLimitReached).not.toHaveBeenCalled();

      await limiter(mockReq, mockRes, mockNext);
      expect(onLimitReached).toHaveBeenCalledWith(mockReq, "1.2.3.4");
    });

    it("should reset window after expiry", async () => {
      vi.useFakeTimers();

      const limiter = createRateLimiter({
        name: "test-window-reset",
        windowMs: 1000,
        maxRequests: 1,
      });

      await limiter(mockReq, mockRes, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(1);

      mockNext.mockClear();
      await limiter(mockReq, mockRes, mockNext);
      expect(mockRes.status).toHaveBeenCalledWith(429);

      // Advance time past window
      vi.advanceTimersByTime(1100);

      mockNext.mockClear();
      mockRes.status.mockClear();
      await limiter(mockReq, mockRes, mockNext);
      expect(mockNext).toHaveBeenCalled();
      expect(mockRes.status).not.toHaveBeenCalled();

      vi.useRealTimers();
    });

    it("should skip failed requests when configured", async () => {
      const limiter = createRateLimiter({
        name: "test-skip-failed",
        windowMs: 60000,
        maxRequests: 2,
        skipFailedRequests: true,
      });

      // Simulate a failed request
      let endHandler;
      mockRes.end = function (...args) {
        if (endHandler) {
          endHandler.apply(this, args);
        }
      };

      await limiter(mockReq, mockRes, mockNext);

      // Mark response as failed
      mockRes.statusCode = 401;
      mockRes.end();

      // Status should show count decremented
      const status = getRateLimitStatus("test-skip-failed", "1.2.3.4");
      expect(status.count).toBe(0);
    });

    it("should track different IPs separately", async () => {
      const limiter = createRateLimiter({
        name: "test-separate-ips",
        windowMs: 60000,
        maxRequests: 2,
      });

      const req1 = { ...mockReq, ip: "1.1.1.1" };
      const req2 = { ...mockReq, ip: "2.2.2.2" };

      await limiter(req1, mockRes, mockNext);
      await limiter(req1, mockRes, mockNext);
      await limiter(req2, mockRes, mockNext);

      const status1 = getRateLimitStatus("test-separate-ips", "1.1.1.1");
      const status2 = getRateLimitStatus("test-separate-ips", "2.2.2.2");

      expect(status1.count).toBe(2);
      expect(status2.count).toBe(1);
    });
  });

  describe("utility functions", () => {
    it("should get rate limit status", async () => {
      const limiter = createRateLimiter({
        name: "test-get-status",
        windowMs: 60000,
        maxRequests: 5,
      });

      const mockReq = createTrustedReq({ ip: "5.5.5.5" });
      const mockRes = { setHeader: vi.fn() };
      const mockNext = vi.fn();

      await limiter(mockReq, mockRes, mockNext);
      await limiter(mockReq, mockRes, mockNext);

      const status = getRateLimitStatus("test-get-status", "5.5.5.5");
      expect(status).toEqual({
        count: 2,
        windowStart: expect.any(Number),
      });
    });

    it("should return null for non-existent entries", () => {
      const status = getRateLimitStatus("nonexistent-limiter", "some-key");
      expect(status).toBeNull();
    });

    it("should reset rate limit for a key", async () => {
      const limiter = createRateLimiter({
        name: "test-reset",
        windowMs: 60000,
        maxRequests: 5,
      });

      const mockReq = createTrustedReq({ ip: "6.6.6.6" });
      const mockRes = { setHeader: vi.fn() };
      const mockNext = vi.fn();

      await limiter(mockReq, mockRes, mockNext);
      await limiter(mockReq, mockRes, mockNext);

      expect(getRateLimitStatus("test-reset", "6.6.6.6").count).toBe(2);

      const result = resetRateLimit("test-reset", "6.6.6.6");
      expect(result).toBe(true);
      expect(getRateLimitStatus("test-reset", "6.6.6.6")).toBeNull();
    });

    it("should list all rate limit entries", async () => {
      const limiter = createRateLimiter({
        name: "test-list-entries",
        windowMs: 60000,
        maxRequests: 10,
      });

      const mockRes = { setHeader: vi.fn() };
      const mockNext = vi.fn();

      await limiter(createTrustedReq({ ip: "7.7.7.7" }), mockRes, mockNext);
      await limiter(createTrustedReq({ ip: "8.8.8.8" }), mockRes, mockNext);
      await limiter(createTrustedReq({ ip: "9.9.9.9" }), mockRes, mockNext);

      const entries = getAllRateLimitEntries("test-list-entries");
      expect(entries).toHaveLength(3);
      expect(entries.map((e) => e.key).toSorted()).toEqual(["7.7.7.7", "8.8.8.8", "9.9.9.9"]);
    });
  });

  describe("error handling", () => {
    it("should fail open on error", async () => {
      const limiter = createRateLimiter({
        name: "test-error-handling",
        windowMs: 60000,
        maxRequests: 5,
        keyGenerator: () => {
          throw new Error("Key generation failed");
        },
      });

      const mockReq = { headers: {}, ip: "1.2.3.4" };
      const mockRes = { setHeader: vi.fn() };
      const mockNext = vi.fn();

      // Should not throw, should call next
      await limiter(mockReq, mockRes, mockNext);
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe("redis integration", () => {
    let mockRedis;

    beforeEach(() => {
      mockRedis = {
        get: vi.fn(),
        set: vi.fn(),
      };
      vi.clearAllMocks();
    });

    it("should use Redis when connected", async () => {
      isRedisConnected.mockReturnValue(true);
      getRedisClient.mockReturnValue(mockRedis);
      mockRedis.get.mockResolvedValue(null);
      mockRedis.set.mockResolvedValue("OK");

      const limiter = createRateLimiter({
        name: "test-redis-connected",
        windowMs: 60000,
        maxRequests: 5,
      });

      const mockReq = { headers: {}, ip: "1.2.3.4" };
      const mockRes = { setHeader: vi.fn() };
      const mockNext = vi.fn();

      await limiter(mockReq, mockRes, mockNext);

      expect(mockRedis.get).toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalled();
    });

    it("should fall back to memory when Redis unavailable", async () => {
      isRedisConnected.mockReturnValue(false);

      const limiter = createRateLimiter({
        name: "test-redis-fallback",
        windowMs: 60000,
        maxRequests: 5,
      });

      const mockReq = { headers: {}, ip: "1.2.3.4" };
      const mockRes = { setHeader: vi.fn() };
      const mockNext = vi.fn();

      await limiter(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
      // Should not call Redis
      expect(mockRedis.get).not.toHaveBeenCalled();
    });

    it("should fall back to memory when Redis operation fails", async () => {
      isRedisConnected.mockReturnValue(true);
      getRedisClient.mockReturnValue(mockRedis);
      mockRedis.get.mockRejectedValue(new Error("Redis connection error"));

      const limiter = createRateLimiter({
        name: "test-redis-error-fallback",
        windowMs: 60000,
        maxRequests: 5,
      });

      const mockReq = { headers: {}, ip: "1.2.3.4" };
      const mockRes = { setHeader: vi.fn() };
      const mockNext = vi.fn();

      await limiter(mockReq, mockRes, mockNext);

      // Should still call next (fail open with memory fallback)
      expect(mockNext).toHaveBeenCalled();
    });

    it("should enforce rate limit via Redis", async () => {
      isRedisConnected.mockReturnValue(true);
      getRedisClient.mockReturnValue(mockRedis);

      // Return existing entry at the limit
      const windowStart = Date.now();
      mockRedis.get.mockResolvedValue(JSON.stringify({ count: 5, windowStart }));
      mockRedis.set.mockResolvedValue("OK");

      const limiter = createRateLimiter({
        name: "test-redis-limit",
        windowMs: 60000,
        maxRequests: 5,
      });

      const mockReq = { headers: {}, ip: "1.2.3.4" };
      const mockRes = {
        setHeader: vi.fn(),
        status: vi.fn().mockReturnThis(),
        json: vi.fn(),
      };
      const mockNext = vi.fn();

      await limiter(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(429);
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe("new invite/share limiters", () => {
    it("should export inviteAcceptLimiter with correct config", () => {
      expect(inviteAcceptLimiter).toBeDefined();
      expect(typeof inviteAcceptLimiter).toBe("function");
    });

    it("should export inviteDeclineLimiter with correct config", () => {
      expect(inviteDeclineLimiter).toBeDefined();
      expect(typeof inviteDeclineLimiter).toBe("function");
    });

    it("should export inviteCreateLimiter with correct config", () => {
      expect(inviteCreateLimiter).toBeDefined();
      expect(typeof inviteCreateLimiter).toBe("function");
    });

    it("should export shareCreateLimiter with correct config", () => {
      expect(shareCreateLimiter).toBeDefined();
      expect(typeof shareCreateLimiter).toBe("function");
    });

    it("should export shareDeleteLimiter with correct config", () => {
      expect(shareDeleteLimiter).toBeDefined();
      expect(typeof shareDeleteLimiter).toBe("function");
    });

    it("inviteAcceptLimiter should use user ID for key", async () => {
      isRedisConnected.mockReturnValue(false);

      const mockReq = {
        headers: {},
        ip: "1.2.3.4",
        user: { id: "user-123" },
      };
      const mockRes = { setHeader: vi.fn() };
      const mockNext = vi.fn();

      await inviteAcceptLimiter(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
      // Verify status is tracked by user ID
      const status = getRateLimitStatus("invite-accept", "user-123");
      expect(status).not.toBeNull();
    });

    it("shareCreateLimiter should use user ID for key", async () => {
      isRedisConnected.mockReturnValue(false);

      const mockReq = {
        headers: {},
        ip: "5.6.7.8",
        user: { id: "user-456" },
      };
      const mockRes = { setHeader: vi.fn() };
      const mockNext = vi.fn();

      await shareCreateLimiter(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
      // Verify status is tracked by user ID
      const status = getRateLimitStatus("share-create", "user-456");
      expect(status).not.toBeNull();
    });
  });

  describe("tenant-scoped rate limiting", () => {
    describe("getTenantRateLimitKey", () => {
      it("should use tenant ID when available", () => {
        const req = {
          headers: {},
          ip: "1.2.3.4",
          tenant: { id: "tenant-123" },
        };
        expect(getTenantRateLimitKey(req)).toBe("tenant:tenant-123");
      });

      it("should use tenantId when tenant object is not available", () => {
        const req = {
          headers: {},
          ip: "1.2.3.4",
          tenantId: "tenant-456",
        };
        expect(getTenantRateLimitKey(req)).toBe("tenant:tenant-456");
      });

      it("should fall back to IP for unauthenticated requests", () => {
        const req = createTrustedReq({ ip: "1.2.3.4" });
        expect(getTenantRateLimitKey(req)).toBe("ip:1.2.3.4");
      });
    });

    describe("getTenantRateLimit", () => {
      it("should return default plan limits", () => {
        expect(DEFAULT_PLAN_RATE_LIMITS.free).toBe(100);
        expect(DEFAULT_PLAN_RATE_LIMITS.pro).toBe(500);
        expect(DEFAULT_PLAN_RATE_LIMITS.enterprise).toBe(2000);
      });

      it("should use API key override when available", () => {
        const req = {
          apiKey: { rate_limit_override: 1000 },
          subscription: { plan: "free" },
        };
        expect(getTenantRateLimit(req)).toBe(1000);
      });

      it("should return -1 (unlimited) when API key override is 0", () => {
        const req = {
          apiKey: { rate_limit_override: 0 },
          subscription: { plan: "free" },
        };
        expect(getTenantRateLimit(req)).toBe(-1);
      });

      it("should return -1 (unlimited) when API key override is -1", () => {
        const req = {
          apiKey: { rate_limit_override: -1 },
          subscription: { plan: "free" },
        };
        expect(getTenantRateLimit(req)).toBe(-1);
      });

      it("should use plan limit from subscription", () => {
        const req = {
          subscription: { plan: "pro" },
        };
        expect(getTenantRateLimit(req)).toBe(500);
      });

      it("should use plan limit from tenant subscription", () => {
        const req = {
          tenant: { subscription: { plan: "enterprise" } },
        };
        expect(getTenantRateLimit(req)).toBe(2000);
      });

      it("should default to free plan limit", () => {
        const req = {};
        expect(getTenantRateLimit(req)).toBe(100);
      });

      it("should use custom plan limits when provided", () => {
        const req = { subscription: { plan: "pro" } };
        const customLimits = { free: 50, pro: 200, enterprise: 1000 };
        expect(getTenantRateLimit(req, customLimits)).toBe(200);
      });

      it("should use default limit for unknown plans", () => {
        const req = { subscription: { plan: "unknown-plan" } };
        expect(getTenantRateLimit(req, DEFAULT_PLAN_RATE_LIMITS, 50)).toBe(50);
      });
    });

    describe("createTenantRateLimiter", () => {
      let mockReq;
      let mockRes;
      let mockNext;

      beforeEach(() => {
        isRedisConnected.mockReturnValue(false);
        mockReq = {
          headers: {},
          ip: "1.2.3.4",
          tenant: { id: "tenant-test" },
          subscription: { plan: "free" },
        };
        mockRes = {
          setHeader: vi.fn(),
          status: vi.fn().mockReturnThis(),
          json: vi.fn(),
        };
        mockNext = vi.fn();
      });

      it("should allow requests under the plan limit", async () => {
        const limiter = createTenantRateLimiter({
          name: "test-tenant-allow",
          windowMs: 60000,
          planLimits: { free: 5 },
        });

        await limiter(mockReq, mockRes, mockNext);

        expect(mockNext).toHaveBeenCalled();
        expect(mockRes.status).not.toHaveBeenCalled();
      });

      it("should set both standard and X-prefixed headers", async () => {
        const limiter = createTenantRateLimiter({
          name: "test-tenant-headers",
          windowMs: 60000,
          planLimits: { free: 100 },
        });

        await limiter(mockReq, mockRes, mockNext);

        // Standard headers
        expect(mockRes.setHeader).toHaveBeenCalledWith("RateLimit-Limit", 100);
        expect(mockRes.setHeader).toHaveBeenCalledWith("RateLimit-Remaining", expect.any(Number));
        expect(mockRes.setHeader).toHaveBeenCalledWith("RateLimit-Reset", expect.any(Number));

        // X-prefixed headers
        expect(mockRes.setHeader).toHaveBeenCalledWith("X-RateLimit-Limit", 100);
        expect(mockRes.setHeader).toHaveBeenCalledWith("X-RateLimit-Remaining", expect.any(Number));
        expect(mockRes.setHeader).toHaveBeenCalledWith("X-RateLimit-Reset", expect.any(Number));
      });

      it("should block requests over the plan limit", async () => {
        const limiter = createTenantRateLimiter({
          name: "test-tenant-block",
          windowMs: 60000,
          planLimits: { free: 2 },
        });

        // First two requests should pass
        await limiter(mockReq, mockRes, mockNext);
        await limiter(mockReq, mockRes, mockNext);
        expect(mockNext).toHaveBeenCalledTimes(2);

        // Reset mocks
        mockNext.mockClear();
        mockRes.status.mockClear();
        mockRes.json.mockClear();

        // Third request should be blocked
        await limiter(mockReq, mockRes, mockNext);

        expect(mockNext).not.toHaveBeenCalled();
        expect(mockRes.status).toHaveBeenCalledWith(429);
        expect(mockRes.json).toHaveBeenCalledWith(
          expect.objectContaining({
            code: "RATE_LIMIT_EXCEEDED",
            retryAfter: expect.any(Number),
            limit: 2,
            reset: expect.any(Number),
          }),
        );
      });

      it("should set Retry-After header when blocked", async () => {
        const limiter = createTenantRateLimiter({
          name: "test-tenant-retry-after",
          windowMs: 60000,
          planLimits: { free: 1 },
        });

        await limiter(mockReq, mockRes, mockNext);
        mockRes.setHeader.mockClear();

        await limiter(mockReq, mockRes, mockNext);

        expect(mockRes.setHeader).toHaveBeenCalledWith("Retry-After", expect.any(Number));
      });

      it("should apply different limits based on plan", async () => {
        const limiter = createTenantRateLimiter({
          name: "test-tenant-plan-limits",
          windowMs: 60000,
          planLimits: { free: 2, pro: 10 },
        });

        // Free tier request
        await limiter(mockReq, mockRes, mockNext);
        expect(mockRes.setHeader).toHaveBeenCalledWith("RateLimit-Limit", 2);

        // Pro tier request
        mockRes.setHeader.mockClear();
        const proReq = {
          ...mockReq,
          tenant: { id: "tenant-pro" },
          subscription: { plan: "pro" },
        };
        await limiter(proReq, mockRes, mockNext);
        expect(mockRes.setHeader).toHaveBeenCalledWith("RateLimit-Limit", 10);
      });

      it("should respect API key rate limit override", async () => {
        const limiter = createTenantRateLimiter({
          name: "test-tenant-api-key-override",
          windowMs: 60000,
          planLimits: { free: 2 },
        });

        const reqWithOverride = {
          ...mockReq,
          apiKey: { rate_limit_override: 1000 },
        };

        await limiter(reqWithOverride, mockRes, mockNext);

        expect(mockRes.setHeader).toHaveBeenCalledWith("RateLimit-Limit", 1000);
      });

      it("should skip rate limiting for unlimited API keys", async () => {
        const limiter = createTenantRateLimiter({
          name: "test-tenant-unlimited",
          windowMs: 60000,
          planLimits: { free: 2 },
        });

        const reqWithUnlimited = {
          ...mockReq,
          apiKey: { rate_limit_override: -1 },
        };

        await limiter(reqWithUnlimited, mockRes, mockNext);

        expect(mockNext).toHaveBeenCalled();
        expect(mockRes.setHeader).toHaveBeenCalledWith("RateLimit-Limit", "unlimited");
        expect(mockRes.setHeader).toHaveBeenCalledWith("RateLimit-Remaining", "unlimited");
      });

      it("should use IP as key for unauthenticated requests", async () => {
        const limiter = createTenantRateLimiter({
          name: "test-tenant-unauthenticated",
          windowMs: 60000,
          planLimits: { free: 2 },
        });

        const unauthReq = {
          headers: {},
          ip: "9.9.9.9",
        };

        await limiter(unauthReq, mockRes, mockNext);
        await limiter(unauthReq, mockRes, mockNext);

        mockNext.mockClear();
        await limiter(unauthReq, mockRes, mockNext);

        expect(mockRes.status).toHaveBeenCalledWith(429);
      });

      it("should track different tenants separately", async () => {
        const limiter = createTenantRateLimiter({
          name: "test-tenant-separate",
          windowMs: 60000,
          planLimits: { free: 2 },
        });

        const tenant1Req = { ...mockReq, tenant: { id: "tenant-1" } };
        const tenant2Req = { ...mockReq, tenant: { id: "tenant-2" } };

        // Exhaust tenant 1's limit
        await limiter(tenant1Req, mockRes, mockNext);
        await limiter(tenant1Req, mockRes, mockNext);

        mockNext.mockClear();
        mockRes.status.mockClear();

        // Tenant 1 should be blocked
        await limiter(tenant1Req, mockRes, mockNext);
        expect(mockRes.status).toHaveBeenCalledWith(429);

        mockNext.mockClear();
        mockRes.status.mockClear();

        // Tenant 2 should still be allowed
        await limiter(tenant2Req, mockRes, mockNext);
        expect(mockNext).toHaveBeenCalled();
        expect(mockRes.status).not.toHaveBeenCalled();
      });

      it("should call onLimitReached with tenant info", async () => {
        const onLimitReached = vi.fn();
        const limiter = createTenantRateLimiter({
          name: "test-tenant-callback",
          windowMs: 60000,
          planLimits: { free: 1 },
          onLimitReached,
        });

        await limiter(mockReq, mockRes, mockNext);
        await limiter(mockReq, mockRes, mockNext);

        expect(onLimitReached).toHaveBeenCalledWith(
          mockReq,
          "tenant:tenant-test",
          expect.objectContaining({
            limit: 1,
            count: 1,
            tenantId: "tenant-test",
            plan: "free",
          }),
        );
      });
    });

    describe("pre-configured tenant limiters", () => {
      it("should export tenantApiLimiter", () => {
        expect(tenantApiLimiter).toBeDefined();
        expect(typeof tenantApiLimiter).toBe("function");
      });

      it("should export tenantSensitiveLimiter", () => {
        expect(tenantSensitiveLimiter).toBeDefined();
        expect(typeof tenantSensitiveLimiter).toBe("function");
      });

      it("tenantApiLimiter should apply plan limits", async () => {
        isRedisConnected.mockReturnValue(false);

        const mockReq = {
          headers: {},
          ip: "1.2.3.4",
          tenant: { id: "tenant-api-test" },
          subscription: { plan: "pro" },
        };
        const mockRes = { setHeader: vi.fn() };
        const mockNext = vi.fn();

        await tenantApiLimiter(mockReq, mockRes, mockNext);

        expect(mockNext).toHaveBeenCalled();
        expect(mockRes.setHeader).toHaveBeenCalledWith("RateLimit-Limit", 500);
      });
    });
  });
});
