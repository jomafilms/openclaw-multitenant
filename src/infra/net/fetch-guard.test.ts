import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fetchWithSsrFGuard, type GuardedFetchOptions } from "./fetch-guard.js";

// Mock the ssrf module
vi.mock("./ssrf.js", () => ({
  resolvePinnedHostname: vi
    .fn()
    .mockResolvedValue({ hostname: "example.com", address: "93.184.216.34" }),
  resolvePinnedHostnameWithPolicy: vi
    .fn()
    .mockResolvedValue({ hostname: "example.com", address: "93.184.216.34" }),
  createPinnedDispatcher: vi.fn().mockReturnValue(null),
  closeDispatcher: vi.fn().mockResolvedValue(undefined),
}));

describe("fetch-guard", () => {
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockFetch = vi.fn();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe("fetchWithSsrFGuard", () => {
    it("should throw if fetch is not available", async () => {
      // Save and remove globalThis.fetch
      const originalFetch = globalThis.fetch;
      // @ts-expect-error - intentionally setting to undefined for test
      globalThis.fetch = undefined;

      try {
        await expect(
          fetchWithSsrFGuard({
            url: "https://example.com",
            // Don't provide fetchImpl, rely on globalThis.fetch being undefined
          }),
        ).rejects.toThrow("fetch is not available");
      } finally {
        // Restore fetch
        globalThis.fetch = originalFetch;
      }
    });

    it("should throw for invalid URL", async () => {
      await expect(
        fetchWithSsrFGuard({
          url: "not-a-valid-url",
          fetchImpl: mockFetch,
        }),
      ).rejects.toThrow("Invalid URL");
    });

    it("should throw for non-http/https protocols", async () => {
      await expect(
        fetchWithSsrFGuard({
          url: "ftp://example.com/file",
          fetchImpl: mockFetch,
        }),
      ).rejects.toThrow("Invalid URL: must be http or https");
    });

    it("should make successful request", async () => {
      const mockResponse = new Response("OK", { status: 200 });
      mockFetch.mockResolvedValue(mockResponse);

      const result = await fetchWithSsrFGuard({
        url: "https://example.com",
        fetchImpl: mockFetch,
      });

      expect(result.response).toBe(mockResponse);
      expect(result.finalUrl).toBe("https://example.com");
      expect(typeof result.release).toBe("function");
    });

    it("should follow redirects up to limit", async () => {
      const redirect1 = new Response(null, {
        status: 302,
        headers: { location: "https://example.com/redirect1" },
      });
      const redirect2 = new Response(null, {
        status: 302,
        headers: { location: "https://example.com/final" },
      });
      const finalResponse = new Response("OK", { status: 200 });

      mockFetch
        .mockResolvedValueOnce(redirect1)
        .mockResolvedValueOnce(redirect2)
        .mockResolvedValueOnce(finalResponse);

      const result = await fetchWithSsrFGuard({
        url: "https://example.com/start",
        fetchImpl: mockFetch,
        maxRedirects: 3,
      });

      expect(result.response).toBe(finalResponse);
      expect(result.finalUrl).toBe("https://example.com/final");
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it("should throw when exceeding max redirects", async () => {
      // Each redirect goes to a different URL
      let callCount = 0;
      mockFetch.mockImplementation(() => {
        callCount++;
        return Promise.resolve(
          new Response(null, {
            status: 302,
            headers: { location: `https://example.com/redirect${callCount}` },
          }),
        );
      });

      await expect(
        fetchWithSsrFGuard({
          url: "https://example.com/start",
          fetchImpl: mockFetch,
          maxRedirects: 2,
        }),
      ).rejects.toThrow("Too many redirects (limit: 2)");
    });

    it("should throw on redirect without location header", async () => {
      const redirect = new Response(null, { status: 302 });

      mockFetch.mockResolvedValue(redirect);

      await expect(
        fetchWithSsrFGuard({
          url: "https://example.com",
          fetchImpl: mockFetch,
        }),
      ).rejects.toThrow("Redirect missing location header");
    });

    it("should detect redirect loops", async () => {
      const redirect1 = new Response(null, {
        status: 302,
        headers: { location: "https://example.com/b" },
      });
      const redirect2 = new Response(null, {
        status: 302,
        headers: { location: "https://example.com/c" },
      });
      const redirect3 = new Response(null, {
        status: 302,
        headers: { location: "https://example.com/b" }, // Loop back to /b
      });

      // /a -> /b -> /c -> /b (loop!)
      mockFetch
        .mockResolvedValueOnce(redirect1)
        .mockResolvedValueOnce(redirect2)
        .mockResolvedValueOnce(redirect3);

      await expect(
        fetchWithSsrFGuard({
          url: "https://example.com/a",
          fetchImpl: mockFetch,
          maxRedirects: 10,
        }),
      ).rejects.toThrow("Redirect loop detected");
    });

    it("should handle all redirect status codes", async () => {
      const redirectCodes = [301, 302, 303, 307, 308];

      for (const code of redirectCodes) {
        mockFetch.mockReset();
        const redirect = new Response(null, {
          status: code,
          headers: { location: "https://example.com/final" },
        });
        const finalResponse = new Response("OK", { status: 200 });

        mockFetch.mockResolvedValueOnce(redirect).mockResolvedValueOnce(finalResponse);

        const result = await fetchWithSsrFGuard({
          url: "https://example.com/start",
          fetchImpl: mockFetch,
        });

        expect(result.finalUrl).toBe("https://example.com/final");
      }
    });

    it("should use default maxRedirects of 3", async () => {
      const redirects = Array(4)
        .fill(null)
        .map(
          (_, i) =>
            new Response(null, {
              status: 302,
              headers: { location: `https://example.com/r${i + 1}` },
            }),
        );

      mockFetch
        .mockResolvedValueOnce(redirects[0])
        .mockResolvedValueOnce(redirects[1])
        .mockResolvedValueOnce(redirects[2])
        .mockResolvedValueOnce(redirects[3]);

      await expect(
        fetchWithSsrFGuard({
          url: "https://example.com/start",
          fetchImpl: mockFetch,
          // No maxRedirects specified, should use default of 3
        }),
      ).rejects.toThrow("Too many redirects (limit: 3)");
    });

    it("should respect timeout", async () => {
      const controller = new AbortController();

      // Mock a slow fetch that respects abort signal
      mockFetch.mockImplementation(async (_url: string, init?: RequestInit) => {
        if (init?.signal?.aborted) {
          throw new Error("aborted");
        }
        await new Promise((_, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
        });
      });

      const fetchPromise = fetchWithSsrFGuard({
        url: "https://example.com",
        fetchImpl: mockFetch,
        timeoutMs: 100,
      });

      await expect(fetchPromise).rejects.toThrow();
    });

    it("should respect external abort signal", async () => {
      const controller = new AbortController();

      mockFetch.mockImplementation(async (_url: string, init?: RequestInit) => {
        if (init?.signal?.aborted) {
          throw new DOMException("aborted", "AbortError");
        }
        return new Response("OK");
      });

      // Abort before making the request
      controller.abort();

      // When signal is already aborted, the fetch should throw
      await expect(
        fetchWithSsrFGuard({
          url: "https://example.com",
          fetchImpl: mockFetch,
          signal: controller.signal,
        }),
      ).rejects.toThrow();

      // The fetch should have received an aborted signal
      expect(mockFetch).toHaveBeenCalled();
    });

    it("should pass through request init options", async () => {
      const mockResponse = new Response("OK", { status: 200 });
      mockFetch.mockResolvedValue(mockResponse);

      await fetchWithSsrFGuard({
        url: "https://example.com",
        fetchImpl: mockFetch,
        init: {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ test: true }),
        },
      });

      expect(mockFetch).toHaveBeenCalledWith(
        "https://example.com/",
        expect.objectContaining({
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ test: true }),
          redirect: "manual",
        }),
      );
    });

    it("should call release function", async () => {
      const mockResponse = new Response("OK", { status: 200 });
      mockFetch.mockResolvedValue(mockResponse);

      const result = await fetchWithSsrFGuard({
        url: "https://example.com",
        fetchImpl: mockFetch,
      });

      // Release should be callable
      await result.release();
      // Calling again should be a no-op (idempotent)
      await result.release();
    });

    it("should resolve relative redirect URLs", async () => {
      const redirect = new Response(null, {
        status: 302,
        headers: { location: "/relative/path" },
      });
      const finalResponse = new Response("OK", { status: 200 });

      mockFetch.mockResolvedValueOnce(redirect).mockResolvedValueOnce(finalResponse);

      const result = await fetchWithSsrFGuard({
        url: "https://example.com/start",
        fetchImpl: mockFetch,
      });

      expect(result.finalUrl).toBe("https://example.com/relative/path");
    });
  });
});
