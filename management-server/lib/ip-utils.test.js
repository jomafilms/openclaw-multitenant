/**
 * Tests for IP Utilities
 */
import { describe, it, expect } from "vitest";
import {
  parseCidr,
  isIpInCidr,
  isIpInAllowlist,
  validateCidr,
  validateIp,
  normalizeIp,
  isPrivateIp,
  KNOWN_VPN_RANGES,
} from "./ip-utils.js";

// ============================================================
// parseCidr TESTS
// ============================================================

describe("parseCidr", () => {
  describe("valid IPv4 CIDR", () => {
    it("parses CIDR with /24 prefix", () => {
      const result = parseCidr("192.168.1.0/24");
      expect(result).toEqual({
        ip: "192.168.1.0",
        prefixLength: 24,
        isV6: false,
      });
    });

    it("parses CIDR with /32 prefix (single IP)", () => {
      const result = parseCidr("10.0.0.1/32");
      expect(result).toEqual({
        ip: "10.0.0.1",
        prefixLength: 32,
        isV6: false,
      });
    });

    it("parses CIDR with /0 prefix (all IPs)", () => {
      const result = parseCidr("0.0.0.0/0");
      expect(result).toEqual({
        ip: "0.0.0.0",
        prefixLength: 0,
        isV6: false,
      });
    });

    it("parses IP without prefix as /32", () => {
      const result = parseCidr("192.168.1.100");
      expect(result).toEqual({
        ip: "192.168.1.100",
        prefixLength: 32,
        isV6: false,
      });
    });

    it("handles whitespace", () => {
      const result = parseCidr("  10.0.0.0/8  ");
      expect(result).toEqual({
        ip: "10.0.0.0",
        prefixLength: 8,
        isV6: false,
      });
    });
  });

  describe("valid IPv6 CIDR", () => {
    it("parses full IPv6 CIDR", () => {
      const result = parseCidr("2001:db8::/32");
      expect(result).toEqual({
        ip: "2001:db8::",
        prefixLength: 32,
        isV6: true,
      });
    });

    it("parses IPv6 loopback", () => {
      const result = parseCidr("::1/128");
      expect(result).toEqual({
        ip: "::1",
        prefixLength: 128,
        isV6: true,
      });
    });

    it("parses IPv6 without prefix as /128", () => {
      const result = parseCidr("2001:db8::1");
      expect(result).toEqual({
        ip: "2001:db8::1",
        prefixLength: 128,
        isV6: true,
      });
    });

    it("parses full IPv6 address with prefix", () => {
      const result = parseCidr("2001:0db8:0000:0000:0000:0000:0000:0001/64");
      expect(result).toEqual({
        ip: "2001:0db8:0000:0000:0000:0000:0000:0001",
        prefixLength: 64,
        isV6: true,
      });
    });
  });

  describe("invalid inputs", () => {
    it("returns null for invalid IP", () => {
      expect(parseCidr("256.1.1.1/24")).toBeNull();
      expect(parseCidr("not.an.ip/24")).toBeNull();
      expect(parseCidr("192.168.1/24")).toBeNull();
    });

    it("returns null for invalid prefix", () => {
      expect(parseCidr("192.168.1.0/33")).toBeNull();
      expect(parseCidr("192.168.1.0/-1")).toBeNull();
      expect(parseCidr("192.168.1.0/abc")).toBeNull();
      expect(parseCidr("2001:db8::/129")).toBeNull();
    });

    it("returns null for non-string input", () => {
      expect(parseCidr(null)).toBeNull();
      expect(parseCidr(undefined)).toBeNull();
      expect(parseCidr(123)).toBeNull();
      expect(parseCidr({})).toBeNull();
    });

    it("returns null for empty string", () => {
      expect(parseCidr("")).toBeNull();
      expect(parseCidr("   ")).toBeNull();
    });
  });
});

// ============================================================
// isIpInCidr TESTS
// ============================================================

describe("isIpInCidr", () => {
  describe("IPv4 matching", () => {
    it("matches IP within /24 subnet", () => {
      expect(isIpInCidr("192.168.1.100", "192.168.1.0/24")).toBe(true);
      expect(isIpInCidr("192.168.1.0", "192.168.1.0/24")).toBe(true);
      expect(isIpInCidr("192.168.1.255", "192.168.1.0/24")).toBe(true);
    });

    it("rejects IP outside /24 subnet", () => {
      expect(isIpInCidr("192.168.2.1", "192.168.1.0/24")).toBe(false);
      expect(isIpInCidr("192.167.1.1", "192.168.1.0/24")).toBe(false);
    });

    it("matches IP within /16 subnet", () => {
      expect(isIpInCidr("10.20.30.40", "10.20.0.0/16")).toBe(true);
      expect(isIpInCidr("10.20.255.255", "10.20.0.0/16")).toBe(true);
    });

    it("rejects IP outside /16 subnet", () => {
      expect(isIpInCidr("10.21.0.1", "10.20.0.0/16")).toBe(false);
    });

    it("matches IP within /8 subnet", () => {
      expect(isIpInCidr("10.255.255.255", "10.0.0.0/8")).toBe(true);
      expect(isIpInCidr("10.0.0.1", "10.0.0.0/8")).toBe(true);
    });

    it("matches exact IP with /32", () => {
      expect(isIpInCidr("192.168.1.1", "192.168.1.1/32")).toBe(true);
      expect(isIpInCidr("192.168.1.2", "192.168.1.1/32")).toBe(false);
    });

    it("matches all IPs with /0", () => {
      expect(isIpInCidr("1.2.3.4", "0.0.0.0/0")).toBe(true);
      expect(isIpInCidr("255.255.255.255", "0.0.0.0/0")).toBe(true);
    });

    it("handles common private ranges", () => {
      // 10.0.0.0/8
      expect(isIpInCidr("10.0.0.1", "10.0.0.0/8")).toBe(true);
      expect(isIpInCidr("10.255.255.255", "10.0.0.0/8")).toBe(true);

      // 172.16.0.0/12
      expect(isIpInCidr("172.16.0.1", "172.16.0.0/12")).toBe(true);
      expect(isIpInCidr("172.31.255.255", "172.16.0.0/12")).toBe(true);
      expect(isIpInCidr("172.32.0.1", "172.16.0.0/12")).toBe(false);

      // 192.168.0.0/16
      expect(isIpInCidr("192.168.0.1", "192.168.0.0/16")).toBe(true);
      expect(isIpInCidr("192.168.255.255", "192.168.0.0/16")).toBe(true);
    });

    it("handles Tailscale range", () => {
      expect(isIpInCidr("100.64.0.1", KNOWN_VPN_RANGES.tailscale)).toBe(true);
      expect(isIpInCidr("100.127.255.255", KNOWN_VPN_RANGES.tailscale)).toBe(true);
      expect(isIpInCidr("100.128.0.1", KNOWN_VPN_RANGES.tailscale)).toBe(false);
    });
  });

  describe("IPv6 matching", () => {
    it("matches IPv6 within /64 subnet", () => {
      expect(isIpInCidr("2001:db8::1", "2001:db8::/64")).toBe(true);
      expect(isIpInCidr("2001:db8::ffff:ffff:ffff:ffff", "2001:db8::/64")).toBe(true);
    });

    it("rejects IPv6 outside /64 subnet", () => {
      expect(isIpInCidr("2001:db9::1", "2001:db8::/64")).toBe(false);
    });

    it("matches IPv6 loopback", () => {
      expect(isIpInCidr("::1", "::1/128")).toBe(true);
    });

    it("matches with /0 (all IPv6)", () => {
      expect(isIpInCidr("2001:db8::1", "::/0")).toBe(true);
    });

    it("handles unique local addresses (fc00::/7)", () => {
      expect(isIpInCidr("fc00::1", "fc00::/7")).toBe(true);
      expect(isIpInCidr("fd00::1", "fc00::/7")).toBe(true);
      expect(isIpInCidr("fe00::1", "fc00::/7")).toBe(false);
    });
  });

  describe("version mismatch", () => {
    it("returns false when IP version differs from CIDR", () => {
      expect(isIpInCidr("192.168.1.1", "2001:db8::/32")).toBe(false);
      expect(isIpInCidr("2001:db8::1", "192.168.0.0/16")).toBe(false);
    });
  });

  describe("invalid inputs", () => {
    it("returns false for invalid IP", () => {
      expect(isIpInCidr("not.valid", "192.168.0.0/16")).toBe(false);
      expect(isIpInCidr("256.1.1.1", "192.168.0.0/16")).toBe(false);
    });

    it("returns false for invalid CIDR", () => {
      expect(isIpInCidr("192.168.1.1", "invalid")).toBe(false);
      expect(isIpInCidr("192.168.1.1", "192.168.0.0/33")).toBe(false);
    });

    it("returns false for non-string inputs", () => {
      expect(isIpInCidr(null, "192.168.0.0/16")).toBe(false);
      expect(isIpInCidr("192.168.1.1", null)).toBe(false);
      expect(isIpInCidr(123, "192.168.0.0/16")).toBe(false);
    });
  });
});

// ============================================================
// isIpInAllowlist TESTS
// ============================================================

describe("isIpInAllowlist", () => {
  it("returns true when IP matches any CIDR in allowlist", () => {
    const allowlist = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"];
    expect(isIpInAllowlist("10.1.2.3", allowlist)).toBe(true);
    expect(isIpInAllowlist("192.168.1.100", allowlist)).toBe(true);
    expect(isIpInAllowlist("172.20.0.1", allowlist)).toBe(true);
  });

  it("returns false when IP matches no CIDR in allowlist", () => {
    const allowlist = ["10.0.0.0/8", "192.168.0.0/16"];
    expect(isIpInAllowlist("8.8.8.8", allowlist)).toBe(false);
    expect(isIpInAllowlist("172.16.0.1", allowlist)).toBe(false);
  });

  it("returns false for empty allowlist", () => {
    expect(isIpInAllowlist("192.168.1.1", [])).toBe(false);
  });

  it("returns false for non-array allowlist", () => {
    expect(isIpInAllowlist("192.168.1.1", null)).toBe(false);
    expect(isIpInAllowlist("192.168.1.1", undefined)).toBe(false);
    expect(isIpInAllowlist("192.168.1.1", "192.168.0.0/16")).toBe(false);
  });

  it("handles mixed IPv4 and IPv6 allowlist", () => {
    const allowlist = ["192.168.0.0/16", "2001:db8::/32"];
    expect(isIpInAllowlist("192.168.1.1", allowlist)).toBe(true);
    expect(isIpInAllowlist("2001:db8::1", allowlist)).toBe(true);
    expect(isIpInAllowlist("10.0.0.1", allowlist)).toBe(false);
    expect(isIpInAllowlist("2001:db9::1", allowlist)).toBe(false);
  });

  it("skips invalid entries in allowlist", () => {
    const allowlist = ["invalid", "192.168.0.0/16", null, 123];
    expect(isIpInAllowlist("192.168.1.1", allowlist)).toBe(true);
    expect(isIpInAllowlist("10.0.0.1", allowlist)).toBe(false);
  });

  it("handles single-IP entries (implied /32 or /128)", () => {
    const allowlist = ["192.168.1.100", "10.0.0.1"];
    expect(isIpInAllowlist("192.168.1.100", allowlist)).toBe(true);
    expect(isIpInAllowlist("192.168.1.101", allowlist)).toBe(false);
  });
});

// ============================================================
// validateCidr TESTS
// ============================================================

describe("validateCidr", () => {
  it("returns valid for correct CIDR", () => {
    const result = validateCidr("192.168.0.0/16");
    expect(result.valid).toBe(true);
    expect(result.parsed).toEqual({
      ip: "192.168.0.0",
      prefixLength: 16,
      isV6: false,
    });
  });

  it("returns error for invalid CIDR", () => {
    const result = validateCidr("invalid");
    expect(result.valid).toBe(false);
    expect(result.error).toBe("Invalid CIDR notation");
  });

  it("returns error for non-string", () => {
    const result = validateCidr(123);
    expect(result.valid).toBe(false);
    expect(result.error).toBe("CIDR must be a string");
  });

  it("returns error for empty string", () => {
    const result = validateCidr("");
    expect(result.valid).toBe(false);
    expect(result.error).toBe("CIDR cannot be empty");
  });
});

// ============================================================
// validateIp TESTS
// ============================================================

describe("validateIp", () => {
  it("returns valid for correct IPv4", () => {
    const result = validateIp("192.168.1.1");
    expect(result.valid).toBe(true);
    expect(result.version).toBe(4);
  });

  it("returns valid for correct IPv6", () => {
    const result = validateIp("2001:db8::1");
    expect(result.valid).toBe(true);
    expect(result.version).toBe(6);
  });

  it("returns error for invalid IP", () => {
    const result = validateIp("not.valid");
    expect(result.valid).toBe(false);
    expect(result.error).toBe("Invalid IP address");
  });

  it("returns error for non-string", () => {
    const result = validateIp(123);
    expect(result.valid).toBe(false);
    expect(result.error).toBe("IP address must be a string");
  });

  it("returns error for empty string", () => {
    const result = validateIp("");
    expect(result.valid).toBe(false);
    expect(result.error).toBe("IP address cannot be empty");
  });
});

// ============================================================
// normalizeIp TESTS
// ============================================================

describe("normalizeIp", () => {
  it("returns IPv4 as-is", () => {
    expect(normalizeIp("192.168.1.1")).toBe("192.168.1.1");
  });

  it("expands shortened IPv6", () => {
    expect(normalizeIp("::1")).toBe("0000:0000:0000:0000:0000:0000:0000:0001");
    expect(normalizeIp("2001:db8::")).toBe("2001:0db8:0000:0000:0000:0000:0000:0000");
  });

  it("returns null for invalid IP", () => {
    expect(normalizeIp("invalid")).toBeNull();
    expect(normalizeIp(null)).toBeNull();
  });
});

// ============================================================
// isPrivateIp TESTS
// ============================================================

describe("isPrivateIp", () => {
  it("returns true for private IPv4 addresses", () => {
    expect(isPrivateIp("10.0.0.1")).toBe(true);
    expect(isPrivateIp("172.16.0.1")).toBe(true);
    expect(isPrivateIp("192.168.1.1")).toBe(true);
    expect(isPrivateIp("127.0.0.1")).toBe(true);
  });

  it("returns false for public IPv4 addresses", () => {
    expect(isPrivateIp("8.8.8.8")).toBe(false);
    expect(isPrivateIp("1.1.1.1")).toBe(false);
    expect(isPrivateIp("203.0.113.1")).toBe(false);
  });

  it("returns true for private IPv6 addresses", () => {
    expect(isPrivateIp("::1")).toBe(true);
    expect(isPrivateIp("fc00::1")).toBe(true);
    expect(isPrivateIp("fe80::1")).toBe(true);
  });

  it("returns false for public IPv6 addresses", () => {
    expect(isPrivateIp("2001:db8::1")).toBe(false);
  });

  it("returns false for invalid input", () => {
    expect(isPrivateIp(null)).toBe(false);
    expect(isPrivateIp("invalid")).toBe(false);
  });
});

// ============================================================
// KNOWN_VPN_RANGES TESTS
// ============================================================

describe("KNOWN_VPN_RANGES", () => {
  it("contains expected preset ranges", () => {
    expect(KNOWN_VPN_RANGES.tailscale).toBe("100.64.0.0/10");
    expect(KNOWN_VPN_RANGES.privateNetworkA).toBe("10.0.0.0/8");
    expect(KNOWN_VPN_RANGES.privateNetworkB).toBe("172.16.0.0/12");
    expect(KNOWN_VPN_RANGES.privateNetworkC).toBe("192.168.0.0/16");
    expect(KNOWN_VPN_RANGES.localhost4).toBe("127.0.0.0/8");
    expect(KNOWN_VPN_RANGES.localhost6).toBe("::1/128");
  });
});
