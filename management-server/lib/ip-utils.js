/**
 * IP Address Utilities for Admin Security
 *
 * This module provides CIDR notation parsing, validation, and IP matching
 * functions for the admin IP allowlist feature.
 *
 * Supports both IPv4 and IPv6 addresses.
 */
import { isIP } from "net";

// ============================================================
// KNOWN VPN/CORPORATE RANGES
// ============================================================

/**
 * Known VPN and private network ranges for quick presets
 * These can be used in the UI for easy one-click allowlist additions
 */
export const KNOWN_VPN_RANGES = {
  tailscale: "100.64.0.0/10",
  cloudflareWarp: "172.16.0.0/12",
  privateNetworkA: "10.0.0.0/8",
  privateNetworkB: "172.16.0.0/12",
  privateNetworkC: "192.168.0.0/16",
  localhost4: "127.0.0.0/8",
  localhost6: "::1/128",
};

// ============================================================
// CIDR PARSING
// ============================================================

/**
 * Parse CIDR notation into components
 *
 * @param {string} cidr - CIDR notation string (e.g., "192.168.1.0/24" or "2001:db8::/32")
 * @returns {{ ip: string, prefixLength: number, isV6: boolean } | null} Parsed CIDR or null if invalid
 */
export function parseCidr(cidr) {
  if (typeof cidr !== "string" || !cidr.trim()) {
    return null;
  }

  const trimmed = cidr.trim();
  const slashIndex = trimmed.lastIndexOf("/");

  let ip;
  let prefixStr;

  if (slashIndex === -1) {
    // No prefix specified - treat as single IP
    ip = trimmed;
    prefixStr = null;
  } else {
    ip = trimmed.substring(0, slashIndex);
    prefixStr = trimmed.substring(slashIndex + 1);
  }

  // Validate IP address
  const ipVersion = isIP(ip);
  if (ipVersion === 0) {
    return null;
  }

  const isV6 = ipVersion === 6;
  const maxPrefix = isV6 ? 128 : 32;

  // Parse or default prefix length
  let prefixLength;
  if (prefixStr === null) {
    prefixLength = maxPrefix; // Single IP
  } else {
    prefixLength = parseInt(prefixStr, 10);
    if (isNaN(prefixLength) || prefixLength < 0 || prefixLength > maxPrefix) {
      return null;
    }
  }

  return { ip, prefixLength, isV6 };
}

// ============================================================
// IP CONVERSION HELPERS
// ============================================================

/**
 * Convert an IPv4 address string to a 32-bit unsigned integer
 *
 * @param {string} ip - IPv4 address (e.g., "192.168.1.1")
 * @returns {number} 32-bit unsigned integer representation
 */
function ipv4ToInt(ip) {
  const octets = ip.split(".");
  if (octets.length !== 4) {
    throw new Error("Invalid IPv4 address");
  }

  let result = 0;
  for (let i = 0; i < 4; i++) {
    const octet = parseInt(octets[i], 10);
    if (isNaN(octet) || octet < 0 || octet > 255) {
      throw new Error("Invalid IPv4 octet");
    }
    result = (result << 8) | octet;
  }

  // Convert to unsigned 32-bit integer
  return result >>> 0;
}

/**
 * Expand an IPv6 address to its full 8-group form
 * Handles :: abbreviation and mixed IPv4 notation
 *
 * @param {string} ip - IPv6 address
 * @returns {number[]} Array of 8 16-bit integers
 */
function ipv6ToGroups(ip) {
  // Handle IPv4-mapped IPv6 (e.g., ::ffff:192.168.1.1)
  const ipv4MappedMatch = ip.match(/^(.*):(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (ipv4MappedMatch) {
    const prefix = ipv4MappedMatch[1];
    const ipv4 = ipv4MappedMatch[2];
    const ipv4Int = ipv4ToInt(ipv4);
    const ipv6Part =
      prefix +
      ":" +
      ((ipv4Int >>> 16) & 0xffff).toString(16) +
      ":" +
      (ipv4Int & 0xffff).toString(16);
    return ipv6ToGroups(ipv6Part);
  }

  const parts = ip.split("::");

  if (parts.length > 2) {
    throw new Error("Invalid IPv6 address: multiple ::");
  }

  const leftPart = parts[0] ? parts[0].split(":") : [];
  const rightPart = parts.length > 1 && parts[1] ? parts[1].split(":") : [];

  // Calculate how many zero groups are represented by ::
  const totalGroups = 8;
  const explicitGroups = leftPart.length + rightPart.length;

  if (parts.length === 1 && explicitGroups !== 8) {
    throw new Error("Invalid IPv6 address: wrong number of groups");
  }

  const zeroGroups = parts.length === 2 ? totalGroups - explicitGroups : 0;

  if (zeroGroups < 0) {
    throw new Error("Invalid IPv6 address: too many groups");
  }

  const groups = [];

  // Add left part
  for (const part of leftPart) {
    const val = parseInt(part, 16);
    if (isNaN(val) || val < 0 || val > 0xffff) {
      throw new Error("Invalid IPv6 group");
    }
    groups.push(val);
  }

  // Add zero groups for ::
  for (let i = 0; i < zeroGroups; i++) {
    groups.push(0);
  }

  // Add right part
  for (const part of rightPart) {
    const val = parseInt(part, 16);
    if (isNaN(val) || val < 0 || val > 0xffff) {
      throw new Error("Invalid IPv6 group");
    }
    groups.push(val);
  }

  if (groups.length !== 8) {
    throw new Error("Invalid IPv6 address");
  }

  return groups;
}

// ============================================================
// CIDR MATCHING
// ============================================================

/**
 * Check if an IPv4 address is within a CIDR block
 *
 * @param {string} ip - IPv4 address to check
 * @param {string} baseIp - Base IPv4 address of the CIDR block
 * @param {number} prefixLength - CIDR prefix length (0-32)
 * @returns {boolean} True if IP is within the CIDR block
 */
function ipv4InCidr(ip, baseIp, prefixLength) {
  try {
    const ipInt = ipv4ToInt(ip);
    const baseInt = ipv4ToInt(baseIp);

    if (prefixLength === 0) {
      // /0 matches everything
      return true;
    }

    // Create a mask with prefixLength 1-bits from the left
    const mask = (~0 << (32 - prefixLength)) >>> 0;

    return (ipInt & mask) === (baseInt & mask);
  } catch {
    return false;
  }
}

/**
 * Check if an IPv6 address is within a CIDR block
 *
 * @param {string} ip - IPv6 address to check
 * @param {string} baseIp - Base IPv6 address of the CIDR block
 * @param {number} prefixLength - CIDR prefix length (0-128)
 * @returns {boolean} True if IP is within the CIDR block
 */
function ipv6InCidr(ip, baseIp, prefixLength) {
  try {
    const ipGroups = ipv6ToGroups(ip);
    const baseGroups = ipv6ToGroups(baseIp);

    if (prefixLength === 0) {
      // /0 matches everything
      return true;
    }

    // Compare groups bit by bit
    let remainingBits = prefixLength;

    for (let i = 0; i < 8 && remainingBits > 0; i++) {
      const bitsInGroup = Math.min(16, remainingBits);
      remainingBits -= bitsInGroup;

      if (bitsInGroup === 16) {
        // Full group comparison
        if (ipGroups[i] !== baseGroups[i]) {
          return false;
        }
      } else {
        // Partial group comparison
        const mask = (~0 << (16 - bitsInGroup)) & 0xffff;
        if ((ipGroups[i] & mask) !== (baseGroups[i] & mask)) {
          return false;
        }
      }
    }

    return true;
  } catch {
    return false;
  }
}

/**
 * Check if an IP address is within a CIDR block
 *
 * @param {string} ip - IP address to check
 * @param {string} cidrBlock - CIDR notation (e.g., "192.168.0.0/16" or "2001:db8::/32")
 * @returns {boolean} True if IP is within the CIDR block
 */
export function isIpInCidr(ip, cidrBlock) {
  // Validate inputs
  if (typeof ip !== "string" || typeof cidrBlock !== "string") {
    return false;
  }

  const trimmedIp = ip.trim();
  const ipVersion = isIP(trimmedIp);

  if (ipVersion === 0) {
    return false;
  }

  const parsed = parseCidr(cidrBlock);
  if (!parsed) {
    return false;
  }

  // IP versions must match
  const isV6 = ipVersion === 6;
  if (isV6 !== parsed.isV6) {
    return false;
  }

  if (isV6) {
    return ipv6InCidr(trimmedIp, parsed.ip, parsed.prefixLength);
  } else {
    return ipv4InCidr(trimmedIp, parsed.ip, parsed.prefixLength);
  }
}

// ============================================================
// ALLOWLIST MATCHING
// ============================================================

/**
 * Check if an IP address is in an allowlist of CIDR blocks
 *
 * @param {string} ip - IP address to check
 * @param {string[]} allowlistArray - Array of CIDR blocks
 * @returns {boolean} True if IP matches any block in the allowlist
 */
export function isIpInAllowlist(ip, allowlistArray) {
  // Validate inputs
  if (typeof ip !== "string") {
    return false;
  }

  if (!Array.isArray(allowlistArray)) {
    return false;
  }

  if (allowlistArray.length === 0) {
    return false;
  }

  const trimmedIp = ip.trim();

  for (const cidrBlock of allowlistArray) {
    if (typeof cidrBlock === "string" && isIpInCidr(trimmedIp, cidrBlock)) {
      return true;
    }
  }

  return false;
}

// ============================================================
// VALIDATION
// ============================================================

/**
 * Validate a CIDR notation string
 *
 * @param {string} cidr - CIDR notation to validate
 * @returns {{ valid: boolean, parsed?: { ip: string, prefixLength: number, isV6: boolean }, error?: string }}
 */
export function validateCidr(cidr) {
  if (typeof cidr !== "string") {
    return { valid: false, error: "CIDR must be a string" };
  }

  const trimmed = cidr.trim();

  if (!trimmed) {
    return { valid: false, error: "CIDR cannot be empty" };
  }

  const parsed = parseCidr(trimmed);

  if (!parsed) {
    return { valid: false, error: "Invalid CIDR notation" };
  }

  return { valid: true, parsed };
}

/**
 * Validate an IP address string
 *
 * @param {string} ip - IP address to validate
 * @returns {{ valid: boolean, version?: number, error?: string }}
 */
export function validateIp(ip) {
  if (typeof ip !== "string") {
    return { valid: false, error: "IP address must be a string" };
  }

  const trimmed = ip.trim();

  if (!trimmed) {
    return { valid: false, error: "IP address cannot be empty" };
  }

  const version = isIP(trimmed);

  if (version === 0) {
    return { valid: false, error: "Invalid IP address" };
  }

  return { valid: true, version };
}

// ============================================================
// CLIENT IP EXTRACTION
// ============================================================

/**
 * Get client IP from request with trust proxy awareness
 *
 * This function respects Express's trust proxy setting and handles
 * common proxy headers (X-Forwarded-For, X-Real-IP).
 *
 * @param {object} req - Express request object
 * @returns {string} Client IP address or 'unknown'
 */
export function getClientIpSecure(req) {
  // If Express trust proxy is configured, use req.ip (already processed)
  if (req.app && req.app.get("trust proxy")) {
    return req.ip || req.socket?.remoteAddress || "unknown";
  }

  // When not trusting proxy, use only the direct connection
  return req.socket?.remoteAddress || "unknown";
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

/**
 * Get local network IPs of the current machine
 * Useful for "add current IP" functionality in admin UI
 *
 * @returns {Promise<string[]>} Array of local IPv4 addresses (non-internal)
 */
export async function getLocalIps() {
  try {
    const os = await import("os");
    const networkInterfaces = os.networkInterfaces();
    const ips = [];

    for (const name of Object.keys(networkInterfaces)) {
      for (const iface of networkInterfaces[name]) {
        // Skip internal (loopback) interfaces and IPv6
        if (!iface.internal && iface.family === "IPv4") {
          ips.push(iface.address);
        }
      }
    }

    return ips;
  } catch {
    return [];
  }
}

/**
 * Synchronous version of getLocalIps (uses require)
 *
 * @returns {string[]} Array of local IPv4 addresses (non-internal)
 */
export function getLocalIpsSync() {
  try {
    const os = require("os");
    const networkInterfaces = os.networkInterfaces();
    const ips = [];

    for (const name of Object.keys(networkInterfaces)) {
      for (const iface of networkInterfaces[name]) {
        if (!iface.internal && iface.family === "IPv4") {
          ips.push(iface.address);
        }
      }
    }

    return ips;
  } catch {
    return [];
  }
}

/**
 * Normalize an IP address to its canonical form
 * IPv4: as-is
 * IPv6: lowercase, expanded (no ::)
 *
 * @param {string} ip - IP address to normalize
 * @returns {string | null} Normalized IP or null if invalid
 */
export function normalizeIp(ip) {
  if (typeof ip !== "string") {
    return null;
  }

  const trimmed = ip.trim();
  const version = isIP(trimmed);

  if (version === 0) {
    return null;
  }

  if (version === 4) {
    return trimmed;
  }

  // IPv6: expand to full form
  try {
    const groups = ipv6ToGroups(trimmed);
    return groups.map((g) => g.toString(16).padStart(4, "0")).join(":");
  } catch {
    return null;
  }
}

/**
 * Check if an IP address is a private/internal address
 *
 * @param {string} ip - IP address to check
 * @returns {boolean} True if the IP is private/internal
 */
export function isPrivateIp(ip) {
  if (typeof ip !== "string") {
    return false;
  }

  const privateRanges = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16", // Link-local
    "::1/128", // IPv6 loopback
    "fc00::/7", // IPv6 unique local
    "fe80::/10", // IPv6 link-local
  ];

  return isIpInAllowlist(ip, privateRanges);
}

// ============================================================
// EXPORTS
// ============================================================

export default {
  // Constants
  KNOWN_VPN_RANGES,

  // Core functions
  parseCidr,
  isIpInCidr,
  isIpInAllowlist,

  // Validation
  validateCidr,
  validateIp,

  // Request utilities
  getClientIpSecure,

  // Helpers
  getLocalIps,
  getLocalIpsSync,
  normalizeIp,
  isPrivateIp,
};
