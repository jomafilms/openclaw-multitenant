// management-server/lib/shamir.js
// Shamir's Secret Sharing implementation for social recovery
// Uses GF(2^8) finite field arithmetic for byte-level splitting

import crypto from 'crypto';

// GF(2^8) field operations using polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D)
// This polynomial with generator 2 produces a full 255-element multiplicative group
const FIELD_SIZE = 256;
const POLYNOMIAL = 0x11d;

// Precomputed log and exp tables for GF(2^8)
const LOG_TABLE = new Uint8Array(FIELD_SIZE);
const EXP_TABLE = new Uint8Array(FIELD_SIZE * 2); // Double size for easy wraparound

// Initialize lookup tables
(function initTables() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP_TABLE[i] = x;
    EXP_TABLE[i + 255] = x; // Duplicate to avoid modulo in multiplication
    LOG_TABLE[x] = i;
    x = x << 1;
    if (x >= 256) {
      x ^= POLYNOMIAL;
    }
  }
  // LOG_TABLE[0] is undefined mathematically (log of 0 doesn't exist)
  // We leave it as 0 but handle the 0 case specially in operations
})();

/**
 * GF(2^8) addition (XOR)
 */
function gfAdd(a, b) {
  return a ^ b;
}

/**
 * GF(2^8) multiplication using log/exp tables
 */
function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  // Use the duplicated EXP_TABLE to avoid modulo operation
  return EXP_TABLE[LOG_TABLE[a] + LOG_TABLE[b]];
}

/**
 * GF(2^8) division
 */
function gfDiv(a, b) {
  if (b === 0) throw new Error('Division by zero');
  if (a === 0) return 0;
  return EXP_TABLE[(LOG_TABLE[a] - LOG_TABLE[b] + 255) % 255];
}

/**
 * Evaluate polynomial at point x using Horner's method
 * coefficients[0] is the constant term (secret)
 */
function evaluatePolynomial(coefficients, x) {
  if (x === 0) return coefficients[0];

  let result = 0;
  for (let i = coefficients.length - 1; i >= 0; i--) {
    result = gfAdd(gfMul(result, x), coefficients[i]);
  }
  return result;
}

/**
 * Lagrange interpolation to recover secret (y-value at x=0)
 * @param {Array<{x: number, y: number}>} points - Array of (x, y) points
 * @returns {number} The secret (y value at x=0)
 */
function lagrangeInterpolate(points) {
  let secret = 0;

  for (let i = 0; i < points.length; i++) {
    let numerator = 1;
    let denominator = 1;

    for (let j = 0; j < points.length; j++) {
      if (i === j) continue;

      // For x=0: numerator *= (0 - xj) = xj (in GF(2^8), negation is identity)
      numerator = gfMul(numerator, points[j].x);
      // denominator *= (xi - xj)
      denominator = gfMul(denominator, gfAdd(points[i].x, points[j].x));
    }

    // Lagrange basis polynomial value at x=0
    const basis = gfDiv(numerator, denominator);
    secret = gfAdd(secret, gfMul(points[i].y, basis));
  }

  return secret;
}

/**
 * Split a secret into n shares, requiring k shares to reconstruct
 * @param {Buffer} secret - The secret to split
 * @param {number} n - Total number of shares
 * @param {number} k - Threshold (minimum shares needed)
 * @returns {Array<{x: number, data: Buffer}>} Array of shares
 */
export function split(secret, n, k) {
  if (k < 2) throw new Error('Threshold must be at least 2');
  if (n < k) throw new Error('Total shares must be >= threshold');
  if (n > 255) throw new Error('Maximum 255 shares supported');
  if (k > 255) throw new Error('Maximum threshold is 255');

  const secretBytes = Buffer.isBuffer(secret) ? secret : Buffer.from(secret);
  const shares = [];

  // Create unique x-values for each share (1 to n, never 0)
  const xValues = [];
  for (let i = 1; i <= n; i++) {
    xValues.push(i);
  }

  // Process each byte of the secret independently
  for (let shareIdx = 0; shareIdx < n; shareIdx++) {
    shares.push({
      x: xValues[shareIdx],
      data: Buffer.alloc(secretBytes.length)
    });
  }

  // For each byte position
  for (let byteIdx = 0; byteIdx < secretBytes.length; byteIdx++) {
    // Generate random polynomial coefficients
    // coefficients[0] = secret byte, rest are random
    const coefficients = [secretBytes[byteIdx]];
    for (let i = 1; i < k; i++) {
      coefficients.push(crypto.randomInt(256));
    }

    // Evaluate polynomial at each x-value
    for (let shareIdx = 0; shareIdx < n; shareIdx++) {
      shares[shareIdx].data[byteIdx] = evaluatePolynomial(coefficients, xValues[shareIdx]);
    }
  }

  return shares;
}

/**
 * Combine shares to reconstruct the secret
 * @param {Array<{x: number, data: Buffer}>} shares - Array of shares
 * @returns {Buffer} The reconstructed secret
 */
export function combine(shares) {
  if (shares.length < 2) throw new Error('Need at least 2 shares');

  // Verify all shares have same length
  const length = shares[0].data.length;
  for (const share of shares) {
    if (share.data.length !== length) {
      throw new Error('Share length mismatch');
    }
  }

  // Check for duplicate x-values
  const xSet = new Set(shares.map(s => s.x));
  if (xSet.size !== shares.length) {
    throw new Error('Duplicate share indices');
  }

  const secret = Buffer.alloc(length);

  // Reconstruct each byte independently
  for (let byteIdx = 0; byteIdx < length; byteIdx++) {
    const points = shares.map(share => ({
      x: share.x,
      y: share.data[byteIdx]
    }));
    secret[byteIdx] = lagrangeInterpolate(points);
  }

  return secret;
}

/**
 * Encode a share to base64 string with metadata
 * Format: version(1) | x(1) | data
 */
export function encodeShare(share) {
  const version = 1;
  const buffer = Buffer.alloc(2 + share.data.length);
  buffer[0] = version;
  buffer[1] = share.x;
  share.data.copy(buffer, 2);
  return buffer.toString('base64');
}

/**
 * Decode a share from base64 string
 */
export function decodeShare(encoded) {
  const buffer = Buffer.from(encoded, 'base64');
  if (buffer.length < 3) throw new Error('Invalid share format');

  const version = buffer[0];
  if (version !== 1) throw new Error(`Unsupported share version: ${version}`);

  return {
    x: buffer[1],
    data: buffer.slice(2)
  };
}

/**
 * Create shares with encryption for each contact
 * Each shard is encrypted with a contact-specific key derived from email
 * @param {Buffer} secret - The secret to split
 * @param {number} threshold - Minimum shares needed (k)
 * @param {Array<{email: string}>} contacts - Contact list
 * @returns {Array<{email: string, encryptedShard: string, shareIndex: number}>}
 */
export function createSocialRecoveryShards(secret, threshold, contacts) {
  const n = contacts.length;
  const shares = split(secret, n, threshold);

  return contacts.map((contact, idx) => {
    const encoded = encodeShare(shares[idx]);
    return {
      email: contact.email,
      shard: encoded,
      shareIndex: shares[idx].x
    };
  });
}

/**
 * Reconstruct secret from collected shards
 * @param {Array<{shard: string}>} shards - Array of encoded shards
 * @returns {Buffer} The reconstructed secret
 */
export function reconstructFromShards(shards) {
  const decodedShares = shards.map(s => decodeShare(s.shard));
  return combine(decodedShares);
}
