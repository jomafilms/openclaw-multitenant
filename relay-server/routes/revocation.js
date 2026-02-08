/**
 * Relay Revocation Routes
 *
 * Handles capability revocation requests and queries.
 * Revocations are signed by the capability issuer for verification.
 *
 * SECURITY: Revocations are persisted to PostgreSQL to survive server restarts.
 * A Bloom filter is used for fast rejection of non-revoked capabilities.
 */
import { Router } from 'express';
import { createVerify, createPublicKey, createHash } from 'crypto';
import { capabilityRevocations, meshAuditLogs, MESH_AUDIT_EVENTS } from '../../management-server/db/index.js';
import { cachedSnapshots } from '../db/index.js';
import {
  validate,
  revocationRequestSchema,
  batchRevocationCheckSchema,
  capabilityIdParamSchema,
  snapshotSchema,
  snapshotListSchema,
} from '../lib/schemas.js';

const router = Router();

// Ed25519 SPKI prefix for DER-encoded public keys
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

// Bloom filter for fast revocation checks (loaded from DB at startup)
// Configuration: ~100k items at 0.1% false positive rate
const BLOOM_SIZE = 1437759; // bits
const BLOOM_HASH_COUNT = 10;
let bloomFilter = new Uint8Array(Math.ceil(BLOOM_SIZE / 8));
let bloomItemCount = 0;
let bloomInitialized = false;

// In-memory cache for recently checked revocations (LRU-style, max 10k entries)
const revocationCache = new Map();
const MAX_CACHE_SIZE = 10000;

/**
 * Initialize the revocation Bloom filter from database.
 * Call this at server startup.
 */
export async function initRevocationBloomFilter() {
  if (bloomInitialized) return;

  try {
    console.log('[revocation] Loading revocations from database...');
    const capabilityIds = await capabilityRevocations.getAllCapabilityIds();

    // Resize bloom filter if needed
    const expectedItems = Math.max(capabilityIds.length * 2, 100000);
    const optimalSize = Math.ceil((-expectedItems * Math.log(0.001)) / (Math.LN2 * Math.LN2));
    if (optimalSize > BLOOM_SIZE) {
      bloomFilter = new Uint8Array(Math.ceil(optimalSize / 8));
    }

    // Add all revoked capabilities to bloom filter
    for (const capabilityId of capabilityIds) {
      bloomAdd(capabilityId);
    }

    bloomInitialized = true;
    console.log(`[revocation] Loaded ${capabilityIds.length} revocations into Bloom filter`);
  } catch (err) {
    console.error('[revocation] Failed to load revocations from database:', err);
    // Continue without persistence - will use in-memory only
    bloomInitialized = true;
  }
}

/**
 * Add an item to the Bloom filter.
 */
function bloomAdd(item) {
  const positions = getBloomHashPositions(item);
  for (const pos of positions) {
    const byteIndex = Math.floor(pos / 8);
    const bitIndex = pos % 8;
    bloomFilter[byteIndex] |= (1 << bitIndex);
  }
  bloomItemCount++;
}

/**
 * Check if an item might be in the Bloom filter.
 */
function bloomMightContain(item) {
  const positions = getBloomHashPositions(item);
  for (const pos of positions) {
    const byteIndex = Math.floor(pos / 8);
    const bitIndex = pos % 8;
    if ((bloomFilter[byteIndex] & (1 << bitIndex)) === 0) {
      return false;
    }
  }
  return true;
}

/**
 * Get hash positions for Bloom filter using double hashing.
 */
function getBloomHashPositions(item) {
  const hash = createHash('sha256').update(item).digest();
  const h1 = hash.readBigUInt64LE(0);
  const h2 = hash.readBigUInt64LE(8);
  const positions = [];
  const sizeBigInt = BigInt(BLOOM_SIZE);

  for (let i = 0; i < BLOOM_HASH_COUNT; i++) {
    const combined = (h1 + BigInt(i) * h2) % sizeBigInt;
    positions.push(Number(combined));
  }
  return positions;
}

/**
 * Add to revocation cache with LRU eviction.
 */
function cacheRevocation(capabilityId, record) {
  if (revocationCache.size >= MAX_CACHE_SIZE) {
    // Remove oldest entry (first key)
    const firstKey = revocationCache.keys().next().value;
    revocationCache.delete(firstKey);
  }
  revocationCache.set(capabilityId, record);
}

/**
 * Verify an Ed25519 signature
 */
function verifySignature(payload, signatureBase64, publicKeyBase64) {
  try {
    const rawKey = Buffer.from(publicKeyBase64, 'base64');
    if (rawKey.length !== 32) {
      console.warn('[revocation] Invalid public key length:', rawKey.length);
      return false;
    }

    const spkiDer = Buffer.concat([ED25519_SPKI_PREFIX, rawKey]);
    const publicKey = createPublicKey({ key: spkiDer, type: 'spki', format: 'der' });

    const signatureBuffer = Buffer.from(signatureBase64, 'base64');
    if (signatureBuffer.length !== 64) {
      console.warn('[revocation] Invalid signature length:', signatureBuffer.length);
      return false;
    }

    const verify = createVerify(null);
    verify.update(payload);
    return verify.verify(publicKey, signatureBuffer);
  } catch (err) {
    console.error('[revocation] Signature verification failed:', err.message);
    return false;
  }
}

/**
 * POST /relay/revoke
 * Submit a capability revocation
 *
 * Body: {
 *   capabilityId: string,
 *   revokedBy: string (base64 public key),
 *   signature: string (base64),
 *   reason?: string,
 *   originalExpiry?: string (ISO date),
 *   timestamp: string (ISO date)
 * }
 */
router.post('/revoke', validate({ body: revocationRequestSchema }), async (req, res) => {
  const { capabilityId, revokedBy, signature, reason, originalExpiry, timestamp } = req.validatedBody;

  // Verify timestamp is recent (within 5 minutes)
  const requestTime = new Date(timestamp).getTime();
  const now = Date.now();
  if (Math.abs(now - requestTime) > 5 * 60 * 1000) {
    return res.status(400).json({
      success: false,
      error: 'Revocation request timestamp is too old or in the future'
    });
  }

  // Reconstruct the signed payload
  const signPayload = JSON.stringify({
    action: 'revoke',
    capabilityId,
    revokedBy,
    reason,
    originalExpiry,
    timestamp
  });

  // Verify signature
  if (!verifySignature(signPayload, signature, revokedBy)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid signature - revocation must be signed by capability issuer'
    });
  }

  try {
    // Persist revocation to database
    const record = await capabilityRevocations.create({
      capabilityId,
      issuerPublicKey: revokedBy,
      reason,
      originalExpiry,
      signature,
      metadata: { timestamp }
    });

    // Add to Bloom filter for fast lookup
    bloomAdd(capabilityId);

    // Add to cache
    const revocationRecord = {
      capabilityId,
      revokedBy,
      reason,
      originalExpiry,
      revokedAt: record?.revoked_at?.toISOString() || new Date().toISOString()
    };
    cacheRevocation(capabilityId, revocationRecord);

    // Delete any cached snapshots for this capability
    await cachedSnapshots.deleteByCapabilityId(capabilityId);

    // Log to mesh audit
    await meshAuditLogs.log({
      eventType: MESH_AUDIT_EVENTS.CAPABILITY_REVOKED,
      actorId: revokedBy,
      targetId: capabilityId,
      ipAddress: req.ip,
      success: true,
      source: 'relay-server',
      details: { reason, originalExpiry }
    });

    console.log(`[revocation] Revoked capability ${capabilityId.slice(0, 8)} by ${revokedBy.slice(0, 8)} (persisted)`);

    res.json({
      success: true,
      revocationId: capabilityId
    });
  } catch (err) {
    console.error('[revocation] Failed to persist revocation:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to persist revocation'
    });
  }
});

/**
 * GET /relay/revocation/:capabilityId
 * Check if a capability is revoked
 *
 * Uses Bloom filter for fast rejection, then checks cache, then database.
 */
router.get('/revocation/:capabilityId', validate({ params: capabilityIdParamSchema }), async (req, res) => {
  const { capabilityId } = req.validatedParams;

  // Fast path: Bloom filter says definitely not revoked
  if (!bloomMightContain(capabilityId)) {
    return res.json({ revoked: false, source: 'bloom-filter' });
  }

  // Check cache first
  const cached = revocationCache.get(capabilityId);
  if (cached) {
    return res.json({
      revoked: true,
      revokedAt: cached.revokedAt,
      revokedBy: cached.revokedBy,
      reason: cached.reason,
      source: 'cache'
    });
  }

  try {
    // Check database (authoritative source)
    const record = await capabilityRevocations.findByCapabilityId(capabilityId);

    if (record) {
      // Update cache
      const revocationRecord = {
        capabilityId: record.capability_id,
        revokedBy: record.issuer_public_key,
        reason: record.reason,
        revokedAt: record.revoked_at.toISOString()
      };
      cacheRevocation(capabilityId, revocationRecord);

      return res.json({
        revoked: true,
        revokedAt: revocationRecord.revokedAt,
        revokedBy: revocationRecord.revokedBy,
        reason: revocationRecord.reason,
        source: 'database'
      });
    }

    // Bloom filter false positive
    res.json({ revoked: false, source: 'database' });
  } catch (err) {
    console.error('[revocation] Database check failed:', err);
    // Fail open with warning (security tradeoff: availability vs strictness)
    res.json({ revoked: false, source: 'error', warning: 'Database unavailable' });
  }
});

/**
 * POST /relay/check-revocations
 * Batch check multiple capability revocations
 *
 * Body: { capabilityIds: string[] }
 *
 * Uses Bloom filter to pre-filter, then batch checks database for potential matches.
 */
router.post('/check-revocations', validate({ body: batchRevocationCheckSchema }), async (req, res) => {
  const { capabilityIds } = req.validatedBody;

  const results = {};
  const toCheckInDb = [];

  // First pass: use Bloom filter and cache
  for (const id of capabilityIds) {
    if (!bloomMightContain(id)) {
      // Definitely not revoked
      results[id] = { revoked: false };
    } else {
      // Check cache
      const cached = revocationCache.get(id);
      if (cached) {
        results[id] = {
          revoked: true,
          revokedAt: cached.revokedAt,
          reason: cached.reason
        };
      } else {
        // Need to check database
        toCheckInDb.push(id);
      }
    }
  }

  // Batch check database for remaining IDs
  if (toCheckInDb.length > 0) {
    try {
      const dbResults = await capabilityRevocations.batchCheckRevoked(toCheckInDb);
      for (const [id, result] of Object.entries(dbResults)) {
        results[id] = result;
        // Update cache for revoked items
        if (result.revoked) {
          cacheRevocation(id, {
            capabilityId: id,
            revokedAt: result.revokedAt,
            reason: result.reason
          });
        }
      }
    } catch (err) {
      console.error('[revocation] Batch database check failed:', err);
      // Mark unchecked IDs as unknown (fail open)
      for (const id of toCheckInDb) {
        if (!(id in results)) {
          results[id] = { revoked: false, warning: 'Database unavailable' };
        }
      }
    }
  }

  res.json({ results });
});

/**
 * GET /relay/revocation-stats
 * Get revocation statistics
 */
router.get('/revocation-stats', async (req, res) => {
  try {
    const [dbCount, snapshotCount] = await Promise.all([
      capabilityRevocations.count(),
      cachedSnapshots.count()
    ]);
    res.json({
      totalRevocations: dbCount,
      bloomFilterItems: bloomItemCount,
      cacheSize: revocationCache.size,
      totalSnapshots: snapshotCount,
      bloomInitialized
    });
  } catch (err) {
    console.error('[revocation] Failed to get stats:', err);
    res.json({
      totalRevocations: bloomItemCount, // Fallback to bloom count
      bloomFilterItems: bloomItemCount,
      cacheSize: revocationCache.size,
      totalSnapshots: 0,
      bloomInitialized,
      warning: 'Database unavailable'
    });
  }
});

/**
 * POST /relay/snapshots
 * Store a cached snapshot (for CACHED tier)
 *
 * Body: CachedSnapshot object with recipientPublicKey
 */
router.post('/snapshots', validate({ body: snapshotSchema }), async (req, res) => {
  const snapshot = req.validatedBody;

  // Check if capability is revoked (using Bloom filter + DB)
  if (bloomMightContain(snapshot.capabilityId)) {
    try {
      const isRevoked = await capabilityRevocations.isRevoked(snapshot.capabilityId);
      if (isRevoked) {
        return res.status(400).json({
          success: false,
          error: 'Cannot store snapshot for revoked capability'
        });
      }
    } catch (err) {
      console.error('[snapshots] Revocation check failed:', err);
      // Fail closed for security - don't store if we can't verify
      return res.status(500).json({
        success: false,
        error: 'Cannot verify revocation status'
      });
    }
  }

  // Verify snapshot signature
  const signatureData = `${snapshot.capabilityId}:${snapshot.encryptedData}:${snapshot.ephemeralPublicKey}`;
  if (!verifySignature(signatureData, snapshot.signature, snapshot.issuerPublicKey)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid snapshot signature'
    });
  }

  // Check expiry
  if (new Date(snapshot.expiresAt).getTime() < Date.now()) {
    return res.status(400).json({
      success: false,
      error: 'Snapshot has already expired'
    });
  }

  try {
    // Store snapshot to PostgreSQL
    await cachedSnapshots.upsert({
      capabilityId: snapshot.capabilityId,
      recipientPublicKey: snapshot.recipientPublicKey,
      issuerPublicKey: snapshot.issuerPublicKey,
      encryptedData: snapshot.encryptedData,
      ephemeralPublicKey: snapshot.ephemeralPublicKey,
      nonce: snapshot.nonce,
      tag: snapshot.tag,
      signature: snapshot.signature,
      expiresAt: new Date(snapshot.expiresAt)
    });

    console.log(`[snapshots] Stored snapshot for ${snapshot.capabilityId.slice(0, 8)} (persisted)`);

    res.json({ success: true });
  } catch (err) {
    console.error('[snapshots] Failed to store snapshot:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to store snapshot'
    });
  }
});

/**
 * GET /relay/snapshots/:capabilityId
 * Retrieve a cached snapshot
 */
router.get('/snapshots/:capabilityId', validate({ params: capabilityIdParamSchema }), async (req, res) => {
  const { capabilityId } = req.validatedParams;

  // Check if capability is revoked (using Bloom filter + DB)
  if (bloomMightContain(capabilityId)) {
    try {
      const isRevoked = await capabilityRevocations.isRevoked(capabilityId);
      if (isRevoked) {
        // Also delete the snapshot since capability is revoked
        await cachedSnapshots.deleteByCapabilityId(capabilityId);
        return res.status(404).json({ error: 'Capability has been revoked' });
      }
    } catch (err) {
      console.error('[snapshots] Revocation check failed:', err);
      // Fail closed for security
      return res.status(500).json({ error: 'Cannot verify revocation status' });
    }
  }

  try {
    const row = await cachedSnapshots.findByCapabilityId(capabilityId);

    if (!row) {
      return res.status(404).json({ error: 'Snapshot not found' });
    }

    // Convert DB row to snapshot format
    const snapshot = {
      capabilityId: row.capability_id,
      encryptedData: row.encrypted_data,
      ephemeralPublicKey: row.ephemeral_public_key,
      nonce: row.nonce,
      tag: row.tag,
      signature: row.signature,
      issuerPublicKey: row.issuer_public_key,
      recipientPublicKey: row.recipient_public_key,
      createdAt: row.created_at.toISOString(),
      expiresAt: row.expires_at.toISOString()
    };

    res.json(snapshot);
  } catch (err) {
    console.error('[snapshots] Failed to retrieve snapshot:', err);
    res.status(500).json({ error: 'Failed to retrieve snapshot' });
  }
});

/**
 * DELETE /relay/snapshots/:capabilityId
 * Delete a cached snapshot
 */
router.delete('/snapshots/:capabilityId', validate({ params: capabilityIdParamSchema }), async (req, res) => {
  const { capabilityId } = req.validatedParams;

  try {
    await cachedSnapshots.deleteByCapabilityId(capabilityId);
    res.json({ success: true });
  } catch (err) {
    console.error('[snapshots] Failed to delete snapshot:', err);
    res.status(500).json({ error: 'Failed to delete snapshot' });
  }
});

/**
 * POST /relay/snapshots/list
 * List available snapshots for a recipient
 *
 * Body: { recipientPublicKey, signature, timestamp }
 *
 * The recipient must prove ownership of their public key by signing the request.
 * This prevents enumeration attacks.
 */
router.post('/snapshots/list', validate({ body: snapshotListSchema }), async (req, res) => {
  const { recipientPublicKey, signature, timestamp } = req.validatedBody;

  // Verify timestamp is recent (within 5 minutes)
  const requestTime = new Date(timestamp).getTime();
  const now = Date.now();
  if (Math.abs(now - requestTime) > 5 * 60 * 1000) {
    return res.status(400).json({
      success: false,
      error: 'Request timestamp is too old or in the future'
    });
  }

  // Verify signature proves ownership of recipientPublicKey
  const signPayload = JSON.stringify({
    action: 'list-snapshots',
    recipientPublicKey,
    timestamp
  });

  if (!verifySignature(signPayload, signature, recipientPublicKey)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid signature - must be signed by recipient'
    });
  }

  try {
    const rows = await cachedSnapshots.listByRecipient(recipientPublicKey);

    // Filter out revoked capabilities
    const validRows = [];
    for (const row of rows) {
      if (bloomMightContain(row.capability_id)) {
        try {
          const isRevoked = await capabilityRevocations.isRevoked(row.capability_id);
          if (isRevoked) {
            // Clean up revoked snapshot
            await cachedSnapshots.deleteByCapabilityId(row.capability_id);
            continue;
          }
        } catch (err) {
          // Skip if we can't verify - fail closed
          console.warn('[snapshots] Revocation check failed for', row.capability_id);
          continue;
        }
      }
      validRows.push(row);
    }

    // Convert DB rows to snapshot format
    const snapshots = validRows.map(row => ({
      capabilityId: row.capability_id,
      encryptedData: row.encrypted_data,
      ephemeralPublicKey: row.ephemeral_public_key,
      nonce: row.nonce,
      tag: row.tag,
      signature: row.signature,
      issuerPublicKey: row.issuer_public_key,
      recipientPublicKey: row.recipient_public_key,
      createdAt: row.created_at.toISOString(),
      expiresAt: row.expires_at.toISOString()
    }));

    res.json({ success: true, snapshots });
  } catch (err) {
    console.error('[snapshots] Failed to list snapshots:', err);
    res.status(500).json({ error: 'Failed to list snapshots' });
  }
});

// Export for health check access
export function getRevocationCount() {
  return bloomItemCount;
}

let snapshotCountCache = 0;
let snapshotCountLastUpdate = 0;

export async function getSnapshotCount() {
  // Cache for 30 seconds to avoid hitting DB on every health check
  if (Date.now() - snapshotCountLastUpdate < 30000) {
    return snapshotCountCache;
  }
  try {
    snapshotCountCache = await cachedSnapshots.count();
    snapshotCountLastUpdate = Date.now();
    return snapshotCountCache;
  } catch (err) {
    console.error('[snapshots] Failed to get count:', err);
    return snapshotCountCache;
  }
}

export function isBloomInitialized() {
  return bloomInitialized;
}

/**
 * Cleanup expired revocations from database and rebuild Bloom filter.
 * Run this periodically (e.g., daily cron job).
 */
export async function cleanupExpiredRevocations() {
  try {
    const removedCount = await capabilityRevocations.cleanupExpired();
    if (removedCount > 0) {
      console.log(`[revocation] Cleaned up ${removedCount} expired revocations`);
      // Rebuild Bloom filter
      bloomFilter.fill(0);
      bloomItemCount = 0;
      revocationCache.clear();
      await initRevocationBloomFilter();
    }
    return removedCount;
  } catch (err) {
    console.error('[revocation] Cleanup failed:', err);
    return 0;
  }
}

export default router;
