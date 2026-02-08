/**
 * Relay Status Routes
 *
 * Exposes relay health and revocation status to the UI.
 */
import { Router } from "express";
import {
  checkRelayHealth,
  getRelayStatus,
  checkRevocation,
  checkRevocations,
  getRevocationStats,
  getSnapshot,
  getSnapshotStats,
  triggerSnapshotRefresh,
} from "../lib/relay.js";
import { requireUser, requireAdmin } from "../middleware/auth.js";
import { detectTenant } from "../middleware/tenant-context.js";

const router = Router();

/**
 * GET /api/relay/health
 * Get relay health status (cached + fresh check)
 */
router.get("/health", async (req, res) => {
  try {
    const health = await checkRelayHealth();
    res.json(health);
  } catch (err) {
    res.status(500).json({
      healthy: false,
      error: err.message,
    });
  }
});

/**
 * GET /api/relay/status
 * Get cached relay status (fast, no network call)
 */
router.get("/status", (req, res) => {
  res.json(getRelayStatus());
});

/**
 * GET /api/relay/revocation/:capabilityId
 * Check if a capability is revoked (requires auth)
 */
router.get("/revocation/:capabilityId", requireUser, detectTenant, async (req, res) => {
  try {
    const result = await checkRevocation(req.params.capabilityId);
    res.json(result);
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

/**
 * POST /api/relay/check-revocations
 * Batch check revocations (requires auth)
 */
router.post("/check-revocations", requireUser, detectTenant, async (req, res) => {
  const { capabilityIds } = req.body;

  if (!Array.isArray(capabilityIds)) {
    return res.status(400).json({ error: "capabilityIds must be an array" });
  }

  if (capabilityIds.length > 100) {
    return res.status(400).json({ error: "Maximum 100 capability IDs per request" });
  }

  try {
    const result = await checkRevocations(capabilityIds);
    res.json(result);
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

/**
 * GET /api/relay/stats
 * Get revocation statistics (admin only)
 */
router.get("/stats", requireUser, detectTenant, requireAdmin, async (req, res) => {
  try {
    const stats = await getRevocationStats();
    res.json(stats);
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

// ============================================================
// SNAPSHOT ENDPOINTS (CACHED tier sharing)
// ============================================================

/**
 * GET /api/relay/snapshots/:capabilityId
 * Get a specific cached snapshot
 */
router.get("/snapshots/:capabilityId", requireUser, detectTenant, async (req, res) => {
  try {
    const result = await getSnapshot(req.params.capabilityId);
    if (!result.success) {
      return res.status(404).json(result);
    }
    res.json(result);
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

/**
 * GET /api/relay/snapshot-stats
 * Get snapshot statistics
 */
router.get("/snapshot-stats", requireUser, detectTenant, async (req, res) => {
  try {
    const stats = await getSnapshotStats();
    res.json(stats);
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

/**
 * POST /api/relay/snapshots/sync
 * Trigger a snapshot refresh on the user's container
 * This will refresh all due CACHED tier snapshots and push them to the relay
 */
router.post("/snapshots/sync", requireUser, detectTenant, async (req, res) => {
  try {
    const result = await triggerSnapshotRefresh(req.user.id);
    if (!result.success) {
      return res.status(503).json(result);
    }
    res.json(result);
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

export default router;
