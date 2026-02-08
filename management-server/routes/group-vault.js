import crypto from "crypto";
// Group vault threshold unlock routes
// Implements 2-of-N admin approval for group vault access
import { Router } from "express";
import {
  audit,
  groupMemberships,
  groupUnlockRequests,
  groupThreshold,
  encrypt,
} from "../db/index.js";
import {
  createGroupVaultSession,
  getGroupVaultSession,
  lockGroupVault,
  isGroupVaultUnlocked,
  getGroupVaultTimeRemaining,
  GROUP_VAULT_UNLOCK_DURATION_MS,
  GROUP_VAULT_UNLOCK_DURATION_SEC,
} from "../lib/group-vault-sessions.js";
import { requireUser } from "../middleware/auth.js";
import { requireGroupAdmin } from "../middleware/group-auth.js";
import { detectTenant } from "../middleware/tenant-context.js";

const router = Router();

// Request unlock expiration (24 hours to collect approvals)
const UNLOCK_REQUEST_EXPIRY_MS = 24 * 60 * 60 * 1000;

/**
 * GET /api/groups/:groupId/vault/unlock-status
 * Check current vault unlock status for the group
 */
router.get(
  "/:groupId/vault/unlock-status",
  requireUser,
  detectTenant,
  requireGroupAdmin,
  async (req, res) => {
    try {
      const { groupId } = req.params;

      // Get threshold configuration
      const thresholdConfig = await groupThreshold.get(groupId);
      const adminCount = await groupThreshold.getAdminCount(groupId);
      const threshold = thresholdConfig?.unlock_threshold || 2;

      // Check if currently unlocked
      const session = getGroupVaultSession(groupId);
      const isUnlocked = session !== null;

      // Get pending unlock requests
      const pendingRequests = await groupUnlockRequests.findPendingForOrg(groupId);

      // Get active unlock session if exists
      const activeRequest = await groupUnlockRequests.findActiveForOrg(groupId);

      // For each pending request, get approval count
      const pendingWithApprovals = await Promise.all(
        pendingRequests.map(async (request) => {
          const approvalCount = await groupUnlockRequests.countApprovals(request.id);
          const approvals = await groupUnlockRequests.getApprovals(request.id);
          const hasApproved = await groupUnlockRequests.hasApproved(request.id, req.user.id);
          return {
            ...request,
            approvalCount,
            approvals,
            hasApproved,
            remainingApprovals: Math.max(0, request.required_approvals - approvalCount),
          };
        }),
      );

      res.json({
        isUnlocked,
        expiresIn: isUnlocked ? getGroupVaultTimeRemaining(groupId) : 0,
        expiresAt: session?.expiresAt ? new Date(session.expiresAt) : null,
        threshold,
        adminCount,
        thresholdAchievable: adminCount >= threshold,
        pendingRequests: pendingWithApprovals,
        activeRequest: activeRequest
          ? {
              id: activeRequest.id,
              requestedBy: activeRequest.requester_name,
              unlockedAt: activeRequest.unlocked_at,
              expiresAt: activeRequest.expires_at,
            }
          : null,
      });
    } catch (err) {
      console.error("Get group vault status error:", err);
      res.status(500).json({ error: "Failed to get vault status" });
    }
  },
);

/**
 * POST /api/groups/:groupId/vault/request-unlock
 * Admin requests to unlock the group vault (first step of threshold unlock)
 */
router.post(
  "/:groupId/vault/request-unlock",
  requireUser,
  detectTenant,
  requireGroupAdmin,
  async (req, res) => {
    try {
      const { groupId } = req.params;
      const { reason } = req.body;

      // Check if already unlocked
      if (isGroupVaultUnlocked(groupId)) {
        return res.status(400).json({ error: "Vault is already unlocked" });
      }

      // Check for existing pending request
      const existingRequests = await groupUnlockRequests.findPendingForOrg(groupId);
      if (existingRequests.length > 0) {
        return res.status(400).json({
          error: "A pending unlock request already exists",
          requestId: existingRequests[0].id,
        });
      }

      // Get threshold configuration
      const thresholdConfig = await groupThreshold.get(groupId);
      const adminCount = await groupThreshold.getAdminCount(groupId);
      const threshold = thresholdConfig?.unlock_threshold || 2;

      // Validate threshold is achievable
      if (adminCount < threshold) {
        return res.status(400).json({
          error: `Cannot unlock: need ${threshold} admins but only ${adminCount} exist`,
          threshold,
          adminCount,
        });
      }

      // Create unlock request
      const expiresAt = new Date(Date.now() + UNLOCK_REQUEST_EXPIRY_MS);
      const request = await groupUnlockRequests.create({
        groupId,
        requestedBy: req.user.id,
        reason: reason || "Vault access requested",
        requiredApprovals: threshold,
        expiresAt,
      });

      // The requester automatically approves
      await groupUnlockRequests.addApproval(request.id, req.user.id);
      const approvalCount = 1;

      await audit.log(
        req.user.id,
        "group.vault.unlock_requested",
        {
          groupId,
          requestId: request.id,
          reason,
          threshold,
        },
        req.ip,
      );

      // Check if threshold is already met (edge case: threshold = 1)
      if (approvalCount >= threshold) {
        return await completeUnlock(request.id, groupId, req, res);
      }

      res.json({
        success: true,
        requestId: request.id,
        message: `Unlock request created. Need ${threshold - approvalCount} more approval(s).`,
        approvalCount,
        requiredApprovals: threshold,
        expiresAt,
      });
    } catch (err) {
      console.error("Request group vault unlock error:", err);
      res.status(500).json({ error: "Failed to create unlock request" });
    }
  },
);

/**
 * POST /api/groups/:groupId/vault/approve/:requestId
 * Another admin approves the unlock request
 */
router.post(
  "/:groupId/vault/approve/:requestId",
  requireUser,
  detectTenant,
  requireGroupAdmin,
  async (req, res) => {
    try {
      const { groupId, requestId } = req.params;

      // Find the request
      const request = await groupUnlockRequests.findById(requestId);
      if (!request) {
        return res.status(404).json({ error: "Unlock request not found" });
      }

      // Validate it belongs to this group
      if (request.group_id !== groupId) {
        return res.status(403).json({ error: "Request does not belong to this group" });
      }

      // Check status
      if (request.status !== "pending") {
        return res.status(400).json({ error: `Request is ${request.status}, not pending` });
      }

      // Check if expired
      if (new Date(request.expires_at) < new Date()) {
        await groupUnlockRequests.cancel(requestId);
        return res.status(400).json({ error: "Unlock request has expired" });
      }

      // Check if already approved by this user
      const hasApproved = await groupUnlockRequests.hasApproved(requestId, req.user.id);
      if (hasApproved) {
        return res.status(400).json({ error: "You have already approved this request" });
      }

      // Add approval
      await groupUnlockRequests.addApproval(requestId, req.user.id);
      const approvalCount = await groupUnlockRequests.countApprovals(requestId);

      await audit.log(
        req.user.id,
        "group.vault.unlock_approved",
        {
          groupId,
          requestId,
          approvalCount,
          requiredApprovals: request.required_approvals,
        },
        req.ip,
      );

      // Check if threshold is met
      if (approvalCount >= request.required_approvals) {
        return await completeUnlock(requestId, groupId, req, res);
      }

      const remaining = request.required_approvals - approvalCount;
      res.json({
        success: true,
        message: `Approval recorded. Need ${remaining} more approval(s).`,
        approvalCount,
        requiredApprovals: request.required_approvals,
        remainingApprovals: remaining,
      });
    } catch (err) {
      console.error("Approve group vault unlock error:", err);
      res.status(500).json({ error: "Failed to approve unlock request" });
    }
  },
);

/**
 * POST /api/groups/:groupId/vault/lock
 * Force lock the group vault (any admin can do this)
 */
router.post(
  "/:groupId/vault/lock",
  requireUser,
  detectTenant,
  requireGroupAdmin,
  async (req, res) => {
    try {
      const { groupId } = req.params;

      // Check if currently unlocked
      const session = getGroupVaultSession(groupId);
      if (!session) {
        return res.status(400).json({ error: "Vault is not currently unlocked" });
      }

      // Lock the vault
      lockGroupVault(groupId);

      // Update the unlock request status
      if (session.requestId) {
        await groupUnlockRequests.lock(session.requestId);
      }

      await audit.log(
        req.user.id,
        "group.vault.locked",
        {
          groupId,
          requestId: session.requestId,
          lockedBy: req.user.id,
        },
        req.ip,
      );

      res.json({
        success: true,
        message: "Vault has been locked",
      });
    } catch (err) {
      console.error("Lock group vault error:", err);
      res.status(500).json({ error: "Failed to lock vault" });
    }
  },
);

/**
 * POST /api/groups/:groupId/vault/cancel/:requestId
 * Cancel a pending unlock request (requester or any admin)
 */
router.post(
  "/:groupId/vault/cancel/:requestId",
  requireUser,
  detectTenant,
  requireGroupAdmin,
  async (req, res) => {
    try {
      const { groupId, requestId } = req.params;

      const request = await groupUnlockRequests.findById(requestId);
      if (!request) {
        return res.status(404).json({ error: "Unlock request not found" });
      }

      if (request.group_id !== groupId) {
        return res.status(403).json({ error: "Request does not belong to this group" });
      }

      if (request.status !== "pending") {
        return res.status(400).json({ error: `Cannot cancel: request is ${request.status}` });
      }

      await groupUnlockRequests.cancel(requestId);

      await audit.log(
        req.user.id,
        "group.vault.unlock_cancelled",
        {
          groupId,
          requestId,
          cancelledBy: req.user.id,
        },
        req.ip,
      );

      res.json({
        success: true,
        message: "Unlock request cancelled",
      });
    } catch (err) {
      console.error("Cancel group vault unlock error:", err);
      res.status(500).json({ error: "Failed to cancel unlock request" });
    }
  },
);

/**
 * PUT /api/groups/:groupId/vault/threshold
 * Update the unlock threshold (requires current threshold approval or single admin if only one exists)
 */
router.put(
  "/:groupId/vault/threshold",
  requireUser,
  detectTenant,
  requireGroupAdmin,
  async (req, res) => {
    try {
      const { groupId } = req.params;
      const { threshold } = req.body;

      if (typeof threshold !== "number" || threshold < 1) {
        return res.status(400).json({ error: "Threshold must be a positive integer" });
      }

      const adminCount = await groupThreshold.getAdminCount(groupId);
      if (threshold > adminCount) {
        return res.status(400).json({
          error: `Threshold cannot exceed admin count (${adminCount})`,
          adminCount,
        });
      }

      await groupThreshold.set(groupId, threshold);

      await audit.log(
        req.user.id,
        "group.vault.threshold_updated",
        {
          groupId,
          threshold,
          adminCount,
        },
        req.ip,
      );

      res.json({
        success: true,
        threshold,
        adminCount,
        message: `Unlock threshold set to ${threshold} of ${adminCount} admins`,
      });
    } catch (err) {
      console.error("Update group vault threshold error:", err);
      res.status(500).json({ error: "Failed to update threshold" });
    }
  },
);

/**
 * GET /api/groups/:groupId/vault/history
 * Get unlock request history for the group
 */
router.get(
  "/:groupId/vault/history",
  requireUser,
  detectTenant,
  requireGroupAdmin,
  async (req, res) => {
    try {
      const { groupId } = req.params;
      const limit = parseInt(req.query.limit) || 50;

      const requests = await groupUnlockRequests.listForOrg(groupId, limit);

      // Add approval details
      const withApprovals = await Promise.all(
        requests.map(async (request) => {
          const approvals = await groupUnlockRequests.getApprovals(request.id);
          return {
            ...request,
            approvals,
          };
        }),
      );

      res.json({ requests: withApprovals });
    } catch (err) {
      console.error("Get group vault history error:", err);
      res.status(500).json({ error: "Failed to get vault history" });
    }
  },
);

/**
 * GET /api/groups/:groupId/vault/admins
 * List admins who can approve unlock requests
 */
router.get(
  "/:groupId/vault/admins",
  requireUser,
  detectTenant,
  requireGroupAdmin,
  async (req, res) => {
    try {
      const { groupId } = req.params;

      const admins = await groupThreshold.listAdmins(groupId);
      const thresholdConfig = await groupThreshold.get(groupId);
      const threshold = thresholdConfig?.unlock_threshold || 2;

      res.json({
        admins,
        adminCount: admins.length,
        threshold,
        thresholdAchievable: admins.length >= threshold,
      });
    } catch (err) {
      console.error("Get group vault admins error:", err);
      res.status(500).json({ error: "Failed to get admins" });
    }
  },
);

/**
 * Helper: Complete the unlock process when threshold is met
 */
async function completeUnlock(requestId, groupId, req, res) {
  try {
    // Get all approvers
    const approvals = await groupUnlockRequests.getApprovals(requestId);
    const approverIds = approvals.map((a) => a.approved_by);

    // Create session
    const { sessionKey, expiresAt } = createGroupVaultSession(groupId, requestId, approverIds);

    // Encrypt session key for storage (so it can be recovered if server restarts)
    const encryptedKey = encrypt(sessionKey);

    // Update request status
    const unlockExpiresAt = new Date(Date.now() + ORG_VAULT_UNLOCK_DURATION_MS);
    await groupUnlockRequests.unlock(requestId, encryptedKey);

    await audit.log(
      req.user.id,
      "group.vault.unlocked",
      {
        groupId,
        requestId,
        approverCount: approverIds.length,
        expiresAt: unlockExpiresAt,
      },
      req.ip,
    );

    res.json({
      success: true,
      message: "Vault unlocked successfully",
      sessionKey,
      expiresAt: unlockExpiresAt,
      expiresIn: ORG_VAULT_UNLOCK_DURATION_SEC,
    });
  } catch (err) {
    console.error("Complete group vault unlock error:", err);
    res.status(500).json({ error: "Failed to complete unlock" });
  }
}

export default router;
