// Unified shares routes (replaces peer.js + org grants)
import { Router } from "express";
import { users, audit, shares, peerGrants } from "../db/index.js";
import { broadcastToUser } from "../lib/sse.js";
import { requireUser } from "../middleware/auth.js";
import { detectTenant } from "../middleware/tenant-context.js";

const router = Router();

// ============================================================
// UNIFIED SHARE ENDPOINTS
// ============================================================

// List shares for a resource
router.get("/resource/:resourceId", requireUser, detectTenant, async (req, res) => {
  try {
    const shareList = await shares.listByResource(req.params.resourceId);
    res.json({ shares: shareList });
  } catch (err) {
    console.error("List shares for resource error:", err);
    res.status(500).json({ error: "Failed to list shares" });
  }
});

// List available shares for current user (pending)
router.get("/available", requireUser, detectTenant, async (req, res) => {
  try {
    const available = await shares.listAvailableForUser(req.user.id);
    res.json({ shares: available });
  } catch (err) {
    console.error("List available shares error:", err);
    res.status(500).json({ error: "Failed to list available shares" });
  }
});

// List connected shares for current user
router.get("/connected", requireUser, detectTenant, async (req, res) => {
  try {
    const connected = await shares.listConnectedForUser(req.user.id);
    res.json({ shares: connected });
  } catch (err) {
    console.error("List connected shares error:", err);
    res.status(500).json({ error: "Failed to list connected shares" });
  }
});

// Connect to a share
router.post("/:shareId/connect", requireUser, detectTenant, async (req, res) => {
  try {
    const share = await shares.findById(req.params.shareId);

    if (!share) {
      return res.status(404).json({ error: "Share not found" });
    }

    if (share.user_id !== req.user.id) {
      return res.status(403).json({ error: "Not your share" });
    }

    if (share.status === "revoked") {
      return res.status(400).json({ error: "Access has been revoked" });
    }

    const updated = await shares.connect(req.params.shareId);

    await audit.log(
      req.user.id,
      "share.connected",
      {
        shareId: req.params.shareId,
        resourceId: share.resource_id,
        groupId: share.group_id,
      },
      req.ip,
    );

    res.json({ success: true, share: updated });
  } catch (err) {
    console.error("Connect share error:", err);
    res.status(500).json({ error: "Failed to connect to share" });
  }
});

// Disconnect from a share
router.delete("/:shareId/disconnect", requireUser, detectTenant, async (req, res) => {
  try {
    const share = await shares.findById(req.params.shareId);

    if (!share) {
      return res.status(404).json({ error: "Share not found" });
    }

    if (share.user_id !== req.user.id) {
      return res.status(403).json({ error: "Not your share" });
    }

    const updated = await shares.disconnect(req.params.shareId);

    await audit.log(
      req.user.id,
      "share.disconnected",
      {
        shareId: req.params.shareId,
        resourceId: share.resource_id,
        groupId: share.group_id,
      },
      req.ip,
    );

    res.json({ success: true, share: updated });
  } catch (err) {
    console.error("Disconnect share error:", err);
    res.status(500).json({ error: "Failed to disconnect from share" });
  }
});

// Revoke a share (owner only)
router.delete("/:shareId", requireUser, detectTenant, async (req, res) => {
  try {
    const share = await shares.findById(req.params.shareId);

    if (!share) {
      return res.status(404).json({ error: "Share not found" });
    }

    // Check if user is the grantor/owner
    if (share.granted_by !== req.user.id) {
      return res.status(403).json({ error: "Not your share to revoke" });
    }

    const updated = await shares.revoke(req.params.shareId);

    await audit.log(
      req.user.id,
      "share.revoked",
      {
        shareId: req.params.shareId,
        resourceId: share.resource_id,
        userId: share.user_id,
      },
      req.ip,
    );

    res.json({ success: true, share: updated });
  } catch (err) {
    console.error("Revoke share error:", err);
    res.status(500).json({ error: "Failed to revoke share" });
  }
});

// ============================================================
// PEER SHARING ENDPOINTS (capability-based)
// These are legacy-compatible endpoints for peer-to-peer sharing
// ============================================================

// Request access to another user's capability
router.post("/peer/requests", requireUser, detectTenant, async (req, res) => {
  try {
    const { grantorEmail, capability, reason } = req.body;

    if (!grantorEmail || !capability) {
      return res.status(400).json({ error: "Grantor email and capability required" });
    }

    const grantor = await users.findByEmail(grantorEmail);
    if (!grantor) {
      return res.status(404).json({ error: "User not found" });
    }

    if (grantor.id === req.user.id) {
      return res.status(400).json({ error: "Cannot request access to your own data" });
    }

    const existing = await peerGrants.findByGrantorGranteeCapability(
      grantor.id,
      req.user.id,
      capability,
    );

    if (existing && existing.status === "approved") {
      if (!existing.expires_at || new Date(existing.expires_at) > new Date()) {
        return res.status(400).json({ error: "You already have access to this capability" });
      }
    }

    const grant = await peerGrants.create({
      grantorId: grantor.id,
      granteeId: req.user.id,
      capability,
      reason,
    });

    await audit.log(
      req.user.id,
      "peer.request.created",
      {
        grantorId: grantor.id,
        capability,
        reason,
      },
      req.ip,
      grantor.id,
    );

    broadcastToUser(grantor.id, "peer_request", {
      id: grant.id,
      grantee_name: req.user.name,
      grantee_email: req.user.email,
      capability,
      reason,
      created_at: grant.created_at,
    });

    res.json({
      success: true,
      request: {
        id: grant.id,
        status: grant.status,
        capability: grant.capability,
        created_at: grant.created_at,
      },
    });
  } catch (err) {
    console.error("Create peer request error:", err);
    res.status(500).json({ error: "Failed to create access request" });
  }
});

// List incoming requests (waiting for my approval)
router.get("/peer/requests/incoming", requireUser, detectTenant, async (req, res) => {
  try {
    const requests = await peerGrants.listIncomingRequests(req.user.id);
    res.json({ requests });
  } catch (err) {
    console.error("List incoming requests error:", err);
    res.status(500).json({ error: "Failed to list incoming requests" });
  }
});

// List outgoing requests (my requests to others)
router.get("/peer/requests/outgoing", requireUser, detectTenant, async (req, res) => {
  try {
    const requests = await peerGrants.listOutgoingRequests(req.user.id);
    res.json({ requests });
  } catch (err) {
    console.error("List outgoing requests error:", err);
    res.status(500).json({ error: "Failed to list outgoing requests" });
  }
});

// Approve a peer request
router.post("/peer/grants/:id/approve", requireUser, detectTenant, async (req, res) => {
  try {
    const grant = await peerGrants.findById(req.params.id);

    if (!grant) {
      return res.status(404).json({ error: "Request not found" });
    }

    if (grant.grantor_id !== req.user.id) {
      return res.status(403).json({ error: "Not your request to approve" });
    }

    if (grant.status !== "pending") {
      return res.status(400).json({ error: "Request is not pending" });
    }

    const { duration } = req.body;
    let expiresAt = null;

    if (duration === "day") {
      expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
    } else if (duration === "week") {
      expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    } else if (duration === "month") {
      expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    }

    const updated = await peerGrants.approve(req.params.id, expiresAt);

    await audit.log(
      req.user.id,
      "peer.request.approved",
      {
        grantId: req.params.id,
        granteeId: grant.grantee_id,
        capability: grant.capability,
        duration: duration || "always",
        expiresAt,
      },
      req.ip,
      grant.grantee_id,
    );

    broadcastToUser(grant.grantee_id, "peer_approved", {
      id: grant.id,
      grantor_name: req.user.name,
      capability: grant.capability,
      expires_at: expiresAt,
    });

    res.json({ success: true, grant: updated });
  } catch (err) {
    console.error("Approve peer request error:", err);
    res.status(500).json({ error: "Failed to approve request" });
  }
});

// Deny a peer request
router.post("/peer/grants/:id/deny", requireUser, detectTenant, async (req, res) => {
  try {
    const grant = await peerGrants.findById(req.params.id);

    if (!grant) {
      return res.status(404).json({ error: "Request not found" });
    }

    if (grant.grantor_id !== req.user.id) {
      return res.status(403).json({ error: "Not your request to deny" });
    }

    if (grant.status !== "pending") {
      return res.status(400).json({ error: "Request is not pending" });
    }

    const updated = await peerGrants.deny(req.params.id);

    await audit.log(
      req.user.id,
      "peer.request.denied",
      {
        grantId: req.params.id,
        granteeId: grant.grantee_id,
        capability: grant.capability,
      },
      req.ip,
      grant.grantee_id,
    );

    broadcastToUser(grant.grantee_id, "peer_denied", {
      id: grant.id,
      grantor_name: req.user.name,
      capability: grant.capability,
    });

    res.json({ success: true, grant: updated });
  } catch (err) {
    console.error("Deny peer request error:", err);
    res.status(500).json({ error: "Failed to deny request" });
  }
});

// Revoke a peer grant
router.delete("/peer/grants/:id", requireUser, detectTenant, async (req, res) => {
  try {
    const grant = await peerGrants.findById(req.params.id);

    if (!grant) {
      return res.status(404).json({ error: "Grant not found" });
    }

    if (grant.grantor_id !== req.user.id) {
      return res.status(403).json({ error: "Not your grant to revoke" });
    }

    if (grant.status !== "approved") {
      return res.status(400).json({ error: "Grant is not active" });
    }

    const updated = await peerGrants.revoke(req.params.id);

    await audit.log(
      req.user.id,
      "peer.grant.revoked",
      {
        grantId: req.params.id,
        granteeId: grant.grantee_id,
        capability: grant.capability,
      },
      req.ip,
      grant.grantee_id,
    );

    broadcastToUser(grant.grantee_id, "peer_revoked", {
      id: grant.id,
      grantor_name: req.user.name,
      capability: grant.capability,
    });

    res.json({ success: true, grant: updated });
  } catch (err) {
    console.error("Revoke peer grant error:", err);
    res.status(500).json({ error: "Failed to revoke grant" });
  }
});

// List grants to me (what I can access)
router.get("/peer/grants/to-me", requireUser, detectTenant, async (req, res) => {
  try {
    const grants = await peerGrants.listGrantsToMe(req.user.id);
    res.json({ grants });
  } catch (err) {
    console.error("List grants to me error:", err);
    res.status(500).json({ error: "Failed to list grants" });
  }
});

// List grants from me (what I've shared)
router.get("/peer/grants/from-me", requireUser, detectTenant, async (req, res) => {
  try {
    const grants = await peerGrants.listGrantsFromMe(req.user.id);
    res.json({ grants });
  } catch (err) {
    console.error("List grants from me error:", err);
    res.status(500).json({ error: "Failed to list grants" });
  }
});

// Check if grantee has access (for inter-container gateway)
router.get("/peer/grants/check", requireUser, detectTenant, async (req, res) => {
  try {
    const { grantorId, capability } = req.query;

    if (!grantorId || !capability) {
      return res.status(400).json({ error: "Grantor ID and capability required" });
    }

    const hasAccess = await peerGrants.hasAccess(grantorId, req.user.id, capability);

    res.json({ hasAccess });
  } catch (err) {
    console.error("Check peer access error:", err);
    res.status(500).json({ error: "Failed to check access" });
  }
});

export default router;
