// User group routes (my-groups, resources)
// Note: Invite routes are in group-invites.js
import { Router } from "express";
import { audit, groupMemberships, shares } from "../db/index.js";
import { requireUser } from "../middleware/auth.js";
import { detectTenant } from "../middleware/tenant-context.js";

const router = Router();

// List user's groups
router.get("/my-groups", requireUser, detectTenant, async (req, res) => {
  try {
    const memberships = await groupMemberships.listByUser(req.user.id);
    res.json({ groups: memberships });
  } catch (err) {
    console.error("List my groups error:", err);
    res.status(500).json({ error: "Failed to list groups" });
  }
});

// List available resources (granted but not connected)
router.get("/available-resources", requireUser, detectTenant, async (req, res) => {
  try {
    const resources = await shares.listAvailableForUser(req.user.id);
    res.json({ resources });
  } catch (err) {
    console.error("List available resources error:", err);
    res.status(500).json({ error: "Failed to list available resources" });
  }
});

// List connected resources
router.get("/connected-resources", requireUser, detectTenant, async (req, res) => {
  try {
    const resources = await shares.listConnectedForUser(req.user.id);
    res.json({ resources });
  } catch (err) {
    console.error("List connected resources error:", err);
    res.status(500).json({ error: "Failed to list connected resources" });
  }
});

// Connect to a resource (opt-in)
router.post("/connect-resource/:shareId", requireUser, detectTenant, async (req, res) => {
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
    console.error("Connect resource error:", err);
    res.status(500).json({ error: "Failed to connect to resource" });
  }
});

// Disconnect from a resource (opt-out)
router.delete("/disconnect-resource/:shareId", requireUser, detectTenant, async (req, res) => {
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
    console.error("Disconnect resource error:", err);
    res.status(500).json({ error: "Failed to disconnect from resource" });
  }
});

// Note: Invite management routes are in group-invites.js to avoid duplication

export default router;
