// Resource shares routes (peer-to-peer integration sharing)
import { Router } from "express";
import { users, audit, integrations, resourceShares } from "../db/index.js";
import { broadcastToUser } from "../lib/sse.js";
import { requireUser } from "../middleware/auth.js";
import { detectTenant } from "../middleware/tenant-context.js";

const router = Router();

// Get icon for integration type
function getIntegrationIcon(provider) {
  const icons = {
    google: "📧",
    "google-calendar": "📅",
    "google-drive": "📁",
    outlook: "📧",
    "outlook-calendar": "📅",
    slack: "💬",
    github: "🐙",
    notion: "📝",
    openai: "🤖",
    anthropic: "🧠",
  };
  return icons[provider] || "🔌";
}

// Get display name for integration
function getIntegrationDisplayName(integration) {
  // Use provider email if available (e.g., "user@gmail.com")
  if (integration.provider_email) {
    return `${integration.provider} (${integration.provider_email})`;
  }
  // Otherwise just use provider name
  return integration.provider;
}

// List shareable resources (user's integrations)
router.get("/shareable-resources", requireUser, detectTenant, async (req, res) => {
  try {
    const userIntegrations = await integrations.listForUser(req.user.id);

    const resources = userIntegrations
      .filter((i) => i.status === "active")
      .map((i) => ({
        id: i.id,
        name: getIntegrationDisplayName(i),
        type: i.provider,
        icon: getIntegrationIcon(i.provider),
        source: "integration",
        sourceName: i.provider_email || i.provider,
      }));

    res.json({ resources });
  } catch (err) {
    console.error("List shareable resources error:", err);
    res.status(500).json({ error: "Failed to list shareable resources" });
  }
});

// Create a resource share (share an integration with another user)
router.post("/resource-shares", requireUser, detectTenant, async (req, res) => {
  try {
    const { resourceId, recipientEmail, tier, permissions, expiresAt } = req.body;

    if (!resourceId || !recipientEmail) {
      return res.status(400).json({ error: "Resource ID and recipient email are required" });
    }

    // Verify the integration exists and belongs to this user
    const integration = await integrations.findByUserAndProvider(req.user.id, null);
    const userIntegrations = await integrations.listForUser(req.user.id);
    const matchingIntegration = userIntegrations.find((i) => i.id === resourceId);

    if (!matchingIntegration) {
      return res.status(404).json({ error: "Integration not found" });
    }

    // Can't share with yourself
    if (recipientEmail.toLowerCase() === req.user.email.toLowerCase()) {
      return res.status(400).json({ error: "Cannot share with yourself" });
    }

    // Look up recipient (but sharing works even if they don't have an account yet)
    const recipient = await users.findByEmail(recipientEmail.toLowerCase());

    // Create the share
    const share = await resourceShares.create({
      integrationId: resourceId,
      ownerId: req.user.id,
      recipientEmail: recipientEmail.toLowerCase(),
      recipientId: recipient?.id || null,
      tier: tier || "LIVE",
      permissions: permissions || ["read"],
      expiresAt: expiresAt ? new Date(expiresAt) : null,
    });

    await audit.log(
      req.user.id,
      "resource_share.created",
      {
        shareId: share.id,
        integrationId: resourceId,
        recipientEmail: recipientEmail.toLowerCase(),
        recipientId: recipient?.id,
        tier: tier || "LIVE",
        permissions: permissions || ["read"],
      },
      req.ip,
      recipient?.id,
    );

    // Notify recipient if they have an account
    if (recipient) {
      broadcastToUser(recipient.id, "resource_share_received", {
        id: share.id,
        ownerName: req.user.name,
        ownerEmail: req.user.email,
        resourceType: matchingIntegration.provider,
        resourceName: getIntegrationDisplayName(matchingIntegration),
        tier: tier || "LIVE",
      });
    }

    res.json({ success: true, shareId: share.id });
  } catch (err) {
    console.error("Create resource share error:", err);
    res.status(500).json({ error: "Failed to create share" });
  }
});

// List shares I've created (outgoing)
router.get("/resource-shares/outgoing", requireUser, detectTenant, async (req, res) => {
  try {
    const sharesList = await resourceShares.listByOwner(req.user.id);

    const shares = sharesList.map((s) => ({
      id: s.id,
      resourceId: s.integration_id,
      resourceName: s.resource_name,
      resourceType: s.resource_type,
      recipientId: s.recipient_id,
      recipientName: s.recipient_name || s.recipient_email,
      recipientEmail: s.recipient_email,
      tier: s.tier,
      permissions:
        typeof s.permissions === "object"
          ? Object.keys(s.permissions).filter((k) => s.permissions[k])
          : s.permissions,
      status: s.status === "active" ? "active" : s.status === "pending" ? "pending" : s.status,
      expiresAt: s.expires_at,
      createdAt: s.created_at,
      approvedAt: s.accepted_at,
    }));

    res.json({ shares });
  } catch (err) {
    console.error("List outgoing shares error:", err);
    res.status(500).json({ error: "Failed to list shares" });
  }
});

// List shares offered to me (incoming)
router.get("/resource-shares/incoming", requireUser, detectTenant, async (req, res) => {
  try {
    const sharesList = await resourceShares.listByRecipient(req.user.id, req.user.email);

    const shares = sharesList.map((s) => ({
      id: s.id,
      resourceId: s.integration_id,
      resourceName: s.resource_name,
      resourceType: s.resource_type,
      ownerId: s.owner_id,
      ownerName: s.owner_name,
      ownerEmail: s.owner_email,
      tier: s.tier,
      permissions:
        typeof s.permissions === "object"
          ? Object.keys(s.permissions).filter((k) => s.permissions[k])
          : s.permissions,
      status:
        s.status === "active" ? "active" : s.status === "pending" ? "pending_approval" : s.status,
      ownerOnline: true, // Could check container status
      sharedAt: s.created_at,
      expiresAt: s.expires_at,
    }));

    res.json({ shares });
  } catch (err) {
    console.error("List incoming shares error:", err);
    res.status(500).json({ error: "Failed to list shares" });
  }
});

// Accept a share
router.post("/resource-shares/:shareId/accept", requireUser, detectTenant, async (req, res) => {
  try {
    const share = await resourceShares.findById(req.params.shareId);

    if (!share) {
      return res.status(404).json({ error: "Share not found" });
    }

    // Verify this share is for the current user
    if (
      share.recipient_id !== req.user.id &&
      share.recipient_email.toLowerCase() !== req.user.email.toLowerCase()
    ) {
      return res.status(403).json({ error: "Not your share" });
    }

    if (share.status !== "pending") {
      return res.status(400).json({ error: "Share is not pending" });
    }

    const updated = await resourceShares.accept(req.params.shareId);

    await audit.log(
      req.user.id,
      "resource_share.accepted",
      {
        shareId: req.params.shareId,
        integrationId: share.integration_id,
        ownerId: share.owner_id,
      },
      req.ip,
      share.owner_id,
    );

    // Notify owner
    broadcastToUser(share.owner_id, "resource_share_accepted", {
      id: share.id,
      recipientName: req.user.name,
      recipientEmail: req.user.email,
      resourceType: share.resource_type,
      resourceName: share.resource_name,
    });

    res.json({ success: true, share: updated });
  } catch (err) {
    console.error("Accept share error:", err);
    res.status(500).json({ error: "Failed to accept share" });
  }
});

// Decline a share
router.post("/resource-shares/:shareId/decline", requireUser, detectTenant, async (req, res) => {
  try {
    const share = await resourceShares.findById(req.params.shareId);

    if (!share) {
      return res.status(404).json({ error: "Share not found" });
    }

    // Verify this share is for the current user
    if (
      share.recipient_id !== req.user.id &&
      share.recipient_email.toLowerCase() !== req.user.email.toLowerCase()
    ) {
      return res.status(403).json({ error: "Not your share" });
    }

    if (share.status !== "pending") {
      return res.status(400).json({ error: "Share is not pending" });
    }

    const updated = await resourceShares.decline(req.params.shareId);

    await audit.log(
      req.user.id,
      "resource_share.declined",
      {
        shareId: req.params.shareId,
        integrationId: share.integration_id,
        ownerId: share.owner_id,
      },
      req.ip,
      share.owner_id,
    );

    res.json({ success: true, share: updated });
  } catch (err) {
    console.error("Decline share error:", err);
    res.status(500).json({ error: "Failed to decline share" });
  }
});

// Revoke a share (owner only)
router.delete("/resource-shares/:shareId", requireUser, detectTenant, async (req, res) => {
  try {
    const share = await resourceShares.findById(req.params.shareId);

    if (!share) {
      return res.status(404).json({ error: "Share not found" });
    }

    // Only owner can revoke
    if (share.owner_id !== req.user.id) {
      return res.status(403).json({ error: "Not your share to revoke" });
    }

    await resourceShares.revoke(req.params.shareId);

    await audit.log(
      req.user.id,
      "resource_share.revoked",
      {
        shareId: req.params.shareId,
        integrationId: share.integration_id,
        recipientId: share.recipient_id,
        recipientEmail: share.recipient_email,
      },
      req.ip,
      share.recipient_id,
    );

    // Notify recipient if they have an account
    if (share.recipient_id) {
      broadcastToUser(share.recipient_id, "resource_share_revoked", {
        id: share.id,
        ownerName: req.user.name,
        resourceType: share.resource_type,
        resourceName: share.resource_name,
      });
    }

    res.json({ success: true });
  } catch (err) {
    console.error("Revoke share error:", err);
    res.status(500).json({ error: "Failed to revoke share" });
  }
});

export default router;
