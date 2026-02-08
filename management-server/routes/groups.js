// Group admin routes (unified naming for organizations)
import { Router } from "express";
import { z } from "zod";
import {
  users,
  audit,
  groups,
  groupMemberships,
  groupResources,
  shares,
  groupInvites,
  PERMISSION_LEVELS,
  DEFAULT_PERMISSIONS,
  meshAuditLogs,
  MESH_AUDIT_EVENTS,
} from "../db/index.js";
import { updateAgentContext } from "../lib/context.js";
import { sendGroupInviteEmail } from "../lib/email.js";
import { inviteLimiter } from "../lib/rate-limit.js";
import {
  validate,
  createGroupSchema,
  updateGroupSchema,
  createResourceSchema,
  updateResourceSchema,
  createGrantSchema,
  updateGrantSchema,
  addGroupMemberSchema,
  inviteToGroupSchema,
  groupIdParamSchema,
  userIdParamSchema,
  resourceIdParamSchema,
  grantIdParamSchema,
  inviteIdParamSchema,
  uuidSchema,
} from "../lib/schemas.js";
import { requireUser } from "../middleware/auth.js";
import { requireGroupMember, requireGroupAdmin } from "../middleware/group-auth.js";
import { detectTenant } from "../middleware/tenant-context.js";

// Combined param schemas for nested routes
const groupResourceParamsSchema = z.object({
  groupId: uuidSchema,
  resourceId: uuidSchema,
});

const groupShareParamsSchema = z.object({
  groupId: uuidSchema,
  shareId: uuidSchema,
});

const groupUserParamsSchema = z.object({
  groupId: uuidSchema,
  userId: uuidSchema,
});

const groupInviteParamsSchema = z.object({
  groupId: uuidSchema,
  inviteId: uuidSchema,
});

// Alias schemas for shares (using grant schemas)
const createShareSchema = createGrantSchema;
const updateShareSchema = updateGrantSchema;

const router = Router();

// Get available permission levels (for UI)
router.get("/permission-levels", requireUser, detectTenant, (req, res) => {
  res.json({
    levels: PERMISSION_LEVELS,
    defaults: DEFAULT_PERMISSIONS,
    descriptions: {
      read: "View resource data (GET requests)",
      list: "List items in resource",
      write: "Create/update data (POST, PUT, PATCH requests)",
      delete: "Delete data (DELETE requests)",
      admin: "Manage the resource itself",
      share: "Can share resource with others",
    },
  });
});

// Create group (any authenticated user can create)
router.post(
  "/",
  requireUser,
  detectTenant,
  validate({ body: createGroupSchema }),
  async (req, res) => {
    try {
      const { name, slug, description } = req.validatedBody;

      const existing = await groups.findBySlug(slug);
      if (existing) {
        return res.status(409).json({ error: "Group slug already exists" });
      }

      const group = await groups.create({ name, slug, description });
      await groupMemberships.add(req.user.id, group.id, "admin");
      await audit.log(req.user.id, "group.created", { groupId: group.id, name, slug }, req.ip);

      res.json({ success: true, group });
    } catch (err) {
      console.error("Create group error:", err);
      res.status(500).json({ error: "Failed to create group" });
    }
  },
);

// Get group details
router.get(
  "/:groupId",
  requireUser,
  detectTenant,
  validate({ params: groupIdParamSchema }),
  requireGroupMember,
  async (req, res) => {
    try {
      const group = await groups.findById(req.validatedParams.groupId);
      if (!group) {
        return res.status(404).json({ error: "Group not found" });
      }

      const members = await groupMemberships.listByGroup(group.id);
      const resources = await groupResources.listByGroup(group.id);

      res.json({
        group,
        members,
        resources,
        isAdmin: req.groupMembership?.role === "admin",
      });
    } catch (err) {
      console.error("Get group error:", err);
      res.status(500).json({ error: "Failed to get group" });
    }
  },
);

// Update group
router.put(
  "/:groupId",
  requireUser,
  detectTenant,
  validate({ params: groupIdParamSchema, body: updateGroupSchema }),
  requireGroupAdmin,
  async (req, res) => {
    try {
      const { name, description } = req.validatedBody;
      const { groupId } = req.validatedParams;
      const group = await groups.update(groupId, { name, description });
      await audit.log(
        req.user.id,
        "group.updated",
        { groupId: group.id, name, description },
        req.ip,
      );
      res.json({ success: true, group });
    } catch (err) {
      console.error("Update group error:", err);
      res.status(500).json({ error: "Failed to update group" });
    }
  },
);

// Add group resource
router.post(
  "/:groupId/resources",
  requireUser,
  detectTenant,
  validate({ params: groupIdParamSchema, body: createResourceSchema }),
  requireGroupAdmin,
  async (req, res) => {
    try {
      const { name, description, resourceType, endpoint, authConfig, metadata } = req.validatedBody;
      const { groupId } = req.validatedParams;

      const resource = await groupResources.create({
        groupId,
        name,
        description,
        resourceType,
        endpoint,
        authConfig,
        metadata,
      });

      await audit.log(
        req.user.id,
        "group.resource.created",
        {
          groupId,
          resourceId: resource.id,
          name,
        },
        req.ip,
      );

      res.json({ success: true, resource });
    } catch (err) {
      console.error("Create resource error:", err);
      res.status(500).json({ error: "Failed to create resource" });
    }
  },
);

// List group resources
router.get(
  "/:groupId/resources",
  requireUser,
  detectTenant,
  validate({ params: groupIdParamSchema }),
  requireGroupMember,
  async (req, res) => {
    try {
      const resources = await groupResources.listByGroup(req.validatedParams.groupId);
      res.json({ resources });
    } catch (err) {
      console.error("List resources error:", err);
      res.status(500).json({ error: "Failed to list resources" });
    }
  },
);

// Update group resource
router.put(
  "/:groupId/resources/:resourceId",
  requireUser,
  detectTenant,
  validate({ params: groupResourceParamsSchema, body: updateResourceSchema }),
  requireGroupAdmin,
  async (req, res) => {
    try {
      const { name, description, endpoint, authConfig, metadata, status } = req.validatedBody;
      const { groupId, resourceId } = req.validatedParams;

      const resource = await groupResources.update(resourceId, {
        name,
        description,
        endpoint,
        authConfig,
        metadata,
        status,
      });

      await audit.log(
        req.user.id,
        "group.resource.updated",
        {
          groupId,
          resourceId,
        },
        req.ip,
      );

      res.json({ success: true, resource });
    } catch (err) {
      console.error("Update resource error:", err);
      res.status(500).json({ error: "Failed to update resource" });
    }
  },
);

// Delete group resource
router.delete(
  "/:groupId/resources/:resourceId",
  requireUser,
  detectTenant,
  validate({ params: groupResourceParamsSchema }),
  requireGroupAdmin,
  async (req, res) => {
    try {
      const { groupId, resourceId } = req.validatedParams;
      await groupResources.delete(resourceId);

      await audit.log(
        req.user.id,
        "group.resource.deleted",
        {
          groupId,
          resourceId,
        },
        req.ip,
      );

      res.json({ success: true });
    } catch (err) {
      console.error("Delete resource error:", err);
      res.status(500).json({ error: "Failed to delete resource" });
    }
  },
);

// Share resource with user (create share)
router.post(
  "/:groupId/shares",
  requireUser,
  detectTenant,
  validate({ params: groupIdParamSchema, body: createShareSchema }),
  requireGroupAdmin,
  async (req, res) => {
    try {
      const { resourceId, userId, permissions } = req.validatedBody;
      const { groupId } = req.validatedParams;

      const isMember = await groupMemberships.isMember(userId, groupId);
      if (!isMember) {
        return res.status(400).json({ error: "User must be a member of the group" });
      }

      const share = await shares.create({
        groupId,
        resourceId,
        userId,
        permissions: permissions,
        grantedBy: req.user.id,
      });

      await audit.log(
        req.user.id,
        "share.created",
        {
          groupId,
          resourceId,
          granteeId: userId,
          permissions: share.permissions,
        },
        req.ip,
      );

      // Log to mesh audit for sharing
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.SHARE_GRANTED,
        actorId: req.user.id,
        targetId: userId,
        groupId: groupId,
        ipAddress: req.ip,
        success: true,
        details: { resourceId, permissions: share.permissions },
      });

      res.json({ success: true, share });
    } catch (err) {
      console.error("Create share error:", err);
      res.status(500).json({ error: "Failed to create share" });
    }
  },
);

// List all shares for group
router.get(
  "/:groupId/shares",
  requireUser,
  detectTenant,
  validate({ params: groupIdParamSchema }),
  requireGroupAdmin,
  async (req, res) => {
    try {
      const shareList = await shares.listByGroup(req.validatedParams.groupId);
      res.json({ shares: shareList });
    } catch (err) {
      console.error("List shares error:", err);
      res.status(500).json({ error: "Failed to list shares" });
    }
  },
);

// Update share permissions
router.put(
  "/:groupId/shares/:shareId",
  requireUser,
  detectTenant,
  validate({ params: groupShareParamsSchema, body: updateShareSchema }),
  requireGroupAdmin,
  async (req, res) => {
    try {
      const { permissions } = req.validatedBody;
      const { groupId, shareId } = req.validatedParams;

      const share = await shares.updatePermissions(shareId, permissions);

      await audit.log(
        req.user.id,
        "share.updated",
        {
          groupId,
          shareId,
          permissions: share.permissions,
        },
        req.ip,
      );

      res.json({ success: true, share });
    } catch (err) {
      console.error("Update share error:", err);
      res.status(500).json({ error: "Failed to update share" });
    }
  },
);

// Revoke share
router.delete(
  "/:groupId/shares/:shareId",
  requireUser,
  detectTenant,
  validate({ params: groupShareParamsSchema }),
  requireGroupAdmin,
  async (req, res) => {
    try {
      const { groupId, shareId } = req.validatedParams;
      const share = await shares.findById(shareId);
      if (!share) {
        return res.status(404).json({ error: "Share not found" });
      }

      await shares.revoke(shareId);

      await audit.log(
        req.user.id,
        "share.revoked",
        {
          groupId,
          shareId,
          userId: share.user_id,
        },
        req.ip,
      );

      // Log to mesh audit for share revocation
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.SHARE_REVOKED,
        actorId: req.user.id,
        targetId: share.user_id,
        groupId: groupId,
        ipAddress: req.ip,
        success: true,
        details: { shareId, resourceId: share.resource_id },
      });

      res.json({ success: true });
    } catch (err) {
      console.error("Revoke share error:", err);
      res.status(500).json({ error: "Failed to revoke share" });
    }
  },
);

// Add member to group (creates invite, requires user acceptance)
router.post(
  "/:groupId/members",
  requireUser,
  detectTenant,
  validate({ params: groupIdParamSchema, body: addGroupMemberSchema }),
  requireGroupAdmin,
  async (req, res) => {
    try {
      const { userId, role } = req.validatedBody;
      const { groupId } = req.validatedParams;

      const user = await users.findById(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      // Check if already a member
      const existingMembership = await groupMemberships.isMember(userId, groupId);
      if (existingMembership) {
        return res.status(400).json({ error: "User is already a member" });
      }

      // Check for existing pending invite
      const existingInvite = await groupInvites.findPendingByGroupAndEmail(groupId, user.email);
      if (existingInvite) {
        return res.status(400).json({ error: "User already has a pending invite" });
      }

      // Create invite instead of direct membership
      const invite = await groupInvites.create({
        groupId: groupId,
        inviterId: req.user.id,
        inviteeEmail: user.email,
        inviteeId: userId,
        role: role || "member",
      });

      await audit.log(
        req.user.id,
        "group.invite.created",
        {
          groupId,
          inviteId: invite.id,
          inviteeId: userId,
          inviteeEmail: user.email,
          role: role || "member",
        },
        req.ip,
      );

      res.json({ success: true, invite, message: "Invite sent. User must accept to join." });
    } catch (err) {
      console.error("Add member error:", err);
      res.status(500).json({ error: "Failed to send invite" });
    }
  },
);

// List group members
router.get(
  "/:groupId/members",
  requireUser,
  detectTenant,
  validate({ params: groupIdParamSchema }),
  requireGroupMember,
  async (req, res) => {
    try {
      const members = await groupMemberships.listByGroup(req.validatedParams.groupId);
      res.json({ members });
    } catch (err) {
      console.error("List members error:", err);
      res.status(500).json({ error: "Failed to list members" });
    }
  },
);

// Remove member from group
router.delete(
  "/:groupId/members/:userId",
  requireUser,
  detectTenant,
  validate({ params: groupUserParamsSchema }),
  requireGroupAdmin,
  async (req, res) => {
    try {
      const { groupId, userId } = req.validatedParams;
      const members = await groupMemberships.listByGroup(groupId);
      const admins = members.filter((m) => m.role === "admin");
      const memberToRemove = members.find((m) => m.user_id === userId);

      // Don't allow removing the only admin
      if (userId === req.user.id && admins.length <= 1) {
        return res.status(400).json({ error: "Cannot remove the only admin" });
      }

      // If removing an admin, check threshold achievability
      let thresholdWarning = null;
      if (memberToRemove?.role === "admin") {
        const group = await groups.findById(groupId);
        const threshold = group?.unlock_threshold || 2;
        const newAdminCount = admins.length - 1;

        if (newAdminCount < threshold) {
          thresholdWarning = `Warning: After removal, only ${newAdminCount} admin(s) will remain, but vault unlock requires ${threshold}. Consider reducing the threshold first.`;
        }

        if (newAdminCount === 1) {
          thresholdWarning =
            "Warning: Only 1 admin will remain. Single admin cannot unlock vault alone with threshold > 1.";
        }
      }

      await groupMemberships.remove(userId, groupId);

      await audit.log(
        req.user.id,
        "group.member.removed",
        {
          groupId,
          userId,
          wasAdmin: memberToRemove?.role === "admin",
        },
        req.ip,
      );

      res.json({
        success: true,
        warning: thresholdWarning,
      });
    } catch (err) {
      console.error("Remove member error:", err);
      res.status(500).json({ error: "Failed to remove member" });
    }
  },
);

// Invite member by email (creates pending invite)
router.post(
  "/:groupId/invite",
  requireUser,
  detectTenant,
  validate({ params: groupIdParamSchema, body: inviteToGroupSchema }),
  requireGroupAdmin,
  inviteLimiter,
  async (req, res) => {
    try {
      const { email, role } = req.validatedBody;
      const { groupId } = req.validatedParams;

      const normalizedEmail = email;

      // Look up user (but don't reveal if they exist)
      const invitee = await users.findByEmail(normalizedEmail);

      // Check if already a member (only if user exists)
      if (invitee) {
        const existingMembership = await groupMemberships.isMember(invitee.id, groupId);
        if (existingMembership) {
          return res.json({ success: true, message: "Invite sent" });
        }
      }

      const invite = await groupInvites.create({
        groupId: groupId,
        inviterId: req.user.id,
        inviteeEmail: normalizedEmail,
        inviteeId: invitee?.id || null,
        role: role || "member",
      });

      await audit.log(
        req.user.id,
        "group.invite.created",
        {
          groupId,
          inviteId: invite.id,
          inviteeEmail: normalizedEmail,
          inviteeId: invitee?.id || null,
          role: role || "member",
        },
        req.ip,
      );

      // Send invite email
      const group = await groups.findById(groupId);
      sendGroupInviteEmail({
        to: normalizedEmail,
        groupName: group.name,
        inviterName: req.user.name || req.user.email,
        inviteToken: invite.token,
        role: role || "member",
      }).catch((err) => {
        console.error(`Failed to send invite email: ${err.message}`);
      });

      res.json({ success: true, message: "Invite sent" });
    } catch (err) {
      console.error("Invite to group error:", err);
      res.status(500).json({ error: "Failed to send invite" });
    }
  },
);

// List pending invites for group (admin only)
router.get(
  "/:groupId/invites",
  requireUser,
  detectTenant,
  validate({ params: groupIdParamSchema }),
  requireGroupAdmin,
  async (req, res) => {
    try {
      const rawInvites = await groupInvites.listByGroup(req.validatedParams.groupId);

      const invites = rawInvites.map((invite) => {
        const isExpired = invite.expires_at && new Date(invite.expires_at) < new Date();
        return {
          id: invite.id,
          inviteeEmail: invite.invitee_email,
          inviterName: invite.inviter_name || invite.inviter_email,
          role: invite.role || "member",
          status: isExpired && invite.status === "pending" ? "expired" : invite.status,
          createdAt: invite.created_at,
          expiresAt: invite.expires_at,
          decidedAt: invite.decided_at,
        };
      });

      res.json({ invites });
    } catch (err) {
      console.error("List invites error:", err);
      res.status(500).json({ error: "Failed to list invites" });
    }
  },
);

// Cancel a pending invite (admin only)
router.delete(
  "/:groupId/invites/:inviteId",
  requireUser,
  detectTenant,
  validate({ params: groupInviteParamsSchema }),
  requireGroupAdmin,
  async (req, res) => {
    try {
      const { groupId, inviteId } = req.validatedParams;
      const invite = await groupInvites.findById(inviteId);
      if (!invite) {
        return res.status(404).json({ error: "Invite not found" });
      }

      if (invite.group_id !== groupId) {
        return res.status(403).json({ error: "Invite does not belong to this group" });
      }

      if (invite.status !== "pending") {
        return res.status(400).json({ error: "Can only cancel pending invites" });
      }

      await groupInvites.cancel(inviteId);

      await audit.log(
        req.user.id,
        "group.invite.cancelled",
        {
          groupId,
          inviteId,
          inviteeEmail: invite.invitee_email,
        },
        req.ip,
      );

      res.json({ success: true });
    } catch (err) {
      console.error("Cancel invite error:", err);
      res.status(500).json({ error: "Failed to cancel invite" });
    }
  },
);

export default router;
