// Group invite routes (user-facing invite management)
import { Router } from "express";
import { z } from "zod";
import { users, audit, groups, groupMemberships, groupInvites } from "../db/index.js";
import { updateAgentContext } from "../lib/context.js";
import { sendGroupInviteEmail } from "../lib/email.js";
import {
  validate,
  uuidSchema,
  inviteToGroupSchema,
  tokenParamSchema,
  groupIdParamSchema,
} from "../lib/schemas.js";
import { requireUser } from "../middleware/auth.js";
import { requireGroupAdmin } from "../middleware/group-auth.js";
import { detectTenant } from "../middleware/tenant-context.js";

const idParamSchema = z.object({
  id: uuidSchema,
});

const groupInviteParamsSchema = z.object({
  groupId: uuidSchema,
  inviteId: uuidSchema,
});

const router = Router();

// ============================================================
// USER-FACING INVITE ENDPOINTS
// ============================================================

// List my pending invites
router.get("/", requireUser, detectTenant, async (req, res) => {
  try {
    const invites = await groupInvites.listPendingForUser(req.user.id);

    const safeInvites = invites.map((invite) => ({
      id: invite.id,
      groupId: invite.group_id,
      groupName: invite.group_name,
      groupSlug: invite.group_slug,
      inviterName: invite.inviter_name,
      inviterEmail: invite.inviter_email,
      role: invite.role,
      status: invite.status,
      createdAt: invite.created_at,
      expiresAt: invite.expires_at,
    }));

    res.json({ invites: safeInvites });
  } catch (err) {
    console.error("List invites error:", err);
    res.status(500).json({ error: "Failed to list invites" });
  }
});

// Get invite details by ID (only if belongs to current user)
router.get(
  "/:id",
  requireUser,
  detectTenant,
  validate({ params: idParamSchema }),
  async (req, res) => {
    try {
      const invite = await groupInvites.findById(req.validatedParams.id);

      if (!invite) {
        return res.status(404).json({ error: "Invite not found" });
      }

      if (invite.invitee_id !== req.user.id && invite.invitee_email !== req.user.email) {
        return res.status(403).json({ error: "This invite is not for you" });
      }

      const isExpired = invite.expires_at && new Date(invite.expires_at) < new Date();

      res.json({
        invite: {
          id: invite.id,
          groupId: invite.group_id,
          groupName: invite.group_name,
          groupSlug: invite.group_slug,
          inviterName: invite.inviter_name,
          inviterEmail: invite.inviter_email,
          role: invite.role,
          status: isExpired && invite.status === "pending" ? "expired" : invite.status,
          createdAt: invite.created_at,
          expiresAt: invite.expires_at,
          decidedAt: invite.decided_at,
        },
      });
    } catch (err) {
      console.error("Get invite error:", err);
      res.status(500).json({ error: "Failed to get invite" });
    }
  },
);

// Accept an invite
router.post(
  "/:id/accept",
  requireUser,
  detectTenant,
  validate({ params: idParamSchema }),
  async (req, res) => {
    try {
      const { id } = req.validatedParams;
      const invite = await groupInvites.findById(id);

      if (!invite) {
        return res.status(404).json({ error: "Invite not found" });
      }

      if (invite.invitee_id !== req.user.id && invite.invitee_email !== req.user.email) {
        return res.status(403).json({ error: "This invite is not for you" });
      }

      if (!groupInvites.isValid(invite)) {
        const isExpired = invite.expires_at && new Date(invite.expires_at) < new Date();
        if (isExpired) {
          return res.status(400).json({ error: "Invite has expired" });
        }
        return res.status(400).json({ error: "Invite is no longer pending" });
      }

      const accepted = await groupInvites.accept(id, req.user.id);

      if (!accepted) {
        return res.status(400).json({ error: "Failed to accept invite. It may have expired." });
      }

      await groupMemberships.add(req.user.id, invite.group_id, invite.role);

      await audit.log(
        req.user.id,
        "group.invite.accepted",
        {
          inviteId: invite.id,
          groupId: invite.group_id,
          groupName: invite.group_name,
          role: invite.role,
        },
        req.ip,
      );

      updateAgentContext(req.user.id).catch((err) => {
        console.error(`Failed to update agent context for new group member: ${err.message}`);
      });

      res.json({
        success: true,
        message: `You are now a member of ${invite.group_name}`,
        membership: {
          groupId: invite.group_id,
          groupName: invite.group_name,
          groupSlug: invite.group_slug,
          role: invite.role,
        },
      });
    } catch (err) {
      console.error("Accept invite error:", err);
      res.status(500).json({ error: "Failed to accept invite" });
    }
  },
);

// Decline an invite
router.post(
  "/:id/decline",
  requireUser,
  detectTenant,
  validate({ params: idParamSchema }),
  async (req, res) => {
    try {
      const { id } = req.validatedParams;
      const invite = await groupInvites.findById(id);

      if (!invite) {
        return res.status(404).json({ error: "Invite not found" });
      }

      if (invite.invitee_id !== req.user.id && invite.invitee_email !== req.user.email) {
        return res.status(403).json({ error: "This invite is not for you" });
      }

      if (invite.status !== "pending") {
        return res.status(400).json({ error: "Invite is no longer pending" });
      }

      await groupInvites.decline(id, req.user.id);

      await audit.log(
        req.user.id,
        "group.invite.declined",
        {
          inviteId: id,
          groupId: invite.group_id,
          groupName: invite.group_name,
        },
        req.ip,
      );

      res.json({ success: true, message: "Invite declined" });
    } catch (err) {
      console.error("Decline invite error:", err);
      res.status(500).json({ error: "Failed to decline invite" });
    }
  },
);

// ============================================================
// TOKEN-BASED INVITE ENDPOINTS (for email links)
// ============================================================

router.get("/token/:token", validate({ params: tokenParamSchema }), async (req, res) => {
  try {
    const invite = await groupInvites.findByToken(req.validatedParams.token);

    if (!invite) {
      return res.status(404).json({ error: "Invalid or expired invite" });
    }

    const isExpired = invite.expires_at && new Date(invite.expires_at) < new Date();
    if (isExpired || invite.status !== "pending") {
      return res.status(400).json({
        error: "This invite has expired or is no longer valid",
        status: isExpired ? "expired" : invite.status,
      });
    }

    res.json({
      valid: true,
      invite: {
        id: invite.id,
        groupName: invite.group_name,
        groupSlug: invite.group_slug,
        inviterName: invite.inviter_name,
        role: invite.role,
        expiresAt: invite.expires_at,
      },
    });
  } catch (err) {
    console.error("Get invite by token error:", err);
    res.status(500).json({ error: "Failed to validate invite" });
  }
});

router.post(
  "/token/:token/accept",
  requireUser,
  detectTenant,
  validate({ params: tokenParamSchema }),
  async (req, res) => {
    try {
      const invite = await groupInvites.findByToken(req.validatedParams.token);

      if (!invite) {
        return res.status(404).json({ error: "Invalid or expired invite" });
      }

      if (invite.invitee_email !== req.user.email.toLowerCase()) {
        return res.status(403).json({ error: "This invite is not for your account" });
      }

      if (!groupInvites.isValid(invite)) {
        const isExpired = invite.expires_at && new Date(invite.expires_at) < new Date();
        if (isExpired) {
          return res.status(400).json({ error: "Invite has expired" });
        }
        return res.status(400).json({ error: "Invite is no longer pending" });
      }

      const accepted = await groupInvites.accept(invite.id, req.user.id);

      if (!accepted) {
        return res.status(400).json({ error: "Failed to accept invite. It may have expired." });
      }

      await groupMemberships.add(req.user.id, invite.group_id, invite.role);

      await audit.log(
        req.user.id,
        "group.invite.accepted",
        {
          inviteId: invite.id,
          groupId: invite.group_id,
          groupName: invite.group_name,
          role: invite.role,
          viaToken: true,
        },
        req.ip,
      );

      updateAgentContext(req.user.id).catch((err) => {
        console.error(`Failed to update agent context for new group member: ${err.message}`);
      });

      res.json({
        success: true,
        message: `You are now a member of ${invite.group_name}`,
        membership: {
          groupId: invite.group_id,
          groupName: invite.group_name,
          groupSlug: invite.group_slug,
          role: invite.role,
        },
      });
    } catch (err) {
      console.error("Accept invite by token error:", err);
      res.status(500).json({ error: "Failed to accept invite" });
    }
  },
);

// ============================================================
// ADMIN INVITE MANAGEMENT ENDPOINTS
// ============================================================

router.post(
  "/groups/:groupId/invites",
  requireUser,
  detectTenant,
  validate({ params: groupIdParamSchema, body: inviteToGroupSchema }),
  requireGroupAdmin,
  async (req, res) => {
    try {
      const { email, role } = req.validatedBody;
      const { groupId } = req.validatedParams;

      const normalizedEmail = email;
      const invitee = await users.findByEmail(normalizedEmail);

      if (invitee) {
        const existingMembership = await groupMemberships.isMember(invitee.id, groupId);
        if (existingMembership) {
          return res.json({ success: true, message: "Invite sent" });
        }
      }

      const group = await groups.findById(groupId);

      const existingInvite = await groupInvites.findPendingByOrgAndEmail(groupId, normalizedEmail);
      if (existingInvite) {
        const invite = await groupInvites.create({
          groupId: groupId,
          inviterId: req.user.id,
          inviteeEmail: normalizedEmail,
          inviteeId: invitee?.id || null,
          role: role || "member",
        });

        await audit.log(
          req.user.id,
          "group.invite.refreshed",
          {
            groupId,
            inviteId: invite.id,
            inviteeEmail: normalizedEmail,
          },
          req.ip,
        );

        sendGroupInviteEmail({
          to: normalizedEmail,
          orgName: group.name,
          inviterName: req.user.name || req.user.email,
          inviteToken: invite.token,
          role: role || "member",
        }).catch((err) => {
          console.error(`Failed to send invite email: ${err.message}`);
        });

        return res.json({ success: true, message: "Invite sent" });
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

      sendGroupInviteEmail({
        to: normalizedEmail,
        orgName: group.name,
        inviterName: req.user.name || req.user.email,
        inviteToken: invite.token,
        role: role || "member",
      }).catch((err) => {
        console.error(`Failed to send invite email: ${err.message}`);
      });

      res.json({ success: true, message: "Invite sent" });
    } catch (err) {
      console.error("Create invite error:", err);
      res.status(500).json({ error: "Failed to send invite" });
    }
  },
);

router.get(
  "/groups/:groupId/invites",
  requireUser,
  detectTenant,
  validate({ params: groupIdParamSchema }),
  requireGroupAdmin,
  async (req, res) => {
    try {
      const invites = await groupInvites.listByGroup(req.validatedParams.groupId);

      const transformedInvites = invites.map((invite) => {
        const isExpired = invite.expires_at && new Date(invite.expires_at) < new Date();
        return {
          id: invite.id,
          inviteeEmail: invite.invitee_email || "Unknown",
          inviterName: invite.inviter_name || invite.inviter_email || "Unknown",
          role: invite.role || "member",
          status: isExpired && invite.status === "pending" ? "expired" : invite.status,
          createdAt: invite.created_at,
          expiresAt: invite.expires_at,
          decidedAt: invite.decided_at,
        };
      });

      res.json({ invites: transformedInvites });
    } catch (err) {
      console.error("List group invites error:", err);
      res.status(500).json({ error: "Failed to list invites" });
    }
  },
);

router.delete(
  "/groups/:groupId/invites/:inviteId",
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

router.post(
  "/groups/:groupId/invites/:inviteId/resend",
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

      if (invite.status !== "pending" && invite.status !== "expired") {
        return res.status(400).json({ error: "Can only resend pending or expired invites" });
      }

      const group = await groups.findById(groupId);

      const newInvite = await groupInvites.create({
        groupId: invite.group_id,
        inviterId: req.user.id,
        inviteeEmail: invite.invitee_email,
        inviteeId: invite.invitee_id,
        role: invite.role,
      });

      await audit.log(
        req.user.id,
        "group.invite.resent",
        {
          groupId,
          inviteId: newInvite.id,
          inviteeEmail: invite.invitee_email,
        },
        req.ip,
      );

      sendGroupInviteEmail({
        to: invite.invitee_email,
        orgName: group.name,
        inviterName: req.user.name || req.user.email,
        inviteToken: newInvite.token,
        role: invite.role,
      }).catch((err) => {
        console.error(`Failed to send invite email: ${err.message}`);
      });

      res.json({ success: true, message: "Invite resent" });
    } catch (err) {
      console.error("Resend invite error:", err);
      res.status(500).json({ error: "Failed to resend invite" });
    }
  },
);

export default router;
