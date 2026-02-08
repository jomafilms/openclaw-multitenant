import { groupMemberships } from "../db/index.js";

/**
 * Middleware to require group membership
 * Expects :groupId in route params and req.user to be set (use requireUser first)
 * Sets req.groupMembership with user's role
 */
export function requireGroupMember(req, res, next) {
  const groupId = req.params.groupId || req.params.groupId;
  const userId = req.user?.id;

  if (!userId) {
    return res.status(401).json({ error: "Authentication required" });
  }

  if (!groupId) {
    return res.status(400).json({ error: "Group ID required" });
  }

  groupMemberships
    .findByUserAndGroup(userId, groupId)
    .then((membership) => {
      if (!membership) {
        return res.status(403).json({ error: "Not a member of this group" });
      }
      req.groupMembership = membership;
      next();
    })
    .catch((err) => {
      console.error("Group membership check error:", err);
      res.status(500).json({ error: "Failed to verify group membership" });
    });
}

/**
 * Middleware to require group admin role
 * Expects :groupId in route params and req.user to be set (use requireUser first)
 * Sets req.groupMembership with user's role
 */
export function requireGroupAdmin(req, res, next) {
  const groupId = req.params.groupId || req.params.groupId;
  const userId = req.user?.id;

  if (!userId) {
    return res.status(401).json({ error: "Authentication required" });
  }

  if (!groupId) {
    return res.status(400).json({ error: "Group ID required" });
  }

  groupMemberships
    .findByUserAndGroup(userId, groupId)
    .then((membership) => {
      if (!membership) {
        return res.status(403).json({ error: "Not a member of this group" });
      }
      if (membership.role !== "admin") {
        return res.status(403).json({ error: "Admin access required" });
      }
      req.groupMembership = membership;
      next();
    })
    .catch((err) => {
      console.error("Group admin check error:", err);
      res.status(500).json({ error: "Failed to verify group admin status" });
    });
}

/**
 * Middleware to optionally load group membership (doesn't require it)
 * Sets req.groupMembership if user is a member
 */
export function optionalGroupMember(req, res, next) {
  const groupId = req.params.groupId || req.params.groupId;
  const userId = req.user?.id;

  if (!userId || !groupId) {
    return next();
  }

  groupMemberships
    .findByUserAndGroup(userId, groupId)
    .then((membership) => {
      if (membership) {
        req.groupMembership = membership;
      }
      next();
    })
    .catch(() => next());
}

export default {
  requireGroupMember,
  requireGroupAdmin,
  optionalGroupMember,
};
