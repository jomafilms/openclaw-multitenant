// Admin routes for user allowlist management
import { Router } from "express";
import { userAllowlist, users, audit, meshAuditLogs, MESH_AUDIT_EVENTS } from "../db/index.js";
import { requireUser, requireAdmin } from "../middleware/auth.js";

const router = Router();

// All routes require admin
router.use(requireUser, requireAdmin);

/**
 * GET /api/admin/user-allowlist
 * List all allowlist entries and settings
 */
router.get("/", async (req, res) => {
  try {
    const includeDisabled = req.query.includeDisabled === "true";
    const entries = await userAllowlist.list({ includeDisabled });
    const stats = await userAllowlist.getStats();
    const enabled = await userAllowlist.isEnabled();

    res.json({
      enabled,
      entries,
      stats,
    });
  } catch (err) {
    console.error("List allowlist error:", err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/admin/user-allowlist
 * Add an entry to the allowlist
 */
router.post("/", async (req, res) => {
  try {
    const { entryType, value, description, expiresAt } = req.body;

    if (!entryType || !["email", "domain"].includes(entryType)) {
      return res.status(400).json({ error: "entryType must be 'email' or 'domain'" });
    }

    if (!value || typeof value !== "string") {
      return res.status(400).json({ error: "value is required" });
    }

    // Validate email format
    if (entryType === "email" && !value.includes("@")) {
      return res.status(400).json({ error: "Invalid email format" });
    }

    // Validate domain format (no @ sign)
    if (entryType === "domain" && value.includes("@")) {
      return res.status(400).json({ error: "Domain should not include @ sign" });
    }

    const entry = await userAllowlist.add({
      entryType,
      value,
      description,
      createdBy: req.user.id,
      expiresAt: expiresAt ? new Date(expiresAt) : null,
    });

    await audit.log(req.user.id, "admin.allowlist.entry_added", {
      entryId: entry.id,
      entryType,
      value: value.toLowerCase(),
    }, req.ip);

    await meshAuditLogs.log({
      eventType: "admin.allowlist.entry_added",
      actorId: req.user.id,
      ipAddress: req.ip,
      success: true,
      details: { entryId: entry.id, entryType, value: value.toLowerCase() },
    });

    res.json({ success: true, entry });
  } catch (err) {
    console.error("Add allowlist entry error:", err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * DELETE /api/admin/user-allowlist/:id
 * Remove an entry from the allowlist
 */
router.delete("/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const entry = await userAllowlist.findById(id);
    if (!entry) {
      return res.status(404).json({ error: "Entry not found" });
    }

    await userAllowlist.remove(id);

    await audit.log(req.user.id, "admin.allowlist.entry_removed", {
      entryId: id,
      entryType: entry.entry_type,
      value: entry.value,
    }, req.ip);

    await meshAuditLogs.log({
      eventType: "admin.allowlist.entry_removed",
      actorId: req.user.id,
      ipAddress: req.ip,
      success: true,
      details: { entryId: id, entryType: entry.entry_type, value: entry.value },
    });

    res.json({ success: true });
  } catch (err) {
    console.error("Remove allowlist entry error:", err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/admin/user-allowlist/:id/enable
 * Enable an allowlist entry
 */
router.post("/:id/enable", async (req, res) => {
  try {
    const { id } = req.params;

    const entry = await userAllowlist.enable(id);
    if (!entry) {
      return res.status(404).json({ error: "Entry not found" });
    }

    await audit.log(req.user.id, "admin.allowlist.entry_enabled", {
      entryId: id,
    }, req.ip);

    res.json({ success: true, entry });
  } catch (err) {
    console.error("Enable allowlist entry error:", err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/admin/user-allowlist/:id/disable
 * Disable an allowlist entry
 */
router.post("/:id/disable", async (req, res) => {
  try {
    const { id } = req.params;

    const entry = await userAllowlist.disable(id);
    if (!entry) {
      return res.status(404).json({ error: "Entry not found" });
    }

    await audit.log(req.user.id, "admin.allowlist.entry_disabled", {
      entryId: id,
    }, req.ip);

    res.json({ success: true, entry });
  } catch (err) {
    console.error("Disable allowlist entry error:", err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/admin/user-allowlist/toggle
 * Toggle the allowlist feature on/off
 */
router.post("/toggle", async (req, res) => {
  try {
    const { enabled } = req.body;

    if (typeof enabled !== "boolean") {
      return res.status(400).json({ error: "enabled must be a boolean" });
    }

    await userAllowlist.setEnabled(enabled, req.user.id);

    await audit.log(req.user.id, "admin.allowlist.toggled", {
      enabled,
    }, req.ip);

    await meshAuditLogs.log({
      eventType: "admin.allowlist.toggled",
      actorId: req.user.id,
      ipAddress: req.ip,
      success: true,
      details: { enabled },
    });

    res.json({ success: true, enabled });
  } catch (err) {
    console.error("Toggle allowlist error:", err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/admin/user-allowlist/pending-users
 * List users pending approval
 */
router.get("/pending-users", async (req, res) => {
  try {
    const { query: q } = await import("../db/core.js");
    const result = await q(
      `SELECT id, email, name, created_at, status
       FROM users
       WHERE status = 'pending_approval'
       ORDER BY created_at DESC
       LIMIT 100`,
    );

    res.json({ users: result.rows });
  } catch (err) {
    console.error("List pending users error:", err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/admin/user-allowlist/approve/:userId
 * Approve a pending user
 */
router.post("/approve/:userId", async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await users.findById(userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    if (user.status !== "pending_approval") {
      return res.status(400).json({ error: "User is not pending approval" });
    }

    // Update user status to pending (ready for provisioning on next login)
    await users.updateStatus(userId, "pending");

    await audit.log(req.user.id, "admin.allowlist.user_approved", {
      approvedUserId: userId,
      approvedUserEmail: user.email,
    }, req.ip);

    await meshAuditLogs.log({
      eventType: "admin.allowlist.user_approved",
      actorId: req.user.id,
      targetId: userId,
      ipAddress: req.ip,
      success: true,
      details: { approvedUserEmail: user.email },
    });

    res.json({ success: true, message: `User ${user.email} approved` });
  } catch (err) {
    console.error("Approve user error:", err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/admin/user-allowlist/reject/:userId
 * Reject a pending user (delete their account)
 */
router.post("/reject/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const { reason } = req.body;

    const user = await users.findById(userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    if (user.status !== "pending_approval") {
      return res.status(400).json({ error: "User is not pending approval" });
    }

    // Log before deletion
    await audit.log(req.user.id, "admin.allowlist.user_rejected", {
      rejectedUserId: userId,
      rejectedUserEmail: user.email,
      reason,
    }, req.ip);

    await meshAuditLogs.log({
      eventType: "admin.allowlist.user_rejected",
      actorId: req.user.id,
      targetId: userId,
      ipAddress: req.ip,
      success: true,
      details: { rejectedUserEmail: user.email, reason },
    });

    // Delete the user (cascade will clean up related data)
    const { query: q } = await import("../db/core.js");
    await q(`DELETE FROM users WHERE id = $1`, [userId]);

    res.json({ success: true, message: `User ${user.email} rejected and removed` });
  } catch (err) {
    console.error("Reject user error:", err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/admin/user-allowlist/check
 * Check if an email would be allowed (for testing)
 */
router.post("/check", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || typeof email !== "string") {
      return res.status(400).json({ error: "email is required" });
    }

    const result = await userAllowlist.checkEmail(email);

    res.json(result);
  } catch (err) {
    console.error("Check email error:", err);
    res.status(500).json({ error: err.message });
  }
});

export default router;
