// Capability approval routes (human-in-the-loop for agent operations)
import { Router } from "express";
import { users, audit, capabilityApprovals } from "../db/index.js";
import { broadcastToUser } from "../lib/sse.js";
import { requireUser } from "../middleware/auth.js";
import { detectTenant } from "../middleware/tenant-context.js";

const router = Router();

// Request a capability approval (called by agent/container)
router.post("/request", requireUser, detectTenant, async (req, res) => {
  try {
    const {
      subjectPublicKey,
      subjectEmail,
      resource,
      scope,
      expiresInSeconds,
      maxCalls,
      reason,
      agentContext,
    } = req.body;

    // Validate required fields
    if (!subjectPublicKey || !resource || !scope || !expiresInSeconds) {
      return res.status(400).json({
        error: "Missing required fields: subjectPublicKey, resource, scope, expiresInSeconds",
      });
    }

    // Check for existing pending approval for same subject/resource
    const existing = await capabilityApprovals.findPendingByUserAndSubject(
      req.user.id,
      subjectPublicKey,
      resource,
    );

    if (existing) {
      return res.status(409).json({
        error: "A pending approval already exists for this capability",
        approvalId: existing.id,
        status: existing.status,
      });
    }

    // Create the approval request
    const approval = await capabilityApprovals.create({
      userId: req.user.id,
      operationType: "issue_capability",
      subjectPublicKey,
      subjectEmail,
      resource,
      scope: Array.isArray(scope) ? scope : [scope],
      expiresInSeconds,
      maxCalls,
      reason,
      agentContext,
    });

    // Log the action
    await audit.log(
      req.user.id,
      "capability.approval.requested",
      {
        approvalId: approval.id,
        resource,
        scope,
        subjectEmail,
      },
      req.ip,
    );

    // Notify user via SSE
    broadcastToUser(req.user.id, "capability_approval_requested", {
      id: approval.id,
      resource,
      scope,
      subjectEmail,
      reason,
      created_at: approval.created_at,
    });

    res.json({
      success: true,
      approval: {
        id: approval.id,
        token: approval.token,
        status: approval.status,
        expiresAt: approval.expires_at,
      },
    });
  } catch (err) {
    console.error("Create approval request error:", err);
    res.status(500).json({ error: "Failed to create approval request" });
  }
});

// List pending approvals for current user
router.get("/pending", requireUser, detectTenant, async (req, res) => {
  try {
    const approvals = await capabilityApprovals.listPendingForUser(req.user.id);
    res.json({ approvals });
  } catch (err) {
    console.error("List pending approvals error:", err);
    res.status(500).json({ error: "Failed to list pending approvals" });
  }
});

// List all approvals for current user (with history)
router.get("/history", requireUser, detectTenant, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const approvals = await capabilityApprovals.listAllForUser(req.user.id, limit);
    res.json({ approvals });
  } catch (err) {
    console.error("List approval history error:", err);
    res.status(500).json({ error: "Failed to list approval history" });
  }
});

// Get a specific approval
router.get("/:id", requireUser, detectTenant, async (req, res) => {
  try {
    const approval = await capabilityApprovals.findById(req.params.id);

    if (!approval) {
      return res.status(404).json({ error: "Approval not found" });
    }

    if (approval.user_id !== req.user.id) {
      return res.status(403).json({ error: "Not your approval" });
    }

    res.json({ approval });
  } catch (err) {
    console.error("Get approval error:", err);
    res.status(500).json({ error: "Failed to get approval" });
  }
});

// Check approval status (called by agent/container to poll)
router.get("/:id/status", requireUser, detectTenant, async (req, res) => {
  try {
    const approval = await capabilityApprovals.findById(req.params.id);

    if (!approval) {
      return res.status(404).json({ error: "Approval not found" });
    }

    if (approval.user_id !== req.user.id) {
      return res.status(403).json({ error: "Not your approval" });
    }

    res.json({
      id: approval.id,
      status: approval.status,
      decidedAt: approval.decided_at,
    });
  } catch (err) {
    console.error("Check approval status error:", err);
    res.status(500).json({ error: "Failed to check approval status" });
  }
});

// Approve a capability request with optional constraints
router.post("/:id/approve", requireUser, detectTenant, async (req, res) => {
  try {
    const approval = await capabilityApprovals.findById(req.params.id);

    if (!approval) {
      return res.status(404).json({ error: "Approval not found" });
    }

    if (approval.user_id !== req.user.id) {
      return res.status(403).json({ error: "Not your approval to decide" });
    }

    if (approval.status !== "pending") {
      return res.status(400).json({ error: "Approval is not pending" });
    }

    if (new Date(approval.expires_at) < new Date()) {
      return res.status(400).json({ error: "Approval request has expired" });
    }

    // Extract optional constraints from request body
    const { constraints } = req.body || {};
    let appliedConstraints = {};

    if (constraints) {
      // Validate and apply constraints
      if (
        constraints.expiresInSeconds !== undefined &&
        typeof constraints.expiresInSeconds === "number"
      ) {
        // Cannot extend beyond original request
        appliedConstraints.expiresInSeconds = Math.min(
          constraints.expiresInSeconds,
          approval.expires_in_seconds,
        );
      }

      if (constraints.scope && Array.isArray(constraints.scope)) {
        // Can only reduce scope, not expand it
        appliedConstraints.scope = constraints.scope.filter((s) => approval.scope.includes(s));
        if (appliedConstraints.scope.length === 0) {
          return res.status(400).json({ error: "At least one permission must be granted" });
        }
      }

      if (constraints.maxCalls !== undefined) {
        // Can set or reduce max calls
        if (constraints.maxCalls === null) {
          // Use original
          appliedConstraints.maxCalls = approval.max_calls;
        } else if (typeof constraints.maxCalls === "number" && constraints.maxCalls > 0) {
          appliedConstraints.maxCalls = approval.max_calls
            ? Math.min(constraints.maxCalls, approval.max_calls)
            : constraints.maxCalls;
        }
      }
    }

    const updated = await capabilityApprovals.approveWithConstraints(
      req.params.id,
      appliedConstraints,
    );

    await audit.log(
      req.user.id,
      "capability.approval.approved",
      {
        approvalId: req.params.id,
        resource: approval.resource,
        scope: appliedConstraints.scope || approval.scope,
        subjectEmail: approval.subject_email,
        constraints: appliedConstraints,
      },
      req.ip,
    );

    // Notify any listening agents/containers
    broadcastToUser(req.user.id, "capability_approval_decided", {
      id: approval.id,
      status: "approved",
      resource: approval.resource,
      constraints: appliedConstraints,
    });

    res.json({ success: true, approval: updated, appliedConstraints });
  } catch (err) {
    console.error("Approve capability error:", err);
    res.status(500).json({ error: "Failed to approve capability" });
  }
});

// Deny a capability request
router.post("/:id/deny", requireUser, detectTenant, async (req, res) => {
  try {
    const approval = await capabilityApprovals.findById(req.params.id);

    if (!approval) {
      return res.status(404).json({ error: "Approval not found" });
    }

    if (approval.user_id !== req.user.id) {
      return res.status(403).json({ error: "Not your approval to decide" });
    }

    if (approval.status !== "pending") {
      return res.status(400).json({ error: "Approval is not pending" });
    }

    const updated = await capabilityApprovals.deny(req.params.id);

    await audit.log(
      req.user.id,
      "capability.approval.denied",
      {
        approvalId: req.params.id,
        resource: approval.resource,
        scope: approval.scope,
        subjectEmail: approval.subject_email,
      },
      req.ip,
    );

    // Notify any listening agents/containers
    broadcastToUser(req.user.id, "capability_approval_decided", {
      id: approval.id,
      status: "denied",
      resource: approval.resource,
    });

    res.json({ success: true, approval: updated });
  } catch (err) {
    console.error("Deny capability error:", err);
    res.status(500).json({ error: "Failed to deny capability" });
  }
});

// Approve via token (from push notification or magic link)
router.post("/token/:token/approve", async (req, res) => {
  try {
    const approval = await capabilityApprovals.findByToken(req.params.token);

    if (!approval) {
      return res.status(404).json({ error: "Invalid or expired approval token" });
    }

    if (approval.status !== "pending") {
      return res.status(400).json({ error: "Approval is not pending" });
    }

    const updated = await capabilityApprovals.approve(approval.id);

    await audit.log(
      approval.user_id,
      "capability.approval.approved",
      {
        approvalId: approval.id,
        resource: approval.resource,
        scope: approval.scope,
        subjectEmail: approval.subject_email,
        method: "token",
      },
      req.ip,
    );

    // Notify any listening agents/containers
    broadcastToUser(approval.user_id, "capability_approval_decided", {
      id: approval.id,
      status: "approved",
      resource: approval.resource,
    });

    res.json({ success: true, message: "Capability approved" });
  } catch (err) {
    console.error("Approve via token error:", err);
    res.status(500).json({ error: "Failed to approve capability" });
  }
});

// Deny via token (from push notification or magic link)
router.post("/token/:token/deny", async (req, res) => {
  try {
    const approval = await capabilityApprovals.findByToken(req.params.token);

    if (!approval) {
      return res.status(404).json({ error: "Invalid or expired approval token" });
    }

    if (approval.status !== "pending") {
      return res.status(400).json({ error: "Approval is not pending" });
    }

    const updated = await capabilityApprovals.deny(approval.id);

    await audit.log(
      approval.user_id,
      "capability.approval.denied",
      {
        approvalId: approval.id,
        resource: approval.resource,
        scope: approval.scope,
        subjectEmail: approval.subject_email,
        method: "token",
      },
      req.ip,
    );

    // Notify any listening agents/containers
    broadcastToUser(approval.user_id, "capability_approval_decided", {
      id: approval.id,
      status: "denied",
      resource: approval.resource,
    });

    res.json({ success: true, message: "Capability denied" });
  } catch (err) {
    console.error("Deny via token error:", err);
    res.status(500).json({ error: "Failed to deny capability" });
  }
});

// Validate a token (for UI to display approval details)
router.get("/token/:token", async (req, res) => {
  try {
    const approval = await capabilityApprovals.findByToken(req.params.token);

    if (!approval) {
      return res.status(404).json({ error: "Invalid or expired approval token" });
    }

    res.json({
      valid: true,
      approval: {
        id: approval.id,
        status: approval.status,
        resource: approval.resource,
        scope: approval.scope,
        subjectEmail: approval.subject_email,
        reason: approval.reason,
        agentContext: approval.agent_context,
        createdAt: approval.created_at,
        expiresAt: approval.expires_at,
        userName: approval.user_name,
      },
    });
  } catch (err) {
    console.error("Validate token error:", err);
    res.status(500).json({ error: "Failed to validate token" });
  }
});

// Mark an approved capability as issued (called by container after signing)
router.post("/:id/issued", requireUser, detectTenant, async (req, res) => {
  try {
    const approval = await capabilityApprovals.findById(req.params.id);

    if (!approval) {
      return res.status(404).json({ error: "Approval not found" });
    }

    if (approval.user_id !== req.user.id) {
      return res.status(403).json({ error: "Not your approval" });
    }

    if (approval.status !== "approved") {
      return res.status(400).json({ error: "Approval is not approved" });
    }

    const updated = await capabilityApprovals.markIssued(req.params.id);

    await audit.log(
      req.user.id,
      "capability.issued",
      {
        approvalId: req.params.id,
        resource: approval.resource,
        scope: approval.scope,
        subjectEmail: approval.subject_email,
      },
      req.ip,
    );

    res.json({ success: true, approval: updated });
  } catch (err) {
    console.error("Mark issued error:", err);
    res.status(500).json({ error: "Failed to mark as issued" });
  }
});

export default router;
