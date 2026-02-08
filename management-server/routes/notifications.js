// Notifications SSE stream route
import { Router } from "express";
import { capabilityApprovals, notifications } from "../db/index.js";
import { sseConnections, broadcastToUser } from "../lib/sse.js";
import { requireUser } from "../middleware/auth.js";
import { requireUserSSE } from "../middleware/sse-auth.js";
import { detectTenant } from "../middleware/tenant-context.js";

const router = Router();

// SSE stream for real-time notifications
// Uses SSE-specific auth that allows query param tokens for EventSource
// This uses the same SSE connection pool as chat, so events from either work
router.get("/stream", requireUserSSE, (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no"); // Disable nginx buffering

  const userId = req.user.id;
  if (!sseConnections.has(userId)) {
    sseConnections.set(userId, new Set());
  }
  sseConnections.get(userId).add(res);

  res.write(`event: connected\ndata: ${JSON.stringify({ userId, type: "notifications" })}\n\n`);

  // Send initial pending approval count
  capabilityApprovals
    .listPendingForUser(userId)
    .then((approvals) => {
      res.write(`event: approval_count\ndata: ${JSON.stringify({ count: approvals.length })}\n\n`);
    })
    .catch((err) => {
      console.error("Failed to get initial approval count:", err);
    });

  // Heartbeat to keep connection alive
  const heartbeat = setInterval(() => {
    try {
      res.write(`: heartbeat\n\n`);
    } catch (e) {
      // Connection closed
    }
  }, 30000);

  req.on("close", () => {
    clearInterval(heartbeat);
    sseConnections.get(userId)?.delete(res);
    if (sseConnections.get(userId)?.size === 0) {
      sseConnections.delete(userId);
    }
  });
});

// Get pending approval count
router.get("/approval-count", requireUser, detectTenant, async (req, res) => {
  try {
    const approvals = await capabilityApprovals.listPendingForUser(req.user.id);
    res.json({ count: approvals.length });
  } catch (err) {
    console.error("Get approval count error:", err);
    res.status(500).json({ error: "Failed to get approval count" });
  }
});

// Get all unread notifications
router.get("/", requireUser, detectTenant, async (req, res) => {
  try {
    const unread = await notifications.getUnread(req.user.id);
    const recent = await notifications.getRecent(req.user.id, 50);
    res.json({
      unread,
      recent,
      unreadCount: unread.length,
    });
  } catch (err) {
    console.error("Get notifications error:", err);
    res.status(500).json({ error: "Failed to get notifications" });
  }
});

// Mark notification as read
router.post("/:id/read", requireUser, detectTenant, async (req, res) => {
  try {
    const notification = await notifications.markRead(req.params.id, req.user.id);
    if (!notification) {
      return res.status(404).json({ error: "Notification not found" });
    }
    res.json({ success: true, notification });
  } catch (err) {
    console.error("Mark notification read error:", err);
    res.status(500).json({ error: "Failed to mark notification as read" });
  }
});

// Mark all notifications as read
router.post("/read-all", requireUser, detectTenant, async (req, res) => {
  try {
    const marked = await notifications.markAllRead(req.user.id);
    res.json({ success: true, count: marked.length });
  } catch (err) {
    console.error("Mark all read error:", err);
    res.status(500).json({ error: "Failed to mark all as read" });
  }
});

export default router;
