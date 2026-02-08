// Agent activity and anomaly detection routes
import { Router } from "express";
import { agentActivity, anomalyAlerts, notifications } from "../db/index.js";
import {
  getActivityDigest,
  isVaultLockedByAnomaly,
  unlockVaultAfterAnomaly,
} from "../lib/anomaly-detection.js";
import { requireUser } from "../middleware/auth.js";
import { detectTenant } from "../middleware/tenant-context.js";

const router = Router();

// GET /api/agent/activity-digest - Weekly activity summary
router.get("/activity-digest", requireUser, detectTenant, async (req, res) => {
  try {
    const days = parseInt(req.query.days, 10) || 7;
    const digest = await getActivityDigest(req.user.id, days);
    res.json({ success: true, digest });
  } catch (err) {
    console.error("Get activity digest error:", err);
    res.status(500).json({ error: "Failed to get activity digest" });
  }
});

// GET /api/agent/recent-activity - Recent activity log
router.get("/recent-activity", requireUser, detectTenant, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
    const activity = await agentActivity.getRecentActivity(req.user.id, limit);
    res.json({ success: true, activity });
  } catch (err) {
    console.error("Get recent activity error:", err);
    res.status(500).json({ error: "Failed to get recent activity" });
  }
});

// GET /api/agent/security-status - Check for security issues
router.get("/security-status", requireUser, detectTenant, async (req, res) => {
  try {
    const vaultLockedByAnomaly = await isVaultLockedByAnomaly(req.user.id);
    const unacknowledgedAlerts = await anomalyAlerts.getUnacknowledged(req.user.id);
    const unreadNotifications = await notifications.countUnread(req.user.id);

    res.json({
      success: true,
      status: {
        vaultLockedByAnomaly,
        unacknowledgedAlerts: unacknowledgedAlerts.length,
        unreadNotifications,
        alerts: unacknowledgedAlerts.map((a) => ({
          id: a.id,
          type: a.alert_type,
          severity: a.severity,
          description: a.description,
          createdAt: a.created_at,
        })),
      },
    });
  } catch (err) {
    console.error("Get security status error:", err);
    res.status(500).json({ error: "Failed to get security status" });
  }
});

// POST /api/agent/acknowledge-alerts - Acknowledge security alerts
router.post("/acknowledge-alerts", requireUser, detectTenant, async (req, res) => {
  try {
    const { alertId } = req.body;

    if (alertId) {
      // Acknowledge specific alert
      const alert = await anomalyAlerts.acknowledge(alertId, req.user.id);
      if (!alert) {
        return res.status(404).json({ error: "Alert not found" });
      }
      res.json({ success: true, alert });
    } else {
      // Acknowledge all alerts
      const alerts = await anomalyAlerts.acknowledgeAll(req.user.id);
      res.json({ success: true, acknowledged: alerts.length });
    }
  } catch (err) {
    console.error("Acknowledge alerts error:", err);
    res.status(500).json({ error: "Failed to acknowledge alerts" });
  }
});

// POST /api/agent/unlock-after-anomaly - Unlock vault after anomaly detection
router.post("/unlock-after-anomaly", requireUser, detectTenant, async (req, res) => {
  try {
    const isLocked = await isVaultLockedByAnomaly(req.user.id);
    if (!isLocked) {
      return res.status(400).json({ error: "Vault is not locked by anomaly" });
    }

    await unlockVaultAfterAnomaly(req.user.id);
    res.json({
      success: true,
      message: "Vault anomaly lock cleared. You can now unlock your vault normally.",
    });
  } catch (err) {
    console.error("Unlock after anomaly error:", err);
    res.status(500).json({ error: "Failed to clear anomaly lock" });
  }
});

// GET /api/agent/notifications - Get user notifications
router.get("/notifications", requireUser, detectTenant, async (req, res) => {
  try {
    const unreadOnly = req.query.unread === "true";
    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);

    let notifs;
    if (unreadOnly) {
      notifs = await notifications.getUnread(req.user.id);
    } else {
      notifs = await notifications.getRecent(req.user.id, limit);
    }

    const unreadCount = await notifications.countUnread(req.user.id);

    res.json({
      success: true,
      notifications: notifs,
      unreadCount,
    });
  } catch (err) {
    console.error("Get notifications error:", err);
    res.status(500).json({ error: "Failed to get notifications" });
  }
});

// POST /api/agent/notifications/:id/read - Mark notification as read
router.post("/notifications/:id/read", requireUser, detectTenant, async (req, res) => {
  try {
    const notif = await notifications.markRead(req.params.id, req.user.id);
    if (!notif) {
      return res.status(404).json({ error: "Notification not found" });
    }
    res.json({ success: true, notification: notif });
  } catch (err) {
    console.error("Mark notification read error:", err);
    res.status(500).json({ error: "Failed to mark notification as read" });
  }
});

// POST /api/agent/notifications/read-all - Mark all notifications as read
router.post("/notifications/read-all", requireUser, detectTenant, async (req, res) => {
  try {
    const marked = await notifications.markAllRead(req.user.id);
    res.json({ success: true, marked: marked.length });
  } catch (err) {
    console.error("Mark all notifications read error:", err);
    res.status(500).json({ error: "Failed to mark notifications as read" });
  }
});

// DELETE /api/agent/notifications/:id - Delete notification
router.delete("/notifications/:id", requireUser, detectTenant, async (req, res) => {
  try {
    await notifications.delete(req.params.id, req.user.id);
    res.json({ success: true });
  } catch (err) {
    console.error("Delete notification error:", err);
    res.status(500).json({ error: "Failed to delete notification" });
  }
});

// GET /api/agent/alerts - Get anomaly alerts
router.get("/alerts", requireUser, detectTenant, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
    const alerts = await anomalyAlerts.getRecent(req.user.id, limit);
    const unacknowledged = alerts.filter((a) => !a.acknowledged_at);

    res.json({
      success: true,
      alerts,
      unacknowledgedCount: unacknowledged.length,
    });
  } catch (err) {
    console.error("Get alerts error:", err);
    res.status(500).json({ error: "Failed to get alerts" });
  }
});

export default router;
