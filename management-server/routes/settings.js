// User settings routes
import { Router } from "express";
import { users } from "../db/index.js";
import { requireUser } from "../middleware/auth.js";
import { detectTenant } from "../middleware/tenant-context.js";

const router = Router();

// Get user settings
router.get("/", requireUser, detectTenant, async (req, res) => {
  try {
    const settings = await users.getSettings(req.user.id);
    res.json({ settings });
  } catch (err) {
    console.error("Get settings error:", err);
    res.status(500).json({ error: "Failed to get settings" });
  }
});

// Update user settings (partial update)
router.patch("/", requireUser, detectTenant, async (req, res) => {
  try {
    const updates = req.body;
    const allowedKeys = ["vaultAutoLock", "theme", "notifications"];
    const filteredUpdates = {};
    for (const key of Object.keys(updates)) {
      if (allowedKeys.includes(key)) {
        filteredUpdates[key] = updates[key];
      }
    }
    const settings = await users.updateSettings(req.user.id, filteredUpdates);
    res.json({ settings });
  } catch (err) {
    console.error("Update settings error:", err);
    res.status(500).json({ error: "Failed to update settings" });
  }
});

export default router;
