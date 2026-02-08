import crypto from "crypto";
// Biometrics and device key routes
import { Router } from "express";
import { users, audit, deviceKeys, encrypt, decrypt } from "../db/index.js";
import { vaultSessions, VAULT_SESSION_TIMEOUT_MS } from "../lib/vault-sessions.js";
import { canUseBiometrics } from "../lib/vault.js";
import { requireUser } from "../middleware/auth.js";
import { detectTenant } from "../middleware/tenant-context.js";
import { requireVaultUnlocked } from "./vault.js";

const router = Router();

// Enable biometrics for this device
router.post("/enable", requireUser, detectTenant, requireVaultUnlocked, async (req, res) => {
  try {
    const { deviceName, deviceFingerprint } = req.body;

    if (!deviceName || !deviceFingerprint) {
      return res.status(400).json({ error: "Device name and fingerprint required" });
    }

    const deviceKey = crypto.randomBytes(32);

    await deviceKeys.create({
      userId: req.user.id,
      deviceName,
      deviceFingerprint,
      encryptedDeviceKey: encrypt(deviceKey.toString("base64")),
    });

    await users.setBiometricsEnabled(req.user.id, true);
    await audit.log(req.user.id, "biometrics.enabled", { device: deviceName }, req.ip);

    res.json({ success: true, deviceKey: deviceKey.toString("base64") });
  } catch (err) {
    console.error("Biometrics enable error:", err);
    res.status(500).json({ error: "Failed to enable biometrics" });
  }
});

// Unlock with biometrics
router.post("/unlock", requireUser, detectTenant, async (req, res) => {
  try {
    const { deviceKey, deviceFingerprint } = req.body;

    if (!deviceKey || !deviceFingerprint) {
      return res.status(400).json({ error: "Device key and fingerprint required" });
    }

    const biometricsStatus = await users.getBiometricsStatus(req.user.id);
    if (!biometricsStatus?.biometrics_enabled) {
      return res.status(401).json({ error: "Biometrics not enabled", code: "BIOMETRICS_DISABLED" });
    }

    if (
      !canUseBiometrics(
        biometricsStatus.biometrics_last_password_at,
        biometricsStatus.biometrics_max_age_days,
      )
    ) {
      return res
        .status(401)
        .json({
          error: "Password required",
          code: "BIOMETRICS_EXPIRED",
          reason: "biometrics_expired",
        });
    }

    const deviceKeyRecord = await deviceKeys.findByUserAndFingerprint(
      req.user.id,
      deviceFingerprint,
    );
    if (!deviceKeyRecord) {
      return res.status(401).json({ error: "Device not registered", code: "UNKNOWN_DEVICE" });
    }

    const storedDeviceKey = decrypt(deviceKeyRecord.encrypted_device_key);
    if (storedDeviceKey !== deviceKey) {
      await audit.log(
        req.user.id,
        "biometrics.unlock_failed",
        { device: deviceFingerprint },
        req.ip,
      );
      return res.status(401).json({ error: "Invalid device key" });
    }

    const vaultSessionToken = crypto.randomBytes(32).toString("hex");
    vaultSessions.set(vaultSessionToken, {
      userId: req.user.id,
      unlockedAt: Date.now(),
      expiresAt: Date.now() + VAULT_SESSION_TIMEOUT_MS,
      biometric: true,
    });

    await deviceKeys.updateLastUsed(deviceKeyRecord.id);
    await audit.log(
      req.user.id,
      "vault.unlocked_biometrics",
      { device: deviceFingerprint },
      req.ip,
    );

    res.json({ success: true, vaultSessionToken, expiresIn: 30 * 60 });
  } catch (err) {
    console.error("Biometrics unlock error:", err);
    res.status(500).json({ error: "Failed to unlock with biometrics" });
  }
});

// Check biometrics status
router.get("/status", requireUser, detectTenant, async (req, res) => {
  try {
    const { deviceFingerprint } = req.query;

    const biometricsStatus = await users.getBiometricsStatus(req.user.id);
    const canUse =
      biometricsStatus?.biometrics_enabled &&
      canUseBiometrics(
        biometricsStatus.biometrics_last_password_at,
        biometricsStatus.biometrics_max_age_days,
      );

    let deviceRegistered = false;
    if (deviceFingerprint) {
      const deviceRecord = await deviceKeys.findByUserAndFingerprint(
        req.user.id,
        deviceFingerprint,
      );
      deviceRegistered = !!deviceRecord;
    }

    res.json({
      biometricsEnabled: biometricsStatus?.biometrics_enabled || false,
      canUseBiometrics: canUse,
      deviceRegistered,
      lastPasswordAt: biometricsStatus?.biometrics_last_password_at,
      maxAgeDays: biometricsStatus?.biometrics_max_age_days || 14,
      passwordRequiredReason: !canUse && biometricsStatus?.biometrics_enabled ? "expired" : null,
    });
  } catch (err) {
    console.error("Biometrics status error:", err);
    res.status(500).json({ error: "Failed to get biometrics status" });
  }
});

// Disable biometrics
router.post("/disable", requireUser, detectTenant, requireVaultUnlocked, async (req, res) => {
  try {
    await deviceKeys.deleteAllForUser(req.user.id);
    await users.setBiometricsEnabled(req.user.id, false);
    await audit.log(req.user.id, "biometrics.disabled", null, req.ip);
    res.json({ success: true });
  } catch (err) {
    console.error("Biometrics disable error:", err);
    res.status(500).json({ error: "Failed to disable biometrics" });
  }
});

// List registered devices
router.get("/devices", requireUser, detectTenant, requireVaultUnlocked, async (req, res) => {
  try {
    const devices = await deviceKeys.listForUser(req.user.id);
    res.json({ devices });
  } catch (err) {
    console.error("List devices error:", err);
    res.status(500).json({ error: "Failed to list devices" });
  }
});

// Remove a device
router.delete(
  "/devices/:deviceId",
  requireUser,
  detectTenant,
  requireVaultUnlocked,
  async (req, res) => {
    try {
      await deviceKeys.delete(req.params.deviceId, req.user.id);
      await audit.log(req.user.id, "device.removed", { deviceId: req.params.deviceId }, req.ip);
      res.json({ success: true });
    } catch (err) {
      console.error("Remove device error:", err);
      res.status(500).json({ error: "Failed to remove device" });
    }
  },
);

export default router;
