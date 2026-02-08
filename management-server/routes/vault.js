import crypto from "crypto";
// Vault routes - Zero-knowledge encryption, biometrics, device keys
import { Router } from "express";
import {
  users,
  audit,
  deviceKeys,
  encrypt,
  decrypt,
  meshAuditLogs,
  MESH_AUDIT_EVENTS,
} from "../db/index.js";
import { logActivity, ACTION_TYPES, isVaultLockedByAnomaly } from "../lib/anomaly-detection.js";
import { syncCredentialsFromVaultData } from "../lib/context.js";
import { vaultUnlockLimiter, recoveryLimiter } from "../lib/rate-limit.js";
import {
  validate,
  validateBody,
  vaultSetupSchema,
  vaultUnlockSchema,
  vaultChangePasswordSchema,
  vaultRecoverSchema,
  vaultDataUpdateSchema,
  uuidSchema,
  userIdParamSchema,
} from "../lib/schemas.js";
import {
  vaultSessions,
  createVaultSession,
  getVaultSession,
  extendVaultSession,
  deleteVaultSession,
  VAULT_SESSION_TIMEOUT_MS,
  VAULT_SESSION_TIMEOUT_SEC,
} from "../lib/vault-sessions.js";
import {
  createVault,
  unlockVault,
  unlockVaultWithPasswordAndKey,
  unlockVaultWithRecovery,
  updateVault,
  createVaultWithData,
  changePassword as changeVaultPassword,
  exportVault,
  canUseBiometrics,
} from "../lib/vault.js";
import { requireUser } from "../middleware/auth.js";
import { detectTenant } from "../middleware/tenant-context.js";

const router = Router();

// Middleware: require vault unlocked
async function requireVaultUnlocked(req, res, next) {
  const vaultSessionToken = req.headers["x-vault-session"] || req.cookies?.ocmt_vault_session;
  if (!vaultSessionToken) {
    return res.status(401).json({ error: "Vault is locked", code: "VAULT_LOCKED" });
  }
  const session = await getVaultSession(vaultSessionToken);
  if (!session || session.userId !== req.user.id) {
    return res.status(401).json({ error: "Vault session expired", code: "VAULT_SESSION_EXPIRED" });
  }
  req.vaultSession = session;
  next();
}

// Check vault status
router.get("/status", requireUser, detectTenant, async (req, res) => {
  try {
    const hasVault = await users.hasVault(req.user.id);
    const vaultSessionToken = req.headers["x-vault-session"];

    let isUnlocked = false;
    let expiresIn = 0;

    if (vaultSessionToken) {
      const session = await getVaultSession(vaultSessionToken);
      if (session && session.userId === req.user.id) {
        isUnlocked = true;
        expiresIn = Math.floor((session.expiresAt - Date.now()) / 1000);
      }
    }

    const biometricsStatus = await users.getBiometricsStatus(req.user.id);

    res.json({
      hasVault,
      isUnlocked,
      expiresIn,
      biometrics: biometricsStatus
        ? {
            enabled: biometricsStatus.biometrics_enabled,
            canUse: canUseBiometrics(
              biometricsStatus.biometrics_last_password_at,
              biometricsStatus.biometrics_max_age_days,
            ),
            lastPasswordAt: biometricsStatus.biometrics_last_password_at,
            maxAgeDays: biometricsStatus.biometrics_max_age_days,
          }
        : null,
    });
  } catch (err) {
    console.error("Vault status error:", err);
    res.status(500).json({ error: "Failed to get vault status" });
  }
});

// Create vault (first time setup)
router.post(
  "/setup",
  requireUser,
  detectTenant,
  validate({ body: vaultSetupSchema }),
  async (req, res) => {
    try {
      const { password } = req.validatedBody;

      const existing = await users.hasVault(req.user.id);
      if (existing) {
        return res.status(400).json({ error: "Vault already exists" });
      }

      const { vault, recoveryPhrase } = await createVault(password);
      await users.setVault(req.user.id, vault);
      await audit.log(req.user.id, "vault.created", null, req.ip);

      // Log to mesh audit
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.VAULT_CREATED,
        actorId: req.user.id,
        ipAddress: req.ip,
        success: true,
        details: { hasRecoveryPhrase: true },
      });

      res.json({
        success: true,
        recoveryPhrase,
        message: "Save your recovery phrase securely. It will not be shown again.",
      });
    } catch (err) {
      console.error("Vault setup error:", err);
      res.status(500).json({ error: "Failed to create vault" });
    }
  },
);

// Unlock vault
// Rate limited: 5 attempts per 15 minutes per IP to prevent brute force
router.post(
  "/unlock",
  vaultUnlockLimiter,
  requireUser,
  detectTenant,
  validate({ body: vaultUnlockSchema }),
  async (req, res) => {
    try {
      const { password } = req.validatedBody;

      // Check if vault is locked due to anomaly detection
      const lockedByAnomaly = await isVaultLockedByAnomaly(req.user.id);
      if (lockedByAnomaly) {
        return res.status(403).json({
          error: "Vault is locked due to suspicious activity",
          code: "VAULT_LOCKED_ANOMALY",
          message:
            "Please review the security alerts in your account settings and acknowledge them before unlocking.",
        });
      }

      const vault = await users.getVault(req.user.id);
      if (!vault) {
        return res.status(400).json({ error: "No vault found. Please set up your vault first." });
      }

      const { data, key } = await unlockVaultWithPasswordAndKey(vault, password);

      const vaultSessionToken = crypto.randomBytes(32).toString("hex");
      vaultSessions.set(vaultSessionToken, {
        userId: req.user.id,
        unlockedAt: Date.now(),
        expiresAt: Date.now() + VAULT_SESSION_TIMEOUT_MS,
        vaultKey: key,
      });

      await users.updateBiometricsLastPassword(req.user.id);
      await audit.log(req.user.id, "vault.unlocked", null, req.ip);

      // Log to mesh audit
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.VAULT_UNLOCKED,
        actorId: req.user.id,
        ipAddress: req.ip,
        success: true,
      });

      // Log vault unlock for anomaly detection
      logActivity(req.user.id, ACTION_TYPES.VAULT_UNLOCK, null, { ip: req.ip }).catch((err) => {
        console.error("Failed to log vault unlock activity:", err.message);
      });

      // Sync credentials to container when vault is unlocked
      // Pass vaultKey so we can refresh expired tokens and persist them
      if (data.integrations && Object.keys(data.integrations).length > 0) {
        syncCredentialsFromVaultData(req.user.id, data, {
          vaultKey: key,
          updateVaultOnRefresh: true,
        }).catch((err) => {
          console.error("Failed to sync credentials on unlock:", err.message);
        });
      }

      res.cookie("ocmt_vault_session", vaultSessionToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: VAULT_SESSION_TIMEOUT_MS,
      });

      res.json({ success: true, vaultSessionToken, expiresIn: VAULT_SESSION_TIMEOUT_SEC });
    } catch (err) {
      if (err.message === "Invalid password") {
        await audit.log(req.user.id, "vault.unlock_failed", null, req.ip);
        // Log failed unlock attempt to mesh audit
        await meshAuditLogs.log({
          eventType: MESH_AUDIT_EVENTS.VAULT_UNLOCK_FAILED,
          actorId: req.user.id,
          ipAddress: req.ip,
          success: false,
          errorMessage: "Invalid password",
        });
        return res.status(401).json({ error: "Invalid vault password" });
      }
      console.error("Vault unlock error:", err);
      res.status(500).json({ error: "Failed to unlock vault" });
    }
  },
);

// Lock vault
router.post("/lock", requireUser, detectTenant, async (req, res) => {
  try {
    const vaultSessionToken = req.headers["x-vault-session"] || req.cookies?.ocmt_vault_session;
    if (vaultSessionToken) {
      await deleteVaultSession(vaultSessionToken);
    }
    res.clearCookie("ocmt_vault_session");
    await audit.log(req.user.id, "vault.locked", null, req.ip);

    // Log to mesh audit
    await meshAuditLogs.log({
      eventType: MESH_AUDIT_EVENTS.VAULT_LOCKED,
      actorId: req.user.id,
      ipAddress: req.ip,
      success: true,
    });

    res.json({ success: true });
  } catch (err) {
    console.error("Vault lock error:", err);
    res.status(500).json({ error: "Failed to lock vault" });
  }
});

// Extend vault session
router.post("/extend", requireUser, detectTenant, requireVaultUnlocked, async (req, res) => {
  try {
    const vaultSessionToken = req.headers["x-vault-session"];
    if (await extendVaultSession(vaultSessionToken)) {
      res.json({ expiresIn: VAULT_SESSION_TIMEOUT_SEC });
    } else {
      res.status(401).json({ error: "Session expired" });
    }
  } catch (err) {
    console.error("Vault extend error:", err);
    res.status(500).json({ error: "Failed to extend session" });
  }
});

// Download vault backup
router.get("/backup", requireUser, detectTenant, async (req, res) => {
  try {
    const vault = await users.getVault(req.user.id);
    if (!vault) {
      return res.status(400).json({ error: "No vault found" });
    }
    await audit.log(req.user.id, "vault.backup_downloaded", null, req.ip);
    const backup = exportVault(vault);
    res.setHeader("Content-Type", "application/json");
    res.setHeader("Content-Disposition", `attachment; filename="ocmt-vault-${Date.now()}.vault"`);
    res.send(backup);
  } catch (err) {
    console.error("Vault backup error:", err);
    res.status(500).json({ error: "Failed to download backup" });
  }
});

// Recover with recovery phrase
// Rate limited: 3 attempts per 30 minutes to prevent enumeration
router.post(
  "/recover",
  recoveryLimiter,
  requireUser,
  detectTenant,
  validate({ body: vaultRecoverSchema }),
  async (req, res) => {
    try {
      const { recoveryPhrase, newPassword } = req.validatedBody;

      const vault = await users.getVault(req.user.id);
      if (!vault) {
        return res.status(400).json({ error: "No vault found" });
      }

      const { data, seed } = unlockVaultWithRecovery(vault, recoveryPhrase);
      const { vault: newVault } = await createVaultWithData(newPassword, data, seed);
      await users.setVault(req.user.id, newVault);
      await users.setBiometricsEnabled(req.user.id, false);
      await deviceKeys.deleteAllForUser(req.user.id);
      await audit.log(req.user.id, "vault.password_reset_via_recovery", null, req.ip);

      // Log to mesh audit
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.VAULT_RECOVERED,
        actorId: req.user.id,
        ipAddress: req.ip,
        success: true,
        details: { method: "recovery_phrase" },
      });

      res.json({ success: true, message: "Password reset successfully." });
    } catch (err) {
      if (err.message === "Invalid recovery phrase") {
        await audit.log(req.user.id, "vault.recovery_failed", null, req.ip);
        return res.status(401).json({ error: "Invalid recovery phrase" });
      }
      console.error("Vault recovery error:", err);
      res.status(500).json({ error: "Failed to recover vault" });
    }
  },
);

// Change password
router.post(
  "/change-password",
  requireUser,
  detectTenant,
  requireVaultUnlocked,
  validate({ body: vaultChangePasswordSchema }),
  async (req, res) => {
    try {
      const { currentPassword, newPassword } = req.validatedBody;

      const vault = await users.getVault(req.user.id);
      if (!vault) {
        return res.status(400).json({ error: "No vault found" });
      }

      const { vault: newVault } = await changeVaultPassword(vault, currentPassword, newPassword);
      await users.setVault(req.user.id, newVault);

      const vaultSessionToken = req.headers["x-vault-session"];
      if (vaultSessionToken) {
        await deleteVaultSession(vaultSessionToken);
      }

      await users.setBiometricsEnabled(req.user.id, false);
      await deviceKeys.deleteAllForUser(req.user.id);
      await audit.log(req.user.id, "vault.password_changed", null, req.ip);

      // Log to mesh audit
      await meshAuditLogs.log({
        eventType: MESH_AUDIT_EVENTS.VAULT_PASSWORD_CHANGED,
        actorId: req.user.id,
        ipAddress: req.ip,
        success: true,
      });

      res.json({ success: true, message: "Password changed successfully." });
    } catch (err) {
      if (err.message === "Invalid password") {
        return res.status(401).json({ error: "Current password is incorrect" });
      }
      console.error("Change password error:", err);
      res.status(500).json({ error: "Failed to change password" });
    }
  },
);

// Get vault data
router.get("/data", requireUser, detectTenant, requireVaultUnlocked, async (req, res) => {
  res.json({ success: true, message: "Vault is unlocked. Use specific endpoints to access data." });
});

// Update vault data
router.post(
  "/data",
  requireUser,
  detectTenant,
  requireVaultUnlocked,
  validate({ body: vaultDataUpdateSchema }),
  async (req, res) => {
    try {
      const { password, data } = req.validatedBody;

      const vault = await users.getVault(req.user.id);
      if (!vault) {
        return res.status(400).json({ error: "No vault found" });
      }

      const newVault = await updateVault(vault, password, data);
      await users.updateVault(req.user.id, newVault);
      await audit.log(req.user.id, "vault.data_updated", null, req.ip);

      res.json({ success: true });
    } catch (err) {
      if (err.message === "Invalid password") {
        return res.status(401).json({ error: "Invalid password" });
      }
      console.error("Update vault data error:", err);
      res.status(500).json({ error: "Failed to update vault data" });
    }
  },
);

// Get credentials (requires password)
router.get("/credentials", requireUser, detectTenant, requireVaultUnlocked, async (req, res) => {
  try {
    const { password } = req.query;
    if (!password) {
      return res.json({
        success: true,
        available: true,
        message: "Vault is unlocked. Send password to retrieve credentials.",
      });
    }

    const vault = await users.getVault(req.user.id);
    if (!vault) {
      return res.status(400).json({ error: "No vault found" });
    }

    const data = await unlockVault(vault, password);
    await audit.log(req.user.id, "vault.credentials_accessed", null, req.ip);

    // Log credential access for anomaly detection
    logActivity(req.user.id, ACTION_TYPES.CREDENTIAL_ACCESS, "vault_credentials", {
      ip: req.ip,
    }).catch((err) => {
      console.error("Failed to log credential access activity:", err.message);
    });

    res.json({
      success: true,
      credentials: data.credentials || [],
      integrations: data.integrations || {},
    });
  } catch (err) {
    if (err.message === "Invalid password") {
      return res.status(401).json({ error: "Invalid password" });
    }
    console.error("Get credentials error:", err);
    res.status(500).json({ error: "Failed to get credentials" });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Vault Migration to Container
// ─────────────────────────────────────────────────────────────────────────────

import {
  migrateUserToContainerVault,
  getMigrationStatus,
  checkMigrationEligibility,
  listMigrationCandidates,
  MIGRATION_STATUS,
} from "../lib/migration.js";

// Admin-only middleware (simple check - in production use proper RBAC)
function requireAdmin(req, res, next) {
  // For now, check if user has admin role in any org or is in allowed admin list
  const adminEmails = (process.env.ADMIN_EMAILS || "")
    .split(",")
    .map((e) => e.trim().toLowerCase());
  if (adminEmails.includes(req.user.email?.toLowerCase())) {
    return next();
  }
  return res.status(403).json({ error: "Admin access required" });
}

// Get migration status for a user (admin or self)
router.get(
  "/migrate/:userId/status",
  requireUser,
  detectTenant,
  validate({ params: userIdParamSchema }),
  async (req, res) => {
    try {
      const { userId } = req.validatedParams;

      // Allow user to check their own status, or admin to check anyone
      const adminEmails = (process.env.ADMIN_EMAILS || "")
        .split(",")
        .map((e) => e.trim().toLowerCase());
      const isAdmin = adminEmails.includes(req.user.email?.toLowerCase());

      if (userId !== req.user.id && !isAdmin) {
        return res.status(403).json({ error: "Access denied" });
      }

      const status = await getMigrationStatus(userId);
      const eligibility = await checkMigrationEligibility(userId);

      res.json({
        userId,
        migration: status,
        eligibility,
      });
    } catch (err) {
      console.error("Migration status error:", err);
      res.status(500).json({ error: "Failed to get migration status" });
    }
  },
);

// Migrate user vault to container (admin only)
router.post(
  "/migrate/:userId",
  requireUser,
  detectTenant,
  requireAdmin,
  requireVaultUnlocked,
  validate({ params: userIdParamSchema }),
  async (req, res) => {
    try {
      const { userId } = req.validatedParams;
      const { force, containerPassword } = req.body;

      // The admin must have unlocked the target user's vault
      // This requires the admin to have the user's vault password
      // In practice, the user would initiate this themselves

      // For admin migration, we need to get the target user's vault session
      // This is complex - let's check if this is self-migration or admin migration
      if (userId === req.user.id) {
        // Self-migration: use the current vault session
        const vaultSessionToken = req.headers["x-vault-session"] || req.cookies?.ocmt_vault_session;

        const result = await migrateUserToContainerVault(userId, {
          vaultSessionToken,
          containerPassword,
          force,
          adminUserId: req.user.id,
          ipAddress: req.ip,
        });

        return res.json(result);
      }

      // Admin migration of another user requires their vault to be unlocked
      // This is a security feature - admins cannot migrate without user consent
      return res.status(400).json({
        error: "Admin migration requires user vault session",
        hint: "The target user must unlock their vault and provide the session token",
      });
    } catch (err) {
      console.error("Migration error:", err);
      res.status(500).json({ error: "Migration failed", message: err.message });
    }
  },
);

// Self-migration endpoint (user migrates their own vault)
router.post("/migrate", requireUser, detectTenant, requireVaultUnlocked, async (req, res) => {
  try {
    const { containerPassword, force } = req.body;
    const vaultSessionToken = req.headers["x-vault-session"] || req.cookies?.ocmt_vault_session;

    const result = await migrateUserToContainerVault(req.user.id, {
      vaultSessionToken,
      containerPassword,
      force,
      adminUserId: req.user.id,
      ipAddress: req.ip,
    });

    res.json(result);
  } catch (err) {
    console.error("Self-migration error:", err);
    res.status(500).json({ error: "Migration failed", message: err.message });
  }
});

// List migration candidates (admin only)
router.get("/migrate/candidates", requireUser, detectTenant, requireAdmin, async (req, res) => {
  try {
    const candidates = await listMigrationCandidates();
    res.json({
      total: candidates.length,
      candidates,
      statusCounts: {
        notStarted: candidates.filter((c) => c.migrationStatus === MIGRATION_STATUS.NOT_STARTED)
          .length,
        completed: candidates.filter((c) => c.migrationStatus === MIGRATION_STATUS.COMPLETED)
          .length,
        failed: candidates.filter((c) => c.migrationStatus === MIGRATION_STATUS.FAILED).length,
        partial: candidates.filter((c) => c.migrationStatus === MIGRATION_STATUS.PARTIAL).length,
        inProgress: candidates.filter((c) => c.migrationStatus === MIGRATION_STATUS.IN_PROGRESS)
          .length,
      },
    });
  } catch (err) {
    console.error("List candidates error:", err);
    res.status(500).json({ error: "Failed to list migration candidates" });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Container Vault Sync (encrypted blob storage)
// Container pushes encrypted vault blob here for persistent storage
// Management server NEVER has the decryption key
// ─────────────────────────────────────────────────────────────────────────────

// Receive encrypted vault blob from container for storage
// This is called by the container after vault data changes
// The blob is already encrypted - we just store it
router.post("/container-sync", requireUser, detectTenant, async (req, res) => {
  try {
    const { encryptedVault, version, checksum } = req.body;

    if (!encryptedVault) {
      return res.status(400).json({ error: "encryptedVault required" });
    }

    // Store the encrypted vault blob
    // This replaces the user's vault with the container-encrypted version
    // We never decrypt it - just store the blob as-is
    await users.setContainerVault(req.user.id, {
      encryptedVault,
      version: version || 1,
      checksum,
      syncedAt: new Date().toISOString(),
    });

    await audit.log(req.user.id, "vault.container_sync", { version, checksum }, req.ip);

    // Log to mesh audit
    await meshAuditLogs.log({
      eventType: MESH_AUDIT_EVENTS.VAULT_CONTAINER_SYNC || "vault.container_sync",
      actorId: req.user.id,
      ipAddress: req.ip,
      success: true,
      details: { version, checksum },
    });

    res.json({ success: true, syncedAt: new Date().toISOString() });
  } catch (err) {
    console.error("Container vault sync error:", err);
    res.status(500).json({ error: "Failed to sync container vault" });
  }
});

// Get the stored encrypted vault blob for container restore
// Container calls this on startup to restore its vault state
router.get("/container-sync", requireUser, detectTenant, async (req, res) => {
  try {
    const containerVault = await users.getContainerVault(req.user.id);

    if (!containerVault) {
      return res.json({
        success: true,
        exists: false,
        encryptedVault: null,
      });
    }

    await audit.log(req.user.id, "vault.container_restore", null, req.ip);

    res.json({
      success: true,
      exists: true,
      ...containerVault,
    });
  } catch (err) {
    console.error("Container vault restore error:", err);
    res.status(500).json({ error: "Failed to get container vault" });
  }
});

export default router;
export { requireVaultUnlocked };
