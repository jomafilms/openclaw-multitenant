// MFA API routes - TOTP setup, verification, and backup codes
import crypto from "crypto";
import { Router } from "express";
import { audit, sessions, users } from "../db/index.js";
import { mfaAttempts, mfaBackupCodes, pendingMfaSessions, userMfa } from "../db/mfa.js";
import { createRateLimiter } from "../lib/rate-limit.js";
import {
  generateBackupCodes,
  generateTotpQRCodeUri,
  generateTotpSecret,
  verifyBackupCode,
  verifyTotpCode,
} from "../lib/totp.js";
import { requireUser } from "../middleware/auth.js";
import { detectTenant } from "../middleware/tenant-context.js";

const router = Router();

// MFA verification rate limiter - 5 attempts per 15 minutes
const mfaVerifyLimiter = createRateLimiter({
  name: "mfa-verify",
  windowMs: 15 * 60 * 1000,
  maxRequests: 5,
  message: "Too many MFA verification attempts. Please try again in 15 minutes.",
  onLimitReached: async (req, key) => {
    console.warn(`[security] MFA verification rate limit reached for: ${key}`);
  },
});

// MFA setup rate limiter - 10 attempts per hour
const mfaSetupLimiter = createRateLimiter({
  name: "mfa-setup",
  windowMs: 60 * 60 * 1000,
  maxRequests: 10,
  message: "Too many MFA setup attempts. Please try again later.",
});

// ============================================================
// MFA STATUS
// ============================================================

/**
 * GET /api/mfa/status
 * Get MFA status for current user
 */
router.get("/status", requireUser, detectTenant, async (req, res) => {
  try {
    const status = await userMfa.getStatus(req.user.id);
    res.json(status);
  } catch (err) {
    console.error("MFA status error:", err);
    res.status(500).json({ error: "Failed to get MFA status" });
  }
});

// ============================================================
// TOTP SETUP
// ============================================================

/**
 * POST /api/mfa/setup
 * Begin TOTP setup - generates secret and QR code URI
 * Returns the secret (show once) and URI for QR generation
 */
router.post("/setup", requireUser, detectTenant, mfaSetupLimiter, async (req, res) => {
  try {
    // Check if TOTP is already enabled
    const existingMfa = await userMfa.findByUserId(req.user.id);
    if (existingMfa?.totp_enabled) {
      return res.status(400).json({
        error: "TOTP is already enabled. Disable it first to set up again.",
      });
    }

    // Generate new TOTP secret
    const { secret, encryptedSecret } = generateTotpSecret();

    // Generate QR code URI (frontend renders the QR)
    const qrUri = generateTotpQRCodeUri(req.user.email, secret);

    // Store encrypted secret (not yet enabled)
    await userMfa.setupTotp(req.user.id, encryptedSecret);

    await audit.log(req.user.id, "mfa.totp_setup_started", {}, req.ip);

    res.json({
      secret,
      qrUri,
      message: "Scan the QR code with your authenticator app, then verify with a code.",
    });
  } catch (err) {
    console.error("MFA setup error:", err);
    res.status(500).json({ error: "Failed to start MFA setup" });
  }
});

/**
 * POST /api/mfa/verify
 * Verify TOTP code and enable MFA
 * Also generates backup codes
 */
router.post("/verify", requireUser, detectTenant, mfaVerifyLimiter, async (req, res) => {
  try {
    const { code } = req.body;

    if (!code || typeof code !== "string") {
      return res.status(400).json({ error: "Verification code required" });
    }

    const mfaConfig = await userMfa.findByUserId(req.user.id);

    if (!mfaConfig?.totp_secret_encrypted) {
      return res.status(400).json({
        error: "TOTP setup not started. Call POST /api/mfa/setup first.",
      });
    }

    if (mfaConfig.totp_enabled) {
      return res.status(400).json({ error: "TOTP is already enabled" });
    }

    // Verify the code
    const isValid = verifyTotpCode(mfaConfig.totp_secret_encrypted, code);

    // Log the attempt
    await mfaAttempts.log({
      userId: req.user.id,
      attemptType: "totp_setup",
      success: isValid,
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"],
    });

    if (!isValid) {
      return res.status(401).json({ error: "Invalid verification code" });
    }

    // Enable TOTP
    await userMfa.enableTotp(req.user.id);

    // Generate backup codes
    const { codes, hashedCodes } = await generateBackupCodes();
    await mfaBackupCodes.replaceAll(req.user.id, hashedCodes);

    await audit.log(req.user.id, "mfa.totp_enabled", {}, req.ip);

    res.json({
      success: true,
      message: "MFA enabled successfully",
      backupCodes: codes,
      warning: "Save these backup codes securely. They will not be shown again.",
    });
  } catch (err) {
    console.error("MFA verify error:", err);
    res.status(500).json({ error: "Failed to verify MFA code" });
  }
});

// ============================================================
// DISABLE TOTP
// ============================================================

/**
 * POST /api/mfa/disable
 * Disable TOTP MFA (requires current code)
 */
router.post("/disable", requireUser, detectTenant, mfaVerifyLimiter, async (req, res) => {
  try {
    const { code } = req.body;

    if (!code || typeof code !== "string") {
      return res.status(400).json({ error: "Verification code required" });
    }

    const mfaConfig = await userMfa.findByUserId(req.user.id);

    if (!mfaConfig?.totp_enabled) {
      return res.status(400).json({ error: "TOTP is not enabled" });
    }

    // Verify the code before disabling
    const isValid = verifyTotpCode(mfaConfig.totp_secret_encrypted, code);

    // Log the attempt
    await mfaAttempts.log({
      userId: req.user.id,
      attemptType: "totp_disable",
      success: isValid,
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"],
    });

    if (!isValid) {
      return res.status(401).json({ error: "Invalid verification code" });
    }

    // Disable TOTP and clear secret
    await userMfa.disableTotp(req.user.id);

    // Delete all backup codes
    await mfaBackupCodes.deleteAll(req.user.id);

    await audit.log(req.user.id, "mfa.totp_disabled", {}, req.ip);

    res.json({ success: true, message: "MFA disabled successfully" });
  } catch (err) {
    console.error("MFA disable error:", err);
    res.status(500).json({ error: "Failed to disable MFA" });
  }
});

// ============================================================
// BACKUP CODES
// ============================================================

/**
 * POST /api/mfa/backup-codes
 * Generate new backup codes (requires current TOTP code)
 * Replaces any existing backup codes
 */
router.post("/backup-codes", requireUser, detectTenant, mfaVerifyLimiter, async (req, res) => {
  try {
    const { code } = req.body;

    if (!code || typeof code !== "string") {
      return res.status(400).json({ error: "Verification code required" });
    }

    const mfaConfig = await userMfa.findByUserId(req.user.id);

    if (!mfaConfig?.totp_enabled) {
      return res.status(400).json({ error: "MFA must be enabled to generate backup codes" });
    }

    // Verify TOTP code before generating new backup codes
    const isValid = verifyTotpCode(mfaConfig.totp_secret_encrypted, code);

    // Log the attempt
    await mfaAttempts.log({
      userId: req.user.id,
      attemptType: "backup_codes_regen",
      success: isValid,
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"],
    });

    if (!isValid) {
      return res.status(401).json({ error: "Invalid verification code" });
    }

    // Generate new backup codes
    const { codes, hashedCodes } = await generateBackupCodes();
    await mfaBackupCodes.replaceAll(req.user.id, hashedCodes);

    await audit.log(req.user.id, "mfa.backup_codes_regenerated", {}, req.ip);

    res.json({
      success: true,
      backupCodes: codes,
      warning: "Save these backup codes securely. They replace any previous codes.",
    });
  } catch (err) {
    console.error("Backup codes error:", err);
    res.status(500).json({ error: "Failed to generate backup codes" });
  }
});

/**
 * GET /api/mfa/backup-codes/count
 * Get count of remaining unused backup codes
 */
router.get("/backup-codes/count", requireUser, detectTenant, async (req, res) => {
  try {
    const count = await mfaBackupCodes.countUnused(req.user.id);
    res.json({ remaining: count });
  } catch (err) {
    console.error("Backup codes count error:", err);
    res.status(500).json({ error: "Failed to get backup codes count" });
  }
});

// ============================================================
// LOGIN VERIFICATION (used during auth flow)
// ============================================================

/**
 * POST /api/mfa/verify/totp
 * Verify TOTP during login (after magic link, before session creation)
 * Used when user has MFA enabled
 */
router.post("/verify/totp", mfaVerifyLimiter, async (req, res) => {
  try {
    const { pendingToken, code } = req.body;

    if (!pendingToken || !code) {
      return res.status(400).json({ error: "Pending token and code required" });
    }

    // Find pending MFA session
    const pending = await pendingMfaSessions.findValidByToken(pendingToken);
    if (!pending) {
      return res.status(401).json({ error: "Session expired or invalid" });
    }

    // Get MFA config
    const mfaConfig = await userMfa.findByUserId(pending.user_id);
    if (!mfaConfig?.totp_secret_encrypted) {
      return res.status(400).json({ error: "MFA not configured" });
    }

    // Verify code
    const isValid = verifyTotpCode(mfaConfig.totp_secret_encrypted, code);

    // Log the attempt
    await mfaAttempts.log({
      userId: pending.user_id,
      attemptType: "totp_login",
      success: isValid,
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"],
    });

    if (!isValid) {
      return res.status(401).json({ error: "Invalid verification code" });
    }

    // Complete login - create real session
    const sessionToken = crypto.randomBytes(32).toString("hex");
    const sessionExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

    await sessions.create(pending.user_id, sessionToken, sessionExpiresAt);

    // Delete pending MFA session
    await pendingMfaSessions.delete(pending.id);

    // Update MFA last verified timestamp
    await users.updateMfaLastVerified(pending.user_id);

    // Get user details
    const user = await users.findById(pending.user_id);

    await audit.log(pending.user_id, "mfa.login_verified", { method: "totp" }, req.ip);

    res.json({
      success: true,
      sessionToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (err) {
    console.error("MFA login verify error:", err);
    res.status(500).json({ error: "Failed to verify MFA" });
  }
});

/**
 * POST /api/mfa/verify/backup-code
 * Verify using backup code during login
 */
router.post("/verify/backup-code", mfaVerifyLimiter, async (req, res) => {
  try {
    const { pendingToken, code } = req.body;

    if (!pendingToken || !code) {
      return res.status(400).json({ error: "Pending token and backup code required" });
    }

    // Find pending MFA session
    const pending = await pendingMfaSessions.findValidByToken(pendingToken);
    if (!pending) {
      return res.status(401).json({ error: "Session expired or invalid" });
    }

    // Get all unused backup codes
    const backupCodes = await mfaBackupCodes.getUnused(pending.user_id);
    let matchedCode = null;

    // Check each backup code (need to verify against hash)
    for (const bc of backupCodes) {
      const isMatch = await verifyBackupCode(code, bc.code_hash);
      if (isMatch) {
        matchedCode = bc;
        break;
      }
    }

    // Log the attempt
    await mfaAttempts.log({
      userId: pending.user_id,
      attemptType: "backup_code_login",
      success: !!matchedCode,
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"],
    });

    if (!matchedCode) {
      return res.status(401).json({ error: "Invalid backup code" });
    }

    // Mark backup code as used
    await mfaBackupCodes.markUsed(matchedCode.id);

    // Complete login - create real session
    const sessionToken = crypto.randomBytes(32).toString("hex");
    const sessionExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

    await sessions.create(pending.user_id, sessionToken, sessionExpiresAt);

    // Delete pending MFA session
    await pendingMfaSessions.delete(pending.id);

    // Get remaining backup codes count
    const remainingCodes = backupCodes.length - 1;

    // Get user details
    const user = await users.findById(pending.user_id);

    await audit.log(pending.user_id, "mfa.login_verified", { method: "backup_code" }, req.ip);

    res.json({
      success: true,
      sessionToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
      backupCodesRemaining: remainingCodes,
      warning:
        remainingCodes < 3 ? "You are running low on backup codes. Generate new ones soon." : null,
    });
  } catch (err) {
    console.error("Backup code login verify error:", err);
    res.status(500).json({ error: "Failed to verify backup code" });
  }
});

export default router;
