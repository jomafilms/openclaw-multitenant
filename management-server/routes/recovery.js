import crypto from "crypto";
// Recovery routes - Social recovery and hardware backup
import { Router } from "express";
import {
  users,
  audit,
  recoveryMethods,
  recoveryContacts,
  recoveryRequests,
  recoveryShards,
  encrypt,
  decrypt,
} from "../db/index.js";
import {
  setupSocialRecovery,
  decryptContactShard,
  recoverSeedFromShards,
  generateHardwareBackupKey,
  setupHardwareRecovery,
  recoverWithHardwareKey,
  createRecoveryToken,
  hashRecoveryToken,
  RecoveryMethodType,
} from "../lib/recovery.js";
import { vaultSessions, getVaultSession } from "../lib/vault-sessions.js";
import {
  unlockVault,
  unlockVaultWithKey,
  createVaultWithData,
  decrypt as vaultDecrypt,
} from "../lib/vault.js";
import { requireUser } from "../middleware/auth.js";
import { detectTenant } from "../middleware/tenant-context.js";
import { requireVaultUnlocked } from "./vault.js";

const router = Router();

// Recovery request expiry (48 hours)
const RECOVERY_REQUEST_EXPIRY_MS = 48 * 60 * 60 * 1000;

// ============================================================
// RECOVERY STATUS
// ============================================================

// Get enabled recovery methods for user
router.get("/status", requireUser, detectTenant, async (req, res) => {
  try {
    const methods = await recoveryMethods.listForUser(req.user.id);
    const contacts = await recoveryContacts.listForUser(req.user.id);
    const activeRequest = await recoveryRequests.findActiveForUser(req.user.id);

    res.json({
      methods: methods.map((m) => ({
        type: m.method_type,
        enabled: m.enabled,
        createdAt: m.created_at,
        updatedAt: m.updated_at,
      })),
      socialRecovery: {
        configured: methods.some((m) => m.method_type === "social" && m.enabled),
        contactCount: contacts.length,
        contacts: contacts.map((c) => ({
          email: c.contact_email,
          name: c.contact_name,
          addedAt: c.created_at,
        })),
      },
      hardwareBackup: {
        configured: methods.some((m) => m.method_type === "hardware" && m.enabled),
      },
      activeRecoveryRequest: activeRequest
        ? {
            id: activeRequest.id,
            shardsCollected: activeRequest.shards_collected,
            threshold: activeRequest.threshold,
            expiresAt: activeRequest.expires_at,
          }
        : null,
    });
  } catch (err) {
    console.error("Recovery status error:", err);
    res.status(500).json({ error: "Failed to get recovery status" });
  }
});

// ============================================================
// SOCIAL RECOVERY SETUP
// ============================================================

// Set up social recovery with trusted contacts
// Requires vault to be unlocked to access the seed
router.post("/social/setup", requireUser, detectTenant, requireVaultUnlocked, async (req, res) => {
  try {
    const { contacts, threshold = 3 } = req.body;

    // Validate contacts
    if (!Array.isArray(contacts) || contacts.length < 3) {
      return res.status(400).json({ error: "Need at least 3 trusted contacts" });
    }
    if (contacts.length > 10) {
      return res.status(400).json({ error: "Maximum 10 contacts allowed" });
    }
    if (threshold < 2 || threshold > contacts.length) {
      return res.status(400).json({ error: `Threshold must be between 2 and ${contacts.length}` });
    }

    // Validate each contact
    for (const contact of contacts) {
      if (!contact.email || !contact.name) {
        return res.status(400).json({ error: "Each contact must have email and name" });
      }
      // Basic email validation
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contact.email)) {
        return res.status(400).json({ error: `Invalid email: ${contact.email}` });
      }
      // Cannot add self
      if (contact.email.toLowerCase() === req.user.email?.toLowerCase()) {
        return res.status(400).json({ error: "Cannot add yourself as a recovery contact" });
      }
    }

    // Check for duplicate emails
    const emails = contacts.map((c) => c.email.toLowerCase());
    if (new Set(emails).size !== emails.length) {
      return res.status(400).json({ error: "Duplicate contact emails" });
    }

    // Get the vault seed from the session
    const vaultSessionToken = req.headers["x-vault-session"] || req.cookies?.ocmt_vault_session;
    const session = await getVaultSession(vaultSessionToken);
    if (!session || !session.vaultKey) {
      return res.status(401).json({ error: "Vault session invalid" });
    }

    // Get the vault and extract the seed
    const vault = await users.getVault(req.user.id);
    if (!vault) {
      return res.status(400).json({ error: "No vault found" });
    }

    // Decrypt the seed from the vault using the session key
    const seedNonce = Buffer.from(vault.recovery.nonce, "base64");
    const seedTag = Buffer.from(vault.recovery.tag, "base64");
    const seedCiphertext = Buffer.from(vault.recovery.encrypted_seed, "base64");
    const seed = vaultDecrypt(session.vaultKey, seedNonce, seedTag, seedCiphertext);

    // Set up social recovery (creates Shamir shares)
    const socialSetup = setupSocialRecovery(seed, contacts, threshold);

    // Delete existing contacts
    await recoveryContacts.deleteForUser(req.user.id);

    // Store each contact's shard
    for (const contact of socialSetup.contacts) {
      await recoveryContacts.create({
        userId: req.user.id,
        recoveryId: socialSetup.recoveryId,
        contactEmail: contact.email,
        contactName: contact.name,
        shareIndex: contact.shareIndex,
        shardEncrypted: encrypt(JSON.stringify(contact.encryptedShard)),
      });
    }

    // Store the recovery method config
    await recoveryMethods.create({
      userId: req.user.id,
      methodType: RecoveryMethodType.SOCIAL,
      configEncrypted: encrypt(
        JSON.stringify({
          recoveryId: socialSetup.recoveryId,
          threshold: socialSetup.threshold,
          totalShares: socialSetup.totalShares,
          createdAt: socialSetup.createdAt,
        }),
      ),
      enabled: true,
    });

    await audit.log(
      req.user.id,
      "recovery.social.setup",
      {
        contactCount: contacts.length,
        threshold,
      },
      req.ip,
    );

    res.json({
      success: true,
      recoveryId: socialSetup.recoveryId,
      threshold: socialSetup.threshold,
      totalShares: socialSetup.totalShares,
      message: `Social recovery configured. ${threshold} of ${contacts.length} contacts needed for recovery.`,
    });
  } catch (err) {
    console.error("Social recovery setup error:", err);
    res.status(500).json({ error: "Failed to set up social recovery" });
  }
});

// Disable social recovery
router.delete("/social", requireUser, detectTenant, requireVaultUnlocked, async (req, res) => {
  try {
    await recoveryContacts.deleteForUser(req.user.id);
    await recoveryMethods.delete(req.user.id, RecoveryMethodType.SOCIAL);
    await audit.log(req.user.id, "recovery.social.disabled", null, req.ip);
    res.json({ success: true });
  } catch (err) {
    console.error("Disable social recovery error:", err);
    res.status(500).json({ error: "Failed to disable social recovery" });
  }
});

// ============================================================
// SOCIAL RECOVERY INITIATION
// ============================================================

// Initiate social recovery process (when user forgot password)
router.post("/social/initiate", requireUser, detectTenant, async (req, res) => {
  try {
    // Check if social recovery is configured
    const socialMethod = await recoveryMethods.findByUserAndType(
      req.user.id,
      RecoveryMethodType.SOCIAL,
    );
    if (!socialMethod || !socialMethod.enabled) {
      return res.status(400).json({ error: "Social recovery not configured" });
    }

    // Check for existing active request
    const existingRequest = await recoveryRequests.findActiveForUser(req.user.id);
    if (existingRequest) {
      return res.status(400).json({
        error: "Recovery already in progress",
        requestId: existingRequest.id,
        shardsCollected: existingRequest.shards_collected,
        threshold: existingRequest.threshold,
        expiresAt: existingRequest.expires_at,
      });
    }

    // Get recovery config
    const configEncrypted = socialMethod.config_encrypted;
    const config = JSON.parse(decrypt(configEncrypted));

    // Create recovery token
    const recoveryToken = createRecoveryToken();
    const tokenHash = hashRecoveryToken(recoveryToken);

    // Create recovery request
    const expiresAt = new Date(Date.now() + RECOVERY_REQUEST_EXPIRY_MS);
    const request = await recoveryRequests.create({
      userId: req.user.id,
      recoveryId: config.recoveryId,
      tokenHash,
      threshold: config.threshold,
      expiresAt,
    });

    await audit.log(
      req.user.id,
      "recovery.social.initiated",
      {
        requestId: request.id,
      },
      req.ip,
    );

    // Return the token (user shares with contacts) and contact list
    const contacts = await recoveryContacts.listForUser(req.user.id);

    res.json({
      success: true,
      recoveryToken, // User shares this with contacts
      requestId: request.id,
      threshold: config.threshold,
      totalContacts: contacts.length,
      contacts: contacts.map((c) => ({
        email: c.contact_email,
        name: c.contact_name,
      })),
      expiresAt: expiresAt.toISOString(),
      message: `Share the recovery token with ${config.threshold} of your ${contacts.length} contacts. They will use it to submit their recovery shards.`,
    });
  } catch (err) {
    console.error("Social recovery initiation error:", err);
    res.status(500).json({ error: "Failed to initiate social recovery" });
  }
});

// Cancel active recovery request
router.delete("/social/request", requireUser, detectTenant, async (req, res) => {
  try {
    const request = await recoveryRequests.findActiveForUser(req.user.id);
    if (!request) {
      return res.status(404).json({ error: "No active recovery request" });
    }

    await recoveryShards.deleteForRequest(request.id);
    await recoveryRequests.cancel(request.id);
    await audit.log(req.user.id, "recovery.social.cancelled", { requestId: request.id }, req.ip);

    res.json({ success: true });
  } catch (err) {
    console.error("Cancel recovery error:", err);
    res.status(500).json({ error: "Failed to cancel recovery" });
  }
});

// ============================================================
// SHARD SUBMISSION (Contact endpoint)
// ============================================================

// Submit a recovery shard (called by recovery contacts)
router.post("/social/submit-shard", async (req, res) => {
  try {
    const { recoveryToken, contactEmail } = req.body;

    if (!recoveryToken || !contactEmail) {
      return res.status(400).json({ error: "Recovery token and contact email required" });
    }

    // Find the recovery request
    const tokenHash = hashRecoveryToken(recoveryToken);
    const request = await recoveryRequests.findByTokenHash(tokenHash);
    if (!request) {
      return res.status(404).json({ error: "Invalid or expired recovery token" });
    }

    // Find the contact's shard
    const contact = await recoveryContacts.findByUserAndEmail(request.user_id, contactEmail);
    if (!contact) {
      return res.status(403).json({ error: "You are not a recovery contact for this user" });
    }

    // Check if already submitted
    const existingShards = await recoveryShards.listForRequest(request.id);
    if (existingShards.some((s) => s.contact_email === contactEmail.toLowerCase())) {
      return res.status(400).json({ error: "Shard already submitted" });
    }

    // Get the recovery config
    const socialMethod = await recoveryMethods.findByUserAndType(
      request.user_id,
      RecoveryMethodType.SOCIAL,
    );
    const config = JSON.parse(decrypt(socialMethod.config_encrypted));

    // Decrypt the contact's shard
    const encryptedShard = JSON.parse(decrypt(contact.shard_encrypted));
    const decryptedShard = decryptContactShard(config.recoveryId, contactEmail, encryptedShard);

    // Store the submitted shard
    await recoveryShards.submit({
      requestId: request.id,
      contactEmail,
      shard: decryptedShard,
    });

    // Update shard count
    const shardCount = await recoveryShards.countForRequest(request.id);
    await recoveryRequests.updateShardsCollected(request.id, shardCount);

    await audit.log(
      request.user_id,
      "recovery.social.shard_submitted",
      {
        requestId: request.id,
        contactEmail,
        shardsCollected: shardCount,
      },
      req.ip,
    );

    res.json({
      success: true,
      shardsCollected: shardCount,
      threshold: request.threshold,
      complete: shardCount >= request.threshold,
      message:
        shardCount >= request.threshold
          ? "Enough shards collected! The user can now complete recovery."
          : `${request.threshold - shardCount} more shards needed.`,
    });
  } catch (err) {
    console.error("Shard submission error:", err);
    res.status(500).json({ error: "Failed to submit shard" });
  }
});

// Get recovery request status (for both user and contacts)
router.get("/social/status/:token", async (req, res) => {
  try {
    const tokenHash = hashRecoveryToken(req.params.token);
    const request = await recoveryRequests.findByTokenHash(tokenHash);

    if (!request) {
      return res.status(404).json({ error: "Invalid or expired recovery token" });
    }

    const shards = await recoveryShards.listForRequest(request.id);

    res.json({
      requestId: request.id,
      userName: request.user_name,
      status: request.status,
      shardsCollected: request.shards_collected,
      threshold: request.threshold,
      submittedBy: shards.map((s) => s.contact_email),
      expiresAt: request.expires_at,
      complete: request.shards_collected >= request.threshold,
    });
  } catch (err) {
    console.error("Recovery status error:", err);
    res.status(500).json({ error: "Failed to get recovery status" });
  }
});

// ============================================================
// COMPLETE SOCIAL RECOVERY
// ============================================================

// Complete social recovery (reset password with recovered seed)
router.post("/social/complete", requireUser, detectTenant, async (req, res) => {
  try {
    const { newPassword } = req.body;

    if (!newPassword || newPassword.length < 12) {
      return res.status(400).json({ error: "Password must be at least 12 characters" });
    }

    // Get active recovery request
    const request = await recoveryRequests.findActiveForUser(req.user.id);
    if (!request) {
      return res.status(404).json({ error: "No active recovery request" });
    }

    // Check if enough shards collected
    if (request.shards_collected < request.threshold) {
      return res.status(400).json({
        error: `Need ${request.threshold - request.shards_collected} more shards`,
        shardsCollected: request.shards_collected,
        threshold: request.threshold,
      });
    }

    // Get submitted shards
    const shards = await recoveryShards.listForRequest(request.id);
    const shardData = shards.map((s) => ({ shard: s.shard }));

    // Reconstruct the seed
    const recoveredSeed = recoverSeedFromShards(shardData);

    // Get current vault
    const vault = await users.getVault(req.user.id);
    if (!vault) {
      return res.status(400).json({ error: "No vault found" });
    }

    // Verify the recovered seed by trying to decrypt the vault
    const seedNonce = Buffer.from(vault.recovery.vault_nonce, "base64");
    const seedTag = Buffer.from(vault.recovery.vault_tag, "base64");
    const seedCiphertext = Buffer.from(vault.recovery.vault_ciphertext, "base64");

    let vaultData;
    try {
      const plaintext = vaultDecrypt(recoveredSeed, seedNonce, seedTag, seedCiphertext);
      vaultData = JSON.parse(plaintext.toString("utf8"));
    } catch {
      return res.status(400).json({ error: "Recovery failed - shards may be corrupted" });
    }

    // Create new vault with new password but same seed (keeps same recovery phrase)
    const { vault: newVault } = await createVaultWithData(newPassword, vaultData, recoveredSeed);
    await users.setVault(req.user.id, newVault);

    // Mark recovery complete
    await recoveryRequests.complete(request.id);
    await recoveryShards.deleteForRequest(request.id);

    await audit.log(
      req.user.id,
      "recovery.social.completed",
      {
        requestId: request.id,
      },
      req.ip,
    );

    res.json({
      success: true,
      message: "Password reset successfully via social recovery.",
    });
  } catch (err) {
    console.error("Complete social recovery error:", err);
    res.status(500).json({ error: "Failed to complete social recovery" });
  }
});

// ============================================================
// HARDWARE BACKUP SETUP
// ============================================================

// Generate hardware backup key
router.post(
  "/hardware/setup",
  requireUser,
  detectTenant,
  requireVaultUnlocked,
  async (req, res) => {
    try {
      // Get the vault session
      const vaultSessionToken = req.headers["x-vault-session"] || req.cookies?.ocmt_vault_session;
      const session = await getVaultSession(vaultSessionToken);
      if (!session || !session.vaultKey) {
        return res.status(401).json({ error: "Vault session invalid" });
      }

      // Get the vault and extract the seed
      const vault = await users.getVault(req.user.id);
      if (!vault) {
        return res.status(400).json({ error: "No vault found" });
      }

      // Decrypt the seed
      const seedNonce = Buffer.from(vault.recovery.nonce, "base64");
      const seedTag = Buffer.from(vault.recovery.tag, "base64");
      const seedCiphertext = Buffer.from(vault.recovery.encrypted_seed, "base64");
      const seed = vaultDecrypt(session.vaultKey, seedNonce, seedTag, seedCiphertext);

      // Generate hardware backup key
      const { backupKey, keyBytes, keyHash } = generateHardwareBackupKey();

      // Encrypt the seed with hardware key
      const hardwareRecovery = await setupHardwareRecovery(seed, keyBytes);

      // Store the recovery method config
      await recoveryMethods.create({
        userId: req.user.id,
        methodType: RecoveryMethodType.HARDWARE,
        configEncrypted: encrypt(
          JSON.stringify({
            encryptedSeed: hardwareRecovery.encryptedSeed,
            keyHash: hardwareRecovery.keyHash,
            createdAt: hardwareRecovery.createdAt,
          }),
        ),
        enabled: true,
      });

      await audit.log(req.user.id, "recovery.hardware.setup", null, req.ip);

      res.json({
        success: true,
        backupKey, // User must save this securely!
        message:
          "Store this backup key securely. It can be used to recover your vault if you forget your password. This key will not be shown again.",
      });
    } catch (err) {
      console.error("Hardware backup setup error:", err);
      res.status(500).json({ error: "Failed to set up hardware backup" });
    }
  },
);

// Disable hardware backup
router.delete("/hardware", requireUser, detectTenant, requireVaultUnlocked, async (req, res) => {
  try {
    await recoveryMethods.delete(req.user.id, RecoveryMethodType.HARDWARE);
    await audit.log(req.user.id, "recovery.hardware.disabled", null, req.ip);
    res.json({ success: true });
  } catch (err) {
    console.error("Disable hardware backup error:", err);
    res.status(500).json({ error: "Failed to disable hardware backup" });
  }
});

// ============================================================
// HARDWARE BACKUP RECOVERY
// ============================================================

// Recover vault using hardware backup key
router.post("/hardware/recover", requireUser, detectTenant, async (req, res) => {
  try {
    const { backupKey, newPassword } = req.body;

    if (!backupKey) {
      return res.status(400).json({ error: "Backup key required" });
    }
    if (!newPassword || newPassword.length < 12) {
      return res.status(400).json({ error: "Password must be at least 12 characters" });
    }

    // Check if hardware recovery is configured
    const hardwareMethod = await recoveryMethods.findByUserAndType(
      req.user.id,
      RecoveryMethodType.HARDWARE,
    );
    if (!hardwareMethod || !hardwareMethod.enabled) {
      return res.status(400).json({ error: "Hardware backup not configured" });
    }

    // Get recovery config
    const config = JSON.parse(decrypt(hardwareMethod.config_encrypted));

    // Recover seed using hardware key
    let recoveredSeed;
    try {
      recoveredSeed = await recoverWithHardwareKey(backupKey, config.encryptedSeed);
    } catch {
      await audit.log(req.user.id, "recovery.hardware.failed", null, req.ip);
      return res.status(401).json({ error: "Invalid backup key" });
    }

    // Get current vault and verify recovered seed
    const vault = await users.getVault(req.user.id);
    if (!vault) {
      return res.status(400).json({ error: "No vault found" });
    }

    // Decrypt vault data using recovered seed
    const seedNonce = Buffer.from(vault.recovery.vault_nonce, "base64");
    const seedTag = Buffer.from(vault.recovery.vault_tag, "base64");
    const seedCiphertext = Buffer.from(vault.recovery.vault_ciphertext, "base64");

    let vaultData;
    try {
      const plaintext = vaultDecrypt(recoveredSeed, seedNonce, seedTag, seedCiphertext);
      vaultData = JSON.parse(plaintext.toString("utf8"));
    } catch {
      return res.status(400).json({ error: "Recovery failed - backup key may be invalid" });
    }

    // Create new vault with new password
    const { vault: newVault } = await createVaultWithData(newPassword, vaultData, recoveredSeed);
    await users.setVault(req.user.id, newVault);

    await audit.log(req.user.id, "recovery.hardware.completed", null, req.ip);

    res.json({
      success: true,
      message: "Password reset successfully via hardware backup key.",
    });
  } catch (err) {
    console.error("Hardware recovery error:", err);
    res.status(500).json({ error: "Failed to recover with hardware key" });
  }
});

export default router;
