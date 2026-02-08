/**
 * Per-tenant backup and restore module
 * Wave 5.5 - Multi-tenant SaaS enterprise feature
 *
 * Features:
 * - Create encrypted backups of tenant data
 * - Store backups locally or in S3
 * - Restore from backup (replace or merge)
 * - Export/import for migration
 * - Background backup jobs
 * - Scheduled automatic backups
 * - Retention policy (30 days default)
 *
 * Backup includes:
 * - Users (without password hashes for security)
 * - Groups and group memberships
 * - Group resources (with encrypted auth configs)
 * - Tenant settings
 * - Vault data (already encrypted, handled carefully)
 *
 * Excludes:
 * - Sessions (temporary data)
 * - API keys (security sensitive, regenerate on restore)
 * - Audit logs (kept separately for compliance)
 */

import crypto from "crypto";
import { createReadStream, createWriteStream, existsSync, mkdirSync } from "fs";
import fs from "fs/promises";
import path from "path";
import { pipeline } from "stream/promises";
import { promisify } from "util";
import zlib from "zlib";
import { query } from "../db/core.js";
import { groups, groupMemberships, groupResources } from "../db/groups.js";
import { tenants, tenantMemberships } from "../db/tenants.js";
import { users } from "../db/users.js";
import { encrypt, decrypt, generateKey } from "./encryption.js";

const gzip = promisify(zlib.gzip);
const gunzip = promisify(zlib.gunzip);

// ============================================================
// CONSTANTS
// ============================================================

// Backup storage configuration
const BACKUP_DIR = process.env.BACKUP_DIR || path.join(process.cwd(), "backups");
const S3_BUCKET = process.env.BACKUP_S3_BUCKET;
const S3_REGION = process.env.BACKUP_S3_REGION || "us-east-1";

// Retention configuration
const DEFAULT_RETENTION_DAYS = parseInt(process.env.BACKUP_RETENTION_DAYS || "30", 10);

// Backup format version (for future migrations)
const BACKUP_VERSION = 1;

// Backup status values
export const BACKUP_STATUS = {
  PENDING: "pending",
  IN_PROGRESS: "in_progress",
  COMPLETED: "completed",
  FAILED: "failed",
  EXPIRED: "expired",
};

// Restore mode values
export const RESTORE_MODE = {
  REPLACE: "replace", // Delete existing data, replace with backup
  MERGE: "merge", // Keep existing, add/update from backup
};

// In-memory backup job tracking (use Redis for distributed deployments)
const backupJobs = new Map();
const restoreJobs = new Map();

// Scheduled backup interval handle
let scheduledBackupInterval = null;

// ============================================================
// INITIALIZATION
// ============================================================

/**
 * Initialize backup storage directory
 */
function initBackupDir() {
  if (!existsSync(BACKUP_DIR)) {
    mkdirSync(BACKUP_DIR, { recursive: true, mode: 0o700 });
  }
}

// Initialize on module load
initBackupDir();

// ============================================================
// ENCRYPTION UTILITIES
// ============================================================

/**
 * Generate a backup encryption key from tenant-specific data
 * This key is derived from the tenant's master key stored in settings
 *
 * @param {string} tenantId - Tenant UUID
 * @returns {Promise<Buffer>} 32-byte encryption key
 */
async function getBackupKey(tenantId) {
  const tenant = await tenants.findById(tenantId);
  if (!tenant) {
    throw new Error("Tenant not found");
  }

  // Use tenant's backup key if exists, otherwise generate one
  let backupKeyHex = tenant.settings?.backup_key;
  if (!backupKeyHex) {
    // Generate and store a backup key
    backupKeyHex = generateKey();
    await tenants.updateSettings(tenantId, { backup_key: backupKeyHex });
  }

  return Buffer.from(backupKeyHex, "hex");
}

/**
 * Encrypt backup data with tenant-specific key
 *
 * @param {Buffer} data - Data to encrypt
 * @param {Buffer} key - 32-byte encryption key
 * @returns {{ nonce: Buffer, tag: Buffer, ciphertext: Buffer }} Encrypted data
 */
function encryptBackup(data, key) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { nonce, tag, ciphertext };
}

/**
 * Decrypt backup data
 *
 * @param {Buffer} nonce - 12-byte nonce
 * @param {Buffer} tag - 16-byte auth tag
 * @param {Buffer} ciphertext - Encrypted data
 * @param {Buffer} key - 32-byte encryption key
 * @returns {Buffer} Decrypted data
 */
function decryptBackup(nonce, tag, ciphertext, key) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// ============================================================
// DATA COLLECTION
// ============================================================

/**
 * Collect all data for a tenant backup
 *
 * @param {string} tenantId - Tenant UUID
 * @param {object} options - Collection options
 * @param {boolean} options.includeVault - Include vault data (default: true)
 * @param {boolean} options.includeSensitive - Include sensitive fields (default: false)
 * @returns {Promise<object>} Collected data
 */
async function collectTenantData(tenantId, options = {}) {
  const { includeVault = true, includeSensitive = false } = options;

  // Get tenant info
  const tenant = await tenants.findById(tenantId);
  if (!tenant) {
    throw new Error("Tenant not found");
  }

  // Collect users (without sensitive data by default)
  const usersResult = await query(
    `SELECT id, name, email, status, created_at, updated_at,
       ${includeVault ? "vault, vault_created_at," : ""}
       ${includeSensitive ? "password_hash, gateway_token, telegram_bot_token," : ""}
       biometrics_enabled, settings, mfa_required
     FROM users
     WHERE tenant_id = $1`,
    [tenantId],
  );

  // Collect groups
  const groupsResult = await query(
    `SELECT id, name, slug, description, created_at, updated_at
     FROM groups
     WHERE tenant_id = $1`,
    [tenantId],
  );

  // Collect group memberships
  const membershipsResult = await query(
    `SELECT user_id, group_id, role, created_at
     FROM group_memberships
     WHERE tenant_id = $1`,
    [tenantId],
  );

  // Collect group resources (auth_config is already encrypted in DB)
  const resourcesResult = await query(
    `SELECT id, group_id, name, description, resource_type, endpoint,
       auth_config_encrypted, metadata, status, created_at, updated_at
     FROM group_resources
     WHERE tenant_id = $1`,
    [tenantId],
  );

  // Collect shares
  const sharesResult = await query(
    `SELECT s.* FROM shares s
     JOIN group_resources gr ON s.resource_id = gr.id
     WHERE gr.tenant_id = $1`,
    [tenantId],
  );

  // Collect group vault data (already encrypted)
  const groupVaultsResult = await query(
    `SELECT gv.* FROM group_vaults gv
     JOIN groups g ON gv.group_id = g.id
     WHERE g.tenant_id = $1`,
    [tenantId],
  );

  // Collect threshold configurations
  const thresholdsResult = await query(
    `SELECT gt.* FROM group_threshold gt
     JOIN groups g ON gt.group_id = g.id
     WHERE g.tenant_id = $1`,
    [tenantId],
  );

  return {
    tenant: {
      id: tenant.id,
      name: tenant.name,
      slug: tenant.slug,
      settings: tenant.settings,
      status: tenant.status,
      created_at: tenant.created_at,
      updated_at: tenant.updated_at,
    },
    users: usersResult.rows,
    groups: groupsResult.rows,
    groupMemberships: membershipsResult.rows,
    groupResources: resourcesResult.rows,
    shares: sharesResult.rows,
    groupVaults: groupVaultsResult.rows,
    thresholds: thresholdsResult.rows,
  };
}

// ============================================================
// BACKUP CREATION
// ============================================================

/**
 * Create a backup for a tenant
 *
 * @param {string} tenantId - Tenant UUID
 * @param {object} options - Backup options
 * @param {boolean} options.includeVault - Include vault data (default: true)
 * @param {string} options.description - Optional description
 * @param {string} options.triggeredBy - User ID who triggered the backup
 * @returns {Promise<{ backupId: string, status: string }>} Backup ID and initial status
 */
export async function createBackup(tenantId, options = {}) {
  const { includeVault = true, description = "", triggeredBy = null } = options;

  // Generate backup ID
  const backupId = crypto.randomUUID();
  const timestamp = new Date().toISOString();

  // Initialize job tracking
  backupJobs.set(backupId, {
    id: backupId,
    tenantId,
    status: BACKUP_STATUS.PENDING,
    progress: 0,
    description,
    triggeredBy,
    createdAt: timestamp,
    startedAt: null,
    completedAt: null,
    error: null,
    metadata: null,
  });

  // Start backup in background
  runBackupJob(backupId, tenantId, { includeVault, description }).catch((err) => {
    console.error(`[tenant-backup] Backup ${backupId} failed:`, err);
    const job = backupJobs.get(backupId);
    if (job) {
      job.status = BACKUP_STATUS.FAILED;
      job.error = err.message;
      job.completedAt = new Date().toISOString();
    }
  });

  return {
    backupId,
    status: BACKUP_STATUS.PENDING,
    message: "Backup started in background",
  };
}

/**
 * Run the actual backup job
 */
async function runBackupJob(backupId, tenantId, options) {
  const job = backupJobs.get(backupId);
  if (!job) {
    return;
  }

  job.status = BACKUP_STATUS.IN_PROGRESS;
  job.startedAt = new Date().toISOString();
  job.progress = 10;

  try {
    // Collect data
    const data = await collectTenantData(tenantId, { includeVault: options.includeVault });
    job.progress = 40;

    // Build backup package
    const backupPackage = {
      version: BACKUP_VERSION,
      format: "ocmt-tenant-backup",
      tenantId,
      createdAt: job.createdAt,
      description: options.description,
      data,
    };

    // Serialize and compress
    const jsonData = JSON.stringify(backupPackage);
    const compressed = await gzip(Buffer.from(jsonData, "utf-8"));
    job.progress = 60;

    // Encrypt
    const key = await getBackupKey(tenantId);
    const { nonce, tag, ciphertext } = encryptBackup(compressed, key);
    job.progress = 80;

    // Build final backup file
    const backupFile = {
      format: "ocmt-backup-encrypted",
      version: 1,
      nonce: nonce.toString("base64"),
      tag: tag.toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    };

    // Save to storage
    const filename = `backup_${tenantId}_${backupId}.json`;
    const filepath = path.join(BACKUP_DIR, tenantId);

    // Create tenant backup directory
    if (!existsSync(filepath)) {
      mkdirSync(filepath, { recursive: true, mode: 0o700 });
    }

    await fs.writeFile(path.join(filepath, filename), JSON.stringify(backupFile), {
      mode: 0o600,
    });
    job.progress = 95;

    // Store metadata for listing
    const metadata = {
      id: backupId,
      tenantId,
      filename,
      size: Buffer.byteLength(JSON.stringify(backupFile)),
      createdAt: job.createdAt,
      description: options.description,
      userCount: data.users.length,
      groupCount: data.groups.length,
      resourceCount: data.groupResources.length,
      includesVault: options.includeVault,
      expiresAt: new Date(Date.now() + DEFAULT_RETENTION_DAYS * 24 * 60 * 60 * 1000).toISOString(),
    };

    // Save metadata
    await fs.writeFile(
      path.join(filepath, `metadata_${backupId}.json`),
      JSON.stringify(metadata, null, 2),
      { mode: 0o600 },
    );

    // TODO: Upload to S3 if configured
    if (S3_BUCKET) {
      // await uploadToS3(filepath, filename, backupFile);
    }

    // Mark complete
    job.status = BACKUP_STATUS.COMPLETED;
    job.progress = 100;
    job.completedAt = new Date().toISOString();
    job.metadata = metadata;

    console.log(`[tenant-backup] Backup ${backupId} completed for tenant ${tenantId}`);
  } catch (err) {
    job.status = BACKUP_STATUS.FAILED;
    job.error = err.message;
    job.completedAt = new Date().toISOString();
    throw err;
  }
}

// ============================================================
// BACKUP STATUS AND LISTING
// ============================================================

/**
 * Get backup job status
 *
 * @param {string} backupId - Backup UUID
 * @returns {object|null} Backup job status or null if not found
 */
export function getBackupStatus(backupId) {
  return backupJobs.get(backupId) || null;
}

/**
 * List all backups for a tenant
 *
 * @param {string} tenantId - Tenant UUID
 * @param {object} options - List options
 * @param {number} options.limit - Max results (default: 50)
 * @param {number} options.offset - Offset for pagination (default: 0)
 * @returns {Promise<{ backups: object[], total: number }>} List of backups
 */
export async function listBackups(tenantId, options = {}) {
  const { limit = 50, offset = 0 } = options;

  const backupPath = path.join(BACKUP_DIR, tenantId);

  if (!existsSync(backupPath)) {
    return { backups: [], total: 0 };
  }

  try {
    const files = await fs.readdir(backupPath);
    const metadataFiles = files.filter((f) => f.startsWith("metadata_") && f.endsWith(".json"));

    // Load all metadata
    const allBackups = [];
    for (const file of metadataFiles) {
      try {
        const content = await fs.readFile(path.join(backupPath, file), "utf-8");
        const metadata = JSON.parse(content);

        // Check if expired
        if (new Date(metadata.expiresAt) < new Date()) {
          metadata.status = BACKUP_STATUS.EXPIRED;
        } else {
          metadata.status = BACKUP_STATUS.COMPLETED;
        }

        allBackups.push(metadata);
      } catch (err) {
        console.warn(`[tenant-backup] Failed to read metadata file ${file}:`, err.message);
      }
    }

    // Add in-progress jobs
    for (const [, job] of backupJobs) {
      if (job.tenantId === tenantId && job.status !== BACKUP_STATUS.COMPLETED) {
        allBackups.push({
          id: job.id,
          tenantId: job.tenantId,
          status: job.status,
          progress: job.progress,
          createdAt: job.createdAt,
          description: job.description,
          error: job.error,
        });
      }
    }

    // Sort by creation date (newest first)
    allBackups.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    return {
      backups: allBackups.slice(offset, offset + limit),
      total: allBackups.length,
    };
  } catch (err) {
    if (err.code === "ENOENT") {
      return { backups: [], total: 0 };
    }
    throw err;
  }
}

/**
 * Get backup details by ID
 *
 * @param {string} tenantId - Tenant UUID
 * @param {string} backupId - Backup UUID
 * @returns {Promise<object|null>} Backup metadata or null if not found
 */
export async function getBackup(tenantId, backupId) {
  // Check in-progress jobs first
  const job = backupJobs.get(backupId);
  if (job && job.tenantId === tenantId) {
    return {
      id: job.id,
      tenantId: job.tenantId,
      status: job.status,
      progress: job.progress,
      createdAt: job.createdAt,
      startedAt: job.startedAt,
      completedAt: job.completedAt,
      description: job.description,
      error: job.error,
      metadata: job.metadata,
    };
  }

  // Check stored metadata
  const metadataPath = path.join(BACKUP_DIR, tenantId, `metadata_${backupId}.json`);
  try {
    const content = await fs.readFile(metadataPath, "utf-8");
    const metadata = JSON.parse(content);

    // Check if expired
    if (new Date(metadata.expiresAt) < new Date()) {
      metadata.status = BACKUP_STATUS.EXPIRED;
    } else {
      metadata.status = BACKUP_STATUS.COMPLETED;
    }

    return metadata;
  } catch (err) {
    if (err.code === "ENOENT") {
      return null;
    }
    throw err;
  }
}

/**
 * Delete a backup
 *
 * @param {string} tenantId - Tenant UUID
 * @param {string} backupId - Backup UUID
 * @returns {Promise<boolean>} True if deleted, false if not found
 */
export async function deleteBackup(tenantId, backupId) {
  const backupPath = path.join(BACKUP_DIR, tenantId);
  const backupFile = path.join(backupPath, `backup_${tenantId}_${backupId}.json`);
  const metadataFile = path.join(backupPath, `metadata_${backupId}.json`);

  let deleted = false;

  try {
    await fs.unlink(backupFile);
    deleted = true;
  } catch (err) {
    if (err.code !== "ENOENT") {
      throw err;
    }
  }

  try {
    await fs.unlink(metadataFile);
    deleted = true;
  } catch (err) {
    if (err.code !== "ENOENT") {
      throw err;
    }
  }

  // Also remove from in-progress jobs
  if (backupJobs.has(backupId)) {
    backupJobs.delete(backupId);
    deleted = true;
  }

  console.log(`[tenant-backup] Deleted backup ${backupId} for tenant ${tenantId}`);
  return deleted;
}

// ============================================================
// BACKUP VALIDATION
// ============================================================

/**
 * Validate a backup file's integrity
 *
 * @param {string} tenantId - Tenant UUID
 * @param {string} backupId - Backup UUID
 * @returns {Promise<{ valid: boolean, error?: string, details?: object }>} Validation result
 */
export async function validateBackup(tenantId, backupId) {
  try {
    // Load backup file
    const backupPath = path.join(BACKUP_DIR, tenantId, `backup_${tenantId}_${backupId}.json`);
    const backupContent = await fs.readFile(backupPath, "utf-8");
    const backupFile = JSON.parse(backupContent);

    // Check format
    if (backupFile.format !== "ocmt-backup-encrypted") {
      return { valid: false, error: "Invalid backup format" };
    }

    // Try to decrypt
    const key = await getBackupKey(tenantId);
    const nonce = Buffer.from(backupFile.nonce, "base64");
    const tag = Buffer.from(backupFile.tag, "base64");
    const ciphertext = Buffer.from(backupFile.ciphertext, "base64");

    const decrypted = decryptBackup(nonce, tag, ciphertext, key);
    const decompressed = await gunzip(decrypted);
    const backupData = JSON.parse(decompressed.toString("utf-8"));

    // Validate structure
    if (backupData.format !== "ocmt-tenant-backup") {
      return { valid: false, error: "Invalid backup data format" };
    }

    if (backupData.tenantId !== tenantId) {
      return { valid: false, error: "Backup belongs to a different tenant" };
    }

    return {
      valid: true,
      details: {
        version: backupData.version,
        createdAt: backupData.createdAt,
        userCount: backupData.data.users?.length || 0,
        groupCount: backupData.data.groups?.length || 0,
        resourceCount: backupData.data.groupResources?.length || 0,
      },
    };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

// ============================================================
// RESTORE OPERATIONS
// ============================================================

/**
 * Preview what would be restored from a backup
 *
 * @param {string} tenantId - Tenant UUID
 * @param {string} backupId - Backup UUID
 * @returns {Promise<object>} Preview of restore operation
 */
export async function previewRestore(tenantId, backupId) {
  // Load and decrypt backup
  const backupPath = path.join(BACKUP_DIR, tenantId, `backup_${tenantId}_${backupId}.json`);
  const backupContent = await fs.readFile(backupPath, "utf-8");
  const backupFile = JSON.parse(backupContent);

  const key = await getBackupKey(tenantId);
  const nonce = Buffer.from(backupFile.nonce, "base64");
  const tag = Buffer.from(backupFile.tag, "base64");
  const ciphertext = Buffer.from(backupFile.ciphertext, "base64");

  const decrypted = decryptBackup(nonce, tag, ciphertext, key);
  const decompressed = await gunzip(decrypted);
  const backupData = JSON.parse(decompressed.toString("utf-8"));

  // Get current state
  const currentData = await collectTenantData(tenantId, { includeVault: false });

  // Compare
  const preview = {
    backupCreatedAt: backupData.createdAt,
    changes: {
      users: {
        inBackup: backupData.data.users.length,
        current: currentData.users.length,
        new: 0,
        updated: 0,
        unchanged: 0,
      },
      groups: {
        inBackup: backupData.data.groups.length,
        current: currentData.groups.length,
        new: 0,
        updated: 0,
        unchanged: 0,
      },
      resources: {
        inBackup: backupData.data.groupResources.length,
        current: currentData.groupResources.length,
        new: 0,
        updated: 0,
        unchanged: 0,
      },
    },
    warnings: [],
  };

  // Calculate user changes
  const currentUserIds = new Set(currentData.users.map((u) => u.id));
  for (const user of backupData.data.users) {
    if (currentUserIds.has(user.id)) {
      preview.changes.users.updated++;
    } else {
      preview.changes.users.new++;
    }
  }
  preview.changes.users.unchanged = currentData.users.length - preview.changes.users.updated;

  // Calculate group changes
  const currentGroupIds = new Set(currentData.groups.map((g) => g.id));
  for (const group of backupData.data.groups) {
    if (currentGroupIds.has(group.id)) {
      preview.changes.groups.updated++;
    } else {
      preview.changes.groups.new++;
    }
  }
  preview.changes.groups.unchanged = currentData.groups.length - preview.changes.groups.updated;

  // Calculate resource changes
  const currentResourceIds = new Set(currentData.groupResources.map((r) => r.id));
  for (const resource of backupData.data.groupResources) {
    if (currentResourceIds.has(resource.id)) {
      preview.changes.resources.updated++;
    } else {
      preview.changes.resources.new++;
    }
  }
  preview.changes.resources.unchanged =
    currentData.groupResources.length - preview.changes.resources.updated;

  // Add warnings
  if (backupData.data.users.some((u) => u.vault)) {
    preview.warnings.push(
      "Backup contains vault data. Vault will be restored, potentially overwriting current vault.",
    );
  }

  return preview;
}

/**
 * Restore a backup
 *
 * @param {string} tenantId - Tenant UUID
 * @param {string} backupId - Backup UUID
 * @param {object} options - Restore options
 * @param {string} options.mode - Restore mode (replace or merge)
 * @param {boolean} options.restoreVault - Restore vault data (default: false)
 * @param {string} options.triggeredBy - User ID who triggered the restore
 * @returns {Promise<{ restoreId: string, status: string }>} Restore job ID
 */
export async function restoreBackup(tenantId, backupId, options = {}) {
  const { mode = RESTORE_MODE.MERGE, restoreVault = false, triggeredBy = null } = options;

  // Validate backup first
  const validation = await validateBackup(tenantId, backupId);
  if (!validation.valid) {
    throw new Error(`Invalid backup: ${validation.error}`);
  }

  // Generate restore ID
  const restoreId = crypto.randomUUID();
  const timestamp = new Date().toISOString();

  // Initialize job tracking
  restoreJobs.set(restoreId, {
    id: restoreId,
    tenantId,
    backupId,
    status: BACKUP_STATUS.PENDING,
    progress: 0,
    mode,
    restoreVault,
    triggeredBy,
    createdAt: timestamp,
    startedAt: null,
    completedAt: null,
    error: null,
    results: null,
  });

  // Start restore in background
  runRestoreJob(restoreId, tenantId, backupId, { mode, restoreVault }).catch((err) => {
    console.error(`[tenant-backup] Restore ${restoreId} failed:`, err);
    const job = restoreJobs.get(restoreId);
    if (job) {
      job.status = BACKUP_STATUS.FAILED;
      job.error = err.message;
      job.completedAt = new Date().toISOString();
    }
  });

  return {
    restoreId,
    status: BACKUP_STATUS.PENDING,
    message: "Restore started in background",
  };
}

/**
 * Run the actual restore job
 */
async function runRestoreJob(restoreId, tenantId, backupId, options) {
  const job = restoreJobs.get(restoreId);
  if (!job) {
    return;
  }

  job.status = BACKUP_STATUS.IN_PROGRESS;
  job.startedAt = new Date().toISOString();
  job.progress = 5;

  const results = {
    users: { restored: 0, skipped: 0, errors: 0 },
    groups: { restored: 0, skipped: 0, errors: 0 },
    memberships: { restored: 0, skipped: 0, errors: 0 },
    resources: { restored: 0, skipped: 0, errors: 0 },
    shares: { restored: 0, skipped: 0, errors: 0 },
  };

  try {
    // Load and decrypt backup
    const backupPath = path.join(BACKUP_DIR, tenantId, `backup_${tenantId}_${backupId}.json`);
    const backupContent = await fs.readFile(backupPath, "utf-8");
    const backupFile = JSON.parse(backupContent);

    const key = await getBackupKey(tenantId);
    const nonce = Buffer.from(backupFile.nonce, "base64");
    const tag = Buffer.from(backupFile.tag, "base64");
    const ciphertext = Buffer.from(backupFile.ciphertext, "base64");

    const decrypted = decryptBackup(nonce, tag, ciphertext, key);
    const decompressed = await gunzip(decrypted);
    const backupData = JSON.parse(decompressed.toString("utf-8"));
    job.progress = 20;

    // If replace mode, clear existing data (except audit logs)
    if (options.mode === RESTORE_MODE.REPLACE) {
      await query(
        "DELETE FROM shares WHERE resource_id IN (SELECT id FROM group_resources WHERE tenant_id = $1)",
        [tenantId],
      );
      await query("DELETE FROM group_resources WHERE tenant_id = $1", [tenantId]);
      await query("DELETE FROM group_memberships WHERE tenant_id = $1", [tenantId]);
      await query(
        "DELETE FROM group_vaults WHERE group_id IN (SELECT id FROM groups WHERE tenant_id = $1)",
        [tenantId],
      );
      await query(
        "DELETE FROM group_threshold WHERE group_id IN (SELECT id FROM groups WHERE tenant_id = $1)",
        [tenantId],
      );
      await query("DELETE FROM groups WHERE tenant_id = $1", [tenantId]);
      // Don't delete users - just update them
    }
    job.progress = 30;

    // Restore groups first (needed for foreign keys)
    for (const group of backupData.data.groups || []) {
      try {
        await query(
          `INSERT INTO groups (id, name, slug, description, tenant_id, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           ON CONFLICT (id) DO UPDATE SET
             name = EXCLUDED.name,
             description = EXCLUDED.description,
             updated_at = NOW()`,
          [
            group.id,
            group.name,
            group.slug,
            group.description,
            tenantId,
            group.created_at,
            group.updated_at,
          ],
        );
        results.groups.restored++;
      } catch (err) {
        console.warn(`[tenant-backup] Failed to restore group ${group.id}:`, err.message);
        results.groups.errors++;
      }
    }
    job.progress = 45;

    // Restore users
    for (const user of backupData.data.users || []) {
      try {
        const vaultValue = options.restoreVault && user.vault ? JSON.stringify(user.vault) : null;

        await query(
          `INSERT INTO users (id, name, email, status, tenant_id, biometrics_enabled, settings, mfa_required, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
           ON CONFLICT (id) DO UPDATE SET
             name = EXCLUDED.name,
             status = EXCLUDED.status,
             biometrics_enabled = EXCLUDED.biometrics_enabled,
             settings = EXCLUDED.settings,
             mfa_required = EXCLUDED.mfa_required,
             updated_at = NOW()`,
          [
            user.id,
            user.name,
            user.email,
            user.status || "active",
            tenantId,
            user.biometrics_enabled || false,
            JSON.stringify(user.settings || {}),
            user.mfa_required || false,
            user.created_at,
            user.updated_at,
          ],
        );

        // Restore vault separately if requested
        if (vaultValue) {
          await query("UPDATE users SET vault = $1, vault_created_at = $2 WHERE id = $3", [
            vaultValue,
            user.vault_created_at,
            user.id,
          ]);
        }

        results.users.restored++;
      } catch (err) {
        console.warn(`[tenant-backup] Failed to restore user ${user.id}:`, err.message);
        results.users.errors++;
      }
    }
    job.progress = 60;

    // Restore group memberships
    for (const membership of backupData.data.groupMemberships || []) {
      try {
        await query(
          `INSERT INTO group_memberships (user_id, group_id, role, tenant_id, created_at)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (user_id, group_id) DO UPDATE SET
             role = EXCLUDED.role`,
          [
            membership.user_id,
            membership.group_id,
            membership.role,
            tenantId,
            membership.created_at,
          ],
        );
        results.memberships.restored++;
      } catch (err) {
        console.warn(`[tenant-backup] Failed to restore membership:`, err.message);
        results.memberships.errors++;
      }
    }
    job.progress = 75;

    // Restore group resources
    for (const resource of backupData.data.groupResources || []) {
      try {
        await query(
          `INSERT INTO group_resources (id, group_id, name, description, resource_type, endpoint,
             auth_config_encrypted, metadata, status, tenant_id, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
           ON CONFLICT (id) DO UPDATE SET
             name = EXCLUDED.name,
             description = EXCLUDED.description,
             resource_type = EXCLUDED.resource_type,
             endpoint = EXCLUDED.endpoint,
             auth_config_encrypted = EXCLUDED.auth_config_encrypted,
             metadata = EXCLUDED.metadata,
             status = EXCLUDED.status,
             updated_at = NOW()`,
          [
            resource.id,
            resource.group_id,
            resource.name,
            resource.description,
            resource.resource_type,
            resource.endpoint,
            resource.auth_config_encrypted,
            JSON.stringify(resource.metadata || {}),
            resource.status || "active",
            tenantId,
            resource.created_at,
            resource.updated_at,
          ],
        );
        results.resources.restored++;
      } catch (err) {
        console.warn(`[tenant-backup] Failed to restore resource ${resource.id}:`, err.message);
        results.resources.errors++;
      }
    }
    job.progress = 90;

    // Restore shares (if in replace mode, they were deleted; in merge mode, upsert)
    for (const share of backupData.data.shares || []) {
      try {
        await query(
          `INSERT INTO shares (id, resource_id, user_id, permission_level, status, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           ON CONFLICT (id) DO UPDATE SET
             permission_level = EXCLUDED.permission_level,
             status = EXCLUDED.status,
             updated_at = NOW()`,
          [
            share.id,
            share.resource_id,
            share.user_id,
            share.permission_level || "read",
            share.status || "active",
            share.created_at,
            share.updated_at,
          ],
        );
        results.shares.restored++;
      } catch (err) {
        console.warn(`[tenant-backup] Failed to restore share ${share.id}:`, err.message);
        results.shares.errors++;
      }
    }

    // Mark complete
    job.status = BACKUP_STATUS.COMPLETED;
    job.progress = 100;
    job.completedAt = new Date().toISOString();
    job.results = results;

    console.log(`[tenant-backup] Restore ${restoreId} completed for tenant ${tenantId}`);
  } catch (err) {
    job.status = BACKUP_STATUS.FAILED;
    job.error = err.message;
    job.completedAt = new Date().toISOString();
    job.results = results;
    throw err;
  }
}

/**
 * Get restore job status
 *
 * @param {string} restoreId - Restore job UUID
 * @returns {object|null} Restore job status or null if not found
 */
export function getRestoreStatus(restoreId) {
  return restoreJobs.get(restoreId) || null;
}

// ============================================================
// EXPORT/IMPORT FOR MIGRATION
// ============================================================

/**
 * Export tenant data for migration to another instance
 * Similar to backup but returns decrypted data
 *
 * @param {string} tenantId - Tenant UUID
 * @param {object} options - Export options
 * @returns {Promise<Buffer>} Compressed export data
 */
export async function exportTenant(tenantId, options = {}) {
  const { includeVault = false, includeSensitive = false } = options;

  const data = await collectTenantData(tenantId, { includeVault, includeSensitive });

  const exportPackage = {
    version: BACKUP_VERSION,
    format: "ocmt-tenant-export",
    exportedAt: new Date().toISOString(),
    tenantId,
    data,
  };

  // Compress but don't encrypt (for cross-instance migration)
  const jsonData = JSON.stringify(exportPackage);
  const compressed = await gzip(Buffer.from(jsonData, "utf-8"));

  return compressed;
}

/**
 * Import tenant data from another instance
 *
 * @param {Buffer} data - Compressed export data
 * @param {string} targetTenantId - Target tenant UUID
 * @param {object} options - Import options
 * @param {string} options.mode - Import mode (replace or merge)
 * @returns {Promise<object>} Import results
 */
export async function importTenant(data, targetTenantId, options = {}) {
  const { mode = RESTORE_MODE.MERGE } = options;

  // Decompress
  const decompressed = await gunzip(data);
  const importData = JSON.parse(decompressed.toString("utf-8"));

  // Validate format
  if (importData.format !== "ocmt-tenant-export") {
    throw new Error("Invalid export format");
  }

  // Create a temporary backup-like structure and use restore logic
  const backupId = crypto.randomUUID();
  const key = await getBackupKey(targetTenantId);

  // Re-serialize as backup format
  const backupPackage = {
    version: BACKUP_VERSION,
    format: "ocmt-tenant-backup",
    tenantId: targetTenantId, // Use target tenant ID
    createdAt: new Date().toISOString(),
    description: `Imported from ${importData.tenantId} on ${importData.exportedAt}`,
    data: {
      ...importData.data,
      tenant: {
        ...importData.data.tenant,
        id: targetTenantId, // Override tenant ID
      },
    },
  };

  const jsonData = JSON.stringify(backupPackage);
  const compressed = await gzip(Buffer.from(jsonData, "utf-8"));
  const { nonce, tag, ciphertext } = encryptBackup(compressed, key);

  const backupFile = {
    format: "ocmt-backup-encrypted",
    version: 1,
    nonce: nonce.toString("base64"),
    tag: tag.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };

  // Save temporary backup
  const filename = `backup_${targetTenantId}_${backupId}.json`;
  const filepath = path.join(BACKUP_DIR, targetTenantId);

  if (!existsSync(filepath)) {
    mkdirSync(filepath, { recursive: true, mode: 0o700 });
  }

  await fs.writeFile(path.join(filepath, filename), JSON.stringify(backupFile), {
    mode: 0o600,
  });

  // Save metadata
  const metadata = {
    id: backupId,
    tenantId: targetTenantId,
    filename,
    createdAt: new Date().toISOString(),
    description: backupPackage.description,
    isImport: true,
    sourcetenantId: importData.tenantId,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(), // 7 days for imports
  };

  await fs.writeFile(
    path.join(filepath, `metadata_${backupId}.json`),
    JSON.stringify(metadata, null, 2),
    { mode: 0o600 },
  );

  // Now restore from the imported backup
  return restoreBackup(targetTenantId, backupId, { mode, restoreVault: false });
}

// ============================================================
// SCHEDULED BACKUPS
// ============================================================

/**
 * Start scheduled automatic backups
 *
 * @param {number} intervalMs - Backup interval in milliseconds (default: 24 hours)
 * @param {object} options - Backup options
 */
export function startScheduledBackups(intervalMs = 24 * 60 * 60 * 1000, options = {}) {
  if (scheduledBackupInterval) {
    console.log("[tenant-backup] Scheduled backups already running");
    return;
  }

  console.log(`[tenant-backup] Starting scheduled backups (interval: ${intervalMs}ms)`);

  async function runScheduledBackups() {
    try {
      const allTenants = await tenants.list({ status: "active", limit: 1000 });

      for (const tenant of allTenants) {
        try {
          // Check if tenant has backup enabled in settings
          if (tenant.settings?.backups_enabled === false) {
            continue;
          }

          console.log(`[tenant-backup] Running scheduled backup for tenant ${tenant.id}`);
          await createBackup(tenant.id, {
            description: "Scheduled automatic backup",
            ...options,
          });
        } catch (err) {
          console.error(
            `[tenant-backup] Scheduled backup failed for tenant ${tenant.id}:`,
            err.message,
          );
        }
      }
    } catch (err) {
      console.error("[tenant-backup] Scheduled backup run failed:", err.message);
    }
  }

  // Run immediately, then on interval
  runScheduledBackups();
  scheduledBackupInterval = setInterval(runScheduledBackups, intervalMs);
  scheduledBackupInterval.unref(); // Don't prevent process exit
}

/**
 * Stop scheduled backups
 */
export function stopScheduledBackups() {
  if (scheduledBackupInterval) {
    clearInterval(scheduledBackupInterval);
    scheduledBackupInterval = null;
    console.log("[tenant-backup] Scheduled backups stopped");
  }
}

// ============================================================
// CLEANUP
// ============================================================

/**
 * Clean up expired backups based on retention policy
 *
 * @returns {Promise<{ deleted: number, errors: number }>} Cleanup results
 */
export async function cleanupExpiredBackups() {
  let deleted = 0;
  let errors = 0;

  try {
    const entries = await fs.readdir(BACKUP_DIR, { withFileTypes: true });
    const tenantDirs = entries.filter((e) => e.isDirectory());

    for (const dir of tenantDirs) {
      const tenantPath = path.join(BACKUP_DIR, dir.name);
      const files = await fs.readdir(tenantPath);
      const metadataFiles = files.filter((f) => f.startsWith("metadata_"));

      for (const metaFile of metadataFiles) {
        try {
          const content = await fs.readFile(path.join(tenantPath, metaFile), "utf-8");
          const metadata = JSON.parse(content);

          if (new Date(metadata.expiresAt) < new Date()) {
            // Delete backup and metadata
            const backupId = metaFile.replace("metadata_", "").replace(".json", "");
            await deleteBackup(dir.name, backupId);
            deleted++;
          }
        } catch (err) {
          console.warn(`[tenant-backup] Failed to process ${metaFile}:`, err.message);
          errors++;
        }
      }
    }
  } catch (err) {
    console.error("[tenant-backup] Cleanup failed:", err.message);
    errors++;
  }

  if (deleted > 0) {
    console.log(`[tenant-backup] Cleaned up ${deleted} expired backups`);
  }

  return { deleted, errors };
}

// Run cleanup daily
const cleanupInterval = setInterval(cleanupExpiredBackups, 24 * 60 * 60 * 1000);
cleanupInterval.unref();

// ============================================================
// DOWNLOAD
// ============================================================

/**
 * Get backup file for download
 *
 * @param {string} tenantId - Tenant UUID
 * @param {string} backupId - Backup UUID
 * @returns {Promise<{ stream: ReadStream, filename: string, size: number }|null>}
 */
export async function getBackupForDownload(tenantId, backupId) {
  const metadata = await getBackup(tenantId, backupId);
  if (!metadata || metadata.status === BACKUP_STATUS.EXPIRED) {
    return null;
  }

  const backupPath = path.join(BACKUP_DIR, tenantId, `backup_${tenantId}_${backupId}.json`);

  try {
    const stat = await fs.stat(backupPath);
    const stream = createReadStream(backupPath);

    return {
      stream,
      filename: `backup_${tenantId}_${backupId}.json`,
      size: stat.size,
    };
  } catch (err) {
    if (err.code === "ENOENT") {
      return null;
    }
    throw err;
  }
}

// ============================================================
// EXPORTS
// ============================================================

export default {
  // Constants
  BACKUP_STATUS,
  RESTORE_MODE,

  // Backup operations
  createBackup,
  getBackupStatus,
  listBackups,
  getBackup,
  deleteBackup,
  validateBackup,
  getBackupForDownload,

  // Restore operations
  restoreBackup,
  previewRestore,
  getRestoreStatus,

  // Export/Import
  exportTenant,
  importTenant,

  // Scheduling
  startScheduledBackups,
  stopScheduledBackups,

  // Cleanup
  cleanupExpiredBackups,
};
