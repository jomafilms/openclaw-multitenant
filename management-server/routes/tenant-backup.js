/**
 * Tenant Backup Routes
 * Wave 5.5 - Per-tenant backup/restore API endpoints
 *
 * Endpoints:
 * - POST /api/tenants/:id/backup - Create backup
 * - GET /api/tenants/:id/backups - List backups
 * - GET /api/tenants/:id/backups/:backupId - Get backup details
 * - GET /api/tenants/:id/backups/:backupId/status - Get backup job status
 * - POST /api/tenants/:id/backups/:backupId/restore - Restore from backup
 * - GET /api/tenants/:id/backups/:backupId/preview - Preview restore
 * - DELETE /api/tenants/:id/backups/:backupId - Delete backup
 * - GET /api/tenants/:id/backups/:backupId/download - Download backup file
 * - POST /api/tenants/:id/export - Export tenant for migration
 * - POST /api/tenants/:id/import - Import tenant data
 */

import { Router } from "express";
import { z } from "zod";
import { tenants, tenantMemberships, audit } from "../db/index.js";
import {
  createBackup,
  getBackupStatus,
  listBackups,
  getBackup,
  deleteBackup,
  validateBackup,
  getBackupForDownload,
  restoreBackup,
  previewRestore,
  getRestoreStatus,
  exportTenant,
  importTenant,
  BACKUP_STATUS,
  RESTORE_MODE,
} from "../lib/tenant-backup.js";
import { requireUser } from "../middleware/auth.js";

const router = Router();

// ============================================================
// VALIDATION SCHEMAS
// ============================================================

const uuidSchema = z.string().uuid();

const createBackupSchema = z.object({
  includeVault: z.boolean().optional().default(true),
  description: z.string().max(500).optional(),
});

const listBackupsSchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).optional().default(50),
  offset: z.coerce.number().int().min(0).optional().default(0),
});

const restoreBackupSchema = z.object({
  mode: z.enum(["replace", "merge"]).optional().default("merge"),
  restoreVault: z.boolean().optional().default(false),
});

// ============================================================
// AUTHORIZATION HELPERS
// ============================================================

/**
 * Check if user can manage tenant backups
 * Must be tenant owner or platform admin
 */
async function canManageBackups(user, tenantId) {
  // Platform admins can manage any tenant's backups
  if (user.is_platform_admin) {
    return true;
  }

  // Check if user is tenant owner
  const tenant = await tenants.findById(tenantId);
  if (!tenant) {
    return false;
  }

  return tenant.owner_id === user.id;
}

/**
 * Middleware to require backup management permission
 */
async function requireBackupPermission(req, res, next) {
  const tenantId = req.params.id;

  const parseResult = uuidSchema.safeParse(tenantId);
  if (!parseResult.success) {
    return res.status(400).json({ error: "Invalid tenant ID" });
  }

  if (!(await canManageBackups(req.user, tenantId))) {
    return res.status(403).json({
      error: "Backup management requires tenant owner or platform admin",
      code: "BACKUP_PERMISSION_DENIED",
    });
  }

  // Store validated tenant ID for handlers
  req.tenantId = tenantId;
  next();
}

// ============================================================
// BACKUP ROUTES
// ============================================================

/**
 * POST /api/tenants/:id/backup
 * Create a new backup for the tenant
 */
router.post("/tenants/:id/backup", requireUser, requireBackupPermission, async (req, res) => {
  try {
    const parseResult = createBackupSchema.safeParse(req.body || {});
    if (!parseResult.success) {
      return res.status(400).json({
        error: "Invalid request body",
        details: parseResult.error.issues,
      });
    }

    const { includeVault, description } = parseResult.data;

    const result = await createBackup(req.tenantId, {
      includeVault,
      description,
      triggeredBy: req.user.id,
    });

    await audit.log(
      req.user.id,
      "tenant.backup.created",
      {
        tenantId: req.tenantId,
        backupId: result.backupId,
        includeVault,
      },
      req.ip,
    );

    res.status(202).json({
      ...result,
      message: "Backup started. Use GET /status to check progress.",
    });
  } catch (err) {
    console.error("[tenant-backup] Create backup error:", err);
    res.status(500).json({ error: "Failed to create backup" });
  }
});

/**
 * GET /api/tenants/:id/backups
 * List all backups for the tenant
 */
router.get("/tenants/:id/backups", requireUser, requireBackupPermission, async (req, res) => {
  try {
    const parseResult = listBackupsSchema.safeParse(req.query);
    if (!parseResult.success) {
      return res.status(400).json({
        error: "Invalid query parameters",
        details: parseResult.error.issues,
      });
    }

    const { limit, offset } = parseResult.data;
    const result = await listBackups(req.tenantId, { limit, offset });

    res.json({
      ...result,
      limit,
      offset,
    });
  } catch (err) {
    console.error("[tenant-backup] List backups error:", err);
    res.status(500).json({ error: "Failed to list backups" });
  }
});

/**
 * GET /api/tenants/:id/backups/:backupId
 * Get backup details
 */
router.get(
  "/tenants/:id/backups/:backupId",
  requireUser,
  requireBackupPermission,
  async (req, res) => {
    try {
      const backupIdParse = uuidSchema.safeParse(req.params.backupId);
      if (!backupIdParse.success) {
        return res.status(400).json({ error: "Invalid backup ID" });
      }

      const backup = await getBackup(req.tenantId, req.params.backupId);
      if (!backup) {
        return res.status(404).json({ error: "Backup not found" });
      }

      res.json(backup);
    } catch (err) {
      console.error("[tenant-backup] Get backup error:", err);
      res.status(500).json({ error: "Failed to get backup details" });
    }
  },
);

/**
 * GET /api/tenants/:id/backups/:backupId/status
 * Get backup job status (for polling)
 */
router.get(
  "/tenants/:id/backups/:backupId/status",
  requireUser,
  requireBackupPermission,
  async (req, res) => {
    try {
      const backupIdParse = uuidSchema.safeParse(req.params.backupId);
      if (!backupIdParse.success) {
        return res.status(400).json({ error: "Invalid backup ID" });
      }

      // Check in-progress jobs first
      const job = getBackupStatus(req.params.backupId);
      if (job && job.tenantId === req.tenantId) {
        return res.json({
          id: job.id,
          status: job.status,
          progress: job.progress,
          error: job.error,
          createdAt: job.createdAt,
          startedAt: job.startedAt,
          completedAt: job.completedAt,
        });
      }

      // Check stored backup
      const backup = await getBackup(req.tenantId, req.params.backupId);
      if (!backup) {
        return res.status(404).json({ error: "Backup not found" });
      }

      res.json({
        id: backup.id,
        status: backup.status,
        progress: 100,
        createdAt: backup.createdAt,
      });
    } catch (err) {
      console.error("[tenant-backup] Get backup status error:", err);
      res.status(500).json({ error: "Failed to get backup status" });
    }
  },
);

/**
 * GET /api/tenants/:id/backups/:backupId/validate
 * Validate backup integrity
 */
router.get(
  "/tenants/:id/backups/:backupId/validate",
  requireUser,
  requireBackupPermission,
  async (req, res) => {
    try {
      const backupIdParse = uuidSchema.safeParse(req.params.backupId);
      if (!backupIdParse.success) {
        return res.status(400).json({ error: "Invalid backup ID" });
      }

      const result = await validateBackup(req.tenantId, req.params.backupId);
      res.json(result);
    } catch (err) {
      console.error("[tenant-backup] Validate backup error:", err);
      res.status(500).json({ error: "Failed to validate backup" });
    }
  },
);

/**
 * GET /api/tenants/:id/backups/:backupId/preview
 * Preview what would be restored
 */
router.get(
  "/tenants/:id/backups/:backupId/preview",
  requireUser,
  requireBackupPermission,
  async (req, res) => {
    try {
      const backupIdParse = uuidSchema.safeParse(req.params.backupId);
      if (!backupIdParse.success) {
        return res.status(400).json({ error: "Invalid backup ID" });
      }

      const preview = await previewRestore(req.tenantId, req.params.backupId);
      res.json(preview);
    } catch (err) {
      console.error("[tenant-backup] Preview restore error:", err);
      res.status(500).json({ error: "Failed to preview restore" });
    }
  },
);

/**
 * POST /api/tenants/:id/backups/:backupId/restore
 * Restore from backup
 */
router.post(
  "/tenants/:id/backups/:backupId/restore",
  requireUser,
  requireBackupPermission,
  async (req, res) => {
    try {
      const backupIdParse = uuidSchema.safeParse(req.params.backupId);
      if (!backupIdParse.success) {
        return res.status(400).json({ error: "Invalid backup ID" });
      }

      const parseResult = restoreBackupSchema.safeParse(req.body || {});
      if (!parseResult.success) {
        return res.status(400).json({
          error: "Invalid request body",
          details: parseResult.error.issues,
        });
      }

      const { mode, restoreVault } = parseResult.data;

      // Validate backup first
      const validation = await validateBackup(req.tenantId, req.params.backupId);
      if (!validation.valid) {
        return res.status(400).json({
          error: "Invalid backup",
          details: validation.error,
        });
      }

      const result = await restoreBackup(req.tenantId, req.params.backupId, {
        mode,
        restoreVault,
        triggeredBy: req.user.id,
      });

      await audit.log(
        req.user.id,
        "tenant.backup.restored",
        {
          tenantId: req.tenantId,
          backupId: req.params.backupId,
          restoreId: result.restoreId,
          mode,
          restoreVault,
        },
        req.ip,
      );

      res.status(202).json({
        ...result,
        message: "Restore started. Use GET /restore/:restoreId/status to check progress.",
      });
    } catch (err) {
      console.error("[tenant-backup] Restore backup error:", err);
      res.status(500).json({ error: err.message || "Failed to restore backup" });
    }
  },
);

/**
 * GET /api/tenants/:id/restore/:restoreId/status
 * Get restore job status
 */
router.get(
  "/tenants/:id/restore/:restoreId/status",
  requireUser,
  requireBackupPermission,
  async (req, res) => {
    try {
      const restoreIdParse = uuidSchema.safeParse(req.params.restoreId);
      if (!restoreIdParse.success) {
        return res.status(400).json({ error: "Invalid restore ID" });
      }

      const job = getRestoreStatus(req.params.restoreId);
      if (!job || job.tenantId !== req.tenantId) {
        return res.status(404).json({ error: "Restore job not found" });
      }

      res.json({
        id: job.id,
        backupId: job.backupId,
        status: job.status,
        progress: job.progress,
        mode: job.mode,
        error: job.error,
        results: job.results,
        createdAt: job.createdAt,
        startedAt: job.startedAt,
        completedAt: job.completedAt,
      });
    } catch (err) {
      console.error("[tenant-backup] Get restore status error:", err);
      res.status(500).json({ error: "Failed to get restore status" });
    }
  },
);

/**
 * DELETE /api/tenants/:id/backups/:backupId
 * Delete a backup
 */
router.delete(
  "/tenants/:id/backups/:backupId",
  requireUser,
  requireBackupPermission,
  async (req, res) => {
    try {
      const backupIdParse = uuidSchema.safeParse(req.params.backupId);
      if (!backupIdParse.success) {
        return res.status(400).json({ error: "Invalid backup ID" });
      }

      const deleted = await deleteBackup(req.tenantId, req.params.backupId);

      if (!deleted) {
        return res.status(404).json({ error: "Backup not found" });
      }

      await audit.log(
        req.user.id,
        "tenant.backup.deleted",
        {
          tenantId: req.tenantId,
          backupId: req.params.backupId,
        },
        req.ip,
      );

      res.json({ success: true, message: "Backup deleted" });
    } catch (err) {
      console.error("[tenant-backup] Delete backup error:", err);
      res.status(500).json({ error: "Failed to delete backup" });
    }
  },
);

/**
 * GET /api/tenants/:id/backups/:backupId/download
 * Download backup file
 */
router.get(
  "/tenants/:id/backups/:backupId/download",
  requireUser,
  requireBackupPermission,
  async (req, res) => {
    try {
      const backupIdParse = uuidSchema.safeParse(req.params.backupId);
      if (!backupIdParse.success) {
        return res.status(400).json({ error: "Invalid backup ID" });
      }

      const download = await getBackupForDownload(req.tenantId, req.params.backupId);

      if (!download) {
        return res.status(404).json({ error: "Backup not found or expired" });
      }

      await audit.log(
        req.user.id,
        "tenant.backup.downloaded",
        {
          tenantId: req.tenantId,
          backupId: req.params.backupId,
        },
        req.ip,
      );

      res.setHeader("Content-Type", "application/json");
      res.setHeader("Content-Disposition", `attachment; filename="${download.filename}"`);
      res.setHeader("Content-Length", download.size);

      download.stream.pipe(res);
    } catch (err) {
      console.error("[tenant-backup] Download backup error:", err);
      res.status(500).json({ error: "Failed to download backup" });
    }
  },
);

// ============================================================
// EXPORT/IMPORT ROUTES
// ============================================================

/**
 * POST /api/tenants/:id/export
 * Export tenant data for migration
 */
router.post("/tenants/:id/export", requireUser, requireBackupPermission, async (req, res) => {
  try {
    const { includeVault = false } = req.body || {};

    const exportData = await exportTenant(req.tenantId, { includeVault });

    await audit.log(
      req.user.id,
      "tenant.exported",
      {
        tenantId: req.tenantId,
        includeVault,
      },
      req.ip,
    );

    res.setHeader("Content-Type", "application/gzip");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="tenant_export_${req.tenantId}_${Date.now()}.json.gz"`,
    );
    res.setHeader("Content-Length", exportData.length);

    res.send(exportData);
  } catch (err) {
    console.error("[tenant-backup] Export error:", err);
    res.status(500).json({ error: "Failed to export tenant" });
  }
});

/**
 * POST /api/tenants/:id/import
 * Import tenant data from export
 */
router.post("/tenants/:id/import", requireUser, requireBackupPermission, async (req, res) => {
  try {
    // Check content type
    const contentType = req.headers["content-type"] || "";
    if (
      !contentType.includes("application/gzip") &&
      !contentType.includes("application/octet-stream")
    ) {
      return res.status(400).json({
        error: "Content-Type must be application/gzip or application/octet-stream",
      });
    }

    const { mode = "merge" } = req.query;

    if (!["replace", "merge"].includes(mode)) {
      return res.status(400).json({
        error: "Invalid mode. Must be 'replace' or 'merge'",
      });
    }

    // Collect request body as buffer
    const chunks = [];
    for await (const chunk of req) {
      chunks.push(chunk);
    }
    const importData = Buffer.concat(chunks);

    if (importData.length === 0) {
      return res.status(400).json({ error: "No import data provided" });
    }

    const result = await importTenant(importData, req.tenantId, { mode });

    await audit.log(
      req.user.id,
      "tenant.imported",
      {
        tenantId: req.tenantId,
        mode,
        restoreId: result.restoreId,
      },
      req.ip,
    );

    res.status(202).json({
      ...result,
      message: "Import started. Use restore status endpoint to check progress.",
    });
  } catch (err) {
    console.error("[tenant-backup] Import error:", err);
    res.status(500).json({ error: err.message || "Failed to import tenant" });
  }
});

export default router;
