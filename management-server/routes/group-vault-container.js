import axios from "axios";
import crypto from "crypto";
// Group vault container management routes
// Handles provisioning, container lifecycle, and secrets API proxying
import { Router } from "express";
import { groupVaults, groupVaultAudit, groupVaultTokens, audit, groups } from "../db/index.js";
import { AGENT_SERVER_URL, AGENT_SERVER_TOKEN } from "../lib/context.js";
import { requireUser } from "../middleware/auth.js";
import { requireGroupMember, requireGroupAdmin } from "../middleware/group-auth.js";
import { detectTenant } from "../middleware/tenant-context.js";

const router = Router();

// Container auth token for group vault containers
const GROUP_VAULT_AUTH_TOKEN =
  process.env.GROUP_VAULT_AUTH_TOKEN || crypto.randomBytes(32).toString("hex");

/**
 * GET /api/groups/:groupId/vault-container/status
 * Get group vault container status
 */
router.get(
  "/:groupId/vault-container/status",
  requireUser,
  detectTenant,
  requireGroupMember,
  async (req, res) => {
    try {
      const vault = await groupVaults.findByGroup(req.params.groupId);

      if (!vault) {
        return res.json({
          initialized: false,
          status: "not_created",
        });
      }

      // Check container health if active
      let containerHealth = null;
      if (vault.status === "active" && vault.container_port) {
        try {
          const healthRes = await axios.get(`http://localhost:${vault.container_port}/health`, {
            timeout: 3000,
          });
          containerHealth = healthRes.data;
        } catch {
          containerHealth = { status: "unreachable" };
        }
      }

      res.json({
        initialized: !!vault.vault_encrypted || containerHealth?.vaultInitialized,
        status: vault.status,
        containerId: vault.container_id,
        containerPort: vault.container_port,
        containerHealth,
        createdAt: vault.created_at,
        updatedAt: vault.updated_at,
      });
    } catch (err) {
      console.error("Get vault container status error:", err);
      res.status(500).json({ error: "Failed to get vault status" });
    }
  },
);

/**
 * POST /api/groups/:groupId/vault-container/provision
 * Provision group vault container (admin only)
 */
router.post(
  "/:groupId/vault-container/provision",
  requireUser,
  detectTenant,
  requireGroupAdmin,
  async (req, res) => {
    try {
      const { groupId } = req.params;

      // Check if vault already exists
      let vault = await groupVaults.findByGroup(groupId);
      if (vault && vault.status === "active") {
        return res.status(400).json({ error: "Vault container already provisioned" });
      }

      // Create vault record if not exists
      if (!vault) {
        vault = await groupVaults.create(groupId);
      }

      // Get group for naming
      const org = await groups.findById(groupId);
      if (!org) {
        return res.status(404).json({ error: "Group not found" });
      }

      // Provision container via agent server
      try {
        const response = await axios.post(
          `${AGENT_SERVER_URL}/api/group-vaults/provision`,
          {
            groupId,
            orgSlug: org.slug,
            authToken: GROUP_VAULT_AUTH_TOKEN,
          },
          {
            headers: { "x-auth-token": AGENT_SERVER_TOKEN },
            timeout: 60000,
          },
        );

        // Update vault with container info
        await groupVaults.updateContainer(groupId, {
          containerId: response.data.containerId,
          containerPort: response.data.port,
        });

        await audit.log(
          req.user.id,
          "org.vault.container_provisioned",
          {
            groupId,
            containerId: response.data.containerId,
            port: response.data.port,
          },
          req.ip,
        );

        await groupVaultAudit.log({
          groupId,
          userId: req.user.id,
          action: "container.provisioned",
          ipAddress: req.ip,
          success: true,
        });

        res.json({
          success: true,
          containerId: response.data.containerId,
          port: response.data.port,
        });
      } catch (provisionErr) {
        console.error("Container provision error:", provisionErr.message);
        await groupVaults.updateStatus(groupId, "failed");

        await groupVaultAudit.log({
          groupId,
          userId: req.user.id,
          action: "container.provision_failed",
          ipAddress: req.ip,
          success: false,
          errorMessage: provisionErr.message,
        });

        res.status(503).json({ error: "Failed to provision vault container" });
      }
    } catch (err) {
      console.error("Provision vault container error:", err);
      res.status(500).json({ error: "Failed to provision vault container" });
    }
  },
);

/**
 * POST /api/groups/:groupId/vault-container/init
 * Initialize vault with password (admin only)
 */
router.post(
  "/:groupId/vault-container/init",
  requireUser,
  detectTenant,
  requireGroupAdmin,
  async (req, res) => {
    try {
      const { groupId } = req.params;
      const { password } = req.body;

      if (!password || password.length < 16) {
        return res.status(400).json({ error: "Password must be at least 16 characters" });
      }

      const vault = await groupVaults.findByGroup(groupId);
      if (!vault || vault.status !== "active") {
        return res.status(400).json({ error: "Vault container not provisioned or not active" });
      }

      // Call container to initialize vault
      try {
        await axios.post(
          `http://localhost:${vault.container_port}/init`,
          { password },
          {
            headers: { "x-auth-token": GROUP_VAULT_AUTH_TOKEN },
            timeout: 30000,
          },
        );

        await groupVaultAudit.log({
          groupId,
          userId: req.user.id,
          action: "vault.initialized",
          ipAddress: req.ip,
          success: true,
        });

        res.json({ success: true, message: "Vault initialized" });
      } catch (initErr) {
        console.error("Vault init error:", initErr.response?.data || initErr.message);

        await groupVaultAudit.log({
          groupId,
          userId: req.user.id,
          action: "vault.init_failed",
          ipAddress: req.ip,
          success: false,
          errorMessage: initErr.response?.data?.error || initErr.message,
        });

        const errorMsg = initErr.response?.data?.error || "Failed to initialize vault";
        res.status(initErr.response?.status || 503).json({ error: errorMsg });
      }
    } catch (err) {
      console.error("Init vault error:", err);
      res.status(500).json({ error: "Failed to initialize vault" });
    }
  },
);

/**
 * POST /api/groups/:groupId/vault-container/unlock
 * Unlock vault container (admin only)
 * Note: This bypasses threshold approval - use group-vault.js routes for threshold unlock
 */
router.post(
  "/:groupId/vault-container/unlock",
  requireUser,
  detectTenant,
  requireGroupAdmin,
  async (req, res) => {
    try {
      const { groupId } = req.params;
      const { password } = req.body;

      if (!password) {
        return res.status(400).json({ error: "Password required" });
      }

      const vault = await groupVaults.findByGroup(groupId);
      if (!vault || vault.status !== "active") {
        return res.status(400).json({ error: "Vault container not provisioned or not active" });
      }

      // Call container to unlock vault
      try {
        const response = await axios.post(
          `http://localhost:${vault.container_port}/unlock`,
          { password, userId: req.user.id },
          {
            headers: { "x-auth-token": GROUP_VAULT_AUTH_TOKEN },
            timeout: 30000,
          },
        );

        await groupVaultAudit.log({
          groupId,
          userId: req.user.id,
          action: "vault.unlocked",
          ipAddress: req.ip,
          success: true,
        });

        res.json({
          success: true,
          expiresIn: response.data.expiresIn,
          secretCount: response.data.secretCount,
        });
      } catch (unlockErr) {
        const status = unlockErr.response?.status;
        const message = unlockErr.response?.data?.error || unlockErr.message;

        await groupVaultAudit.log({
          groupId,
          userId: req.user.id,
          action: "vault.unlock_failed",
          ipAddress: req.ip,
          success: false,
          errorMessage: message,
        });

        if (status === 401) {
          return res.status(401).json({ error: "Invalid password" });
        }
        res.status(503).json({ error: "Failed to unlock vault" });
      }
    } catch (err) {
      console.error("Unlock vault container error:", err);
      res.status(500).json({ error: "Failed to unlock vault" });
    }
  },
);

/**
 * POST /api/groups/:groupId/vault-container/lock
 * Lock vault container (admin only)
 */
router.post(
  "/:groupId/vault-container/lock",
  requireUser,
  detectTenant,
  requireGroupAdmin,
  async (req, res) => {
    try {
      const { groupId } = req.params;

      const vault = await groupVaults.findByGroup(groupId);
      if (!vault || vault.status !== "active") {
        return res.status(400).json({ error: "Vault container not provisioned or not active" });
      }

      try {
        await axios.post(
          `http://localhost:${vault.container_port}/lock`,
          { userId: req.user.id },
          {
            headers: { "x-auth-token": GROUP_VAULT_AUTH_TOKEN },
            timeout: 5000,
          },
        );

        await groupVaultAudit.log({
          groupId,
          userId: req.user.id,
          action: "vault.locked",
          ipAddress: req.ip,
          success: true,
        });

        res.json({ success: true });
      } catch (lockErr) {
        console.error("Vault lock error:", lockErr.message);
        res.status(503).json({ error: "Failed to lock vault" });
      }
    } catch (err) {
      console.error("Lock vault container error:", err);
      res.status(500).json({ error: "Failed to lock vault" });
    }
  },
);

/**
 * POST /api/groups/:groupId/vault-container/tokens
 * Issue capability token (admin only)
 */
router.post(
  "/:groupId/vault-container/tokens",
  requireUser,
  detectTenant,
  requireGroupAdmin,
  async (req, res) => {
    try {
      const { groupId } = req.params;
      const { userId, allowedSecrets, permissions, ttlSeconds } = req.body;

      if (!userId) {
        return res.status(400).json({ error: "userId required" });
      }

      const vault = await groupVaults.findByGroup(groupId);
      if (!vault || vault.status !== "active") {
        return res.status(400).json({ error: "Vault container not provisioned or not active" });
      }

      // Request token from container
      try {
        const response = await axios.post(
          `http://localhost:${vault.container_port}/tokens`,
          { userId, allowedSecrets, permissions, ttlSeconds },
          {
            headers: { "x-auth-token": GROUP_VAULT_AUTH_TOKEN },
            timeout: 10000,
          },
        );

        // Store token hash in database for tracking
        const tokenHash = crypto.createHash("sha256").update(response.data.token).digest("hex");
        await groupVaultTokens.create({
          groupId,
          userId,
          tokenHash,
          allowedSecrets: allowedSecrets || ["*"],
          permissions: permissions || ["read"],
          issuedBy: req.user.id,
          expiresAt: new Date(Date.now() + (ttlSeconds || 3600) * 1000),
        });

        await groupVaultAudit.log({
          groupId,
          userId: req.user.id,
          action: "token.issued",
          ipAddress: req.ip,
          success: true,
          metadata: { targetUserId: userId, permissions, allowedSecrets },
        });

        res.json({
          success: true,
          token: response.data.token,
          expiresIn: response.data.expiresIn,
        });
      } catch (tokenErr) {
        console.error("Token issue error:", tokenErr.response?.data || tokenErr.message);

        if (tokenErr.response?.status === 423) {
          return res.status(423).json({ error: "Vault is locked. Unlock it first." });
        }

        res.status(503).json({ error: "Failed to issue token" });
      }
    } catch (err) {
      console.error("Issue token error:", err);
      res.status(500).json({ error: "Failed to issue token" });
    }
  },
);

/**
 * GET /api/groups/:groupId/vault-container/tokens
 * List active tokens (admin only)
 */
router.get(
  "/:groupId/vault-container/tokens",
  requireUser,
  detectTenant,
  requireGroupAdmin,
  async (req, res) => {
    try {
      const tokens = await groupVaultTokens.listByGroup(req.params.groupId);
      res.json({ tokens });
    } catch (err) {
      console.error("List tokens error:", err);
      res.status(500).json({ error: "Failed to list tokens" });
    }
  },
);

/**
 * DELETE /api/groups/:groupId/vault-container/tokens/:tokenId
 * Revoke token (admin only)
 */
router.delete(
  "/:groupId/vault-container/tokens/:tokenId",
  requireUser,
  detectTenant,
  requireGroupAdmin,
  async (req, res) => {
    try {
      const token = await groupVaultTokens.revoke(req.params.tokenId);
      if (!token) {
        return res.status(404).json({ error: "Token not found" });
      }

      // Also revoke in container (best effort)
      const vault = await groupVaults.findByGroup(req.params.groupId);
      if (vault && vault.status === "active") {
        try {
          await axios.delete(
            `http://localhost:${vault.container_port}/tokens/${token.token_hash}`,
            {
              headers: { "x-auth-token": GROUP_VAULT_AUTH_TOKEN },
              timeout: 5000,
            },
          );
        } catch {
          // Ignore container errors - token is revoked in DB
        }
      }

      await groupVaultAudit.log({
        groupId: req.params.groupId,
        userId: req.user.id,
        action: "token.revoked",
        ipAddress: req.ip,
        success: true,
        metadata: { revokedTokenId: req.params.tokenId },
      });

      res.json({ success: true });
    } catch (err) {
      console.error("Revoke token error:", err);
      res.status(500).json({ error: "Failed to revoke token" });
    }
  },
);

/**
 * DELETE /api/groups/:groupId/vault-container/tokens/user/:userId
 * Revoke all tokens for a user (admin only)
 */
router.delete(
  "/:groupId/vault-container/tokens/user/:userId",
  requireUser,
  detectTenant,
  requireGroupAdmin,
  async (req, res) => {
    try {
      const tokens = await groupVaultTokens.revokeAllForUser(req.params.groupId, req.params.userId);

      // Also revoke in container (best effort)
      const vault = await groupVaults.findByGroup(req.params.groupId);
      if (vault && vault.status === "active") {
        try {
          await axios.delete(
            `http://localhost:${vault.container_port}/tokens/user/${req.params.userId}`,
            {
              headers: { "x-auth-token": GROUP_VAULT_AUTH_TOKEN },
              timeout: 5000,
            },
          );
        } catch {
          // Ignore container errors
        }
      }

      await groupVaultAudit.log({
        groupId: req.params.groupId,
        userId: req.user.id,
        action: "tokens.revoked_all_for_user",
        ipAddress: req.ip,
        success: true,
        metadata: { targetUserId: req.params.userId, count: tokens.length },
      });

      res.json({ success: true, count: tokens.length });
    } catch (err) {
      console.error("Revoke user tokens error:", err);
      res.status(500).json({ error: "Failed to revoke tokens" });
    }
  },
);

/**
 * GET /api/groups/:groupId/vault-container/audit
 * Get container audit logs (admin only)
 */
router.get(
  "/:groupId/vault-container/audit",
  requireUser,
  detectTenant,
  requireGroupAdmin,
  async (req, res) => {
    try {
      const limit = parseInt(req.query.limit) || 100;
      const logs = await groupVaultAudit.getRecent(req.params.groupId, limit);
      res.json({ logs });
    } catch (err) {
      console.error("Get audit logs error:", err);
      res.status(500).json({ error: "Failed to get audit logs" });
    }
  },
);

/**
 * GET /api/groups/:groupId/vault-container/audit/secret/:key
 * Get audit logs for specific secret (admin only)
 */
router.get(
  "/:groupId/vault-container/audit/secret/:key",
  requireUser,
  detectTenant,
  requireGroupAdmin,
  async (req, res) => {
    try {
      const limit = parseInt(req.query.limit) || 50;
      const logs = await groupVaultAudit.getForSecret(req.params.groupId, req.params.key, limit);
      res.json({ logs });
    } catch (err) {
      console.error("Get secret audit logs error:", err);
      res.status(500).json({ error: "Failed to get audit logs" });
    }
  },
);

export default router;
