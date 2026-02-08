// Workspace file operations routes
import { Router } from "express";
import fs from "fs";
import path from "path";
import { containers } from "../lib/containers.js";
import { DATA_DIR, writeAuthProfiles, readAuthProfiles } from "../lib/setup.js";

const router = Router();

// Write a file to workspace (only .ocmt/ allowed)
router.post("/:userId/workspace/write", (req, res) => {
  const { userId } = req.params;
  const { filePath, content } = req.body;
  const info = containers.get(userId);

  if (!info) {
    return res.status(404).json({ error: "Container not found" });
  }

  if (!filePath || content === undefined) {
    return res.status(400).json({ error: "filePath and content required" });
  }

  // Security: only allow writing to .ocmt/ directory or config.json
  const normalizedPath = path.normalize(filePath);
  const allowedPaths = [".ocmt", "config.json"];
  const isAllowed = normalizedPath.startsWith(".ocmt/") || allowedPaths.includes(normalizedPath);
  if (!isAllowed) {
    return res.status(403).json({ error: "Can only write to .ocmt/ directory or config.json" });
  }

  if (normalizedPath.includes("..")) {
    return res.status(403).json({ error: "Path traversal not allowed" });
  }

  try {
    const workspaceDir = path.join(DATA_DIR, userId, "workspace");
    const fullPath = path.join(workspaceDir, normalizedPath);

    // Ensure parent directory exists
    const parentDir = path.dirname(fullPath);
    fs.mkdirSync(parentDir, { recursive: true });
    fs.chownSync(parentDir, 1000, 1000);

    // Write file
    fs.writeFileSync(fullPath, content, "utf-8");
    fs.chownSync(fullPath, 1000, 1000);

    console.log(`[workspace] ${userId.slice(0, 8)}: wrote ${normalizedPath}`);
    res.json({ status: "ok", path: normalizedPath });
  } catch (error) {
    console.error(`[workspace] Error writing:`, error.message);
    res.status(500).json({ error: error.message });
  }
});

// Read a file from workspace (only .ocmt/ allowed)
router.get("/:userId/workspace/read", (req, res) => {
  const { userId } = req.params;
  const { filePath } = req.query;
  const info = containers.get(userId);

  if (!info) {
    return res.status(404).json({ error: "Container not found" });
  }

  if (!filePath) {
    return res.status(400).json({ error: "filePath required" });
  }

  // Security: only allow reading from .ocmt/ directory or config.json
  const normalizedPath = path.normalize(filePath);
  const allowedPaths = [".ocmt", "config.json"];
  const isAllowed = normalizedPath.startsWith(".ocmt/") || allowedPaths.includes(normalizedPath);
  if (!isAllowed) {
    return res.status(403).json({ error: "Can only read from .ocmt/ directory or config.json" });
  }

  if (normalizedPath.includes("..")) {
    return res.status(403).json({ error: "Path traversal not allowed" });
  }

  try {
    const workspaceDir = path.join(DATA_DIR, userId, "workspace");
    const fullPath = path.join(workspaceDir, normalizedPath);

    if (!fs.existsSync(fullPath)) {
      return res.status(404).json({ error: "File not found" });
    }

    const content = fs.readFileSync(fullPath, "utf-8");
    res.json({ path: normalizedPath, content });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Sync auth-profiles (for OAuth credentials)
router.post("/:userId/auth-profiles", (req, res) => {
  const { userId } = req.params;
  const { profiles } = req.body;
  const info = containers.get(userId);

  if (!info) {
    return res.status(404).json({ error: "Container not found" });
  }

  if (!profiles || typeof profiles !== "object") {
    return res.status(400).json({ error: "profiles object required" });
  }

  try {
    const result = writeAuthProfiles(userId, profiles);
    res.json({ status: "ok", profileCount: Object.keys(profiles).length });
  } catch (error) {
    console.error(`[workspace] Error writing auth-profiles:`, error.message);
    res.status(500).json({ error: error.message });
  }
});

// Get auth-profiles
router.get("/:userId/auth-profiles", (req, res) => {
  const { userId } = req.params;
  const info = containers.get(userId);

  if (!info) {
    return res.status(404).json({ error: "Container not found" });
  }

  try {
    const profiles = readAuthProfiles(userId);
    if (!profiles) {
      return res.json({ profiles: {} });
    }
    res.json(profiles);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

export default router;
