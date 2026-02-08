import crypto from "crypto";
import dotenv from "dotenv";
// OCMT Agent Server - Container orchestration for user AI agents
import express from "express";
import { createServer } from "http";
import os from "os";
import {
  containers,
  scanExistingContainers,
  checkHibernation,
  PAUSE_AFTER_MS,
  STOP_AFTER_MS,
} from "./lib/containers.js";
import { setupUnlockProxy } from "./lib/unlock-proxy.js";
import channelsRouter from "./routes/channels.js";
import containersRouter from "./routes/containers.js";
import groupVaultsRouter, { scanExistingGroupVaultContainers } from "./routes/group-vaults.js";
import oauthPkceRouter from "./routes/oauth-pkce.js";
import vaultRouter from "./routes/vault.js";
import workspaceRouter from "./routes/workspace.js";

dotenv.config();

const app = express();
const server = createServer(app);
app.use(express.json());

const PORT = process.env.PORT || 4000;
const AUTH_TOKEN = process.env.AUTH_TOKEN;
const HIBERNATION_CHECK_INTERVAL = 60_000;

if (!AUTH_TOKEN) {
  console.error("ERROR: AUTH_TOKEN not set");
  process.exit(1);
}

// Set up WebSocket proxy for direct browser-to-container vault unlock
setupUnlockProxy(server, AUTH_TOKEN);

// Auth middleware - timing-safe comparison to prevent timing attacks
function requireAuth(req, res, next) {
  const token = req.headers["x-auth-token"];
  if (!token || typeof token !== "string") {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const tokenBuf = Buffer.from(token);
  const authBuf = Buffer.from(AUTH_TOKEN);
  if (tokenBuf.length !== authBuf.length || !crypto.timingSafeEqual(tokenBuf, authBuf)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// Health check with capacity monitoring
app.get("/health", (req, res) => {
  const hibernation = { running: 0, paused: 0, stopped: 0 };
  for (const info of containers.values()) {
    hibernation[info.hibernationState || "running"]++;
  }

  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  const memPercent = Math.round((usedMem / totalMem) * 100);

  const estimatedCapacity = Math.floor((totalMem * 0.85) / (500 * 1024 * 1024));
  const runningContainers = hibernation.running;

  let capacityStatus = "ok";
  if (memPercent >= 85) {
    capacityStatus = "critical";
  } else if (memPercent >= 70) {
    capacityStatus = "warning";
  }

  res.json({
    status: "ok",
    containers: containers.size,
    hibernation,
    capacity: {
      status: capacityStatus,
      memoryPercent: memPercent,
      memoryUsedGB: (usedMem / 1024 / 1024 / 1024).toFixed(1),
      memoryTotalGB: (totalMem / 1024 / 1024 / 1024).toFixed(1),
      runningContainers,
      estimatedMaxRunning: estimatedCapacity,
      headroom: estimatedCapacity - runningContainers,
    },
  });
});

// Mount routes (all require auth)
app.use("/api/containers", requireAuth, containersRouter);
app.use("/api/containers", requireAuth, channelsRouter);
app.use("/api/containers", requireAuth, workspaceRouter);
// Vault unlock routes - direct browser-to-container proxy (HTTP fallback)
app.use("/api/containers", requireAuth, vaultRouter);

// Zero-knowledge OAuth with PKCE - container exchanges tokens directly
app.use("/api/containers", requireAuth, oauthPkceRouter);

// Group vault container management
app.use("/api/group-vaults", requireAuth, groupVaultsRouter);

// Legacy route aliases
app.post("/api/provision", requireAuth, (req, res, next) => {
  req.url = "/provision";
  containersRouter(req, res, next);
});

// Startup
Promise.all([scanExistingContainers(), scanExistingGroupVaultContainers()]).then(() => {
  setInterval(checkHibernation, HIBERNATION_CHECK_INTERVAL);
  console.log(`[hibernate] Check every ${HIBERNATION_CHECK_INTERVAL / 1000}s`);
  console.log(`[hibernate] Pause after ${PAUSE_AFTER_MS / 60000}min idle`);
  console.log(`[hibernate] Stop after ${STOP_AFTER_MS / 60000}min total`);

  server.listen(PORT, "0.0.0.0", () => {
    console.log("");
    console.log("OCMT Agent Server");
    console.log("====================");
    console.log("Port:", PORT);
    console.log("Auth: configured");
    console.log("Hibernation: enabled");
    console.log("WebSocket unlock proxy: enabled");
    console.log("");
    console.log("Ready.");
  });
});
