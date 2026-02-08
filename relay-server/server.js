import dotenv from "dotenv";
// OCMT Encrypted Message Relay Server
// Zero-knowledge relay for container-to-container communication
import express from "express";
import http from "http";
import { messages, containerRegistry, cachedSnapshots } from "./db/index.js";
import { generalApiLimiter } from "./lib/rate-limit.js";
import { initWebSocket, getConnectionCount } from "./lib/websocket.js";
import messagesRouter from "./routes/messages.js";
import registryRouter from "./routes/registry.js";
import relayRouter from "./routes/relay.js";
import revocationRouter, {
  getRevocationCount,
  getSnapshotCount,
  initRevocationBloomFilter,
  cleanupExpiredRevocations,
  isBloomInitialized,
} from "./routes/revocation.js";

dotenv.config();

const app = express();
app.use(express.json({ limit: "2mb" })); // Allow larger payloads for encrypted blobs

// CORS configuration - restrict to internal services
// ALLOWED_ORIGINS must be explicitly configured; no wildcard fallback
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "").split(",").filter(Boolean);
if (ALLOWED_ORIGINS.length === 0) {
  console.warn(
    "WARNING: ALLOWED_ORIGINS not configured. CORS will reject all cross-origin requests.",
  );
}

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.header("Access-Control-Allow-Origin", origin);
  }
  // No wildcard fallback - explicit origins only
  res.header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Container-Id");
  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }
  next();
});

// Health check
app.get("/health", async (req, res) => {
  let registryCount = 0;
  let snapshotCount = 0;
  try {
    registryCount = await containerRegistry.count();
    snapshotCount = await cachedSnapshots.count();
  } catch {
    // Ignore errors in health check
  }

  res.json({
    status: "ok",
    service: "ocmt-relay",
    connections: getConnectionCount(),
    revocations: getRevocationCount(),
    snapshots: snapshotCount || getSnapshotCount(),
    registrations: registryCount,
    revocationsLoaded: isBloomInitialized(),
  });
});

// Apply general rate limiting to all relay routes
app.use("/relay", generalApiLimiter);

// Relay API routes (legacy simple send/pending/ack)
app.use("/relay", relayRouter);

// Message forwarding with capability verification
app.use("/relay", messagesRouter);

// Container registry for callback URLs and discovery
app.use("/relay/registry", registryRouter);

// Revocation API routes (also under /relay for consistency with client expectations)
app.use("/relay", revocationRouter);

// Create HTTP server (needed for WebSocket)
const server = http.createServer(app);

// Initialize WebSocket server for real-time message delivery
initWebSocket(server);

// Initialize revocation Bloom filter from database at startup
(async () => {
  try {
    await initRevocationBloomFilter();
    console.log("[startup] Revocation Bloom filter initialized from database");
  } catch (err) {
    console.error("[startup] Failed to initialize revocation Bloom filter:", err.message);
    console.error("[startup] Revocations will still work but may be slower");
  }
})();

// Periodic cleanup of expired messages
const CLEANUP_INTERVAL_MS = 60 * 60 * 1000; // 1 hour
setInterval(async () => {
  try {
    const expired = await messages.expireOldMessages(24);
    if (expired.length > 0) {
      console.log(`[cleanup] Expired ${expired.length} old messages`);
    }
  } catch (err) {
    console.error("[cleanup] Failed to expire messages:", err.message);
  }
}, CLEANUP_INTERVAL_MS);

// Periodic cleanup of expired revocations (daily)
const REVOCATION_CLEANUP_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours
setInterval(async () => {
  try {
    const removed = await cleanupExpiredRevocations();
    if (removed > 0) {
      console.log(`[cleanup] Removed ${removed} expired revocations`);
    }
  } catch (err) {
    console.error("[cleanup] Failed to clean up revocations:", err.message);
  }
}, REVOCATION_CLEANUP_INTERVAL_MS);

// Start server
const PORT = process.env.PORT || 5000;
server.listen(PORT, "0.0.0.0", () => {
  console.log(`OCMT Relay Server running on http://0.0.0.0:${PORT}`);
  console.log("WebSocket endpoint: ws://0.0.0.0:" + PORT + "/relay/subscribe");
  console.log("");
  console.log("SECURITY NOTICE: This relay is ZERO-KNOWLEDGE");
  console.log("- Message payloads are encrypted end-to-end");
  console.log("- The relay CANNOT read message content");
  console.log("- Only metadata is logged: who->whom, timestamp, size");
});
