import axios from "axios";
// Chat proxy routes with SSE
import { Router } from "express";
import { AGENT_SERVER_URL, AGENT_SERVER_TOKEN } from "../lib/context.js";
import { decryptGatewayToken, generateEphemeralToken } from "../lib/gateway-tokens.js";
import { sseConnections, broadcastToUser } from "../lib/sse.js";
import { requireUser } from "../middleware/auth.js";
import { requireUserSSE } from "../middleware/sse-auth.js";
import { detectTenant } from "../middleware/tenant-context.js";

const router = Router();

// SSE stream for real-time chat messages
// Uses SSE-specific auth that allows query param tokens for EventSource
router.get("/stream", requireUserSSE, (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no"); // Disable nginx buffering

  const userId = req.user.id;
  if (!sseConnections.has(userId)) {
    sseConnections.set(userId, new Set());
  }
  sseConnections.get(userId).add(res);

  res.write(`event: connected\ndata: ${JSON.stringify({ userId })}\n\n`);

  const heartbeat = setInterval(() => {
    res.write(`: heartbeat\n\n`);
  }, 30000);

  req.on("close", () => {
    clearInterval(heartbeat);
    sseConnections.get(userId)?.delete(res);
    if (sseConnections.get(userId)?.size === 0) {
      sseConnections.delete(userId);
    }
  });
});

// Send message to container and stream response
router.post("/send", requireUser, detectTenant, async (req, res) => {
  try {
    const { message } = req.body;
    const user = req.user;

    if (!message || typeof message !== "string") {
      return res.status(400).json({ error: "Message required" });
    }

    if (!user.containerId || !user.containerPort) {
      return res.status(503).json({ error: "AI container not ready. Please wait a moment." });
    }

    broadcastToUser(user.id, "message", {
      role: "user",
      content: message,
      timestamp: new Date().toISOString(),
    });

    try {
      // Generate ephemeral token for container communication
      let ephemeralToken;
      try {
        const rawToken = decryptGatewayToken(user.gatewayToken);
        ephemeralToken = generateEphemeralToken(user.id, rawToken, 3600);
      } catch {
        // Legacy unencrypted token
        ephemeralToken = generateEphemeralToken(user.id, user.gatewayToken, 3600);
      }

      const response = await axios.post(
        `${AGENT_SERVER_URL}/api/chat/${user.id}`,
        { message },
        {
          headers: {
            Authorization: `Bearer ${AGENT_SERVER_TOKEN}`,
            "X-Gateway-Token": ephemeralToken,
          },
          timeout: 120000, // 2 minute timeout
        },
      );

      const assistantMessage = {
        role: "assistant",
        content: response.data.response || response.data.message,
        timestamp: new Date().toISOString(),
      };

      broadcastToUser(user.id, "message", assistantMessage);

      res.json({
        success: true,
        response: assistantMessage.content,
        timestamp: assistantMessage.timestamp,
      });
    } catch (proxyErr) {
      console.error("Container proxy error:", proxyErr.message);

      broadcastToUser(user.id, "error", {
        message: "Failed to get response from AI",
        timestamp: new Date().toISOString(),
      });

      res.status(502).json({ error: "Failed to communicate with AI container" });
    }
  } catch (err) {
    console.error("Chat send error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
