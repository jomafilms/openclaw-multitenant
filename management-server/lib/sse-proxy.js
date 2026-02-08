// SSE (Server-Sent Events) proxy for gateway token isolation
// Authenticates via httpOnly session cookie and proxies SSE from container
// Gateway tokens are never exposed to the browser

import axios from "axios";
import { sessions } from "../db/index.js";
import { AGENT_SERVER_URL, AGENT_SERVER_TOKEN } from "./context.js";
import { decryptGatewayToken, generateEphemeralToken } from "./gateway-tokens.js";

const SESSION_COOKIE = "ocmt_session";

/**
 * Parse cookies from request
 * @param {object} req - Express request
 * @returns {string|null} Session token
 */
function getSessionToken(req) {
  return req.cookies?.[SESSION_COOKIE] || null;
}

/**
 * SSE proxy handler for container events
 * Authenticates via cookie and proxies SSE stream from container
 *
 * @param {Request} req - Express request
 * @param {Response} res - Express response
 */
export async function sseProxyHandler(req, res) {
  // Cookie auth only - don't accept tokens from query params
  const sessionToken = getSessionToken(req);

  if (!sessionToken) {
    return res.status(401).json({ error: "Authentication required" });
  }

  try {
    // Validate session
    const session = await sessions.findByToken(sessionToken);
    if (!session) {
      return res.status(401).json({ error: "Invalid or expired session" });
    }

    // Check container assignment
    if (!session.container_id || !session.gateway_token || !session.container_port) {
      return res.status(503).json({ error: "Container not available" });
    }

    // Generate ephemeral token for container communication
    let ephemeralToken;
    try {
      const rawToken = decryptGatewayToken(session.gateway_token);
      ephemeralToken = generateEphemeralToken(session.user_id, rawToken, 3600);
    } catch {
      // Legacy unencrypted token
      ephemeralToken = generateEphemeralToken(session.user_id, session.gateway_token, 3600);
    }

    // Proxy SSE from container
    const containerUrl = `${AGENT_SERVER_URL}/api/containers/${session.user_id}/events`;

    const response = await axios({
      method: "GET",
      url: containerUrl,
      headers: {
        Authorization: `Bearer ${ephemeralToken}`,
        "x-auth-token": AGENT_SERVER_TOKEN,
        Accept: "text/event-stream",
      },
      responseType: "stream",
      timeout: 0, // No timeout for SSE
    });

    // Set SSE headers
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("X-Accel-Buffering", "no"); // Disable nginx buffering

    // Send initial connected event
    res.write(`event: connected\ndata: ${JSON.stringify({ userId: session.user_id })}\n\n`);

    // Pipe container response to client
    response.data.pipe(res);

    // Handle client disconnect
    req.on("close", () => {
      console.log(`[sse-proxy] Client disconnected for user ${session.user_id.slice(0, 8)}`);
      response.data.destroy();
    });

    console.log(`[sse-proxy] Proxying SSE for user ${session.user_id.slice(0, 8)}`);
  } catch (err) {
    console.error("[sse-proxy] Error:", err.message);

    // If headers not sent yet, send error response
    if (!res.headersSent) {
      if (err.response?.status === 404) {
        return res.status(503).json({ error: "Container not available" });
      }
      return res.status(502).json({ error: "Failed to connect to container" });
    }

    // If already streaming, try to send error event
    try {
      res.write(`event: error\ndata: ${JSON.stringify({ message: "Connection error" })}\n\n`);
      res.end();
    } catch {
      // Client already disconnected
    }
  }
}

/**
 * Create SSE proxy router
 * @returns {Promise<Router>} Express router
 */
export async function createSseProxyRouter() {
  const { Router } = await import("express");
  const router = Router();

  router.get("/container", sseProxyHandler);

  return router;
}

export default { sseProxyHandler, createSseProxyRouter };
