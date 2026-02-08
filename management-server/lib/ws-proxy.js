// WebSocket proxy for gateway token isolation
// Authenticates via httpOnly session cookie and proxies to container
// Gateway tokens are never exposed to the browser

import { WebSocketServer, WebSocket } from "ws";
import { sessions } from "../db/index.js";
import { AGENT_SERVER_URL } from "./context.js";
import { decryptGatewayToken, generateEphemeralToken } from "./gateway-tokens.js";
import { wakeContainerIfNeeded } from "./wake-on-request.js";

const SESSION_COOKIE = "ocmt_session";

// Active WebSocket connections by user ID (for monitoring/cleanup)
export const wsConnections = new Map();

// Max connections per user to prevent resource exhaustion
const MAX_CONNECTIONS_PER_USER = 5;

// Heartbeat interval (30 seconds)
const HEARTBEAT_INTERVAL = 30000;

// Connection timeout (5 minutes of inactivity)
const CONNECTION_TIMEOUT = 5 * 60 * 1000;

/**
 * Parse cookies from a cookie header string
 * @param {string} cookieHeader - Cookie header value
 * @returns {object} Parsed cookies
 */
function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) {
    return cookies;
  }

  cookieHeader.split(";").forEach((cookie) => {
    const parts = cookie.split("=");
    if (parts.length >= 2) {
      const name = parts[0].trim();
      const value = parts.slice(1).join("=").trim();
      cookies[name] = decodeURIComponent(value);
    }
  });

  return cookies;
}

/**
 * Setup WebSocket proxy on an HTTP server
 * @param {http.Server} server - HTTP server instance
 * @returns {WebSocketServer} WebSocket server instance
 */
export function setupWebSocketProxy(server) {
  const wss = new WebSocketServer({ noServer: true });

  // Handle HTTP upgrade requests
  server.on("upgrade", async (request, socket, head) => {
    // Only handle /api/ws/* paths
    const url = new URL(request.url, `http://${request.headers.host}`);

    if (!url.pathname.startsWith("/api/ws/")) {
      socket.destroy();
      return;
    }

    try {
      // Parse session cookie - authentication via httpOnly cookie only
      // Never accept tokens from query params for WebSocket to prevent token exposure
      const cookies = parseCookies(request.headers.cookie || "");
      const sessionToken = cookies[SESSION_COOKIE];

      if (!sessionToken) {
        console.log("[ws-proxy] Rejected: no session cookie");
        socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
        socket.destroy();
        return;
      }

      // Validate session
      const session = await sessions.findByToken(sessionToken);
      if (!session) {
        console.log("[ws-proxy] Rejected: invalid or expired session");
        socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
        socket.destroy();
        return;
      }

      // Check container assignment
      if (!session.container_id || !session.gateway_token || !session.container_port) {
        console.log(`[ws-proxy] Rejected: no container for user ${session.user_id.slice(0, 8)}`);
        socket.write("HTTP/1.1 503 Service Unavailable\r\n\r\n");
        socket.destroy();
        return;
      }

      // Check connection limit per user
      const userConnections = wsConnections.get(session.user_id) || new Set();
      if (userConnections.size >= MAX_CONNECTIONS_PER_USER) {
        console.log(
          `[ws-proxy] Rejected: connection limit for user ${session.user_id.slice(0, 8)}`,
        );
        socket.write("HTTP/1.1 429 Too Many Requests\r\n\r\n");
        socket.destroy();
        return;
      }

      // Upgrade connection
      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit("connection", ws, request, {
          userId: session.user_id,
          containerId: session.container_id,
          containerPort: session.container_port,
          gatewayToken: session.gateway_token,
          email: session.email,
        });
      });
    } catch (err) {
      console.error("[ws-proxy] Upgrade error:", err);
      socket.write("HTTP/1.1 500 Internal Server Error\r\n\r\n");
      socket.destroy();
    }
  });

  // Handle new connections
  wss.on("connection", async (clientWs, request, sessionData) => {
    const { userId, containerPort, gatewayToken } = sessionData;

    // Track connection
    if (!wsConnections.has(userId)) {
      wsConnections.set(userId, new Set());
    }
    wsConnections.get(userId).add(clientWs);

    console.log(`[ws-proxy] Client connected for user ${userId.slice(0, 8)}`);

    // Wake container if hibernated before trying to connect
    try {
      const wakeResult = await wakeContainerIfNeeded(userId, "websocket");
      if (wakeResult.wakeTime > 0) {
        console.log(
          `[ws-proxy] Woke container for ${userId.slice(0, 8)} in ${wakeResult.wakeTime}ms`,
        );
      }
    } catch (err) {
      console.warn(`[ws-proxy] Wake failed for ${userId.slice(0, 8)}:`, err.message);
      // Continue anyway - container might still be reachable
    }

    // Generate ephemeral token for container connection
    // This ensures permanent tokens are never transmitted, even server-to-server
    let ephemeralToken;
    try {
      const rawToken = decryptGatewayToken(gatewayToken);
      ephemeralToken = generateEphemeralToken(userId, rawToken, 3600);
    } catch {
      // Legacy unencrypted token
      ephemeralToken = generateEphemeralToken(userId, gatewayToken, 3600);
    }

    // Connect to container using ephemeral token
    // The gateway token is injected server-side and never exposed to the browser
    const containerUrl = `${AGENT_SERVER_URL.replace("http", "ws")}/ws/${userId}`;
    const containerWs = new WebSocket(containerUrl, {
      headers: {
        Authorization: `Bearer ${ephemeralToken}`,
      },
    });

    // Track connection state
    let containerConnected = false;
    let lastActivity = Date.now();

    // Heartbeat to keep connection alive and detect stale connections
    const heartbeatInterval = setInterval(() => {
      if (Date.now() - lastActivity > CONNECTION_TIMEOUT) {
        console.log(`[ws-proxy] Connection timeout for user ${userId.slice(0, 8)}`);
        clientWs.close(1000, "Connection timeout");
        return;
      }

      if (clientWs.readyState === WebSocket.OPEN) {
        clientWs.ping();
      }
    }, HEARTBEAT_INTERVAL);

    // Container connection handlers
    containerWs.on("open", () => {
      containerConnected = true;
      console.log(`[ws-proxy] Proxying WS for user ${userId.slice(0, 8)} to container`);

      // Send ready message to client
      if (clientWs.readyState === WebSocket.OPEN) {
        clientWs.send(JSON.stringify({ type: "proxy_ready" }));
      }
    });

    containerWs.on("error", (err) => {
      console.error(`[ws-proxy] Container WS error for ${userId.slice(0, 8)}:`, err.message);
      if (clientWs.readyState === WebSocket.OPEN) {
        clientWs.close(1011, "Container connection error");
      }
    });

    containerWs.on("close", (code, reason) => {
      console.log(`[ws-proxy] Container disconnected for ${userId.slice(0, 8)}: ${code}`);
      if (clientWs.readyState === WebSocket.OPEN) {
        clientWs.close(1000, "Container disconnected");
      }
    });

    // Proxy messages from container to client
    containerWs.on("message", (data) => {
      lastActivity = Date.now();
      if (clientWs.readyState === WebSocket.OPEN) {
        clientWs.send(data);
      }
    });

    // Client connection handlers
    clientWs.on("pong", () => {
      lastActivity = Date.now();
    });

    clientWs.on("message", (data) => {
      lastActivity = Date.now();
      if (containerConnected && containerWs.readyState === WebSocket.OPEN) {
        containerWs.send(data);
      }
    });

    clientWs.on("close", () => {
      console.log(`[ws-proxy] Client disconnected for ${userId.slice(0, 8)}`);

      // Cleanup
      clearInterval(heartbeatInterval);
      wsConnections.get(userId)?.delete(clientWs);
      if (wsConnections.get(userId)?.size === 0) {
        wsConnections.delete(userId);
      }

      // Close container connection
      if (containerWs.readyState === WebSocket.OPEN) {
        containerWs.close();
      }
    });

    clientWs.on("error", (err) => {
      console.error(`[ws-proxy] Client WS error for ${userId.slice(0, 8)}:`, err.message);

      // Cleanup
      clearInterval(heartbeatInterval);
      wsConnections.get(userId)?.delete(clientWs);
      if (wsConnections.get(userId)?.size === 0) {
        wsConnections.delete(userId);
      }

      // Close container connection
      if (containerWs.readyState === WebSocket.OPEN) {
        containerWs.close();
      }
    });
  });

  console.log("[ws-proxy] WebSocket proxy initialized");

  return wss;
}

/**
 * Get count of active WebSocket connections
 * @returns {object} Connection statistics
 */
export function getConnectionStats() {
  let totalConnections = 0;
  const userCounts = {};

  for (const [userId, connections] of wsConnections.entries()) {
    const count = connections.size;
    totalConnections += count;
    userCounts[userId.slice(0, 8)] = count;
  }

  return {
    totalConnections,
    uniqueUsers: wsConnections.size,
    userCounts,
  };
}

/**
 * Close all connections for a user (e.g., on logout)
 * @param {string} userId - User ID
 */
export function closeUserConnections(userId) {
  const connections = wsConnections.get(userId);
  if (connections) {
    for (const ws of connections) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.close(1000, "Session ended");
      }
    }
    wsConnections.delete(userId);
    console.log(`[ws-proxy] Closed all connections for user ${userId.slice(0, 8)}`);
  }
}
