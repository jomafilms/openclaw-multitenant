import { WebSocketServer } from "ws";
import { messages } from "../db/index.js";
import { authenticateWebSocket } from "../middleware/auth.js";
import { wsMessageSchema, formatZodError } from "./schemas.js";

// Map of userId -> Set of WebSocket connections
const connections = new Map();

/**
 * Initialize WebSocket server
 *
 * Supports two authentication methods:
 * 1. Secure: Sec-WebSocket-Protocol header with "token.<base64(containerId:token)>, ocmt-relay"
 * 2. Deprecated: Query parameters ?token=<token>&containerId=<id>
 */
export function initWebSocket(server) {
  const wss = new WebSocketServer({
    noServer: true, // Handle upgrade manually to support protocol negotiation
  });

  // Handle HTTP upgrade requests for WebSocket
  server.on("upgrade", async (request, socket, head) => {
    // Check if this is for our path
    const url = new URL(request.url, `http://${request.headers.host}`);
    if (url.pathname !== "/relay/subscribe") {
      // Not our path, ignore (let other handlers deal with it)
      socket.destroy();
      return;
    }

    // Authenticate the connection
    const authResult = await authenticateWebSocket(request);

    if (!authResult.container) {
      socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
      socket.destroy();
      return;
    }

    // Complete the WebSocket upgrade, optionally with accepted protocol
    if (authResult.acceptedProtocol) {
      // Echo back the accepted subprotocol (e.g., "ocmt-relay")
      // This is required by the WebSocket spec when client sends Sec-WebSocket-Protocol
      wss.handleUpgrade(request, socket, head, (ws) => {
        // Manually set the protocol on the ws object
        ws.protocol = authResult.acceptedProtocol;
        wss.emit("connection", ws, request, authResult);
      });
    } else {
      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit("connection", ws, request, authResult);
      });
    }
  });

  wss.on("connection", async (ws, request, authResult) => {
    const container = authResult.container;
    const userId = container.userId;

    // Log connection with auth method for monitoring deprecation
    if (authResult.authMethod === "query-param") {
      console.log(
        `[ws] Container ${userId.slice(0, 8)} connected (using deprecated query param auth)`,
      );
    } else {
      console.log(`[ws] Container ${userId.slice(0, 8)} connected`);
    }

    // Add to connections map
    if (!connections.has(userId)) {
      connections.set(userId, new Set());
    }
    connections.get(userId).add(ws);

    // Send any pending messages immediately
    try {
      const pending = await messages.getPending(userId);
      if (pending.length > 0) {
        for (const msg of pending) {
          ws.send(
            JSON.stringify({
              type: "message",
              id: msg.id,
              from: msg.from_container_id,
              payload: msg.payload_encrypted,
              timestamp: msg.created_at,
            }),
          );
        }
      }
    } catch (err) {
      console.error(`[ws] Failed to send pending messages: ${err.message}`);
    }

    // Handle incoming messages (ACKs)
    ws.on("message", async (data) => {
      try {
        const raw = JSON.parse(data.toString());

        // Validate message against schema
        const result = wsMessageSchema.safeParse(raw);
        if (!result.success) {
          ws.send(
            JSON.stringify({
              type: "error",
              error: "Invalid message format",
              details: formatZodError(result.error),
            }),
          );
          console.warn(
            `[ws] Invalid message from ${userId.slice(0, 8)}: ${formatZodError(result.error)}`,
          );
          return;
        }

        const msg = result.data;

        if (msg.type === "ack") {
          // Mark message as delivered
          await messages.markDelivered(msg.messageId);
          console.log(`[ws] Message ${msg.messageId.slice(0, 8)} acknowledged`);
        } else if (msg.type === "ack_batch") {
          // Batch acknowledge
          await messages.markManyDelivered(msg.messageIds);
          console.log(`[ws] ${msg.messageIds.length} messages acknowledged`);
        } else if (msg.type === "ping") {
          // Respond to ping with pong
          ws.send(JSON.stringify({ type: "pong", timestamp: Date.now() }));
        }
      } catch (err) {
        if (err instanceof SyntaxError) {
          ws.send(
            JSON.stringify({
              type: "error",
              error: "Invalid JSON",
            }),
          );
          console.warn(`[ws] Invalid JSON from ${userId.slice(0, 8)}`);
        } else {
          console.error(`[ws] Error processing message: ${err.message}`);
        }
      }
    });

    // Handle disconnect
    ws.on("close", () => {
      console.log(`[ws] Container ${userId.slice(0, 8)} disconnected`);
      const userConnections = connections.get(userId);
      if (userConnections) {
        userConnections.delete(ws);
        if (userConnections.size === 0) {
          connections.delete(userId);
        }
      }
    });

    // Handle errors
    ws.on("error", (err) => {
      console.error(`[ws] WebSocket error for ${userId.slice(0, 8)}: ${err.message}`);
    });

    // Send a welcome message
    ws.send(
      JSON.stringify({
        type: "connected",
        containerId: userId,
        timestamp: Date.now(),
      }),
    );
  });

  // Periodic ping to keep connections alive
  setInterval(() => {
    wss.clients.forEach((ws) => {
      if (ws.readyState === ws.OPEN) {
        ws.ping();
      }
    });
  }, 30000);

  console.log("[ws] WebSocket server initialized");
  return wss;
}

/**
 * Send a message to a connected container via WebSocket
 * Returns true if delivered, false if not connected
 */
export function sendToContainer(userId, message) {
  const userConnections = connections.get(userId);

  if (!userConnections || userConnections.size === 0) {
    return false;
  }

  const payload = JSON.stringify({
    type: "message",
    id: message.id,
    from: message.from_container_id,
    payload: message.payload_encrypted,
    timestamp: message.created_at,
  });

  let delivered = false;
  for (const ws of userConnections) {
    if (ws.readyState === ws.OPEN) {
      ws.send(payload);
      delivered = true;
    }
  }

  return delivered;
}

/**
 * Check if a container is currently connected via WebSocket
 */
export function isContainerConnected(userId) {
  const userConnections = connections.get(userId);
  if (!userConnections) {
    return false;
  }

  for (const ws of userConnections) {
    if (ws.readyState === ws.OPEN) {
      return true;
    }
  }
  return false;
}

/**
 * Get count of connected containers
 */
export function getConnectionCount() {
  let count = 0;
  for (const [, conns] of connections) {
    for (const ws of conns) {
      if (ws.readyState === ws.OPEN) {
        count++;
      }
    }
  }
  return count;
}

/**
 * Broadcast a message to all connected containers
 * Used for system announcements
 */
export function broadcast(message) {
  const payload = JSON.stringify(message);
  let count = 0;

  for (const [, conns] of connections) {
    for (const ws of conns) {
      if (ws.readyState === ws.OPEN) {
        ws.send(payload);
        count++;
      }
    }
  }

  return count;
}

export default {
  initWebSocket,
  sendToContainer,
  isContainerConnected,
  getConnectionCount,
  broadcast,
};
